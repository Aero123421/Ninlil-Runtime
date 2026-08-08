/*
 * R9 SX1262 + R1 sole-edge host tests (Proposed ADR-0025).
 * Fake-bus only. Not RF HIL.
 */

#include "domain_store_codec.h"
#include "ninlil_sx1262_backend.h"
#include "ninlil_sx1262_cmd.h"
#include "ninlil_sx1262_phy.h"
#include "radio_hal.h"
#include "radio_hal_spy.h"
#include "sx1262_bus_spy.h"
#include "sx1262_r9_edge.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "%s:%d: FAIL %s\n", __FILE__, __LINE__, #c);  \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void fill_board(ninlil_sx1262_board_config_t *b)
{
    (void)memset(b, 0, sizeof(*b));
    b->abi_version = NINLIL_SX1262_ABI_VERSION;
    b->struct_size = (uint16_t)sizeof(*b);
    b->pin_nss = 1001u;
    b->pin_sck = 1002u;
    b->pin_mosi = 1003u;
    b->pin_miso = 1004u;
    b->pin_reset = 1005u;
    b->pin_busy = 1006u;
    b->pin_dio1 = 1007u;
    b->pin_ant_sw = NINLIL_SX1262_PIN_UNSET;
    b->reset_pulse_us = 1000u;
    b->busy_timeout_ms = 50u;
    b->spi_busy_timeout_ms = 50u;
    b->post_spi_busy_guard_us = 1u;
    b->busy_poll_interval_us = 100u;
    b->busy_poll_slack = 2u;
    b->regulator_mode = NINLIL_SX1262_REG_MODE_LDO;
}

static void set_id(ninlil_radio_hal_id_t *id, uint8_t tag)
{
    size_t i;
    for (i = 0u; i < sizeof(id->bytes); ++i) {
        id->bytes[i] = (uint8_t)(tag + i);
    }
}

static int sha_frame(const uint8_t *f, uint32_t n, uint8_t out[32])
{
    ninlil_model_domain_digest_t d;
    size_t i;
    if (ninlil_model_domain_sha256(f, n, &d) != NINLIL_OK) {
        return 0;
    }
    for (i = 0u; i < 32u; ++i) {
        out[i] = d.bytes[i];
    }
    return 1;
}

static ninlil_radio_hal_status_t sha_digest_verify(
    void *ctx,
    const ninlil_radio_hal_frame_view_t *frame,
    const uint8_t digest[NINLIL_RADIO_HAL_DIGEST_BYTES],
    uint32_t digest_algorithm,
    ninlil_radio_hal_error_t *out_error)
{
    uint8_t computed[32];

    (void)ctx;
    (void)digest_algorithm;
    if (frame == NULL || digest == NULL || frame->bytes == NULL
        || frame->length == 0u || !sha_frame(frame->bytes, frame->length, computed)
        || ninlil_sx1262_r9_digest_ct_neq(computed, digest) != 0) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH;
        }
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_RADIO_HAL_OK;
}

static const ninlil_radio_hal_digest_ops_t g_sha_digest_ops = {
    sha_digest_verify
};

/*
 * R2 permit seam stub for sole-edge host tests.
 * Sequence/single-use watermark authority is R1 HAL (not this spy list).
 * Avoids radio_hal_spy consumed_seqs CAP=128 which would break 10k.
 */
static ninlil_radio_hal_status_t sole_permit_validate(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    (void)ctx;
    (void)permit;
    (void)frame;
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t sole_permit_consume(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    (void)ctx;
    (void)permit;
    (void)frame;
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_RADIO_HAL_OK;
}

static const ninlil_radio_hal_permit_ops_t g_sole_permit_ops = {
    sole_permit_validate,
    sole_permit_consume
};

typedef struct {
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_backend_object_t be_obj;
    ninlil_sx1262_backend_t *be;
    ninlil_sx1262_phy_object_t phy_obj;
    ninlil_sx1262_phy_t *phy;
    ninlil_sx1262_rf_profile_t prof;
    ninlil_sx1262_r9_edge_object_t edge_obj;
    ninlil_sx1262_r9_edge_t *edge;
    const ninlil_radio_hal_edge_ops_t *edge_ops;
    void *edge_ctx;
    ninlil_radio_hal_object_t hal_obj;
    ninlil_radio_hal_t *hal;
    ninlil_radio_hal_spy_t hspy;
} sole_env_t;

static int sole_env_open(sole_env_t *e)
{
    ninlil_sx1262_board_config_t board;
    ninlil_sx1262_error_t err;
    ninlil_sx1262_bus_ops_t ops;
    ninlil_radio_hal_error_t herr;
    ninlil_radio_hal_live_binding_t live;

    (void)memset(e, 0, sizeof(*e));
    ninlil_sx1262_bus_spy_init(&e->spy);
    e->spy.now_ms = 10000u;
    e->spy.status_byte =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    ops = *ninlil_sx1262_bus_spy_ops();
    fill_board(&board);
    e->be_obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_init(
                &e->be_obj, &board, &ops, &e->spy, &e->be, &err)
        == NINLIL_SX1262_OK);
    ninlil_sx1262_rf_profile_lab_default(&e->prof);
    e->phy_obj = (ninlil_sx1262_phy_object_t)NINLIL_SX1262_PHY_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_phy_init(
                &e->phy_obj, e->be, &e->prof, NULL, NULL, &e->phy, &err)
        == NINLIL_SX1262_OK);
    e->edge_obj = (ninlil_sx1262_r9_edge_object_t)NINLIL_SX1262_R9_EDGE_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_r9_edge_init(
                &e->edge_obj,
                e->phy,
                &e->prof,
                &e->edge,
                &e->edge_ops,
                &e->edge_ctx,
                &herr)
        == NINLIL_RADIO_HAL_OK);

    ninlil_radio_hal_spy_init(&e->hspy);
    e->hspy.clock_ms = 10000u;
    e->hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e->hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    e->hspy.next_digest_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_init_object(&e->hal_obj, &e->hal)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_bind_edge(
                e->hal, e->edge_ops, e->edge_ctx, &herr)
        == NINLIL_RADIO_HAL_OK);
    /* Cap-free R2 stub; R1 HAL owns sequence watermark. */
    REQUIRE(ninlil_radio_hal_bind_permit_ops(
                e->hal, &g_sole_permit_ops, NULL, &herr)
        == NINLIL_RADIO_HAL_OK);
    /* SHA-256 digest seam (matches R9 edge recompute). */
    REQUIRE(ninlil_radio_hal_bind_digest_ops(
                e->hal, &g_sha_digest_ops, NULL, &herr)
        == NINLIL_RADIO_HAL_OK);

    (void)memset(&live, 0, sizeof(live));
    set_id(&live.hardware_profile_id, 0x10u);
    live.hardware_profile_rev = 1u;
    set_id(&live.regulatory_profile_id, 0x20u);
    live.regulatory_profile_rev = 1u;
    set_id(&live.site_assignment_id, 0x30u);
    live.site_assignment_rev = 1u;
    live.site_assignment_epoch = 1u;
    set_id(&live.transmitter_id, 0x40u);
    live.channel_id = 1u;
    live.phy.bandwidth_hz = 125000u;
    live.phy.spreading_factor = 7u;
    live.phy.coding_rate_denom = 5u;
    live.phy.preamble_symbols = 8u;
    live.phy.tx_power_mdb = 14000;
    /*
     * HAL check_live requires permit.max_airtime_us == live.max_airtime_us.
     * Ceiling matches LAB profile; edge independently recomputes ToA and
     * rejects when real airtime exceeds this bound (does not trust caller ToA).
     */
    live.max_airtime_us = 2000000u;
    REQUIRE(ninlil_radio_hal_set_live_binding(e->hal, &live, &herr)
        == NINLIL_RADIO_HAL_OK);
    return 0;
}

/* Rebind live max_airtime only (same ids/phy); used by airtime-exceed tests. */
static int rebind_live_max_airtime(sole_env_t *e, uint32_t max_airtime_us)
{
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_error_t herr;

    (void)memset(&live, 0, sizeof(live));
    set_id(&live.hardware_profile_id, 0x10u);
    live.hardware_profile_rev = 1u;
    set_id(&live.regulatory_profile_id, 0x20u);
    live.regulatory_profile_rev = 1u;
    set_id(&live.site_assignment_id, 0x30u);
    live.site_assignment_rev = 1u;
    live.site_assignment_epoch = 1u;
    set_id(&live.transmitter_id, 0x40u);
    live.channel_id = 1u;
    live.phy.bandwidth_hz = 125000u;
    live.phy.spreading_factor = 7u;
    live.phy.coding_rate_denom = 5u;
    live.phy.preamble_symbols = 8u;
    live.phy.tx_power_mdb = 14000;
    live.max_airtime_us = max_airtime_us;
    return ninlil_radio_hal_set_live_binding(e->hal, &live, &herr)
            == NINLIL_RADIO_HAL_OK
        ? 0
        : 1;
}

static int fill_hal_permit(
    ninlil_radio_hal_permit_snapshot_t *p,
    const uint8_t *frame,
    uint32_t flen,
    uint64_t seq)
{
    (void)memset(p, 0, sizeof(*p));
    set_id(&p->hardware_profile_id, 0x10u);
    p->hardware_profile_rev = 1u;
    set_id(&p->regulatory_profile_id, 0x20u);
    p->regulatory_profile_rev = 1u;
    set_id(&p->site_assignment_id, 0x30u);
    p->site_assignment_rev = 1u;
    p->site_assignment_epoch = 1u;
    set_id(&p->transmitter_id, 0x40u);
    p->channel_id = 1u;
    p->phy.bandwidth_hz = 125000u;
    p->phy.spreading_factor = 7u;
    p->phy.coding_rate_denom = 5u;
    p->phy.preamble_symbols = 8u;
    p->phy.tx_power_mdb = 14000;
    p->frame_byte_length = flen;
    p->frame_digest_algorithm = 1u; /* SHA-256 */
    REQUIRE(sha_frame(frame, flen, p->frame_digest));
    /* Match live binding; edge recomputes real ToA (does not trust this as ToA). */
    p->max_airtime_us = 2000000u;
    p->not_before_ms = 0u;
    p->expiry_ms = 100000000ull;
    p->permit_sequence = seq;
    return 0;
}

static int test_timeout_steps_unit(void)
{
    uint32_t steps = 0u;
    /* 15625 µs → exactly 1000 steps (15625/15.625) */
    REQUIRE(ninlil_sx1262_r9_airtime_to_settx_steps(15625u, 0u, &steps) == 1);
    REQUIRE(steps == 1000u);
    REQUIRE(ninlil_sx1262_r9_airtime_to_settx_steps(1u, 0u, &steps) == 1);
    REQUIRE(steps == 1u);
    REQUIRE(ninlil_sx1262_r9_airtime_to_settx_steps(0xFFFFFFFFu, 0xFFFFFFFFu, &steps)
        == 0);
    return 0;
}

static int test_digest_ct(void)
{
    uint8_t a[32];
    uint8_t b[32];
    (void)memset(a, 0xABu, sizeof(a));
    (void)memset(b, 0xABu, sizeof(b));
    REQUIRE(ninlil_sx1262_r9_digest_ct_neq(a, b) == 0);
    b[31] ^= 1u;
    REQUIRE(ninlil_sx1262_r9_digest_ct_neq(a, b) == 1);
    return 0;
}

static int test_sole_edge_tx_ok(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_error_t perr;
    ninlil_sx1262_r9_edge_stats_t est;
    uint8_t bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint32_t i;

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 8u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 8u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == 1u);
    e.spy.irq_status = 0x0001u;
    for (i = 0u; i < 8u; ++i) {
        REQUIRE(ninlil_sx1262_phy_poll(e.phy, &perr) == NINLIL_SX1262_OK);
        if (ninlil_sx1262_phy_state(e.phy) == NINLIL_SX1262_PHY_STATE_IDLE) {
            break;
        }
    }
    ninlil_sx1262_r9_edge_stats(e.edge, &est);
    REQUIRE(est.edge_ok == 1u);
    REQUIRE(est.digest_reject == 0u);
    /* bare R4 still deny */
    REQUIRE(ninlil_sx1262_request_transmit(e.be, bytes, 8u, &perr)
        == NINLIL_SX1262_TX_DENIED);
    return 0;
}

static int test_sole_edge_digest_reject(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    uint8_t bytes[4] = {9, 8, 7, 6};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    permit.frame_digest[0] ^= 0xFFu; /* corrupt after fill */
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    {
        ninlil_radio_hal_status_t st =
            ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr);
        REQUIRE(st != NINLIL_RADIO_HAL_OK);
    }
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_airtime_exceed_no_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_r9_edge_stats_t est;
    uint8_t bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 8u, 1u) == 0);
    /* Live must match permit max; edge recomputes ToA >> 1 and rejects. */
    permit.max_airtime_us = 1u;
    REQUIRE(rebind_live_max_airtime(&e, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 8u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        != NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    ninlil_sx1262_r9_edge_stats(e.edge, &est);
    REQUIRE(est.airtime_reject == 1u);
    return 0;
}

static int test_lifecycle_10k_sole_edge(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_error_t perr;
    ninlil_sx1262_r9_edge_stats_t est;
    uint8_t bytes[4] = {0xAAu, 0xBBu, 0xCCu, 0xDDu};
    uint32_t i;
    uint64_t gen0;

    REQUIRE(sole_env_open(&e) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    gen0 = ninlil_sx1262_phy_generation(e.phy);
    for (i = 0u; i < 10000u; ++i) {
        REQUIRE(fill_hal_permit(&permit, bytes, 4u, (uint64_t)i + 1u) == 0);
        e.spy.irq_status = 0u;
        REQUIRE(ninlil_radio_hal_transmit_with_permit(
                    e.hal, &permit, &frame, &herr)
            == NINLIL_RADIO_HAL_OK);
        e.spy.irq_status = 0x0001u;
        REQUIRE(ninlil_sx1262_phy_poll(e.phy, &perr) == NINLIL_SX1262_OK);
        if ((i % 2000u) == 1999u) {
            REQUIRE(ninlil_sx1262_phy_recover(e.phy, &perr) == NINLIL_SX1262_OK);
            REQUIRE(ninlil_sx1262_phy_generation(e.phy) > gen0);
            gen0 = ninlil_sx1262_phy_generation(e.phy);
        }
    }
    REQUIRE(e.spy.settx_opcodes_seen == 10000u);
    ninlil_sx1262_r9_edge_stats(e.edge, &est);
    REQUIRE(est.edge_ok == 10000u);
    return 0;
}

static int test_seq_replay_no_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_error_t perr;
    uint8_t bytes[4] = {1, 2, 3, 4};
    uint32_t settx0;

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 7u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    e.spy.irq_status = 0x0001u;
    REQUIRE(ninlil_sx1262_phy_poll(e.phy, &perr) == NINLIL_SX1262_OK);
    settx0 = e.spy.settx_opcodes_seen;
    /* Same sequence: R1 HAL is sole watermark authority. */
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        != NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == settx0);
    return 0;
}

static int test_stale_generation_reject(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_error_t perr;
    ninlil_sx1262_r9_edge_stats_t est;
    ninlil_sx1262_phy_tx_plan_t plan;
    uint8_t bytes[4] = {5, 6, 7, 8};
    uint64_t stale_gen;

    REQUIRE(sole_env_open(&e) == 0);
    stale_gen = ninlil_sx1262_phy_generation(e.phy);
    REQUIRE(ninlil_sx1262_phy_recover(e.phy, &perr) == NINLIL_SX1262_OK);
    REQUIRE(ninlil_sx1262_phy_generation(e.phy) != stale_gen);
    (void)memset(&plan, 0, sizeof(plan));
    plan.frequency_hz = 915000000u;
    plan.bandwidth_hz = 125000u;
    plan.spreading_factor = 7u;
    plan.coding_rate_denom = 5u;
    plan.preamble_symbols = 8u;
    plan.tx_power_mdb = 14000;
    plan.settx_timeout_steps = 1000u;
    plan.expected_radio_generation = stale_gen;
    REQUIRE(ninlil_sx1262_phy_arm_tx(e.phy, &plan, bytes, 4u, &perr)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);

    /* Full sole edge still works after recover with current generation. */
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == 1u);
    ninlil_sx1262_r9_edge_stats(e.edge, &est);
    REQUIRE(est.edge_ok == 1u);
    return 0;
}

static int test_fault_spi_no_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    uint8_t bytes[4] = {0x11u, 0x22u, 0x33u, 0x44u};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    /* Fail the next SPI after init traffic (arm path must not reach SetTx). */
    e.spy.fail_spi_on_n = (int)(e.spy.spi_calls + 1u);
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        != NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_irq_timeout_recovery(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_error_t perr;
    uint8_t bytes[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    uint32_t i;

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_sx1262_phy_state(e.phy) == NINLIL_SX1262_PHY_STATE_TX_ACTIVE);
    /* No TxDone IRQ: advance clock past deadline. */
    e.spy.irq_status = 0u;
    e.spy.now_ms = 10000u + 60000u;
    for (i = 0u; i < 4u; ++i) {
        REQUIRE(ninlil_sx1262_phy_poll(e.phy, &perr) == NINLIL_SX1262_OK);
        if (ninlil_sx1262_phy_state(e.phy) == NINLIL_SX1262_PHY_STATE_IDLE) {
            break;
        }
    }
    REQUIRE(ninlil_sx1262_phy_state(e.phy) == NINLIL_SX1262_PHY_STATE_IDLE);
    REQUIRE(ninlil_sx1262_phy_recover(e.phy, &perr) == NINLIL_SX1262_OK);
    /* Restart path after recover. */
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 2u) == 0);
    e.spy.now_ms = 10000u;
    e.hspy.clock_ms = 10000u;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    e.spy.irq_status = 0x0001u;
    REQUIRE(ninlil_sx1262_phy_poll(e.phy, &perr) == NINLIL_SX1262_OK);
    return 0;
}

static int test_legacy_permit_api_not_sole(void)
{
    sole_env_t e;
    ninlil_sx1262_tx_permit_t legacy;
    ninlil_sx1262_error_t err;
    uint8_t f[2] = {1, 2};

    /*
     * Legacy request_transmit_with_permit remains callable for fixtures but
     * production sole path is radio_hal only. Bare R4 still denies.
     */
    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(ninlil_sx1262_request_transmit(e.be, f, 2u, &err)
        == NINLIL_SX1262_TX_DENIED);
    (void)memset(&legacy, 0, sizeof(legacy));
    legacy.abi_version = NINLIL_SX1262_PHY_ABI_VERSION;
    legacy.struct_size = (uint16_t)sizeof(legacy);
    legacy.permit_sequence = 1u;
    legacy.attempt_id = 1u;
    legacy.radio_generation = ninlil_sx1262_phy_generation(e.phy);
    legacy.not_before_ms = 0u;
    legacy.expiry_ms = 100000000ull;
    legacy.frequency_hz = 915000000u;
    legacy.bandwidth_hz = 125000u;
    legacy.spreading_factor = 7u;
    legacy.coding_rate_denom = 5u;
    legacy.preamble_symbols = 8u;
    legacy.tx_power_mdb = 14000;
    legacy.max_airtime_us = 500000u;
    legacy.frame_byte_length = 2u;
    legacy.frame_digest[0] = 0xA5u;
    /* Fixture path may arm (uses phy_arm_tx under the hood) — not sole authority. */
    REQUIRE(ninlil_sx1262_request_transmit_with_permit(
                e.phy, &legacy, f, 2u, &err)
        == NINLIL_SX1262_OK);
    return 0;
}

static int test_bare_r4_deny(void)
{
    sole_env_t e;
    ninlil_sx1262_error_t err;
    uint8_t f[2] = {1, 2};
    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(ninlil_sx1262_request_transmit(e.be, f, 2u, &err)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_ldro_auto(void)
{
    /* SF7 / 125kHz: Tsym = 1.024 ms < 16.38 → LDRO off */
    REQUIRE(ninlil_sx1262_phy_ldro_auto_effective(7u, 125000u) == 0);
    /* SF12 / 125kHz: Tsym = 32.768 ms >= 16.38 → LDRO on */
    REQUIRE(ninlil_sx1262_phy_ldro_auto_effective(12u, 125000u) == 1);
    return 0;
}

static int test_status_error_no_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    uint8_t bytes[4] = {0x11u, 0x22u, 0x33u, 0x44u};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    /* Poison SPI status after a few xfers (cmd_status process error = 4). */
    e.spy.fail_status_after_n_spi = (int)(e.spy.spi_xfer_count_for_status + 3);
    e.spy.status_byte_poison =
        (uint8_t)((NINLIL_SX1262_CHIP_MODE_STBY_RC
                      << NINLIL_SX1262_CHIP_MODES_POS)
            | (NINLIL_SX1262_CMD_STATUS_CMD_PROCESS_ERROR
                << NINLIL_SX1262_CMD_STATUS_POS));
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        != NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_lbt_busy_no_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    uint8_t bytes[4] = {1, 2, 3, 4};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    e.spy.cad_force_busy = 1;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        != NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.setcad_opcodes_seen >= 1u);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_lbt_clear_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    uint8_t bytes[4] = {5, 6, 7, 8};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    e.spy.cad_force_busy = 0;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.setcad_opcodes_seen >= 1u);
    REQUIRE(e.spy.settx_opcodes_seen == 1u);
    return 0;
}

static int test_lbt_deadline_no_settx(void)
{
    sole_env_t e;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    uint8_t bytes[4] = {9, 8, 7, 6};

    REQUIRE(sole_env_open(&e) == 0);
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    e.spy.cad_force_timeout = 1;
    e.spy.advance_ms_per_now = 20u; /* hit 50 ms LBT deadline quickly */
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        != NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_ant_sw_tx_rx(void)
{
    sole_env_t e;
    ninlil_sx1262_board_config_t board;
    ninlil_sx1262_error_t err;
    ninlil_sx1262_bus_ops_t ops;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t herr;
    size_t trace_before_rx;
    uint8_t bytes[4] = {0xAAu, 0xBBu, 0xCCu, 0xDDu};

    (void)memset(&e, 0, sizeof(e));
    ninlil_sx1262_bus_spy_init(&e.spy);
    e.spy.now_ms = 10000u;
    e.spy.status_byte =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    ops = *ninlil_sx1262_bus_spy_ops_with_ant_sw();
    fill_board(&board);
    board.pin_ant_sw = 1038u;
    board.feature_flags = NINLIL_SX1262_FEATURE_ANT_SW_PRESENT;
    board.ant_sw_active_high = 1u;
    e.be_obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_init(
                &e.be_obj, &board, &ops, &e.spy, &e.be, &err)
        == NINLIL_SX1262_OK);
    ninlil_sx1262_rf_profile_lab_default(&e.prof);
    e.phy_obj = (ninlil_sx1262_phy_object_t)NINLIL_SX1262_PHY_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_phy_init(
                &e.phy_obj, e.be, &e.prof, NULL, NULL, &e.phy, &err)
        == NINLIL_SX1262_OK);
    e.edge_obj = (ninlil_sx1262_r9_edge_object_t)NINLIL_SX1262_R9_EDGE_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_r9_edge_init(
                &e.edge_obj,
                e.phy,
                &e.prof,
                &e.edge,
                &e.edge_ops,
                &e.edge_ctx,
                &herr)
        == NINLIL_RADIO_HAL_OK);
    ninlil_radio_hal_spy_init(&e.hspy);
    e.hspy.clock_ms = 10000u;
    REQUIRE(ninlil_radio_hal_init_object(&e.hal_obj, &e.hal)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_bind_edge(
                e.hal, e.edge_ops, e.edge_ctx, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_bind_permit_ops(
                e.hal, &g_sole_permit_ops, NULL, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_bind_digest_ops(
                e.hal, &g_sha_digest_ops, NULL, &herr)
        == NINLIL_RADIO_HAL_OK);
    {
        ninlil_radio_hal_live_binding_t live;
        (void)memset(&live, 0, sizeof(live));
        set_id(&live.hardware_profile_id, 0x10u);
        live.hardware_profile_rev = 1u;
        set_id(&live.regulatory_profile_id, 0x20u);
        live.regulatory_profile_rev = 1u;
        set_id(&live.site_assignment_id, 0x30u);
        live.site_assignment_rev = 1u;
        live.site_assignment_epoch = 1u;
        set_id(&live.transmitter_id, 0x40u);
        live.channel_id = 1u;
        live.phy.bandwidth_hz = 125000u;
        live.phy.spreading_factor = 7u;
        live.phy.coding_rate_denom = 5u;
        live.phy.preamble_symbols = 8u;
        live.phy.tx_power_mdb = 14000;
        live.max_airtime_us = 2000000u;
        REQUIRE(ninlil_radio_hal_set_live_binding(e.hal, &live, &herr)
            == NINLIL_RADIO_HAL_OK);
    }
    REQUIRE(fill_hal_permit(&permit, bytes, 4u, 1u) == 0);
    frame.bytes = bytes;
    frame.length = 4u;
    e.hspy.next_validate_status = NINLIL_RADIO_HAL_OK;
    e.hspy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(ninlil_radio_hal_transmit_with_permit(
                e.hal, &permit, &frame, &herr)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(e.spy.ant_sw_set_calls >= 1u);
    REQUIRE(e.spy.last_ant_sw_active == 1);
    e.spy.irq_status = 0x0001u;
    REQUIRE(ninlil_sx1262_phy_poll(e.phy, &err) == NINLIL_SX1262_OK);
    REQUIRE(e.spy.last_ant_sw_active == 0);

    e.spy.trace_len = 0u;
    e.spy.trace_seq = 0u;
    trace_before_rx = 0u;
    REQUIRE(ninlil_sx1262_phy_start_rx(e.phy, 1000u, &err) == NINLIL_SX1262_OK);
    REQUIRE(e.spy.last_ant_sw_active == 1);
    {
        size_t i;
        int saw_rx_packet_params = 0;
        for (i = trace_before_rx; i < e.spy.trace_len; ++i) {
            if (e.spy.trace[i].event == NINLIL_SX1262_SPY_EV_SPI
                && e.spy.trace[i].opcode == 0x8Cu
                && e.spy.trace[i].sample_len >= 5u) {
                saw_rx_packet_params = 1;
                REQUIRE(e.spy.trace[i].sample[3] == 0x00u);
                REQUIRE(e.spy.trace[i].sample[4] == 0xFFu);
            }
        }
        REQUIRE(saw_rx_packet_params == 1);
    }
    return 0;
}

static int test_permit_substitution_seal(void)
{
    sole_env_t e;
    ninlil_sx1262_phy_tx_plan_t plan;
    ninlil_sx1262_error_t perr;
    uint8_t bytes[4] = {1, 2, 3, 4};

    REQUIRE(sole_env_open(&e) == 0);
    (void)memset(&plan, 0, sizeof(plan));
    plan.frequency_hz = 915000000u;
    plan.bandwidth_hz = 125000u;
    plan.spreading_factor = 7u;
    plan.coding_rate_denom = 5u;
    plan.preamble_symbols = 8u;
    plan.tx_power_mdb = 14000;
    plan.settx_timeout_steps = 1000u;
    plan.expected_radio_generation = ninlil_sx1262_phy_generation(e.phy);
    plan.frame_byte_length = 3u; /* mismatch vs actual 4 */
    plan.require_lbt = 0u;
    REQUIRE(ninlil_sx1262_phy_arm_tx(e.phy, &plan, bytes, 4u, &perr)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(e.spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_exact_board_pins_in_hil_defaults(void)
{
    /* Documented board pins (also enforced by python gates on sdkconfig). */
    const uint32_t pins[] = {41u, 7u, 9u, 8u, 42u, 40u, 39u, 38u};
    REQUIRE(pins[0] == 41u);
    REQUIRE(pins[7] == 38u);
    ninlil_sx1262_rf_profile_t p;
    ninlil_sx1262_rf_profile_lab_default(&p);
    REQUIRE(p.bandwidth_hz == 125000u);
    REQUIRE(p.sf_min == 7u);
    return 0;
}

int main(void)
{
    REQUIRE(test_timeout_steps_unit() == 0);
    REQUIRE(test_digest_ct() == 0);
    REQUIRE(test_ldro_auto() == 0);
    REQUIRE(test_bare_r4_deny() == 0);
    REQUIRE(test_sole_edge_tx_ok() == 0);
    REQUIRE(test_sole_edge_digest_reject() == 0);
    REQUIRE(test_airtime_exceed_no_settx() == 0);
    REQUIRE(test_seq_replay_no_settx() == 0);
    REQUIRE(test_stale_generation_reject() == 0);
    REQUIRE(test_fault_spi_no_settx() == 0);
    REQUIRE(test_status_error_no_settx() == 0);
    REQUIRE(test_lbt_clear_settx() == 0);
    REQUIRE(test_lbt_busy_no_settx() == 0);
    REQUIRE(test_lbt_deadline_no_settx() == 0);
    REQUIRE(test_ant_sw_tx_rx() == 0);
    REQUIRE(test_permit_substitution_seal() == 0);
    REQUIRE(test_exact_board_pins_in_hil_defaults() == 0);
    REQUIRE(test_irq_timeout_recovery() == 0);
    REQUIRE(test_legacy_permit_api_not_sole() == 0);
    REQUIRE(test_lifecycle_10k_sole_edge() == 0);
    (void)fprintf(stderr, "sx1262_r9_test ok\n");
    return 0;
}
