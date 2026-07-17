/*
 * R1 host tests: ninlil_radio_hal sole transmit-with-permit + spy port.
 * Does not claim R2/R4/SX1262/RF/legal/HIL/production radio complete.
 */

#include "radio_hal.h"
#include "radio_hal_spy.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void fill_id(ninlil_radio_hal_id_t *id, uint8_t tag)
{
    size_t i;

    for (i = 0u; i < NINLIL_RADIO_HAL_ID_BYTES; ++i) {
        id->bytes[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void fill_live_and_permit(
    ninlil_radio_hal_live_binding_t *live,
    ninlil_radio_hal_permit_snapshot_t *permit,
    const uint8_t *frame,
    uint32_t frame_len,
    uint64_t seq)
{
    (void)memset(live, 0, sizeof(*live));
    (void)memset(permit, 0, sizeof(*permit));

    fill_id(&live->hardware_profile_id, 0x10u);
    live->hardware_profile_rev = 1u;
    fill_id(&live->regulatory_profile_id, 0x20u);
    live->regulatory_profile_rev = 2u;
    fill_id(&live->site_assignment_id, 0x30u);
    live->site_assignment_rev = 3u;
    live->site_assignment_epoch = 100u;
    fill_id(&live->transmitter_id, 0x40u);
    live->channel_id = 7u;
    live->phy.bandwidth_hz = 125000u;
    live->phy.spreading_factor = 7u;
    live->phy.coding_rate_denom = 5u;
    live->phy.preamble_symbols = 8u;
    live->phy.tx_power_mdb = 13000;
    live->max_airtime_us = 50000u;

    permit->hardware_profile_id = live->hardware_profile_id;
    permit->hardware_profile_rev = live->hardware_profile_rev;
    permit->regulatory_profile_id = live->regulatory_profile_id;
    permit->regulatory_profile_rev = live->regulatory_profile_rev;
    permit->site_assignment_id = live->site_assignment_id;
    permit->site_assignment_rev = live->site_assignment_rev;
    permit->site_assignment_epoch = live->site_assignment_epoch;
    permit->transmitter_id = live->transmitter_id;
    permit->channel_id = live->channel_id;
    permit->phy = live->phy;
    permit->frame_byte_length = frame_len;
    permit->max_airtime_us = live->max_airtime_us;
    permit->not_before_ms = 1000u;
    permit->expiry_ms = 2000u;
    permit->permit_sequence = seq;
    ninlil_radio_hal_spy_digest_fold(frame, frame_len, permit->frame_digest);
    permit->frame_digest_algorithm = 0u;
}

static int setup_ready(
    ninlil_radio_hal_object_t *obj,
    ninlil_radio_hal_t **out_rh,
    ninlil_radio_hal_spy_t *spy,
    ninlil_radio_hal_live_binding_t *live)
{
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_t *rh = NULL;

    ninlil_radio_hal_spy_init(spy);
    /*
     * First init requires semantic member-zero (OBJECT_INIT / member zero).
     * Stack reuse after ACTIVE would be INVALID_STATE without zero or SHUTDOWN.
     */
    (void)memset(obj, 0, sizeof(*obj));
    REQUIRE(ninlil_radio_hal_init_object(obj, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_edge(
            rh, ninlil_radio_hal_spy_edge_ops(), spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(
            rh, ninlil_radio_hal_spy_permit_ops(), spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_digest_ops(
            rh, ninlil_radio_hal_spy_digest_ops(), spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_set_live_binding(rh, live, &err)
        == NINLIL_RADIO_HAL_OK);
    *out_rh = rh;
    return 0;
}

static int test_object_ceilings(void)
{
    ninlil_radio_hal_object_t stack_obj = NINLIL_RADIO_HAL_OBJECT_INIT;

    REQUIRE(ninlil_radio_hal_object_size() <= NINLIL_RADIO_HAL_OBJECT_BYTES);
    REQUIRE(ninlil_radio_hal_object_size() == sizeof(ninlil_radio_hal_t));
    REQUIRE(NINLIL_RADIO_HAL_OBJECT_BYTES == 2048u);
    /* Actual type align — not a hard-coded 8 if the type requires more. */
    REQUIRE(
        ninlil_radio_hal_object_align() == _Alignof(ninlil_radio_hal_t));
    REQUIRE(
        ninlil_radio_hal_object_align()
        == _Alignof(ninlil_radio_hal_object_t));
    REQUIRE(
        ninlil_radio_hal_object_align() >= NINLIL_RADIO_HAL_OBJECT_ALIGN);
    REQUIRE(NINLIL_RADIO_HAL_MAX_FRAME_BYTES == 256u);
    /* Type-level alignment: stack object must satisfy actual + minimum. */
    REQUIRE(_Alignof(ninlil_radio_hal_object_t) >= NINLIL_RADIO_HAL_OBJECT_ALIGN);
    REQUIRE(
        ((uintptr_t)&stack_obj % ninlil_radio_hal_object_align()) == 0u);
    REQUIRE(
        ((uintptr_t)(void *)&stack_obj % NINLIL_RADIO_HAL_OBJECT_ALIGN)
        == 0u);
    REQUIRE(sizeof(ninlil_radio_hal_object_t) == sizeof(ninlil_radio_hal_t));
    REQUIRE(sizeof(ninlil_radio_hal_t) <= NINLIL_RADIO_HAL_OBJECT_BYTES);
    return 0;
}

static int test_default_deny(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x01, 0x02, 0x03};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_stats_t stats;

    ninlil_radio_hal_spy_init(&spy);
    fill_live_and_permit(&live, &permit, frame_bytes, 3u, 1u);
    frame.bytes = frame_bytes;
    frame.length = 3u;

    REQUIRE(ninlil_radio_hal_init_object(&obj, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_edge(
            rh, ninlil_radio_hal_spy_edge_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_DEFAULT_DENY);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.validate_calls == 0u);
    ninlil_radio_hal_stats(rh, &stats);
    REQUIRE(stats.default_deny == 1u);
    REQUIRE(stats.edge_calls == 0u);
    return 0;
}

static int test_null_zero_oversize(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[8];
    uint8_t big[NINLIL_RADIO_HAL_MAX_FRAME_BYTES + 1u];
    ninlil_radio_hal_frame_view_t frame;

    (void)memset(frame_bytes, 0xAB, sizeof(frame_bytes));
    (void)memset(big, 0xCD, sizeof(big));
    fill_live_and_permit(&live, &permit, frame_bytes, 8u, 2u);
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    frame.bytes = frame_bytes;
    frame.length = 8u;

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(NULL, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, NULL, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, NULL, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);

    frame.length = 0u;
    permit.frame_byte_length = 0u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);

    frame.bytes = big;
    frame.length = NINLIL_RADIO_HAL_MAX_FRAME_BYTES + 1u;
    permit.frame_byte_length = frame.length;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);

    frame.bytes = frame_bytes;
    frame.length = 8u;
    permit.frame_byte_length = 7u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);

    REQUIRE(spy.edge_calls == 0u);
    return 0;
}

static int test_validator_deny_error(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x11, 0x22};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, 3u);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    spy.next_validate_status = NINLIL_RADIO_HAL_PERMIT_DENIED;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_PERMIT_DENIED);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.consume_calls == 0u);

    spy.next_validate_status = NINLIL_RADIO_HAL_PERMIT_ERROR;
    permit.permit_sequence = 4u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_PERMIT_ERROR);
    REQUIRE(spy.edge_calls == 0u);
    return 0;
}

static int test_consume_deny_error(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x33, 0x44, 0x55};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 3u, 5u);
    frame.bytes = frame_bytes;
    frame.length = 3u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* CONSUME_DENIED = definitely unconsumed; same seq may retry. */
    spy.next_consume_status = NINLIL_RADIO_HAL_CONSUME_DENIED;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_CONSUME_DENIED);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.validate_calls == 1u);

    spy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);

    /* CONSUME_ERROR = terminal fenced (not commit-unknown); same seq no TX. */
    spy.next_consume_status = NINLIL_RADIO_HAL_CONSUME_ERROR;
    permit.permit_sequence = 6u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 3u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_CONSUME_ERROR);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_CONSUME_FENCED);
    REQUIRE(spy.edge_calls == 1u);

    spy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_consume_fenced_no_retry(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x71};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 7u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    spy.next_consume_status = NINLIL_RADIO_HAL_CONSUME_FENCED;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_CONSUME_FENCED);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_CONSUME_FENCED);
    REQUIRE(spy.edge_calls == 0u);

    spy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 0u);

    permit.permit_sequence = 8u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_success_exactly_once(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_stats_t stats;

    fill_live_and_permit(&live, &permit, frame_bytes, 4u, 10u);
    frame.bytes = frame_bytes;
    frame.length = 4u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    REQUIRE(spy.validate_calls == 1u);
    REQUIRE(spy.consume_calls == 1u);
    /* Pre-consume digest only; no post-consume external digest callback. */
    REQUIRE(spy.digest_calls == 1u);
    /* Callback-observed order: DIGEST→PERMIT_CHECK→CONSUME→EDGE, each ×1. */
    REQUIRE(ninlil_radio_hal_spy_trace_has_order_success(&spy));
    REQUIRE(spy.last_edge_length == 4u);
    REQUIRE(spy.last_edge_permit_seq == 10u);
    ninlil_radio_hal_stats(rh, &stats);
    REQUIRE(stats.success == 1u);
    REQUIRE(stats.edge_calls == 1u);
    REQUIRE(stats.edge_ok == 1u);
    return 0;
}

static int test_oneshot_replay_deny(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x01, 0x02};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, 10u);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);

    /* Same sequence reuse. */
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 1u);

    /* Monotonic advance then lower-sequence replay must also be edge 0. */
    permit.permit_sequence = 11u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 2u);

    permit.permit_sequence = 10u; /* <= last (11) */
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 2u);
    return 0;
}

static int test_callback_reentry(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xAA, 0xBB};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, 12u);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    spy.reenter_hal = rh;
    spy.reenter_permit = permit;
    spy.reenter_permit.permit_sequence = 99u;
    spy.reenter_frame = frame;
    spy.reenter_transmit_on_validate = 1u;

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.reenter_status_seen == NINLIL_RADIO_HAL_BUSY);
    REQUIRE(spy.edge_calls == 1u); /* outer only; reentry must not edge */
    return 0;
}

static int test_frame_mutation_fail_closed(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x10, 0x20, 0x30};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 3u, 13u);
    frame.bytes = frame_bytes;
    frame.length = 3u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    spy.mutate_frame_on_consume = 1u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_FRAME_MISMATCH);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.consume_calls == 1u); /* consume already happened */
    return 0;
}

static int test_live_field_mismatches(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t bad;
    uint8_t frame_bytes[] = {0x01};
    ninlil_radio_hal_frame_view_t frame;
    uint64_t seq = 20u;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, seq);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

#define RUN_MISMATCH(mut_block, expect_reason)                                 \
    do {                                                                       \
        ninlil_radio_hal_stats_t st_before;                                    \
        ninlil_radio_hal_stats_t st_after;                                     \
        bad = permit;                                                          \
        bad.permit_sequence = ++seq;                                           \
        mut_block;                                                             \
        ninlil_radio_hal_spy_digest_fold(                                      \
            frame_bytes, 1u, bad.frame_digest);                                \
        ninlil_radio_hal_stats(rh, &st_before);                                \
        REQUIRE(                                                               \
            ninlil_radio_hal_transmit_with_permit(                             \
                rh, &bad, &frame, &err)                                        \
            == NINLIL_RADIO_HAL_LIVE_MISMATCH);                                \
        REQUIRE(err.reason == (expect_reason));                                \
        REQUIRE(spy.edge_calls == 0u);                                         \
        ninlil_radio_hal_stats(rh, &st_after);                                 \
        /* Exactly one live_mismatch per field (no double sat_inc). */         \
        REQUIRE(st_after.live_mismatch == st_before.live_mismatch + 1u);       \
    } while (0)

    RUN_MISMATCH(bad.hardware_profile_id.bytes[0] ^= 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_HW_ID);
    RUN_MISMATCH(bad.hardware_profile_rev += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_HW_REV);
    RUN_MISMATCH(bad.regulatory_profile_id.bytes[0] ^= 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_REG_ID);
    RUN_MISMATCH(bad.regulatory_profile_rev += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_REG_REV);
    RUN_MISMATCH(bad.site_assignment_id.bytes[0] ^= 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_SITE_ID);
    RUN_MISMATCH(bad.site_assignment_rev += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_SITE_REV);
    RUN_MISMATCH(bad.site_assignment_epoch += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_SITE_EPOCH);
    RUN_MISMATCH(bad.transmitter_id.bytes[0] ^= 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_TX_ID);
    RUN_MISMATCH(bad.channel_id += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_CHANNEL);
    RUN_MISMATCH(bad.phy.spreading_factor += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_PHY);
    RUN_MISMATCH(bad.max_airtime_us += 1u,
        NINLIL_RADIO_HAL_REASON_LIVE_AIRTIME);

#undef RUN_MISMATCH
    return 0;
}

static int test_time_boundaries(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x09};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 40u);
    /* not_before=1000, expiry=2000 — enforced by spy ctx clock, not caller. */
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    spy.clock_ms = 999u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(
            rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_NOT_BEFORE);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.last_validate_clock_ms == 999u);

    spy.clock_ms = 1000u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(
            rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    REQUIRE(spy.last_consume_clock_ms == 1000u);

    permit.permit_sequence = 41u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
    spy.clock_ms = 2000u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(
            rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_EXPIRED);
    REQUIRE(spy.edge_calls == 1u);

    permit.permit_sequence = 42u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
    spy.clock_ms = 1999u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(
            rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 2u);
    return 0;
}

static int test_edge_error_no_reuse(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x77};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 50u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    spy.next_edge_status = NINLIL_RADIO_HAL_EDGE_ERROR;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_EDGE_ERROR);
    REQUIRE(spy.edge_calls == 1u);

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_counter_saturation(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x01};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_stats_t stats;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 60u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* Force attempts counter to near-max via repeated default path is slow;
     * instead verify sat_add helper and that stats remain well-defined. */
    REQUIRE(ninlil_radio_hal_sat_add_u64(UINT64_MAX, 1u) == UINT64_MAX);
    REQUIRE(ninlil_radio_hal_sat_add_u64(UINT64_MAX - 1u, 1u) == UINT64_MAX);
    REQUIRE(ninlil_radio_hal_sat_add_u64(5u, 7u) == 12u);

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    ninlil_radio_hal_stats(rh, &stats);
    REQUIRE(stats.attempts == 1u);
    REQUIRE(stats.success == 1u);
    return 0;
}

static int test_spy_trace_overflow(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x02};
    ninlil_radio_hal_frame_view_t frame;
    uint64_t i;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 100u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* 3 events/TX (check, consume, edge); 30*3 > TRACE_CAP(64). */
    for (i = 0u; i < 30u; ++i) {
        permit.permit_sequence = 100u + i;
        ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_OK);
    }
    REQUIRE(ninlil_radio_hal_spy_trace_overflowed(&spy));
    REQUIRE(
        ninlil_radio_hal_spy_trace_count(&spy)
        == NINLIL_RADIO_HAL_SPY_TRACE_CAP);
    REQUIRE(spy.edge_calls == 30u);
    return 0;
}

static int test_unbound_edge(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x03};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 200u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    ninlil_radio_hal_spy_init(&spy);
    (void)memset(&obj, 0, sizeof(obj));
    REQUIRE(ninlil_radio_hal_init_object(&obj, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(
            rh, ninlil_radio_hal_spy_permit_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_DEFAULT_DENY);
    REQUIRE(spy.edge_calls == 0u);
    return 0;
}

static int test_shutdown_blocks_tx(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x04};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 201u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    REQUIRE(ninlil_radio_hal_shutdown(rh, &err) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(spy.edge_calls == 0u);
    return 0;
}


static int test_seq_exhausted_after_max(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x5A};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, UINT64_MAX);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);

    /* Any further sequence is fail-closed after UINT64_MAX watermark. */
    permit.permit_sequence = 1u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_EXHAUSTED);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_clear_authorities_default_deny(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x0C};
    ninlil_radio_hal_frame_view_t frame;
    uint64_t seq = 70u;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, seq);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* Clear live after bind. */
    REQUIRE(ninlil_radio_hal_set_live_binding(rh, NULL, &err) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_DEFAULT_DENY);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_UNBOUND_LIVE);

    REQUIRE(ninlil_radio_hal_set_live_binding(rh, &live, &err) == NINLIL_RADIO_HAL_OK);

    /* Clear digest. */
    REQUIRE(
        ninlil_radio_hal_bind_digest_ops(rh, NULL, NULL, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_DEFAULT_DENY);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_UNBOUND_DIGEST);

    REQUIRE(
        ninlil_radio_hal_bind_digest_ops(
            rh, ninlil_radio_hal_spy_digest_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);

    /* Clear permit ops. */
    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(rh, NULL, NULL, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_DEFAULT_DENY);
    REQUIRE(spy.edge_calls == 0u);

    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(
            rh, ninlil_radio_hal_spy_permit_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);

    /* Clear edge. */
    REQUIRE(ninlil_radio_hal_bind_edge(rh, NULL, NULL, &err) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_DEFAULT_DENY);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_UNBOUND_EDGE);
    return 0;
}

static int test_plan_mutation_records_seal_seq(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x10, 0x20, 0x30};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 3u, 80u);
    frame.bytes = frame_bytes;
    frame.length = 3u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* Mutate working plan frame during consume; sealed seq 80 must watermark. */
    spy.mutate_frame_on_consume = 1u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_FRAME_MISMATCH);
    REQUIRE(spy.edge_calls == 0u);

    /* Replay sealed seq and lower must fail closed without edge. */
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 0u);

    permit.permit_sequence = 79u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 3u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 0u);

    /* Monotonic next still allowed. */
    spy.mutate_frame_on_consume = 0u;
    permit.permit_sequence = 81u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 3u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

/*
 * Closed partition of consume return statuses (no plan mutation):
 *   CONSUME_DENIED → no burn, same-seq retry OK, edge 0
 *   PERMIT_DENIED / DEFAULT_DENY / PERMIT_ERROR / NOT_BEFORE / EXPIRED /
 *   FENCED / ERROR / SEQ_REUSE / unknown / others → burn, SEQ_REUSE on replay
 * Pre-consume NOT_BEFORE/EXPIRED (validate-stage time) are covered elsewhere
 * and leave watermark unchanged; here statuses are returned FROM consume.
 */
static int test_consume_status_closed_partition(void)
{
    typedef struct {
        ninlil_radio_hal_status_t consume_st;
        int retryable; /* 1 = CONSUME_DENIED only */
        ninlil_radio_hal_status_t expect_tx; /* first TX status */
    } row_t;

    static const row_t k_rows[] = {
        {NINLIL_RADIO_HAL_CONSUME_DENIED, 1, NINLIL_RADIO_HAL_CONSUME_DENIED},
        {NINLIL_RADIO_HAL_PERMIT_DENIED, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_DEFAULT_DENY, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_PERMIT_ERROR, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_NOT_BEFORE, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_EXPIRED, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_CONSUME_FENCED, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_CONSUME_ERROR, 0, NINLIL_RADIO_HAL_CONSUME_ERROR},
        {NINLIL_RADIO_HAL_SEQ_REUSE, 0, NINLIL_RADIO_HAL_SEQ_REUSE},
        {NINLIL_RADIO_HAL_UNSUPPORTED, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_BUSY, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_INVALID_STATE, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_INVALID_ARGUMENT, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_EDGE_ERROR, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_LIVE_MISMATCH, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_SEQ_EXHAUSTED, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_FRAME_MISMATCH, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {(ninlil_radio_hal_status_t)0xA5A5u, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {(ninlil_radio_hal_status_t)0xFFFFu, 0, NINLIL_RADIO_HAL_CONSUME_FENCED},
        {NINLIL_RADIO_HAL_OK, 0, NINLIL_RADIO_HAL_OK}, /* burns + edge 1 */
    };
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xB0, 0x0B};
    ninlil_radio_hal_frame_view_t frame;
    size_t i;
    uint64_t seq_base = 1500u;
    uint64_t edge_before;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, seq_base);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    for (i = 0u; i < (sizeof(k_rows) / sizeof(k_rows[0])); ++i) {
        uint64_t seq = seq_base + (uint64_t)i;
        ninlil_radio_hal_status_t st;

        permit.permit_sequence = seq;
        ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
        spy.next_consume_status = k_rows[i].consume_st;
        spy.mutate_frame_on_consume = 0u;
        edge_before = spy.edge_calls;
        st = ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err);
        REQUIRE(st == k_rows[i].expect_tx);

        if (k_rows[i].consume_st == NINLIL_RADIO_HAL_OK) {
            REQUIRE(spy.edge_calls == edge_before + 1u);
            /* Burned by success: replay SEQ_REUSE, no second edge. */
            spy.next_consume_status = NINLIL_RADIO_HAL_OK;
            REQUIRE(
                ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
                == NINLIL_RADIO_HAL_SEQ_REUSE);
            REQUIRE(spy.edge_calls == edge_before + 1u);
        } else if (k_rows[i].retryable != 0) {
            REQUIRE(spy.edge_calls == edge_before);
            spy.next_consume_status = NINLIL_RADIO_HAL_OK;
            REQUIRE(
                ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
                == NINLIL_RADIO_HAL_OK);
            REQUIRE(spy.edge_calls == edge_before + 1u);
        } else {
            REQUIRE(spy.edge_calls == edge_before);
            spy.next_consume_status = NINLIL_RADIO_HAL_OK;
            REQUIRE(
                ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
                == NINLIL_RADIO_HAL_SEQ_REUSE);
            REQUIRE(spy.edge_calls == edge_before);
        }
    }

    /*
     * Pre-consume time reject (validate-stage): consume not entered; watermark
     * unchanged; same seq succeeds after clock advances. Distinct from
     * consume-return NOT_BEFORE (which burns in the table above).
     */
    {
        uint64_t seq =
            seq_base + (uint64_t)(sizeof(k_rows) / sizeof(k_rows[0])) + 10u;
        uint64_t consume_before;

        permit.permit_sequence = seq;
        ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
        spy.next_consume_status = NINLIL_RADIO_HAL_OK;
        spy.clock_ms = 999u; /* fill_live uses not_before=1000 */
        edge_before = spy.edge_calls;
        consume_before = spy.consume_calls;
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_NOT_BEFORE);
        REQUIRE(spy.edge_calls == edge_before);
        REQUIRE(spy.consume_calls == consume_before);
        REQUIRE(spy.last_validate_clock_ms == 999u);
        spy.clock_ms = 1500u;
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_OK);
        REQUIRE(spy.edge_calls == edge_before + 1u);
    }
    return 0;
}

/*
 * Consume callback plan mutation is a contract fault: every return status
 * (including DENIED / NOT_BEFORE / unknown) terminal-burns sealed seq, edge 0.
 * Only non-mutation CONSUME_DENIED remains same-seq retry-eligible.
 */
static int test_consume_status_plan_mutation_burns_all(void)
{
    static const ninlil_radio_hal_status_t k_statuses[] = {
        NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_CONSUME_DENIED,
        NINLIL_RADIO_HAL_PERMIT_DENIED,
        NINLIL_RADIO_HAL_NOT_BEFORE,
        NINLIL_RADIO_HAL_EXPIRED,
        NINLIL_RADIO_HAL_CONSUME_FENCED,
        NINLIL_RADIO_HAL_CONSUME_ERROR,
        NINLIL_RADIO_HAL_SEQ_REUSE,
        NINLIL_RADIO_HAL_UNSUPPORTED,
        NINLIL_RADIO_HAL_DEFAULT_DENY,
        NINLIL_RADIO_HAL_BUSY,
        NINLIL_RADIO_HAL_INVALID_STATE,
        NINLIL_RADIO_HAL_INVALID_ARGUMENT,
        NINLIL_RADIO_HAL_PERMIT_ERROR,
        NINLIL_RADIO_HAL_EDGE_ERROR,
        NINLIL_RADIO_HAL_LIVE_MISMATCH,
        NINLIL_RADIO_HAL_SEQ_EXHAUSTED,
        (ninlil_radio_hal_status_t)0xA5A5u, /* unknown non-catalog */
        (ninlil_radio_hal_status_t)0xFFFFu,
    };
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xC0, 0xDE};
    ninlil_radio_hal_frame_view_t frame;
    size_t i;
    uint64_t seq_base = 900u;
    uint64_t edge_before;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, seq_base);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    for (i = 0u; i < (sizeof(k_statuses) / sizeof(k_statuses[0])); ++i) {
        uint64_t seq = seq_base + (uint64_t)i;

        permit.permit_sequence = seq;
        ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
        spy.next_consume_status = k_statuses[i];
        spy.mutate_frame_on_consume = 1u;
        edge_before = spy.edge_calls;
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_FRAME_MISMATCH);
        REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_PLAN_MUTATED);
        REQUIRE(spy.edge_calls == edge_before);

        /* Same seq must not authorize TX after mutation burn (incl. DENIED). */
        spy.next_consume_status = NINLIL_RADIO_HAL_OK;
        spy.mutate_frame_on_consume = 0u;
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_SEQ_REUSE);
        REQUIRE(spy.edge_calls == edge_before);
    }

    /*
     * Control: non-mutation CONSUME_DENIED remains retry-eligible (same seq).
     * Uses a fresh sequence above the table watermark ceiling.
     */
    permit.permit_sequence =
        seq_base + (uint64_t)(sizeof(k_statuses) / sizeof(k_statuses[0])) + 1u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
    spy.next_consume_status = NINLIL_RADIO_HAL_CONSUME_DENIED;
    spy.mutate_frame_on_consume = 0u;
    edge_before = spy.edge_calls;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_CONSUME_DENIED);
    REQUIRE(spy.edge_calls == edge_before);
    spy.next_consume_status = NINLIL_RADIO_HAL_OK;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == edge_before + 1u);
    return 0;
}

static int test_alias_out_error_with_permit(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t permit_before;
    uint8_t frame_bytes[] = {0xAB};
    uint8_t frame_before[1];
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t *alias_err;
    ninlil_radio_hal_error_t last;
    ninlil_radio_hal_stats_t stats_before;
    ninlil_radio_hal_stats_t stats_after;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 90u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    memcpy(&permit_before, &permit, sizeof(permit_before));
    frame_before[0] = frame_bytes[0];
    ninlil_radio_hal_stats(rh, &stats_before);

    /* Abuse: out_error aliases into permit snapshot storage. */
    alias_err = (ninlil_radio_hal_error_t *)(void *)&permit;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, alias_err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    /* Exact zero mutation of caller permit / frame; unsafe out_error not written. */
    REQUIRE(memcmp(&permit, &permit_before, sizeof(permit)) == 0);
    REQUIRE(frame_bytes[0] == frame_before[0]);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.validate_calls == 0u);
    ninlil_radio_hal_last_error(rh, &last);
    REQUIRE(last.status == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(last.reason == NINLIL_RADIO_HAL_REASON_ALIAS);
    ninlil_radio_hal_stats(rh, &stats_after);
    REQUIRE(stats_after.alias_reject == stats_before.alias_reject + 1u);
    /* (A) before attempt entry: attempts unchanged. */
    REQUIRE(stats_after.attempts == stats_before.attempts);
    /* Lifecycle remains active: a later non-aliased TX may proceed. */
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &last)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_alias_frame_with_hal_storage(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t permit_before;
    ninlil_radio_hal_frame_view_t frame;
    uint8_t safe_frame[] = {0x11};
    uint8_t *hal_bytes;

    fill_live_and_permit(&live, &permit, (const uint8_t *)"x", 1u, 91u);
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    memcpy(&permit_before, &permit, sizeof(permit_before));
    /* Point frame bytes into HAL object storage (alias). */
    hal_bytes = (uint8_t *)(void *)rh;
    frame.bytes = hal_bytes;
    frame.length = 1u;
    permit.frame_byte_length = 1u;
    ninlil_radio_hal_spy_digest_fold(hal_bytes, 1u, permit.frame_digest);

    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_ALIAS);
    REQUIRE(spy.edge_calls == 0u);
    /* Permit caller snapshot was only mutated by our local digest write above
     * before the call; lifecycle still active for a clean TX. */
    frame.bytes = safe_frame;
    frame.length = 1u;
    memcpy(&permit, &permit_before, sizeof(permit));
    permit.frame_byte_length = 1u;
    permit.permit_sequence = 91u;
    ninlil_radio_hal_spy_digest_fold(safe_frame, 1u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_shutdown_clears_plan_and_watermark(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x42};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 55u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);

    REQUIRE(ninlil_radio_hal_shutdown(rh, &err) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_STATE);

    /* New init_object: watermark domain restarts; same seq allowed. */
    REQUIRE(ninlil_radio_hal_init_object(&obj, &rh) == NINLIL_RADIO_HAL_OK);
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    permit.permit_sequence = 55u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_huge_length_rejected_before_range_math(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t permit_before;
    uint8_t frame_bytes[1] = {0x01};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_stats_t stats_before;
    ninlil_radio_hal_stats_t stats_after;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 56u);
    frame.bytes = frame_bytes;
    /* Intentionally huge length: must fail OVERSIZE without UB range math. */
    frame.length = UINT32_MAX;
    permit.frame_byte_length = UINT32_MAX;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    memcpy(&permit_before, &permit, sizeof(permit_before));
    ninlil_radio_hal_stats(rh, &stats_before);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_OVERSIZE);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(memcmp(&permit, &permit_before, sizeof(permit)) == 0);
    ninlil_radio_hal_stats(rh, &stats_after);
    REQUIRE(stats_after.success == stats_before.success);
    REQUIRE(stats_after.edge_calls == stats_before.edge_calls);
    return 0;
}

/* (A) frame-view object itself overlaps HAL — before any field dereference. */
static int test_alias_frame_view_in_hal(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t permit_before;
    const ninlil_radio_hal_frame_view_t *evil_frame;
    uint8_t frame_bytes[] = {0x01};
    ninlil_radio_hal_stats_t stats_before;
    ninlil_radio_hal_stats_t stats_after;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 57u);
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    memcpy(&permit_before, &permit, sizeof(permit_before));
    ninlil_radio_hal_stats(rh, &stats_before);
    evil_frame = (const ninlil_radio_hal_frame_view_t *)(const void *)rh;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, evil_frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_ALIAS);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.validate_calls == 0u);
    REQUIRE(memcmp(&permit, &permit_before, sizeof(permit)) == 0);
    ninlil_radio_hal_stats(rh, &stats_after);
    /* (A) fails before attempt entry: attempts must not advance. */
    REQUIRE(stats_after.attempts == stats_before.attempts);
    REQUIRE(stats_after.alias_reject == stats_before.alias_reject + 1u);
    return 0;
}

/* (A) permit object overlaps HAL. */
static int test_alias_permit_in_hal(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t *evil_permit;
    uint8_t frame_bytes[] = {0x02};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_stats_t stats_before;
    ninlil_radio_hal_stats_t stats_after;
    ninlil_radio_hal_permit_snapshot_t permit_scratch;

    fill_live_and_permit(&live, &permit_scratch, frame_bytes, 1u, 58u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    ninlil_radio_hal_stats(rh, &stats_before);
    evil_permit =
        (ninlil_radio_hal_permit_snapshot_t *)(void *)rh;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, evil_permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_ALIAS);
    REQUIRE(spy.edge_calls == 0u);
    REQUIRE(spy.validate_calls == 0u);
    ninlil_radio_hal_stats(rh, &stats_after);
    REQUIRE(stats_after.attempts == stats_before.attempts);
    REQUIRE(stats_after.alias_reject == stats_before.alias_reject + 1u);
    return 0;
}

/* (A) out_error overlaps frame-view object; length 0 must not be the reason. */
static int test_alias_out_error_in_frame_view(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t permit_before;
    uint8_t frame_bytes[] = {0x03};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_frame_view_t frame_before;
    ninlil_radio_hal_error_t *alias_err;
    ninlil_radio_hal_error_t last;
    ninlil_radio_hal_stats_t stats_before;
    ninlil_radio_hal_stats_t stats_after;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 59u);
    frame.bytes = frame_bytes;
    frame.length = 0u; /* would be ZERO_LENGTH if alias were not first */
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    memcpy(&permit_before, &permit, sizeof(permit_before));
    frame_before = frame;
    ninlil_radio_hal_stats(rh, &stats_before);
    alias_err = (ninlil_radio_hal_error_t *)(void *)&frame;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, alias_err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(memcmp(&permit, &permit_before, sizeof(permit)) == 0);
    REQUIRE(frame.bytes == frame_before.bytes);
    REQUIRE(frame.length == frame_before.length);
    REQUIRE(spy.edge_calls == 0u);
    ninlil_radio_hal_last_error(rh, &last);
    REQUIRE(last.reason == NINLIL_RADIO_HAL_REASON_ALIAS);
    ninlil_radio_hal_stats(rh, &stats_after);
    REQUIRE(stats_after.attempts == stats_before.attempts);
    return 0;
}

/* Zero-length after (A): authority fields unchanged except stats/last_error. */
static int test_zero_length_authority_zero_mutation(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_permit_snapshot_t permit_before;
    uint8_t frame_bytes[] = {0x04};
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_stats_t stats_before;
    ninlil_radio_hal_stats_t stats_after;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 60u);
    frame.bytes = frame_bytes;
    frame.length = 0u;
    permit.frame_byte_length = 0u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    memcpy(&permit_before, &permit, sizeof(permit_before));
    ninlil_radio_hal_stats(rh, &stats_before);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_ZERO_LENGTH);
    REQUIRE(memcmp(&permit, &permit_before, sizeof(permit)) == 0);
    REQUIRE(spy.edge_calls == 0u);
    ninlil_radio_hal_stats(rh, &stats_after);
    REQUIRE(stats_after.edge_calls == stats_before.edge_calls);
    REQUIRE(stats_after.success == stats_before.success);
    REQUIRE(stats_after.permit_consume_ok == stats_before.permit_consume_ok);
    /* Later valid TX proves lifecycle/live/ops still bound. */
    frame.length = 1u;
    permit.frame_byte_length = 1u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 1u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

static int test_structural_zero_id_and_live(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x01};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 92u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* Zero hardware profile id is not a valid identity. */
    (void)memset(permit.hardware_profile_id.bytes, 0, NINLIL_RADIO_HAL_ID_BYTES);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_ZERO_ID);
    REQUIRE(spy.edge_calls == 0u);

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 93u);
    permit.phy.bandwidth_hz = 0u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_STRUCT_INVALID);
    REQUIRE(spy.edge_calls == 0u);

    /* Live structural reject at set. */
    live.reserved_zero = 1u;
    REQUIRE(
        ninlil_radio_hal_set_live_binding(rh, &live, &err)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_STRUCT_INVALID);
    return 0;
}

static int test_working_plan_mutation_on_validate_fail_closed(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xDE, 0xAD};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, 94u);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* Mutate caller buffer during validate; edge must still see sealed copy. */
    spy.mutate_frame_on_validate = 1u;
    /*
     * Mutating through the plan pointer (working) is detected; mutating only
     * the original caller buffer is done by overwriting after we cannot.
     * Here spy mutates the working plan -> PLAN_MUTATED / FRAME_MISMATCH.
     */
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_FRAME_MISMATCH);
    REQUIRE(spy.edge_calls == 0u);

    /* Fresh attempt without mutation: original caller bytes still work. */
    spy.mutate_frame_on_validate = 0u;
    frame_bytes[0] = 0xDEu;
    frame_bytes[1] = 0xADu;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
    permit.permit_sequence = 95u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    REQUIRE(spy.last_edge_sample[0] == 0xDEu);
    REQUIRE(spy.last_edge_sample[1] == 0xADu);
    return 0;
}


/*
 * Seal immutability: authority callbacks mutate working plan and return OK;
 * every case must yield FRAME_MISMATCH / PLAN_MUTATED and edge_calls==0.
 * Proves seal is never handed to digest/validate/consume for silent TX of
 * mutated content.
 */
static int test_mutation_authority_callbacks_edge_zero(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x10, 0x20, 0x30, 0x40};
    ninlil_radio_hal_frame_view_t frame;
    uint64_t seq = 200u;
    ninlil_radio_hal_stats_t stats;

    fill_live_and_permit(&live, &permit, frame_bytes, 4u, seq);
    frame.bytes = frame_bytes;
    frame.length = 4u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

#define RUN_MUT(flag_stmt)                                                     \
    do {                                                                       \
        ninlil_radio_hal_spy_init(&spy);                                       \
        spy.clock_ms = 1500u;                                                  \
        REQUIRE(                                                               \
            ninlil_radio_hal_bind_edge(                                        \
                rh, ninlil_radio_hal_spy_edge_ops(), &spy, &err)               \
            == NINLIL_RADIO_HAL_OK);                                           \
        REQUIRE(                                                               \
            ninlil_radio_hal_bind_permit_ops(                                  \
                rh, ninlil_radio_hal_spy_permit_ops(), &spy, &err)             \
            == NINLIL_RADIO_HAL_OK);                                           \
        REQUIRE(                                                               \
            ninlil_radio_hal_bind_digest_ops(                                  \
                rh, ninlil_radio_hal_spy_digest_ops(), &spy, &err)             \
            == NINLIL_RADIO_HAL_OK);                                           \
        REQUIRE(                                                               \
            ninlil_radio_hal_set_live_binding(rh, &live, &err)                 \
            == NINLIL_RADIO_HAL_OK);                                           \
        seq += 1u;                                                             \
        permit.permit_sequence = seq;                                          \
        frame_bytes[0] = 0x10u;                                                \
        frame_bytes[1] = 0x20u;                                                \
        frame_bytes[2] = 0x30u;                                                \
        frame_bytes[3] = 0x40u;                                                \
        ninlil_radio_hal_spy_digest_fold(                                      \
            frame_bytes, 4u, permit.frame_digest);                             \
        flag_stmt;                                                             \
        REQUIRE(                                                               \
            ninlil_radio_hal_transmit_with_permit(                             \
                rh, &permit, &frame, &err)                                     \
            == NINLIL_RADIO_HAL_FRAME_MISMATCH);                                \
        REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_PLAN_MUTATED);            \
        REQUIRE(spy.edge_calls == 0u);                                         \
        ninlil_radio_hal_stats(rh, &stats);                                    \
        REQUIRE(stats.edge_calls == 0u || stats.edge_ok < stats.attempts);     \
    } while (0)

    /* Digest returns OK after mutating working frame. */
    RUN_MUT(spy.mutate_frame_on_digest = 1u);

    /* Validate mutates frame. */
    RUN_MUT(spy.mutate_frame_on_validate = 1u);

    /* Validate mutates permit metadata (channel/PHY). */
    RUN_MUT(spy.mutate_permit_on_validate = 1u);

    /* Consume mutates frame (and still one-shot watermarks). */
    RUN_MUT(spy.mutate_frame_on_consume = 1u);

    /* Consume mutates permit metadata. */
    RUN_MUT(spy.mutate_permit_on_consume = 1u);

    /* Both frame + permit on consume. */
    RUN_MUT({
        spy.mutate_frame_on_consume = 1u;
        spy.mutate_permit_on_consume = 1u;
    });

#undef RUN_MUT

    /* Success path: exactly one digest call (no post-consume digest). */
    ninlil_radio_hal_spy_init(&spy);
    spy.clock_ms = 1500u;
    REQUIRE(
        ninlil_radio_hal_bind_edge(
            rh, ninlil_radio_hal_spy_edge_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(
            rh, ninlil_radio_hal_spy_permit_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_digest_ops(
            rh, ninlil_radio_hal_spy_digest_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_set_live_binding(rh, &live, &err)
        == NINLIL_RADIO_HAL_OK);
    seq += 1u;
    permit.permit_sequence = seq;
    frame_bytes[0] = 0x10u;
    ninlil_radio_hal_spy_digest_fold(frame_bytes, 4u, permit.frame_digest);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.digest_calls == 1u);
    REQUIRE(spy.edge_calls == 1u);
    REQUIRE(spy.consume_calls == 1u);
    REQUIRE(spy.validate_calls == 1u);
    /* Edge saw original sealed first byte. */
    REQUIRE(spy.last_edge_sample[0] == 0x10u);
    return 0;
}


static int test_digest_error_does_not_reset_clock(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x01};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 300u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    spy.clock_ms = 1777u;
    spy.next_digest_status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_FRAME_MISMATCH);
    /* Digest error must not clobber ctx clock authority state. */
    REQUIRE(spy.clock_ms == 1777u);
    REQUIRE(spy.edge_calls == 0u);
    return 0;
}

static int test_init_out_hal_alias_object(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t **evil_out;

    evil_out = (ninlil_radio_hal_t **)(void *)&obj;
    REQUIRE(
        ninlil_radio_hal_init_object(&obj, evil_out)
        == NINLIL_RADIO_HAL_INVALID_ARGUMENT);
    return 0;
}

static int test_init_active_reinit_rejected(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_t *rh2 = NULL;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x09};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 301u);
    frame.bytes = frame_bytes;
    frame.length = 1u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    /* ACTIVE re-init forbidden (would erase watermark). */
    REQUIRE(
        ninlil_radio_hal_init_object(&obj, &rh2)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh2 == NULL);
    /* Same seq reuse still denied on original object. */
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    return 0;
}

/*
 * First init: OBJECT_INIT (member zero) and whole memset both succeed.
 * Must not depend on padding bytes being zero (C11 does not guarantee that
 * for automatic OBJECT_INIT).
 */
static int test_init_zeroed_first_ok(void)
{
    ninlil_radio_hal_object_t via_macro = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_object_t via_memset;
    ninlil_radio_hal_object_t painted;
    ninlil_radio_hal_t *rh = NULL;

    REQUIRE(
        ninlil_radio_hal_init_object(&via_macro, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(rh != NULL);
    REQUIRE(rh == &via_macro);

    rh = NULL;
    (void)memset(&via_memset, 0, sizeof(via_memset));
    REQUIRE(
        ninlil_radio_hal_init_object(&via_memset, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(rh != NULL);

    /*
     * Representation paint then field-wise member zero (no whole-struct
     * assign): padding may remain non-zero while members are semantic-fresh.
     */
    rh = NULL;
    (void)memset(&painted, 0xA5, sizeof(painted));
    painted.magic = 0u;
    painted.lifecycle = 0u;
    painted.in_transmit = 0u;
    painted.edge_bound = 0u;
    painted.permit_bound = 0u;
    painted.digest_bound = 0u;
    painted.live_bound = 0u;
    painted.has_consumed_seq = 0u;
    painted.reserved_zero = 0u;
    painted.last_consumed_seq = 0u;
    painted.edge_ops.transmit = NULL;
    painted.edge_ctx = NULL;
    painted.permit_ops.validate = NULL;
    painted.permit_ops.consume = NULL;
    painted.permit_ctx = NULL;
    painted.digest_ops.verify = NULL;
    painted.digest_ctx = NULL;
    (void)memset(&painted.live, 0, sizeof(painted.live));
    (void)memset(&painted.plan_permit, 0, sizeof(painted.plan_permit));
    (void)memset(&painted.seal_permit, 0, sizeof(painted.seal_permit));
    (void)memset(painted.plan_frame, 0, sizeof(painted.plan_frame));
    (void)memset(painted.seal_frame, 0, sizeof(painted.seal_frame));
    painted.plan_view.bytes = NULL;
    painted.plan_view.length = 0u;
    painted.seal_view.bytes = NULL;
    painted.seal_view.length = 0u;
    (void)memset(&painted.stats, 0, sizeof(painted.stats));
    (void)memset(&painted.last_error, 0, sizeof(painted.last_error));
    REQUIRE(
        ninlil_radio_hal_init_object(&painted, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(rh == &painted);
    return 0;
}

/*
 * Stable automatic OBJECT_INIT under optimizer pressure (Release / -O2 /
 * sanitizers). Multiple independent stack objects must first-init cleanly.
 */
static int test_init_object_init_automatic_stable(void)
{
    ninlil_radio_hal_object_t a = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_object_t b = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_object_t c = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *ha = NULL;
    ninlil_radio_hal_t *hb = NULL;
    ninlil_radio_hal_t *hc = NULL;
    volatile int keep = 0;

    REQUIRE(ninlil_radio_hal_init_object(&a, &ha) == NINLIL_RADIO_HAL_OK);
    REQUIRE(ha == &a);
    keep += (ha != NULL) ? 1 : 0;
    REQUIRE(ninlil_radio_hal_init_object(&b, &hb) == NINLIL_RADIO_HAL_OK);
    REQUIRE(hb == &b);
    keep += (hb != NULL) ? 1 : 0;
    REQUIRE(ninlil_radio_hal_init_object(&c, &hc) == NINLIL_RADIO_HAL_OK);
    REQUIRE(hc == &c);
    keep += (hc != NULL) ? 1 : 0;
    REQUIRE(keep == 3);
    return 0;
}

/*
 * Lifecycle contract by real behavior (no setup_ready memset after re-init):
 *   zero-init first → ACTIVE → ACTIVE re-init reject → SHUTDOWN →
 *   direct re-init (no zero) → bind same rh → same-seq TX OK.
 */
static int test_init_shutdown_reinit_ok(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_t *rh2 = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x5A};
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 1u, 401u);
    frame.bytes = frame_bytes;
    frame.length = 1u;

    /* First init: explicit zero via OBJECT_INIT only (no setup_ready). */
    ninlil_radio_hal_spy_init(&spy);
    REQUIRE(ninlil_radio_hal_init_object(&obj, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(rh != NULL);
    REQUIRE(
        ninlil_radio_hal_bind_edge(
            rh, ninlil_radio_hal_spy_edge_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(
            rh, ninlil_radio_hal_spy_permit_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_digest_ops(
            rh, ninlil_radio_hal_spy_digest_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_set_live_binding(rh, &live, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);

    /* ACTIVE re-init rejected; original handle and watermark remain. */
    REQUIRE(
        ninlil_radio_hal_init_object(&obj, &rh2)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh2 == NULL);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_SEQ_REUSE);
    REQUIRE(spy.edge_calls == 1u);

    REQUIRE(ninlil_radio_hal_shutdown(rh, &err) == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_INVALID_STATE);

    /*
     * Direct SHUTDOWN re-init: do NOT memset / setup_ready (those zero the
     * object and hide the SHUTDOWN path). Bind and TX on the returned rh.
     */
    rh = NULL;
    REQUIRE(ninlil_radio_hal_init_object(&obj, &rh) == NINLIL_RADIO_HAL_OK);
    REQUIRE(rh != NULL);
    ninlil_radio_hal_spy_init(&spy);
    REQUIRE(
        ninlil_radio_hal_bind_edge(
            rh, ninlil_radio_hal_spy_edge_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_permit_ops(
            rh, ninlil_radio_hal_spy_permit_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_bind_digest_ops(
            rh, ninlil_radio_hal_spy_digest_ops(), &spy, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(
        ninlil_radio_hal_set_live_binding(rh, &live, &err)
        == NINLIL_RADIO_HAL_OK);
    /* New watermark domain: same seq must TX successfully. */
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    REQUIRE(spy.consume_calls == 1u);
    REQUIRE(spy.validate_calls == 1u);
    return 0;
}

/*
 * Semantic poison reject (not padding-only). Contract rejects wrong tags or
 * non-fresh members; does not promise reject on arbitrary padding bytes.
 */
static int test_init_poisoned_first_reject(void)
{
    ninlil_radio_hal_object_t poison = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_object_t active_image = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_object_t reuse;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_t *rh_active = NULL;

    /* Full-byte poison → non-zero magic tag. */
    (void)memset(&poison, 0xA5, sizeof(poison));
    rh = (ninlil_radio_hal_t *)(void *)1;
    REQUIRE(
        ninlil_radio_hal_init_object(&poison, &rh)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh == NULL);

    /* magic==0 lifecycle==ZERO but watermark member non-zero: not fresh. */
    poison = (ninlil_radio_hal_object_t)NINLIL_RADIO_HAL_OBJECT_INIT;
    poison.last_consumed_seq = 1u;
    rh = (ninlil_radio_hal_t *)(void *)1;
    REQUIRE(
        ninlil_radio_hal_init_object(&poison, &rh)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh == NULL);

    /* magic==0 lifecycle==ZERO but bound flag set. */
    poison = (ninlil_radio_hal_object_t)NINLIL_RADIO_HAL_OBJECT_INIT;
    poison.edge_bound = 1u;
    rh = (ninlil_radio_hal_t *)(void *)1;
    REQUIRE(
        ninlil_radio_hal_init_object(&poison, &rh)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh == NULL);

    /* Unknown lifecycle tag with MAGIC-looking non-MAGIC value. */
    poison = (ninlil_radio_hal_object_t)NINLIL_RADIO_HAL_OBJECT_INIT;
    poison.magic = 0x11111111u;
    poison.lifecycle = 0u;
    rh = (ninlil_radio_hal_t *)(void *)1;
    REQUIRE(
        ninlil_radio_hal_init_object(&poison, &rh)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh == NULL);

    /*
     * Stack-reuse of ACTIVE object image: memcpy a live ACTIVE object into
     * another slot. First "init" of the copy must fail as ACTIVE re-init.
     */
    REQUIRE(
        ninlil_radio_hal_init_object(&active_image, &rh_active)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(rh_active != NULL);
    (void)memcpy(&reuse, &active_image, sizeof(reuse));
    rh = (ninlil_radio_hal_t *)(void *)1;
    REQUIRE(
        ninlil_radio_hal_init_object(&reuse, &rh)
        == NINLIL_RADIO_HAL_INVALID_STATE);
    REQUIRE(rh == NULL);
    return 0;
}

/*
 * Semantic-identical permit with poisoned padding must still plan_matches_seal
 * (padding-independent compare). Then each semantic field mutation rejects.
 */
static int test_permit_semantic_equal_padding_and_fields(void)
{
    static const uint32_t k_fields[] = {
        NINLIL_RADIO_HAL_SPY_FIELD_HW_REV,
        NINLIL_RADIO_HAL_SPY_FIELD_REG_REV,
        NINLIL_RADIO_HAL_SPY_FIELD_SITE_REV,
        NINLIL_RADIO_HAL_SPY_FIELD_SITE_EPOCH,
        NINLIL_RADIO_HAL_SPY_FIELD_CHANNEL,
        NINLIL_RADIO_HAL_SPY_FIELD_PHY_BW,
        NINLIL_RADIO_HAL_SPY_FIELD_PHY_SF,
        NINLIL_RADIO_HAL_SPY_FIELD_PHY_CR,
        NINLIL_RADIO_HAL_SPY_FIELD_PHY_PREAMBLE,
        NINLIL_RADIO_HAL_SPY_FIELD_PHY_TX_POWER,
        NINLIL_RADIO_HAL_SPY_FIELD_PHY_FLAGS,
        NINLIL_RADIO_HAL_SPY_FIELD_DIGEST_ALG,
        NINLIL_RADIO_HAL_SPY_FIELD_FRAME_LEN,
        NINLIL_RADIO_HAL_SPY_FIELD_AIRTIME,
        NINLIL_RADIO_HAL_SPY_FIELD_NOT_BEFORE,
        NINLIL_RADIO_HAL_SPY_FIELD_EXPIRY,
        NINLIL_RADIO_HAL_SPY_FIELD_SEQ,
        NINLIL_RADIO_HAL_SPY_FIELD_RESERVED,
        NINLIL_RADIO_HAL_SPY_FIELD_HW_ID0,
        NINLIL_RADIO_HAL_SPY_FIELD_DIGEST0,
        NINLIL_RADIO_HAL_SPY_FIELD_TX_ID0,
    };
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0x11, 0x22};
    ninlil_radio_hal_frame_view_t frame;
    size_t i;
    uint64_t seq = 1200u;
    uint64_t edge_before;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, seq);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }

    /* Poison padding only: semantic fields restored — must still TX OK. */
    spy.poison_permit_padding_on_validate = 1u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(spy.edge_calls == 1u);
    spy.poison_permit_padding_on_validate = 0u;

    for (i = 0u; i < (sizeof(k_fields) / sizeof(k_fields[0])); ++i) {
        seq += 1u;
        permit.permit_sequence = seq;
        ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
        /* Mutate after live check: only plan_matches_seal should fail. */
        spy.mutate_permit_semantic_field = k_fields[i];
        edge_before = spy.edge_calls;
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_FRAME_MISMATCH);
        REQUIRE(err.reason == NINLIL_RADIO_HAL_REASON_PLAN_MUTATED);
        REQUIRE(spy.edge_calls == edge_before);
        spy.mutate_permit_semantic_field = NINLIL_RADIO_HAL_SPY_FIELD_NONE;
    }
    return 0;
}

static int test_callback_reentry_all_phases(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xAA, 0xBB};
    ninlil_radio_hal_frame_view_t frame;
    uint64_t seq = 310u;
    int phase;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, seq);
    frame.bytes = frame_bytes;
    frame.length = 2u;

    for (phase = 0; phase < 4; ++phase) {
        if (setup_ready(&obj, &rh, &spy, &live) != 0) {
            return 1;
        }
        seq += 1u;
        permit.permit_sequence = seq;
        ninlil_radio_hal_spy_digest_fold(frame_bytes, 2u, permit.frame_digest);
        spy.reenter_hal = rh;
        spy.reenter_permit = permit;
        spy.reenter_permit.permit_sequence = seq + 50u;
        spy.reenter_frame = frame;
        spy.reenter_transmit_on_digest = 0u;
        spy.reenter_transmit_on_validate = 0u;
        spy.reenter_transmit_on_consume = 0u;
        spy.reenter_transmit_on_edge = 0u;
        spy.reenter_status_seen = 0xFFFFFFFFu;
        if (phase == 0) {
            spy.reenter_transmit_on_digest = 1u;
        } else if (phase == 1) {
            spy.reenter_transmit_on_validate = 1u;
        } else if (phase == 2) {
            spy.reenter_transmit_on_consume = 1u;
        } else {
            spy.reenter_transmit_on_edge = 1u;
        }
        REQUIRE(
            ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
            == NINLIL_RADIO_HAL_OK);
        REQUIRE(spy.reenter_status_seen == NINLIL_RADIO_HAL_BUSY);
        /* Outer exactly one edge; nested must not add edge. */
        REQUIRE(spy.edge_calls == 1u);
        ninlil_radio_hal_shutdown(rh, &err);
    }
    return 0;
}

static int test_true_caller_buffer_mutation_isolated(void)
{
    ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
    ninlil_radio_hal_t *rh = NULL;
    ninlil_radio_hal_spy_t spy;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_snapshot_t permit;
    uint8_t frame_bytes[] = {0xDE, 0xAD};
    uint8_t original0;
    ninlil_radio_hal_frame_view_t frame;

    fill_live_and_permit(&live, &permit, frame_bytes, 2u, 320u);
    frame.bytes = frame_bytes;
    frame.length = 2u;
    original0 = frame_bytes[0];
    if (setup_ready(&obj, &rh, &spy, &live) != 0) {
        return 1;
    }
    spy.caller_frame_bytes = frame_bytes;
    spy.caller_frame_len = 2u;
    spy.mutate_caller_frame_on_validate = 1u;
    REQUIRE(
        ninlil_radio_hal_transmit_with_permit(rh, &permit, &frame, &err)
        == NINLIL_RADIO_HAL_OK);
    /* Caller buffer was mutated mid-call. */
    REQUIRE(frame_bytes[0] != original0);
    /* Edge used sealed/working copy of original bytes. */
    REQUIRE(spy.last_edge_sample[0] == original0);
    REQUIRE(spy.edge_calls == 1u);
    return 0;
}

int main(void)
{
    if (test_object_ceilings() != 0) {
        return 1;
    }
    if (test_default_deny() != 0) {
        return 1;
    }
    if (test_null_zero_oversize() != 0) {
        return 1;
    }
    if (test_validator_deny_error() != 0) {
        return 1;
    }
    if (test_consume_deny_error() != 0) {
        return 1;
    }
    if (test_consume_fenced_no_retry() != 0) {
        return 1;
    }
    if (test_success_exactly_once() != 0) {
        return 1;
    }
    if (test_oneshot_replay_deny() != 0) {
        return 1;
    }
    if (test_callback_reentry() != 0) {
        return 1;
    }
    if (test_frame_mutation_fail_closed() != 0) {
        return 1;
    }
    if (test_live_field_mismatches() != 0) {
        return 1;
    }
    if (test_time_boundaries() != 0) {
        return 1;
    }
    if (test_edge_error_no_reuse() != 0) {
        return 1;
    }
    if (test_counter_saturation() != 0) {
        return 1;
    }
    if (test_spy_trace_overflow() != 0) {
        return 1;
    }
    if (test_unbound_edge() != 0) {
        return 1;
    }
    if (test_seq_exhausted_after_max() != 0) {
        return 1;
    }
    if (test_clear_authorities_default_deny() != 0) {
        return 1;
    }
    if (test_plan_mutation_records_seal_seq() != 0) {
        return 1;
    }
    if (test_consume_status_closed_partition() != 0) {
        return 1;
    }
    if (test_consume_status_plan_mutation_burns_all() != 0) {
        return 1;
    }
    if (test_alias_out_error_with_permit() != 0) {
        return 1;
    }
    if (test_alias_frame_with_hal_storage() != 0) {
        return 1;
    }
    if (test_shutdown_clears_plan_and_watermark() != 0) {
        return 1;
    }
    if (test_huge_length_rejected_before_range_math() != 0) {
        return 1;
    }
    if (test_alias_frame_view_in_hal() != 0) {
        return 1;
    }
    if (test_alias_permit_in_hal() != 0) {
        return 1;
    }
    if (test_alias_out_error_in_frame_view() != 0) {
        return 1;
    }
    if (test_zero_length_authority_zero_mutation() != 0) {
        return 1;
    }
    if (test_mutation_authority_callbacks_edge_zero() != 0) {
        return 1;
    }
    if (test_digest_error_does_not_reset_clock() != 0) {
        return 1;
    }
    if (test_init_out_hal_alias_object() != 0) {
        return 1;
    }
    if (test_init_zeroed_first_ok() != 0) {
        return 1;
    }
    if (test_init_object_init_automatic_stable() != 0) {
        return 1;
    }
    if (test_init_active_reinit_rejected() != 0) {
        return 1;
    }
    if (test_init_shutdown_reinit_ok() != 0) {
        return 1;
    }
    if (test_init_poisoned_first_reject() != 0) {
        return 1;
    }
    if (test_permit_semantic_equal_padding_and_fields() != 0) {
        return 1;
    }
    if (test_callback_reentry_all_phases() != 0) {
        return 1;
    }
    if (test_true_caller_buffer_mutation_isolated() != 0) {
        return 1;
    }
    if (test_structural_zero_id_and_live() != 0) {
        return 1;
    }
    if (test_working_plan_mutation_on_validate_fail_closed() != 0) {
        return 1;
    }
    if (test_shutdown_blocks_tx() != 0) {
        return 1;
    }
    (void)printf("radio_hal_r1_test: OK\n");
    return 0;
}
