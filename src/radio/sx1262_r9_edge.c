/*
 * R9 sole physical TX edge: radio_hal → SX1262 phy (Proposed ADR-0025).
 */

#include "sx1262_r9_edge.h"

#include "airtime_calculator.h"
#include "domain_store_codec.h"

#include <string.h>

#define EDGE_MAGIC ((uint32_t)0x45395239u) /* 'E9R9' */

struct ninlil_sx1262_r9_edge {
    uint32_t magic;
    ninlil_sx1262_phy_t *phy;
    ninlil_sx1262_rf_profile_t profile;
    ninlil_sx1262_r9_edge_stats_t stats;
};

_Static_assert(
    sizeof(struct ninlil_sx1262_r9_edge) <= NINLIL_SX1262_R9_EDGE_OBJECT_BYTES,
    "r9 edge object size");

static void sat_inc(uint64_t *c)
{
    if (c != NULL && *c < UINT64_MAX) {
        *c += 1u;
    }
}

static void set_hal_err(
    ninlil_radio_hal_error_t *out,
    ninlil_radio_hal_status_t st,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_reason_t reason,
    const char *hint)
{
    size_t i;

    if (out == NULL) {
        return;
    }
    (void)memset(out, 0, sizeof(*out));
    out->status = st;
    out->stage = stage;
    out->reason = reason;
    if (hint != NULL) {
        for (i = 0u; i + 1u < sizeof(out->hint) && hint[i] != '\0'; ++i) {
            out->hint[i] = hint[i];
        }
    }
}

int ninlil_sx1262_r9_digest_ct_neq(
    const uint8_t a[32],
    const uint8_t b[32])
{
    uint8_t acc = 0u;
    size_t i;

    if (a == NULL || b == NULL) {
        return 1;
    }
    for (i = 0u; i < 32u; ++i) {
        acc = (uint8_t)(acc | (a[i] ^ b[i]));
    }
    return acc != 0u ? 1 : 0;
}

int ninlil_sx1262_r9_airtime_to_settx_steps(
    uint32_t airtime_us,
    uint32_t margin_us,
    uint32_t *out_steps)
{
    uint64_t us;
    uint64_t steps;

    if (out_steps == NULL) {
        return 0;
    }
    us = (uint64_t)airtime_us + (uint64_t)margin_us;
    if (us == 0u) {
        us = 1u;
    }
    /* steps = ceil(us / 15.625) = ceil(us * 64 / 1000) */
    steps = (us * 64ull + 999ull) / 1000ull;
    if (steps == 0u) {
        steps = 1u;
    }
    if (steps > 0xFFFFFFull) {
        return 0;
    }
    *out_steps = (uint32_t)steps;
    return 1;
}

int ninlil_sx1262_r9_channel_to_freq_hz(
    const ninlil_sx1262_rf_profile_t *profile,
    uint32_t channel_id,
    uint32_t *out_freq_hz)
{
    uint32_t freq;

    if (profile == NULL || out_freq_hz == NULL || channel_id == 0u) {
        return 0;
    }
    /*
     * Closed LAB channel map (not Japan legal table).
     * channel_id 1..N mapped linearly from freq_hz_min with 200 kHz steps,
     * clamped to profile max.
     */
    if (channel_id > 64u) {
        return 0;
    }
    freq = profile->freq_hz_min + (channel_id - 1u) * 200000u;
    if (freq < profile->freq_hz_min || freq > profile->freq_hz_max) {
        return 0;
    }
    *out_freq_hz = freq;
    return 1;
}

size_t ninlil_sx1262_r9_edge_object_size(void)
{
    return sizeof(struct ninlil_sx1262_r9_edge);
}

static ninlil_radio_hal_status_t edge_transmit(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_sx1262_r9_edge_t *edge = (ninlil_sx1262_r9_edge_t *)ctx;
    ninlil_model_domain_digest_t dig;
    uint8_t computed[32];
    ninlil_airtime_lora_input_t ain;
    ninlil_airtime_result_t aout;
    ninlil_sx1262_phy_tx_plan_t plan;
    ninlil_sx1262_error_t perr;
    ninlil_sx1262_status_t pst;
    uint32_t freq = 0u;
    uint32_t steps = 0u;
    uint8_t cr;
    size_t i;

    if (edge == NULL || edge->magic != EDGE_MAGIC || edge->phy == NULL
        || permit == NULL || frame == NULL || frame->bytes == NULL
        || frame->length == 0u) {
        set_hal_err(out_error, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "edge args");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    sat_inc(&edge->stats.edge_calls);

    /* (1) Recompute SHA-256 of sealed frame; constant-time compare. */
    /* Non-zero digest check alone is forbidden — full 32-byte cteq required. */
    if (permit->frame_digest_algorithm != 1u) {
        sat_inc(&edge->stats.digest_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_FRAME_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH,
            "digest alg");
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    if (permit->frame_byte_length != frame->length) {
        sat_inc(&edge->stats.digest_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_FRAME_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_LENGTH_MISMATCH,
            "frame len");
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    if (ninlil_model_domain_sha256(
            frame->bytes, frame->length, &dig)
        != NINLIL_OK) {
        sat_inc(&edge->stats.digest_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_FRAME_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH,
            "sha256 fail");
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    for (i = 0u; i < 32u; ++i) {
        computed[i] = dig.bytes[i];
    }
    if (ninlil_sx1262_r9_digest_ct_neq(computed, permit->frame_digest) != 0) {
        sat_inc(&edge->stats.digest_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_FRAME_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH,
            "digest mismatch");
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }

    /* (2) Independent airtime recompute — do not trust caller ToA. */
    (void)memset(&ain, 0, sizeof(ain));
    ain.sf = permit->phy.spreading_factor;
    /* HAL coding_rate_denom 5..8 → airtime cr 1..4 */
    if (permit->phy.coding_rate_denom < 5u
        || permit->phy.coding_rate_denom > 8u) {
        sat_inc(&edge->stats.airtime_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_STRUCT_INVALID,
            "cr");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    cr = (uint8_t)(permit->phy.coding_rate_denom - 4u);
    ain.cr = cr;
    ain.header_implicit = NINLIL_AIRTIME_HEADER_EXPLICIT;
    ain.crc_on = NINLIL_AIRTIME_CRC_ON;
    ain.ldro = NINLIL_AIRTIME_LDRO_AUTO;
    if (frame->length > 255u) {
        sat_inc(&edge->stats.airtime_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_LENGTH_MISMATCH,
            "plen");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    ain.payload_len_bytes = (uint8_t)frame->length;
    ain.preamble_len_symbols = permit->phy.preamble_symbols;
    ain.bw_hz = permit->phy.bandwidth_hz;
    if (ninlil_airtime_lora_us(&ain, &aout) != NINLIL_AIRTIME_OK) {
        sat_inc(&edge->stats.airtime_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_STRUCT_INVALID,
            "airtime calc");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (aout.airtime_us > permit->max_airtime_us
        || aout.airtime_us > edge->profile.max_airtime_us_ceiling) {
        sat_inc(&edge->stats.airtime_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_STRUCT_INVALID,
            "airtime exceed");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (!ninlil_sx1262_r9_airtime_to_settx_steps(
            aout.airtime_us, 50000u, &steps)) {
        sat_inc(&edge->stats.airtime_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_STRUCT_INVALID,
            "timeout steps");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }

    /* Profile / channel → frequency. */
    if (!ninlil_sx1262_r9_channel_to_freq_hz(
            &edge->profile, permit->channel_id, &freq)) {
        sat_inc(&edge->stats.profile_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_LIVE_CHANNEL,
            "channel");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (permit->phy.bandwidth_hz != edge->profile.bandwidth_hz
        || permit->phy.spreading_factor < edge->profile.sf_min
        || permit->phy.spreading_factor > edge->profile.sf_max
        || permit->phy.coding_rate_denom < edge->profile.cr_denom_min
        || permit->phy.coding_rate_denom > edge->profile.cr_denom_max
        || permit->phy.preamble_symbols < edge->profile.preamble_min
        || permit->phy.preamble_symbols > edge->profile.preamble_max
        || permit->phy.tx_power_mdb < edge->profile.tx_power_mdb_min
        || permit->phy.tx_power_mdb > edge->profile.tx_power_mdb_max) {
        sat_inc(&edge->stats.profile_reject);
        set_hal_err(out_error, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_LIVE_PHY,
            "phy profile");
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }

    (void)memset(&plan, 0, sizeof(plan));
    plan.frequency_hz = freq;
    plan.bandwidth_hz = permit->phy.bandwidth_hz;
    plan.spreading_factor = permit->phy.spreading_factor;
    plan.coding_rate_denom = permit->phy.coding_rate_denom;
    plan.preamble_symbols = permit->phy.preamble_symbols;
    plan.tx_power_mdb = permit->phy.tx_power_mdb;
    plan.settx_timeout_steps = steps;
    plan.expected_radio_generation = ninlil_sx1262_phy_generation(edge->phy);
    /* Immutable seal: payload/context/window cannot change after arm. */
    plan.frame_byte_length = frame->length;
    for (i = 0u; i < 32u; ++i) {
        plan.frame_digest[i] = permit->frame_digest[i];
    }
    plan.max_airtime_us = permit->max_airtime_us;
    plan.not_before_ms = permit->not_before_ms;
    plan.expiry_ms = permit->expiry_ms;
    plan.permit_sequence = permit->permit_sequence;
    plan.ldro_effective = aout.ldro_effective;
    plan.require_lbt = 1u; /* production edge always runs CAD/LBT before SetTx */
    plan.lbt_timeout_ms = 50u;

    pst = ninlil_sx1262_phy_arm_tx(
        edge->phy, &plan, frame->bytes, frame->length, &perr);
    if (pst != NINLIL_SX1262_OK) {
        sat_inc(&edge->stats.phy_reject);
        if (pst == NINLIL_SX1262_TX_DENIED) {
            sat_inc(&edge->stats.gen_reject);
        }
        set_hal_err(out_error, NINLIL_RADIO_HAL_EDGE_ERROR,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_NONE,
            perr.hint[0] != '\0' ? perr.hint : "phy arm");
        return NINLIL_RADIO_HAL_EDGE_ERROR;
    }
    sat_inc(&edge->stats.edge_ok);
    set_hal_err(out_error, NINLIL_RADIO_HAL_OK, NINLIL_RADIO_HAL_STAGE_NONE,
        NINLIL_RADIO_HAL_REASON_NONE, NULL);
    return NINLIL_RADIO_HAL_OK;
}

static const ninlil_radio_hal_edge_ops_t g_edge_ops = {
    edge_transmit
};

ninlil_radio_hal_status_t ninlil_sx1262_r9_edge_init(
    ninlil_sx1262_r9_edge_object_t *object,
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_rf_profile_t *profile,
    ninlil_sx1262_r9_edge_t **out_edge,
    const ninlil_radio_hal_edge_ops_t **out_ops,
    void **out_ctx,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_sx1262_r9_edge_t *edge;

    if (object == NULL || phy == NULL || profile == NULL || out_edge == NULL
        || out_ops == NULL || out_ctx == NULL) {
        set_hal_err(out_error, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "init");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (sizeof(struct ninlil_sx1262_r9_edge) > sizeof(object->storage)) {
        set_hal_err(out_error, NINLIL_RADIO_HAL_INVALID_STATE,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_STRUCT_INVALID,
            "size");
        return NINLIL_RADIO_HAL_INVALID_STATE;
    }
    (void)memset(object->storage, 0, sizeof(object->storage));
    edge = (ninlil_sx1262_r9_edge_t *)(void *)object->storage;
    edge->magic = EDGE_MAGIC;
    edge->phy = phy;
    edge->profile = *profile;
    *out_edge = edge;
    *out_ops = &g_edge_ops;
    *out_ctx = edge;
    set_hal_err(out_error, NINLIL_RADIO_HAL_OK, NINLIL_RADIO_HAL_STAGE_NONE,
        NINLIL_RADIO_HAL_REASON_NONE, NULL);
    return NINLIL_RADIO_HAL_OK;
}

void ninlil_sx1262_r9_edge_stats(
    const ninlil_sx1262_r9_edge_t *edge,
    ninlil_sx1262_r9_edge_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (edge == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = edge->stats;
}
