#include "c6_lab_enforcement.h"

#include <string.h>

/* Marker for structural sole-edge gate (tools/c6_lab_enforcement_gate.py). */
#define C6_LAB_SOLE_EDGE_R5_R2_R1_R9 1

struct ninlil_c6_lab {
    uint32_t magic;
    uint32_t lifecycle;
    ninlil_r5_t *r5;
    ninlil_radio_hal_object_t hal_obj;
    ninlil_radio_hal_t *hal;
    ninlil_c6_lab_spi_tx_sim_t spi;
    ninlil_c6_lab_stats_t stats;
    ninlil_c6_lab_error_t last_error;
};

#define NINLIL_C6_LAB_MAGIC ((uint32_t)0x364C4142u) /* 'BAL6' LE */

_Static_assert(
    sizeof(ninlil_c6_lab_t) <= NINLIL_C6_LAB_OBJECT_BYTES,
    "c6_lab object exceeds OBJECT_BYTES ceiling");

static void set_error(
    ninlil_c6_lab_t *c6,
    ninlil_c6_lab_error_t *out,
    ninlil_c6_lab_status_t status,
    ninlil_c6_lab_stage_t stage,
    ninlil_c6_lab_reason_t reason,
    const char *hint)
{
    ninlil_c6_lab_error_t local;

    local.status = status;
    local.stage = stage;
    local.reason = reason;
    local.reserved_zero = 0u;
    if (hint == NULL) {
        (void)memset(local.hint, 0, sizeof(local.hint));
    } else {
        size_t i;
        for (i = 0u; i < sizeof(local.hint) - 1u && hint[i] != '\0'; ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (c6 != NULL) {
        c6->last_error = local;
    }
    if (out != NULL) {
        *out = local;
    }
}

static void digest_fold(
    const uint8_t *bytes,
    uint32_t length,
    uint8_t out_digest[NINLIL_RADIO_HAL_DIGEST_BYTES])
{
    uint32_t i;

    (void)memset(out_digest, 0, NINLIL_RADIO_HAL_DIGEST_BYTES);
    if (bytes == NULL || length == 0u) {
        return;
    }
    for (i = 0u; i < length; ++i) {
        out_digest[i % NINLIL_RADIO_HAL_DIGEST_BYTES] ^=
            bytes[i];
    }
    out_digest[0] ^= (uint8_t)(length & 0xFFu);
    out_digest[1] ^= (uint8_t)((length >> 8) & 0xFFu);
}

static ninlil_radio_hal_status_t c6_digest_verify(
    void *ctx,
    const ninlil_radio_hal_frame_view_t *frame,
    const uint8_t digest[NINLIL_RADIO_HAL_DIGEST_BYTES],
    uint32_t digest_algorithm,
    ninlil_radio_hal_error_t *out_error)
{
    uint8_t computed[NINLIL_RADIO_HAL_DIGEST_BYTES];

    (void)ctx;
    (void)digest_algorithm;
    if (frame == NULL || digest == NULL || frame->bytes == NULL
        || frame->length == 0u) {
        if (out_error != NULL) {
            out_error->status = NINLIL_RADIO_HAL_INVALID_ARGUMENT;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
            out_error->reserved_zero = 0u;
            (void)memset(out_error->hint, 0, sizeof(out_error->hint));
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    digest_fold(frame->bytes, frame->length, computed);
    if (memcmp(computed, digest, NINLIL_RADIO_HAL_DIGEST_BYTES) != 0) {
        if (out_error != NULL) {
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH;
            out_error->reserved_zero = 0u;
            (void)memset(out_error->hint, 0, sizeof(out_error->hint));
        }
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    if (out_error != NULL) {
        out_error->status = NINLIL_RADIO_HAL_OK;
        out_error->stage = NINLIL_RADIO_HAL_STAGE_NONE;
        out_error->reason = NINLIL_RADIO_HAL_REASON_NONE;
        out_error->reserved_zero = 0u;
        (void)memset(out_error->hint, 0, sizeof(out_error->hint));
    }
    return NINLIL_RADIO_HAL_OK;
}

static const ninlil_radio_hal_digest_ops_t g_c6_digest_ops = {
    c6_digest_verify
};

size_t ninlil_c6_lab_object_size(void)
{
    return sizeof(ninlil_c6_lab_t);
}

ninlil_c6_lab_status_t ninlil_c6_lab_init_object(
    ninlil_c6_lab_object_t *object,
    ninlil_r5_t *r5,
    ninlil_c6_lab_t **out_c6,
    ninlil_c6_lab_error_t *out_error)
{
    ninlil_c6_lab_t *c6;
    ninlil_radio_hal_live_binding_t live;
    ninlil_radio_hal_permit_ops_t permit_ops;
    ninlil_r5_error_t r5_err;
    ninlil_radio_hal_error_t hal_err;

    if (object == NULL || out_c6 == NULL || r5 == NULL) {
        set_error(NULL, out_error, NINLIL_C6_LAB_INVALID_ARGUMENT,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_NULL_ARG, "null");
        return NINLIL_C6_LAB_INVALID_ARGUMENT;
    }
    if (sizeof(ninlil_c6_lab_t) > sizeof(object->storage)) {
        set_error(NULL, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_NOT_ACTIVE,
            "object bytes");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    if (out_c6 == (ninlil_c6_lab_t **)(void *)object
        || object == (ninlil_c6_lab_object_t *)(void *)out_c6) {
        set_error(NULL, out_error, NINLIL_C6_LAB_INVALID_ARGUMENT,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_NULL_ARG, "alias");
        return NINLIL_C6_LAB_INVALID_ARGUMENT;
    }
    c6 = (ninlil_c6_lab_t *)(void *)object->storage;
    if (c6->magic == NINLIL_C6_LAB_MAGIC && c6->lifecycle == 1u) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_NOT_ACTIVE,
            "active re-init");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    (void)memset(c6, 0, sizeof(*c6));
    c6->r5 = r5;
    ninlil_c6_lab_spi_tx_sim_init(&c6->spi);

    (void)memset(&c6->hal_obj, 0, sizeof(c6->hal_obj));
    if (ninlil_radio_hal_init_object(&c6->hal_obj, &c6->hal)
        != NINLIL_RADIO_HAL_OK) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_HAL, "hal init");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    if (ninlil_radio_hal_bind_edge(
            c6->hal,
            ninlil_c6_lab_spi_tx_sim_edge_ops(),
            &c6->spi,
            &hal_err)
        != NINLIL_RADIO_HAL_OK) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_HAL, "edge bind");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    ninlil_r5_permit_ops(&permit_ops);
    if (ninlil_radio_hal_bind_permit_ops(c6->hal, &permit_ops, r5, &hal_err)
        != NINLIL_RADIO_HAL_OK) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_HAL, "permit bind");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    if (ninlil_radio_hal_bind_digest_ops(c6->hal, &g_c6_digest_ops, c6, &hal_err)
        != NINLIL_RADIO_HAL_OK) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_HAL, "digest bind");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    (void)memset(&live, 0, sizeof(live));
    if (ninlil_r5_build_live_binding(r5, &live, &r5_err) != NINLIL_R5_OK) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_R5, "live bind");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    if (ninlil_radio_hal_set_live_binding(c6->hal, &live, &hal_err)
        != NINLIL_RADIO_HAL_OK) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_INIT, NINLIL_C6_LAB_REASON_HAL, "live set");
        return NINLIL_C6_LAB_INVALID_STATE;
    }

    c6->magic = NINLIL_C6_LAB_MAGIC;
    c6->lifecycle = 1u;
    *out_c6 = c6;
    set_error(c6, out_error, NINLIL_C6_LAB_OK, NINLIL_C6_LAB_STAGE_NONE,
        NINLIL_C6_LAB_REASON_NONE, NULL);
    return NINLIL_C6_LAB_OK;
}

ninlil_c6_lab_status_t ninlil_c6_lab_transmit(
    ninlil_c6_lab_t *c6,
    ninlil_v1_frame_type_t frame_type,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_c6_lab_error_t *out_error)
{
    ninlil_r5_bind_plan_t full;
    ninlil_radio_hal_permit_snapshot_t snap;
    ninlil_radio_hal_frame_view_t frame;
    ninlil_radio_hal_error_t hal_err;
    ninlil_r5_error_t r5_err;
    ninlil_r5_status_t r5_st;
    ninlil_radio_hal_status_t hal_st;
    uint64_t spi_before;

    if (c6 == NULL || plan == NULL) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_ARGUMENT,
            NINLIL_C6_LAB_STAGE_NONE, NINLIL_C6_LAB_REASON_NULL_ARG, "null");
        return NINLIL_C6_LAB_INVALID_ARGUMENT;
    }
    if (c6->magic != NINLIL_C6_LAB_MAGIC || c6->lifecycle != 1u
        || c6->hal == NULL || c6->r5 == NULL) {
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
            NINLIL_C6_LAB_STAGE_NONE, NINLIL_C6_LAB_REASON_NOT_ACTIVE,
            "not active");
        return NINLIL_C6_LAB_INVALID_STATE;
    }
    c6->stats.transmit_attempts += 1u;
    spi_before = c6->spi.spi_tx_count;

    if (!ninlil_v1_frame_type_is_transmittable(frame_type)) {
        c6->stats.frame_type_reject += 1u;
        set_error(c6, out_error, NINLIL_C6_LAB_FRAME_DENIED,
            NINLIL_C6_LAB_STAGE_NONE, NINLIL_C6_LAB_REASON_FRAME_TYPE,
            "manifest deny");
        return NINLIL_C6_LAB_FRAME_DENIED;
    }

    /* R5 bind + R2 issue (permit snapshot). */
    r5_st = ninlil_r5_issue(c6->r5, plan, &full, &snap, &r5_err);
    if (r5_st != NINLIL_R5_OK) {
        c6->stats.profile_reject += 1u;
        if (r5_st == NINLIL_R5_PROFILE_DENIED
            || r5_st == NINLIL_R5_PROFILE_EXPIRED
            || r5_st == NINLIL_R5_PROFILE_NOT_EFFECTIVE) {
            set_error(c6, out_error, NINLIL_C6_LAB_PROFILE_DENIED,
                NINLIL_C6_LAB_STAGE_ISSUE, NINLIL_C6_LAB_REASON_R5,
                "profile deny");
            return NINLIL_C6_LAB_PROFILE_DENIED;
        }
        if (r5_st == NINLIL_R5_PCP) {
            c6->stats.permit_reject += 1u;
            set_error(c6, out_error, NINLIL_C6_LAB_PERMIT_DENIED,
                NINLIL_C6_LAB_STAGE_ISSUE, NINLIL_C6_LAB_REASON_R5,
                "permit deny");
            return NINLIL_C6_LAB_PERMIT_DENIED;
        }
        set_error(c6, out_error, NINLIL_C6_LAB_PERMIT_DENIED,
            NINLIL_C6_LAB_STAGE_ISSUE, NINLIL_C6_LAB_REASON_R5, "issue fail");
        return NINLIL_C6_LAB_PERMIT_DENIED;
    }

    if (plan->frame_bytes == NULL || plan->frame_byte_length == 0u) {
        c6->stats.hal_reject += 1u;
        set_error(c6, out_error, NINLIL_C6_LAB_INVALID_ARGUMENT,
            NINLIL_C6_LAB_STAGE_HAL, NINLIL_C6_LAB_REASON_NULL_ARG,
            "empty frame");
        return NINLIL_C6_LAB_INVALID_ARGUMENT;
    }
    frame.bytes = plan->frame_bytes;
    frame.length = plan->frame_byte_length;

    /* HAL requires live.max_airtime_us == permit.max_airtime_us (per-plan R3). */
    {
        ninlil_radio_hal_live_binding_t live;
        if (ninlil_r5_build_live_binding(c6->r5, &live, &r5_err) != NINLIL_R5_OK) {
            c6->stats.hal_reject += 1u;
            set_error(c6, out_error, NINLIL_C6_LAB_INVALID_STATE,
                NINLIL_C6_LAB_STAGE_HAL, NINLIL_C6_LAB_REASON_R5,
                "live refresh");
            return NINLIL_C6_LAB_INVALID_STATE;
        }
        live.max_airtime_us = snap.max_airtime_us;
        if (ninlil_radio_hal_set_live_binding(c6->hal, &live, &hal_err)
            != NINLIL_RADIO_HAL_OK) {
            c6->stats.hal_reject += 1u;
            set_error(c6, out_error, NINLIL_C6_LAB_HAL_DENIED,
                NINLIL_C6_LAB_STAGE_HAL, NINLIL_C6_LAB_REASON_HAL,
                "live airtime");
            return NINLIL_C6_LAB_HAL_DENIED;
        }
    }

    /*
     * R1 transmit_with_permit: digest -> R5 validate -> R5 consume -> R9 edge.
     * C6_LAB_SOLE_EDGE_R5_R2_R1_R9
     */
    hal_st = ninlil_radio_hal_transmit_with_permit(
        c6->hal, &snap, &frame, &hal_err);
    if (hal_st != NINLIL_RADIO_HAL_OK) {
        c6->stats.hal_reject += 1u;
        if (hal_st == NINLIL_RADIO_HAL_PERMIT_DENIED
            || hal_st == NINLIL_RADIO_HAL_CONSUME_DENIED
            || hal_st == NINLIL_RADIO_HAL_CONSUME_FENCED
            || hal_st == NINLIL_RADIO_HAL_CONSUME_ERROR
            || hal_st == NINLIL_RADIO_HAL_NOT_BEFORE
            || hal_st == NINLIL_RADIO_HAL_EXPIRED) {
            c6->stats.permit_reject += 1u;
            set_error(c6, out_error, NINLIL_C6_LAB_PERMIT_DENIED,
                NINLIL_C6_LAB_STAGE_HAL, NINLIL_C6_LAB_REASON_HAL,
                "permit/consume deny");
            return NINLIL_C6_LAB_PERMIT_DENIED;
        }
        set_error(c6, out_error, NINLIL_C6_LAB_HAL_DENIED,
            NINLIL_C6_LAB_STAGE_HAL, NINLIL_C6_LAB_REASON_HAL,
            hal_err.hint[0] != '\0' ? hal_err.hint : "hal deny");
        return NINLIL_C6_LAB_HAL_DENIED;
    }

    if (c6->spi.spi_tx_count != spi_before + 1u) {
        c6->stats.hal_reject += 1u;
        set_error(c6, out_error, NINLIL_C6_LAB_HAL_DENIED,
            NINLIL_C6_LAB_STAGE_HAL, NINLIL_C6_LAB_REASON_HAL, "spi mismatch");
        return NINLIL_C6_LAB_HAL_DENIED;
    }

    c6->stats.transmit_ok += 1u;
    c6->stats.spi_tx_count = c6->spi.spi_tx_count;
    set_error(c6, out_error, NINLIL_C6_LAB_OK, NINLIL_C6_LAB_STAGE_NONE,
        NINLIL_C6_LAB_REASON_NONE, NULL);
    return NINLIL_C6_LAB_OK;
}

void ninlil_c6_lab_stats(
    const ninlil_c6_lab_t *c6,
    ninlil_c6_lab_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (c6 == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = c6->stats;
    out_stats->spi_tx_count = c6->spi.spi_tx_count;
}

ninlil_c6_lab_status_t ninlil_c6_lab_shutdown(
    ninlil_c6_lab_t *c6,
    ninlil_c6_lab_error_t *out_error)
{
    ninlil_radio_hal_error_t hal_err;

    if (c6 == NULL) {
        set_error(NULL, out_error, NINLIL_C6_LAB_INVALID_ARGUMENT,
            NINLIL_C6_LAB_STAGE_NONE, NINLIL_C6_LAB_REASON_NULL_ARG, "null");
        return NINLIL_C6_LAB_INVALID_ARGUMENT;
    }
    if (c6->hal != NULL) {
        (void)ninlil_radio_hal_shutdown(c6->hal, &hal_err);
    }
    c6->lifecycle = 2u;
    c6->magic = 0u;
    c6->hal = NULL;
    c6->r5 = NULL;
    set_error(c6, out_error, NINLIL_C6_LAB_OK, NINLIL_C6_LAB_STAGE_NONE,
        NINLIL_C6_LAB_REASON_NONE, NULL);
    return NINLIL_C6_LAB_OK;
}
