#include "radio_hal_spy.h"

#include <string.h>

/* Field-wise copy: does not copy padding (restores after poison). */
static void copy_permit_semantic(
    ninlil_radio_hal_permit_snapshot_t *dst,
    const ninlil_radio_hal_permit_snapshot_t *src)
{
    size_t i;

    for (i = 0u; i < NINLIL_RADIO_HAL_ID_BYTES; ++i) {
        dst->hardware_profile_id.bytes[i] = src->hardware_profile_id.bytes[i];
        dst->regulatory_profile_id.bytes[i] =
            src->regulatory_profile_id.bytes[i];
        dst->site_assignment_id.bytes[i] = src->site_assignment_id.bytes[i];
        dst->transmitter_id.bytes[i] = src->transmitter_id.bytes[i];
    }
    dst->hardware_profile_rev = src->hardware_profile_rev;
    dst->regulatory_profile_rev = src->regulatory_profile_rev;
    dst->site_assignment_rev = src->site_assignment_rev;
    dst->site_assignment_epoch = src->site_assignment_epoch;
    dst->channel_id = src->channel_id;
    dst->phy.bandwidth_hz = src->phy.bandwidth_hz;
    dst->phy.spreading_factor = src->phy.spreading_factor;
    dst->phy.coding_rate_denom = src->phy.coding_rate_denom;
    dst->phy.preamble_symbols = src->phy.preamble_symbols;
    dst->phy.tx_power_mdb = src->phy.tx_power_mdb;
    dst->phy.phy_flags = src->phy.phy_flags;
    for (i = 0u; i < NINLIL_RADIO_HAL_DIGEST_BYTES; ++i) {
        dst->frame_digest[i] = src->frame_digest[i];
    }
    dst->frame_digest_algorithm = src->frame_digest_algorithm;
    dst->frame_byte_length = src->frame_byte_length;
    dst->max_airtime_us = src->max_airtime_us;
    dst->not_before_ms = src->not_before_ms;
    dst->expiry_ms = src->expiry_ms;
    dst->permit_sequence = src->permit_sequence;
    dst->reserved_zero = src->reserved_zero;
}

static void mutate_permit_semantic_field(
    ninlil_radio_hal_permit_snapshot_t *mp,
    uint32_t field)
{
    switch (field) {
    case NINLIL_RADIO_HAL_SPY_FIELD_HW_REV:
        mp->hardware_profile_rev ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_REG_REV:
        mp->regulatory_profile_rev ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_SITE_REV:
        mp->site_assignment_rev ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_SITE_EPOCH:
        mp->site_assignment_epoch ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_CHANNEL:
        mp->channel_id ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_PHY_BW:
        mp->phy.bandwidth_hz ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_PHY_SF:
        mp->phy.spreading_factor = (uint8_t)(mp->phy.spreading_factor ^ 1u);
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_PHY_CR:
        mp->phy.coding_rate_denom = (uint8_t)(mp->phy.coding_rate_denom ^ 1u);
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_PHY_PREAMBLE:
        mp->phy.preamble_symbols = (uint16_t)(mp->phy.preamble_symbols ^ 1u);
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_PHY_TX_POWER:
        mp->phy.tx_power_mdb ^= 1;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_PHY_FLAGS:
        mp->phy.phy_flags ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_DIGEST_ALG:
        mp->frame_digest_algorithm ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_FRAME_LEN:
        mp->frame_byte_length ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_AIRTIME:
        mp->max_airtime_us ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_NOT_BEFORE:
        mp->not_before_ms ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_EXPIRY:
        mp->expiry_ms ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_SEQ:
        mp->permit_sequence ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_RESERVED:
        mp->reserved_zero ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_HW_ID0:
        mp->hardware_profile_id.bytes[0] ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_DIGEST0:
        mp->frame_digest[0] ^= 1u;
        break;
    case NINLIL_RADIO_HAL_SPY_FIELD_TX_ID0:
        mp->transmitter_id.bytes[0] ^= 1u;
        break;
    default:
        break;
    }
}

static void push_trace(
    ninlil_radio_hal_spy_t *spy,
    ninlil_radio_hal_spy_event_t event,
    ninlil_radio_hal_status_t status,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_reason_t reason,
    uint32_t frame_length,
    uint64_t permit_sequence,
    const uint8_t *bytes,
    uint32_t length)
{
    ninlil_radio_hal_spy_trace_record_t *rec;

    if (spy == NULL) {
        return;
    }
    spy->trace_seq = ninlil_radio_hal_sat_add_u64(spy->trace_seq, 1u);
    if (spy->trace_count >= NINLIL_RADIO_HAL_SPY_TRACE_CAP) {
        spy->trace_overflow = 1u;
        return;
    }
    rec = &spy->trace[spy->trace_count];
    (void)memset(rec, 0, sizeof(*rec));
    rec->sequence = spy->trace_seq;
    rec->event = event;
    rec->status = status;
    rec->stage = stage;
    rec->reason = reason;
    rec->frame_length = frame_length;
    rec->permit_sequence = permit_sequence;
    if (bytes != NULL && length > 0u) {
        uint32_t n = length;
        if (n > NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES) {
            n = (uint32_t)NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES;
        }
        (void)memcpy(rec->sample, bytes, n);
        rec->sample_len = (uint8_t)n;
    }
    spy->trace_count += 1u;
}

void ninlil_radio_hal_spy_init(ninlil_radio_hal_spy_t *spy)
{
    if (spy == NULL) {
        return;
    }
    (void)memset(spy, 0, sizeof(*spy));
    spy->next_validate_status = NINLIL_RADIO_HAL_OK;
    spy->next_consume_status = NINLIL_RADIO_HAL_OK;
    spy->next_edge_status = NINLIL_RADIO_HAL_OK;
    spy->next_digest_status = NINLIL_RADIO_HAL_OK;
    spy->clock_ms = 1500u; /* default inside typical test permit window */
    spy->last_validate_clock_ms = 0u;
    spy->last_consume_clock_ms = 0u;
}

void ninlil_radio_hal_spy_digest_fold(
    const uint8_t *bytes,
    uint32_t length,
    uint8_t out_digest[NINLIL_RADIO_HAL_DIGEST_BYTES])
{
    uint32_t i;
    uint8_t acc = 0xA5u;

    (void)memset(out_digest, 0, NINLIL_RADIO_HAL_DIGEST_BYTES);
    if (bytes == NULL) {
        return;
    }
    for (i = 0u; i < length; ++i) {
        acc = (uint8_t)(acc ^ bytes[i]);
        acc = (uint8_t)((acc << 1) | (acc >> 7));
        out_digest[i % NINLIL_RADIO_HAL_DIGEST_BYTES] ^=
            (uint8_t)(bytes[i] + (uint8_t)i + acc);
    }
    out_digest[0] ^= (uint8_t)(length & 0xFFu);
    out_digest[1] ^= (uint8_t)((length >> 8) & 0xFFu);
}

static ninlil_radio_hal_status_t spy_time_check(
    ninlil_radio_hal_spy_t *spy,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_error_t *out_error)
{
    if (spy->clock_ms < permit->not_before_ms) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_NOT_BEFORE;
            out_error->stage = stage;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NOT_BEFORE;
        }
        return NINLIL_RADIO_HAL_NOT_BEFORE;
    }
    if (spy->clock_ms >= permit->expiry_ms) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_EXPIRED;
            out_error->stage = stage;
            out_error->reason = NINLIL_RADIO_HAL_REASON_EXPIRED;
        }
        return NINLIL_RADIO_HAL_EXPIRED;
    }
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t spy_validate(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_spy_t *spy = (ninlil_radio_hal_spy_t *)ctx;
    ninlil_radio_hal_status_t st;

    if (spy == NULL || permit == NULL || frame == NULL) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_PERMIT_ERROR;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    spy->validate_calls =
        ninlil_radio_hal_sat_add_u64(spy->validate_calls, 1u);
    push_trace(
        spy,
        NINLIL_RADIO_HAL_SPY_EV_PERMIT_CHECK,
        NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
        NINLIL_RADIO_HAL_REASON_NONE,
        frame->length,
        permit->permit_sequence,
        frame->bytes,
        frame->length);

    /* Authoritative clock from spy ctx (not caller). */
    spy->last_validate_clock_ms = spy->clock_ms;
    st = spy_time_check(
        spy, permit, NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }

    if (spy->mutate_frame_on_validate != 0u && frame->bytes != NULL
        && frame->length > 0u) {
        /* Intentional TOCTOU: mutate working plan via const-cast. */
        uint8_t *mut = (uint8_t *)(uintptr_t)frame->bytes;
        mut[0] ^= 0xFFu;
    }
    if (spy->mutate_permit_on_validate != 0u) {
        ninlil_radio_hal_permit_snapshot_t *mp =
            (ninlil_radio_hal_permit_snapshot_t *)(uintptr_t)permit;
        mp->channel_id ^= 1u;
        mp->phy.spreading_factor =
            (uint8_t)(mp->phy.spreading_factor ^ 1u);
        mp->phy.bandwidth_hz ^= 1u;
    }
    if (spy->poison_permit_padding_on_validate != 0u) {
        ninlil_radio_hal_permit_snapshot_t *mp =
            (ninlil_radio_hal_permit_snapshot_t *)(uintptr_t)permit;
        ninlil_radio_hal_permit_snapshot_t saved;

        (void)memset(&saved, 0, sizeof(saved));
        copy_permit_semantic(&saved, permit);
        (void)memset(mp, 0xA5, sizeof(*mp));
        copy_permit_semantic(mp, &saved);
    }
    if (spy->mutate_permit_semantic_field != NINLIL_RADIO_HAL_SPY_FIELD_NONE) {
        ninlil_radio_hal_permit_snapshot_t *mp =
            (ninlil_radio_hal_permit_snapshot_t *)(uintptr_t)permit;
        mutate_permit_semantic_field(mp, spy->mutate_permit_semantic_field);
    }
    if (spy->mutate_caller_frame_on_validate != 0u
        && spy->caller_frame_bytes != NULL
        && spy->caller_frame_len > 0u) {
        spy->caller_frame_bytes[0] ^= 0xCCu;
        spy->last_caller_frame_sample = spy->caller_frame_bytes[0];
    }

    if (spy->reenter_transmit_on_validate != 0u && spy->reenter_hal != NULL) {
        ninlil_radio_hal_error_t re_err;
        ninlil_radio_hal_status_t re_st;

        re_st = ninlil_radio_hal_transmit_with_permit(
            spy->reenter_hal,
            &spy->reenter_permit,
            &spy->reenter_frame,
            &re_err);
        spy->reenter_status_seen = re_st;
        (void)re_err;
    }

    st = spy->next_validate_status;
    if (st != NINLIL_RADIO_HAL_OK) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = st;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE;
            out_error->reason = (st == NINLIL_RADIO_HAL_PERMIT_DENIED)
                ? NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY
                : NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR;
        }
        /* one-shot scripted status unless sticky OK */
        if (st != NINLIL_RADIO_HAL_OK) {
            spy->next_validate_status = NINLIL_RADIO_HAL_OK;
        }
        return st;
    }
    return NINLIL_RADIO_HAL_OK;
}

static int seq_consumed(const ninlil_radio_hal_spy_t *spy, uint64_t seq)
{
    uint32_t i;

    for (i = 0u; i < spy->consumed_count; ++i) {
        if (spy->consumed_seqs[i] == seq) {
            return 1;
        }
    }
    return 0;
}

static ninlil_radio_hal_status_t spy_consume(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_spy_t *spy = (ninlil_radio_hal_spy_t *)ctx;
    ninlil_radio_hal_status_t st;

    if (spy == NULL || permit == NULL || frame == NULL) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_CONSUME_ERROR;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }
    spy->consume_calls =
        ninlil_radio_hal_sat_add_u64(spy->consume_calls, 1u);
    push_trace(
        spy,
        NINLIL_RADIO_HAL_SPY_EV_CONSUME,
        NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
        NINLIL_RADIO_HAL_REASON_NONE,
        frame->length,
        permit->permit_sequence,
        frame->bytes,
        frame->length);

    spy->last_consume_clock_ms = spy->clock_ms;
    st = spy_time_check(
        spy, permit, NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }

    if (spy->mutate_frame_on_consume != 0u && frame->bytes != NULL
        && frame->length > 0u) {
        uint8_t *mut = (uint8_t *)(uintptr_t)frame->bytes;
        mut[0] ^= 0x55u;
    }
    if (spy->mutate_permit_on_consume != 0u) {
        ninlil_radio_hal_permit_snapshot_t *mp =
            (ninlil_radio_hal_permit_snapshot_t *)(uintptr_t)permit;
        mp->channel_id ^= 2u;
        mp->phy.spreading_factor =
            (uint8_t)(mp->phy.spreading_factor ^ 2u);
        mp->max_airtime_us ^= 1u;
    }

    if (spy->reenter_transmit_on_consume != 0u && spy->reenter_hal != NULL) {
        ninlil_radio_hal_error_t re_err;
        ninlil_radio_hal_status_t re_st;

        re_st = ninlil_radio_hal_transmit_with_permit(
            spy->reenter_hal,
            &spy->reenter_permit,
            &spy->reenter_frame,
            &re_err);
        spy->reenter_status_seen = re_st;
        (void)re_err;
    }

    st = spy->next_consume_status;
    if (st != NINLIL_RADIO_HAL_OK) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = st;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME;
            if (st == NINLIL_RADIO_HAL_CONSUME_DENIED) {
                out_error->reason = NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED;
            } else if (st == NINLIL_RADIO_HAL_CONSUME_FENCED
                || st == NINLIL_RADIO_HAL_SEQ_REUSE
                || st == NINLIL_RADIO_HAL_CONSUME_ERROR) {
                out_error->reason = NINLIL_RADIO_HAL_REASON_CONSUME_FENCED;
            } else {
                out_error->reason = NINLIL_RADIO_HAL_REASON_CONSUME_ERROR;
            }
        }
        spy->next_consume_status = NINLIL_RADIO_HAL_OK;
        return st;
    }

    if (seq_consumed(spy, permit->permit_sequence)) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_SEQ_REUSE;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME;
            out_error->reason = NINLIL_RADIO_HAL_REASON_SEQ_REUSE;
        }
        return NINLIL_RADIO_HAL_SEQ_REUSE;
    }
    if (spy->consumed_count >= NINLIL_RADIO_HAL_SPY_CONSUMED_CAP) {
        spy->consumed_overflow = 1u;
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_CONSUME_ERROR;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME;
            out_error->reason = NINLIL_RADIO_HAL_REASON_COUNTER_SAT;
        }
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }
    spy->consumed_seqs[spy->consumed_count] = permit->permit_sequence;
    spy->consumed_count += 1u;
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t spy_edge(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_spy_t *spy = (ninlil_radio_hal_spy_t *)ctx;
    ninlil_radio_hal_status_t st;
    uint32_t n;

    if (spy == NULL || permit == NULL || frame == NULL) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_EDGE_ERROR;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_EDGE;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_EDGE_ERROR;
    }
    spy->edge_calls = ninlil_radio_hal_sat_add_u64(spy->edge_calls, 1u);
    spy->edge_bytes_total =
        ninlil_radio_hal_sat_add_u64(spy->edge_bytes_total, frame->length);
    spy->last_edge_length = frame->length;
    spy->last_edge_permit_seq = permit->permit_sequence;
    n = frame->length;
    if (n > NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES) {
        n = (uint32_t)NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES;
    }
    if (frame->bytes != NULL && n > 0u) {
        (void)memcpy(spy->last_edge_sample, frame->bytes, n);
    }
    spy->last_edge_sample_len = (uint8_t)n;

    push_trace(
        spy,
        NINLIL_RADIO_HAL_SPY_EV_EDGE,
        NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_STAGE_EDGE,
        NINLIL_RADIO_HAL_REASON_NONE,
        frame->length,
        permit->permit_sequence,
        frame->bytes,
        frame->length);

    if (spy->reenter_transmit_on_edge != 0u && spy->reenter_hal != NULL) {
        ninlil_radio_hal_error_t re_err;
        ninlil_radio_hal_status_t re_st;

        re_st = ninlil_radio_hal_transmit_with_permit(
            spy->reenter_hal,
            &spy->reenter_permit,
            &spy->reenter_frame,
            &re_err);
        spy->reenter_status_seen = re_st;
        (void)re_err;
    }

    st = spy->next_edge_status;
    if (st != NINLIL_RADIO_HAL_OK) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_EDGE_ERROR;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_EDGE;
            out_error->reason = NINLIL_RADIO_HAL_REASON_EDGE_FAIL;
        }
        spy->next_edge_status = NINLIL_RADIO_HAL_OK;
        return NINLIL_RADIO_HAL_EDGE_ERROR;
    }
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t spy_digest(
    void *ctx,
    const ninlil_radio_hal_frame_view_t *frame,
    const uint8_t digest[NINLIL_RADIO_HAL_DIGEST_BYTES],
    uint32_t digest_algorithm,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_spy_t *spy = (ninlil_radio_hal_spy_t *)ctx;
    uint8_t computed[NINLIL_RADIO_HAL_DIGEST_BYTES];
    ninlil_radio_hal_status_t st;

    (void)digest_algorithm;
    if (spy == NULL || frame == NULL || digest == NULL) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    spy->digest_calls = ninlil_radio_hal_sat_add_u64(spy->digest_calls, 1u);
    /* Real observation: digest callback itself records DIGEST (not HAL entry). */
    push_trace(
        spy,
        NINLIL_RADIO_HAL_SPY_EV_DIGEST,
        NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_STAGE_DIGEST,
        NINLIL_RADIO_HAL_REASON_NONE,
        frame->length,
        0u,
        frame->bytes,
        frame->length);

    if (spy->reenter_transmit_on_digest != 0u && spy->reenter_hal != NULL) {
        ninlil_radio_hal_error_t re_err;
        ninlil_radio_hal_status_t re_st;

        re_st = ninlil_radio_hal_transmit_with_permit(
            spy->reenter_hal,
            &spy->reenter_permit,
            &spy->reenter_frame,
            &re_err);
        spy->reenter_status_seen = re_st;
        (void)re_err;
    }

    st = spy->next_digest_status;
    if (st != NINLIL_RADIO_HAL_OK) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH;
        }
        spy->next_digest_status = NINLIL_RADIO_HAL_OK;
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }

    ninlil_radio_hal_spy_digest_fold(frame->bytes, frame->length, computed);
    if (memcmp(computed, digest, NINLIL_RADIO_HAL_DIGEST_BYTES) != 0) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH;
        }
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }

    /*
     * After successful verify, optionally mutate working frame and still
     * return OK — HAL must plan_matches_seal fail (edge 0). Never receives seal.
     */
    if (spy->mutate_frame_on_digest != 0u && frame->bytes != NULL
        && frame->length > 0u) {
        uint8_t *mut = (uint8_t *)(uintptr_t)frame->bytes;
        mut[0] ^= 0xAAu;
    }
    return NINLIL_RADIO_HAL_OK;
}

static const ninlil_radio_hal_edge_ops_t g_edge_ops = {
    spy_edge
};
static const ninlil_radio_hal_permit_ops_t g_permit_ops = {
    spy_validate,
    spy_consume
};
static const ninlil_radio_hal_digest_ops_t g_digest_ops = {
    spy_digest
};

const ninlil_radio_hal_edge_ops_t *ninlil_radio_hal_spy_edge_ops(void)
{
    return &g_edge_ops;
}

const ninlil_radio_hal_permit_ops_t *ninlil_radio_hal_spy_permit_ops(void)
{
    return &g_permit_ops;
}

const ninlil_radio_hal_digest_ops_t *ninlil_radio_hal_spy_digest_ops(void)
{
    return &g_digest_ops;
}

size_t ninlil_radio_hal_spy_trace_count(const ninlil_radio_hal_spy_t *spy)
{
    return spy == NULL ? 0u : (size_t)spy->trace_count;
}

int ninlil_radio_hal_spy_trace_overflowed(const ninlil_radio_hal_spy_t *spy)
{
    return spy != NULL && spy->trace_overflow != 0u;
}

const ninlil_radio_hal_spy_trace_record_t *ninlil_radio_hal_spy_trace_at(
    const ninlil_radio_hal_spy_t *spy,
    size_t index)
{
    if (spy == NULL || index >= (size_t)spy->trace_count) {
        return NULL;
    }
    return &spy->trace[index];
}

int ninlil_radio_hal_spy_trace_has_order_success(
    const ninlil_radio_hal_spy_t *spy)
{
    size_t i;
    uint32_t n_digest = 0u;
    uint32_t n_check = 0u;
    uint32_t n_consume = 0u;
    uint32_t n_edge = 0u;
    int phase = 0; /* 0 wait DIGEST, 1 CHECK, 2 CONSUME, 3 EDGE, 4 done */

    if (spy == NULL) {
        return 0;
    }
    for (i = 0u; i < (size_t)spy->trace_count; ++i) {
        ninlil_radio_hal_spy_event_t ev = spy->trace[i].event;

        if (ev == NINLIL_RADIO_HAL_SPY_EV_DIGEST) {
            n_digest += 1u;
            if (phase != 0 || n_digest != 1u) {
                return 0;
            }
            phase = 1;
        } else if (ev == NINLIL_RADIO_HAL_SPY_EV_PERMIT_CHECK) {
            n_check += 1u;
            if (phase != 1 || n_check != 1u) {
                return 0;
            }
            phase = 2;
        } else if (ev == NINLIL_RADIO_HAL_SPY_EV_CONSUME) {
            n_consume += 1u;
            if (phase != 2 || n_consume != 1u) {
                return 0;
            }
            phase = 3;
        } else if (ev == NINLIL_RADIO_HAL_SPY_EV_EDGE) {
            n_edge += 1u;
            if (phase != 3 || n_edge != 1u) {
                return 0;
            }
            phase = 4;
        }
        /* Other event kinds (e.g. STATUS) do not advance or reset the chain. */
    }

    return phase == 4
        && n_digest == 1u
        && n_check == 1u
        && n_consume == 1u
        && n_edge == 1u;
}
