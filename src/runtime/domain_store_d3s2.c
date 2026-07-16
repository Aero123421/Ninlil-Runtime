#include "domain_store_d3s2.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_store_scanner.h"

#include <string.h>

/*
 * D3-S2: fixed context, modes 21–26 same-txn multipass phase machine.
 * No KEY_DIGEST reverse. No second 4096. No heap/VLA. No Storage mutation.
 * No second concurrent iterator. Port terminal → note 0.
 * Stage5 D3 bind, D3-S3..S12, D3 overall, D4, public Runtime remain pending.
 */

/* ---- small pure helpers ---- */

static void encode_u64_be_field(uint8_t out[8], uint64_t value)
{
    ninlil_model_domain_encode_u64_be(out, value);
}

static uint64_t decode_u64_be_field(const uint8_t in[8])
{
    return ninlil_model_domain_decode_u64_be(in);
}

static void encode_u32_be_field(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

static uint32_t decode_u32_be_field(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void set_u64_lane(uint8_t lane[8], uint64_t value)
{
    encode_u64_be_field(lane, value);
}

static uint64_t get_u64_lane(const uint8_t lane[8])
{
    return decode_u64_be_field(lane);
}

static void inc_u64_lane(uint8_t lane[8])
{
    uint64_t v = get_u64_lane(lane);
    if (v < UINT64_MAX) {
        set_u64_lane(lane, v + 1u);
    }
}

static int popcount8(uint8_t v)
{
    v = (uint8_t)(v - ((v >> 1) & 0x55u));
    v = (uint8_t)((v & 0x33u) + ((v >> 2) & 0x33u));
    return (int)((v + (v >> 4)) & 0x0fu);
}

uint8_t ninlil_domain_scan_d3s2_required_count_mask(uint8_t focus_mode)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT:
        return (uint8_t)(NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT
            | NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX);
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_REVERSE_REPLY:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_RETRY:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_MANAGEMENT:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT;
    default:
        return 0u;
    }
}

uint8_t ninlil_domain_scan_d3s2_required_binding_mask(uint8_t focus_mode)
{
    /* Same family bits as count mask for closed modes 21..26. */
    return ninlil_domain_scan_d3s2_required_count_mask(focus_mode);
}

static ninlil_status_t note_finding(ninlil_domain_scan_session_t *session)
{
    return ninlil_domain_scan_note_terminal_corrupt(session);
}

static ninlil_domain_scan_d3s2_context_t *ctx_of(
    ninlil_domain_scan_session_t *session)
{
    if (session == NULL
        || session->bound_d3_kind != NINLIL_DOMAIN_SCAN_D3_KIND_S2) {
        return NULL;
    }
    return session->bound_d3s2_context;
}

static void flags_set(ninlil_domain_scan_d3s2_context_t *ctx, uint8_t bit)
{
    ctx->flags = (uint8_t)(ctx->flags | bit);
}

static void flags_clear(ninlil_domain_scan_d3s2_context_t *ctx, uint8_t bit)
{
    ctx->flags = (uint8_t)(ctx->flags & (uint8_t)~bit);
}

static int flags_has(const ninlil_domain_scan_d3s2_context_t *ctx, uint8_t bit)
{
    return (ctx->flags & bit) != 0u;
}

static const ninlil_model_domain_typed_record_t *typed_of(
    const ninlil_domain_scan_workspace_t *workspace)
{
    return &workspace->row_validate_scratch.typed;
}

/* ---- complete-key rebuild helpers (fixed stack only) ---- */

static ninlil_status_t write_complete_key(
    uint8_t family,
    uint8_t subtype,
    uint8_t identity_kind,
    ninlil_bytes_view_t identity,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_model_domain_key_t key;
    ninlil_status_t status;

    if (out_key == NULL || out_key_len == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_build_key(
        family, subtype, identity_kind, identity, &key);
    if (status != NINLIL_OK) {
        *out_key_len = 0u;
        return status;
    }
    if (key.length == 0u
        || key.length > NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY
        || key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        *out_key_len = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = (uint8_t)key.length;
    return NINLIL_OK;
}

static ninlil_status_t write_composite_key(
    uint8_t subtype,
    ninlil_bytes_view_t components,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t identity;
    ninlil_status_t status;

    if (out_key == NULL || out_key_len == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_composite_digest(subtype, components, &dig);
    if (status != NINLIL_OK) {
        *out_key_len = 0u;
        return status;
    }
    identity.data = dig.bytes;
    identity.length = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity,
        out_key,
        out_key_len);
}

static int encode_raw16(
    uint8_t *out,
    uint32_t capacity,
    uint16_t raw_length,
    const uint8_t *raw,
    uint32_t *out_length)
{
    if (out == NULL || out_length == NULL
        || raw_length > 255u
        || (raw_length != 0u && raw == NULL)
        || capacity < 2u + (uint32_t)raw_length) {
        return 0;
    }
    ninlil_model_domain_encode_u16_be(out, raw_length);
    if (raw_length != 0u) {
        (void)memcpy(&out[2], raw, raw_length);
    }
    *out_length = 2u + (uint32_t)raw_length;
    return 1;
}

static ninlil_status_t rebuild_tx_state_key(
    const uint8_t tx[16],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (tx == NULL || ninlil_model_domain_id_is_zero(tx)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = tx;
    identity.length = 16u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

static ninlil_status_t rebuild_anchor_key(
    const uint8_t tx[16],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (tx == NULL || ninlil_model_domain_id_is_zero(tx)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = tx;
    identity.length = 16u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

static ninlil_status_t rebuild_event_spool_key(
    const uint8_t tx[16],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (tx == NULL || ninlil_model_domain_id_is_zero(tx)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = tx;
    identity.length = 16u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

static ninlil_status_t rebuild_result_cache_key(
    const uint8_t *delivery_raw,
    uint16_t delivery_raw_len,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 80u];
    uint32_t o = 0u;
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), delivery_raw_len,
            delivery_raw, &o)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_delivery_key(
    const uint8_t *delivery_raw,
    uint16_t delivery_raw_len,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 80u];
    uint32_t o = 0u;
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), delivery_raw_len,
            delivery_raw, &o)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_attempt_key(
    uint16_t owner_kind,
    const uint8_t *owner_raw,
    uint16_t owner_raw_len,
    const uint8_t attempt_id[16],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 80u + 16u];
    uint32_t o = 0u;
    uint32_t part = 0u;
    ninlil_bytes_view_t view;

    if (owner_raw == NULL || attempt_id == NULL
        || ninlil_model_domain_id_is_zero(attempt_id)
        || (owner_kind != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
            && owner_kind != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY)
        || (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
            && owner_raw_len != 16u)
        || (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY
            && owner_raw_len
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(components, owner_kind);
    o = 2u;
    if (!encode_raw16(
            &components[o], (uint32_t)sizeof(components) - o, owner_raw_len,
            owner_raw, &part)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o += part;
    (void)memcpy(&components[o], attempt_id, 16u);
    o += 16u;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_attempt_index_key(
    const uint8_t attempt_id[16],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    ninlil_bytes_view_t identity;

    if (attempt_id == NULL || ninlil_model_domain_id_is_zero(attempt_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = attempt_id;
    identity.length = 16u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        out_key,
        out_key_len);
}

static ninlil_status_t rebuild_evidence_key(
    uint16_t owner_kind,
    const uint8_t *owner_raw,
    uint16_t owner_raw_len,
    uint32_t slot,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 80u + 4u];
    uint32_t o = 0u;
    uint32_t part = 0u;
    ninlil_bytes_view_t view;

    if (owner_raw == NULL
        || (owner_kind != NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
            && owner_kind != NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY)
        || (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
            && owner_raw_len != 16u)
        || (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY
            && owner_raw_len
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(components, owner_kind);
    o = 2u;
    if (!encode_raw16(
            &components[o], (uint32_t)sizeof(components) - o, owner_raw_len,
            owner_raw, &part)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    o += part;
    encode_u32_be_field(&components[o], slot);
    o += 4u;
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_retry_key(
    const uint8_t tx[16],
    uint16_t kind,
    uint16_t slot,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[16u + 2u + 2u];
    ninlil_bytes_view_t view;

    if (tx == NULL || ninlil_model_domain_id_is_zero(tx)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(components, tx, 16u);
    ninlil_model_domain_encode_u16_be(&components[16], kind);
    ninlil_model_domain_encode_u16_be(&components[18], slot);
    view.data = components;
    view.length = 20u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY, view, out_key, out_key_len);
}

/*
 * Mode24 REVERSE_REPLY complete key (docs17 §5.1 / §8.5):
 *   reply_key_raw contents = delivery_key_raw:RAW16(80→82) || reply_kind:u32
 *                            exact 86 bytes
 *   key = COMPOSITE(42, reply_key_raw:RAW16)  // components = RAW16(86)
 * Closed reply_kind domain: 1..4.
 */
static ninlil_status_t rebuild_reverse_reply_key(
    const uint8_t *delivery_raw,
    uint16_t delivery_raw_len,
    uint32_t reply_kind,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t reply_contents[86];
    uint8_t components[2u + 86u];
    uint32_t o = 0u;
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || reply_kind < NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
        || reply_kind > NINLIL_MODEL_DOMAIN_REPLY_KIND_CANCEL_RESULT) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(
            reply_contents, (uint32_t)sizeof(reply_contents), delivery_raw_len,
            delivery_raw, &o)
        || o != 82u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    encode_u32_be_field(&reply_contents[82], reply_kind);
    o = 0u;
    if (!encode_raw16(
            components, (uint32_t)sizeof(components), 86u, reply_contents,
            &o)
        || o != 88u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = o;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_cleanup_plan_key(
    uint16_t subject_kind,
    const uint8_t subject_primary_key_digest[32],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 32u];
    ninlil_bytes_view_t view;

    if (subject_primary_key_digest == NULL) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(components, subject_kind);
    (void)memcpy(&components[2], subject_primary_key_digest, 32u);
    view.data = components;
    view.length = 34u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN, view, out_key, out_key_len);
}

/*
 * CANCEL_STATE complete key: COMPOSITE(33, cancel_owner_kind:u16 ||
 * owner_key_raw:RAW16). Same wire as D3-S1 rebuild helpers.
 */
static ninlil_status_t rebuild_tx_cancel_state_key(
    const uint8_t tx[16],
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 16u];
    ninlil_bytes_view_t view;

    if (tx == NULL || ninlil_model_domain_id_is_zero(tx)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION);
    ninlil_model_domain_encode_u16_be(&components[2], 16u);
    (void)memcpy(&components[4], tx, 16u);
    view.data = components;
    view.length = 4u + 16u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_delivery_cancel_state_key(
    const uint8_t *delivery_raw,
    uint16_t delivery_raw_len,
    uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(
        components, NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY);
    ninlil_model_domain_encode_u16_be(&components[2], delivery_raw_len);
    (void)memcpy(&components[4], delivery_raw, delivery_raw_len);
    view.data = components;
    view.length = 4u + (uint32_t)delivery_raw_len;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE, view, out_key, out_key_len);
}

static ninlil_status_t key_digest_of(
    const uint8_t *key,
    uint8_t key_len,
    uint8_t out[32])
{
    ninlil_bytes_view_t kv;
    ninlil_model_domain_digest_t dig;
    ninlil_status_t st;

    if (key == NULL || key_len == 0u || out == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    kv.data = key;
    kv.length = key_len;
    st = ninlil_model_domain_key_digest(kv, &dig);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return NINLIL_OK;
}

/*
 * Install focus_primary_key_digest as KEY_DIGEST of the true primary complete
 * key (ANCHOR for TX / DELIVERY for DLV) — never the STATE/RESULT carrier key.
 */
static ninlil_status_t install_true_primary_key_digest(
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    uint8_t primary_key[NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY];
    uint8_t primary_key_len = 0u;
    ninlil_status_t st;

    if (ctx->focus_owner_kind == 1u) {
        st = rebuild_anchor_key(
            ctx->focus_tx_id, primary_key, &primary_key_len);
    } else if (ctx->focus_owner_kind == 2u) {
        st = rebuild_delivery_key(
            ctx->focus_raw80, ctx->focus_raw_len, primary_key,
            &primary_key_len);
    } else {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (st != NINLIL_OK) {
        return st;
    }
    return key_digest_of(
        primary_key, primary_key_len, ctx->focus_primary_key_digest);
}

/*
 * declared cancel ATTEMPT lane 0|1 from CANCEL_STATE companion:
 * ABSENT (EventFact) → 0; PRESENT with non-zero cancel_attempt_id → 1;
 * PRESENT with zero cancel_attempt_id (NONE) → 0.
 * Port failure: sticky, note 0 (H3).
 */
static ninlil_status_t load_declared_cancel_attempt_count(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    uint64_t *out_cancel)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    ninlil_model_domain_typed_record_t *tr;

    *out_cancel = 0u;
    if (ctx->focus_owner_kind == 1u) {
        st = rebuild_tx_cancel_state_key(
            ctx->focus_tx_id, ctx->peer_key, &ctx->peer_key_len);
    } else if (ctx->focus_owner_kind == 2u) {
        st = rebuild_delivery_cancel_state_key(
            ctx->focus_raw80, ctx->focus_raw_len, ctx->peer_key,
            &ctx->peer_key_len);
    } else {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (st != NINLIL_OK) {
        return st;
    }
    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    st = ninlil_domain_scan_exact_get(session, key_view, &got);
    if (st != NINLIL_OK) {
        return st; /* Port: no note */
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return NINLIL_OK;
    }
    if (session->bound_workspace == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tr = &session->bound_workspace->row_validate_scratch.typed;
    {
        ninlil_bytes_view_t kv;
        kv.data = ctx->peer_key;
        kv.length = ctx->peer_key_len;
        if (ninlil_model_domain_validate_typed_record(kv, got.value, tr)
                != NINLIL_OK
            || tr->subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    if (!ninlil_model_domain_id_is_zero(tr->cancel_state.cancel_attempt_id)) {
        *out_cancel = 1u;
    }
    return NINLIL_OK;
}

/* ---- phase / mask helpers ---- */

static int is_focus_stream_phase(uint8_t phase)
{
    return phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT
        || phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX
        || phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_MANAGEMENT;
}

static int is_focus_known_slot_phase(uint8_t phase)
{
    return phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_EVIDENCE
        || phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_REPLY
        || phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_RETRY;
}

static int is_bind_phase(uint8_t phase)
{
    return phase >= NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT
        && phase <= NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_MANAGEMENT;
}

static void clear_observed_lanes(ninlil_domain_scan_d3s2_context_t *ctx)
{
    set_u64_lane(ctx->observed_a, 0u);
    set_u64_lane(ctx->observed_b, 0u);
    set_u64_lane(ctx->observed_c, 0u);
    ctx->observed_reply_mask = 0u;
    ctx->evidence_slot_mask[0] = 0u;
    ctx->evidence_slot_mask[1] = 0u;
    ctx->retry_slot_mask = 0u;
}

static void clear_declared_lanes(ninlil_domain_scan_d3s2_context_t *ctx)
{
    set_u64_lane(ctx->declared_a, 0u);
    set_u64_lane(ctx->declared_b, 0u);
    set_u64_lane(ctx->declared_c, 0u);
    encode_u32_be_field(ctx->declared_reply_count, 0u);
    ctx->declared_L = 0u;
    ctx->declared_retry_recent_n = 0u;
    ctx->declared_flags = 0u;
}

static void clear_focus_identity(ninlil_domain_scan_d3s2_context_t *ctx)
{
    (void)memset(ctx->focus_raw80, 0, sizeof(ctx->focus_raw80));
    ctx->focus_raw_len = 0u;
    (void)memset(ctx->focus_tx_id, 0, sizeof(ctx->focus_tx_id));
    (void)memset(
        ctx->focus_primary_key_digest, 0, sizeof(ctx->focus_primary_key_digest));
    ctx->focus_owner_kind = 0u;
    ctx->focus_family_gate = 0u;
    ctx->source_aux_len = 0u;
    ctx->peer_key_len = 0u;
    ctx->cleanup_skip = 0u;
}

static int mode_is_carrier_subtype(
    uint8_t focus_mode,
    uint8_t family,
    uint8_t subtype,
    const ninlil_model_domain_typed_record_t *typed)
{
    if (family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN || typed == NULL) {
        return 0;
    }
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE
            || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_REVERSE_REPLY:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_RETRY:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY
            && typed->retry_summary.summary_kind
            == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE
            && typed->retry_summary.slot_index == 0u;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_MANAGEMENT:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL;
    default:
        return 0;
    }
}

static uint8_t first_focus_phase(uint8_t focus_mode)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_EVIDENCE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_REVERSE_REPLY:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_REPLY;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_RETRY:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_RETRY;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_MANAGEMENT:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_MANAGEMENT;
    default:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
    }
}

static uint8_t first_bind_phase(uint8_t focus_mode)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_EVIDENCE;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_REVERSE_REPLY:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_REPLY;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_RETRY:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_RETRY;
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_MANAGEMENT:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_MANAGEMENT;
    default:
        return NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
    }
}

static uint8_t bind_mask_bit_for_phase(uint8_t phase)
{
    switch (phase) {
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_INDEX:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_EVIDENCE:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_REPLY:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_RETRY:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_MANAGEMENT:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT;
    default:
        return 0u;
    }
}

static uint8_t focus_mask_bit_for_phase(uint8_t phase)
{
    switch (phase) {
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_EVIDENCE:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_REPLY:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_RETRY:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_MANAGEMENT:
        return NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT;
    default:
        return 0u;
    }
}

/* ---- CLEANUP_PLAN gate (Modes 21/22 only for skip) ---- */

static ninlil_status_t apply_cleanup_plan_gate(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    uint16_t subject_kind;

    ctx->cleanup_skip = 0u;
    if (ctx->focus_mode >= NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE) {
        /* Modes 23–26: ordinary counts always apply. */
        return NINLIL_OK;
    }
    if (ctx->focus_owner_kind == 1u) {
        subject_kind = NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_TRANSACTION;
    } else if (ctx->focus_owner_kind == 2u) {
        subject_kind = NINLIL_MODEL_DOMAIN_CLEANUP_SUBJECT_DELIVERY;
    } else {
        return NINLIL_OK;
    }
    /*
     * CLEANUP_PLAN key = COMPOSITE(63, subject_kind || KEY_DIGEST(complete
     * true primary key)). Must use ANCHOR/DELIVERY digest already installed
     * in focus_primary_key_digest — never STATE/RESULT carrier key digest.
     */
    st = rebuild_cleanup_plan_key(
        subject_kind, ctx->focus_primary_key_digest, ctx->peer_key,
        &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return st;
    }
    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    st = ninlil_domain_scan_exact_get(session, key_view, &got);
    if (st != NINLIL_OK) {
        /* Port failure: sticky already; no note (H3). */
        return st;
    }
    if (got.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        ctx->cleanup_skip = 1u;
    }
    return NINLIL_OK;
}

/* ---- carrier install ---- */

static ninlil_status_t install_carrier_from_typed(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s2_context_t *ctx,
    uint32_t key_length)
{
    const ninlil_model_domain_typed_record_t *typed = typed_of(workspace);
    uint8_t subtype = workspace->key[9];
    uint8_t L;
    uint64_t app;
    uint64_t cancel;
    uint64_t total;

    clear_focus_identity(ctx);
    clear_declared_lanes(ctx);
    clear_observed_lanes(ctx);
    ctx->count_complete_mask = 0u;

    if (key_length == 0u
        || key_length > NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(ctx->last_carrier_key, workspace->key, key_length);
    ctx->last_carrier_key_len = (uint8_t)key_length;

    switch (ctx->focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT:
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(
            ctx->focus_tx_id, typed->transaction_state.transaction_id, 16u);
        (void)memcpy(
            ctx->focus_raw80, typed->transaction_state.transaction_id, 16u);
        ctx->focus_raw_len = 16u;
        ctx->focus_owner_kind = 1u;
        if (install_true_primary_key_digest(ctx) != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        app = typed->transaction_state.cumulative_attempts;
        /* Cancel declared 0|1 from TX CANCEL_STATE companion (§9 / §18.13.12.1). */
        {
            ninlil_status_t cst;
            cst = load_declared_cancel_attempt_count(session, ctx, &cancel);
            if (cst != NINLIL_OK) {
                return cst;
            }
        }
        set_u64_lane(ctx->declared_a, app);
        set_u64_lane(ctx->declared_b, cancel);
        set_u64_lane(ctx->declared_c, app + cancel);
        break;

    case NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT:
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (typed->result_cache.delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(
            ctx->focus_raw80, typed->result_cache.delivery_key_raw, 80u);
        ctx->focus_raw_len = 80u;
        (void)memcpy(
            ctx->focus_tx_id, typed->result_cache.transaction_id, 16u);
        ctx->focus_owner_kind = 2u;
        if (install_true_primary_key_digest(ctx) != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        app = (uint64_t)typed->result_cache.application_attempt_count;
        /* Cancel 0|1 from DLV CANCEL_STATE (not app==0 heuristic). C MBZ. */
        {
            ninlil_status_t cst;
            cst = load_declared_cancel_attempt_count(session, ctx, &cancel);
            if (cst != NINLIL_OK) {
                return cst;
            }
        }
        set_u64_lane(ctx->declared_a, app);
        set_u64_lane(ctx->declared_b, cancel);
        set_u64_lane(ctx->declared_c, 0u); /* MBZ */
        break;

    case NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE:
        if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE) {
            (void)memcpy(
                ctx->focus_tx_id, typed->transaction_state.transaction_id,
                16u);
            (void)memcpy(
                ctx->focus_raw80, typed->transaction_state.transaction_id,
                16u);
            ctx->focus_raw_len = 16u;
            ctx->focus_owner_kind = 1u;
        } else if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE) {
            if (typed->result_cache.delivery_key_raw_length
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            (void)memcpy(
                ctx->focus_raw80, typed->result_cache.delivery_key_raw, 80u);
            ctx->focus_raw_len = 80u;
            (void)memcpy(
                ctx->focus_tx_id, typed->result_cache.transaction_id, 16u);
            ctx->focus_owner_kind = 2u;
            if (typed->result_cache.application_attempt_count == 0u) {
                /* CANCEL_FIRST → empty evidence set. */
                ctx->declared_L = 0u;
                set_u64_lane(ctx->declared_a, 0u);
                set_u64_lane(ctx->declared_b, 0u);
                set_u64_lane(ctx->declared_c, 0u);
                return apply_cleanup_plan_gate(session, ctx);
            }
        } else {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (install_true_primary_key_digest(ctx) != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        L = 0u;
        if (session->bound_workspace != NULL) {
            L = (uint8_t)session->bound_workspace->candidate.limits
                    .max_evidence_per_target;
        }
        if (L < 1u || L > 8u) {
            L = 1u;
        }
        ctx->declared_L = L;
        /* SUMMARY counters filled at B6k after slot0 get when PRESENT. */
        set_u64_lane(ctx->declared_a, 0u);
        set_u64_lane(ctx->declared_b, 0u);
        set_u64_lane(ctx->declared_c, 0u);
        break;

    case NINLIL_DOMAIN_SCAN_D3S2_MODE_REVERSE_REPLY:
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (typed->result_cache.delivery_key_raw_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(
            ctx->focus_raw80, typed->result_cache.delivery_key_raw, 80u);
        ctx->focus_raw_len = 80u;
        (void)memcpy(
            ctx->focus_tx_id, typed->result_cache.transaction_id, 16u);
        ctx->focus_owner_kind = 2u;
        if (install_true_primary_key_digest(ctx) != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        total = (uint64_t)typed->result_cache.reply_count;
        if (total > 4u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        set_u64_lane(ctx->declared_a, total);
        encode_u32_be_field(ctx->declared_reply_count, (uint32_t)total);
        set_u64_lane(ctx->declared_b, 0u);
        set_u64_lane(ctx->declared_c, 0u);
        break;

    case NINLIL_DOMAIN_SCAN_D3S2_MODE_RETRY:
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(
            ctx->focus_tx_id, typed->retry_summary.transaction_id, 16u);
        (void)memcpy(
            ctx->focus_raw80, typed->retry_summary.transaction_id, 16u);
        ctx->focus_raw_len = 16u;
        ctx->focus_owner_kind = 1u;
        if (install_true_primary_key_digest(ctx) != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        total = typed->retry_summary.cumulative.total_completed_cycle_count;
        set_u64_lane(ctx->declared_a, total);
        {
            uint64_t recent_n = total < 4u ? total : 4u;
            set_u64_lane(ctx->declared_b, recent_n);
            ctx->declared_retry_recent_n = (uint8_t)recent_n;
        }
        set_u64_lane(ctx->declared_c, 1u); /* CUM expected present */
        break;

    case NINLIL_DOMAIN_SCAN_D3S2_MODE_MANAGEMENT:
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(
            ctx->focus_tx_id, typed->event_spool.transaction_id, 16u);
        (void)memcpy(
            ctx->focus_raw80, typed->event_spool.transaction_id, 16u);
        ctx->focus_raw_len = 16u;
        ctx->focus_owner_kind = 1u;
        if (install_true_primary_key_digest(ctx) != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        total = (uint64_t)typed->event_spool.successful_resume_count
            + (uint64_t)typed->event_spool.discard_committed;
        if (total > 9u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        set_u64_lane(ctx->declared_a, total);
        set_u64_lane(ctx->declared_b, 0u);
        set_u64_lane(ctx->declared_c, 0u);
        break;

    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }

    return apply_cleanup_plan_gate(session, ctx);
}

/* ---- FOCUS stream match ---- */

static int stream_attempt_matches(
    const ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_model_domain_body_attempt_t *att)
{
    if (ctx->focus_owner_kind == 1u) {
        if (att->attempt_owner_kind
                != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
            || att->owner_key_raw_length != 16u
            || memcmp(att->owner_key_raw, ctx->focus_raw80, 16u) != 0
            || memcmp(att->transaction_id, ctx->focus_tx_id, 16u) != 0) {
            return 0;
        }
    } else if (ctx->focus_owner_kind == 2u) {
        if (att->attempt_owner_kind
                != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY
            || att->owner_key_raw_length != 80u
            || memcmp(att->owner_key_raw, ctx->focus_raw80, 80u) != 0) {
            return 0;
        }
    } else {
        return 0;
    }
    return memcmp(
               att->primary_key_digest, ctx->focus_primary_key_digest, 32u)
        == 0;
}

static int stream_index_matches(
    const ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_model_domain_body_attempt_id_index_t *idx)
{
    return memcmp(idx->transaction_id, ctx->focus_tx_id, 16u) == 0;
}

static int stream_management_matches(
    const ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_model_domain_body_management_ledger_t *mg)
{
    return memcmp(mg->transaction_id, ctx->focus_tx_id, 16u) == 0;
}

static int key_strictly_greater_than_last(
    const ninlil_domain_scan_d3s2_context_t *ctx,
    const uint8_t *key,
    uint32_t key_length)
{
    uint32_t common;
    int order;

    if (ctx->last_carrier_key_len == 0u) {
        return 1; /* last is −∞ */
    }
    if (key_length > 255u) {
        return 0;
    }
    common = (uint32_t)ctx->last_carrier_key_len < key_length
        ? (uint32_t)ctx->last_carrier_key_len
        : key_length;
    order = memcmp(ctx->last_carrier_key, key, common);
    if (order < 0) {
        return 1; /* last < key */
    }
    if (order > 0) {
        return 0; /* last > key */
    }
    /* prefix equal: longer wins in memcmp-style domain lex */
    return (uint32_t)ctx->last_carrier_key_len < key_length;
}

static ninlil_status_t on_row_select(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s2_context_t *ctx,
    uint32_t key_length,
    uint8_t typed_current_ok)
{
    const ninlil_model_domain_typed_record_t *typed;
    uint8_t family;
    uint8_t subtype;
    ninlil_status_t st;

    if (typed_current_ok == 0u || key_length < 10u) {
        return NINLIL_OK;
    }
    family = workspace->key[8];
    subtype = workspace->key[9];
    typed = typed_of(workspace);
    if (!mode_is_carrier_subtype(ctx->focus_mode, family, subtype, typed)) {
        return NINLIL_OK;
    }
    /* First remaining eligible: complete key strictly greater than last. */
    if (!key_strictly_greater_than_last(ctx, workspace->key, key_length)) {
        return NINLIL_OK;
    }

    st = install_carrier_from_typed(session, workspace, ctx, key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    ctx->phase = first_focus_phase(ctx->focus_mode);
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE);
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_BIND_PHASE_ACTIVE);
    /* Drive coordination: carrier installed this pass (existing flags u8). */
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED);
    return NINLIL_OK;
}

static ninlil_status_t on_row_focus_stream(
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_workspace_t *workspace,
    uint8_t typed_current_ok)
{
    const ninlil_model_domain_typed_record_t *typed;
    uint8_t subtype;

    if (typed_current_ok == 0u) {
        return NINLIL_OK;
    }
    /*
     * P0-2: SELECT residual rows after carrier install must not count.
     * CARRIER_INSTALLED is set by on_row_select in the same advance; drive
     * reopens zero-prefix and clears the flag before the true FOCUS stream.
     */
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED)) {
        return NINLIL_OK;
    }
    typed = typed_of(workspace);
    subtype = typed->subtype;

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
            return NINLIL_OK;
        }
        if (!stream_attempt_matches(ctx, &typed->attempt)) {
            return NINLIL_OK;
        }
        if (typed->attempt.attempt_kind
            == NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL) {
            inc_u64_lane(ctx->observed_b);
        } else {
            inc_u64_lane(ctx->observed_a);
        }
        return NINLIL_OK;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX) {
            return NINLIL_OK;
        }
        if (!stream_index_matches(ctx, &typed->attempt_id_index)) {
            return NINLIL_OK;
        }
        inc_u64_lane(ctx->observed_c);
        return NINLIL_OK;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_MANAGEMENT) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER) {
            return NINLIL_OK;
        }
        if (!stream_management_matches(ctx, &typed->management_ledger)) {
            return NINLIL_OK;
        }
        inc_u64_lane(ctx->observed_a);
        return NINLIL_OK;
    }
    return NINLIL_OK;
}

/* ---- focus-close compare (H2 / B6k shared) ---- */

static ninlil_status_t focus_close_compare(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    uint8_t bit = focus_mask_bit_for_phase(ctx->phase);
    uint64_t da = get_u64_lane(ctx->declared_a);
    uint64_t db = get_u64_lane(ctx->declared_b);
    uint64_t dc = get_u64_lane(ctx->declared_c);
    uint64_t oa = get_u64_lane(ctx->observed_a);
    uint64_t ob = get_u64_lane(ctx->observed_b);
    uint64_t oc = get_u64_lane(ctx->observed_c);

    if (ctx->cleanup_skip != 0u
        && (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT
            || ctx->focus_mode
                == NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT)
        && (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT
            || ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX)) {
        /* Mandatory skip ordinary compare for Mode21/22 under plan. */
        ctx->count_complete_mask =
            (uint8_t)(ctx->count_complete_mask | bit);
        return NINLIL_OK;
    }

    switch (ctx->phase) {
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT:
        if (oa != da || ob != db) {
            return note_finding(session);
        }
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT
            && oc != 0u) {
            return note_finding(session);
        }
        break;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX:
        /* Mode21: observed_c == declared_c == A+B */
        if (oc != dc || dc != da + db) {
            return note_finding(session);
        }
        break;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_MANAGEMENT:
        if (oa != da || ob != 0u || oc != 0u) {
            return note_finding(session);
        }
        break;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_REPLY:
        if (oa != da || (uint32_t)popcount8(ctx->observed_reply_mask) != oa
            || decode_u32_be_field(ctx->declared_reply_count) != (uint32_t)da
            || ob != 0u || oc != 0u) {
            return note_finding(session);
        }
        break;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_RETRY:
        /* observed_a == declared_b (RECENT count); observed_c == declared_c */
        if (oa != db || oc != dc || ob != 0u
            || ctx->declared_retry_recent_n != (uint8_t)db) {
            return note_finding(session);
        }
        break;
    case NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_EVIDENCE:
        /* Equation when SUMMARY present (declared_a may be 0 if absent):
         * declared_a == observed_a + declared_b
         * late: observed_c <= declared_c <= declared_a; declared_b <= declared_a
         */
        if (ctx->declared_L == 0u) {
            if (oa != 0u || ob != 0u || oc != 0u) {
                return note_finding(session);
            }
            break;
        }
        if (da != oa + db) {
            return note_finding(session);
        }
        if (oc > dc || dc > da || db > da) {
            return note_finding(session);
        }
        if (ob != 0u) {
            return note_finding(session);
        }
        break;
    default:
        return NINLIL_E_INVALID_STATE;
    }

    ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask | bit);
    return NINLIL_OK;
}

static ninlil_status_t after_focus_subphase_done(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    ninlil_status_t st;

    st = focus_close_compare(session, ctx);
    if (st != NINLIL_OK) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
        return st;
    }

    /* Mode21: ATTEMPT then INDEX. */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT
        && ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT) {
        clear_observed_lanes(ctx);
        /* INDEX uses observed_c only; reset all observed for clean count. */
        clear_observed_lanes(ctx);
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN);
        return NINLIL_OK;
    }

    /* Carrier focus complete → next SELECT. */
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE);
    clear_observed_lanes(ctx);
    clear_focus_identity(ctx);
    ctx->cleanup_skip = 0u;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER;
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

/* ---- known-slot B6k ---- */

static ninlil_status_t focus_known_slot_matrix(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    uint32_t i;

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_EVIDENCE) {
        uint8_t L = ctx->declared_L;
        uint16_t owner_kind;
        if (L == 0u) {
            /* Empty set: no cells expected. */
            return after_focus_subphase_done(session, ctx);
        }
        owner_kind = ctx->focus_owner_kind == 1u
            ? NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
            : NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY;
        for (i = 0u; i <= (uint32_t)L; i += 1u) {
            st = rebuild_evidence_key(
                owner_kind, ctx->focus_raw80, ctx->focus_raw_len, i,
                ctx->peer_key, &ctx->peer_key_len);
            if (st != NINLIL_OK) {
                return st;
            }
            key_view.data = ctx->peer_key;
            key_view.length = ctx->peer_key_len;
            st = ninlil_domain_scan_exact_get(session, key_view, &got);
            if (st != NINLIL_OK) {
                return st;
            }
            if (got.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
                if (i < 8u) {
                    ctx->evidence_slot_mask[0] =
                        (uint8_t)(ctx->evidence_slot_mask[0] | (uint8_t)(1u << i));
                } else {
                    ctx->evidence_slot_mask[1] =
                        (uint8_t)(ctx->evidence_slot_mask[1] | 0x01u);
                }
                /* Decode value via workspace after exact_get (value in WS). */
                {
                    ninlil_bytes_view_t kv;
                    ninlil_bytes_view_t vv;
                    ninlil_model_domain_typed_record_t *tr =
                        &session->bound_workspace->row_validate_scratch.typed;
                    kv.data = ctx->peer_key;
                    kv.length = ctx->peer_key_len;
                    vv = got.value;
                    if (ninlil_model_domain_validate_typed_record(kv, vv, tr)
                        == NINLIL_OK
                        && tr->subtype
                            == NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL) {
                        if (i == 0u
                            && tr->evidence_cell.cell_kind
                                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY) {
                            set_u64_lane(
                                ctx->declared_a,
                                tr->evidence_cell.valid_material_count);
                            set_u64_lane(
                                ctx->declared_b,
                                tr->evidence_cell.raw_overflow_count);
                            set_u64_lane(
                                ctx->declared_c,
                                tr->evidence_cell.late_evidence_count);
                        } else if (
                            i >= 1u
                            && tr->evidence_cell.cell_kind
                                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW
                            && tr->evidence_cell.cell_state
                                == NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED) {
                            inc_u64_lane(ctx->observed_a);
                            if (tr->evidence_cell.late_material != 0u) {
                                inc_u64_lane(ctx->observed_c);
                            }
                        }
                    }
                }
            } else if (i == 0u) {
                /* SUMMARY ABSENT: declared counters stay 0 until presence fail. */
            }
        }
        /*
         * P0-8 Mode23 close (1)(6): slots 0..L must all be PRESENT
         * (evidence_slot_mask). Physical absence is a real finding even when
         * SUMMARY counters happen to be 0-coherent.
         */
        for (i = 0u; i <= (uint32_t)L; i += 1u) {
            int present;
            if (i < 8u) {
                present = (ctx->evidence_slot_mask[0]
                              & (uint8_t)(1u << i))
                    != 0u;
            } else {
                present = (ctx->evidence_slot_mask[1] & 0x01u) != 0u;
            }
            if (!present) {
                return note_finding(session);
            }
        }
        return after_focus_subphase_done(session, ctx);
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_REPLY) {
        /*
         * Mode24 known-kind presence matrix (docs/17 §18.13.7 / §18.13.12.1):
         * exact_get all closed reply_kind 1..4 rebuilt from RESULT carrier
         * delivery_key_raw. ABSENT is legal; PRESENT requires typed body
         * delivery raw + reply_kind match. observed_a = popcount(mask);
         * close compares to declared reply_count (A / declared_reply_count).
         */
        uint32_t kind;

        if (ctx->focus_raw_len
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            || ctx->focus_owner_kind != 2u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        ctx->observed_reply_mask = 0u;
        set_u64_lane(ctx->observed_a, 0u);
        set_u64_lane(ctx->observed_b, 0u);
        set_u64_lane(ctx->observed_c, 0u);

        for (kind = NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT;
             kind <= NINLIL_MODEL_DOMAIN_REPLY_KIND_CANCEL_RESULT;
             kind += 1u) {
            st = rebuild_reverse_reply_key(
                ctx->focus_raw80, ctx->focus_raw_len, kind, ctx->peer_key,
                &ctx->peer_key_len);
            if (st != NINLIL_OK) {
                return st;
            }
            key_view.data = ctx->peer_key;
            key_view.length = ctx->peer_key_len;
            st = ninlil_domain_scan_exact_get(session, key_view, &got);
            if (st != NINLIL_OK) {
                return st; /* H3 Port: no note */
            }
            if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
                continue;
            }
            {
                ninlil_bytes_view_t kv;
                ninlil_model_domain_typed_record_t *tr;

                if (session->bound_workspace == NULL) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
                tr = &session->bound_workspace->row_validate_scratch.typed;
                kv.data = ctx->peer_key;
                kv.length = ctx->peer_key_len;
                if (ninlil_model_domain_validate_typed_record(
                        kv, got.value, tr)
                        != NINLIL_OK
                    || tr->subtype
                        != NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY) {
                    return note_finding(session);
                }
                if (tr->reverse_reply.delivery_key_raw_length
                        != ctx->focus_raw_len
                    || memcmp(
                           tr->reverse_reply.delivery_key_raw,
                           ctx->focus_raw80, ctx->focus_raw_len)
                        != 0
                    || tr->reverse_reply.reply_kind != kind) {
                    return note_finding(session);
                }
            }
            /* bit0..3 ↔ kinds 1..4 */
            ctx->observed_reply_mask = (uint8_t)(ctx->observed_reply_mask
                | (uint8_t)(1u << (kind - 1u)));
            inc_u64_lane(ctx->observed_a);
        }
        return after_focus_subphase_done(session, ctx);
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_RETRY) {
        /* CUM slot0 already is the carrier; probe RECENT 0..3. */
        st = rebuild_retry_key(
            ctx->focus_tx_id,
            NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE, 0u, ctx->peer_key,
            &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return st;
        }
        key_view.data = ctx->peer_key;
        key_view.length = ctx->peer_key_len;
        st = ninlil_domain_scan_exact_get(session, key_view, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            ctx->retry_slot_mask = (uint8_t)(ctx->retry_slot_mask | 0x01u);
            set_u64_lane(ctx->observed_c, 1u);
        } else {
            set_u64_lane(ctx->observed_c, 0u);
        }
        for (i = 0u; i < 4u; i += 1u) {
            st = rebuild_retry_key(
                ctx->focus_tx_id,
                NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_RECENT, (uint16_t)i,
                ctx->peer_key, &ctx->peer_key_len);
            if (st != NINLIL_OK) {
                return st;
            }
            key_view.data = ctx->peer_key;
            key_view.length = ctx->peer_key_len;
            st = ninlil_domain_scan_exact_get(session, key_view, &got);
            if (st != NINLIL_OK) {
                return st;
            }
            if (got.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
                ctx->retry_slot_mask =
                    (uint8_t)(ctx->retry_slot_mask | (uint8_t)(1u << (i + 1u)));
                inc_u64_lane(ctx->observed_a);
            }
        }
        return after_focus_subphase_done(session, ctx);
    }

    return NINLIL_E_INVALID_STATE;
}

/* ---- BIND per-row ---- */

/*
 * Typed-validate exact_get value into workspace scratch. Returns note on
 * validate/subtype failure; Port path is caller's exact_get status.
 */
static ninlil_status_t bind_typed_from_get(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got,
    uint8_t expected_subtype,
    const ninlil_model_domain_typed_record_t **out_typed)
{
    ninlil_bytes_view_t kv;
    ninlil_model_domain_typed_record_t *tr;

    if (session == NULL || session->bound_workspace == NULL || ctx == NULL
        || got == NULL || out_typed == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tr = &session->bound_workspace->row_validate_scratch.typed;
    kv.data = ctx->peer_key;
    kv.length = ctx->peer_key_len;
    if (ninlil_model_domain_validate_typed_record(kv, got->value, tr)
            != NINLIL_OK
        || tr->subtype != expected_subtype) {
        return note_finding(session);
    }
    *out_typed = tr;
    return NINLIL_OK;
}

/*
 * P1-1: true primary PRESENT + VALUE_DIGEST match + raw identity bijection
 * vs BIND scratch (TX id for ANCHOR; delivery raw for DELIVERY).
 * Uses peer_key already rebuilt as the true-primary complete key.
 * Budget: ≤1 exact_get.
 */
static ninlil_status_t verify_true_primary_pvd_and_raw(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const uint8_t expected_pvd[32])
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    ninlil_model_domain_digest_t dig;
    const ninlil_model_domain_typed_record_t *tr;

    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    st = ninlil_domain_scan_exact_get(session, key_view, &got);
    if (st != NINLIL_OK) {
        return st; /* Port: no note */
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = ninlil_model_domain_value_digest(got.value, &dig);
    if (st != NINLIL_OK
        || memcmp(dig.bytes, expected_pvd, 32u) != 0) {
        return note_finding(session);
    }

    if (ctx->focus_owner_kind == 1u) {
        st = bind_typed_from_get(
            session, ctx, &got,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR, &tr);
        if (st != NINLIL_OK) {
            return st;
        }
        if (memcmp(tr->transaction_anchor.transaction_id, ctx->focus_tx_id, 16u)
            != 0) {
            return note_finding(session);
        }
    } else if (ctx->focus_owner_kind == 2u) {
        st = bind_typed_from_get(
            session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, &tr);
        if (st != NINLIL_OK) {
            return st;
        }
        if (tr->delivery.delivery_key_raw_length != ctx->focus_raw_len
            || ctx->focus_raw_len
                != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
            || memcmp(
                   tr->delivery.delivery_key_raw, ctx->focus_raw80,
                   ctx->focus_raw_len)
                != 0) {
            return note_finding(session);
        }
    } else {
        return note_finding(session);
    }
    return NINLIL_OK;
}

/* P1-2 carrier companions: typed subject/raw vs secondary scratch. */

static ninlil_status_t verify_carrier_tx_state(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got)
{
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;

    st = bind_typed_from_get(
        session, ctx, got, NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (memcmp(tr->transaction_state.transaction_id, ctx->focus_tx_id, 16u)
        != 0) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

static ninlil_status_t verify_carrier_result_cache(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got)
{
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;

    st = bind_typed_from_get(
        session, ctx, got, NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (tr->result_cache.delivery_key_raw_length != ctx->focus_raw_len
        || ctx->focus_raw_len
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || memcmp(
               tr->result_cache.delivery_key_raw, ctx->focus_raw80,
               ctx->focus_raw_len)
            != 0
        || memcmp(tr->result_cache.transaction_id, ctx->focus_tx_id, 16u)
            != 0) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

static ninlil_status_t verify_carrier_event_spool(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got)
{
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;

    st = bind_typed_from_get(
        session, ctx, got, NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (memcmp(tr->event_spool.transaction_id, ctx->focus_tx_id, 16u) != 0) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

static ninlil_status_t verify_carrier_retry_cum(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got)
{
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;

    st = bind_typed_from_get(
        session, ctx, got, NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (memcmp(tr->retry_summary.transaction_id, ctx->focus_tx_id, 16u) != 0
        || tr->retry_summary.summary_kind
            != NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE
        || tr->retry_summary.slot_index != 0u) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

/*
 * P1-3: Mode21 INDEX peer body vs ATTEMPT scratch (attempt_id / tx /
 * attempt_record_key_digest complete-key KEY_DIGEST).
 */
static ninlil_status_t verify_index_pair_for_attempt(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got,
    const ninlil_model_domain_body_attempt_t *att)
{
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;
    uint8_t att_key[NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY];
    uint8_t att_key_len = 0u;
    uint8_t dig[32];

    st = bind_typed_from_get(
        session, ctx, got, NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (memcmp(tr->attempt_id_index.attempt_id, att->attempt_id, 16u) != 0
        || memcmp(
               tr->attempt_id_index.transaction_id, att->transaction_id, 16u)
            != 0) {
        return note_finding(session);
    }
    st = rebuild_attempt_key(
        NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION, att->transaction_id,
        16u, att->attempt_id, att_key, &att_key_len);
    if (st != NINLIL_OK
        || key_digest_of(att_key, att_key_len, dig) != NINLIL_OK
        || memcmp(dig, tr->attempt_id_index.attempt_record_key_digest, 32u)
            != 0) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

static ninlil_status_t bind_attempt_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    /*
     * Copy-before-get: any companion/primary typed validate reuses the
     * workspace typed scratch and would invalidate a live *typed pointer.
     */
    uint8_t attempt_id[16];
    uint8_t transaction_id[16];
    uint8_t owner_raw[80];
    uint16_t owner_raw_len;
    uint16_t attempt_owner_kind;
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    uint8_t expected_pvd[32];
    ninlil_model_domain_body_attempt_t att_local;

    if (typed->attempt.owner_key_raw_length > 80u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    owner_raw_len = typed->attempt.owner_key_raw_length;
    attempt_owner_kind = typed->attempt.attempt_owner_kind;
    (void)memcpy(attempt_id, typed->attempt.attempt_id, 16u);
    (void)memcpy(transaction_id, typed->attempt.transaction_id, 16u);
    (void)memcpy(owner_raw, typed->attempt.owner_key_raw, owner_raw_len);
    (void)memcpy(
        expected_pvd, typed->envelope.header.primary_value_digest, 32u);

    /* Durable BIND scratch for carrier/primary/pair (no second 4096). */
    (void)memcpy(ctx->focus_raw80, owner_raw, owner_raw_len);
    ctx->focus_raw_len = (uint8_t)owner_raw_len;
    (void)memcpy(ctx->focus_tx_id, transaction_id, 16u);
    (void)memcpy(ctx->focus_primary_key_digest, expected_pvd, 32u);
    (void)memcpy(ctx->source_aux, attempt_id, 16u);
    ctx->source_aux_len = 16u;
    ctx->focus_owner_kind =
        attempt_owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
        ? 1u
        : 2u;

    /* Local attempt view for pair proof after scratch reuse. */
    (void)memset(&att_local, 0, sizeof(att_local));
    (void)memcpy(att_local.attempt_id, attempt_id, 16u);
    (void)memcpy(att_local.transaction_id, transaction_id, 16u);
    att_local.attempt_owner_kind = attempt_owner_kind;
    att_local.owner_key_raw_length = owner_raw_len;
    att_local.owner_key_raw = owner_raw;

    /* 2. Carrier companion. */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT) {
        st = rebuild_tx_state_key(
            transaction_id, ctx->peer_key, &ctx->peer_key_len);
    } else {
        st = rebuild_result_cache_key(
            owner_raw, owner_raw_len, ctx->peer_key, &ctx->peer_key_len);
    }
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    st = ninlil_domain_scan_exact_get(session, key_view, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    /* P1-2: carrier subject/raw typed match. */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT) {
        st = verify_carrier_tx_state(session, ctx, &got);
    } else {
        st = verify_carrier_result_cache(session, ctx, &got);
    }
    if (st != NINLIL_OK) {
        return st;
    }

    /* 3. True primary (P1-1: PVD + raw bijection). */
    if (ctx->focus_owner_kind == 1u) {
        st = rebuild_anchor_key(
            transaction_id, ctx->peer_key, &ctx->peer_key_len);
    } else {
        st = rebuild_delivery_key(
            owner_raw, owner_raw_len, ctx->peer_key, &ctx->peer_key_len);
    }
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = verify_true_primary_pvd_and_raw(session, ctx, expected_pvd);
    if (st != NINLIL_OK) {
        return st;
    }

    /* 4. Pair peer (≤1 get; Mode21 PRESENT body bijection / Mode22 ABSENT). */
    st = rebuild_attempt_index_key(
        attempt_id, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    st = ninlil_domain_scan_exact_get(session, key_view, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT) {
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        /* P1-3: INDEX body attempt_id / tx / record key digest. */
        st = verify_index_pair_for_attempt(session, ctx, &got, &att_local);
        if (st != NINLIL_OK) {
            return st;
        }
    } else {
        /* Mode22: INDEX ABSENT. */
        if (got.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
    }
    return NINLIL_OK;
}

static ninlil_status_t bind_index_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    uint8_t attempt_id[16];
    uint8_t transaction_id[16];
    uint8_t attempt_record_key_digest[32];
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    uint8_t expected_pvd[32];

    /* Copy-before-get: primary typed validate overwrites workspace scratch. */
    (void)memcpy(attempt_id, typed->attempt_id_index.attempt_id, 16u);
    (void)memcpy(
        transaction_id, typed->attempt_id_index.transaction_id, 16u);
    (void)memcpy(
        attempt_record_key_digest,
        typed->attempt_id_index.attempt_record_key_digest, 32u);
    (void)memcpy(
        expected_pvd, typed->envelope.header.primary_value_digest, 32u);

    (void)memcpy(ctx->focus_tx_id, transaction_id, 16u);
    (void)memcpy(ctx->source_aux, attempt_id, 16u);
    ctx->source_aux_len = 16u;
    (void)memcpy(ctx->focus_primary_key_digest, expected_pvd, 32u);

    /* No STATE companion for BIND_INDEX. True primary ANCHOR (P1-1 raw). */
    ctx->focus_owner_kind = 1u;
    ctx->focus_raw_len = 16u;
    (void)memcpy(ctx->focus_raw80, transaction_id, 16u);
    st = rebuild_anchor_key(
        transaction_id, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = verify_true_primary_pvd_and_raw(session, ctx, expected_pvd);
    if (st != NINLIL_OK) {
        return st;
    }

    /* ATTEMPT PRESENT pair: digest bijection + typed subject match. */
    st = rebuild_attempt_key(
        NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION, transaction_id, 16u,
        attempt_id, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    {
        uint8_t dig[32];
        if (key_digest_of(ctx->peer_key, ctx->peer_key_len, dig) != NINLIL_OK
            || memcmp(dig, attempt_record_key_digest, 32u) != 0) {
            return note_finding(session);
        }
    }
    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    st = ninlil_domain_scan_exact_get(session, key_view, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    /* Symmetric to P1-3: ATTEMPT body attempt_id / tx match INDEX. */
    {
        const ninlil_model_domain_typed_record_t *tr;
        st = bind_typed_from_get(
            session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT, &tr);
        if (st != NINLIL_OK) {
            return st;
        }
        if (memcmp(tr->attempt.attempt_id, attempt_id, 16u) != 0
            || memcmp(tr->attempt.transaction_id, transaction_id, 16u) != 0
            || tr->attempt.attempt_owner_kind
                != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
            || tr->attempt.owner_key_raw_length != 16u
            || memcmp(tr->attempt.owner_key_raw, transaction_id, 16u)
                != 0) {
            return note_finding(session);
        }
    }
    return NINLIL_OK;
}

static ninlil_status_t bind_generic_secondary(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    uint8_t phase,
    const ninlil_model_domain_typed_record_t *typed)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_bytes_view_t key_view;
    ninlil_status_t st;
    uint8_t expected_pvd[32];

    (void)memcpy(
        expected_pvd, typed->envelope.header.primary_value_digest, 32u);
    (void)memcpy(ctx->focus_primary_key_digest, expected_pvd, 32u);

    if (phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_EVIDENCE) {
        uint8_t owner_raw[80];
        uint16_t owner_raw_len;
        uint16_t evidence_owner_kind;
        uint32_t evidence_slot;
        uint8_t accepted_L;
        uint8_t cancel_first_empty;

        /*
         * Per-row composite authority (docs/17 §18.13.9 BIND_EVIDENCE +
         * §18.13.12.1 Mode23):
         *   L := accepted exact profile max_evidence_per_target (1..8)
         *   shape := matching owner carrier body (not ctx->declared_L)
         * TX retained STATE / DLV APPLICATION_FIRST RESULT_CACHE → slots 0..L
         * DLV CANCEL_FIRST RESULT_CACHE → exact 0 cells; any Evidence row is
         * STORAGE_CORRUPT. ctx->declared_L is last-FOCUS scratch only and
         * must not gate global BIND. Stop order: copy-before-get → fail-closed
         * profile L → carrier exact_get+typed+owner → shape/slot finding →
         * true primary get. Max 2 gets; illegal slot notes after carrier get
         * and before primary get.
         */
        if (typed->evidence_cell.owner_key_raw_length > 80u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        owner_raw_len = typed->evidence_cell.owner_key_raw_length;
        evidence_owner_kind = typed->evidence_cell.evidence_owner_kind;
        evidence_slot = typed->evidence_cell.slot_index;
        (void)memcpy(
            owner_raw, typed->evidence_cell.owner_key_raw, owner_raw_len);
        (void)memcpy(ctx->focus_raw80, owner_raw, owner_raw_len);
        ctx->focus_raw_len = (uint8_t)owner_raw_len;
        ctx->focus_owner_kind =
            evidence_owner_kind
                == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
            ? 1u
            : 2u;

        if (session->bound_workspace == NULL) {
            return note_finding(session);
        }
        {
            uint32_t pl = session->bound_workspace->candidate.limits
                              .max_evidence_per_target;
            if (pl < 1u || pl > 8u) {
                return note_finding(session);
            }
            accepted_L = (uint8_t)pl;
        }

        if (ctx->focus_owner_kind == 1u) {
            st = rebuild_tx_state_key(
                owner_raw, ctx->peer_key, &ctx->peer_key_len);
        } else {
            st = rebuild_result_cache_key(
                owner_raw, owner_raw_len, ctx->peer_key, &ctx->peer_key_len);
        }
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        key_view.data = ctx->peer_key;
        key_view.length = ctx->peer_key_len;
        st = ninlil_domain_scan_exact_get(session, key_view, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }

        cancel_first_empty = 0u;
        if (ctx->focus_owner_kind == 1u) {
            (void)memcpy(ctx->focus_tx_id, owner_raw, 16u);
            st = verify_carrier_tx_state(session, ctx, &got);
            if (st != NINLIL_OK) {
                return st;
            }
        } else {
            const ninlil_model_domain_typed_record_t *tr;
            st = bind_typed_from_get(
                session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE,
                &tr);
            if (st != NINLIL_OK) {
                return st;
            }
            if (tr->result_cache.delivery_key_raw_length != ctx->focus_raw_len
                || memcmp(
                       tr->result_cache.delivery_key_raw, ctx->focus_raw80,
                       ctx->focus_raw_len)
                    != 0) {
                return note_finding(session);
            }
            (void)memcpy(
                ctx->focus_tx_id, tr->result_cache.transaction_id, 16u);
            /*
             * Carrier body shape: APPLICATION_FIRST has application_attempt
             * count ≥1; CANCEL_FIRST is app=0 empty evidence set (same
             * discrimination as FOCUS install).
             */
            if (tr->result_cache.application_attempt_count == 0u) {
                cancel_first_empty = 1u;
            }
        }

        /* Slot legality from carrier shape + profile L — before primary get. */
        if (cancel_first_empty != 0u
            || evidence_slot > (uint32_t)accepted_L) {
            return note_finding(session);
        }

        if (ctx->focus_owner_kind == 1u) {
            st = rebuild_anchor_key(
                owner_raw, ctx->peer_key, &ctx->peer_key_len);
        } else {
            st = rebuild_delivery_key(
                owner_raw, owner_raw_len, ctx->peer_key, &ctx->peer_key_len);
        }
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        return verify_true_primary_pvd_and_raw(session, ctx, expected_pvd);
    }

    if (phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_REPLY) {
        uint8_t delivery_raw[80];
        uint8_t transaction_id[16];

        if (typed->reverse_reply.delivery_key_raw_length != 80u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        (void)memcpy(
            delivery_raw, typed->reverse_reply.delivery_key_raw, 80u);
        (void)memcpy(
            transaction_id, typed->reverse_reply.transaction_id, 16u);
        (void)memcpy(ctx->focus_raw80, delivery_raw, 80u);
        ctx->focus_raw_len = 80u;
        ctx->focus_owner_kind = 2u;
        (void)memcpy(ctx->focus_tx_id, transaction_id, 16u);
        st = rebuild_result_cache_key(
            delivery_raw, 80u, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        key_view.data = ctx->peer_key;
        key_view.length = ctx->peer_key_len;
        st = ninlil_domain_scan_exact_get(session, key_view, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        st = verify_carrier_result_cache(session, ctx, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        st = rebuild_delivery_key(
            delivery_raw, 80u, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        return verify_true_primary_pvd_and_raw(session, ctx, expected_pvd);
    }

    if (phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_RETRY) {
        uint8_t transaction_id[16];
        uint16_t summary_kind;

        (void)memcpy(
            transaction_id, typed->retry_summary.transaction_id, 16u);
        summary_kind = typed->retry_summary.summary_kind;
        (void)memcpy(ctx->focus_tx_id, transaction_id, 16u);
        ctx->focus_owner_kind = 1u;
        (void)memcpy(ctx->focus_raw80, transaction_id, 16u);
        ctx->focus_raw_len = 16u;
        if (summary_kind == NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_RECENT) {
            /* Carrier companion: CUM required (P1-2 typed subject). */
            st = rebuild_retry_key(
                transaction_id,
                NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE, 0u,
                ctx->peer_key, &ctx->peer_key_len);
            if (st != NINLIL_OK) {
                return note_finding(session);
            }
            key_view.data = ctx->peer_key;
            key_view.length = ctx->peer_key_len;
            st = ninlil_domain_scan_exact_get(session, key_view, &got);
            if (st != NINLIL_OK) {
                return st;
            }
            if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
                return note_finding(session); /* RECENT-without-CUM */
            }
            st = verify_carrier_retry_cum(session, ctx, &got);
            if (st != NINLIL_OK) {
                return st;
            }
        }
        /* CUM self-carrier: no companion get. True primary ANCHOR. */
        st = rebuild_anchor_key(
            transaction_id, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        return verify_true_primary_pvd_and_raw(session, ctx, expected_pvd);
    }

    if (phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_MANAGEMENT) {
        uint8_t transaction_id[16];

        (void)memcpy(
            transaction_id, typed->management_ledger.transaction_id, 16u);
        (void)memcpy(ctx->focus_tx_id, transaction_id, 16u);
        ctx->focus_owner_kind = 1u;
        (void)memcpy(ctx->focus_raw80, transaction_id, 16u);
        ctx->focus_raw_len = 16u;
        st = rebuild_event_spool_key(
            transaction_id, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        key_view.data = ctx->peer_key;
        key_view.length = ctx->peer_key_len;
        st = ninlil_domain_scan_exact_get(session, key_view, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        st = verify_carrier_event_spool(session, ctx, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        st = rebuild_anchor_key(
            transaction_id, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        return verify_true_primary_pvd_and_raw(session, ctx, expected_pvd);
    }

    return NINLIL_OK;
}

static ninlil_status_t on_row_bind(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx,
    const ninlil_domain_scan_workspace_t *workspace,
    uint8_t typed_current_ok)
{
    const ninlil_model_domain_typed_record_t *typed;
    uint8_t subtype;

    if (typed_current_ok == 0u) {
        return NINLIL_OK;
    }
    typed = typed_of(workspace);
    subtype = typed->subtype;

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT) {
            return NINLIL_OK;
        }
        /* P0-6: mode-scoped owner filter (same as FOCUS stream_attempt_matches). */
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT) {
            if (typed->attempt.attempt_owner_kind
                != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION) {
                return NINLIL_OK;
            }
        } else if (
            ctx->focus_mode
            == NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT) {
            if (typed->attempt.attempt_owner_kind
                != NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
                return NINLIL_OK;
            }
        } else {
            return NINLIL_OK;
        }
        return bind_attempt_row(session, ctx, typed);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_INDEX) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX) {
            return NINLIL_OK;
        }
        return bind_index_row(session, ctx, typed);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_EVIDENCE) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL) {
            return NINLIL_OK;
        }
        return bind_generic_secondary(session, ctx, ctx->phase, typed);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_REPLY) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY) {
            return NINLIL_OK;
        }
        return bind_generic_secondary(session, ctx, ctx->phase, typed);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_RETRY) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY) {
            return NINLIL_OK;
        }
        return bind_generic_secondary(session, ctx, ctx->phase, typed);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_MANAGEMENT) {
        if (subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER) {
            return NINLIL_OK;
        }
        return bind_generic_secondary(session, ctx, ctx->phase, typed);
    }
    return NINLIL_OK;
}

/* ---- public H1 / H2 ---- */

ninlil_status_t ninlil_domain_scan_d3s2_on_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok)
{
    ninlil_domain_scan_d3s2_context_t *ctx;

    (void)value_length;
    if (session == NULL || workspace == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = ctx_of(session);
    if (ctx == NULL || ctx->pass_kind != NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL) {
        return NINLIL_OK;
    }
    if (session->profile_exact_active == 0u
        || session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        /* S2 evaluator off entire machine when profile not exact. */
        return NINLIL_OK;
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER) {
        /* Only install one carrier per SELECT pass; stop if already live. */
        if ((ctx->flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE) != 0u) {
            return NINLIL_OK;
        }
        return on_row_select(
            session, workspace, ctx, key_length, typed_current_ok);
    }
    if (is_focus_stream_phase(ctx->phase)) {
        return on_row_focus_stream(ctx, workspace, typed_current_ok);
    }
    if (is_bind_phase(ctx->phase)) {
        return on_row_bind(session, ctx, workspace, typed_current_ok);
    }
    return NINLIL_OK;
}

static ninlil_status_t enter_bind_set(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    (void)session;
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE)) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    ctx->phase = first_bind_phase(ctx->focus_mode);
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_BIND_PHASE_ACTIVE);
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

static ninlil_status_t complete_if_masks_ready(
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    uint8_t need = ninlil_domain_scan_d3s2_required_binding_mask(ctx->focus_mode);
    if ((ctx->binding_complete_mask & need) == need) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_BIND_PHASE_ACTIVE);
        return NINLIL_OK;
    }
    return NINLIL_OK;
}

static ninlil_status_t after_bind_subtype_exhausted(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    uint8_t bit = bind_mask_bit_for_phase(ctx->phase);
    uint8_t need = ninlil_domain_scan_d3s2_required_binding_mask(ctx->focus_mode);

    (void)session;
    ctx->binding_complete_mask = (uint8_t)(ctx->binding_complete_mask | bit);

    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT
        && ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_INDEX;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN);
        return NINLIL_OK;
    }

    if ((ctx->binding_complete_mask & need) == need) {
        return complete_if_masks_ready(ctx);
    }
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
    return NINLIL_E_STORAGE_CORRUPT;
}

ninlil_status_t ninlil_domain_scan_d3s2_on_exhausted(
    ninlil_domain_scan_session_t *session)
{
    ninlil_domain_scan_d3s2_context_t *ctx;
    ninlil_status_t st;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = ctx_of(session);
    if (ctx == NULL || ctx->pass_kind != NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL) {
        return NINLIL_OK;
    }
    if (session->profile_exact_active == 0u
        || session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        return NINLIL_OK;
    }

    /* B6: FOCUS stream close only on true EXHAUSTED. */
    if (is_focus_stream_phase(ctx->phase)) {
        /*
         * P0-2: residual EXHAUSTED of the SELECT install advance must not
         * close the focus stream. Drive reopens zero-prefix for a full-band
         * count after clearing CARRIER_INSTALLED.
         */
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return after_focus_subphase_done(session, ctx);
    }

    /* B7: SELECT_CARRIER EXHAUSTED with no next carrier → BIND set. */
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER) {
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE)) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* If carrier was installed mid-pass, drive handles focus; here no next. */
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return enter_bind_set(session, ctx);
    }

    /* B8: BIND subtype EXHAUSTED. */
    if (is_bind_phase(ctx->phase)) {
        st = after_bind_subtype_exhausted(session, ctx);
        return st;
    }

    return NINLIL_OK;
}

/* ---- drive ---- */

static ninlil_status_t ensure_reopen_if_needed(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *ctx)
{
    ninlil_status_t st;
    if (!flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN)) {
        return NINLIL_OK;
    }
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN);
    st = ninlil_domain_scan_reopen_zero_prefix_iter(session);
    return st;
}

ninlil_status_t ninlil_domain_scan_d3s2_drive(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget)
{
    ninlil_domain_scan_d3s2_context_t *ctx;
    ninlil_status_t st;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* B0 */
    if (row_budget == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = ctx_of(session);
    if (ctx == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->has_sticky_primary != 0u
        || session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
        return session->has_sticky_primary != 0u ? session->sticky_primary
                                                : NINLIL_E_STORAGE_CORRUPT;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE) {
        return NINLIL_OK;
    }

    /* PASS_BASELINE: one advance chunk. */
    if (ctx->pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BASELINE) {
        if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            return NINLIL_E_INVALID_STATE;
        }
        st = ninlil_domain_scan_advance(session, row_budget);
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
            return st;
        }
        if (session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
            /*
             * Baseline done. Profile mismatch / future_profile candidate
             * (exact inactive) → S2 evaluator off entire machine (§18.13.10
             * ladder 3 / §15.10.6 / §18.13.15 case12). Do not reopen a second
             * zero-prefix iterator, do not enter PASS_INTERNAL / SELECT /
             * FOCUS / BIND, and do not clear baseline D2 counters or profile
             * flags. Stay phase BASELINE with BASELINE_DONE only — not
             * COMPLETE/COMPLETE_READY (those mean count+BIND proof). Finalize
             * uses a narrow evaluator-off exemption for this exact shape.
             * Ordinary exact-profile path is unchanged below.
             */
            ctx->flags = (uint8_t)(ctx->flags
                | NINLIL_DOMAIN_SCAN_D3S2_FLAG_BASELINE_DONE);
            if (session->profile_exact_active == 0u
                && (session->profile_mismatch != 0u
                    || session->future_profile_candidate != 0u)) {
                /* pass_kind stays BASELINE; masks/flags already zeroed at begin. */
                return NINLIL_OK;
            }
            ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL;
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER;
            st = ninlil_domain_scan_reopen_zero_prefix_iter(session);
            if (st != NINLIL_OK) {
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
                return st;
            }
        }
        return NINLIL_OK;
    }

    /* Known-slot FOCUS: B6k, no row_budget consumption. */
    if (is_focus_known_slot_phase(ctx->phase)
        && flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE)) {
        st = focus_known_slot_matrix(session, ctx);
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
            return st;
        }
        return ensure_reopen_if_needed(session, ctx);
    }

    st = ensure_reopen_if_needed(session, ctx);
    if (st != NINLIL_OK) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
        return st;
    }

    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN
        && ctx->phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE) {
        if (session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
            st = ninlil_domain_scan_reopen_zero_prefix_iter(session);
            if (st != NINLIL_OK) {
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
                return st;
            }
        } else {
            return NINLIL_E_INVALID_STATE;
        }
    }

    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED);
    st = ninlil_domain_scan_advance(session, row_budget);
    if (st != NINLIL_OK) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
        return st;
    }

    /* Carrier installed mid-SELECT: switch to FOCUS; stop this drive chunk. */
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED)) {
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED);
        if (is_focus_known_slot_phase(ctx->phase)) {
            st = focus_known_slot_matrix(session, ctx);
            if (st != NINLIL_OK) {
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
                return st;
            }
            return ensure_reopen_if_needed(session, ctx);
        }
        /* Stream FOCUS: reopen from front for full-band count. */
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN);
        return ensure_reopen_if_needed(session, ctx);
    }

    st = ensure_reopen_if_needed(session, ctx);
    if (st != NINLIL_OK) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED;
        return st;
    }
    return NINLIL_OK;
}
