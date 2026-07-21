#include "domain_store_d3s3.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_store_scanner.h"

#include <limits.h>
#include <string.h>

/*
 * D3-S3: fixed context, modes 27–30 same-txn BLOB lifecycle multipass.
 * No KEY_DIGEST reverse. No second 4096. No heap/VLA. No Storage mutation.
 * No second concurrent iterator. Port terminal → sticky / note 0.
 * Stage5 D3 bind, D3-S4..S12, D3 overall, D4, public Runtime remain pending.
 */

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
    ninlil_model_domain_encode_u32_be(out, value);
}

static uint32_t decode_u32_be_field(const uint8_t in[4])
{
    return ninlil_model_domain_decode_u32_be(in);
}

static int digest_eq(const uint8_t a[32], const uint8_t b[32])
{
    return memcmp(a, b, 32u) == 0;
}

static int digest_is_zero32(const uint8_t d[32])
{
    return ninlil_model_domain_digest_is_zero(d);
}

static ninlil_status_t note_finding(ninlil_domain_scan_session_t *session)
{
    return ninlil_domain_scan_note_terminal_corrupt(session);
}

static ninlil_domain_scan_d3s3_context_t *ctx_of(
    ninlil_domain_scan_session_t *session)
{
    if (session == NULL
        || session->bound_d3_kind != NINLIL_DOMAIN_SCAN_D3_KIND_S3) {
        return NULL;
    }
    return session->bound_d3s3_context;
}

static void flags_set(ninlil_domain_scan_d3s3_context_t *ctx, uint8_t bit)
{
    ctx->flags = (uint8_t)(ctx->flags | bit);
}

static void flags_clear(ninlil_domain_scan_d3s3_context_t *ctx, uint8_t bit)
{
    ctx->flags = (uint8_t)(ctx->flags & (uint8_t)~bit);
}

static int flags_has(const ninlil_domain_scan_d3s3_context_t *ctx, uint8_t bit)
{
    return (ctx->flags & bit) != 0u;
}

static const ninlil_model_domain_typed_record_t *typed_of(
    const ninlil_domain_scan_workspace_t *workspace)
{
    return &workspace->row_validate_scratch.typed;
}

uint8_t ninlil_domain_scan_d3s3_required_count_mask(uint8_t focus_mode)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB:
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB:
        return (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB:
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB:
        return (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC);
    default:
        return 0u;
    }
}

uint8_t ninlil_domain_scan_d3s3_required_binding_mask(uint8_t focus_mode)
{
    if (focus_mode < NINLIL_DOMAIN_SCAN_D3S3_MODE_MIN
        || focus_mode > NINLIL_DOMAIN_SCAN_D3S3_MODE_MAX) {
        return 0u;
    }
    return (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_CHUNK);
}

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
        || key.length > NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY
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
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN, subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, identity, out_key,
        out_key_len);
}

static int encode_raw16(
    uint8_t *out,
    uint32_t capacity,
    uint16_t raw_length,
    const uint8_t *raw,
    uint32_t *out_length)
{
    if (out == NULL || out_length == NULL || raw_length > 255u
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

static ninlil_status_t key_digest_of(
    const uint8_t *key, uint8_t key_len, uint8_t out[32])
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

static ninlil_status_t rebuild_blob_manifest_key(
    const uint8_t blob_id[32], uint8_t *out_key, uint8_t *out_key_len)
{
    uint8_t components[1u + 32u];
    ninlil_bytes_view_t view;

    if (blob_id == NULL || digest_is_zero32(blob_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    components[0] = 1u;
    (void)memcpy(&components[1], blob_id, 32u);
    view.data = components;
    view.length = 33u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_blob_chunk_key(
    const uint8_t blob_id[32], uint32_t index, uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[1u + 32u + 4u];
    ninlil_bytes_view_t view;

    if (blob_id == NULL || digest_is_zero32(blob_id)) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    components[0] = 2u;
    (void)memcpy(&components[1], blob_id, 32u);
    encode_u32_be_field(&components[33], index);
    view.data = components;
    view.length = 37u;
    return write_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, view, out_key, out_key_len);
}

static ninlil_status_t rebuild_tx_state_key(
    const uint8_t tx[16], uint8_t *out_key, uint8_t *out_key_len)
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
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128, identity, out_key, out_key_len);
}

static ninlil_status_t rebuild_event_spool_key(
    const uint8_t tx[16], uint8_t *out_key, uint8_t *out_key_len)
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
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128, identity, out_key, out_key_len);
}

static ninlil_status_t rebuild_result_cache_key(
    const uint8_t *delivery_raw, uint16_t delivery_raw_len, uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 80u];
    uint32_t o = 0u;
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(components, (uint32_t)sizeof(components), delivery_raw_len,
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
    const uint8_t *delivery_raw, uint16_t delivery_raw_len, uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 80u];
    uint32_t o = 0u;
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_raw16(components, (uint32_t)sizeof(components), delivery_raw_len,
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

static ninlil_status_t rebuild_cancel_state_delivery_key(
    const uint8_t *delivery_raw, uint16_t delivery_raw_len, uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES];
    ninlil_bytes_view_t view;

    if (delivery_raw == NULL
        || delivery_raw_len != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
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

static ninlil_status_t rebuild_evidence_cell_key(
    uint16_t owner_kind, const uint8_t *owner_raw, uint16_t owner_raw_len,
    uint32_t slot, uint8_t *out_key, uint8_t *out_key_len)
{
    uint8_t components[2u + 2u + 80u + 4u];
    uint32_t o = 0u;
    uint32_t part = 0u;
    ninlil_bytes_view_t view;

    if (owner_raw == NULL
        || owner_kind != NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY
        || owner_raw_len != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u16_be(components, owner_kind);
    o = 2u;
    if (!encode_raw16(&components[o], (uint32_t)sizeof(components) - o,
            owner_raw_len, owner_raw, &part)) {
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

static void sha_store(
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_sha256_ctx_t *sha)
{
    (void)memcpy(ctx->sha_state, sha->state, 32u);
    (void)memcpy(ctx->sha_bitcount, &sha->bit_length, 8u);
    (void)memcpy(ctx->sha_block, sha->buffer, 64u);
    ctx->sha_block_len = (uint8_t)(sha->buffer_length & 0xffu);
}

static void sha_load(
    const ninlil_domain_scan_d3s3_context_t *ctx,
    ninlil_model_domain_sha256_ctx_t *sha)
{
    (void)memset(sha, 0, sizeof(*sha));
    (void)memcpy(sha->state, ctx->sha_state, 32u);
    (void)memcpy(&sha->bit_length, ctx->sha_bitcount, 8u);
    (void)memcpy(sha->buffer, ctx->sha_block, 64u);
    sha->buffer_length = (uint32_t)ctx->sha_block_len;
}

static void sha_init_ctx(ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_model_domain_sha256_ctx_t sha;
    ninlil_model_domain_sha256_init(&sha);
    sha_store(ctx, &sha);
}

static ninlil_status_t sha_update_ctx(
    ninlil_domain_scan_d3s3_context_t *ctx, const uint8_t *data, uint32_t length)
{
    ninlil_model_domain_sha256_ctx_t sha;
    ninlil_status_t st;

    sha_load(ctx, &sha);
    st = ninlil_model_domain_sha256_update(&sha, data, length);
    if (st != NINLIL_OK) {
        return st;
    }
    sha_store(ctx, &sha);
    return NINLIL_OK;
}

static ninlil_status_t sha_final_ctx(
    ninlil_domain_scan_d3s3_context_t *ctx, uint8_t out[32])
{
    ninlil_model_domain_sha256_ctx_t sha;
    ninlil_model_domain_digest_t dig;
    ninlil_status_t st;

    sha_load(ctx, &sha);
    st = ninlil_model_domain_sha256_final(&sha, &dig);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return NINLIL_OK;
}

static ninlil_status_t typed_from_get(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_domain_scan_exact_get_result_t *got,
    uint8_t expected_subtype,
    const ninlil_model_domain_typed_record_t **out_typed)
{
    ninlil_bytes_view_t kv;
    ninlil_model_domain_typed_record_t *tr;

    if (out_typed == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_typed = NULL;
    if (session == NULL || session->bound_workspace == NULL || ctx == NULL
        || got == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tr = &session->bound_workspace->row_validate_scratch.typed;
    kv.data = ctx->peer_key;
    kv.length = ctx->peer_key_len;
    if (ninlil_model_domain_validate_typed_record(kv, got->value, tr) != NINLIL_OK
        || tr->subtype != expected_subtype) {
        return note_finding(session);
    }
    *out_typed = tr;
    return NINLIL_OK;
}

static ninlil_status_t exact_get_peer(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    ninlil_domain_scan_exact_get_result_t *got)
{
    ninlil_bytes_view_t key_view;

    key_view.data = ctx->peer_key;
    key_view.length = ctx->peer_key_len;
    return ninlil_domain_scan_exact_get(session, key_view, got);
}

static void clear_unit_install(ninlil_domain_scan_d3s3_context_t *ctx)
{
    (void)memset(ctx->blob_id_digest, 0, 32u);
    (void)memset(ctx->content_digest, 0, 32u);
    (void)memset(ctx->owner_primary_key_digest, 0, 32u);
    (void)memset(ctx->expected_manifest_value_digest, 0, 32u);
    (void)memset(ctx->expected_owner_pvd, 0, 32u);
    (void)memset(ctx->peer_key, 0, sizeof(ctx->peer_key));
    ctx->peer_key_len = 0u;
    encode_u64_be_field(ctx->total_length, 0u);
    encode_u32_be_field(ctx->chunk_count, 0u);
    encode_u32_be_field(ctx->next_chunk_index, 0u);
    encode_u64_be_field(ctx->length_sum, 0u);
    ctx->owner_kind = 0u;
    ctx->blob_kind = 0u;
    ctx->observed_live = 0u;
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED);
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE);
}

static int key_strictly_greater_than_last(
    const ninlil_domain_scan_d3s3_context_t *ctx,
    const uint8_t *key,
    uint32_t key_length)
{
    uint32_t common;
    int order;

    if (ctx->last_carrier_key_len == 0u) {
        return 1;
    }
    if (key_length > 255u) {
        return 0;
    }
    common = (uint32_t)ctx->last_carrier_key_len < key_length
        ? (uint32_t)ctx->last_carrier_key_len
        : key_length;
    order = memcmp(ctx->last_carrier_key, key, common);
    if (order < 0) {
        return 1;
    }
    if (order > 0) {
        return 0;
    }
    return (uint32_t)ctx->last_carrier_key_len < key_length;
}

static int carrier_subtype_ok(uint8_t focus_mode, uint8_t subtype)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB:
        return subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY;
    default:
        return 0;
    }
}

static ninlil_status_t install_carrier_common(
    ninlil_domain_scan_d3s3_context_t *ctx,
    const uint8_t *key,
    uint32_t key_length)
{
    if (key_length == 0u
        || key_length > NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(ctx->last_carrier_key, key, key_length);
    ctx->last_carrier_key_len = (uint8_t)key_length;
    clear_unit_install(ctx);
    ctx->count_complete_mask = 0u;
    ctx->focus_sub = 0u;
    ctx->semantic_pass = 0u;
    ctx->reply_kind = 0u;
    ctx->pad0 = 0u;
    (void)memset(ctx->receipt_evidence_bytes, 0, 128u);
    ctx->receipt_evidence_len = 0u;
    encode_u32_be_field(ctx->pinned_receipt_stage, 0u);
    (void)memset(ctx->expected_semantic_digest, 0, 32u);
    (void)memset(ctx->view_a_key_digest, 0, 32u);
    (void)memset(ctx->view_b_key_digest, 0, 32u);
    (void)memset(ctx->focus_raw80, 0, 80u);
    ctx->focus_raw_len = 0u;
    (void)memset(ctx->focus_id16, 0, 16u);
    (void)memset(ctx->focus_key_digest, 0, 32u);
    return NINLIL_OK;
}

/* REP1: SELECT_SETUP pure G pending (phase2 / semantic_pass=6). */
#define NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP ((uint8_t)6u)

/*
 * Mode27 SELECT pure-W pin only (GET 0). STATE/SPOOL proof is SELECT_SETUP G.
 * owner_kind temporarily holds is_event_fact 0/1 until setup G consumes it.
 *
 * want_avd pin: the complete ANCHOR record value digest is stored in the
 * Mode28-only view_a slot (Mode27 does not use dual-view; no collision with
 * man.expected_owner_pvd). SELECT_SETUP G cross-row consumes it before any
 * lifecycle classification (docs/17 §18.14.19.3 / R27).
 */
static ninlil_status_t pin_mode27_from_carrier(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed,
    uint32_t value_length)
{
    ninlil_bytes_view_t full;
    ninlil_model_domain_digest_t vdig;
    ninlil_status_t st;

    full.data = workspace->value;
    full.length = value_length;
    st = ninlil_model_domain_value_digest(full, &vdig);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    (void)memcpy(ctx->view_a_key_digest, vdig.bytes, 32u);
    (void)memcpy(ctx->focus_id16, typed->transaction_anchor.transaction_id, 16u);
    (void)memcpy(ctx->focus_key_digest,
        typed->transaction_anchor.payload_blob_key_digest, 32u);
    ctx->owner_kind =
        !ninlil_model_domain_id_is_zero(typed->transaction_anchor.event_id)
        ? 1u
        : 0u;
    /* Lifecycle unknown until SELECT_SETUP G; keep NONE placeholder. */
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE;
    ctx->expected_live = 0u;
    return NINLIL_OK;
}

/* Mode27 SELECT_SETUP G: STATE [+ EVENT_SPOOL] exact_get; set lifecycle. */
static ninlil_status_t run_select_setup_mode27(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    const ninlil_model_domain_typed_record_t *st_typed;
    ninlil_status_t st;
    int is_event_fact;
    int dig_zero;
    int terminal_tx;
    int is_receipt;
    int is_discard;
    int hist_ok;
    int live_ok;
    int st_is_ef;
    uint32_t tx_state;
    uint32_t tx_outcome;
    uint32_t tx_reason;
    uint32_t tx_discarded;
    uint32_t deadline_verdict;
    uint32_t event_park_cause;
    uint64_t event_spool_revision;
    uint8_t st_avd[32];
    uint8_t st_pvd[32];
    uint8_t st_tx[16];
    uint32_t spool_state;
    uint32_t spool_park_cause;
    uint64_t spool_revision;
    uint64_t spool_record_revision;
    uint8_t spool_pvd[32];
    uint8_t spool_tx[16];

    is_event_fact = (ctx->owner_kind != 0u) ? 1 : 0;

    st = rebuild_tx_state_key(ctx->focus_id16, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = typed_from_get(session, ctx, &got,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE, &st_typed);
    if (st != NINLIL_OK) {
        return st;
    }
    /*
     * Copy STATE lifecycle + Mode27 cross-row fields to drive-local before the
     * EVENT_SPOOL exact_get overwrites workspace / typed pointer
     * (docs/17 §18.14.4). 32B/16B arrays go to stack locals; context stays
     * 754 bytes (no field added).
     */
    tx_state = st_typed->transaction_state.state;
    tx_outcome = st_typed->transaction_state.outcome;
    tx_reason = st_typed->transaction_state.reason;
    tx_discarded = st_typed->transaction_state.explicitly_discarded;
    deadline_verdict = st_typed->transaction_state.deadline_verdict;
    event_park_cause = st_typed->transaction_state.event_park_cause;
    event_spool_revision = st_typed->transaction_state.event_spool_revision;
    (void)memcpy(st_avd, st_typed->transaction_state.anchor_value_digest, 32u);
    (void)memcpy(st_pvd, st_typed->envelope.header.primary_value_digest, 32u);
    (void)memcpy(st_tx, st_typed->transaction_state.transaction_id, 16u);
    dig_zero = digest_is_zero32(ctx->focus_key_digest) ? 1 : 0;
    terminal_tx = (tx_state == NINLIL_TXN_TERMINAL) ? 1 : 0;
    spool_state = 0u;
    spool_park_cause = 0u;
    spool_revision = 0u;
    spool_record_revision = 0u;
    (void)memset(spool_pvd, 0, 32u);
    (void)memset(spool_tx, 0, 16u);

    if (is_event_fact) {
        /*
         * EventFact cardinality: EVENT_SPOOL exact PRESENT (§18.14.19.3
         * item 9/10). ABSENT/NOT_FOUND at SELECT_SETUP is sticky CORRUPT
         * (phase14 / sem6), not historical live=0. DesiredState never GETs
         * spool here.
         */
        st = rebuild_event_spool_key(
            ctx->focus_id16, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        st = exact_get_peer(session, ctx, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        st = typed_from_get(session, ctx, &got,
            NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL, &st_typed);
        if (st != NINLIL_OK) {
            return st;
        }
        spool_state = st_typed->event_spool.spool_state;
        spool_park_cause = st_typed->event_spool.park_cause;
        spool_revision = st_typed->event_spool.spool_revision;
        spool_record_revision = st_typed->envelope.header.record_revision;
        (void)memcpy(spool_pvd,
            st_typed->envelope.header.primary_value_digest, 32u);
        (void)memcpy(spool_tx, st_typed->event_spool.transaction_id, 16u);
    }

    /* owner_kind was setup scratch; clear for man install later */
    ctx->owner_kind = 0u;

    /*
     * R27 cross-row closed product (oracle o1a_mode27_cross_row_ok; both GETs
     * complete, before lifecycle classification, strict oracle order). Any
     * failure keeps lifecycle_class NONE (no ILLEGAL_CARRIER) and returns
     * sticky CORRUPT. want_avd = ctx->view_a_key_digest (SELECT pure-W pin).
     */
    /* (1) family: EF anchor ⇔ STATE deadline_verdict NA (DS ⇔ not NA). */
    st_is_ef = (deadline_verdict == NINLIL_DEADLINE_NOT_APPLICABLE) ? 1 : 0;
    if (is_event_fact != st_is_ef) {
        return note_finding(session);
    }
    /* (2) STATE anchor_value_digest == complete ANCHOR value digest. */
    if (!digest_eq(st_avd, ctx->view_a_key_digest)) {
        return note_finding(session);
    }
    /* (3) STATE envelope common primary_value_digest == ANCHOR value digest. */
    if (!digest_eq(st_pvd, ctx->view_a_key_digest)) {
        return note_finding(session);
    }
    /* (4) STATE transaction_id == anchor body tx (focus_id16). */
    if (memcmp(st_tx, ctx->focus_id16, 16u) != 0) {
        return note_finding(session);
    }

    is_receipt = (terminal_tx != 0
            && tx_outcome == NINLIL_OUTCOME_SATISFIED
            && tx_reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET
            && tx_discarded == 0u)
        ? 1
        : 0;
    is_discard = (terminal_tx != 0
            && tx_outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE
            && tx_reason
                == NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT
            && tx_discarded == 1u)
        ? 1
        : 0;

    if (is_event_fact) {
        /* (6) spool envelope PVD / tx / revision closed product. */
        if (!digest_eq(spool_pvd, ctx->view_a_key_digest)) {
            return note_finding(session);
        }
        if (memcmp(spool_tx, st_tx, 16u) != 0) {
            return note_finding(session);
        }
        if (event_spool_revision != spool_revision) {
            return note_finding(session);
        }
        if (spool_record_revision != spool_revision) {
            return note_finding(session);
        }
        /* (7) state × spool × park-cause closed product. */
        if (tx_state == NINLIL_TXN_PARKED_RETRY) {
            if (spool_state != NINLIL_MODEL_DOMAIN_SPOOL_STATE_PARKED_RETRY
                || event_park_cause != spool_park_cause
                || event_park_cause < 1u || event_park_cause > 5u) {
                return note_finding(session);
            }
        } else if (terminal_tx == 0) {
            if (spool_state != NINLIL_MODEL_DOMAIN_SPOOL_STATE_ACTIVE
                || event_park_cause != 0u || spool_park_cause != 0u) {
                return note_finding(session);
            }
        } else if (is_receipt != 0) {
            if (spool_state != NINLIL_MODEL_DOMAIN_SPOOL_STATE_RELEASED
                || event_park_cause != 0u || spool_park_cause != 0u) {
                return note_finding(session);
            }
        } else if (is_discard != 0) {
            if (spool_state != NINLIL_MODEL_DOMAIN_SPOOL_STATE_DISCARDED
                || event_park_cause != 0u || spool_park_cause != 0u) {
                return note_finding(session);
            }
        } else {
            /* other terminal shapes are not EventFact-legal owners */
            return note_finding(session);
        }

        /* Lifecycle classification (RefSession exact matrix). */
        hist_ok = ((is_receipt != 0
                && spool_state == NINLIL_MODEL_DOMAIN_SPOOL_STATE_RELEASED)
                || (is_discard != 0
                    && spool_state
                        == NINLIL_MODEL_DOMAIN_SPOOL_STATE_DISCARDED))
            ? 1
            : 0;
        if (terminal_tx == 0) {
            if (tx_state == NINLIL_TXN_PARKED_RETRY) {
                live_ok = (spool_state
                        == NINLIL_MODEL_DOMAIN_SPOOL_STATE_PARKED_RETRY
                    && tx_discarded == 0u)
                    ? 1
                    : 0;
            } else {
                live_ok = (spool_state
                        == NINLIL_MODEL_DOMAIN_SPOOL_STATE_ACTIVE
                    && tx_discarded == 0u)
                    ? 1
                    : 0;
            }
        } else {
            live_ok = 0;
        }
        if (hist_ok != 0) {
            if (dig_zero != 0) {
                return note_finding(session);
            }
            ctx->lifecycle_class =
                NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT;
            ctx->expected_live = 0u;
            return NINLIL_OK;
        }
        if (live_ok == 0) {
            /* fail-closed net (closed product (7) already excludes these) */
            return note_finding(session);
        }
        if (dig_zero != 0) {
            ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE;
            ctx->expected_live = 0u;
            return NINLIL_OK;
        }
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
        ctx->expected_live = 1u;
        return NINLIL_OK;
    }

    /*
     * DesiredState: no spool GET; cross-row (1)-(4) already applied
     * (family enforces deadline_verdict != NA).
     */
    if (tx_discarded != 0u) {
        return note_finding(session);
    }
    if (terminal_tx != 0) {
        /* TERMINAL ⇒ HISTORICAL; requires nonzero historical payload dig */
        if (dig_zero != 0) {
            return note_finding(session);
        }
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT;
        ctx->expected_live = 0u;
        return NINLIL_OK;
    }
    /* nonterminal: zero dig ⇒ NONE; nonzero ⇒ LIVE */
    if (dig_zero != 0) {
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE;
        ctx->expected_live = 0u;
        return NINLIL_OK;
    }
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
    ctx->expected_live = 1u;
    return NINLIL_OK;
}

/*
 * Mode28 focus_id16 layout (§18.14.19.5): sole packed u64be pair
 * [0..7]=view_a_total, [8..15]=view_b_total. Empty view keeps 0.
 */
static void pin_mode28_totals(
    ninlil_domain_scan_d3s3_context_t *ctx, uint64_t view_a, uint64_t view_b)
{
    encode_u64_be_field(&ctx->focus_id16[0], view_a);
    encode_u64_be_field(&ctx->focus_id16[8], view_b);
}

static void mode28_set_view_total(
    ninlil_domain_scan_d3s3_context_t *ctx, int which_a, uint64_t total)
{
    uint64_t a = decode_u64_be_field(&ctx->focus_id16[0]);
    uint64_t b = decode_u64_be_field(&ctx->focus_id16[8]);
    if (which_a != 0) {
        a = total;
    } else {
        b = total;
    }
    pin_mode28_totals(ctx, a, b);
}

static ninlil_status_t setup_mode28(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    int za;
    int zb;

    if (typed->ordered_ingress.ingress_state
        != NINLIL_MODEL_DOMAIN_INGRESS_STATE_PENDING) {
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_ILLEGAL_CARRIER;
        return note_finding(session);
    }
    (void)memcpy(ctx->view_a_key_digest,
        typed->ordered_ingress.payload_blob_key_digest, 32u);
    (void)memcpy(ctx->view_b_key_digest,
        typed->ordered_ingress.evidence_blob_key_digest, 32u);
    /* New ORDERED_INGRESS carrier: both totals halves zero (empty views stay 0). */
    pin_mode28_totals(ctx, 0u, 0u);

    za = digest_is_zero32(ctx->view_a_key_digest) ? 1 : 0;
    zb = digest_is_zero32(ctx->view_b_key_digest) ? 1 : 0;
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;

    if (za == 0) {
        /* Za=0: FOCUS_SCAN A */
        (void)memcpy(ctx->focus_key_digest, ctx->view_a_key_digest, 32u);
        ctx->focus_sub = 0u;
        ctx->expected_live = 1u;
    } else if (zb == 0) {
        /* Za=1,Zb=0: skip A → FOCUS_SCAN_B */
        (void)memcpy(ctx->focus_key_digest, ctx->view_b_key_digest, 32u);
        ctx->focus_sub = 1u;
        ctx->expected_live = 1u;
    } else {
        /* Za=1,Zb=1: skip both scans/chunks → SEMANTIC (set in on_row) */
        (void)memset(ctx->focus_key_digest, 0, 32u);
        ctx->focus_sub = 1u;
        ctx->expected_live = 0u;
    }
    return NINLIL_OK;
}

/*
 * Mode29 SELECT pure-W pin only. APPLICATION_FIRST RESULT_CACHE is SELECT_SETUP G.
 * owner_kind temporarily holds creation_kind (1 APP / 2 CANCEL).
 * Returns 1 if SELECT_SETUP G is required, 0 if pin alone finished lifecycle.
 */
static ninlil_status_t pin_mode29_from_carrier(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed,
    int *out_needs_setup)
{
    uint16_t ck;

    *out_needs_setup = 0;
    if (typed->delivery.delivery_key_raw_length
        != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        return note_finding(session);
    }
    (void)memcpy(ctx->focus_raw80, typed->delivery.delivery_key_raw, 80u);
    ctx->focus_raw_len = 80u;
    /*
     * Mode29 layout: pin owner raw + payload digest only. focus_id16 is not
     * DELIVERY.transaction_id (§18.14.19.5 / Mode29: keep zero unless specified).
     * install_carrier_common already zeroed the slot; do not store tx here.
     */
    (void)memset(ctx->focus_id16, 0, 16u);
    (void)memcpy(ctx->focus_key_digest, typed->delivery.payload_blob_key_digest,
        32u);
    ck = typed->delivery.creation_kind;
    ctx->owner_kind = (uint8_t)(ck & 0xFFu);

    if (ck == NINLIL_MODEL_DOMAIN_DELIVERY_CREATION_CANCEL_FIRST) {
        if (!digest_is_zero32(ctx->focus_key_digest)) {
            return note_finding(session);
        }
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE;
        ctx->expected_live = 0u;
        return NINLIL_OK;
    }
    if (ck != NINLIL_MODEL_DOMAIN_DELIVERY_CREATION_APPLICATION_FIRST) {
        return note_finding(session);
    }
    /* APP_FIRST: RC GET deferred to SELECT_SETUP G. */
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE;
    ctx->expected_live = 0u;
    *out_needs_setup = 1;
    return NINLIL_OK;
}

static ninlil_status_t run_select_setup_mode29(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    const ninlil_model_domain_typed_record_t *rc;
    ninlil_status_t st;
    int terminal;

    st = rebuild_result_cache_key(ctx->focus_raw80, ctx->focus_raw_len,
        ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = typed_from_get(session, ctx, &got,
        NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE, &rc);
    if (st != NINLIL_OK) {
        return st;
    }
    terminal = (rc->result_cache.delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RESULT_COMMITTED
        || rc->result_cache.delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DISPOSITION_COMMITTED
        || rc->result_cache.delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_CANCEL_TOMBSTONE_ONLY);
    ctx->owner_kind = 0u;
    if (terminal) {
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT;
        ctx->expected_live = 0u;
    } else {
        if (digest_is_zero32(ctx->focus_key_digest)) {
            return note_finding(session);
        }
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
        ctx->expected_live = 1u;
    }
    return NINLIL_OK;
}

static ninlil_status_t setup_mode30(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed)
{
    uint32_t ss;

    if (typed->reverse_reply.delivery_key_raw_length
        != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES) {
        return note_finding(session);
    }
    (void)memcpy(ctx->focus_raw80, typed->reverse_reply.delivery_key_raw, 80u);
    ctx->focus_raw_len = 80u;
    (void)memcpy(ctx->focus_id16, typed->reverse_reply.transaction_id, 16u);
    (void)memcpy(ctx->focus_key_digest, typed->reverse_reply.body_blob_key_digest,
        32u);
    if (typed->reverse_reply.reply_kind < NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
        || typed->reverse_reply.reply_kind
            > NINLIL_MODEL_DOMAIN_REPLY_KIND_CANCEL_RESULT) {
        return note_finding(session);
    }
    ctx->reply_kind = (uint8_t)typed->reverse_reply.reply_kind;
    ss = typed->reverse_reply.send_state;
    if (ss >= NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING
        && ss <= NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_DENIED) {
        if (digest_is_zero32(ctx->focus_key_digest)) {
            return note_finding(session);
        }
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
        ctx->expected_live = 1u;
    } else if (ss
        == NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_COUNTER_EXHAUSTED) {
        ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT;
        ctx->expected_live = 0u;
    } else {
        return note_finding(session);
    }
    return NINLIL_OK;
}

/*
 * SELECT pure-W install: pin carrier from Port row only (GET 0).
 * *out_needs_setup_g = 1 ⇒ exit SELECT W with semantic_pass=6; next drive is
 * SELECT_SETUP pure G (Mode27 STATE/SPOOL; Mode29 APPLICATION_FIRST RC).
 */
static ninlil_status_t install_and_setup_carrier(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s3_context_t *ctx,
    uint32_t key_length,
    uint32_t value_length,
    int *out_needs_setup_g)
{
    const ninlil_model_domain_typed_record_t *typed = typed_of(workspace);
    ninlil_status_t st;

    *out_needs_setup_g = 0;
    st = install_carrier_common(ctx, workspace->key, key_length);
    if (st != NINLIL_OK) {
        return st;
    }
    switch (ctx->focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB:
        st = pin_mode27_from_carrier(
            session, workspace, ctx, typed, value_length);
        if (st == NINLIL_OK) {
            *out_needs_setup_g = 1;
        }
        return st;
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB:
        return setup_mode28(session, ctx, typed);
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB:
        return pin_mode29_from_carrier(session, ctx, typed, out_needs_setup_g);
    case NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB:
        return setup_mode30(session, ctx, typed);
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

/* ---- FOCUS_MANIFEST_SCAN single arm ---- */

/*
 * R12 owner_raw identity gate (§18.14 / ADR R12): dig-matching man must bind
 * to the SELECT carrier identity before any man install / MATCH. Mode28 is
 * not in the R12 equality set (carrier identity is view digests; man raw is
 * D1-length-checked ordered_sequence only). Failure → sticky CORRUPT at this
 * exact row; caller aborts the walk (no residual iter_next).
 */
static int focus_carrier_owner_raw_identity_ok(
    const ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_body_blob_manifest_t *m)
{
    if (m == NULL || m->owner_key_raw == NULL) {
        return 0;
    }
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB) {
        return m->owner_key_raw_length == 16u
            && memcmp(m->owner_key_raw, ctx->focus_id16, 16u) == 0;
    }
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB
        || ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        return m->owner_key_raw_length == 80u && ctx->focus_raw_len == 80u
            && memcmp(m->owner_key_raw, ctx->focus_raw80, 80u) == 0;
    }
    /* Mode28: R12 does not require ordered_sequence equality at dig-match. */
    return 1;
}

static ninlil_status_t install_manifest_match(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s3_context_t *ctx,
    uint32_t key_length,
    uint32_t value_length)
{
    const ninlil_model_domain_typed_record_t *typed = typed_of(workspace);
    const ninlil_model_domain_body_blob_manifest_t *m;
    ninlil_bytes_view_t full;
    ninlil_model_domain_digest_t vdig;
    ninlil_status_t st;
    uint8_t kd[32];

    if (workspace->key[9] != NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB
        || typed->envelope.header.flags
            != NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
        return NINLIL_OK;
    }
    m = &typed->blob_manifest;

    st = key_digest_of(workspace->key, (uint8_t)key_length, kd);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    if (!digest_eq(kd, ctx->focus_key_digest)) {
        return NINLIL_OK;
    }

    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)) {
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE);
        return NINLIL_OK;
    }

    /*
     * R12: validate owner_raw vs carrier identity BEFORE copying any man
     * fields / installing MATCH. Immediate sticky CORRUPT; walk aborts via
     * non-OK return (no Port reclassification; first sticky wins).
     * Mode30 H14 kinds / H15 length-content are NOT applied here: oracle
     * installs the first dig-match + identity-valid man and continues pure W
     * to true NOT_FOUND, then applies those checks at exhaustion
     * (§18.14.19.3 / §18.14.19.8; vector_gen _drive_focus_scan_w).
     */
    if (!focus_carrier_owner_raw_identity_ok(ctx, m)) {
        return note_finding(session);
    }

    (void)memcpy(ctx->blob_id_digest, m->blob_id_digest, 32u);
    (void)memcpy(ctx->content_digest, m->content_digest, 32u);
    (void)memcpy(ctx->owner_primary_key_digest, m->owner_primary_key_digest, 32u);
    encode_u64_be_field(ctx->total_length, m->total_length);
    encode_u32_be_field(ctx->chunk_count, m->chunk_count);
    encode_u32_be_field(ctx->next_chunk_index, 0u);
    encode_u64_be_field(ctx->length_sum, 0u);
    ctx->owner_kind = (uint8_t)m->blob_owner_kind;
    ctx->blob_kind = (uint8_t)m->blob_kind;
    (void)memcpy(ctx->peer_key, workspace->key, key_length);
    ctx->peer_key_len = (uint8_t)key_length;

    full.data = workspace->value;
    full.length = value_length;
    st = ninlil_model_domain_value_digest(full, &vdig);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    (void)memcpy(ctx->expected_manifest_value_digest, vdig.bytes, 32u);
    (void)memcpy(ctx->expected_owner_pvd,
        typed->envelope.header.primary_value_digest, 32u);

    /*
     * Mode28 first-focus only: pin man total_length into the matching view
     * half of focus_id16 (preserve the other half). Semantic RESCAN_A/B
     * (sem 1/3) must not rewrite the first-focus pin authority (§18.14.19.5).
     */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
        && ctx->semantic_pass != 1u
        && ctx->semantic_pass != 3u) {
        if (ctx->focus_sub == 0u) {
            mode28_set_view_total(ctx, 1, m->total_length);
        } else {
            mode28_set_view_total(ctx, 0, m->total_length);
        }
    }

    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED);
    ctx->observed_live = 1u;
    return NINLIL_OK;
}

/*
 * Mode30 FOCUS_SCAN H14/H15 from installed 754 pins (post true NOT_FOUND).
 * R12 owner_raw already gated at dig-match; H14 re-checks kinds only.
 * H15: RECEIPT total_length ≤128; non-RECEIPT total/count 0 and content_digest
 * == SHA256(empty). Uses only already-installed context fields — no second
 * walk, no context growth, no dynamic allocation.
 */
static int mode30_focus_h14_h15_ok(const ninlil_domain_scan_d3s3_context_t *ctx)
{
    if (ctx->owner_kind != (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY
        || ctx->blob_kind != (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY) {
        return 0;
    }
    if (ctx->reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
        if (decode_u64_be_field(ctx->total_length) > 128u) {
            return 0;
        }
        return 1;
    }
    if (decode_u64_be_field(ctx->total_length) != 0u
        || decode_u32_be_field(ctx->chunk_count) != 0u) {
        return 0;
    }
    {
        ninlil_model_domain_digest_t empty;
        if (ninlil_model_domain_sha256(NULL, 0u, &empty) != NINLIL_OK
            || !digest_eq(ctx->content_digest, empty.bytes)) {
            return 0;
        }
    }
    return 1;
}

static ninlil_status_t after_manifest_scan(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE)) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return note_finding(session);
    }
    if (ctx->expected_live == 1u) {
        if (!flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
            || ctx->observed_live != 1u) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return note_finding(session);
        }
        /*
         * Mode30: H14 kinds + H15 length/content only after true exhaustion
         * (§18.14.19.8). Semantic finding retains earlier Port events of the
         * FOCUS W drive (§18.14.19.10). Installed MATCH pins remain for the
         * failure-point snapshot when invalid.
         */
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB
            && !mode30_focus_h14_h15_ok(ctx)) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return note_finding(session);
        }
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF;
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
            && ctx->focus_sub == 1u) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF_B;
        }
        /* Mode30 OWNER_PVD deferred to semantic DELIVERY get. */
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS;
        }
        return NINLIL_OK;
    }
    /* expected 0: match_count must be 0 (historical non-zero digest OK absent) */
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)) {
        /* live manifest when expected 0 → corrupt unless historical zero-digest NONE */
        if (ctx->lifecycle_class
            == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return note_finding(session);
        }
        /* LIVE view empty (Mode28): expected 0 means no manifest */
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return note_finding(session);
        }
    }
    /* count unit complete with zero live */
    ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    /* advance to next unit / semantic / select */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
        && ctx->focus_sub == 0u) {
        ctx->focus_sub = 1u;
        (void)memcpy(ctx->focus_key_digest, ctx->view_b_key_digest, 32u);
        ctx->expected_live = digest_is_zero32(ctx->view_b_key_digest) ? 0u : 1u;
        clear_unit_install(ctx);
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        return NINLIL_OK;
    }
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
        || ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        /* semantic only when at least one LIVE unit; Mode28 dual empty still
         * needs semantic of empty streams; Mode30 HISTORICAL → no semantic */
        if (ctx->lifecycle_class
            == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT
            || ctx->lifecycle_class == NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE) {
            if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB
                && ctx->lifecycle_class
                    == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT) {
                ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC);
            } else if (ctx->focus_mode
                == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB) {
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
                return NINLIL_OK;
            }
        } else {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
            return NINLIL_OK;
        }
    }
    /* resume SELECT for next carrier */
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

/* ---- OWNER_PVD_PROOF (Mode27/28/29; Mode30 deferred) ---- */

static ninlil_status_t run_owner_pvd_proof(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_status_t st;
    ninlil_bytes_view_t vv;
    ninlil_model_domain_digest_t dig;

    if (ctx->last_carrier_key_len == 0u) {
        return note_finding(session);
    }
    (void)memcpy(ctx->peer_key, ctx->last_carrier_key, ctx->last_carrier_key_len);
    ctx->peer_key_len = ctx->last_carrier_key_len;
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st; /* sticky Port failure, note 0 */
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    vv = got.value;
    st = ninlil_model_domain_value_digest(vv, &dig);
    if (st != NINLIL_OK || !digest_eq(dig.bytes, ctx->expected_owner_pvd)) {
        return note_finding(session);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF_B) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS_B;
    } else {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS;
    }
    return NINLIL_OK;
}

/* ---- FOCUS_CHUNKS known-index stream ---- */

/*
 * §18.14.19 failure-point / O1a _drive_chunks_g: after FOCUS_CHUNKS
 * present/absent adjudication, every D3 semantic finding records count
 * MANIFEST (0x01) only. Natural exact_get Storage-mapped returns must not
 * call this — they retain the pre-event mask (typically 0).
 */
static ninlil_status_t note_focus_chunks_semantic_finding(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST);
    return note_finding(session);
}

static ninlil_status_t run_focus_chunks(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    uint32_t count = decode_u32_be_field(ctx->chunk_count);
    uint64_t total = decode_u64_be_field(ctx->total_length);
    uint64_t sum = 0u;
    uint32_t i;
    ninlil_status_t st;
    uint8_t final_dig[32];

    if (count == 0u) {
        /* empty stream: content_digest must be SHA256(empty) */
        ninlil_model_domain_digest_t empty;
        if (total != 0u) {
            return note_focus_chunks_semantic_finding(session, ctx);
        }
        if (ninlil_model_domain_sha256(NULL, 0u, &empty) != NINLIL_OK
            || !digest_eq(ctx->content_digest, empty.bytes)) {
            return note_focus_chunks_semantic_finding(session, ctx);
        }
    } else {
        sha_init_ctx(ctx);
        for (i = 0u; i < count; i += 1u) {
            ninlil_domain_scan_exact_get_result_t got;
            const ninlil_model_domain_typed_record_t *tr;
            const ninlil_model_domain_body_blob_chunk_t *ch;

            st = rebuild_blob_chunk_key(
                ctx->blob_id_digest, i, ctx->peer_key, &ctx->peer_key_len);
            if (st != NINLIL_OK) {
                return note_focus_chunks_semantic_finding(session, ctx);
            }
            st = exact_get_peer(session, ctx, &got);
            if (st != NINLIL_OK) {
                /* Natural Storage fault: pre-event mask unchanged. */
                return st;
            }
            if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
                return note_focus_chunks_semantic_finding(session, ctx);
            }
            st = typed_from_get(session, ctx, &got,
                NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, &tr);
            if (st != NINLIL_OK) {
                /* typed_from_get already sticky-noted; O1a TYPED_FAIL sets
                 * MASK_COUNT_MAN before sticky — record MANIFEST here. */
                ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST);
                return st;
            }
            if (tr->envelope.header.flags != NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
                return note_focus_chunks_semantic_finding(session, ctx);
            }
            ch = &tr->blob_chunk;
            if (!digest_eq(ch->blob_id_digest, ctx->blob_id_digest)
                || ch->chunk_index != i
                || ch->chunk_count != count
                || ch->total_length != total
                || !digest_eq(ch->content_digest, ctx->content_digest)
                || !digest_eq(tr->envelope.header.primary_value_digest,
                       ctx->expected_manifest_value_digest)) {
                return note_focus_chunks_semantic_finding(session, ctx);
            }
            sum += (uint64_t)ch->chunk_length;
            st = sha_update_ctx(ctx, ch->chunk_bytes, ch->chunk_length);
            if (st != NINLIL_OK) {
                return note_focus_chunks_semantic_finding(session, ctx);
            }
        }
        encode_u64_be_field(ctx->length_sum, sum);
        if (sum != total) {
            return note_focus_chunks_semantic_finding(session, ctx);
        }
        st = sha_final_ctx(ctx, final_dig);
        if (st != NINLIL_OK || !digest_eq(final_dig, ctx->content_digest)) {
            return note_focus_chunks_semantic_finding(session, ctx);
        }
    }

    ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    /* MATCH_* is FOCUS-local; successful CHUNKS exits use REP1 normal forms. */
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED);
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE);

    /* Mode28 dual: after view A chunks → B SCAN if Zb=0, else semantic */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
        && ctx->focus_sub == 0u
        && (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS)) {
        ctx->focus_sub = 1u;
        if (!digest_is_zero32(ctx->view_b_key_digest)) {
            (void)memcpy(ctx->focus_key_digest, ctx->view_b_key_digest, 32u);
            ctx->expected_live = 1u;
            clear_unit_install(ctx);
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
            flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
            return NINLIL_OK;
        }
        /* Zb=1: no B Port walk — enter SEMANTIC with focus_sub=1 */
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
        return NINLIL_OK;
    }

    /* Mode28/30 → semantic; Mode27/29 → next carrier */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
        || ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
        return NINLIL_OK;
    }
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

/* ---- SEMANTIC Mode28 one-drive micro-units (§18.14.19.8 rows 4914–4923) ---- */

/* semantic_pass values for Mode28 (closed vocabulary §18.14.19.4). */
#define M28_SEM_RESCAN_A ((uint8_t)1u)
#define M28_SEM_VIEW_A ((uint8_t)2u)
#define M28_SEM_RESCAN_B ((uint8_t)3u)
#define M28_SEM_VIEW_B ((uint8_t)4u)

static ninlil_status_t fill_prefix_from_ordered_ingress(
    ninlil_model_domain_message_semantic_prefix_t *prefix,
    const ninlil_model_domain_body_ordered_ingress_t *ing,
    uint32_t payload_length)
{
    (void)memset(prefix, 0, sizeof(*prefix));
    prefix->kind = ing->message_kind;
    prefix->flags = ing->message_flags;
    (void)memcpy(prefix->transaction_id, ing->transaction_id, 16u);
    (void)memcpy(prefix->attempt_id, ing->attempt_id, 16u);
    (void)memcpy(prefix->event_id, ing->event_id, 16u);
    prefix->source = ing->source;
    prefix->target = ing->target;
    prefix->service = ing->service;
    (void)memcpy(prefix->content_digest, ing->content_digest, 32u);
    prefix->generation = ing->generation;
    (void)memcpy(prefix->deadline_clock_epoch, ing->deadline_clock_epoch, 16u);
    prefix->absolute_effect_deadline_ms = ing->absolute_effect_deadline_ms;
    prefix->evidence_grace_ms = ing->evidence_grace_ms;
    prefix->required_evidence = ing->required_evidence;
    prefix->receipt_stage = ing->receipt_stage;
    prefix->disposition = ing->disposition;
    prefix->effect_certainty = ing->effect_certainty;
    prefix->retry_guidance = ing->retry_guidance;
    prefix->cancel_kind = ing->cancel_kind;
    prefix->retry_delay_ms = ing->retry_delay_ms;
    (void)memcpy(prefix->evidence_clock_epoch, ing->evidence_clock_epoch, 16u);
    prefix->evidence_now_ms = ing->evidence_now_ms;
    prefix->evidence_trust = ing->evidence_trust;
    prefix->payload_length = payload_length;
    return NINLIL_OK;
}

/* Persist MSD SHA into the fixed 754-byte context sha_* slots. */
static void msd_store_sha(
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_message_semantic_digest_ctx_t *msd)
{
    sha_store(ctx, &msd->sha);
}

/*
 * Reconstruct MSD for a later G unit from persistent SHA + known schedule
 * phase/lengths (754 layout has no room for full MSD counters).
 */
static void msd_load_payload_phase(
    const ninlil_domain_scan_d3s3_context_t *ctx,
    ninlil_model_domain_message_semantic_digest_ctx_t *msd,
    uint32_t declared_payload)
{
    (void)memset(msd, 0, sizeof(*msd));
    sha_load(ctx, &msd->sha);
    msd->phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_PAYLOAD;
    msd->declared_payload_length = declared_payload;
    msd->received_payload_length = 0u;
}

static void msd_load_evidence_phase(
    const ninlil_domain_scan_d3s3_context_t *ctx,
    ninlil_model_domain_message_semantic_digest_ctx_t *msd,
    uint32_t declared_payload,
    uint32_t declared_evidence)
{
    (void)memset(msd, 0, sizeof(*msd));
    sha_load(ctx, &msd->sha);
    msd->phase = NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE;
    msd->declared_payload_length = declared_payload;
    msd->received_payload_length = declared_payload;
    msd->declared_evidence_length = declared_evidence;
    msd->received_evidence_length = 0u;
}

static ninlil_status_t mode28_finalize_semantic_ok(
    ninlil_domain_scan_d3s3_context_t *ctx,
    ninlil_model_domain_message_semantic_digest_ctx_t *msd)
{
    ninlil_model_domain_digest_t final_dig;
    ninlil_status_t st;

    st = ninlil_model_domain_message_semantic_digest_final(msd, &final_dig);
    if (st != NINLIL_OK
        || !digest_eq(final_dig.bytes, ctx->expected_semantic_digest)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    /* OK exit: (EXHAUSTED, 2, 1, 1, 0, 0x11, 0x07, 0) */
    ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC);
    ctx->semantic_pass = 0u;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

static ninlil_status_t stream_view_chunks_into_msd(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    ninlil_model_domain_message_semantic_digest_ctx_t *msd,
    int as_payload)
{
    uint32_t count = decode_u32_be_field(ctx->chunk_count);
    uint32_t i;
    ninlil_status_t st;

    for (i = 0u; i < count; i += 1u) {
        ninlil_domain_scan_exact_get_result_t got;
        const ninlil_model_domain_typed_record_t *tr;

        st = rebuild_blob_chunk_key(
            ctx->blob_id_digest, i, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        st = exact_get_peer(session, ctx, &got);
        if (st != NINLIL_OK) {
            return st; /* natural fault: last Port event */
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        st = typed_from_get(
            session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, &tr);
        if (st != NINLIL_OK) {
            return st;
        }
        if (as_payload != 0) {
            st = ninlil_model_domain_message_semantic_digest_update_payload(
                msd, tr->blob_chunk.chunk_bytes, tr->blob_chunk.chunk_length);
        } else {
            st = ninlil_model_domain_message_semantic_digest_update_evidence(
                msd, tr->blob_chunk.chunk_bytes, tr->blob_chunk.chunk_length);
        }
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
    }
    return NINLIL_OK;
}

/*
 * PREFIX G (phase9 / sem0): checked-u32 gate before any Port; carrier re-get;
 * pin expected_semantic; init persistent SHA from prefix + pinned lengths.
 * Nested W/G forbidden — only exact_get(s) for the carrier re-get.
 */
static ninlil_status_t run_mode28_prefix_g(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;
    ninlil_model_domain_message_semantic_digest_ctx_t msd;
    ninlil_model_domain_message_semantic_prefix_t prefix;
    uint64_t a_pin;
    uint64_t b_pin;
    uint32_t pay_len;
    uint32_t evi_len;
    int za;
    int zb;

    /* §18.14.19.5 rule 6: before any Port event. */
    a_pin = decode_u64_be_field(&ctx->focus_id16[0]);
    b_pin = decode_u64_be_field(&ctx->focus_id16[8]);
    if (a_pin > (uint64_t)UINT32_MAX || b_pin > (uint64_t)UINT32_MAX) {
        return note_finding(session);
    }
    pay_len = (uint32_t)a_pin;
    evi_len = (uint32_t)b_pin;

    if (ctx->last_carrier_key_len == 0u) {
        return note_finding(session);
    }
    (void)memcpy(ctx->peer_key, ctx->last_carrier_key, ctx->last_carrier_key_len);
    ctx->peer_key_len = ctx->last_carrier_key_len;
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = typed_from_get(session, ctx, &got,
        NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    /*
     * Pin expected_semantic FIRST (before any later unit). Byte loop instead
     * of memcpy: GCC 13 -O3 -Warray-bounds false-positive (union pointer
     * reload derives object size 0 for ctx) rejects the memcpy form.
     */
    {
        uint8_t *dst = ctx->expected_semantic_digest;
        const uint8_t *sd = tr->ordered_ingress.message_semantic_digest;
        uint32_t di;
        for (di = 0u; di < 32u; di++) {
            dst[di] = sd[di];
        }
    }

    (void)fill_prefix_from_ordered_ingress(
        &prefix, &tr->ordered_ingress, pay_len);
    st = ninlil_model_domain_message_semantic_digest_init(&msd, &prefix);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }

    za = digest_is_zero32(ctx->view_a_key_digest) ? 1 : 0;
    zb = digest_is_zero32(ctx->view_b_key_digest) ? 1 : 0;

    if (za != 0 && zb != 0) {
        /* Both zero: no rescan/chunk; finalize SHA in this G. */
        st = ninlil_model_domain_message_semantic_digest_begin_evidence(
            &msd, 0u);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        st = mode28_finalize_semantic_ok(ctx, &msd);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        return NINLIL_OK;
    }

    if (za == 0) {
        /* A nonzero: PREFIX only; RESCAN_A W next. */
        msd_store_sha(ctx, &msd);
        (void)memcpy(ctx->focus_key_digest, ctx->view_a_key_digest, 32u);
        clear_unit_install(ctx);
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
        ctx->semantic_pass = M28_SEM_RESCAN_A;
        ctx->focus_sub = 1u;
        ctx->count_complete_mask = (uint8_t)(
            NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
        ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        return NINLIL_OK;
    }

    /* Za=1, Zb=0: payload empty complete → begin evidence; RESCAN_B W next. */
    st = ninlil_model_domain_message_semantic_digest_begin_evidence(
        &msd, evi_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    msd_store_sha(ctx, &msd);
    (void)memcpy(ctx->focus_key_digest, ctx->view_b_key_digest, 32u);
    clear_unit_install(ctx);
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
    ctx->semantic_pass = M28_SEM_RESCAN_B;
    ctx->focus_sub = 1u;
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

/* VIEW_A_CHUNKS G (phase10 / sem2): payload stream from RESCAN_A install. */
static ninlil_status_t run_mode28_view_a_chunks_g(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_model_domain_message_semantic_digest_ctx_t msd;
    ninlil_status_t st;
    uint32_t pay_len;
    uint32_t evi_len;
    int zb;

    pay_len = (uint32_t)decode_u64_be_field(&ctx->focus_id16[0]);
    evi_len = (uint32_t)decode_u64_be_field(&ctx->focus_id16[8]);
    msd_load_payload_phase(ctx, &msd, pay_len);

    st = stream_view_chunks_into_msd(session, ctx, &msd, 1);
    if (st != NINLIL_OK) {
        return st;
    }
    st = ninlil_model_domain_message_semantic_digest_begin_evidence(
        &msd, evi_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }

    zb = digest_is_zero32(ctx->view_b_key_digest) ? 1 : 0;
    if (zb != 0) {
        st = mode28_finalize_semantic_ok(ctx, &msd);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        return NINLIL_OK;
    }

    /* B pending: store SHA after begin_evidence; RESCAN_B next. */
    msd_store_sha(ctx, &msd);
    (void)memcpy(ctx->focus_key_digest, ctx->view_b_key_digest, 32u);
    clear_unit_install(ctx);
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
    ctx->semantic_pass = M28_SEM_RESCAN_B;
    ctx->focus_sub = 1u;
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    return NINLIL_OK;
}

/* VIEW_B_CHUNKS G (phase10 / sem4): evidence stream + finalize. */
static ninlil_status_t run_mode28_view_b_chunks_g(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_model_domain_message_semantic_digest_ctx_t msd;
    ninlil_status_t st;
    uint32_t pay_len;
    uint32_t evi_len;

    pay_len = (uint32_t)decode_u64_be_field(&ctx->focus_id16[0]);
    evi_len = (uint32_t)decode_u64_be_field(&ctx->focus_id16[8]);
    msd_load_evidence_phase(ctx, &msd, pay_len, evi_len);

    st = stream_view_chunks_into_msd(session, ctx, &msd, 0);
    if (st != NINLIL_OK) {
        return st;
    }
    st = mode28_finalize_semantic_ok(ctx, &msd);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

static ninlil_status_t run_semantic_mode28(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET
        && ctx->semantic_pass == 0u) {
        return run_mode28_prefix_g(session, ctx);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK
        && ctx->semantic_pass == M28_SEM_VIEW_A) {
        return run_mode28_view_a_chunks_g(session, ctx);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK
        && ctx->semantic_pass == M28_SEM_VIEW_B) {
        return run_mode28_view_b_chunks_g(session, ctx);
    }
    return NINLIL_E_INVALID_STATE;
}

/*
 * RESCAN_A/B W true-exhaustion exit (§18.14.19.8):
 *   sem1 → (EXHAUSTED, 10, 1, 1, 2, 0x03, 0x03, 0)
 *   sem3 → (EXHAUSTED, 10, 1, 1, 4, 0x03, 0x03, 0)
 */
static ninlil_status_t after_mode28_semantic_rescan_w(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE)) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return note_finding(session);
    }
    if (!flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        || ctx->observed_live != 1u) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return note_finding(session);
    }
    if (ctx->semantic_pass == M28_SEM_RESCAN_A) {
        ctx->semantic_pass = M28_SEM_VIEW_A;
    } else if (ctx->semantic_pass == M28_SEM_RESCAN_B) {
        ctx->semantic_pass = M28_SEM_VIEW_B;
    } else {
        return NINLIL_E_INVALID_STATE;
    }
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK;
    ctx->focus_sub = 1u;
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    /* G entry: EXHAUSTED, flags 0x03, no NEED_REOPEN. */
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    return NINLIL_OK;
}

/* ---- SEMANTIC Mode30 two-G schedule (§18.14.19.8 rows; #14/#15/#16) ---- */

/*
 * PREFIX G (phase9 / sem0): carrier RR re-get pins expected_semantic FIRST;
 * then DELIVERY / RESULT / CELL|CANCEL companions per kind matrix. Init +
 * persist SHA after begin_evidence; no reply BLOB chunk GET; no finalize.
 * OK exit: (EXHAUSTED, 10, 1, 0, 0, 0x03, 0x03, 0).
 */
static ninlil_status_t run_mode30_prefix_g(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_domain_scan_exact_get_result_t got;
    const ninlil_model_domain_typed_record_t *tr;
    ninlil_status_t st;
    ninlil_model_domain_message_semantic_digest_ctx_t msd;
    ninlil_model_domain_message_semantic_prefix_t prefix;
    uint8_t delivery_raw[80];
    uint8_t tx16[16];
    uint8_t attempt_id[16];
    uint8_t reply_kind = ctx->reply_kind;
    uint32_t evi_len = 0u;
    uint64_t pinned_total;
    uint32_t pinned_chunks;

    if (ctx->lifecycle_class
        == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT) {
        /* state5: no semantic */
        ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC);
        ctx->semantic_pass = 0u;
        ctx->focus_sub = 0u;
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
        ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        return NINLIL_OK;
    }

    /*
     * #15 pin re-check (PREFIX; non-RECEIPT must already be empty blob).
     * SCAN install is authority; this rejects illegal nonempty pins before
     * companions and ensures SEM_CHUNK never streams non-RECEIPT chunks.
     */
    pinned_total = decode_u64_be_field(ctx->total_length);
    pinned_chunks = decode_u32_be_field(ctx->chunk_count);
    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
        if (pinned_total > 128u) {
            return note_finding(session);
        }
    } else if (pinned_total != 0u || pinned_chunks != 0u) {
        return note_finding(session);
    }

    if (ctx->last_carrier_key_len == 0u) {
        return note_finding(session);
    }
    (void)memcpy(delivery_raw, ctx->focus_raw80, 80u);
    (void)memcpy(tx16, ctx->focus_id16, 16u);

    /* 1. RR re-get — pin expected_semantic FIRST (before any companion). */
    (void)memcpy(ctx->peer_key, ctx->last_carrier_key, ctx->last_carrier_key_len);
    ctx->peer_key_len = ctx->last_carrier_key_len;
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st; /* natural fault: last Port event */
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = typed_from_get(
        session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    (void)memcpy(ctx->expected_semantic_digest,
        tr->reverse_reply.semantic_digest, 32u);
    /* Snapshot attempt_id before workspace overwrite by companions. */
    (void)memcpy(attempt_id, tr->reverse_reply.attempt_id, 16u);

    /* 2. DELIVERY get — #14 + OWNER_PVD */
    st = rebuild_delivery_key(delivery_raw, 80u, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = typed_from_get(
        session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, &tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (tr->delivery.delivery_key_raw_length != 80u
        || memcmp(tr->delivery.delivery_key_raw, delivery_raw, 80u) != 0
        || memcmp(tr->delivery.transaction_id, tx16, 16u) != 0
        || memcmp(tr->delivery.transaction_id, &delivery_raw[32], 16u) != 0) {
        return note_finding(session);
    }
    {
        ninlil_model_domain_digest_t vdig;
        st = ninlil_model_domain_value_digest(got.value, &vdig);
        if (st != NINLIL_OK
            || !digest_eq(vdig.bytes, ctx->expected_owner_pvd)) {
            return note_finding(session);
        }
    }

    /* Snapshot DELIVERY scalars into prefix before RESULT/CELL overwrite. */
    {
        const ninlil_model_domain_body_delivery_t *dlv = &tr->delivery;
        (void)memset(&prefix, 0, sizeof(prefix));
        if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
            prefix.kind = 2u; /* Bearer RECEIPT */
        } else if (reply_kind
            == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION) {
            prefix.kind = 3u;
        } else if (reply_kind
            == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY) {
            prefix.kind = 5u;
        } else {
            prefix.kind = 6u; /* CANCEL_RESULT */
        }
        prefix.flags = 0u;
        (void)memcpy(prefix.transaction_id, dlv->transaction_id, 16u);
        (void)memcpy(prefix.attempt_id, attempt_id, 16u);
        (void)memcpy(prefix.event_id, dlv->event_id, 16u);
        prefix.source = dlv->source;
        prefix.target = dlv->local_target;
        prefix.service = dlv->service;
        (void)memcpy(prefix.content_digest, dlv->content_digest, 32u);
        prefix.generation = dlv->generation;
        (void)memcpy(prefix.deadline_clock_epoch, dlv->deadline_clock_epoch, 16u);
        prefix.absolute_effect_deadline_ms = dlv->absolute_effect_deadline_ms;
        prefix.evidence_grace_ms = dlv->evidence_grace_ms;
        prefix.required_evidence = dlv->required_evidence;
        prefix.payload_length = 0u; /* REPLY path always 0 */
    }

    /* 3. RESULT get — kind matrix (a) checks (reason check-only, never SHA). */
    st = rebuild_result_cache_key(
        delivery_raw, 80u, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session);
    }
    st = typed_from_get(
        session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE, &tr);
    if (st != NINLIL_OK) {
        return st;
    }

    /*
     * Per-kind matrix (§18.14.7.3):
     * RECEIPT: RESULT POSITIVE_EVIDENCE+NONE + CELL SUMMARY@0 #16.
     * DISPOSITION: RESULT DISPOSITION closed tuple; reason (a) only.
     * CUSTODY: contradiction checks only; fixed zero semantic tuple.
     * CANCEL_RESULT: RESULT + CANCEL_STATE bijection; cancel_kind ∈ {1,3}.
     */
    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
        uint32_t stage_snap;
        uint8_t evi_clock[16];
        uint64_t evi_now;
        uint32_t evi_trust;

        if (tr->result_cache.application_result_kind != 1u
            || tr->result_cache.disposition != 0u
            || tr->result_cache.reason != 0u
            || tr->result_cache.effect_certainty != 0u
            || tr->result_cache.retry_guidance != 0u
            || tr->result_cache.retry_delay_ms != 0u
            || tr->result_cache.cancel_result_kind != 0u
            || tr->result_cache.evidence_stage == 0u) {
            return note_finding(session);
        }
        stage_snap = tr->result_cache.evidence_stage;
        encode_u32_be_field(ctx->pinned_receipt_stage, stage_snap);
        prefix.receipt_stage = stage_snap;
        prefix.disposition = 0u;
        prefix.effect_certainty = 0u;
        prefix.retry_guidance = 0u;
        prefix.cancel_kind = 0u;
        prefix.retry_delay_ms = 0u;

        /* 4. EVIDENCE_CELL SUMMARY@0 — pin receipt bytes; evidence_time for SHA. */
        st = rebuild_evidence_cell_key(
            NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY, delivery_raw, 80u, 0u,
            ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        st = exact_get_peer(session, ctx, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        st = typed_from_get(
            session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL, &tr);
        if (st != NINLIL_OK) {
            return st;
        }
        if (tr->evidence_cell.cell_kind
                != NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY
            || tr->evidence_cell.material_receipt_stage != stage_snap
            || (uint64_t)tr->evidence_cell.evidence_length != pinned_total
            || !digest_eq(tr->evidence_cell.evidence_digest, ctx->content_digest)
            || tr->evidence_cell.evidence_length > 128u) {
            return note_finding(session);
        }
        evi_len = (uint32_t)tr->evidence_cell.evidence_length;
        ctx->receipt_evidence_len = (uint8_t)evi_len;
        if (evi_len != 0u) {
            (void)memcpy(ctx->receipt_evidence_bytes,
                tr->evidence_cell.evidence_bytes, evi_len);
        } else {
            (void)memset(ctx->receipt_evidence_bytes, 0,
                NINLIL_DOMAIN_SCAN_D3S3_RECEIPT_EVIDENCE_CAPACITY);
        }
        (void)memcpy(evi_clock, tr->evidence_cell.evidence_clock_epoch, 16u);
        evi_now = tr->evidence_cell.evidence_at_ms;
        evi_trust = tr->evidence_cell.evidence_trust;
        (void)memcpy(prefix.evidence_clock_epoch, evi_clock, 16u);
        prefix.evidence_now_ms = evi_now;
        prefix.evidence_trust = evi_trust;
    } else if (reply_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION) {
        /* Snapshot RESULT SHA scalars before any later overwrite (none). */
        if (tr->result_cache.application_result_kind != 2u
            || tr->result_cache.disposition == 0u
            || tr->result_cache.evidence_stage != 0u
            || tr->result_cache.cancel_result_kind != 0u) {
            return note_finding(session);
        }
        prefix.receipt_stage = 0u;
        prefix.disposition = tr->result_cache.disposition;
        prefix.effect_certainty = tr->result_cache.effect_certainty;
        prefix.retry_guidance = tr->result_cache.retry_guidance;
        prefix.retry_delay_ms = tr->result_cache.retry_delay_ms;
        prefix.cancel_kind = 0u;
        evi_len = 0u;
        ctx->receipt_evidence_len = 0u;
    } else if (reply_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY) {
        if (tr->result_cache.application_result_kind == 2u
            || tr->result_cache.cancel_result_kind != 0u
            || tr->result_cache.disposition != 0u) {
            return note_finding(session);
        }
        /* Fixed zero disposition tuple for SHA (§12 5.4). */
        prefix.receipt_stage = 0u;
        prefix.disposition = 0u;
        prefix.effect_certainty = 0u;
        prefix.retry_guidance = 0u;
        prefix.retry_delay_ms = 0u;
        prefix.cancel_kind = 0u;
        evi_len = 0u;
        ctx->receipt_evidence_len = 0u;
    } else { /* CANCEL_RESULT */
        uint32_t cancel_rk = tr->result_cache.cancel_result_kind;
        uint32_t cancel_kind_snap;

        prefix.receipt_stage = 0u;
        prefix.disposition = 0u;
        prefix.effect_certainty = 0u;
        prefix.retry_guidance = 0u;
        prefix.retry_delay_ms = 0u;
        /* RESULT fields snapshotted; CANCEL_STATE companion next. */
        st = rebuild_cancel_state_delivery_key(
            delivery_raw, 80u, ctx->peer_key, &ctx->peer_key_len);
        if (st != NINLIL_OK) {
            return note_finding(session);
        }
        st = exact_get_peer(session, ctx, &got);
        if (st != NINLIL_OK) {
            return st;
        }
        if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
            return note_finding(session);
        }
        st = typed_from_get(
            session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE, &tr);
        if (st != NINLIL_OK) {
            return st;
        }
        cancel_kind_snap = tr->cancel_state.cancel_kind;
        if (cancel_kind_snap != 1u && cancel_kind_snap != 3u) {
            return note_finding(session);
        }
        if (cancel_rk != cancel_kind_snap) {
            return note_finding(session); /* RESULT/CANCEL_STATE bijection */
        }
        /* reason is check-only (not SHA); cancel_kind from CANCEL_STATE. */
        prefix.cancel_kind = cancel_kind_snap;
        evi_len = 0u;
        ctx->receipt_evidence_len = 0u;
    }

    /* Init persistent SHA + begin_evidence; do not finalize; no chunk GETs. */
    st = ninlil_model_domain_message_semantic_digest_init(&msd, &prefix);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    st = ninlil_model_domain_message_semantic_digest_begin_evidence(&msd, evi_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    msd_store_sha(ctx, &msd);

    /* OK exit: (EXHAUSTED, 10, 1, 0, 0, 0x03, 0x03, 0) */
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK;
    ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    ctx->focus_sub = 0u;
    ctx->semantic_pass = 0u;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    ctx->binding_complete_mask = 0u;
    return NINLIL_OK;
}

/*
 * SEM_CHUNK G (phase10 / sem0): RECEIPT known-index chunk stream-compare +
 * evidence SHA; non-RECEIPT zero chunk GETs (#15 empty already). Finalize
 * sha_final == expected_semantic_digest pin.
 * OK exit: (EXHAUSTED, 2, 1, 0, 0, 0x11, 0x07, 0).
 */
static ninlil_status_t run_mode30_sem_chunk_g(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_model_domain_message_semantic_digest_ctx_t msd;
    ninlil_model_domain_digest_t final_dig;
    ninlil_status_t st;
    uint32_t evi_len;
    uint8_t reply_kind = ctx->reply_kind;

    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
        evi_len = (uint32_t)ctx->receipt_evidence_len;
    } else {
        evi_len = 0u;
    }

    /* Reconstruct MSD evidence phase from persistent SHA (payload always 0). */
    msd_load_evidence_phase(ctx, &msd, 0u, evi_len);

    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
        && evi_len != 0u) {
        uint32_t count = decode_u32_be_field(ctx->chunk_count);
        uint32_t i;
        uint32_t offset = 0u;

        for (i = 0u; i < count; i += 1u) {
            ninlil_domain_scan_exact_get_result_t got;
            const ninlil_model_domain_typed_record_t *tr;
            uint32_t j;
            uint32_t clen;

            st = rebuild_blob_chunk_key(
                ctx->blob_id_digest, i, ctx->peer_key, &ctx->peer_key_len);
            if (st != NINLIL_OK) {
                return note_finding(session);
            }
            st = exact_get_peer(session, ctx, &got);
            if (st != NINLIL_OK) {
                return st; /* natural fault: last Port event */
            }
            if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
                return note_finding(session);
            }
            st = typed_from_get(
                session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, &tr);
            if (st != NINLIL_OK) {
                return st;
            }
            /* Chunk flags must be CHUNK (typed_from_get subtype already BLOB). */
            if (tr->envelope.header.flags
                != NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
                return note_finding(session);
            }
            clen = tr->blob_chunk.chunk_length;
            for (j = 0u; j < clen; j += 1u) {
                if (offset >= evi_len
                    || tr->blob_chunk.chunk_bytes[j]
                        != ctx->receipt_evidence_bytes[offset]) {
                    return note_finding(session);
                }
                offset += 1u;
            }
            st = ninlil_model_domain_message_semantic_digest_update_evidence(
                &msd, tr->blob_chunk.chunk_bytes, clen);
            if (st != NINLIL_OK) {
                return note_finding(session);
            }
        }
        if (offset != evi_len) {
            return note_finding(session);
        }
    }
    /* non-RECEIPT: zero chunk GETs; empty evidence already begun in PREFIX. */

    st = ninlil_model_domain_message_semantic_digest_final(&msd, &final_dig);
    if (st != NINLIL_OK
        || !digest_eq(final_dig.bytes, ctx->expected_semantic_digest)) {
        return note_finding(session);
    }

    /* OK exit: (EXHAUSTED, 2, 1, 0, 0, 0x11, 0x07, 0) */
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC);
    ctx->semantic_pass = 0u;
    ctx->focus_sub = 0u;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    ctx->binding_complete_mask = 0u;
    return NINLIL_OK;
}

static ninlil_status_t run_semantic_mode30(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET
        && ctx->semantic_pass == 0u) {
        return run_mode30_prefix_g(session, ctx);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK
        && ctx->semantic_pass == 0u) {
        return run_mode30_sem_chunk_g(session, ctx);
    }
    return NINLIL_E_INVALID_STATE;
}

static ninlil_status_t run_semantic(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB) {
        return run_semantic_mode28(session, ctx);
    }
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        return run_semantic_mode30(session, ctx);
    }
    return NINLIL_OK;
}

/* ---- BIND_MANIFEST + BIND_CHUNK + untyped orphan ---- */

static ninlil_status_t rebuild_ingress_owner_key(
    const uint8_t *owner_raw, uint16_t owner_raw_len, uint8_t *out_key,
    uint8_t *out_key_len)
{
    uint64_t ordered_sequence;
    uint8_t seq_be[8];
    ninlil_bytes_view_t identity;

    if (owner_raw == NULL
        || owner_raw_len != NINLIL_MODEL_DOMAIN_BLOB_OWNER_KEY_INGRESS_BYTES) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ordered_sequence = ninlil_model_domain_decode_u64_be(owner_raw);
    if (ordered_sequence == 0u) {
        if (out_key_len != NULL) {
            *out_key_len = 0u;
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_encode_u64_be(seq_be, ordered_sequence);
    identity.data = seq_be;
    identity.length = 8u;
    return write_complete_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
        NINLIL_MODEL_DOMAIN_ID_KIND_U64, identity, out_key, out_key_len);
}

/*
 * §18.14.9.2 / .3 closed (owner_kind, blob_kind) eligibility.
 * Non-eligible man rows: visit only, GET 0.
 */
static int bind_man_pair_eligible(
    uint8_t focus_mode, uint16_t owner_kind, uint16_t blob_kind)
{
    if (focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB) {
        return owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION
            && (blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD
                || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVENT_PAYLOAD);
    }
    if (focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB) {
        return owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS
            && (blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD
                || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE);
    }
    if (focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB) {
        return owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY
            && (blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD
                || blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVENT_PAYLOAD);
    }
    if (focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        return owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY
            && blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY;
    }
    return 0;
}

/*
 * Modes 27–29 BIND_MANIFEST reverse proof (§18.14.9):
 * forward-rebuild owner key → exact_get PRESENT → typed validate →
 * owner referrer digest == KEY_DIGEST(manifest complete key) →
 * owner VALUE_DIGEST == manifest common primary_value_digest (expected_owner
 * when installed, else live man PVD from typed common header).
 *
 * Mode28 referrer (§18.14.9.2 step6): exactly one field selected by pinned
 * blob_kind — INGRESS_PAYLOAD→payload_blob_key_digest,
 * EVIDENCE→evidence_blob_key_digest. Forbidden: payload-or-evidence OR.
 */
static ninlil_status_t bind_manifest_forward_owner(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx,
    const ninlil_model_domain_typed_record_t *typed,
    const uint8_t *man_key,
    uint8_t man_key_len)
{
    const ninlil_model_domain_body_blob_manifest_t *m = &typed->blob_manifest;
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_status_t st;
    uint8_t owner_key[45];
    uint8_t owner_key_len = 0u;
    uint8_t man_key_dig[32];
    uint8_t man_pvd[32];
    uint8_t owner_raw_copy[80];
    uint16_t owner_raw_len;
    uint16_t owner_kind;
    uint16_t blob_kind;
    uint8_t expected_subtype;
    const ninlil_model_domain_typed_record_t *owner_tr;
    ninlil_model_domain_digest_t owner_vdig;
    const uint8_t *referrer_dig = NULL;

    if (man_key == NULL || man_key_len == 0u || typed == NULL) {
        return note_finding(session);
    }
    /* REP1 BIND_MAN WG: pin last_carrier_key to man complete key before GET. */
    if (man_key_len > NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY) {
        return note_finding(session);
    }
    (void)memcpy(ctx->last_carrier_key, man_key, man_key_len);
    ctx->last_carrier_key_len = man_key_len;
    st = key_digest_of(man_key, man_key_len, man_key_dig);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    /* Copy before exact_get — owner_key_raw may borrow workspace body bytes. */
    (void)memcpy(man_pvd, typed->envelope.header.primary_value_digest, 32u);
    owner_kind = m->blob_owner_kind;
    blob_kind = m->blob_kind;
    owner_raw_len = m->owner_key_raw_length;
    if (m->owner_key_raw == NULL || owner_raw_len == 0u
        || owner_raw_len > (uint16_t)sizeof(owner_raw_copy)) {
        return note_finding(session);
    }
    (void)memcpy(owner_raw_copy, m->owner_key_raw, owner_raw_len);
    ctx->owner_kind = (uint8_t)owner_kind;
    ctx->blob_kind = (uint8_t)blob_kind;
    (void)memcpy(ctx->focus_key_digest, man_key_dig, 32u);

    if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION) {
        ninlil_bytes_view_t id;
        if (owner_raw_len != 16u) {
            return note_finding(session);
        }
        id.data = owner_raw_copy;
        id.length = 16u;
        st = write_complete_key(
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128, id, owner_key, &owner_key_len);
        expected_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS) {
        st = rebuild_ingress_owner_key(
            owner_raw_copy, owner_raw_len, owner_key, &owner_key_len);
        expected_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY) {
        if (owner_raw_len != 80u) {
            return note_finding(session);
        }
        st = rebuild_delivery_key(
            owner_raw_copy, 80u, owner_key, &owner_key_len);
        expected_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
    } else {
        return note_finding(session);
    }
    if (st != NINLIL_OK) {
        return note_finding(session);
    }
    (void)memcpy(ctx->peer_key, owner_key, owner_key_len);
    ctx->peer_key_len = owner_key_len;
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session); /* owner absent */
    }
    st = typed_from_get(session, ctx, &got, expected_subtype, &owner_tr);
    if (st != NINLIL_OK) {
        return st;
    }

    /* Owner referrer field must equal KEY_DIGEST(manifest complete key). */
    if (expected_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR) {
        referrer_dig = owner_tr->transaction_anchor.payload_blob_key_digest;
    } else if (expected_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS) {
        /* Closed: one field by pinned blob_kind only — no payload-or-evidence. */
        if (blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD) {
            referrer_dig = owner_tr->ordered_ingress.payload_blob_key_digest;
        } else if (blob_kind == NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE) {
            referrer_dig = owner_tr->ordered_ingress.evidence_blob_key_digest;
        } else {
            return note_finding(session);
        }
    } else {
        referrer_dig = owner_tr->delivery.payload_blob_key_digest;
    }
    if (referrer_dig == NULL || !digest_eq(referrer_dig, man_key_dig)) {
        return note_finding(session); /* referrer mismatch */
    }

    /* Owner VALUE_DIGEST == manifest common primary_value_digest (copied). */
    st = ninlil_model_domain_value_digest(got.value, &owner_vdig);
    if (st != NINLIL_OK || !digest_eq(owner_vdig.bytes, man_pvd)) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

static ninlil_status_t on_row_bind_manifest(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s3_context_t *ctx,
    uint32_t key_length,
    uint8_t typed_current_ok)
{
    const ninlil_model_domain_typed_record_t *typed;
    ninlil_status_t st;

    if (typed_current_ok == 0u || key_length < 10u) {
        return NINLIL_OK;
    }
    if (workspace->key[8] != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_OK;
    }
    typed = typed_of(workspace);

    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        /*
         * Mode30 BIND outer W (phase11 / semantic_pass==0; §18.14.9.3):
         * pure walk GET 0. Select at most the first eligible CURRENT REPLY man
         * complete key strictly greater than proven BLOB-manifest frontier
         * last_carrier_key (empty frontier ⇒ first eligible). Pin peer + proof
         * fields; do NOT advance last_carrier_key at selection. RR-band is a
         * separate pure W (semantic_pass==5); inventing RR keys is forbidden.
         */
        if (ctx->semantic_pass != 0u) {
            return NINLIL_OK;
        }
        if (workspace->key[9] == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB
            && typed->envelope.header.flags
                == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST
            && bind_man_pair_eligible(ctx->focus_mode,
                   typed->blob_manifest.blob_owner_kind,
                   typed->blob_manifest.blob_kind)) {
            const ninlil_model_domain_body_blob_manifest_t *m;
            uint8_t man_dig[32];

            /* At most one selection per outer W (peer_key holds candidate). */
            if (ctx->peer_key_len != 0u) {
                return NINLIL_OK;
            }
            if (key_length == 0u
                || key_length > NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY) {
                return NINLIL_OK;
            }
            if (!key_strictly_greater_than_last(ctx, workspace->key, key_length)) {
                return NINLIL_OK; /* ≤ proven BLOB-manifest frontier */
            }
            m = &typed->blob_manifest;
            if (m->owner_key_raw == NULL
                || m->owner_key_raw_length != 80u) {
                return note_finding(session);
            }
            st = key_digest_of(workspace->key, (uint8_t)key_length, man_dig);
            if (st != NINLIL_OK) {
                return note_finding(session);
            }
            (void)memcpy(ctx->peer_key, workspace->key, key_length);
            ctx->peer_key_len = (uint8_t)key_length;
            (void)memcpy(ctx->focus_key_digest, man_dig, 32u);
            (void)memcpy(ctx->focus_raw80, m->owner_key_raw, 80u);
            ctx->focus_raw_len = 80u;
            ctx->owner_kind = (uint8_t)m->blob_owner_kind;
            ctx->blob_kind = (uint8_t)m->blob_kind;
            ctx->observed_live = 0u;
            /* last_carrier_key stays the prior proven frontier (no advance). */
            return NINLIL_OK;
        }
        return NINLIL_OK;
    }

    /* Modes 27–29: only closed-eligible man rows run reverse owner proof. */
    if (workspace->key[9] != NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB
        || typed->envelope.header.flags
            != NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
        return NINLIL_OK;
    }
    if (!bind_man_pair_eligible(ctx->focus_mode,
            typed->blob_manifest.blob_owner_kind,
            typed->blob_manifest.blob_kind)) {
        return NINLIL_OK; /* visit only, GET 0 */
    }
    return bind_manifest_forward_owner(
        session, ctx, typed, workspace->key, (uint8_t)key_length);
}

/*
 * Modes 27–30 BIND_CHUNK WG (§18.14.9.4):
 * pin phase-local fields from the chunk row BEFORE exact_get (workspace value
 * overwrite invalidates typed/borrowed views), then man-presence GET + body/
 * index/PVD compares on returned bytes only. Never dereference pre-get typed
 * after GET.
 */
static ninlil_status_t on_row_bind_chunk(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s3_context_t *ctx,
    uint32_t key_length,
    uint8_t typed_current_ok)
{
    const ninlil_model_domain_typed_record_t *typed;
    const ninlil_model_domain_body_blob_chunk_t *ch;
    const ninlil_model_domain_typed_record_t *man_tr;
    const ninlil_model_domain_body_blob_manifest_t *man;
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_status_t st;
    ninlil_model_domain_digest_t man_vdig;
    uint8_t expect_ck[45];
    uint8_t expect_ck_len = 0u;
    uint8_t man_key_dig[32];
    uint32_t pinned_index;
    uint32_t pinned_count;
    uint64_t pinned_total;

    if (typed_current_ok == 0u || key_length < 10u) {
        return NINLIL_OK;
    }
    if (workspace->key[8] != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || workspace->key[9] != NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB) {
        return NINLIL_OK;
    }
    typed = typed_of(workspace);
    if (typed->envelope.header.flags != NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
        return NINLIL_OK;
    }
    ch = &typed->blob_chunk;

    /* Phase-local pin map (§18.14.9.4) — all fields before GET. */
    if (key_length > NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY) {
        return note_finding(session);
    }
    (void)memcpy(ctx->last_carrier_key, workspace->key, key_length);
    ctx->last_carrier_key_len = (uint8_t)key_length;
    (void)memcpy(ctx->blob_id_digest, ch->blob_id_digest, 32u);
    (void)memcpy(ctx->focus_key_digest, ch->manifest_key_digest, 32u);
    (void)memcpy(ctx->content_digest, ch->content_digest, 32u);
    (void)memcpy(
        ctx->expected_manifest_value_digest,
        typed->envelope.header.primary_value_digest, 32u);
    pinned_index = ch->chunk_index;
    pinned_count = ch->chunk_count;
    pinned_total = ch->total_length;
    encode_u32_be_field(ctx->next_chunk_index, pinned_index);
    encode_u32_be_field(ctx->chunk_count, pinned_count);
    encode_u64_be_field(ctx->total_length, pinned_total);
    /* typed/ch must not be used after exact_get. */
    typed = NULL;
    ch = NULL;

    /* 1. Rebuild man complete key from pinned blob_id. */
    st = rebuild_blob_manifest_key(
        ctx->blob_id_digest, ctx->peer_key, &ctx->peer_key_len);
    if (st != NINLIL_OK) {
        return note_finding(session);
    }

    /* 7 (request path): pinned manifest_key_digest == KEY_DIGEST(man key). */
    st = key_digest_of(ctx->peer_key, ctx->peer_key_len, man_key_dig);
    if (st != NINLIL_OK || !digest_eq(man_key_dig, ctx->focus_key_digest)) {
        return note_finding(session);
    }

    /* 6. Actual chunk key == COMPOSITE(BLOB, u8=2 ‖ blob_id ‖ index). */
    st = rebuild_blob_chunk_key(
        ctx->blob_id_digest, pinned_index, expect_ck, &expect_ck_len);
    if (st != NINLIL_OK
        || expect_ck_len != ctx->last_carrier_key_len
        || memcmp(expect_ck, ctx->last_carrier_key, expect_ck_len) != 0) {
        return note_finding(session);
    }

    /* 2. exact_get(man) — final Port event for this row drive if natural fault. */
    st = exact_get_peer(session, ctx, &got);
    if (st != NINLIL_OK) {
        return st;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return note_finding(session); /* untyped orphan */
    }

    /* 3/8. Returned value typed CURRENT DOMAIN BLOB MANIFEST. */
    st = typed_from_get(
        session, ctx, &got, NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, &man_tr);
    if (st != NINLIL_OK) {
        return st;
    }
    if (man_tr->envelope.header.flags
        != NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
        return note_finding(session);
    }
    man = &man_tr->blob_manifest;

    /* 4. Man body fields exact-equal pins. */
    if (!digest_eq(man->blob_id_digest, ctx->blob_id_digest)
        || man->chunk_count != pinned_count
        || man->total_length != pinned_total
        || !digest_eq(man->content_digest, ctx->content_digest)) {
        return note_finding(session);
    }

    /* 5. Pinned chunk_index strictly less than returned man.chunk_count. */
    if (pinned_index >= man->chunk_count) {
        return note_finding(session); /* EXTRA_CHUNK family */
    }

    /*
     * 8. VALUE_DIGEST(returned man complete value) == pinned chunk common
     * primary_value_digest. Do not compare man-header PVD (owner-value role).
     */
    st = ninlil_model_domain_value_digest(got.value, &man_vdig);
    if (st != NINLIL_OK
        || !digest_eq(man_vdig.bytes, ctx->expected_manifest_value_digest)) {
        return note_finding(session);
    }
    return NINLIL_OK;
}

/* ---- on_row / on_exhausted / drive ---- */

static ninlil_status_t on_row_select(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s3_context_t *ctx,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok)
{
    ninlil_status_t st;
    int needs_setup_g = 0;

    if (typed_current_ok == 0u || key_length < 10u) {
        return NINLIL_OK;
    }
    if (workspace->key[8] != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_OK;
    }
    if (!carrier_subtype_ok(ctx->focus_mode, workspace->key[9])) {
        return NINLIL_OK;
    }
    if (!key_strictly_greater_than_last(ctx, workspace->key, key_length)) {
        return NINLIL_OK;
    }
    st = install_and_setup_carrier(
        session, workspace, ctx, key_length, value_length, &needs_setup_g);
    if (st != NINLIL_OK) {
        return st;
    }
    /* Latch first carrier; residual SELECT rows do not install another. */
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);

    if (needs_setup_g != 0) {
        /*
         * REP1 design B: stay phase=SELECT, semantic_pass=6 for next pure-G
         * drive. No Port GET in this W; do not enter FOCUS mid-walk.
         */
        ctx->semantic_pass = NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP;
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
        return NINLIL_OK;
    }

    if (ctx->lifecycle_class == NINLIL_DOMAIN_SCAN_D3S3_LIFE_ILLEGAL_CARRIER) {
        return note_finding(session);
    }

    /*
     * Mode28 SELECT Za/Zb exact normal forms (§18.14.19.8):
     *   Za=0 → FOCUS_SCAN A (phase3, focus_sub=0)
     *   Za=1,Zb=0 → FOCUS_SCAN_B (phase6, focus_sub=1, dig B)
     *   Za=1,Zb=1 → SEMANTIC (phase9, focus_sub=1, count 0x03); no scan Port
     * setup_mode28 already pinned digests / sub / expected_live / totals=0.
     */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB) {
        int za = digest_is_zero32(ctx->view_a_key_digest) ? 1 : 0;
        int zb = digest_is_zero32(ctx->view_b_key_digest) ? 1 : 0;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
        if (za != 0 && zb != 0) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
            ctx->focus_sub = 1u;
            ctx->count_complete_mask = (uint8_t)(
                NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
            return NINLIL_OK;
        }
        if (za == 0) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
            ctx->focus_sub = 0u;
            return NINLIL_OK;
        }
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
        ctx->focus_sub = 1u;
        return NINLIL_OK;
    }

    if (ctx->lifecycle_class == NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE
        || (ctx->expected_live == 0u
            && ctx->lifecycle_class
                != NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT
            && digest_is_zero32(ctx->focus_key_digest))) {
        /* Zero-digest none: skip FOCUS for single-view modes */
        ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
        return NINLIL_OK;
    }
    if (ctx->expected_live == 0u
        && digest_is_zero32(ctx->focus_key_digest)
        && ctx->lifecycle_class
            == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT) {
        /* historical: still SCAN to prove absent (match_count 0) */
    }
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_d3s3_on_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok)
{
    ninlil_domain_scan_d3s3_context_t *ctx;

    if (session == NULL || workspace == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = ctx_of(session);
    if (ctx == NULL || ctx->pass_kind != NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL) {
        return NINLIL_OK;
    }
    if (session->profile_exact_active == 0u || session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        return NINLIL_OK;
    }

    /*
     * Mode30 BIND RR-band pure W (phase11 / semantic_pass==5; §18.14.9.3):
     * GET 0. Qualify CURRENT REVERSE_REPLY with body_blob_key_digest, delivery
     * raw80/len80, and send_state∈{1,2,3,4}. Boolean latch observed_live 0/1
     * only (idempotent set to 1; never multi-count).
     */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB
        && ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST
        && ctx->semantic_pass == 5u) {
        const ninlil_model_domain_typed_record_t *tr;
        uint32_t ss;

        if (typed_current_ok != 0u && key_length >= 10u
            && workspace->key[8] == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
            && workspace->key[9] == NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY) {
            tr = typed_of(workspace);
            ss = tr->reverse_reply.send_state;
            if (digest_eq(tr->reverse_reply.body_blob_key_digest,
                    ctx->focus_key_digest)
                && tr->reverse_reply.delivery_key_raw != NULL
                && tr->reverse_reply.delivery_key_raw_length
                    == ctx->focus_raw_len
                && ctx->focus_raw_len == 80u
                && memcmp(tr->reverse_reply.delivery_key_raw, ctx->focus_raw80,
                       80u)
                    == 0
                && ss >= NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING
                && ss <= NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_DENIED) {
                ctx->observed_live = 1u; /* idempotent; never >1 */
            }
        }
        return NINLIL_OK;
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER) {
        /* One carrier latch: FOCUS_LIVE (no-setup path) or CARRIER_INSTALLED. */
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE)
            || flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return on_row_select(
            session, workspace, ctx, key_length, value_length, typed_current_ok);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B) {
        /*
         * P0: residual rows of the SELECT install advance must not run the
         * SCAN match arm. Drive reopens zero-prefix for a full-band SCAN
         * after clearing CARRIER_INSTALLED (same spirit as S2 FOCUS).
         */
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return install_manifest_match(
            session, workspace, ctx, key_length, value_length);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST) {
        return on_row_bind_manifest(
            session, workspace, ctx, key_length, typed_current_ok);
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_CHUNK) {
        return on_row_bind_chunk(
            session, workspace, ctx, key_length, typed_current_ok);
    }
    return NINLIL_OK;
}

static ninlil_status_t enter_bind_set(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    (void)session;
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE)) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_BIND_PHASE_ACTIVE);
    flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);
    ctx->semantic_pass = 0u;
    ctx->focus_sub = 0u; /* empty-SELECT → BIND: focus_sub=0 (§18.14.19.8) */
    ctx->observed_live = 0u;
    /*
     * Mode30 BIND-entry initialization exactly once on SELECT true-exhaustion
     * no-carrier → phase11 (§18.14.9.3 / §18.14.19.8). Empty BLOB-manifest
     * frontier; clear selected peer/pins/latch. Preserve focus_id16 and every
     * unlisted field. Not repeated before later outer W.
     */
    if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
        (void)memset(ctx->last_carrier_key, 0, sizeof(ctx->last_carrier_key));
        ctx->last_carrier_key_len = 0u;
        (void)memset(ctx->peer_key, 0, sizeof(ctx->peer_key));
        ctx->peer_key_len = 0u;
        (void)memset(ctx->focus_key_digest, 0, 32u);
        (void)memset(ctx->focus_raw80, 0, 80u);
        ctx->focus_raw_len = 0u;
        ctx->owner_kind = 0u;
        ctx->blob_kind = 0u;
        ctx->observed_live = 0u;
        ctx->semantic_pass = 0u;
        /* focus_id16 and all unlisted context preserved. */
    }
    return NINLIL_OK;
}

static ninlil_status_t complete_if_ready(ninlil_domain_scan_d3s3_context_t *ctx)
{
    uint8_t need = ninlil_domain_scan_d3s3_required_binding_mask(ctx->focus_mode);
    if ((ctx->binding_complete_mask & need) == need) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_COMPLETE_READY);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_BIND_PHASE_ACTIVE);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE);
        ctx->semantic_pass = 0u;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_d3s3_on_exhausted(
    ninlil_domain_scan_session_t *session)
{
    ninlil_domain_scan_d3s3_context_t *ctx;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = ctx_of(session);
    if (ctx == NULL || ctx->pass_kind != NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL) {
        return NINLIL_OK;
    }
    if (session->profile_exact_active == 0u || session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        return NINLIL_OK;
    }

    /*
     * Mode28 semantic RESCAN_A (sem1) / RESCAN_B (sem3) W true exhaustion:
     * exact post-transition to VIEW_*_CHUNKS G (§18.14.19.8). Not suppressed.
     * Mode30 BIND RR-band uses semantic_pass==5 under BIND_MANIFEST only.
     */
    if ((ctx->semantic_pass == M28_SEM_RESCAN_A
            || ctx->semantic_pass == M28_SEM_RESCAN_B)
        && (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
            || ctx->phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B)) {
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return after_mode28_semantic_rescan_w(session, ctx);
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B) {
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return after_manifest_scan(session, ctx);
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER) {
        /*
         * SELECT pure-W true exhaustion:
         * - semantic_pass==6: carrier pinned; next drive is SELECT_SETUP G.
         * - CARRIER_INSTALLED mid-walk residual only: keep phase as set in on_row.
         * - no carrier: empty SELECT → BIND entry.
         */
        if (ctx->semantic_pass == NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP
            && flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
            /* Checkpoint normal form: BASELINE_DONE only; no NEED_REOPEN for G. */
            ctx->flags = NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE;
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
            ctx->semantic_pass = NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP;
            ctx->count_complete_mask = 0u;
            ctx->expected_live = 0u;
            ctx->observed_live = 0u;
            return NINLIL_OK;
        }
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE)) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
            return NINLIL_OK;
        }
        return enter_bind_set(session, ctx);
    }

    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST) {
        /*
         * Mode30 BIND_MAN pure W closed exits (§18.14.9.3 / §18.14.19.8):
         *   outer sem0 + peer selected → phase11 sem5 NEED_REOPEN (RR W)
         *   outer sem0 + no candidate → phase12 BIND_MAN bit only
         *   RR sem5 latch0 → CORRUPT (frontier unchanged)
         *   RR sem5 latch1 → promote peer→frontier; exact clear pins; sem0
         */
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB) {
            if (ctx->semantic_pass == 5u) {
                if (ctx->observed_live == 0u) {
                    /* sticky CORRUPT; frontier not advanced; failure snapshot */
                    return note_finding(session);
                }
                /* Atomic success promotion: frontier copy then exact clear. */
                if (ctx->peer_key_len == 0u
                    || ctx->peer_key_len
                        > NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY) {
                    return note_finding(session);
                }
                (void)memcpy(ctx->last_carrier_key, ctx->peer_key,
                    ctx->peer_key_len);
                ctx->last_carrier_key_len = ctx->peer_key_len;
                (void)memset(ctx->peer_key, 0, sizeof(ctx->peer_key));
                ctx->peer_key_len = 0u;
                (void)memset(ctx->focus_key_digest, 0, 32u);
                (void)memset(ctx->focus_raw80, 0, 80u);
                ctx->focus_raw_len = 0u;
                ctx->owner_kind = 0u;
                ctx->blob_kind = 0u;
                ctx->observed_live = 0u;
                /* focus_id16 and unlisted state preserved */
                ctx->semantic_pass = 0u;
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
                flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
                return NINLIL_OK;
            }
            if (ctx->peer_key_len != 0u) {
                /* Selected candidate → RR-band W entry (sem5). */
                ctx->semantic_pass = 5u;
                ctx->observed_live = 0u;
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
                flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
                /* binding stays 0; count mask frozen; flags 0x15 with NEED_REOPEN */
                return NINLIL_OK;
            }
            /* No candidate: only path into BIND_CHUNK. */
        }
        ctx->binding_complete_mask = (uint8_t)(ctx->binding_complete_mask
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_MANIFEST);
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_CHUNK;
        ctx->semantic_pass = 0u;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        return NINLIL_OK;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_CHUNK) {
        ctx->binding_complete_mask = (uint8_t)(ctx->binding_complete_mask
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_CHUNK);
        return complete_if_ready(ctx);
    }
    return NINLIL_OK;
}

static ninlil_status_t ensure_reopen_if_needed(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_status_t st;
    if (!flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN)) {
        return NINLIL_OK;
    }
    flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    st = ninlil_domain_scan_reopen_zero_prefix_iter(session);
    return st;
}

/*
 * REP1-L2 micro-step kinds (docs/17 §18.14.19.3): one d3s3_drive is either
 * one Walk (W) or one Get (G). G never reopens; NEED_REOPEN is for a later W.
 * SELECT_SETUP G is phase=SELECT_CARRIER with semantic_pass=6.
 */
static int entry_is_g_unit(const ninlil_domain_scan_d3s3_context_t *ctx)
{
    uint8_t phase = ctx->phase;
    if (phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER
        && ctx->semantic_pass == NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP) {
        return 1;
    }
    return phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF
        || phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF_B
        || phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS
        || phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS_B
        || phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET
        || phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK;
}

/* After SELECT_SETUP G: enter FOCUS W entry normal form (0x13 + NEED_REOPEN). */
static void select_setup_enter_focus(
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ctx->semantic_pass = 0u;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    ctx->count_complete_mask = 0u;
    /* FOCUS walk reconstructs expected_live from lifecycle at W entry. */
    ctx->expected_live = 0u;
    ctx->observed_live = 0u;
}

static ninlil_status_t drive_g_unit(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    ninlil_status_t st;

    /* G: exact_get burst for the entry phase only; no advance / no reopen. */
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER
        && ctx->semantic_pass == NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP) {
        if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB) {
            st = run_select_setup_mode27(session, ctx);
        } else if (ctx->focus_mode
            == NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB) {
            st = run_select_setup_mode29(session, ctx);
        } else {
            return NINLIL_E_INVALID_STATE;
        }
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return st;
        }
        if (ctx->lifecycle_class == NINLIL_DOMAIN_SCAN_D3S3_LIFE_ILLEGAL_CARRIER) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return note_finding(session);
        }
        if (ctx->lifecycle_class == NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE
            && digest_is_zero32(ctx->focus_key_digest)
            && ctx->focus_mode != NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB) {
            /* Zero-digest none after setup: complete count bits; stay SELECT-ish. */
            ctx->count_complete_mask = (uint8_t)(ctx->count_complete_mask
                | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
            ctx->semantic_pass = 0u;
            ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                | NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
            return NINLIL_OK;
        }
        if (ctx->lifecycle_class
                == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT
            && digest_is_zero32(ctx->focus_key_digest)) {
            /* historical absent still needs FOCUS SCAN prove zero match */
        }
        select_setup_enter_focus(ctx);
        return NINLIL_OK;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF_B) {
        st = run_owner_pvd_proof(session, ctx);
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return st;
        }
        return NINLIL_OK;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS_B) {
        st = run_focus_chunks(session, ctx);
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return st;
        }
        /* May set NEED_REOPEN for a later W; do not reopen here. */
        return NINLIL_OK;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK) {
        st = run_semantic(session, ctx);
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return st;
        }
        return NINLIL_OK;
    }
    return NINLIL_E_INVALID_STATE;
}

ninlil_status_t ninlil_domain_scan_d3s3_drive(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget)
{
    ninlil_domain_scan_d3s3_context_t *ctx;
    ninlil_status_t st;
    uint8_t entry_phase;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ctx = ctx_of(session);
    if (ctx == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->has_sticky_primary != 0u
        || session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return session->has_sticky_primary != 0u ? session->sticky_primary
                                                : NINLIL_E_STORAGE_CORRUPT;
    }
    if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE) {
        return NINLIL_OK;
    }

    entry_phase = ctx->phase;

    /* ---- G micro-unit (row_budget == 0; exact_get only) ---- */
    if (entry_is_g_unit(ctx)) {
        if (row_budget != 0u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        return drive_g_unit(session, ctx);
    }

    /* ---- W micro-unit (positive row_budget; advance only) ---- */
    if (row_budget == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /* BASELINE W: begin I1, no reopen. B5 midwalk keeps OPEN/BASELINE. */
    if (ctx->pass_kind == NINLIL_DOMAIN_SCAN_D3S3_PASS_BASELINE
        || ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BASELINE) {
        if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            return NINLIL_E_INVALID_STATE;
        }
        st = ninlil_domain_scan_advance(session, row_budget);
        if (st != NINLIL_OK) {
            ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
            return st;
        }
        if (session->state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            /* B5 midwalk only: still BASELINE, pea deferred, no on_exhausted. */
            return NINLIL_OK;
        }
        if (session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
            return NINLIL_E_INVALID_STATE;
        }
        /* B1 true exhaustion (or evaluator-off hold). */
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE);
        if (session->profile_mismatch != 0u
            || session->future_profile_candidate != 0u) {
            /* Evaluator-off: stay BASELINE; pea remains 0. */
            return NINLIL_OK;
        }
        /* Activate profile-exact after successful true-exhaustion BASELINE W. */
        session->profile_exact_active = 1u;
        session->profile_mismatch = 0u;
        session->future_profile_candidate = 0u;
        ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER;
        flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        /* Reopen belongs to the next SELECT W — not this BASELINE drive. */
        return NINLIL_OK;
    }

    /*
     * Non-BASELINE W: if NEED_REOPEN, close current Ik and open next Ik
     * before the first iter_next. BASELINE never takes this path.
     */
    st = ensure_reopen_if_needed(session, ctx);
    if (st != NINLIL_OK) {
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return st;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        if (session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
            st = ninlil_domain_scan_reopen_zero_prefix_iter(session);
            if (st != NINLIL_OK) {
                ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
                return st;
            }
        } else {
            return NINLIL_E_INVALID_STATE;
        }
    }

    /*
     * SELECT install residual: CARRIER_INSTALLED was set mid-walk; residual
     * rows advanced under that flag. Clear it at W entry so a fresh FOCUS W
     * can match — but only when re-entering FOCUS after a prior SELECT end.
     * On first entry to SELECT the flag is already clear.
     *
     * FOCUS W re-entry after SELECT: clear MATCH bits and observed_live so
     * the SCAN band is clean (MATCH_INSTALLED is set only by a match row).
     */
    if (entry_phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
        || entry_phase
            == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B) {
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED);
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE);
        /*
         * REP1 checkpoints keep expected_live/observed_live at zero.  They
         * are walk-local scratch only: reconstruct the expectation from the
         * durable lifecycle class + current digest immediately before the
         * FOCUS walk, then clear both before returning to the caller.
         */
        ctx->expected_live =
            (ctx->lifecycle_class
                    == NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED
                && !digest_is_zero32(ctx->focus_key_digest))
            ? 1u
            : 0u;
        ctx->observed_live = 0u;
    } else if (entry_phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER) {
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);
    }

    st = ninlil_domain_scan_advance(session, row_budget);
    if (st != NINLIL_OK) {
        if (entry_phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER
            || entry_phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
            || entry_phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B) {
            ctx->expected_live = 0u;
            ctx->observed_live = 0u;
        }
        ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED;
        return st;
    }

    /*
     * SELECT W ended after installing a carrier:
     * - semantic_pass==6: SELECT_SETUP G is the next drive (no NEED_REOPEN).
     * - phase already FOCUS: residual walk finished; NEED_REOPEN for FOCUS W.
     * Do not run OWNER/CHUNKS/SEMANTIC G in this same drive.
     */
    if (flags_has(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED)) {
        if (ctx->semantic_pass == NINLIL_DOMAIN_SCAN_D3S3_SEM_SELECT_SETUP
            && ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER) {
            /* H2 already normalized flags/sem for SELECT_SETUP entry. */
            ctx->expected_live = 0u;
            ctx->observed_live = 0u;
            return NINLIL_OK;
        }
        flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED);
        if (ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
            || ctx->phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B) {
            flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED);
            flags_clear(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE);
            ctx->observed_live = 0u;
            /* FOCUS entry normal form 0x13 after pure-W SELECT (no setup). */
            ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
                | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        } else if (ctx->focus_mode == NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB
            && ctx->phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET) {
            /*
             * Mode28 both-zero SELECT exit (§18.14.19.8):
             * (EXHAUSTED, 9, 1, 1, 0, 0x03, 0x03, 0) — no NEED_REOPEN for G.
             */
            ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
            ctx->focus_sub = 1u;
            ctx->count_complete_mask = (uint8_t)(
                NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
        } else {
            flags_set(ctx, NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        }
        ctx->expected_live = 0u;
        ctx->observed_live = 0u;
        return NINLIL_OK;
    }

    /*
     * True EXHAUSTED W without a mid-walk SELECT install: H2 already ran
     * inside advance (on_exhausted). Phase may now be OWNER/CHUNKS/BIND/…
     * G work is a separate drive call. If H2 set NEED_REOPEN, leave it for
     * the next W — do not reopen here.
     */
    if (entry_phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER
        || entry_phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN
        || entry_phase
            == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B) {
        ctx->expected_live = 0u;
        ctx->observed_live = 0u;
    }
    return NINLIL_OK;
}
