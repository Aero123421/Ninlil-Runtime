#include "domain_store_d3s4.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_store_scanner.h"

#include <limits.h>
#include <string.h>

/*
 * D3-S4 is a production-private, same-snapshot evaluator.  The scanner owns
 * the only transaction, iterator, 4096-byte value buffer, and cleanup tree;
 * this file owns only the closed modes 31..34 and their fixed 949-byte state.
 */

ninlil_status_t ninlil_domain_scan_reopen_zero_prefix_iter(
    ninlil_domain_scan_session_t *session);

void ninlil_domain_scan_d3s4_composition_init(
    ninlil_domain_scan_d3s4_composition_t *composition)
{
    if (composition != NULL) {
        (void)memset(composition, 0, sizeof(*composition));
    }
}

ninlil_status_t ninlil_domain_scan_d3s4_composition_add(
    ninlil_domain_scan_d3s4_composition_t *composition,
    ninlil_status_t finalize_status,
    uint8_t disposition_present,
    uint8_t disposition)
{
    uint8_t candidate;

    if (composition == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (composition->reserved_zero != 0u
        || composition->disposition_present > 1u
        || composition->disposition
            > NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED
        || (composition->disposition_present == 0u
            && composition->disposition != 0u)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (finalize_status != NINLIL_OK) {
        return NINLIL_OK;
    }
    if (disposition_present == 0u) {
        return NINLIL_OK;
    }
    if (disposition_present != 1u
        || disposition
            > NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (composition->accepted_input_count == UINT8_MAX) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }

    candidate = (uint8_t)(composition->disposition | disposition);
    composition->disposition_present = 1u;
    composition->disposition = candidate;
    composition->accepted_input_count =
        (uint8_t)(composition->accepted_input_count + 1u);
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_d3s4_composition_finish(
    const ninlil_domain_scan_d3s4_composition_t *composition,
    uint8_t *out_disposition_present,
    uint8_t *out_disposition)
{
    if (composition == NULL
        || out_disposition_present == NULL
        || out_disposition == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (composition->reserved_zero != 0u
        || composition->disposition_present > 1u
        || composition->disposition
            > NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED
        || (composition->disposition_present == 0u
            && composition->disposition != 0u)) {
        return NINLIL_E_INVALID_STATE;
    }
    *out_disposition_present = composition->disposition_present;
    *out_disposition = composition->disposition;
    return NINLIL_OK;
}

static int row_family_subtype(
    const uint8_t *key,
    uint32_t key_length,
    uint8_t *out_family,
    uint8_t *out_subtype);
static ninlil_status_t key_digest(
    const uint8_t *key,
    uint32_t key_length,
    uint8_t out[32]);
static ninlil_status_t on_row_mode31_32(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s4_context_t *context,
    uint32_t key_length,
    uint8_t family,
    uint8_t subtype,
    uint8_t typed_current_ok);
static ninlil_status_t on_row_mode33(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s4_context_t *context,
    uint32_t key_length,
    uint8_t family,
    uint8_t subtype,
    uint8_t typed_current_ok);

static ninlil_domain_scan_d3s4_context_t *context_of(
    ninlil_domain_scan_session_t *session)
{
    if (session == NULL
        || session->bound_d3_kind != NINLIL_DOMAIN_SCAN_D3_KIND_S4) {
        return NULL;
    }
    return session->bound_d3s4_context;
}

static uint16_t load_u16(const uint8_t in[2])
{
    return ninlil_model_domain_decode_u16_be(in);
}

static void store_u16(uint8_t out[2], uint16_t value)
{
    ninlil_model_domain_encode_u16_be(out, value);
}

static uint64_t load_u64(const uint8_t in[8])
{
    return ninlil_model_domain_decode_u64_be(in);
}

static void store_u64(uint8_t out[8], uint64_t value)
{
    ninlil_model_domain_encode_u64_be(out, value);
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    return n == 0u || memcmp(a, b, n) == 0;
}

static int digest_is_zero(const uint8_t digest[32])
{
    return ninlil_model_domain_digest_is_zero(digest);
}

static ninlil_status_t fail_corrupt(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    if (context != NULL) {
        context->group_class = NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT;
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
    }
    return ninlil_domain_scan_note_terminal_corrupt(session);
}

/*
 * The S4 drive contract publishes a finding by moving the bound session to
 * sticky FAILED, while the call that discovered it still returns OK.  The
 * sticky status is published by finalize; a later drive is INVALID_STATE.
 * This keeps the failure-point context observable and matches the accepted
 * per-call authority without performing cleanup in the discovering drive.
 */
static ninlil_status_t finish_drive_status(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    ninlil_status_t status)
{
    if (status != NINLIL_OK
        && session != NULL
        && context != NULL
        && session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED
        && session->has_sticky_primary != 0u
        && context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED) {
        return NINLIL_OK;
    }
    return status;
}

static void normalize_failed_context(
    const ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    if (session == NULL || context == NULL
        || session->state != NINLIL_DOMAIN_SCAN_STATE_FAILED
        || session->has_sticky_primary == 0u) {
        return;
    }
    context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
    if (session->sticky_primary == NINLIL_E_STORAGE_CORRUPT) {
        context->group_class = NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT;
    }
}

/*
 * REP1-L2 D3-S4 closes every walk at true exhaustion in the same API call.
 * The generic scanner deliberately keeps an exhausted iterator live for the
 * older D3 slices, so S4 owns this stricter boundary locally.
 */
static ninlil_status_t close_exhausted_iterator(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    if (session == NULL || context == NULL
        || session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        || session->txn_live == 0u
        || session->iter_live == 0u
        || session->iter == NULL
        || session->bound_storage == NULL
        || session->bound_storage->iter_close == NULL) {
        return fail_corrupt(session, context);
    }
    session->bound_storage->iter_close(
        session->bound_storage->user, session->iter);
    session->iter = NULL;
    session->iter_live = 0u;
    return NINLIL_OK;
}

static ninlil_status_t copy_key(
    uint8_t out[45], uint8_t *out_length,
    const uint8_t *key, uint32_t key_length)
{
    if (out == NULL || out_length == NULL || key == NULL
        || key_length < 10u
        || key_length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        if (out_length != NULL) {
            *out_length = 0u;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(out, 0, 45u);
    (void)memcpy(out, key, key_length);
    *out_length = (uint8_t)key_length;
    return NINLIL_OK;
}

static ninlil_status_t build_composite_key(
    uint8_t subtype,
    const uint8_t *components,
    uint32_t components_length,
    uint8_t out[45],
    uint8_t *out_length)
{
    ninlil_model_domain_digest_t identity;
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t view;
    ninlil_status_t status;

    if (components == NULL || components_length == 0u
        || out == NULL || out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    view.data = components;
    view.length = components_length;
    status = ninlil_model_domain_composite_digest(subtype, view, &identity);
    if (status != NINLIL_OK) {
        return status;
    }
    view.data = identity.bytes;
    view.length = 32u;
    status = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        view,
        &key);
    if (status != NINLIL_OK
        || key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return copy_key(out, out_length, key.bytes, key.length);
}

static ninlil_status_t build_complete_key(
    uint8_t subtype,
    uint8_t identity_kind,
    const uint8_t *identity_bytes,
    uint32_t identity_length,
    uint8_t out[45],
    uint8_t *out_length);

static ninlil_status_t build_witness_header_key(
    const uint8_t witness_digest[32],
    uint8_t out[45],
    uint8_t *out_length)
{
    /*
     * witness_digest is already the WITNESS_HEADER composite identity copied
     * from the header/chunk body.  It is not the raw operation preimage; do
     * not apply COMPOSITE(0x7f, ...) a second time.
     */
    return build_complete_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        witness_digest, 32u, out, out_length);
}

static ninlil_status_t build_witness_chunk_key(
    const uint8_t witness_digest[32],
    uint16_t chunk_index,
    uint8_t out[45],
    uint8_t *out_length)
{
    uint8_t components[34];

    (void)memcpy(components, witness_digest, 32u);
    ninlil_model_domain_encode_u16_be(&components[32], chunk_index);
    return build_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
        components, (uint32_t)sizeof(components), out, out_length);
}

static ninlil_status_t build_head_index_key(
    const uint8_t member_key_digest[32],
    uint8_t out[45],
    uint8_t *out_length)
{
    return build_composite_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
        member_key_digest, 32u, out, out_length);
}

static ninlil_status_t decode_envelope(
    ninlil_bytes_view_t value,
    ninlil_model_domain_envelope_t *out)
{
    ninlil_status_t status = ninlil_model_domain_decode_envelope(value, out);
    return status == NINLIL_OK ? NINLIL_OK : NINLIL_E_STORAGE_CORRUPT;
}

static ninlil_status_t decode_header_value(
    ninlil_bytes_view_t value,
    ninlil_model_domain_witness_header_t *out)
{
    ninlil_model_domain_envelope_t envelope;
    ninlil_status_t status;

    status = decode_envelope(value, &envelope);
    if (status != NINLIL_OK
        || envelope.record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN
        || envelope.header.subtype
            != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_domain_decode_witness_header(envelope.body, out);
    return status == NINLIL_OK ? NINLIL_OK : NINLIL_E_STORAGE_CORRUPT;
}

static ninlil_status_t decode_chunk_value(
    ninlil_bytes_view_t value,
    ninlil_model_domain_witness_chunk_t *out,
    ninlil_bytes_view_t *out_body)
{
    ninlil_model_domain_envelope_t envelope;
    ninlil_status_t status;

    status = decode_envelope(value, &envelope);
    if (status != NINLIL_OK
        || envelope.record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN
        || envelope.header.subtype
            != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_domain_decode_witness_chunk(envelope.body, out);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (out_body != NULL) {
        *out_body = envelope.body;
    }
    return NINLIL_OK;
}

static ninlil_status_t value_digest(
    ninlil_bytes_view_t value, uint8_t out[32])
{
    ninlil_model_domain_digest_t digest;
    ninlil_status_t status =
        ninlil_model_domain_value_digest(value, &digest);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(out, digest.bytes, 32u);
    return NINLIL_OK;
}

static void manifest_sha_store(
    ninlil_domain_scan_d3s4_context_t *context,
    const ninlil_model_domain_manifest_digest_ctx_t *sha)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        ninlil_model_domain_encode_u32_be(
            &context->sha_state[i * 4u], sha->sha.state[i]);
    }
    store_u64(context->sha_bitcount, sha->sha.bit_length);
    (void)memcpy(context->sha_block, sha->sha.buffer, 64u);
    context->sha_block_len = (uint8_t)sha->sha.buffer_length;
}

static ninlil_status_t manifest_sha_load(
    const ninlil_domain_scan_d3s4_context_t *context,
    ninlil_model_domain_manifest_digest_ctx_t *sha)
{
    uint32_t i;
    uint64_t bit_length;

    (void)memset(sha, 0, sizeof(*sha));
    for (i = 0u; i < 8u; ++i) {
        sha->sha.state[i] =
            ninlil_model_domain_decode_u32_be(&context->sha_state[i * 4u]);
    }
    bit_length = load_u64(context->sha_bitcount);
    sha->sha.bit_length = bit_length;
    (void)memcpy(sha->sha.buffer, context->sha_block, 64u);
    sha->sha.buffer_length = context->sha_block_len;
    /*
     * The domain-separated preimage is 25 bytes.  Each accepted chunk body
     * increments this derived count; no hidden counter is retained.
     */
    /*
     * The portable SHA implementation counts only bytes already compressed
     * into complete 64-byte blocks in bit_length; the current partial block
     * lives in buffer/buffer_length.  Immediately after manifest init the
     * 25-byte domain separator is therefore represented as bit_length == 0
     * and buffer_length == 25.  Validate the complete logical prefix rather
     * than rejecting that canonical state.
     */
    if ((bit_length & 511u) != 0u
        || (bit_length / 8u) + sha->sha.buffer_length < 25u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    sha->chunk_bodies_seen = (uint32_t)context->arm_cursor;
    return NINLIL_OK;
}

static ninlil_status_t manifest_sha_init(
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_model_domain_manifest_digest_ctx_t sha;
    ninlil_status_t status =
        ninlil_model_domain_manifest_digest_init(&sha);
    if (status != NINLIL_OK) {
        return status;
    }
    manifest_sha_store(context, &sha);
    return NINLIL_OK;
}

/*
 * S4 does not have a dedicated "chunks seen" slot.  The SHA state is valid
 * because callers feed exactly when ordinal%8==0 and prove ordinal M at close.
 * The model helper's count guard is reconstructed transiently for each update.
 */
static ninlil_status_t manifest_sha_update(
    ninlil_domain_scan_d3s4_context_t *context,
    ninlil_bytes_view_t chunk_body,
    uint16_t chunk_ordinal)
{
    ninlil_model_domain_manifest_digest_ctx_t sha;
    ninlil_status_t status;

    status = manifest_sha_load(context, &sha);
    if (status != NINLIL_OK) {
        return status;
    }
    sha.chunk_bodies_seen = chunk_ordinal;
    status = ninlil_model_domain_manifest_digest_update(&sha, chunk_body);
    if (status != NINLIL_OK) {
        return status;
    }
    manifest_sha_store(context, &sha);
    return NINLIL_OK;
}

static ninlil_status_t manifest_sha_final(
    ninlil_domain_scan_d3s4_context_t *context,
    uint16_t chunk_count,
    uint8_t out[32])
{
    ninlil_model_domain_manifest_digest_ctx_t sha;
    ninlil_model_domain_digest_t digest;
    ninlil_status_t status;

    status = manifest_sha_load(context, &sha);
    if (status != NINLIL_OK) {
        return status;
    }
    sha.chunk_bodies_seen = chunk_count;
    status = ninlil_model_domain_manifest_digest_final(&sha, &digest);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memcpy(out, digest.bytes, 32u);
    return NINLIL_OK;
}

uint8_t ninlil_domain_scan_d3s4_required_count_mask(uint8_t focus_mode)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS:
        return NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE31;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS:
        return NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE32;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK:
        return NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE34;
    default:
        return 0u;
    }
}

uint8_t ninlil_domain_scan_d3s4_required_binding_mask(uint8_t focus_mode)
{
    switch (focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND:
        return NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE33;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK:
        return (uint8_t)(NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_A
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_B
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_C
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_ALL);
    default:
        return 0u;
    }
}

static int context_closed_shape(
    const ninlil_domain_scan_d3s4_context_t *context)
{
    if (context == NULL
        || context->focus_mode < NINLIL_DOMAIN_SCAN_D3S4_MODE_MIN
        || context->focus_mode > NINLIL_DOMAIN_SCAN_D3S4_MODE_MAX
        || context->phase > NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
        || context->pass_kind > NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL
        || context->group_class > NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT
        || context->member_substep > 3u
        || context->membership_substep > 1u
        || context->membership_need_mask > 3u
        || context->found_count_a > 2u
        || context->found_count_b > 2u
        || context->entry_action > NINLIL_MODEL_DOMAIN_WITNESS_ACTION_SUPERSEDE
        || context->entry_old_present > 1u
        || context->entry_new_present > 1u
        || context->sha_block_len > 63u) {
        return 0;
    }
    if (context->focus_mode <= NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS
        && context->arm_cursor != 0u) {
        return 0;
    }
    if (context->focus_mode == NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND
        && context->arm_cursor > 1u) {
        return 0;
    }
    if (context->focus_mode == NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK
        && context->arm_cursor > 6u) {
        return 0;
    }
    return 1;
}

ninlil_status_t ninlil_domain_scan_d3s4_ready_disposition(
    const ninlil_domain_scan_d3s4_context_t *context,
    uint8_t *out_disposition)
{
    uint8_t required_count;
    uint8_t required_binding;
    uint8_t deferred_s5;
    uint8_t deferred_s6;

    if (context == NULL || out_disposition == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!context_closed_shape(context)
        || context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE
        || context->pass_kind != NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL
        || (context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_BASELINE_DONE) == 0u
        || (context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    required_count =
        ninlil_domain_scan_d3s4_required_count_mask(context->focus_mode);
    required_binding =
        ninlil_domain_scan_d3s4_required_binding_mask(context->focus_mode);
    if (context->count_complete_mask != required_count
        || (context->binding_complete_mask
                & (uint8_t)~NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED)
            != required_binding) {
        return NINLIL_E_INVALID_STATE;
    }
    deferred_s5 =
        (context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN)
            != 0u;
    deferred_s6 =
        (context->binding_complete_mask
            & NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED)
            != 0u;
    if ((context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_COMPLETE_READY) != 0u
        && (deferred_s5 != 0u || deferred_s6 != 0u)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (context->focus_mode == NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS
        && deferred_s5 != deferred_s6) {
        return NINLIL_E_INVALID_STATE;
    }
    if (context->focus_mode == NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS
        && deferred_s5 == 0u && load_u16(context->streamed_members) != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    if (context->focus_mode == NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND
        && deferred_s5 != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    if (context->focus_mode == NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK
        && (deferred_s5 != 0u || deferred_s6 != 0u)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (deferred_s5 != 0u && deferred_s6 != 0u) {
        *out_disposition =
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED;
    } else if (deferred_s5 != 0u) {
        *out_disposition =
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_REQUIRED;
    } else if (deferred_s6 != 0u) {
        *out_disposition =
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S6_REQUIRED;
    } else {
        if ((context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_COMPLETE_READY)
            == 0u) {
            return NINLIL_E_INVALID_STATE;
        }
        *out_disposition =
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_LOCAL_COMPLETE;
    }
    return NINLIL_OK;
}

static ninlil_status_t build_complete_key(
    uint8_t subtype,
    uint8_t identity_kind,
    const uint8_t *identity_bytes,
    uint32_t identity_length,
    uint8_t out[45],
    uint8_t *out_length)
{
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t identity;
    ninlil_status_t status;

    if (identity_bytes == NULL || identity_length == 0u
        || out == NULL || out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    identity.data = identity_bytes;
    identity.length = identity_length;
    status = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype, identity_kind, identity, &key);
    if (status != NINLIL_OK
        || key.length == 0u
        || key.length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return copy_key(out, out_length, key.bytes, key.length);
}

static ninlil_status_t build_raw16_primary_key(
    uint8_t subtype,
    const uint8_t *raw,
    uint16_t raw_length,
    uint8_t out[45],
    uint8_t *out_length)
{
    uint8_t components[2u + NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_RAW_CAPACITY];

    if (raw == NULL || raw_length == 0u
        || raw_length > NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_RAW_CAPACITY) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    store_u16(components, raw_length);
    (void)memcpy(&components[2], raw, raw_length);
    return build_composite_key(
        subtype, components, (uint32_t)raw_length + 2u,
        out, out_length);
}

static ninlil_status_t build_anchor_primary_key(
    const uint8_t transaction_id[16],
    uint8_t out[45],
    uint8_t *out_length)
{
    return build_complete_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        transaction_id, 16u, out, out_length);
}

static ninlil_status_t build_ingress_primary_key(
    const uint8_t ordered_sequence[8],
    uint8_t out[45],
    uint8_t *out_length)
{
    return build_complete_key(
        NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
        NINLIL_MODEL_DOMAIN_ID_KIND_U64,
        ordered_sequence, 8u, out, out_length);
}

static int parse_callback_owner(
    const uint8_t *owner_raw,
    uint16_t owner_raw_length,
    const uint8_t **out_delivery_raw)
{
    uint16_t delivery_length;

    if (owner_raw == NULL || out_delivery_raw == NULL
        || owner_raw_length < 2u + 8u) {
        return 0;
    }
    delivery_length = load_u16(owner_raw);
    if (delivery_length
            != NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
        || (uint32_t)owner_raw_length
            != 2u + (uint32_t)delivery_length + 8u) {
        return 0;
    }
    *out_delivery_raw = &owner_raw[2];
    return 1;
}

static ninlil_status_t pin_primary_raw(
    ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *raw,
    uint16_t raw_length)
{
    if (raw == NULL || raw_length == 0u
        || raw_length > NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_RAW_CAPACITY) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(
        context->expected_primary_raw, 0,
        sizeof(context->expected_primary_raw));
    (void)memcpy(context->expected_primary_raw, raw, raw_length);
    store_u16(context->expected_primary_raw_len, raw_length);
    return NINLIL_OK;
}

static ninlil_status_t pin_primary_raw2(
    ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *raw,
    uint16_t raw_length)
{
    if ((raw_length != 0u && raw == NULL)
        || raw_length > NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_RAW2_CAPACITY) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(
        context->expected_primary_raw2, 0,
        sizeof(context->expected_primary_raw2));
    if (raw_length != 0u) {
        (void)memcpy(context->expected_primary_raw2, raw, raw_length);
    }
    context->expected_primary_raw2_len = (uint8_t)raw_length;
    return NINLIL_OK;
}

static ninlil_status_t pin_primary_aux(
    ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *raw,
    uint16_t raw_length)
{
    if ((raw_length != 0u && raw == NULL)
        || raw_length > NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_AUX_CAPACITY) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(
        context->expected_primary_aux, 0,
        sizeof(context->expected_primary_aux));
    if (raw_length != 0u) {
        (void)memcpy(context->expected_primary_aux, raw, raw_length);
    }
    context->expected_primary_aux_len = (uint8_t)raw_length;
    return NINLIL_OK;
}

/*
 * entry_flags is phase-disjoint primary-normalization state, not a direct
 * copy of every source record's owner enum.  Keep the fixed S4 context in the
 * closed 0..3 alias domain and recover the owner semantics from
 * (source_subtype, alias).  Reservation DELIVERY/CALLBACK intentionally share
 * alias 1 because both normalize to the same 80-byte DELIVERY identity.
 */
static uint8_t primary_owner_alias(
    uint8_t source_subtype,
    uint8_t owner_kind)
{
    switch (source_subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
        switch (owner_kind) {
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE:
            return 0u;
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY:
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK:
            return 1u;
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION:
            return 2u;
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS:
            return 3u;
        default:
            return 0xffu;
        }
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        return 2u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        return 0u;
    default:
        return owner_kind <= 3u ? owner_kind : 0xffu;
    }
}

static uint8_t primary_owner_kind_from_alias(
    uint8_t source_subtype,
    uint8_t alias)
{
    if (source_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION) {
        switch (alias) {
        case 0u:
            return NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE;
        case 1u:
            return NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY;
        case 2u:
            return NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION;
        case 3u:
            return NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS;
        default:
            return 0xffu;
        }
    }
    return alias;
}

static ninlil_status_t build_primary_key_from_pins(
    ninlil_domain_scan_d3s4_context_t *context)
{
    const uint8_t subtype = context->entry_record_role[1];
    const uint8_t owner_kind = primary_owner_kind_from_alias(
        subtype, context->entry_flags);
    const uint8_t *raw = context->expected_primary_raw;
    const uint16_t raw_length =
        load_u16(context->expected_primary_raw_len);
    const uint8_t *delivery_raw = NULL;

    switch (subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
        return build_raw16_primary_key(
            NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
            raw, raw_length, context->peer_key, &context->peer_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
        switch (owner_kind) {
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE:
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION:
            if (raw_length != 16u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS:
            if (raw_length != 8u || load_u64(raw) == 0u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return build_ingress_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY:
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        case NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK:
            if (!parse_callback_owner(raw, raw_length, &delivery_raw)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                delivery_raw,
                NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES,
                context->peer_key, &context->peer_key_len);
        default:
            return NINLIL_E_STORAGE_CORRUPT;
        }
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
        if (context->expected_primary_aux_len != 16u
            || context->expected_primary_raw2_len == 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return build_anchor_primary_key(
            context->expected_primary_aux,
            context->peer_key, &context->peer_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        if (raw_length != 16u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return build_anchor_primary_key(
            raw, context->peer_key, &context->peer_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION) {
            if (raw_length != 16u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY) {
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS
            && raw_length == 8u && load_u64(raw) != 0u) {
            return build_ingress_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
        if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
            && raw_length == 16u) {
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY) {
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
        if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION
            && raw_length == 16u) {
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY) {
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
        if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
            && raw_length == 16u) {
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY) {
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        return build_raw16_primary_key(
            NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
            raw, raw_length, context->peer_key, &context->peer_key_len);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        if (owner_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION
            && raw_length == 16u) {
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY) {
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB:
        if (owner_kind == 0u) {
            uint8_t components[33];
            if (raw_length != 32u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            components[0] = NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST;
            (void)memcpy(&components[1], raw, 32u);
            return build_composite_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB,
                components, (uint32_t)sizeof(components),
                context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION
            && raw_length == 16u) {
            return build_anchor_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS
            && raw_length == 8u && load_u64(raw) != 0u) {
            return build_ingress_primary_key(
                raw, context->peer_key, &context->peer_key_len);
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY) {
            return build_raw16_primary_key(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                raw, raw_length,
                context->peer_key, &context->peer_key_len);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    default:
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static ninlil_status_t prepare_primary_proof(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *member_key,
    uint32_t member_key_length,
    ninlil_bytes_view_t member_value)
{
    ninlil_domain_scan_workspace_t *workspace;
    ninlil_model_domain_typed_record_t *typed;
    ninlil_bytes_view_t key_view;
    uint8_t expected_family = context->entry_record_role[0];
    uint8_t expected_subtype = context->entry_record_role[1];
    uint8_t owner_kind = 0u;
    ninlil_status_t status;

    if (session == NULL || context == NULL || member_key == NULL
        || member_key_length < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES
        || member_key_length > NINLIL_MODEL_DOMAIN_KEY_MAX_CURRENT_BYTES
        || member_value.data == NULL || member_value.length == 0u
        || session->bound_workspace == NULL) {
        return fail_corrupt(session, context);
    }
    workspace = session->bound_workspace;
    typed = &workspace->row_validate_scratch.typed;
    key_view.data = member_key;
    key_view.length = member_key_length;
    status = ninlil_model_domain_validate_typed_record(
        key_view, member_value, typed);
    if (status != NINLIL_OK
        || typed->family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || typed->subtype != member_key[9]
        || (expected_family != 0u
            && (expected_family != typed->family
                || expected_subtype != typed->subtype))
        || digest_is_zero(
            typed->envelope.header.primary_value_digest)) {
        return fail_corrupt(session, context);
    }

    (void)memset(context->expected_primary_pvd, 0, 32u);
    (void)memset(
        context->expected_primary_raw, 0,
        sizeof(context->expected_primary_raw));
    (void)memset(
        context->expected_primary_raw2, 0,
        sizeof(context->expected_primary_raw2));
    (void)memset(
        context->expected_primary_aux, 0,
        sizeof(context->expected_primary_aux));
    store_u16(context->expected_primary_raw_len, 0u);
    context->expected_primary_raw2_len = 0u;
    context->expected_primary_aux_len = 0u;

    switch (typed->subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
        status = pin_primary_raw(
            context, typed->service_quota.service_key_raw,
            typed->service_quota.service_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION: {
        owner_kind = (uint8_t)typed->reservation.owner_kind;
        if (owner_kind
            == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK) {
            const uint8_t *delivery_raw = NULL;
            if (!parse_callback_owner(
                    typed->reservation.owner_key_raw,
                    typed->reservation.owner_key_raw_length,
                    &delivery_raw)) {
                status = NINLIL_E_STORAGE_CORRUPT;
            } else {
                status = pin_primary_raw(
                    context, delivery_raw,
                    NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES);
            }
        } else {
            status = pin_primary_raw(
                context, typed->reservation.owner_key_raw,
                typed->reservation.owner_key_raw_length);
        }
        break;
    }
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
        status = pin_primary_raw(
            context, typed->transaction_sequence_index.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
        status = pin_primary_raw(
            context, typed->transaction_state.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
        status = pin_primary_raw(
            context, typed->idempotency_map.scope_raw,
            typed->idempotency_map.scope_raw_length);
        if (status == NINLIL_OK) {
            status = pin_primary_raw2(
                context, typed->idempotency_map.idempotency_key,
                typed->idempotency_map.idempotency_key_length);
        }
        if (status == NINLIL_OK) {
            status = pin_primary_aux(
                context, typed->idempotency_map.transaction_id, 16u);
        }
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
        status = pin_primary_raw(
            context, typed->event_id_map.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        owner_kind = (uint8_t)typed->scheduler_owner.owner_kind;
        status = pin_primary_raw(
            context, typed->scheduler_owner.subject_key_raw,
            typed->scheduler_owner.subject_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB:
        if (typed->envelope.header.flags
            == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST) {
            owner_kind = (uint8_t)typed->blob_manifest.blob_owner_kind;
            status = pin_primary_raw(
                context, typed->blob_manifest.owner_key_raw,
                typed->blob_manifest.owner_key_raw_length);
        } else if (typed->envelope.header.flags
            == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK) {
            owner_kind = 0u;
            status = pin_primary_raw(
                context, typed->blob_chunk.blob_id_digest, 32u);
        } else {
            status = NINLIL_E_STORAGE_CORRUPT;
        }
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
        owner_kind = (uint8_t)typed->attempt.attempt_owner_kind;
        status = pin_primary_raw(
            context, typed->attempt.owner_key_raw,
            typed->attempt.owner_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        status = pin_primary_raw(
            context, typed->attempt_id_index.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
        owner_kind = (uint8_t)typed->cancel_state.cancel_owner_kind;
        status = pin_primary_raw(
            context, typed->cancel_state.owner_key_raw,
            typed->cancel_state.owner_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
        owner_kind = (uint8_t)typed->evidence_cell.evidence_owner_kind;
        status = pin_primary_raw(
            context, typed->evidence_cell.owner_key_raw,
            typed->evidence_cell.owner_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
        status = pin_primary_raw(
            context, typed->result_cache.delivery_key_raw,
            typed->result_cache.delivery_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        status = pin_primary_raw(
            context, typed->reverse_reply.delivery_key_raw,
            typed->reverse_reply.delivery_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
        status = pin_primary_raw(
            context, typed->event_spool.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
        status = pin_primary_raw(
            context, typed->retry_summary.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
        status = pin_primary_raw(
            context, typed->management_ledger.transaction_id, 16u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
        owner_kind = (uint8_t)typed->retention_basis.subject_kind;
        status = pin_primary_raw(
            context, typed->retention_basis.subject_key_raw,
            typed->retention_basis.subject_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        owner_kind = (uint8_t)typed->cleanup_plan.subject_kind;
        status = pin_primary_raw(
            context, typed->cleanup_plan.subject_key_raw,
            typed->cleanup_plan.subject_key_raw_length);
        break;
    default:
        status = NINLIL_E_STORAGE_CORRUPT;
        break;
    }
    if (status != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    context->entry_record_role[0] = typed->family;
    context->entry_record_role[1] = typed->subtype;
    context->entry_flags =
        primary_owner_alias(typed->subtype, owner_kind);
    if (context->entry_flags == 0xffu) {
        return fail_corrupt(session, context);
    }
    (void)memcpy(
        context->expected_primary_pvd,
        typed->envelope.header.primary_value_digest, 32u);
    (void)memset(context->peer_key, 0, sizeof(context->peer_key));
    context->peer_key_len = 0u;
    status = build_primary_key_from_pins(context);
    if (status != NINLIL_OK || context->peer_key_len == 0u) {
        return fail_corrupt(session, context);
    }
    return NINLIL_OK;
}

static uint8_t expected_primary_subtype(
    const ninlil_domain_scan_d3s4_context_t *context)
{
    const uint8_t source_subtype = context->entry_record_role[1];
    const uint8_t owner_kind = primary_owner_kind_from_alias(
        source_subtype, context->entry_flags);

    switch (source_subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION:
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY
            || owner_kind == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER:
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT:
        return owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION
            ? NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
            : (owner_kind == NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY
                ? NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY : 0u);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CANCEL_STATE:
        return owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_TRANSACTION
            ? NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
            : (owner_kind == NINLIL_MODEL_DOMAIN_CANCEL_OWNER_DELIVERY
                ? NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY : 0u);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL:
        return owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
            ? NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
            : (owner_kind == NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_DELIVERY
                ? NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY : 0u);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETENTION_BASIS:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_CLEANUP_PLAN:
        return owner_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_TRANSACTION
            ? NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR
            : (owner_kind == NINLIL_MODEL_DOMAIN_RETENTION_SUBJECT_DELIVERY
                ? NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY : 0u);
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RESULT_CACHE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB:
        if (owner_kind == 0u) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS;
        }
        if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY) {
            return NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY;
        }
        return 0u;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_STATE:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_SPOOL:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_RETRY_SUMMARY:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_MANAGEMENT_LEDGER:
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_ID_INDEX:
        return NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR;
    default:
        return 0u;
    }
}

static int expected_raw_equals(
    const ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *raw,
    uint16_t raw_length)
{
    return raw != NULL
        && raw_length == load_u16(context->expected_primary_raw_len)
        && bytes_equal(
            raw, context->expected_primary_raw, raw_length);
}

static ninlil_status_t verify_primary_proof(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    ninlil_bytes_view_t primary_value)
{
    ninlil_model_domain_typed_record_t *typed;
    ninlil_bytes_view_t primary_key;
    const uint8_t source_subtype = context->entry_record_role[1];
    const uint8_t owner_kind = primary_owner_kind_from_alias(
        source_subtype, context->entry_flags);
    const uint8_t expected_subtype = expected_primary_subtype(context);
    const uint8_t *expected_delivery_raw = NULL;
    uint8_t digest[32];
    uint8_t sequence[8];
    int tuple_matches = 0;
    ninlil_status_t status;

    if (session == NULL || context == NULL
        || session->bound_workspace == NULL
        || context->entry_record_role[0]
            != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || expected_subtype == 0u
        || context->peer_key_len == 0u
        || load_u16(context->expected_primary_raw_len) == 0u) {
        return fail_corrupt(session, context);
    }
    primary_key.data = context->peer_key;
    primary_key.length = context->peer_key_len;
    typed = &session->bound_workspace->row_validate_scratch.typed;
    status = ninlil_model_domain_validate_typed_record(
        primary_key, primary_value, typed);
    if (status != NINLIL_OK
        || typed->family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || typed->subtype != expected_subtype) {
        return fail_corrupt(session, context);
    }

    switch (expected_subtype) {
    case NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE:
        tuple_matches = expected_raw_equals(
            context, typed->service.service_key_raw,
            typed->service.service_key_raw_length);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR:
        if (source_subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP) {
            tuple_matches =
                context->expected_primary_aux_len == 16u
                && bytes_equal(
                    typed->transaction_anchor.transaction_id,
                    context->expected_primary_aux, 16u)
                && typed->transaction_anchor.idempotency_scope_raw_length
                    == load_u16(context->expected_primary_raw_len)
                && bytes_equal(
                    typed->transaction_anchor.idempotency_scope_raw,
                    context->expected_primary_raw,
                    typed->transaction_anchor.idempotency_scope_raw_length)
                && typed->transaction_anchor.idempotency_key_length
                    == context->expected_primary_raw2_len
                && bytes_equal(
                    typed->transaction_anchor.idempotency_key,
                    context->expected_primary_raw2,
                    typed->transaction_anchor.idempotency_key_length);
        } else {
            tuple_matches = expected_raw_equals(
                context, typed->transaction_anchor.transaction_id, 16u);
        }
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS:
        store_u64(sequence, typed->ordered_ingress.ordered_sequence);
        tuple_matches = expected_raw_equals(context, sequence, 8u);
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY:
        if (source_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION
            && owner_kind
                == NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK) {
            tuple_matches = parse_callback_owner(
                    context->expected_primary_raw,
                    load_u16(context->expected_primary_raw_len),
                    &expected_delivery_raw)
                && typed->delivery.delivery_key_raw_length
                    == NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES
                && bytes_equal(
                    typed->delivery.delivery_key_raw,
                    expected_delivery_raw,
                    NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES);
        } else {
            tuple_matches = expected_raw_equals(
                context, typed->delivery.delivery_key_raw,
                typed->delivery.delivery_key_raw_length);
        }
        break;
    case NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB:
        tuple_matches =
            source_subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB
            && owner_kind == 0u
            && typed->envelope.header.flags
                == NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST
            && expected_raw_equals(
                context, typed->blob_manifest.blob_id_digest, 32u);
        break;
    default:
        tuple_matches = 0;
        break;
    }
    if (!tuple_matches
        || value_digest(primary_value, digest) != NINLIL_OK
        || !bytes_equal(
            digest, context->expected_primary_pvd, 32u)) {
        return fail_corrupt(session, context);
    }
    return NINLIL_OK;
}

static int quota_valid(uint16_t quota)
{
    return quota >= 1u && quota <= 256u;
}

static ninlil_status_t install_quota(
    ninlil_domain_scan_d3s4_context_t *context, uint16_t quota)
{
    uint16_t installed;

    if (!quota_valid(quota)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    installed = load_u16(context->drive_get_quota);
    if (installed == 0u) {
        store_u16(context->drive_get_quota, quota);
    } else if (installed != quota) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (load_u16(context->drive_gets_used) > quota) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static int quota_exhausted(
    const ninlil_domain_scan_d3s4_context_t *context)
{
    return load_u16(context->drive_gets_used)
        >= load_u16(context->drive_get_quota);
}

static void mark_yield(ninlil_domain_scan_d3s4_context_t *context)
{
    context->flags = (uint8_t)(context->flags
        | NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME
        | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE);
}

static ninlil_status_t exact_get_counted(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *key,
    uint8_t key_length,
    ninlil_domain_scan_exact_get_result_t *out)
{
    ninlil_bytes_view_t view;
    ninlil_status_t status;
    uint16_t used;

    if (quota_exhausted(context)) {
        mark_yield(context);
        return NINLIL_E_WOULD_BLOCK;
    }
    view.data = key;
    view.length = key_length;
    status = ninlil_domain_scan_exact_get(session, view, out);
    used = load_u16(context->drive_gets_used);
    if (used == UINT16_MAX) {
        return fail_corrupt(session, context);
    }
    store_u16(context->drive_gets_used, (uint16_t)(used + 1u));
    context->flags =
        (uint8_t)(context->flags | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE);
    if (status != NINLIL_OK) {
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
    }
    return status;
}

static ninlil_status_t reopen_if_exhausted(
    ninlil_domain_scan_session_t *session)
{
    if (session->state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        return NINLIL_OK;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        return NINLIL_E_INVALID_STATE;
    }
    return ninlil_domain_scan_reopen_zero_prefix_iter(session);
}

static void complete_mode(
    ninlil_domain_scan_d3s4_context_t *context)
{
    context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE;
    if ((context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN)
            == 0u
        && (context->binding_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED)
            == 0u) {
        context->flags = (uint8_t)(context->flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_COMPLETE_READY);
    } else {
        context->flags = (uint8_t)(context->flags
            & (uint8_t)~NINLIL_DOMAIN_SCAN_D3S4_FLAG_COMPLETE_READY);
    }
}

static ninlil_status_t drive_mode31_32(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context);
static ninlil_status_t drive_mode33(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context);
static ninlil_status_t drive_mode34(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context);

ninlil_status_t ninlil_domain_scan_d3s4_resume(
    ninlil_domain_scan_session_t *session,
    uint16_t quota)
{
    ninlil_domain_scan_d3s4_context_t *context = context_of(session);

    if (context == NULL) {
        return session == NULL
            ? NINLIL_E_INVALID_ARGUMENT : NINLIL_E_INVALID_STATE;
    }
    if (!quota_valid(quota)
        || context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE
        || context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
        || session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED
        || (context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) == 0u
        || (context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE) == 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    store_u16(context->drive_get_quota, quota);
    store_u16(context->drive_gets_used, 0u);
    context->flags = (uint8_t)(context->flags
        & (uint8_t)~(NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE));
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_d3s4_drive(
    ninlil_domain_scan_session_t *session,
    uint16_t quota)
{
    ninlil_domain_scan_d3s4_context_t *context;
    ninlil_status_t status;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    context = context_of(session);
    if (context == NULL) {
        return NINLIL_E_INVALID_STATE;
    }
    if (!context_closed_shape(context)) {
        return fail_corrupt(session, context);
    }
    if (session->has_sticky_primary != 0u
        || session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED
        || context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED) {
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
        return NINLIL_E_INVALID_STATE;
    }
    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE) {
        return NINLIL_E_INVALID_STATE;
    }
    if ((context->flags & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    status = install_quota(context, quota);
    if (status != NINLIL_OK) {
        if (status == NINLIL_E_STORAGE_CORRUPT) {
            return fail_corrupt(session, context);
        }
        return status;
    }

    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_BASELINE) {
        if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            return NINLIL_E_INVALID_STATE;
        }
        status = ninlil_domain_scan_advance(session, UINT32_MAX);
        if (status != NINLIL_OK) {
            normalize_failed_context(session, context);
            return finish_drive_status(session, context, status);
        }
        if (session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
            return NINLIL_E_INVALID_STATE;
        }
        status = close_exhausted_iterator(session, context);
        if (status != NINLIL_OK) {
            normalize_failed_context(session, context);
            return finish_drive_status(session, context, status);
        }
        context->flags = (uint8_t)(context->flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_BASELINE_DONE);
        if (session->profile_mismatch != 0u
            || session->future_profile_candidate != 0u) {
            return NINLIL_OK;
        }
        session->profile_exact_active = 1u;
        context->pass_kind = NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL;
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT;
        return NINLIL_OK;
    }
    switch (context->focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS:
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS:
        status = drive_mode31_32(session, context);
        break;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND:
        status = drive_mode33(session, context);
        break;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK:
        status = drive_mode34(session, context);
        break;
    default:
        status = fail_corrupt(session, context);
        break;
    }
    /*
     * D2 structural rejection inside an INTERNAL iterator can fail the bound
     * scanner before the mode hook gets a chance to normalize its context.
     * Preserve the accepted discovering-call contract: every sticky terminal
     * failure leaves the S4 context in FAILED, then finish_drive_status()
     * returns OK while finalize publishes the sticky primary.
     */
    if (status != NINLIL_OK
        && session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED
        && session->has_sticky_primary != 0u) {
        normalize_failed_context(session, context);
    }
    return finish_drive_status(session, context, status);
}

static ninlil_status_t on_row_mode34(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s4_context_t *context,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t family,
    uint8_t subtype,
    uint8_t typed_current_ok)
{
    ninlil_bytes_view_t value;
    ninlil_model_domain_typed_record_t *typed;
    const ninlil_model_domain_body_witness_head_index_t *index;
    ninlil_status_t status;

    if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM
        || context->arm_cursor != 0u) {
        return fail_corrupt(session, context);
    }
    value.data = workspace->value;
    value.length = value_length;
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX) {
        if (typed_current_ok == 0u) {
            return fail_corrupt(session, context);
        }
        typed = &workspace->row_validate_scratch.typed;
        index = &typed->witness_head_index;
        if (copy_key(
                context->last_carrier_key,
                &context->last_carrier_key_len,
                workspace->key, key_length)
                != NINLIL_OK
            || copy_key(
                context->membership_key_a,
                &context->membership_key_a_len,
                index->member_key_bytes,
                index->member_key_length)
                != NINLIL_OK
            || value_digest(value, context->pin_digest_b)
                != NINLIL_OK) {
            return fail_corrupt(session, context);
        }
        (void)memcpy(
            context->focus_key_digest,
            index->member_key_digest, 32u);
        (void)memcpy(
            context->entry_new_value_digest,
            index->member_value_digest, 32u);
        (void)memcpy(
            context->witness_digest,
            index->member_head_witness_digest, 32u);
        context->entry_flags = (uint8_t)index->index_state;
        if (build_head_index_key(
                context->focus_key_digest,
                context->peer_key, &context->peer_key_len)
                != NINLIL_OK
            || context->peer_key_len != key_length
            || !bytes_equal(
                context->peer_key, workspace->key, key_length)) {
            return fail_corrupt(session, context);
        }
        context->arm_cursor = 2u;
        context->flags = (uint8_t)(context->flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE);
        return NINLIL_OK;
    }
    if (family == 3u || family == 4u) {
        if (copy_key(
                context->last_carrier_key,
                &context->last_carrier_key_len,
                workspace->key, key_length)
                != NINLIL_OK
            || copy_key(
                context->membership_key_a,
                &context->membership_key_a_len,
                workspace->key, key_length)
                != NINLIL_OK
            || value_digest(value, context->pin_digest_a)
                != NINLIL_OK
            || key_digest(
                workspace->key, key_length,
                context->focus_key_digest)
                != NINLIL_OK
            || build_head_index_key(
                context->focus_key_digest,
                context->peer_key, &context->peer_key_len)
                != NINLIL_OK) {
            return fail_corrupt(session, context);
        }
        context->arm_cursor = 3u;
        context->flags = (uint8_t)(context->flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE);
        return NINLIL_OK;
    }
    if ((family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
            || family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN)
        && !(family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
            && (subtype
                    == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
                || subtype
                    == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK
                || subtype
                    == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER))) {
        ninlil_model_domain_envelope_t envelope;

        if (typed_current_ok == 0u
            || decode_envelope(value, &envelope) != NINLIL_OK) {
            return fail_corrupt(session, context);
        }
        if (digest_is_zero(envelope.header.head_witness_digest)) {
            return NINLIL_OK;
        }
        if (copy_key(
                context->last_carrier_key,
                &context->last_carrier_key_len,
                workspace->key, key_length)
                != NINLIL_OK
            || copy_key(
                context->membership_key_a,
                &context->membership_key_a_len,
                workspace->key, key_length)
                != NINLIL_OK
            || value_digest(value, context->pin_digest_a)
                != NINLIL_OK) {
            return fail_corrupt(session, context);
        }
        (void)memcpy(
            context->witness_digest,
            envelope.header.head_witness_digest, 32u);
        if (!digest_is_zero(envelope.header.primary_value_digest)) {
            status = prepare_primary_proof(
                session, context,
                workspace->key, key_length, value);
            if (status != NINLIL_OK) {
                return status;
            }
            context->arm_cursor = 1u;
        } else {
            context->peer_key_len = 0u;
            context->arm_cursor = 4u;
        }
        context->flags = (uint8_t)(context->flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE);
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_d3s4_on_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok)
{
    ninlil_domain_scan_d3s4_context_t *context = context_of(session);
    uint8_t family;
    uint8_t subtype;

    if (context == NULL || workspace == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!row_family_subtype(
            workspace->key, key_length, &family, &subtype)) {
        return fail_corrupt(session, context);
    }
    switch (context->focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS:
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS:
        return on_row_mode31_32(
            session, workspace, context, key_length,
            family, subtype, typed_current_ok);
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND:
        return on_row_mode33(
            session, workspace, context, key_length,
            family, subtype, typed_current_ok);
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK:
        return on_row_mode34(
            session, workspace, context, key_length, value_length,
            family, subtype, typed_current_ok);
    default:
        return fail_corrupt(session, context);
    }
}

ninlil_status_t ninlil_domain_scan_d3s4_on_exhausted(
    ninlil_domain_scan_session_t *session)
{
    ninlil_domain_scan_d3s4_context_t *context = context_of(session);
    ninlil_status_t status;

    if (context == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = close_exhausted_iterator(session, context);
    if (status != NINLIL_OK) {
        return status;
    }
    switch (context->focus_mode) {
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS:
        if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT) {
            return fail_corrupt(session, context);
        }
        context->count_complete_mask =
            NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE31;
        complete_mode(context);
        return NINLIL_OK;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS:
        if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT) {
            return fail_corrupt(session, context);
        }
        context->count_complete_mask =
            NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE32;
        complete_mode(context);
        return NINLIL_OK;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND:
        if (context->phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE33_BIND
            || context->arm_cursor > 1u) {
            return fail_corrupt(session, context);
        }
        if (context->arm_cursor == 0u) {
            context->arm_cursor = 1u;
            store_u16(context->streamed_members, 0u);
            context->found_count_b = 0u;
            /* Mode33 owns an atomic sequential-subpass boundary: close the
             * exhausted inventory iterator above and reopen the sole
             * zero-prefix chunk-bind iterator in this same API call. */
            status = reopen_if_exhausted(session);
            if (status != NINLIL_OK) {
                context->phase =
                    NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
            }
            return status;
        }
        context->binding_complete_mask = (uint8_t)(
            context->binding_complete_mask
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE33);
        complete_mode(context);
        return NINLIL_OK;
    case NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK:
        if (context->phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM
            || context->arm_cursor != 0u) {
            return fail_corrupt(session, context);
        }
        context->count_complete_mask =
            NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE34;
        context->binding_complete_mask = (uint8_t)(
            NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_A
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_B
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_C
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_ALL);
        complete_mode(context);
        return NINLIL_OK;
    default:
        return fail_corrupt(session, context);
    }
}


static int row_family_subtype(
    const uint8_t *key,
    uint32_t key_length,
    uint8_t *out_family,
    uint8_t *out_subtype)
{
    static const uint8_t root[8] =
        {0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u};

    if (key == NULL || key_length < 10u
        || memcmp(key, root, sizeof(root)) != 0) {
        return 0;
    }
    *out_family = key[8];
    *out_subtype = key[9];
    return 1;
}

static int header_matches_witness(
    const ninlil_model_domain_witness_header_t *header,
    const uint8_t witness_digest[32])
{
    ninlil_model_domain_digest_t derived;
    ninlil_bytes_view_t identity;

    identity.data = header->operation_identity;
    identity.length = header->operation_identity_length;
    return ninlil_model_domain_witness_identity_digest(
               header->operation_kind, identity, &derived)
            == NINLIL_OK
        && bytes_equal(derived.bytes, witness_digest, 32u);
}

static int strict_key_after(
    const uint8_t *previous,
    uint8_t previous_length,
    const uint8_t *current,
    uint16_t current_length)
{
    uint16_t common;
    int cmp;

    if (previous_length == 0u) {
        return 1;
    }
    common = previous_length < current_length
        ? previous_length : current_length;
    cmp = memcmp(previous, current, common);
    return cmp < 0 || (cmp == 0 && previous_length < current_length);
}

static uint8_t fold_group(uint8_t group, uint8_t item)
{
    if (group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT
        || item == NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT) {
        return NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT;
    }
    if (group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET) {
        return item;
    }
    if (item == NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET || group == item) {
        return group;
    }
    if (group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD
        || item == NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD) {
        return NINLIL_DOMAIN_SCAN_D3S4_GROUP_MIXED_OLD_NEW;
    }
    if (group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED
        || item == NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED) {
        return NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
    }
    return NINLIL_DOMAIN_SCAN_D3S4_GROUP_MIXED_OLD_NEW;
}

static ninlil_status_t install_header(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    const uint8_t *key,
    uint32_t key_length,
    const ninlil_model_domain_witness_header_t *header)
{
    uint16_t expected_chunks;

    if (key_length != 45u
        || !header_matches_witness(header, &key[13])
        || ninlil_model_domain_witness_chunk_count_for_members(
               header->member_count, &expected_chunks)
            != NINLIL_OK
        || expected_chunks != header->chunk_count) {
        return fail_corrupt(session, context);
    }
    (void)memcpy(context->witness_digest, &key[13], 32u);
    (void)memcpy(
        context->expected_manifest_digest, header->manifest_digest, 32u);
    store_u16(context->member_count, header->member_count);
    store_u16(context->chunk_count, header->chunk_count);
    store_u16(context->streamed_members, 0u);
    store_u16(context->membership_i, 0u);
    (void)memset(context->prev_member_key, 0, 45u);
    context->prev_member_key_len = 0u;
    context->member_substep = 0u;
    context->group_class = NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET;
    context->entry_action = 0u;
    context->entry_old_present = 0u;
    context->entry_new_present = 0u;
    context->entry_flags = 0u;
    context->entry_record_role[0] = 0u;
    context->entry_record_role[1] = 0u;
    store_u16(context->entry_key_length, 0u);
    context->flags = (uint8_t)(context->flags
        | NINLIL_DOMAIN_SCAN_D3S4_FLAG_HEADER_INSTALLED
        | NINLIL_DOMAIN_SCAN_D3S4_FLAG_MANIFEST_SHA_OPEN);
    if (manifest_sha_init(context) != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_MEMBER_PIPELINE;
    return NINLIL_OK;
}

static ninlil_status_t member_chunk_step(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_model_domain_witness_chunk_t *chunk;
    ninlil_model_domain_witness_entry_t *entry;
    ninlil_bytes_view_t body;
    uint16_t ordinal = load_u16(context->streamed_members);
    uint16_t member_count = load_u16(context->member_count);
    uint16_t chunk_count = load_u16(context->chunk_count);
    uint16_t requested_index;
    uint16_t expected_entries;
    uint16_t slot;
    ninlil_status_t status;

    if (ordinal >= member_count || chunk_count == 0u) {
        return fail_corrupt(session, context);
    }
    requested_index = (uint16_t)(ordinal / 8u);
    status = build_witness_chunk_key(
        context->witness_digest, requested_index,
        context->peer_key, &context->peer_key_len);
    if (status != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    status = exact_get_counted(
        session, context, context->peer_key, context->peer_key_len, &got);
    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return fail_corrupt(session, context);
    }
    chunk = &session->bound_workspace->row_validate_scratch.witness_chunk;
    status = decode_chunk_value(got.value, chunk, &body);
    if (status != NINLIL_OK
        || !bytes_equal(
            chunk->witness_digest, context->witness_digest, 32u)
        || chunk->chunk_index != requested_index
        || chunk->chunk_count != chunk_count) {
        return fail_corrupt(session, context);
    }
    expected_entries = requested_index + 1u == chunk_count
        ? (uint16_t)(member_count - 8u * (chunk_count - 1u))
        : 8u;
    slot = (uint16_t)(ordinal % 8u);
    if (chunk->entry_count != expected_entries
        || slot >= chunk->entry_count) {
        return fail_corrupt(session, context);
    }
    if (slot == 0u
        && manifest_sha_update(
               context, body, requested_index)
            != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    entry = &chunk->entries[slot];
    if (!strict_key_after(
            context->prev_member_key, context->prev_member_key_len,
            entry->key_bytes, entry->key_length)
        || copy_key(
               context->peer_key, &context->peer_key_len,
               entry->key_bytes, entry->key_length)
            != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    (void)memset(context->prev_member_key, 0, 45u);
    (void)memcpy(
        context->prev_member_key, entry->key_bytes, entry->key_length);
    context->prev_member_key_len = (uint8_t)entry->key_length;
    context->entry_action = entry->action;
    context->entry_old_present = entry->old_present;
    context->entry_new_present = entry->new_present;
    (void)memcpy(
        context->entry_prior_head_witness_digest,
        entry->prior_head_witness_digest, 32u);
    (void)memcpy(
        context->entry_old_value_digest, entry->old_value_digest, 32u);
    (void)memcpy(
        context->entry_new_value_digest, entry->new_value_digest, 32u);
    context->entry_record_role[0] =
        (uint8_t)((entry->record_role >> 8u) & 0xffu);
    context->entry_record_role[1] =
        (uint8_t)(entry->record_role & 0xffu);
    store_u16(context->entry_key_length, entry->key_length);
    context->member_substep = 1u;
    return NINLIL_OK;
}

static uint8_t local_match(
    const ninlil_domain_scan_d3s4_context_t *context,
    int present,
    const uint8_t digest[32])
{
    int old_match = context->entry_old_present == (uint8_t)present
        && (!present
            || bytes_equal(
                context->entry_old_value_digest, digest, 32u));
    int new_match = context->entry_new_present == (uint8_t)present
        && (!present
            || bytes_equal(
                context->entry_new_value_digest, digest, 32u));

    if (old_match && !new_match) {
        return NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD;
    }
    if (new_match) {
        return NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_NEW;
    }
    return NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT;
}

static ninlil_status_t classify_member(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    const ninlil_domain_scan_exact_get_result_t *got)
{
    uint8_t family = context->entry_record_role[0];
    uint8_t subtype = context->entry_record_role[1];
    uint8_t key_family;
    uint8_t key_subtype;
    uint8_t digest[32] = {0};
    uint8_t item;
    ninlil_model_domain_envelope_t envelope;
    ninlil_model_domain_witness_header_t header;
    int present = got->presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT;
    ninlil_status_t status;

    if (!row_family_subtype(
            context->peer_key, context->peer_key_len,
            &key_family, &key_subtype)
        || key_family != family || key_subtype != subtype) {
        return fail_corrupt(session, context);
    }
    if (context->entry_action
        == NINLIL_MODEL_DOMAIN_WITNESS_ACTION_SUPERSEDE) {
        if (!present) {
            item =
                NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
        } else {
            status = decode_header_value(got->value, &header);
            if (status != NINLIL_OK
                || !header_matches_witness(
                    &header, &context->peer_key[13])) {
                return fail_corrupt(session, context);
            }
            if (header.witness_state
                == NINLIL_MODEL_DOMAIN_WITNESS_STATE_SUPERSEDED) {
                item = NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_NEW;
            } else if (header.witness_state
                    == NINLIL_MODEL_DOMAIN_WITNESS_STATE_RETIRED
                && bytes_equal(
                    header.successor_witness_digest,
                    context->witness_digest, 32u)) {
                item =
                    NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
            } else {
                return fail_corrupt(session, context);
            }
        }
        if (item
            == NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED) {
            context->flags = (uint8_t)(context->flags
                | NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN);
            context->binding_complete_mask = (uint8_t)(
                context->binding_complete_mask
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED);
        }
        context->group_class =
            fold_group(context->group_class, item);
        context->member_substep = 3u;
        return NINLIL_OK;
    }
    if (present) {
        status = value_digest(got->value, digest);
        if (status != NINLIL_OK) {
            return fail_corrupt(session, context);
        }
    }
    item = local_match(context, present, digest);
    if (context->focus_mode
        == NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS) {
        if (item != NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_NEW) {
            return fail_corrupt(session, context);
        }
        if (present && (family == 5u || family == 6u)) {
            status = decode_envelope(got->value, &envelope);
            if (status != NINLIL_OK
                || !bytes_equal(
                    envelope.header.head_witness_digest,
                    context->witness_digest, 32u)) {
                return fail_corrupt(session, context);
            }
        }
    } else {
        if (item == NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD) {
            return fail_corrupt(session, context);
        }
        if (item == NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT) {
            if (present && (family == 5u || family == 6u)
                && decode_envelope(got->value, &envelope) == NINLIL_OK
                && !digest_is_zero(
                    envelope.header.head_witness_digest)
                && !bytes_equal(
                    envelope.header.head_witness_digest,
                    context->witness_digest, 32u)) {
                item =
                    NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
            } else if (family == 3u || family == 4u) {
                item =
                    NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
            } else {
                return fail_corrupt(session, context);
            }
        } else if (present && (family == 5u || family == 6u)) {
            status = decode_envelope(got->value, &envelope);
            if (status != NINLIL_OK) {
                return fail_corrupt(session, context);
            }
            if (!bytes_equal(
                    envelope.header.head_witness_digest,
                    context->witness_digest, 32u)) {
                if (!digest_is_zero(envelope.header.head_witness_digest)) {
                    item =
                        NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
                } else {
                    return fail_corrupt(session, context);
                }
            }
        }
    }
    context->group_class = fold_group(context->group_class, item);
    if (present && (family == 5u || family == 6u)) {
        status = decode_envelope(got->value, &envelope);
        if (status != NINLIL_OK) {
            return fail_corrupt(session, context);
        }
        if (!digest_is_zero(envelope.header.primary_value_digest)) {
            status = prepare_primary_proof(
                session, context,
                context->peer_key, context->peer_key_len, got->value);
            if (status != NINLIL_OK) {
                return status;
            }
            context->member_substep = 2u;
            return NINLIL_OK;
        }
    }
    context->member_substep = 3u;
    return NINLIL_OK;
}

static ninlil_status_t member_value_step(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_status_t status = exact_get_counted(
        session, context, context->peer_key, context->peer_key_len, &got);

    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    return classify_member(session, context, &got);
}

static void clear_primary_pins(
    ninlil_domain_scan_d3s4_context_t *context)
{
    (void)memset(context->expected_primary_pvd, 0, 32u);
    (void)memset(
        context->expected_primary_raw, 0,
        sizeof(context->expected_primary_raw));
    (void)memset(
        context->expected_primary_raw2, 0,
        sizeof(context->expected_primary_raw2));
    (void)memset(
        context->expected_primary_aux, 0,
        sizeof(context->expected_primary_aux));
    store_u16(context->expected_primary_raw_len, 0u);
    context->expected_primary_raw2_len = 0u;
    context->expected_primary_aux_len = 0u;
    (void)memset(context->peer_key, 0, 45u);
    context->peer_key_len = 0u;
    context->entry_record_role[0] = 0u;
    context->entry_record_role[1] = 0u;
    context->entry_flags = 0u;
    store_u16(context->entry_key_length, 0u);
}

static ninlil_status_t member_primary_step(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_status_t status = exact_get_counted(
        session, context, context->peer_key, context->peer_key_len, &got);

    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return fail_corrupt(session, context);
    }
    status = verify_primary_proof(session, context, got.value);
    if (status != NINLIL_OK) {
        return status;
    }
    clear_primary_pins(context);
    context->member_substep = 3u;
    return NINLIL_OK;
}

static void member_done_step(
    ninlil_domain_scan_d3s4_context_t *context)
{
    uint16_t ordinal = load_u16(context->streamed_members);
    uint16_t member_count = load_u16(context->member_count);

    store_u16(context->streamed_members, (uint16_t)(ordinal + 1u));
    context->member_substep = 0u;
    context->entry_action = 0u;
    context->entry_old_present = 0u;
    context->entry_new_present = 0u;
    context->entry_flags = 0u;
    context->entry_record_role[0] = 0u;
    context->entry_record_role[1] = 0u;
    store_u16(context->entry_key_length, 0u);
    (void)memset(context->entry_old_value_digest, 0, 32u);
    (void)memset(context->entry_new_value_digest, 0, 32u);
    (void)memset(context->entry_prior_head_witness_digest, 0, 32u);
    if ((uint16_t)(ordinal + 1u) == member_count) {
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE;
    }
}

static ninlil_status_t close_member_group(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    uint8_t digest[32];
    uint8_t group = context->group_class;

    if (load_u16(context->streamed_members)
            != load_u16(context->member_count)
        || manifest_sha_final(
               context, load_u16(context->chunk_count), digest)
            != NINLIL_OK
        || !bytes_equal(
            digest, context->expected_manifest_digest, 32u)) {
        return fail_corrupt(session, context);
    }
    if (context->focus_mode
        == NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS) {
        if (group != NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_NEW
            && group
                != NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED) {
            return fail_corrupt(session, context);
        }
        if (group
                == NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED
            && ((context->flags
                    & NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN)
                    == 0u
                || (context->binding_complete_mask
                        & NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED)
                    == 0u)) {
            return fail_corrupt(session, context);
        }
    } else {
        if (group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD
            || group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_MIXED_OLD_NEW
            || group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT
            || group == NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET) {
            return fail_corrupt(session, context);
        }
        context->flags = (uint8_t)(context->flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN);
    }
    context->flags = (uint8_t)(context->flags
        & (uint8_t)~(NINLIL_DOMAIN_SCAN_D3S4_FLAG_HEADER_INSTALLED
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_MANIFEST_SHA_OPEN));
    context->group_class = NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET;
    context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT;
    return NINLIL_OK;
}

static ninlil_status_t drive_mode31_32(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_status_t status;

    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT) {
        status = reopen_if_exhausted(session);
        if (status != NINLIL_OK) {
            context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
            return status;
        }
        return ninlil_domain_scan_advance(session, 1u);
    }
    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_MEMBER_PIPELINE) {
        switch (context->member_substep) {
        case 0u:
            return member_chunk_step(session, context);
        case 1u:
            return member_value_step(session, context);
        case 2u:
            return member_primary_step(session, context);
        case 3u:
            member_done_step(context);
            return NINLIL_OK;
        default:
            return fail_corrupt(session, context);
        }
    }
    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE) {
        return close_member_group(session, context);
    }
    return NINLIL_E_INVALID_STATE;
}

static ninlil_status_t bind_mode33_chunk(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length)
{
    const ninlil_model_domain_witness_chunk_t *chunk =
        &workspace->row_validate_scratch.witness_chunk;
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_model_domain_witness_header_t header;
    uint16_t expected_entries;
    ninlil_status_t status;

    if (copy_key(
            context->last_carrier_key, &context->last_carrier_key_len,
            workspace->key, key_length)
        != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    (void)memcpy(context->witness_digest, chunk->witness_digest, 32u);
    status = build_witness_header_key(
        chunk->witness_digest, context->peer_key, &context->peer_key_len);
    if (status != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    status = exact_get_counted(
        session, context, context->peer_key, context->peer_key_len, &got);
    if (status == NINLIL_E_WOULD_BLOCK) {
        /* drive_mode33 gates before iter_next; this cannot occur. */
        return fail_corrupt(session, context);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT
        || decode_header_value(got.value, &header) != NINLIL_OK
        || !header_matches_witness(&header, chunk->witness_digest)
        || header.chunk_count != chunk->chunk_count
        || chunk->chunk_index >= header.chunk_count) {
        return fail_corrupt(session, context);
    }
    expected_entries = chunk->chunk_index + 1u == header.chunk_count
        ? (uint16_t)(header.member_count
            - 8u * (header.chunk_count - 1u))
        : 8u;
    if (chunk->entry_count != expected_entries) {
        return fail_corrupt(session, context);
    }
    if (header.witness_state
        == NINLIL_MODEL_DOMAIN_WITNESS_STATE_RETIRED) {
        context->binding_complete_mask = (uint8_t)(
            context->binding_complete_mask
            | NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED);
    }
    if (context->found_count_b < 2u) {
        context->found_count_b += 1u;
    }
    return NINLIL_OK;
}

static ninlil_status_t drive_mode33(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_status_t status;

    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT) {
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE33_BIND;
        context->arm_cursor = 0u;
        store_u16(context->membership_i, 0u);
        store_u16(context->streamed_members, 0u);
        context->found_count_a = 0u;
        context->found_count_b = 0u;
        status = reopen_if_exhausted(session);
        if (status != NINLIL_OK) {
            context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
            return status;
        }
        return NINLIL_OK;
    }
    if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE33_BIND) {
        return NINLIL_E_INVALID_STATE;
    }
    if (context->arm_cursor == 1u && quota_exhausted(context)) {
        mark_yield(context);
        return NINLIL_OK;
    }
    status = reopen_if_exhausted(session);
    if (status != NINLIL_OK) {
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
        return status;
    }
    return ninlil_domain_scan_advance(session, 1u);
}

static ninlil_status_t on_row_mode31_32(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s4_context_t *context,
    uint32_t key_length,
    uint8_t family,
    uint8_t subtype,
    uint8_t typed_current_ok)
{
    const ninlil_model_domain_witness_header_t *header;
    uint16_t wanted_state;

    if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT
        || family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
        return NINLIL_OK;
    }
    if (typed_current_ok == 0u) {
        return fail_corrupt(session, context);
    }
    header = &workspace->row_validate_scratch.witness_header;
    wanted_state = context->focus_mode
            == NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS
        ? NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE
        : NINLIL_MODEL_DOMAIN_WITNESS_STATE_SUPERSEDED;
    if (header->witness_state != wanted_state) {
        return NINLIL_OK;
    }
    return install_header(
        session, context, workspace->key, key_length, header);
}

static ninlil_status_t on_row_mode33(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_domain_scan_d3s4_context_t *context,
    uint32_t key_length,
    uint8_t family,
    uint8_t subtype,
    uint8_t typed_current_ok)
{
    uint16_t ordinal;

    if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE33_BIND) {
        return fail_corrupt(session, context);
    }
    if (context->arm_cursor == 0u) {
        ordinal = load_u16(context->membership_i);
        if (ordinal == UINT16_MAX) {
            return fail_corrupt(session, context);
        }
        store_u16(context->membership_i, (uint16_t)(ordinal + 1u));
        if (family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
            && subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
            const ninlil_model_domain_witness_header_t *header =
                &workspace->row_validate_scratch.witness_header;
            if (typed_current_ok == 0u) {
                return fail_corrupt(session, context);
            }
            if (header->witness_state
                == NINLIL_MODEL_DOMAIN_WITNESS_STATE_RETIRED) {
                context->binding_complete_mask = (uint8_t)(
                    context->binding_complete_mask
                    | NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED);
                if (context->found_count_a < 2u) {
                    context->found_count_a += 1u;
                }
            }
        }
        return NINLIL_OK;
    }
    if (context->arm_cursor != 1u) {
        return fail_corrupt(session, context);
    }
    ordinal = load_u16(context->streamed_members);
    if (ordinal == UINT16_MAX) {
        return fail_corrupt(session, context);
    }
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && subtype
            == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK) {
        if (typed_current_ok == 0u) {
            return fail_corrupt(session, context);
        }
        if (bind_mode33_chunk(
                session, context, workspace, key_length)
            != NINLIL_OK) {
            return session->has_sticky_primary != 0u
                ? session->sticky_primary : NINLIL_E_STORAGE_CORRUPT;
        }
    }
    store_u16(context->streamed_members, (uint16_t)(ordinal + 1u));
    return NINLIL_OK;
}

static ninlil_status_t key_digest(
    const uint8_t *key, uint32_t key_length, uint8_t out[32])
{
    ninlil_bytes_view_t view;
    ninlil_model_domain_digest_t digest;

    view.data = key;
    view.length = key_length;
    if (ninlil_model_domain_key_digest(view, &digest) != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(out, digest.bytes, 32u);
    return NINLIL_OK;
}

static void reset_mode34_carrier(
    ninlil_domain_scan_d3s4_context_t *context)
{
    uint16_t carrier_ordinal = load_u16(context->streamed_members);

    context->membership_need_mask = 0u;
    context->found_count_a = 0u;
    context->found_count_b = 0u;
    store_u16(context->membership_i, 0u);
    context->membership_substep = 0u;
    (void)memset(context->pin_digest_a, 0, 32u);
    (void)memset(context->pin_digest_b, 0, 32u);
    (void)memset(context->focus_key_digest, 0, 32u);
    (void)memset(context->witness_digest, 0, 32u);
    (void)memset(context->membership_key_a, 0, 45u);
    context->membership_key_a_len = 0u;
    (void)memset(context->peer_key, 0, 45u);
    context->peer_key_len = 0u;
    (void)memset(context->prev_member_key, 0, 45u);
    context->prev_member_key_len = 0u;
    (void)memset(context->expected_manifest_digest, 0, 32u);
    (void)memset(context->entry_old_value_digest, 0, 32u);
    (void)memset(context->entry_new_value_digest, 0, 32u);
    (void)memset(context->entry_prior_head_witness_digest, 0, 32u);
    (void)memset(context->sha_state, 0, 32u);
    (void)memset(context->sha_bitcount, 0, 8u);
    (void)memset(context->sha_block, 0, 64u);
    context->sha_block_len = 0u;
    store_u16(context->member_count, 0u);
    store_u16(context->chunk_count, 0u);
    context->entry_action = 0u;
    context->entry_old_present = 0u;
    context->entry_new_present = 0u;
    clear_primary_pins(context);
    context->flags = (uint8_t)(context->flags
        & (uint8_t)~(NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_HEADER_INSTALLED
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_MANIFEST_SHA_OPEN));
    context->arm_cursor = 0u;
    if (carrier_ordinal != UINT16_MAX) {
        store_u16(
            context->streamed_members, (uint16_t)(carrier_ordinal + 1u));
    }
}

static ninlil_status_t install_mode34_header(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context,
    const ninlil_model_domain_witness_header_t *header)
{
    uint16_t expected_chunks;

    if (!header_matches_witness(header, context->witness_digest)
        || (header->witness_state
                != NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE
            && header->witness_state
                != NINLIL_MODEL_DOMAIN_WITNESS_STATE_SUPERSEDED)
        || ninlil_model_domain_witness_chunk_count_for_members(
               header->member_count, &expected_chunks)
            != NINLIL_OK
        || expected_chunks != header->chunk_count) {
        return fail_corrupt(session, context);
    }
    store_u16(context->member_count, header->member_count);
    store_u16(context->chunk_count, header->chunk_count);
    (void)memcpy(
        context->expected_manifest_digest, header->manifest_digest, 32u);
    store_u16(context->membership_i, 0u);
    context->membership_substep = 0u;
    context->found_count_a = 0u;
    context->found_count_b = 0u;
    (void)memset(context->prev_member_key, 0, 45u);
    context->prev_member_key_len = 0u;
    context->membership_need_mask =
        context->peer_key_len == 0u ? 1u : 3u;
    context->flags = (uint8_t)(context->flags
        | NINLIL_DOMAIN_SCAN_D3S4_FLAG_HEADER_INSTALLED
        | NINLIL_DOMAIN_SCAN_D3S4_FLAG_MANIFEST_SHA_OPEN);
    if (manifest_sha_init(context) != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    context->arm_cursor = 5u;
    return NINLIL_OK;
}

static ninlil_status_t request_header_mode34(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_model_domain_witness_header_t header;
    uint8_t request_length = 0u;
    ninlil_status_t status;

    status = build_witness_header_key(
        context->witness_digest,
        context->expected_primary_raw, &request_length);
    if (status != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    store_u16(context->expected_primary_raw_len, request_length);
    status = exact_get_counted(
        session, context, context->expected_primary_raw,
        request_length, &got);
    store_u16(context->expected_primary_raw_len, 0u);
    (void)memset(
        context->expected_primary_raw, 0,
        sizeof(context->expected_primary_raw));
    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT
        || decode_header_value(got.value, &header) != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    return install_mode34_header(session, context, &header);
}

static ninlil_status_t mode34_arm_b_member(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    uint8_t digest[32];
    ninlil_status_t status = exact_get_counted(
        session, context,
        context->membership_key_a, context->membership_key_a_len, &got);

    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT
        || value_digest(got.value, digest) != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    (void)memcpy(context->pin_digest_a, digest, 32u);
    if (!bytes_equal(digest, context->entry_new_value_digest, 32u)) {
        return fail_corrupt(session, context);
    }
    if (context->entry_flags == NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
        context->arm_cursor = 6u;
    } else if (context->entry_flags
        == NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED) {
        context->arm_cursor = 4u;
    } else {
        return fail_corrupt(session, context);
    }
    (void)memset(context->entry_new_value_digest, 0, 32u);
    context->entry_flags = 0u;
    return NINLIL_OK;
}

static ninlil_status_t mode34_arm_c_index(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_model_domain_typed_record_t *typed;
    const ninlil_model_domain_body_witness_head_index_t *index;
    ninlil_bytes_view_t key;
    uint8_t digest[32];
    ninlil_status_t status = exact_get_counted(
        session, context, context->peer_key, context->peer_key_len, &got);

    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return fail_corrupt(session, context);
    }
    typed = &session->bound_workspace->row_validate_scratch.typed;
    key.data = context->peer_key;
    key.length = context->peer_key_len;
    if (value_digest(got.value, digest) != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    (void)memcpy(context->pin_digest_b, digest, 32u);
    if (ninlil_model_domain_validate_typed_record(
            key, got.value, typed)
            != NINLIL_OK
        || typed->family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || typed->subtype
            != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX) {
        return fail_corrupt(session, context);
    }
    index = &typed->witness_head_index;
    if (index->member_key_length != context->membership_key_a_len
        || !bytes_equal(
            index->member_key_bytes, context->membership_key_a,
            context->membership_key_a_len)
        || !bytes_equal(
            index->member_key_digest, context->focus_key_digest, 32u)
        || !bytes_equal(
            index->member_value_digest, context->pin_digest_a, 32u)) {
        return fail_corrupt(session, context);
    }
    (void)memcpy(
        context->witness_digest,
        index->member_head_witness_digest, 32u);
    if (index->index_state == NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
        context->arm_cursor = 6u;
    } else if (index->index_state
        == NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED) {
        context->arm_cursor = 4u;
    } else {
        return fail_corrupt(session, context);
    }
    return NINLIL_OK;
}

static ninlil_status_t mode34_membership_close(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    uint8_t digest[32];

    if (load_u16(context->membership_i)
            != load_u16(context->member_count)
        || manifest_sha_final(
               context, load_u16(context->chunk_count), digest)
            != NINLIL_OK
        || !bytes_equal(
            digest, context->expected_manifest_digest, 32u)
        || ((context->membership_need_mask & 1u) != 0u
            && context->found_count_a != 1u)
        || ((context->membership_need_mask & 2u) != 0u
            && context->found_count_b != 1u)) {
        return fail_corrupt(session, context);
    }
    context->flags = (uint8_t)(context->flags
        & (uint8_t)~NINLIL_DOMAIN_SCAN_D3S4_FLAG_MANIFEST_SHA_OPEN);
    context->arm_cursor = 6u;
    return NINLIL_OK;
}

static ninlil_status_t mode34_membership_step(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_model_domain_witness_chunk_t *chunk;
    const ninlil_model_domain_witness_entry_t *entry;
    ninlil_bytes_view_t body;
    uint16_t ordinal;
    uint16_t member_count;
    uint16_t chunk_count;
    uint16_t requested_index;
    uint16_t expected_entries;
    uint16_t slot;
    uint8_t request_length = 0u;
    ninlil_status_t status;

    if (context->membership_substep == 1u) {
        return mode34_membership_close(session, context);
    }
    ordinal = load_u16(context->membership_i);
    member_count = load_u16(context->member_count);
    chunk_count = load_u16(context->chunk_count);
    if (ordinal >= member_count) {
        return fail_corrupt(session, context);
    }
    requested_index = (uint16_t)(ordinal / 8u);
    status = build_witness_chunk_key(
        context->witness_digest, requested_index,
        context->expected_primary_raw, &request_length);
    if (status != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    store_u16(context->expected_primary_raw_len, request_length);
    status = exact_get_counted(
        session, context, context->expected_primary_raw,
        request_length, &got);
    store_u16(context->expected_primary_raw_len, 0u);
    (void)memset(
        context->expected_primary_raw, 0,
        sizeof(context->expected_primary_raw));
    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return fail_corrupt(session, context);
    }
    chunk = &session->bound_workspace->row_validate_scratch.witness_chunk;
    if (decode_chunk_value(got.value, chunk, &body) != NINLIL_OK
        || !bytes_equal(
            chunk->witness_digest, context->witness_digest, 32u)
        || chunk->chunk_index != requested_index
        || chunk->chunk_count != chunk_count) {
        return fail_corrupt(session, context);
    }
    expected_entries = requested_index + 1u == chunk_count
        ? (uint16_t)(member_count - 8u * (chunk_count - 1u))
        : 8u;
    slot = (uint16_t)(ordinal % 8u);
    if (chunk->entry_count != expected_entries
        || slot >= chunk->entry_count) {
        return fail_corrupt(session, context);
    }
    if (slot == 0u
        && manifest_sha_update(context, body, requested_index)
            != NINLIL_OK) {
        return fail_corrupt(session, context);
    }
    entry = &chunk->entries[slot];
    if (!strict_key_after(
            context->prev_member_key, context->prev_member_key_len,
            entry->key_bytes, entry->key_length)) {
        return fail_corrupt(session, context);
    }
    (void)memset(context->prev_member_key, 0, 45u);
    (void)memcpy(
        context->prev_member_key, entry->key_bytes, entry->key_length);
    context->prev_member_key_len = (uint8_t)entry->key_length;
    if ((context->membership_need_mask & 1u) != 0u
        && entry->key_length == context->membership_key_a_len
        && bytes_equal(
            entry->key_bytes, context->membership_key_a,
            entry->key_length)) {
        if (context->found_count_a < 2u) {
            context->found_count_a += 1u;
        }
        if (context->found_count_a == 1u
            && !bytes_equal(
                entry->new_value_digest, context->pin_digest_a, 32u)) {
            return fail_corrupt(session, context);
        }
    }
    if ((context->membership_need_mask & 2u) != 0u
        && entry->key_length == context->peer_key_len
        && bytes_equal(
            entry->key_bytes, context->peer_key, entry->key_length)) {
        if (context->found_count_b < 2u) {
            context->found_count_b += 1u;
        }
        if (context->found_count_b == 1u
            && !bytes_equal(
                entry->new_value_digest, context->pin_digest_b, 32u)) {
            return fail_corrupt(session, context);
        }
    }
    ordinal += 1u;
    store_u16(context->membership_i, ordinal);
    if (ordinal == member_count) {
        context->membership_substep = 1u;
    }
    return NINLIL_OK;
}

static ninlil_status_t mode34_primary_step(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_domain_scan_exact_get_result_t got;
    ninlil_status_t status = exact_get_counted(
        session, context, context->peer_key, context->peer_key_len, &got);

    if (status == NINLIL_E_WOULD_BLOCK) {
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (got.presence != NINLIL_DOMAIN_SCAN_EXACT_PRESENT) {
        return fail_corrupt(session, context);
    }
    status = verify_primary_proof(session, context, got.value);
    if (status != NINLIL_OK) {
        return status;
    }
    clear_primary_pins(context);
    context->arm_cursor = 4u;
    return NINLIL_OK;
}

static ninlil_status_t drive_mode34(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s4_context_t *context)
{
    ninlil_status_t status;

    if (context->phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT) {
        context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM;
        context->arm_cursor = 0u;
        store_u16(context->streamed_members, 0u);
        status = reopen_if_exhausted(session);
        if (status != NINLIL_OK) {
            context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
            return status;
        }
        return NINLIL_OK;
    }
    if (context->phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM) {
        return NINLIL_E_INVALID_STATE;
    }
    switch (context->arm_cursor) {
    case 0u:
        status = reopen_if_exhausted(session);
        if (status != NINLIL_OK) {
            context->phase = NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED;
            return status;
        }
        return ninlil_domain_scan_advance(session, 1u);
    case 1u:
        return mode34_primary_step(session, context);
    case 2u:
        return mode34_arm_b_member(session, context);
    case 3u:
        return mode34_arm_c_index(session, context);
    case 4u:
        return request_header_mode34(session, context);
    case 5u:
        return mode34_membership_step(session, context);
    case 6u:
        reset_mode34_carrier(context);
        return NINLIL_OK;
    default:
        return fail_corrupt(session, context);
    }
}
