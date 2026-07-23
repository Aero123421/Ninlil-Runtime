#include "domain_store_scanner.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_d3s1.h"
#include "domain_store_d3s2.h"
#include "domain_store_d3s3.h"
#include "v1_durable_allowlist.h"

#include <stdint.h>
#include <string.h>

static const uint8_t CURRENT_ROOT[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

/* Packed encoded_values offsets/capacities by key_id-1 (catalog order). */
static const uint16_t ENCODED_OFFSETS[17] = {
    0u, 183u, 267u, 299u, 331u, 363u, 395u, 463u, 531u, 599u, 667u, 735u,
    803u, 871u, 939u, 1007u, 1075u
};
static const uint16_t ENCODED_CAPS[17] = {
    183u, 84u, 32u, 32u, 32u, 32u, 68u, 68u, 68u, 68u, 68u, 68u, 68u, 68u,
    68u, 68u, 68u
};

_Static_assert(
    183u + 84u + 4u * 32u + 11u * 68u
        == NINLIL_DOMAIN_SCAN_ENCODED_VALUES_BYTES,
    "S2 packed encoded_values inventory drift");
_Static_assert(
    1075u + 68u == NINLIL_DOMAIN_SCAN_ENCODED_VALUES_BYTES,
    "S2 packed encoded_values last slot drift");

static int ranges_are_disjoint(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;

    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - left_start
        || right_length > UINTPTR_MAX - right_start) {
        return 0;
    }
    return left_start + left_length <= right_start
        || right_start + right_length <= left_start;
}

static int storage_ops_required_nonnull(const ninlil_storage_ops_t *storage)
{
    return storage != NULL
        && storage->begin != NULL
        && storage->get != NULL
        && storage->iter_open != NULL
        && storage->iter_next != NULL
        && storage->iter_close != NULL
        && storage->rollback != NULL
        && storage->close != NULL;
}

static int storage_status_is_known(ninlil_storage_status_t status)
{
    return status <= NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}

static int storage_status_requires_fence(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_COMMIT_UNKNOWN
        || !storage_status_is_known(status);
}

static ninlil_status_t map_storage_status(ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_BUSY) {
        return NINLIL_E_WOULD_BLOCK;
    }
    if (status == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (status == NINLIL_STORAGE_IO_ERROR) {
        return NINLIL_E_STORAGE;
    }
    if (status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static int is_exact_family14_catalog_key(
    const uint8_t *key,
    uint32_t length)
{
    if (key == NULL || length < 9u) {
        return 0;
    }
    if (memcmp(key, CURRENT_ROOT, sizeof(CURRENT_ROOT)) != 0) {
        return 0;
    }
    if (length == 9u && (key[8] == 0x01u || key[8] == 0x02u)) {
        return 1;
    }
    if (length == 10u) {
        if (key[8] == 0x03u && key[9] >= 1u && key[9] <= 4u) {
            return 1;
        }
        if (key[8] == 0x04u && key[9] >= 1u && key[9] <= 11u) {
            return 1;
        }
    }
    return 0;
}

/*
 * family 1–4 prefix-shaped but not exact catalog (malformed / noncatalog).
 * Value is not inspected.
 */
static int is_family14_prefix_noncatalog(
    const uint8_t *key,
    uint32_t length)
{
    if (key == NULL || length < 9u) {
        return 0;
    }
    if (memcmp(key, CURRENT_ROOT, sizeof(CURRENT_ROOT)) != 0) {
        return 0;
    }
    if (key[8] < 0x01u || key[8] > 0x04u) {
        return 0;
    }
    return !is_exact_family14_catalog_key(key, length);
}

static int catalog_key_id(
    const uint8_t *key,
    uint32_t length,
    uint32_t *out_key_id)
{
    if (!is_exact_family14_catalog_key(key, length) || out_key_id == NULL) {
        return 0;
    }
    if (length == 9u && key[8] == 0x01u) {
        *out_key_id = 1u;
        return 1;
    }
    if (length == 9u && key[8] == 0x02u) {
        *out_key_id = 2u;
        return 1;
    }
    if (length == 10u && key[8] == 0x03u) {
        *out_key_id = 2u + (uint32_t)key[9];
        return 1;
    }
    if (length == 10u && key[8] == 0x04u) {
        *out_key_id = 6u + (uint32_t)key[9];
        return 1;
    }
    return 0;
}

static int key_strictly_increases(
    const uint8_t *previous,
    uint32_t previous_length,
    const uint8_t *key,
    uint32_t key_length)
{
    uint32_t common;
    int order;

    common = previous_length < key_length ? previous_length : key_length;
    order = memcmp(previous, key, common);
    if (order < 0) {
        return 1;
    }
    if (order > 0) {
        return 0;
    }
    return key_length > previous_length;
}

static int begin_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    const ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_scan_workspace_t *workspace)
{
    const size_t session_bytes = sizeof(*session);
    const size_t workspace_bytes = sizeof(*workspace);
    const size_t ops_bytes = sizeof(*storage);
    const size_t handle_slot_bytes = sizeof(*inout_handle);

    if (!ranges_are_disjoint(session, session_bytes, workspace, workspace_bytes)
        || !ranges_are_disjoint(session, session_bytes, storage, ops_bytes)
        || !ranges_are_disjoint(
            session, session_bytes, inout_handle, handle_slot_bytes)
        || !ranges_are_disjoint(
            workspace, workspace_bytes, storage, ops_bytes)
        || !ranges_are_disjoint(
            workspace, workspace_bytes, inout_handle, handle_slot_bytes)
        || !ranges_are_disjoint(
            storage, ops_bytes, inout_handle, handle_slot_bytes)) {
        return 0;
    }
    return 1;
}

static int begin_profiled_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    const ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate)
{
    const size_t candidate_bytes = sizeof(*candidate);

    if (!begin_alias_ok(session, storage, inout_handle, workspace)) {
        return 0;
    }
    if (!ranges_are_disjoint(session, sizeof(*session), candidate, candidate_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), candidate, candidate_bytes)
        || !ranges_are_disjoint(storage, sizeof(*storage), candidate, candidate_bytes)
        || !ranges_are_disjoint(
            inout_handle, sizeof(*inout_handle), candidate, candidate_bytes)) {
        return 0;
    }
    return 1;
}

static int begin_profiled_d3s1_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    const ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    const ninlil_domain_scan_d3s1_context_t *context)
{
    const size_t context_bytes = sizeof(*context);

    if (!begin_profiled_alias_ok(
            session, storage, inout_handle, workspace, candidate)) {
        return 0;
    }
    if (!ranges_are_disjoint(session, sizeof(*session), context, context_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), context, context_bytes)
        || !ranges_are_disjoint(storage, sizeof(*storage), context, context_bytes)
        || !ranges_are_disjoint(
            inout_handle, sizeof(*inout_handle), context, context_bytes)
        || !ranges_are_disjoint(
            candidate, sizeof(*candidate), context, context_bytes)) {
        return 0;
    }
    return 1;
}

static int begin_profiled_d3s2_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    const ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    const ninlil_domain_scan_d3s2_context_t *context)
{
    const size_t context_bytes = sizeof(*context);

    if (!begin_profiled_alias_ok(
            session, storage, inout_handle, workspace, candidate)) {
        return 0;
    }
    if (!ranges_are_disjoint(session, sizeof(*session), context, context_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), context, context_bytes)
        || !ranges_are_disjoint(storage, sizeof(*storage), context, context_bytes)
        || !ranges_are_disjoint(
            inout_handle, sizeof(*inout_handle), context, context_bytes)
        || !ranges_are_disjoint(
            candidate, sizeof(*candidate), context, context_bytes)) {
        return 0;
    }
    return 1;
}

/*
 * out_result must not overlap session, bound workspace, bound ops object, or
 * bound handle slot. Validated before any cleanup/output mutation.
 */
static int begin_profiled_d3s3_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    const ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    const ninlil_domain_scan_d3s3_context_t *context)
{
    const size_t context_bytes = sizeof(*context);

    if (!begin_profiled_alias_ok(
            session, storage, inout_handle, workspace, candidate)) {
        return 0;
    }
    if (!ranges_are_disjoint(session, sizeof(*session), context, context_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), context, context_bytes)
        || !ranges_are_disjoint(storage, sizeof(*storage), context, context_bytes)
        || !ranges_are_disjoint(
            inout_handle, sizeof(*inout_handle), context, context_bytes)
        || !ranges_are_disjoint(
            candidate, sizeof(*candidate), context, context_bytes)) {
        return 0;
    }
    return 1;
}

/*
 * out_result must not overlap session, bound workspace, bound ops object, or
 * bound handle slot. Validated before any cleanup/output mutation.
 */
static int result_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_result_t *out_result)
{
    const size_t session_bytes = sizeof(*session);
    const size_t result_bytes = sizeof(*out_result);
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_storage_handle_t *handle_slot = session->bound_handle_slot;
    ninlil_domain_scan_workspace_t *workspace = session->bound_workspace;

    if (storage == NULL || handle_slot == NULL || workspace == NULL) {
        return 0;
    }
    if (!ranges_are_disjoint(session, session_bytes, out_result, result_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), out_result, result_bytes)
        || !ranges_are_disjoint(
            storage, sizeof(*storage), out_result, result_bytes)
        || !ranges_are_disjoint(
            handle_slot, sizeof(*handle_slot), out_result, result_bytes)) {
        return 0;
    }
    return 1;
}

static void set_sticky_primary(
    ninlil_domain_scan_session_t *session,
    ninlil_status_t status)
{
    if (session->has_sticky_primary == 0u) {
        session->has_sticky_primary = 1u;
        session->sticky_primary = status;
    }
}

static ninlil_status_t checked_inc_u64(uint64_t *counter)
{
    if (*counter == UINT64_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *counter += 1u;
    return NINLIL_OK;
}

/*
 * Close the ORIGINAL begin-time handle exactly once through bound_storage.
 * Clear *bound_handle_slot only if it still equals that original value.
 * Foreign slot contents and NULL slots are left untouched (never closed).
 * Double-close is prevented by original_handle_authority.
 */
static void fence_original_handle(ninlil_domain_scan_session_t *session)
{
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_storage_handle_t *slot = session->bound_handle_slot;

    if (session->original_handle_authority != 0u
        && storage != NULL
        && session->bound_handle_value != NULL) {
        storage->close(storage->user, session->bound_handle_value);
        session->original_handle_authority = 0u;
        if (slot != NULL && *slot == session->bound_handle_value) {
            *slot = NULL;
        }
    } else {
        session->original_handle_authority = 0u;
    }
    session->reopen_required = 1u;
    session->fence_pending = 0u;
}

/*
 * Exact match only while scanner still holds authority: slot must equal the
 * original begin-time handle. NULL or foreign during a live session is drift
 * (unless authority was already consumed by a prior fence).
 */
static int handle_slot_exact_match(
    const ninlil_domain_scan_session_t *session)
{
    if (session->bound_handle_slot == NULL) {
        return 0;
    }
    if (session->original_handle_authority == 0u) {
        /* Already fenced/consumed; no live Port dependency on slot match. */
        return 1;
    }
    return *session->bound_handle_slot == session->bound_handle_value;
}

/*
 * Single cleanup tree (§15.6) on bound Port only:
 * 1) iter_close if live and parent still ACTIVE
 * 2) rollback if txn live (consumes remaining children)
 * 3) fence only when required, after children are consumed — always closes
 *    the original bound handle value, never a foreign slot replacement
 */
static ninlil_status_t cleanup_tree(
    ninlil_domain_scan_session_t *session,
    ninlil_status_t primary)
{
    ninlil_status_t outcome = primary;
    ninlil_storage_status_t rollback_status;
    const ninlil_storage_ops_t *storage = session->bound_storage;

    if (storage == NULL) {
        session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
        if (session->has_sticky_primary != 0u) {
            return session->sticky_primary;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (session->iter_live != 0u && session->txn_live != 0u) {
        storage->iter_close(storage->user, session->iter);
        session->iter = NULL;
        session->iter_live = 0u;
    } else if (session->iter_live != 0u) {
        /* Parent already gone: do not call iter_close on consumed txn. */
        session->iter = NULL;
        session->iter_live = 0u;
    }

    if (session->txn_live != 0u) {
        rollback_status = storage->rollback(storage->user, session->txn);
        session->txn = NULL;
        session->txn_live = 0u;
        session->iter = NULL;
        session->iter_live = 0u;
        if (rollback_status != NINLIL_STORAGE_OK) {
            session->cleanup_status = rollback_status;
            fence_original_handle(session);
            if (session->has_sticky_primary == 0u) {
                outcome = map_storage_status(rollback_status);
            } else {
                outcome = session->sticky_primary;
            }
        }
    }

    if (session->fence_pending != 0u) {
        fence_original_handle(session);
    }

    /* Cleanup completed without a fence: the handle remains caller-owned,
     * and this terminal scanner session relinquishes close authority. */
    session->original_handle_authority = 0u;
    session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
    return outcome;
}

static ninlil_status_t aggregate_finalize_outcome(
    const ninlil_domain_scan_session_t *session,
    ninlil_status_t cleanup_outcome)
{
    if (session->has_sticky_primary != 0u) {
        return session->sticky_primary;
    }
    if (cleanup_outcome != NINLIL_OK) {
        return cleanup_outcome;
    }
    if (session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (session->recognizable_future_seen != 0u) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

static void publish_result(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result,
    ninlil_status_t status,
    uint32_t adopted)
{
    out_result->adopted = adopted;
    out_result->status = status;
    out_result->reopen_required = session->reopen_required;
    out_result->cleanup_status = session->cleanup_status;
    out_result->family14_row_count = session->family14_row_count;
    out_result->current_domain_key_count = session->current_domain_key_count;
    out_result->ok_row_count = session->ok_row_count;
    out_result->recognizable_future_seen = session->recognizable_future_seen;
    out_result->profile_exact_active = session->profile_exact_active;
    out_result->profile_mismatch = session->profile_mismatch;
    out_result->future_profile_candidate = session->future_profile_candidate;
    out_result->profile_get_present_mask = session->profile_get_present_mask;
    out_result->family14_iter_seen_mask = session->family14_iter_seen_mask;
}

static int digest_is_zero_bytes(
    const uint8_t digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_MODEL_DOMAIN_DIGEST_BYTES; ++i) {
        if (digest[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * S3-2: WITNESS_HEADER (7f) / WITNESS_MANIFEST_CHUNK (7e) same-record local
 * only — parse key + envelope + pure decode + key/body/header bijection.
 * No member old/new live match, partial group, or successor chain (D3).
 * Large witness bodies use workspace row_validate_scratch only.
 */
static ninlil_status_t validate_witness_row_local(
    ninlil_domain_scan_workspace_t *workspace,
    ninlil_bytes_view_t encoded_key,
    ninlil_bytes_view_t encoded_value)
{
    ninlil_model_domain_key_view_t key_view;
    ninlil_model_domain_envelope_t envelope;
    ninlil_model_domain_digest_t expected_identity;
    uint8_t expect_primary_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_status_t status;
    ninlil_bytes_view_t op_identity;
    uint8_t components[34];
    ninlil_bytes_view_t components_view;

    (void)memset(&key_view, 0, sizeof(key_view));
    (void)memset(&envelope, 0, sizeof(envelope));
    (void)memset(&expected_identity, 0, sizeof(expected_identity));
    (void)memset(expect_primary_id, 0, sizeof(expect_primary_id));

    status = ninlil_model_domain_parse_key(encoded_key, &key_view);
    if (status == NINLIL_E_UNSUPPORTED) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (status != NINLIL_OK) {
        return status == NINLIL_E_INVALID_ARGUMENT
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }
    if (key_view.family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        || (key_view.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
            && key_view.subtype
                != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK)
        || key_view.identity_kind
            != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
        || key_view.identity_length != NINLIL_MODEL_DOMAIN_DIGEST_BYTES
        || key_view.identity == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    status = ninlil_model_domain_decode_envelope(encoded_value, &envelope);
    if (status == NINLIL_E_UNSUPPORTED) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (status != NINLIL_OK) {
        return status == NINLIL_E_INVALID_ARGUMENT
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }
    if (envelope.record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN
        || envelope.header.subtype != key_view.subtype
        || envelope.header.flags != 0u
        || !digest_is_zero_bytes(envelope.header.primary_value_digest)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (key_view.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
        ninlil_model_domain_witness_header_t *header =
            &workspace->row_validate_scratch.witness_header;

        status = ninlil_model_domain_decode_witness_header(
            envelope.body, header);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        op_identity.data = header->operation_identity_length == 0u
            ? NULL
            : header->operation_identity;
        op_identity.length = header->operation_identity_length;
        status = ninlil_model_domain_witness_identity_digest(
            header->operation_kind, op_identity, &expected_identity);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        if (memcmp(
                key_view.identity,
                expected_identity.bytes,
                NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        {
            ninlil_bytes_view_t id_view;

            id_view.data = key_view.identity;
            id_view.length = key_view.identity_length;
            if (ninlil_model_domain_primary_id_from_identity(
                    key_view.identity_kind, id_view, expect_primary_id)
                != NINLIL_OK
                || memcmp(
                       envelope.header.primary_id,
                       expect_primary_id,
                       NINLIL_MODEL_DOMAIN_ID_BYTES)
                    != 0) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
        return NINLIL_OK;
    }

    /* WITNESS_MANIFEST_CHUNK 7e */
    {
        ninlil_model_domain_witness_chunk_t *chunk =
            &workspace->row_validate_scratch.witness_chunk;
        ninlil_bytes_view_t id_view;

        status = ninlil_model_domain_decode_witness_chunk(
            envelope.body, chunk);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        (void)memcpy(components, chunk->witness_digest, 32u);
        components[32] = (uint8_t)((chunk->chunk_index >> 8) & 0xffu);
        components[33] = (uint8_t)(chunk->chunk_index & 0xffu);
        components_view.data = components;
        components_view.length = 34u;
        status = ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            components_view,
            &expected_identity);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        if (memcmp(
                key_view.identity,
                expected_identity.bytes,
                NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        id_view.data = key_view.identity;
        id_view.length = key_view.identity_length;
        if (ninlil_model_domain_primary_id_from_identity(
                key_view.identity_kind, id_view, expect_primary_id)
            != NINLIL_OK
            || memcmp(
                   envelope.header.primary_id,
                   expect_primary_id,
                   NINLIL_MODEL_DOMAIN_ID_BYTES)
                != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
}

static ninlil_status_t map_structural_status(ninlil_status_t status)
{
    if (status == NINLIL_OK || status == NINLIL_E_UNSUPPORTED) {
        return status;
    }
    /* INVALID_ARGUMENT and any other non-OK structural result: terminal. */
    return NINLIL_E_STORAGE_CORRUPT;
}

/*
 * S3-1: exact-profile CURRENT family 5/6 same-record structural validation.
 * Business subtypes + 7d → validate_typed_record (workspace typed scratch).
 * 7e/7f → validate_witness_row_local.
 * UNSUPPORTED (record_version/domain_format future) is non-terminal.
 *
 * out_typed_current_ok is set to 1 only after full CURRENT typed/witness
 * success for this exact row. RECOGNIZABLE_FUTURE and framing-future
 * (UNSUPPORTED) paths leave it 0 so D3 cannot borrow stale typed scratch.
 * Do not use sticky recognizable_future_seen as a per-row proxy.
 */
static ninlil_status_t validate_current_domain_structural(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t *out_typed_current_ok)
{
    ninlil_bytes_view_t key_view;
    ninlil_bytes_view_t value_view;
    ninlil_model_domain_key_class_t row_class;
    ninlil_status_t status;
    uint8_t family;
    uint8_t subtype;

    if (out_typed_current_ok != NULL) {
        *out_typed_current_ok = 0u;
    }

    key_view.data = workspace->key;
    key_view.length = key_length;
    value_view.data = value_length == 0u ? NULL : workspace->value;
    value_view.length = value_length;

    status = ninlil_model_domain_classify_row(key_view, value_view, &row_class);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        session->recognizable_future_seen = 1u;
        return NINLIL_OK;
    }
    if (row_class != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (key_length < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    family = workspace->key[8];
    subtype = workspace->key[9];

    if (family != NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
            || subtype
                == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK)) {
        status = validate_witness_row_local(workspace, key_view, value_view);
    } else {
        status = ninlil_model_domain_validate_typed_record(
            key_view,
            value_view,
            &workspace->row_validate_scratch.typed);
    }
    status = map_structural_status(status);
    if (status == NINLIL_E_UNSUPPORTED) {
        session->recognizable_future_seen = 1u;
        return checked_inc_u64(&session->current_domain_key_count);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (out_typed_current_ok != NULL) {
        *out_typed_current_ok = 1u;
    }
    return checked_inc_u64(&session->current_domain_key_count);
}

/* S1 transport path: coarse class only (no body structural). */
static ninlil_status_t classify_ok_row(
    ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length)
{
    ninlil_bytes_view_t key_view;
    ninlil_bytes_view_t value_view;
    ninlil_model_domain_key_class_t row_class;
    ninlil_status_t status;

    key_view.data = workspace->key;
    key_view.length = key_length;
    value_view.data = value_length == 0u ? NULL : workspace->value;
    value_view.length = value_length;
    status = ninlil_model_domain_classify_row(key_view, value_view, &row_class);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return checked_inc_u64(&session->current_domain_key_count);
    }
    if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        session->recognizable_future_seen = 1u;
        return NINLIL_OK;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static ninlil_status_t reconcile_catalog_row(
    ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length)
{
    uint32_t key_id = 0u;
    uint32_t index;
    uint32_t bit;
    const uint8_t *retained;
    uint32_t retained_length;

    if (!catalog_key_id(workspace->key, key_length, &key_id)
        || key_id < 1u
        || key_id > 17u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    index = key_id - 1u;
    bit = 1u << index;
    if ((session->family14_iter_seen_mask & bit) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    retained = workspace->encoded_views[index].data;
    retained_length = workspace->encoded_views[index].length;
    if (value_length != retained_length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (value_length != 0u) {
        if (retained == NULL
            || memcmp(workspace->value, retained, value_length) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    session->family14_iter_seen_mask |= bit;
    return checked_inc_u64(&session->family14_row_count);
}

/*
 * S2 PASS_INTERNAL structural re-decode: same S3 typed path for S2 filters,
 * but must not mutate frozen D2 counters / profile / future diagnostics
 * (docs/17 §18.13.5). Recognizable future → typed_ok=0, S2 skip, budget OK.
 */
static ninlil_status_t validate_current_domain_structural_s2_filter(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t *out_typed_current_ok)
{
    ninlil_bytes_view_t key_view;
    ninlil_bytes_view_t value_view;
    ninlil_model_domain_key_class_t row_class;
    ninlil_status_t status;
    uint8_t family;
    uint8_t subtype;

    (void)session;
    if (out_typed_current_ok != NULL) {
        *out_typed_current_ok = 0u;
    }

    key_view.data = workspace->key;
    key_view.length = key_length;
    value_view.data = value_length == 0u ? NULL : workspace->value;
    value_view.length = value_length;

    status = ninlil_model_domain_classify_row(key_view, value_view, &row_class);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        /* S2 skip: not focus/BIND subject; no future flag mutation. */
        return NINLIL_OK;
    }
    if (row_class != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (key_length < NINLIL_MODEL_DOMAIN_KEY_MIN_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    family = workspace->key[8];
    subtype = workspace->key[9];

    if (family != NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER
            || subtype
                == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK)) {
        status = validate_witness_row_local(workspace, key_view, value_view);
    } else {
        status = ninlil_model_domain_validate_typed_record(
            key_view,
            value_view,
            &workspace->row_validate_scratch.typed);
    }
    status = map_structural_status(status);
    if (status == NINLIL_E_UNSUPPORTED) {
        /* Framing future: S2 skip; do not set recognizable_future_seen. */
        return NINLIL_OK;
    }
    if (status != NINLIL_OK) {
        return status;
    }
    if (out_typed_current_ok != NULL) {
        *out_typed_current_ok = 1u;
    }
    return NINLIL_OK;
}

static int d3_pass_internal_active(const ninlil_domain_scan_session_t *session)
{
    if (session == NULL) {
        return 0;
    }
    if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S2
        && session->bound_d3s2_context != NULL) {
        return session->bound_d3s2_context->pass_kind
            == NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL;
    }
    if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S3
        && session->bound_d3s3_context != NULL) {
        return session->bound_d3s3_context->pass_kind
            == NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    }
    return 0;
}

static int row_is_v1_allowlisted_spine_marker(
    const uint8_t *key,
    uint32_t key_length,
    const uint8_t *value,
    uint32_t value_length)
{
    ninlil_v1_durable_record_kind_t kind;
    ninlil_status_t status = ninlil_v1_durable_classify_row(
        (ninlil_bytes_view_t){key, key_length},
        (ninlil_bytes_view_t){value, value_length},
        &kind);

    if (status != NINLIL_OK) {
        return 0;
    }
    return kind >= NINLIL_V1_DURABLE_KIND_SPINE_SERVICE_MARKER
        && kind <= NINLIL_V1_DURABLE_KIND_SPINE_RESERVATION;
}

static ninlil_status_t skip_allowlisted_spine_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    int internal)
{
    if (internal == 0 && session->ok_row_count == UINT64_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(workspace->previous_key, workspace->key, key_length);
    session->previous_key_length = key_length;
    session->has_previous = 1u;
    if (internal == 0) {
        session->ok_row_count += 1u;
    }
    return NINLIL_OK;
}

static ninlil_status_t process_ok_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length)
{
    ninlil_status_t class_status;
    uint8_t typed_current_ok = 0u;
    int internal = d3_pass_internal_active(session);

    if (session->has_previous != 0u) {
        if (!key_strictly_increases(
                workspace->previous_key,
                session->previous_key_length,
                workspace->key,
                key_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }

    if (row_is_v1_allowlisted_spine_marker(
            workspace->key,
            key_length,
            workspace->value,
            value_length)) {
        return skip_allowlisted_spine_row(
            session, workspace, key_length, internal);
    }

    /*
     * Preflight total ok_row headroom before any classification sub-counter
     * or previous-key mutation. PASS_INTERNAL freezes ok_row_count (S2 §18.13.5
     * and S3 REP1 §18.14.9.5 / §18.14.19 — lex-only visit under INTERNAL).
     */
    if (internal == 0 && session->ok_row_count == UINT64_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (internal != 0) {
        /*
         * PASS_INTERNAL: freeze D2 public counters / recon / profile /
         * future flags. Re-decode for S2 filter only when profile exact.
         * Family1-4 catalog rows: visit OK for budget; no re-reconcile.
         * S3 multipass W: has_previous + previous_key only (no ok_row++).
         */
        if (is_exact_family14_catalog_key(workspace->key, key_length)
            || is_family14_prefix_noncatalog(workspace->key, key_length)) {
            if (is_family14_prefix_noncatalog(workspace->key, key_length)
                && !is_exact_family14_catalog_key(
                    workspace->key, key_length)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            class_status = NINLIL_OK;
        } else if (session->profile_exact_active != 0u
            && session->profile_mismatch == 0u
            && session->future_profile_candidate == 0u) {
            class_status = validate_current_domain_structural_s2_filter(
                session, workspace, key_length, value_length,
                &typed_current_ok);
        } else {
            /* Profile inactive: S2 evaluator off; still pass-local lex OK. */
            class_status = NINLIL_OK;
        }
        if (class_status != NINLIL_OK) {
            return class_status;
        }

        /* D3-S1 evaluator off under S2/S3. D3-S2/S3 H1 when profile exact. */
        if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S2
            && session->bound_d3s2_context != NULL
            && session->profile_exact_active != 0u
            && session->profile_mismatch == 0u
            && session->future_profile_candidate == 0u
            && !is_exact_family14_catalog_key(workspace->key, key_length)
            && !is_family14_prefix_noncatalog(workspace->key, key_length)) {
            class_status = ninlil_domain_scan_d3s2_on_row(
                session, workspace, key_length, value_length, typed_current_ok);
            if (class_status != NINLIL_OK) {
                return class_status;
            }
        }
        if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S3
            && session->bound_d3s3_context != NULL
            && session->profile_exact_active != 0u
            && session->profile_mismatch == 0u
            && session->future_profile_candidate == 0u
            && !is_exact_family14_catalog_key(workspace->key, key_length)
            && !is_family14_prefix_noncatalog(workspace->key, key_length)) {
            /*
             * §18.14.9.5 visit commit: under PASS_INTERNAL, every S3 internal
             * W and WG — after successful current-row structural acceptance
             * and before the S3 cross-row hook — commits only pass-local
             * has_previous + previous_key/length exactly once. Applies to
             * FOCUS/SELECT/SEMANTIC pure-W and BIND_MAN/BIND_CHUNK WG alike
             * so a FOCUS semantic CORRUPT (e.g. dig-match owner_raw mismatch)
             * retains the failing row's complete key. Natural GET fault or
             * BIND semantic CORRUPT retains the same lex commit; public D2
             * counters and profile/family diagnostics stay frozen. No commit
             * on structural validation failure (above) or failed iter_next.
             * S2 stays post-hook only (no pre-hook path). workspace->key is
             * not invalidated by D2-S4 exact_get (value only).
             */
            (void)memcpy(workspace->previous_key, workspace->key, key_length);
            session->previous_key_length = key_length;
            session->has_previous = 1u;
            class_status = ninlil_domain_scan_d3s3_on_row(
                session, workspace, key_length, value_length, typed_current_ok);
            if (class_status != NINLIL_OK) {
                return class_status;
            }
        }

        /*
         * Pass-local previous_key only. S2 and S3 both freeze ok_row_count /
         * current_domain_key_count / family14 under PASS_INTERNAL.
         * S3 pre-hook may already have committed above; re-copy is
         * idempotent (same key_length / bytes) on the success path.
         */
        (void)memcpy(workspace->previous_key, workspace->key, key_length);
        session->previous_key_length = key_length;
        session->has_previous = 1u;
        return NINLIL_OK;
    }

    if (is_exact_family14_catalog_key(workspace->key, key_length)) {
        if (session->profile_reconciliation != 0u) {
            class_status = reconcile_catalog_row(
                session, workspace, key_length, value_length);
        } else if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S3) {
            /*
             * S3 REP1: family14 seeded complete at begin (B0). Catalog visits
             * during BASELINE W are budget/lex only — no re-count / re-bit.
             */
            class_status = NINLIL_OK;
        } else {
            class_status = checked_inc_u64(&session->family14_row_count);
        }
    } else if (is_family14_prefix_noncatalog(workspace->key, key_length)) {
        class_status = NINLIL_E_STORAGE_CORRUPT;
    } else if (session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        /* Non-family1-4 skip: no classify_row / domain body decode (S3 off). */
        class_status = NINLIL_OK;
    } else if (session->profile_exact_active != 0u) {
        /* D2-S3: exact profile → family 5/6 structural same-record. */
        class_status = validate_current_domain_structural(
            session, workspace, key_length, value_length, &typed_current_ok);
    } else {
        /* S1 transport begin: coarse class only; no body validation. */
        class_status = classify_ok_row(
            session, workspace, key_length, value_length);
    }
    if (class_status != NINLIL_OK) {
        return class_status;
    }

    /*
     * D3-S1 hybrid local leg (§18.12.7): after full CURRENT typed S3 success
     * for this exact row (typed_current_ok==1), before previous_key update
     * and ok_row_count increment. Inactive when bound_d3_context is NULL
     * (D2 begin_profiled), S2 bound, profile inactive, or row was only
     * future/skip. Sticky recognizable_future_seen is never a per-row gate.
     */
    if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S1
        && session->bound_d3_context != NULL
        && typed_current_ok != 0u
        && session->profile_exact_active != 0u
        && session->profile_mismatch == 0u
        && session->future_profile_candidate == 0u
        && !is_exact_family14_catalog_key(workspace->key, key_length)
        && !is_family14_prefix_noncatalog(workspace->key, key_length)) {
        class_status = ninlil_domain_scan_d3s1_evaluate_after_s3(
            session, workspace, key_length, value_length);
        if (class_status != NINLIL_OK) {
            return class_status;
        }
    }

    (void)memcpy(workspace->previous_key, workspace->key, key_length);
    session->previous_key_length = key_length;
    session->has_previous = 1u;
    session->ok_row_count += 1u;
    /*
     * S3 REP1 formal checkpoint: current_domain_key_count tracks successful
     * OK visits (same as ok_row_count), including family1-4 catalog rows
     * during BASELINE W. PASS_INTERNAL freezes both via the internal branch
     * above (no ok_row increment). D2/S1/S2 keep class-based current count.
     */
    if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S3) {
        session->current_domain_key_count = session->ok_row_count;
    }
    return NINLIL_OK;
}

static void bind_session(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace)
{
    session->bound_storage = storage;
    session->bound_handle_slot = inout_handle;
    session->bound_workspace = workspace;
    /* D2-only begin leaves D3 inactive; d3s1/d3s2 begin sets after bind. */
    session->bound_d3_context = NULL;
    session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_NONE;
    session->bound_handle_value = *inout_handle;
    session->original_handle_authority = 1u;
}

static ninlil_status_t open_zero_prefix_iterator(
    ninlil_domain_scan_session_t *session)
{
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_bytes_view_t prefix;
    ninlil_status_t primary;

    prefix.data = NULL;
    prefix.length = 0u;
    storage_status = storage->iter_open(
        storage->user, session->txn, prefix, &iterator);
    if ((storage_status == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        if (iterator != NULL) {
            storage->iter_close(storage->user, iterator);
        }
        session->fence_pending = 1u;
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        return cleanup_tree(session, NINLIL_E_STORAGE_CORRUPT);
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            session->fence_pending = 1u;
        }
        primary = map_storage_status(storage_status);
        set_sticky_primary(session, primary);
        return cleanup_tree(session, primary);
    }

    session->iter = iterator;
    session->iter_live = 1u;
    session->has_previous = 0u;
    session->previous_key_length = 0u;
    session->state = NINLIL_DOMAIN_SCAN_STATE_OPEN;
    return NINLIL_OK;
}

static ninlil_status_t begin_read_only_txn(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_status_t primary;

    storage_status = storage->begin(
        storage->user, *inout_handle, NINLIL_STORAGE_READ_ONLY, &transaction);
    if ((storage_status == NINLIL_STORAGE_OK) != (transaction != NULL)) {
        if (transaction != NULL) {
            ninlil_storage_status_t cleanup = storage->rollback(
                storage->user, transaction);
            if (cleanup != NINLIL_STORAGE_OK) {
                session->cleanup_status = cleanup;
            }
        }
        session->fence_pending = 1u;
        fence_original_handle(session);
        session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            fence_original_handle(session);
        } else {
            session->original_handle_authority = 0u;
        }
        session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
        primary = map_storage_status(storage_status);
        set_sticky_primary(session, primary);
        return primary;
    }

    session->txn = transaction;
    session->txn_live = 1u;
    return NINLIL_OK;
}

/*
 * Process one Storage get result for profiled begin. Returns OK to continue
 * the 17-get loop, or a terminal status (caller must cleanup without iter).
 */
static ninlil_status_t process_profile_get_result(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_id,
    ninlil_storage_status_t storage_status,
    const ninlil_mut_bytes_t *inout_value)
{
    uint32_t index = key_id - 1u;
    uint32_t bit = 1u << index;
    uint32_t typed_cap = ENCODED_CAPS[index];
    uint8_t *slot = &workspace->encoded_values[ENCODED_OFFSETS[index]];

    if (storage_status == NINLIL_STORAGE_OK) {
        if (inout_value->length > typed_cap
            || (inout_value->length > 0u && inout_value->data == NULL)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        session->profile_get_present_mask |= bit;
        workspace->encoded_views[index].data =
            inout_value->length == 0u ? NULL : slot;
        workspace->encoded_views[index].length = inout_value->length;
        return NINLIL_OK;
    }

    if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
        if (inout_value->length != 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        workspace->encoded_views[index].data = NULL;
        workspace->encoded_views[index].length = 0u;
        return NINLIL_OK;
    }

    if (storage_status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        /* BTS: no reread / no allocation. Do not second-count length shape. */
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (!storage_status_is_known(storage_status)) {
        session->fence_pending = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (inout_value->length != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status_requires_fence(storage_status)) {
        session->fence_pending = 1u;
    }
    return map_storage_status(storage_status);
}

static ninlil_status_t profile_gate_gets_and_model(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace)
{
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_model_runtime_store_encoded_snapshot_t encoded;
    ninlil_model_runtime_store_binding_comparison_t comparison =
        NINLIL_MODEL_RUNTIME_STORE_BINDING_COMPARISON_NONE;
    ninlil_status_t model_status;
    ninlil_status_t get_status;
    uint32_t key_id;

    session->profile_get_present_mask = 0u;
    (void)memset(workspace->encoded_views, 0, sizeof(workspace->encoded_views));
    (void)memset(&workspace->validated, 0, sizeof(workspace->validated));

    for (key_id = 1u; key_id <= 17u; ++key_id) {
        ninlil_model_runtime_store_key_t key;
        ninlil_bytes_view_t key_view;
        ninlil_mut_bytes_t value;
        ninlil_storage_status_t storage_status;
        uint32_t index = key_id - 1u;

        if (ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)key_id, &key)
            != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        key_view.data = key.bytes;
        key_view.length = key.length;
        /*
         * REP1 Port GET: value_capacity is always the session value buffer
         * capacity (4096). Profile catalog values are then copied into the
         * fixed encoded_views slots (ENCODED_CAPS) for model compare.
         */
        (void)memset(&value, 0, sizeof(value));
        value.data = workspace->value;
        value.capacity = NINLIL_DOMAIN_SCAN_VALUE_CAPACITY;
        value.length = 0u;

        storage_status = storage->get(
            storage->user, session->txn, key_view, &value);
        /*
         * inout_value.data/capacity are caller-owned descriptor fields for this
         * get. A provider must not rewrite them. Unsafe shape: terminal CORRUPT
         * + fence after cleanup.
         */
        if (value.data != workspace->value
            || value.capacity != NINLIL_DOMAIN_SCAN_VALUE_CAPACITY) {
            session->fence_pending = 1u;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (storage_status == NINLIL_STORAGE_OK
            && value.length > ENCODED_CAPS[index]) {
            /* Catalog value exceeds typed slot — structural corrupt. */
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (storage_status == NINLIL_STORAGE_OK && value.length > 0u) {
            (void)memcpy(&workspace->encoded_values[ENCODED_OFFSETS[index]],
                value.data, value.length);
            /* process_profile_get_result reads inout_value for presence/mask. */
            value.data = &workspace->encoded_values[ENCODED_OFFSETS[index]];
            value.capacity = ENCODED_CAPS[index];
        } else if (storage_status == NINLIL_STORAGE_OK) {
            value.data = &workspace->encoded_values[ENCODED_OFFSETS[index]];
            value.capacity = ENCODED_CAPS[index];
        }
        get_status = process_profile_get_result(
            session, workspace, key_id, storage_status, &value);
        if (get_status != NINLIL_OK) {
            return get_status;
        }
    }

    if (session->profile_get_present_mask
        != NINLIL_DOMAIN_SCAN_PROFILE_ALL_MASK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    for (key_id = 1u; key_id <= 17u; ++key_id) {
        encoded.values[key_id - 1u] = workspace->encoded_views[key_id - 1u];
    }

    model_status = ninlil_model_runtime_store_validate_snapshot(
        &encoded, &workspace->validated);
    if (model_status == NINLIL_E_STORAGE_CORRUPT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (model_status == NINLIL_E_UNSUPPORTED) {
        session->future_profile_candidate = 1u;
        session->profile_exact_active = 0u;
        session->profile_mismatch = 0u;
        return NINLIL_OK;
    }
    if (model_status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    model_status = ninlil_model_runtime_store_compare_binding(
        &workspace->validated, &workspace->candidate, &comparison);
    if (model_status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (comparison == NINLIL_MODEL_RUNTIME_STORE_BINDING_EXACT) {
        session->profile_exact_active = 1u;
        session->profile_mismatch = 0u;
        session->future_profile_candidate = 0u;
        return NINLIL_OK;
    }
    if (comparison == NINLIL_MODEL_RUNTIME_STORE_BINDING_UNSUPPORTED) {
        session->profile_exact_active = 0u;
        session->profile_mismatch = 1u;
        session->future_profile_candidate = 0u;
        return NINLIL_OK;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

void ninlil_domain_scan_session_init(ninlil_domain_scan_session_t *session)
{
    if (session == NULL) {
        return;
    }
    /* Caller contract: only fresh/non-live storage. Not safe on live sessions. */
    (void)memset(session, 0, sizeof(*session));
    session->state = NINLIL_DOMAIN_SCAN_STATE_IDLE;
    session->sticky_primary = NINLIL_OK;
}

/*
 * Shared profiled begin body after entry-specific prevalidation.
 * d3s1 NULL and d3s2 NULL → D2-only.
 * Exactly one of d3s1/d3s2 may be non-NULL (dual-bound forbidden).
 * On any failure path after bind, clear bound D3 pointers (non-owning).
 * No nullable skip of D3 when context is provided.
 */
static ninlil_status_t begin_profiled_common(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    ninlil_domain_scan_d3s1_context_t *d3s1_context,
    uint8_t d3s1_mode,
    ninlil_domain_scan_d3s2_context_t *d3s2_context,
    uint8_t d3s2_mode,
    ninlil_domain_scan_d3s3_context_t *d3s3_context,
    uint8_t d3s3_mode)
{
    ninlil_status_t status;
    int nbound = 0;

    /* Bind + candidate copy before any Port call; never retain caller ptr. */
    bind_session(session, storage, inout_handle, workspace);
    if (d3s1_context != NULL) {
        nbound += 1;
    }
    if (d3s2_context != NULL) {
        nbound += 1;
    }
    if (d3s3_context != NULL) {
        nbound += 1;
    }
    if (nbound > 1) {
        /* Dual/triple-bound is illegal; defensive. */
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (d3s1_context != NULL) {
        session->bound_d3_context = d3s1_context;
        session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_S1;
        /*
         * Successful D3-S1 begin: zero control/length/flags so stale caller
         * poison cannot leak into the first evaluate. Prevalidation failure
         * paths never reach here (mode 0/>20 / alias leave context untouched).
         */
        d3s1_context->mode = d3s1_mode;
        d3s1_context->peer_key_len = 0u;
        d3s1_context->source_raw_len = 0u;
        d3s1_context->source_raw2_len = 0u;
        d3s1_context->source_aux_len = 0u;
        d3s1_context->flags = 0u;
        d3s1_context->source_subtype = 0u;
        d3s1_context->expect_presence = 0u;
        d3s1_context->owner_kind = 0u;
    }
    if (d3s2_context != NULL) {
        session->bound_d3s2_context = d3s2_context;
        session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_S2;
        /*
         * Successful D3-S2 begin: zero multipass control so stale poison
         * cannot leak. focus_mode immutable after begin. pass_kind BASELINE.
         */
        (void)memset(d3s2_context, 0, sizeof(*d3s2_context));
        d3s2_context->focus_mode = d3s2_mode;
        d3s2_context->pass_kind = NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE;
        d3s2_context->phase = NINLIL_DOMAIN_SCAN_D3S2_PHASE_BASELINE;
    }
    if (d3s3_context != NULL) {
        session->bound_d3s3_context = d3s3_context;
        session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_S3;
        (void)memset(d3s3_context, 0, sizeof(*d3s3_context));
        d3s3_context->focus_mode = d3s3_mode;
        d3s3_context->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_BASELINE;
        d3s3_context->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BASELINE;
    }
    (void)memcpy(&workspace->candidate, candidate, sizeof(workspace->candidate));

    status = begin_read_only_txn(session, storage, inout_handle);
    if (status != NINLIL_OK) {
        session->bound_d3_context = NULL;
        session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_NONE;
        return status;
    }

    status = profile_gate_gets_and_model(session, workspace);
    if (status != NINLIL_OK) {
        set_sticky_primary(session, status);
        session->bound_d3_context = NULL;
        session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_NONE;
        return cleanup_tree(session, status);
    }

    session->profile_reconciliation = 1u;
    session->family14_iter_seen_mask = 0u;
    status = open_zero_prefix_iterator(session);
    if (status != NINLIL_OK) {
        session->bound_d3_context = NULL;
        session->bound_d3_kind = NINLIL_DOMAIN_SCAN_D3_KIND_NONE;
        return status;
    }

    /*
     * D3-S3 REP1-L2 B0 (docs/17 §18.14.19.8 / ADR-0015):
     * Successful begin emits begin+17×get+iter_open and leaves the session
     * OPEN/BASELINE with flags 0x00. profile_exact_active is deferred until
     * true-exhaustion BASELINE W (B1). family14 counters are seeded as
     * begin-complete (oracle/reference profile); BASELINE W must not
     * re-reconcile or double-count catalog rows.
     * D2 / D3-S1 / D3-S2 begin paths are unchanged.
     */
    if (d3s3_context != NULL) {
        if (session->profile_get_present_mask
            == NINLIL_DOMAIN_SCAN_PROFILE_ALL_MASK) {
            session->family14_iter_seen_mask =
                NINLIL_DOMAIN_SCAN_PROFILE_ALL_MASK;
            session->family14_row_count = 17u;
            session->profile_reconciliation = 0u;
        }
        session->profile_exact_active = 0u;
    }
    return status;
}

ninlil_status_t ninlil_domain_scan_begin_profiled(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate)
{
    if (session == NULL || workspace == NULL || inout_handle == NULL
        || candidate == NULL
        || !storage_ops_required_nonnull(storage)
        || *inout_handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!begin_profiled_alias_ok(
            session, storage, inout_handle, workspace, candidate)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }

    return begin_profiled_common(
        session, storage, inout_handle, workspace, candidate, NULL, 0u, NULL,
        0u, NULL, 0u);
}

ninlil_status_t ninlil_domain_scan_begin_profiled_d3s1(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s1_context_t *context)
{
    if (session == NULL || workspace == NULL || inout_handle == NULL
        || candidate == NULL || context == NULL
        || !storage_ops_required_nonnull(storage)
        || *inout_handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (mode < NINLIL_DOMAIN_SCAN_D3S1_MODE_MIN
        || mode > NINLIL_DOMAIN_SCAN_D3S1_MODE_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Modes 1..20 implemented (chunk-C). Mode 0/>20 already rejected above. */
    if (!begin_profiled_d3s1_alias_ok(
            session, storage, inout_handle, workspace, candidate, context)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }

    return begin_profiled_common(
        session, storage, inout_handle, workspace, candidate, context, mode,
        NULL, 0u, NULL, 0u);
}

ninlil_status_t ninlil_domain_scan_begin_profiled_d3s2(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s2_context_t *context)
{
    if (session == NULL || workspace == NULL || inout_handle == NULL
        || candidate == NULL || context == NULL
        || !storage_ops_required_nonnull(storage)
        || *inout_handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (mode < NINLIL_DOMAIN_SCAN_D3S2_MODE_MIN
        || mode > NINLIL_DOMAIN_SCAN_D3S2_MODE_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!begin_profiled_d3s2_alias_ok(
            session, storage, inout_handle, workspace, candidate, context)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }

    return begin_profiled_common(
        session, storage, inout_handle, workspace, candidate, NULL, 0u, context,
        mode, NULL, 0u);
}

ninlil_status_t ninlil_domain_scan_begin_profiled_d3s3(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s3_context_t *context)
{
    if (session == NULL || workspace == NULL || inout_handle == NULL
        || candidate == NULL || context == NULL
        || !storage_ops_required_nonnull(storage)
        || *inout_handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (mode < NINLIL_DOMAIN_SCAN_D3S3_MODE_MIN
        || mode > NINLIL_DOMAIN_SCAN_D3S3_MODE_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!begin_profiled_d3s3_alias_ok(
            session, storage, inout_handle, workspace, candidate, context)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }

    return begin_profiled_common(
        session, storage, inout_handle, workspace, candidate, NULL, 0u, NULL,
        0u, context, mode);
}

ninlil_status_t ninlil_domain_scan_reopen_zero_prefix_iter(
    ninlil_domain_scan_session_t *session)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_bytes_view_t prefix;
    ninlil_status_t primary;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN
        && session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (session->has_sticky_primary != 0u
        || session->txn_live == 0u
        || session->bound_storage == NULL
        || session->bound_workspace == NULL
        || !storage_ops_required_nonnull(session->bound_storage)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (handle_slot_exact_match(session) == 0) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->fence_pending = 1u;
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    storage = session->bound_storage;
    if (session->iter_live != 0u) {
        storage->iter_close(storage->user, session->iter);
        session->iter = NULL;
        session->iter_live = 0u;
    }

    prefix.data = NULL;
    prefix.length = 0u;
    storage_status = storage->iter_open(
        storage->user, session->txn, prefix, &iterator);
    if ((storage_status == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        if (iterator != NULL) {
            storage->iter_close(storage->user, iterator);
        }
        session->fence_pending = 1u;
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            session->fence_pending = 1u;
        }
        primary = map_storage_status(storage_status);
        set_sticky_primary(session, primary);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return primary;
    }

    session->iter = iterator;
    session->iter_live = 1u;
    session->has_previous = 0u;
    session->previous_key_length = 0u;
    session->state = NINLIL_DOMAIN_SCAN_STATE_OPEN;
    /* Pass-local lex only; frozen D2 counters/profile/future untouched. */
    return NINLIL_OK;
}

#if defined(NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN)
ninlil_status_t ninlil_domain_scan_begin(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace)
{
    ninlil_status_t status;

    if (session == NULL || workspace == NULL || inout_handle == NULL
        || !storage_ops_required_nonnull(storage)
        || *inout_handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!begin_alias_ok(session, storage, inout_handle, workspace)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }

    /* Bind before any Port call so cleanup always uses the correct provider. */
    bind_session(session, storage, inout_handle, workspace);

    status = begin_read_only_txn(session, storage, inout_handle);
    if (status != NINLIL_OK) {
        return status;
    }

    /* S1 transport: no get / no profile gate. */
    session->profile_reconciliation = 0u;
    session->profile_exact_active = 0u;
    session->profile_mismatch = 0u;
    session->future_profile_candidate = 0u;
    session->profile_get_present_mask = 0u;
    session->family14_iter_seen_mask = 0u;
    return open_zero_prefix_iterator(session);
}
#endif /* NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN */

ninlil_status_t ninlil_domain_scan_advance(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget)
{
    uint32_t consumed = 0u;
    const ninlil_storage_ops_t *storage;
    ninlil_domain_scan_workspace_t *workspace;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        return NINLIL_E_INVALID_STATE;
    }
    if (row_budget == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    storage = session->bound_storage;
    workspace = session->bound_workspace;
    if (storage == NULL || workspace == NULL
        || session->bound_handle_slot == NULL
        || !storage_ops_required_nonnull(storage)) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (handle_slot_exact_match(session) == 0) {
        /*
         * Drift (NULL or foreign while authority live): fail closed.
         * Cleanup later closes the ORIGINAL bound handle only, never foreign.
         */
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->fence_pending = 1u;
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (session->iter_live == 0u || session->txn_live == 0u) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    while (consumed < row_budget) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;
        ninlil_storage_status_t storage_status;
        ninlil_status_t row_status;

        (void)memset(&key, 0, sizeof(key));
        (void)memset(&value, 0, sizeof(value));
        key.data = workspace->key;
        key.capacity = NINLIL_DOMAIN_SCAN_KEY_CAPACITY;
        key.length = 0u;
        value.data = workspace->value;
        value.capacity = NINLIL_DOMAIN_SCAN_VALUE_CAPACITY;
        value.length = 0u;

        storage_status = storage->iter_next(
            storage->user, session->iter, &key, &value);

        /*
         * inout_key/inout_value data+capacity are caller-owned descriptors for
         * this iter_next (§15.3). Provider rewrite is unsafe shape: CORRUPT +
         * fence after cleanup (same policy as get inout_value descriptors).
         */
        if (key.data != workspace->key
            || key.capacity != NINLIL_DOMAIN_SCAN_KEY_CAPACITY
            || value.data != workspace->value
            || value.capacity != NINLIL_DOMAIN_SCAN_VALUE_CAPACITY) {
            session->fence_pending = 1u;
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return NINLIL_E_STORAGE_CORRUPT;
            }
            /*
             * Family1-4 reconciliation once on baseline only. PASS_INTERNAL
             * freezes the mask; re-check still holds equality if baseline
             * completed cleanly, but must not re-run reconciliation logic.
             */
            if (session->profile_reconciliation != 0u
                && !d3_pass_internal_active(session)
                && session->family14_iter_seen_mask
                    != session->profile_get_present_mask) {
                set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return NINLIL_E_STORAGE_CORRUPT;
            }
            session->state = NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED;
            /*
             * H2: after state=EXHAUSTED, before return OK (§18.13.10).
             * FOCUS stream close only; known-slot uses B6k, not H2.
             */
            if (d3_pass_internal_active(session)) {
                ninlil_status_t h2 = NINLIL_OK;
                if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S2) {
                    h2 = ninlil_domain_scan_d3s2_on_exhausted(session);
                } else if (session->bound_d3_kind
                    == NINLIL_DOMAIN_SCAN_D3_KIND_S3) {
                    h2 = ninlil_domain_scan_d3s3_on_exhausted(session);
                }
                if (h2 != NINLIL_OK) {
                    return h2;
                }
            }
            return NINLIL_OK;
        }

        if (storage_status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (storage_status == NINLIL_STORAGE_OK) {
            if (key.length < 1u
                || key.length > key.capacity
                || key.length > NINLIL_DOMAIN_SCAN_KEY_CAPACITY
                || value.length > value.capacity
                || value.length > NINLIL_DOMAIN_SCAN_VALUE_CAPACITY
                || (value.length != 0u && value.data == NULL)) {
                set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return NINLIL_E_STORAGE_CORRUPT;
            }

            row_status = process_ok_row(
                session, workspace, key.length, value.length);
            if (row_status != NINLIL_OK) {
                set_sticky_primary(session, row_status);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return row_status;
            }
            consumed += 1u;
            continue;
        }

        if (key.length != 0u || value.length != 0u) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (storage_status_requires_fence(storage_status)
            || !storage_status_is_known(storage_status)) {
            session->fence_pending = 1u;
        }
        if (!storage_status_is_known(storage_status)) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        row_status = map_storage_status(storage_status);
        set_sticky_primary(session, row_status);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return row_status;
    }

    return NINLIL_OK;
}

/*
 * S4: key may borrow external storage or workspace->key / previous_key only.
 * Must be disjoint from workspace->value (output) and from out_result.
 * Other workspace regions are not legal key aliases (§15.11.3).
 */
static int exact_get_key_region_ok(
    const ninlil_domain_scan_workspace_t *workspace,
    ninlil_bytes_view_t key)
{
    uintptr_t key_start;
    uintptr_t key_end;
    uintptr_t ws_start;
    uintptr_t ws_end;
    uintptr_t allow_key_start;
    uintptr_t allow_key_end;
    uintptr_t allow_prev_start;
    uintptr_t allow_prev_end;

    if (key.data == NULL || key.length == 0u
        || key.length > NINLIL_DOMAIN_SCAN_KEY_CAPACITY) {
        return 0;
    }
    key_start = (uintptr_t)key.data;
    if (key.length > UINTPTR_MAX - key_start) {
        return 0;
    }
    key_end = key_start + key.length;
    ws_start = (uintptr_t)workspace;
    ws_end = ws_start + sizeof(*workspace);
    allow_key_start = (uintptr_t)workspace->key;
    allow_key_end = allow_key_start + NINLIL_DOMAIN_SCAN_KEY_CAPACITY;
    allow_prev_start = (uintptr_t)workspace->previous_key;
    allow_prev_end =
        allow_prev_start + NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY;

    if (!ranges_are_disjoint(
            key.data,
            key.length,
            workspace->value,
            NINLIL_DOMAIN_SCAN_VALUE_CAPACITY)) {
        return 0;
    }

    /* Outside full workspace object: external storage is fine. */
    if (key_end <= ws_start || key_start >= ws_end) {
        return 1;
    }

    /* Inside workspace: only key[] or previous_key[] are legal. */
    if (key_start >= allow_key_start && key_end <= allow_key_end) {
        return 1;
    }
    if (key_start >= allow_prev_start && key_end <= allow_prev_end) {
        return 1;
    }
    return 0;
}

/*
 * Caller key/out alias only. Live-session authority (null bound_* / ops /
 * txn_live / iter_live) is checked before this and maps to STORAGE_CORRUPT.
 * Requires non-null bound fields established by that earlier gate.
 */
static int exact_get_alias_ok(
    const ninlil_domain_scan_session_t *session,
    ninlil_bytes_view_t key,
    const ninlil_domain_scan_exact_get_result_t *out_result)
{
    const size_t result_bytes = sizeof(*out_result);
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_storage_handle_t *handle_slot = session->bound_handle_slot;
    ninlil_domain_scan_workspace_t *workspace = session->bound_workspace;

    if (!exact_get_key_region_ok(workspace, key)) {
        return 0;
    }
    if (!ranges_are_disjoint(key.data, key.length, out_result, result_bytes)) {
        return 0;
    }
    if (!ranges_are_disjoint(
            session, sizeof(*session), out_result, result_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), out_result, result_bytes)
        || !ranges_are_disjoint(
            storage, sizeof(*storage), out_result, result_bytes)
        || !ranges_are_disjoint(
            handle_slot, sizeof(*handle_slot), out_result, result_bytes)) {
        return 0;
    }
    return 1;
}

static void publish_exact_get_success(
    ninlil_domain_scan_exact_get_result_t *out_result,
    ninlil_domain_scan_exact_presence_t presence,
    const uint8_t *value_data,
    uint32_t value_length)
{
    out_result->presence = presence;
    if (presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT && value_length > 0u) {
        out_result->value.data = value_data;
        out_result->value.length = value_length;
    } else {
        /* ABSENT, or PRESENT with zero length: empty view. */
        out_result->value.data = NULL;
        out_result->value.length = 0u;
    }
}

ninlil_status_t ninlil_domain_scan_exact_get(
    ninlil_domain_scan_session_t *session,
    ninlil_bytes_view_t key,
    ninlil_domain_scan_exact_get_result_t *out_result)
{
    const ninlil_storage_ops_t *storage;
    ninlil_domain_scan_workspace_t *workspace;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t storage_status;
    ninlil_status_t mapped;

    if (session == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN
        && session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (key.data == NULL || key.length < 1u
        || key.length > NINLIL_DOMAIN_SCAN_KEY_CAPACITY) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /*
     * Live-session authority (OPEN/EXHAUSTED): null/missing bound fields,
     * missing required ops, or txn_live/iter_live=0 is corrupted authority.
     * Checked before alias validation so sticky STORAGE_CORRUPT is not masked
     * as INVALID_ARGUMENT (same Port-0 sticky FAILED policy as advance).
     */
    storage = session->bound_storage;
    workspace = session->bound_workspace;
    if (storage == NULL || workspace == NULL
        || session->bound_handle_slot == NULL
        || !storage_ops_required_nonnull(storage)
        || session->iter_live == 0u || session->txn_live == 0u) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (handle_slot_exact_match(session) == 0) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->fence_pending = 1u;
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    /* Invalid caller key/out alias: session and out_result unchanged. */
    if (!exact_get_alias_ok(session, key, out_result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&value, 0, sizeof(value));
    value.data = workspace->value;
    value.capacity = NINLIL_DOMAIN_SCAN_VALUE_CAPACITY;
    value.length = 0u;

    storage_status = storage->get(storage->user, session->txn, key, &value);

    /*
     * inout_value.data/capacity are caller-owned for this get. Provider rewrite
     * is unsafe shape: terminal CORRUPT + always fence after cleanup (§15.11.5).
     */
    if (value.data != workspace->value
        || value.capacity != NINLIL_DOMAIN_SCAN_VALUE_CAPACITY) {
        session->fence_pending = 1u;
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (storage_status == NINLIL_STORAGE_OK) {
        if (value.length > value.capacity
            || value.length > NINLIL_DOMAIN_SCAN_VALUE_CAPACITY
            || (value.length > 0u && value.data == NULL)) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        publish_exact_get_success(
            out_result,
            NINLIL_DOMAIN_SCAN_EXACT_PRESENT,
            workspace->value,
            value.length);
        return NINLIL_OK;
    }

    if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
        if (value.length != 0u) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        publish_exact_get_success(
            out_result, NINLIL_DOMAIN_SCAN_EXACT_ABSENT, NULL, 0u);
        return NINLIL_OK;
    }

    if (storage_status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        /* BTS: no reread / no allocation. Do not second-count length shape. */
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    /*
     * Combined raw-status / shape precedence (§15.11.5):
     * - Status that requires fence (COMMIT_UNKNOWN or unknown) sets
     *   fence_pending even when length shape is also malformed.
     * - Shape poison (non-zero length on non-OK, BTS excluded) yields
     *   STORAGE_CORRUPT rather than the mapped port status.
     * - Descriptor rewrite always fences (handled above).
     */
    if (storage_status_requires_fence(storage_status)
        || !storage_status_is_known(storage_status)) {
        session->fence_pending = 1u;
    }
    if (!storage_status_is_known(storage_status) || value.length != 0u) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    mapped = map_storage_status(storage_status);
    set_sticky_primary(session, mapped);
    session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
    return mapped;
}

ninlil_status_t ninlil_domain_scan_note_terminal_corrupt(
    ninlil_domain_scan_session_t *session)
{
    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN
        && session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        /* IDLE / DONE / FAILED: no mutation, Port 0. */
        return NINLIL_E_INVALID_STATE;
    }

    /*
     * Legal OPEN/EXHAUSTED: Port 0, no cleanup/fence. First sticky only.
     * Preserve all candidate/future flags, counters, previous key, workspace,
     * iter/txn ownership, and binding authority (§15.12.2).
     */
    set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
    session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
    return NINLIL_E_STORAGE_CORRUPT;
}

ninlil_status_t ninlil_domain_scan_finalize(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result)
{
    ninlil_status_t cleanup_outcome;
    ninlil_status_t final_status;
    uint32_t adopted = 0u;
    ninlil_domain_scan_state_t prior_state;

    if (session == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        && session->state != NINLIL_DOMAIN_SCAN_STATE_FAILED) {
        return NINLIL_E_INVALID_STATE;
    }
    /* Alias check before any cleanup/output mutation. */
    if (!result_alias_ok(session, out_result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /*
     * D3-S2 incomplete machine: EXHAUSTED alone is not adopt-ready.
     * Ordinary path requires phase COMPLETE + COMPLETE_READY before cleanup
     * (count+BIND proof). Narrow evaluator-off exemption (not a wide
     * !profile_exact_active bypass): baseline-only shape after true D2
     * EXHAUSTED with profile_mismatch or future_profile_candidate set —
     * S2 evaluator was never applicable; finalize continues to cleanup and
     * aggregate UNSUPPORTED/adopted0. recognizable_future_seen alone is not
     * an exemption. Port 0; session/context/out_result unchanged on reject.
     * FAILED cleanup still proceeds (sticky/failed paths are not false-green).
     */
    if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S2
        && session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        const ninlil_domain_scan_d3s2_context_t *s2 =
            session->bound_d3s2_context;
        int ordinary_complete;
        int evaluator_off_exempt;

        ordinary_complete = (s2 != NULL
            && s2->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
            && (s2->flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY)
                != 0u);
        evaluator_off_exempt = (s2 != NULL
            && session->has_sticky_primary == 0u
            && session->profile_exact_active == 0u
            && ((session->profile_mismatch == 1u
                    && session->future_profile_candidate == 0u)
                || (session->profile_mismatch == 0u
                    && session->future_profile_candidate == 1u))
            && s2->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BASELINE
            && s2->pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE
            && s2->flags == NINLIL_DOMAIN_SCAN_D3S2_FLAG_BASELINE_DONE
            && s2->count_complete_mask == 0u
            && s2->binding_complete_mask == 0u);
        if (!ordinary_complete && !evaluator_off_exempt) {
            return NINLIL_E_INVALID_STATE;
        }
    }

    /* D3-S3 incomplete machine: same COMPLETE gate spirit as S2. */
    if (session->bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S3
        && session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        const ninlil_domain_scan_d3s3_context_t *s3 =
            session->bound_d3s3_context;
        int ordinary_complete;
        int evaluator_off_exempt;

        ordinary_complete = (s3 != NULL
            && s3->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE
            && (s3->flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_COMPLETE_READY)
                != 0u);
        evaluator_off_exempt = (s3 != NULL
            && session->has_sticky_primary == 0u
            && session->profile_exact_active == 0u
            && ((session->profile_mismatch == 1u
                    && session->future_profile_candidate == 0u)
                || (session->profile_mismatch == 0u
                    && session->future_profile_candidate == 1u))
            && s3->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BASELINE
            && s3->pass_kind == NINLIL_DOMAIN_SCAN_D3S3_PASS_BASELINE
            && s3->flags == NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            && s3->count_complete_mask == 0u
            && s3->binding_complete_mask == 0u);
        if (!ordinary_complete && !evaluator_off_exempt) {
            return NINLIL_E_INVALID_STATE;
        }
    }

    prior_state = session->state;
    cleanup_outcome = cleanup_tree(session, NINLIL_OK);
    final_status = aggregate_finalize_outcome(session, cleanup_outcome);

    if (prior_state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        && session->has_sticky_primary == 0u
        && session->profile_mismatch == 0u
        && session->future_profile_candidate == 0u
        && session->recognizable_future_seen == 0u
        && cleanup_outcome == NINLIL_OK
        && final_status == NINLIL_OK
        && session->reopen_required == 0u) {
        adopted = 1u;
    }

    publish_result(session, out_result, final_status, adopted);
    return final_status;
}

ninlil_status_t ninlil_domain_scan_abort(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result)
{
    ninlil_status_t cleanup_outcome;
    ninlil_status_t final_status;

    if (session == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN
        && session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        && session->state != NINLIL_DOMAIN_SCAN_STATE_FAILED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (!result_alias_ok(session, out_result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    cleanup_outcome = cleanup_tree(session, NINLIL_OK);
    if (session->has_sticky_primary != 0u) {
        final_status = session->sticky_primary;
    } else if (cleanup_outcome != NINLIL_OK) {
        final_status = cleanup_outcome;
    } else {
        final_status = NINLIL_OK;
    }
    publish_result(session, out_result, final_status, 0u);
    return final_status;
}
