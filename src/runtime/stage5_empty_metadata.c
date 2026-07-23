#include "stage5_empty_metadata.h"

#include "runtime_store_bootstrap.h"
#include "v1_durable_allowlist.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Packed bootstrap-17 value slots (same layout as domain scanner S2). */
static const uint16_t BOOTSTRAP_ENCODED_OFFSETS[17] = {
    0u, 183u, 267u, 299u, 331u, 363u, 395u, 463u, 531u, 599u, 667u, 735u,
    803u, 871u, 939u, 1007u, 1075u
};
static const uint16_t BOOTSTRAP_ENCODED_CAPS[17] = {
    183u, 84u, 32u, 32u, 32u, 32u, 68u, 68u, 68u, 68u, 68u, 68u, 68u, 68u,
    68u, 68u, 68u
};

static const ninlil_model_runtime_store_key_id_t MEMBER_KEYS[
    NINLIL_STAGE5_EMPTY_HEAD_INDEX_COUNT] = {
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ASSIGNED_OWNER,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TRANSACTION,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TARGET,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_COUNT,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_BYTES,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_RESULT_CACHE,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVIDENCE,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_INGRESS,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN
};

static int storage_ops_required(
    const ninlil_storage_ops_t *storage,
    int need_commit_put)
{
    if (storage == NULL || storage->begin == NULL || storage->get == NULL
        || storage->rollback == NULL || storage->close == NULL
        || storage->iter_open == NULL || storage->iter_next == NULL
        || storage->iter_close == NULL) {
        return 0;
    }
    if (need_commit_put != 0
        && (storage->put == NULL || storage->commit == NULL)) {
        return 0;
    }
    return 1;
}

static int storage_status_is_known(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_OK
        || status == NINLIL_STORAGE_NOT_FOUND
        || status == NINLIL_STORAGE_BUSY
        || status == NINLIL_STORAGE_NO_SPACE
        || status == NINLIL_STORAGE_IO_ERROR
        || status == NINLIL_STORAGE_CORRUPT
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL
        || status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA
        || status == NINLIL_STORAGE_COMMIT_UNKNOWN;
}

static int storage_status_requires_fence(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_COMMIT_UNKNOWN
        || !storage_status_is_known(status);
}

/* Sticky OR: never clear a prior fence_pending bit. */
static void fence_or(uint32_t *inout_fence, int need)
{
    if (need != 0 && inout_fence != NULL) {
        *inout_fence = 1u;
    }
}

static ninlil_status_t map_storage_to_public(ninlil_storage_status_t status)
{
    switch (status) {
    case NINLIL_STORAGE_OK:
        return NINLIL_OK;
    case NINLIL_STORAGE_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_STORAGE_NO_SPACE:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    case NINLIL_STORAGE_IO_ERROR:
        return NINLIL_E_STORAGE;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        return NINLIL_E_UNSUPPORTED;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    default:
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

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

/*
 * Pairwise alias + validation authority guard.
 * On failure leave out_result untouched (no result_init, Port 0).
 */
static int prevalidate_common(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result,
    int need_commit_put)
{
    if (!storage_ops_required(storage, need_commit_put)
        || inout_handle == NULL || *inout_handle == NULL
        || accepted_validation == NULL
        || accepted_validation->status != NINLIL_OK
        || workspace == NULL || out_result == NULL) {
        return 0;
    }
    if (!ranges_are_disjoint(out_result, sizeof(*out_result),
            storage, sizeof(*storage))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            accepted_validation, sizeof(*accepted_validation))
        || !ranges_are_disjoint(workspace, sizeof(*workspace),
            storage, sizeof(*storage))
        || !ranges_are_disjoint(workspace, sizeof(*workspace),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(workspace, sizeof(*workspace),
            accepted_validation, sizeof(*accepted_validation))
        || !ranges_are_disjoint(storage, sizeof(*storage),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(storage, sizeof(*storage),
            accepted_validation, sizeof(*accepted_validation))
        || !ranges_are_disjoint(inout_handle, sizeof(*inout_handle),
            accepted_validation, sizeof(*accepted_validation))) {
        return 0;
    }
    return 1;
}

static void result_init(ninlil_stage5_empty_metadata_result_t *out_result)
{
    (void)memset(out_result, 0, sizeof(*out_result));
}

static void fence_handle(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    if (inout_handle == NULL || *inout_handle == NULL) {
        if (out_result != NULL) {
            out_result->reopen_required = 1u;
        }
        return;
    }
    if (storage != NULL && storage->close != NULL) {
        storage->close(storage->user, *inout_handle);
    }
    *inout_handle = NULL;
    if (out_result != NULL) {
        out_result->reopen_required = 1u;
    }
}

/*
 * Pre-commit / RO cleanup: always consume ACTIVE txn via rollback.
 *
 * docs/14 L374 / L220:
 *   - primary != OK: keep primary; record cleanup_status; fence on rb fail
 *   - primary == OK: adopt only if rollback OK; else map rollback + fence
 *   - fence_pending from earlier Port status/shape is applied after txn
 *     consume (never dropped)
 */
static ninlil_status_t rollback_finish(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_storage_txn_t txn,
    ninlil_status_t primary,
    uint32_t fence_pending,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    ninlil_storage_status_t rb;

    if (txn == NULL || storage == NULL || storage->rollback == NULL) {
        if (fence_pending != 0u) {
            fence_handle(storage, inout_handle, out_result);
        }
        return primary;
    }
    rb = storage->rollback(storage->user, txn);
    if (rb != NINLIL_STORAGE_OK) {
        if (out_result != NULL) {
            out_result->cleanup_status = rb;
        }
        fence_handle(storage, inout_handle, out_result);
        if (primary != NINLIL_OK) {
            return primary;
        }
        return map_storage_to_public(rb);
    }
    if (fence_pending != 0u) {
        fence_handle(storage, inout_handle, out_result);
    }
    return primary;
}

/*
 * docs/14: commit consumes txn for every status. Never rollback after.
 * Fence on COMMIT_UNKNOWN / unknown (no convergence here).
 */
static ninlil_status_t commit_and_map(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_storage_txn_t txn,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    ninlil_storage_status_t st;
    ninlil_status_t mapped;

    st = storage->commit(storage->user, txn, NINLIL_DURABILITY_FULL);
    mapped = map_storage_to_public(st);
    if (storage_status_requires_fence(st)) {
        fence_handle(storage, inout_handle, out_result);
    }
    return mapped;
}

static int id_is_nonzero(const ninlil_id128_t *id)
{
    size_t i;

    if (id == NULL) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        if (id->bytes[i] != 0u) {
            return 1;
        }
    }
    return 0;
}

/*
 * get mapping (docs/14 MB3 / §372 / §374):
 *
 * Natural BUFFER_TOO_SMALL: data/capacity unchanged; required length may
 * exceed provided capacity (valid shape per MB3). Oversized for this
 * private workspace → CORRUPT / no reread / no retry (§372), but not a
 * handle-fence reason by itself (§374).
 *
 * Fence (sticky OR; status fence before early returns):
 *   - COMMIT_UNKNOWN / unknown status
 *   - descriptor rewrite (data/capacity)
 *   - NOT_FOUND / known non-OK with non-zero length (status-inconsistent)
 *   - OK with length > capacity (invalid OK shape)
 * Natural NOT_FOUND (length 0) / known non-OK (length 0) / natural BTS
 * do not fence unless status requires fence or descriptor is rewritten.
 */
static ninlil_status_t storage_get_exact(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    uint8_t *buffer,
    uint32_t capacity,
    uint32_t *out_length,
    uint32_t *inout_fence)
{
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t st;
    uint8_t *const expected_data = buffer;
    const uint32_t expected_capacity = capacity;

    if (storage == NULL || storage->get == NULL || buffer == NULL
        || out_length == NULL || capacity == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    value.data = buffer;
    value.capacity = capacity;
    value.length = 0u;
    st = storage->get(storage->user, txn, key, &value);
    /* Status-derived fence first — before any length/shape early return. */
    fence_or(inout_fence, storage_status_requires_fence(st));

    /* Provider must not rewrite caller-owned descriptor fields. */
    if (value.data != expected_data || value.capacity != expected_capacity) {
        fence_or(inout_fence, 1);
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (st == NINLIL_STORAGE_NOT_FOUND) {
        if (value.length != 0u) {
            fence_or(inout_fence, 1);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_E_NOT_FOUND;
    }
    if (st == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        /*
         * docs/14 MB3: required length > capacity is natural when
         * data/capacity unchanged. §372 CORRUPT/no-reread; §374 no fence.
         */
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (st != NINLIL_STORAGE_OK) {
        if (value.length != 0u) {
            fence_or(inout_fence, 1);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return map_storage_to_public(st);
    }
    if (value.length > expected_capacity
        || (value.length > 0u && value.data == NULL)) {
        fence_or(inout_fence, 1);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_length = value.length;
    return NINLIL_OK;
}

static ninlil_status_t build_member_key(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_model_runtime_store_key_t *out_key)
{
    return ninlil_model_runtime_store_build_key(key_id, out_key);
}

static ninlil_status_t build_clock_key(ninlil_model_domain_key_t *out_key)
{
    ninlil_bytes_view_t identity;

    identity.data = NULL;
    identity.length = 0u;
    return ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE,
        NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON,
        identity,
        out_key);
}

static ninlil_status_t build_head_domain_key(
    ninlil_stage5_empty_metadata_workspace_t *ws,
    const ninlil_model_runtime_store_key_t *member_key)
{
    ninlil_bytes_view_t member_key_view;
    ninlil_bytes_view_t components;
    ninlil_status_t status;

    member_key_view.data = member_key->bytes;
    member_key_view.length = member_key->length;
    if (!ninlil_model_domain_family34_member_key_is_valid(member_key_view)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_domain_key_digest(
        member_key_view, &ws->member_key_digest);
    if (status != NINLIL_OK) {
        return status;
    }
    components.data = ws->member_key_digest.bytes;
    components.length = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
    status = ninlil_model_domain_composite_digest(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
        components,
        &ws->composite_identity);
    if (status != NINLIL_OK) {
        return status;
    }
    return ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        (ninlil_bytes_view_t){ws->composite_identity.bytes, 32u},
        &ws->domain_key);
}

static ninlil_status_t prebuild_expected_keys(
    ninlil_stage5_empty_metadata_workspace_t *ws)
{
    uint32_t index;
    ninlil_status_t status;

    for (index = 0u; index < NINLIL_STAGE5_EMPTY_HEAD_INDEX_COUNT; ++index) {
        status = build_member_key(MEMBER_KEYS[index], &ws->member_key);
        if (status != NINLIL_OK) {
            return status;
        }
        status = build_head_domain_key(ws, &ws->member_key);
        if (status != NINLIL_OK) {
            return status;
        }
        ws->expected_keys[index] = ws->domain_key;
    }
    status = build_clock_key(&ws->domain_key);
    if (status != NINLIL_OK) {
        return status;
    }
    ws->expected_keys[NINLIL_STAGE5_EMPTY_HEAD_INDEX_COUNT] = ws->domain_key;
    return NINLIL_OK;
}

static int key_equals_expected(
    const ninlil_stage5_empty_metadata_workspace_t *ws,
    ninlil_bytes_view_t key)
{
    uint32_t index;

    for (index = 0u; index < NINLIL_STAGE5_EMPTY_METADATA_RECORD_COUNT;
         ++index) {
        if (ws->expected_keys[index].length == key.length
            && key.length > 0u
            && memcmp(
                   ws->expected_keys[index].bytes, key.data, key.length)
                == 0) {
            return 1;
        }
    }
    return 0;
}

static ninlil_status_t encode_head_index_record(
    ninlil_stage5_empty_metadata_workspace_t *ws,
    const ninlil_model_runtime_store_key_t *member_key,
    uint32_t member_value_length,
    uint32_t *out_value_length)
{
    ninlil_model_domain_body_witness_head_index_t body;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t member_value_view;
    ninlil_bytes_view_t body_view;
    ninlil_bytes_view_t identity;
    uint32_t body_len = 0u;
    uint32_t enc_len = 0u;
    ninlil_status_t status;
    ninlil_model_domain_typed_record_t typed;

    if (ws == NULL || member_key == NULL || out_value_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = build_head_domain_key(ws, member_key);
    if (status != NINLIL_OK) {
        return status;
    }

    member_value_view.data = ws->member_value;
    member_value_view.length = member_value_length;
    status = ninlil_model_domain_value_digest(
        member_value_view, &ws->member_value_digest);
    if (status != NINLIL_OK) {
        return status;
    }

    (void)memset(&body, 0, sizeof(body));
    body.index_state = NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE;
    body.reserved0 = 0u;
    (void)memcpy(body.member_key_digest, ws->member_key_digest.bytes, 32u);
    body.member_key_length = (uint16_t)member_key->length;
    body.reserved1 = 0u;
    body.member_key_bytes = member_key->bytes;
    (void)memcpy(
        body.member_value_digest, ws->member_value_digest.bytes, 32u);
    (void)memset(body.member_head_witness_digest, 0, 32u);

    status = ninlil_model_domain_encode_body_witness_head_index(
        &body, ws->body, sizeof(ws->body), &body_len);
    if (status != NINLIL_OK) {
        return status;
    }

    identity.data = ws->composite_identity.bytes;
    identity.length = 32u;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body_len;
    status = ninlil_model_domain_primary_id_from_identity(
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity,
        hdr.primary_id);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memset(hdr.head_witness_digest, 0, 32u);
    (void)memset(hdr.primary_value_digest, 0, 32u);

    body_view.data = ws->body;
    body_view.length = body_len;
    status = ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body_view,
        ws->encoded_value,
        sizeof(ws->encoded_value),
        &enc_len);
    if (status != NINLIL_OK) {
        return status;
    }

    status = ninlil_model_domain_validate_typed_record(
        (ninlil_bytes_view_t){ws->domain_key.bytes, ws->domain_key.length},
        (ninlil_bytes_view_t){ws->encoded_value, enc_len},
        &typed);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    *out_value_length = enc_len;
    return NINLIL_OK;
}

static ninlil_status_t encode_clock_uninitialized(
    ninlil_stage5_empty_metadata_workspace_t *ws,
    uint32_t *out_value_length)
{
    ninlil_model_domain_body_clock_baseline_t body;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t body_view;
    ninlil_bytes_view_t identity;
    ninlil_model_domain_typed_record_t typed;
    uint32_t body_len = 0u;
    uint32_t enc_len = 0u;
    ninlil_status_t status;

    (void)memset(&body, 0, sizeof(body));
    body.baseline_state = NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED;
    body.reserved = 0u;
    body.last_trusted_now_ms = 0u;
    body.publish_generation = 0u;

    status = ninlil_model_domain_encode_body_clock_baseline(
        &body, ws->clock_body, sizeof(ws->clock_body), &body_len);
    if (status != NINLIL_OK) {
        return status;
    }

    status = build_clock_key(&ws->domain_key);
    if (status != NINLIL_OK) {
        return status;
    }

    identity.data = NULL;
    identity.length = 0u;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body_len;
    status = ninlil_model_domain_primary_id_from_identity(
        NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON, identity, hdr.primary_id);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memset(hdr.head_witness_digest, 0, 32u);
    (void)memset(hdr.primary_value_digest, 0, 32u);

    body_view.data = ws->clock_body;
    body_view.length = body_len;
    status = ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body_view,
        ws->encoded_value,
        sizeof(ws->encoded_value),
        &enc_len);
    if (status != NINLIL_OK) {
        return status;
    }

    status = ninlil_model_domain_validate_typed_record(
        (ninlil_bytes_view_t){ws->domain_key.bytes, ws->domain_key.length},
        (ninlil_bytes_view_t){ws->encoded_value, enc_len},
        &typed);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    *out_value_length = enc_len;
    return NINLIL_OK;
}

static ninlil_status_t put_encoded(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_v1_durable_operation_t operation,
    const ninlil_model_domain_key_t *key,
    const uint8_t *value,
    uint32_t value_length,
    uint32_t *inout_fence)
{
    ninlil_bytes_view_t k;
    ninlil_bytes_view_t v;
    ninlil_storage_status_t st;
    ninlil_status_t gate_status;

    k.data = key->bytes;
    k.length = key->length;
    v.data = value;
    v.length = value_length;
    gate_status = ninlil_v1_durable_writer_gate_check(operation, k, v);
    if (gate_status != NINLIL_OK) {
        return gate_status;
    }
    st = storage->put(storage->user, txn, k, v);
    fence_or(inout_fence, storage_status_requires_fence(st));
    return map_storage_to_public(st);
}

static ninlil_status_t validate_one_head_index(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_stage5_empty_metadata_workspace_t *ws,
    ninlil_model_runtime_store_key_id_t member_key_id,
    uint32_t *inout_fence)
{
    ninlil_bytes_view_t member_key_view;
    ninlil_bytes_view_t domain_key_view;
    ninlil_model_domain_typed_record_t typed;
    uint32_t member_value_len = 0u;
    uint32_t head_value_len = 0u;
    ninlil_status_t status;

    status = build_member_key(member_key_id, &ws->member_key);
    if (status != NINLIL_OK) {
        return status;
    }
    member_key_view.data = ws->member_key.bytes;
    member_key_view.length = ws->member_key.length;

    status = storage_get_exact(
        storage,
        txn,
        member_key_view,
        ws->member_value,
        sizeof(ws->member_value),
        &member_value_len,
        inout_fence);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_NOT_FOUND
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }

    status = ninlil_model_domain_key_digest(
        member_key_view, &ws->member_key_digest);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_value_digest(
        (ninlil_bytes_view_t){ws->member_value, member_value_len},
        &ws->member_value_digest);
    if (status != NINLIL_OK) {
        return status;
    }

    status = build_head_domain_key(ws, &ws->member_key);
    if (status != NINLIL_OK) {
        return status;
    }

    domain_key_view.data = ws->domain_key.bytes;
    domain_key_view.length = ws->domain_key.length;
    status = storage_get_exact(
        storage,
        txn,
        domain_key_view,
        ws->encoded_value,
        sizeof(ws->encoded_value),
        &head_value_len,
        inout_fence);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_NOT_FOUND
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }

    status = ninlil_model_domain_validate_typed_record(
        domain_key_view,
        (ninlil_bytes_view_t){ws->encoded_value, head_value_len},
        &typed);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (typed.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
        || typed.witness_head_index.index_state
            != NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE
        || typed.witness_head_index.member_key_length
            != ws->member_key.length
        || memcmp(
               typed.witness_head_index.member_key_digest,
               ws->member_key_digest.bytes,
               32u)
            != 0
        || memcmp(
               typed.witness_head_index.member_value_digest,
               ws->member_value_digest.bytes,
               32u)
            != 0
        || typed.witness_head_index.member_key_bytes == NULL
        || memcmp(
               typed.witness_head_index.member_key_bytes,
               ws->member_key.bytes,
               ws->member_key.length)
            != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t classify_expected_presence(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_stage5_empty_metadata_workspace_t *ws,
    uint32_t *out_present_count,
    uint32_t *inout_fence)
{
    uint32_t index;
    uint32_t present = 0u;
    uint32_t value_len = 0u;
    ninlil_status_t status;
    ninlil_bytes_view_t key_view;

    *out_present_count = 0u;
    status = prebuild_expected_keys(ws);
    if (status != NINLIL_OK) {
        return status;
    }

    for (index = 0u; index < NINLIL_STAGE5_EMPTY_METADATA_RECORD_COUNT;
         ++index) {
        key_view.data = ws->expected_keys[index].bytes;
        key_view.length = ws->expected_keys[index].length;
        status = storage_get_exact(
            storage,
            txn,
            key_view,
            ws->encoded_value,
            sizeof(ws->encoded_value),
            &value_len,
            inout_fence);
        if (status == NINLIL_E_NOT_FOUND) {
            continue;
        }
        if (status != NINLIL_OK) {
            return status;
        }
        present += 1u;
    }
    *out_present_count = present;
    return NINLIL_OK;
}

/*
 * Same-txn zero-prefix surplus / future classification (docs/17 §5 / §16).
 *
 * Allowed without domain surplus claim:
 *   - family 1–4 Runtime Store catalog keys
 *   - the closed set of 16 expected metadata keys
 *
 * All other rows use D1 authoritative helpers only (no local future
 * predicate duplicate):
 *   - ninlil_model_domain_classify_row (docs/17 §15.9 / dual-predicate ban)
 *   - ninlil_model_domain_decode_envelope for CURRENT framing future
 *     (record_version / domain_format)
 *
 * Aggregate (full scan; corrupt > future):
 *   sticky current corruption → NINLIL_E_STORAGE_CORRUPT
 *   else recognizable/framing future only → NINLIL_E_UNSUPPORTED
 *   else OK
 */
static ninlil_status_t prove_namespace_no_surplus(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_stage5_empty_metadata_workspace_t *ws,
    uint32_t *out_fence)
{
    ninlil_storage_iter_t iterator = NULL;
    ninlil_bytes_view_t prefix;
    ninlil_storage_status_t st;
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    uint8_t *const expected_key_data = ws->scan_key;
    uint8_t *const expected_value_data = ws->scan_value;
    const uint32_t expected_key_cap = NINLIL_STAGE5_EMPTY_SCAN_KEY_CAPACITY;
    const uint32_t expected_value_cap = NINLIL_STAGE5_EMPTY_SCAN_VALUE_CAPACITY;
    uint8_t sticky_current_corrupt = 0u;
    uint8_t recognizable_future_seen = 0u;

    /* Do not clear caller's sticky fence_pending from earlier Port calls. */
    if (out_fence == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    prefix.data = NULL;
    prefix.length = 0u;
    ws->previous_key_length = 0u;

    st = storage->iter_open(storage->user, txn, prefix, &iterator);
    /* Status fence before shape branches (non-OK+nonnull must not drop it). */
    fence_or(out_fence, storage_status_requires_fence(st));
    if ((st == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        /* OK+NULL / non-OK+nonnull: unsafe handle shape → fence. */
        fence_or(out_fence, 1);
        if (iterator != NULL) {
            storage->iter_close(storage->user, iterator);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_to_public(st);
    }

    for (;;) {
        ninlil_bytes_view_t key_view;
        ninlil_bytes_view_t value_view;
        ninlil_model_runtime_store_key_id_t key_id;
        ninlil_model_domain_key_class_t row_class;
        ninlil_model_domain_envelope_t envelope;
        ninlil_status_t parse_status;
        ninlil_status_t class_status;
        ninlil_status_t env_status;
        int order;
        uint32_t common;

        key.data = expected_key_data;
        key.capacity = expected_key_cap;
        key.length = 0u;
        value.data = expected_value_data;
        value.capacity = expected_value_cap;
        value.length = 0u;

        st = storage->iter_next(storage->user, iterator, &key, &value);
        fence_or(out_fence, storage_status_requires_fence(st));
        if (key.data != expected_key_data || key.capacity != expected_key_cap
            || value.data != expected_value_data
            || value.capacity != expected_value_cap) {
            fence_or(out_fence, 1);
            storage->iter_close(storage->user, iterator);
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (st == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                fence_or(out_fence, 1);
                storage->iter_close(storage->user, iterator);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            break;
        }
        if (st == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            /*
             * docs/14 MB7: required key/value lengths may exceed capacity
             * with data/capacity unchanged (natural). §372: oversized pair
             * → CORRUPT/no-reread; §374: not handle-fence by itself.
             * Descriptor rewrite already fenced above.
             */
            storage->iter_close(storage->user, iterator);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (st != NINLIL_STORAGE_OK) {
            if (key.length != 0u || value.length != 0u) {
                fence_or(out_fence, 1);
                storage->iter_close(storage->user, iterator);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            storage->iter_close(storage->user, iterator);
            return map_storage_to_public(st);
        }
        if (key.length < 1u || key.length > expected_key_cap
            || value.length > expected_value_cap) {
            fence_or(out_fence, 1);
            storage->iter_close(storage->user, iterator);
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (ws->previous_key_length != 0u) {
            common = ws->previous_key_length < key.length
                ? ws->previous_key_length
                : key.length;
            order = memcmp(ws->previous_key, key.data, common);
            if (order > 0
                || (order == 0 && ws->previous_key_length >= key.length)) {
                storage->iter_close(storage->user, iterator);
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
        (void)memcpy(ws->previous_key, key.data, key.length);
        ws->previous_key_length = key.length;

        key_view.data = key.data;
        key_view.length = key.length;
        value_view.data = value.length == 0u ? NULL : value.data;
        value_view.length = value.length;

        parse_status = ninlil_model_runtime_store_parse_key(key_view, &key_id);
        if (parse_status == NINLIL_OK) {
            /* Family 1–4 catalog: allowed residual after bootstrap. */
            continue;
        }
        if (key_equals_expected(ws, key_view)) {
            /* Closed 16 expected metadata keys (content checked elsewhere). */
            continue;
        }

        /*
         * D1 classify_row is the sole row-class / future-root helper
         * (docs/17: dual future predicate forbidden).
         */
        class_status = ninlil_model_domain_classify_row(
            key_view, value_view, &row_class);
        if (class_status != NINLIL_OK) {
            sticky_current_corrupt = 1u;
            continue;
        }
        if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
            recognizable_future_seen = 1u;
            continue;
        }
        if (row_class != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
            /* MALFORMED / unknown current grammar: current corruption. */
            sticky_current_corrupt = 1u;
            continue;
        }

        /*
         * CURRENT non-expected: framing future (record_version/domain_format)
         * via decode_envelope (same framing gate as scanner structural path).
         * Framing UNSUPPORTED is non-terminal future; any other outcome is
         * current surplus/corruption for this empty-metadata orchestrator.
         */
        env_status = ninlil_model_domain_decode_envelope(value_view, &envelope);
        if (env_status == NINLIL_E_UNSUPPORTED) {
            recognizable_future_seen = 1u;
            continue;
        }
        sticky_current_corrupt = 1u;
    }

    storage->iter_close(storage->user, iterator);

    /* docs/17: corrupt > future (sticky current corruption outranks). */
    if (sticky_current_corrupt != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (recognizable_future_seen != 0u) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

static ninlil_status_t validate_all_expected_in_txn(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_stage5_empty_metadata_workspace_t *ws,
    uint32_t *out_clock_trusted,
    uint32_t *inout_fence)
{
    uint32_t index;
    uint32_t clock_len = 0u;
    ninlil_status_t status;
    ninlil_model_domain_typed_record_t typed;
    ninlil_bytes_view_t clock_key_view;

    if (out_clock_trusted != NULL) {
        *out_clock_trusted = 0u;
    }

    for (index = 0u; index < NINLIL_STAGE5_EMPTY_HEAD_INDEX_COUNT; ++index) {
        status = validate_one_head_index(
            storage, txn, ws, MEMBER_KEYS[index], inout_fence);
        if (status != NINLIL_OK) {
            return status;
        }
    }

    status = build_clock_key(&ws->domain_key);
    if (status != NINLIL_OK) {
        return status;
    }
    clock_key_view.data = ws->domain_key.bytes;
    clock_key_view.length = ws->domain_key.length;
    status = storage_get_exact(
        storage,
        txn,
        clock_key_view,
        ws->encoded_value,
        sizeof(ws->encoded_value),
        &clock_len,
        inout_fence);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_NOT_FOUND
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }
    status = ninlil_model_domain_validate_typed_record(
        clock_key_view,
        (ninlil_bytes_view_t){ws->encoded_value, clock_len},
        &typed);
    if (status != NINLIL_OK
        || typed.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (typed.clock_baseline.baseline_state
        == NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
        if (out_clock_trusted != NULL) {
            *out_clock_trusted = 1u;
        }
    } else if (typed.clock_baseline.baseline_state
        != NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t write_all_metadata(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    uint32_t *inout_fence)
{
    uint32_t index;
    uint32_t value_len = 0u;
    ninlil_status_t status;

    for (index = 0u; index < NINLIL_STAGE5_EMPTY_HEAD_INDEX_COUNT; ++index) {
        ninlil_bytes_view_t member_key_view;
        uint32_t member_value_len = 0u;

        status = build_member_key(MEMBER_KEYS[index], &workspace->member_key);
        if (status != NINLIL_OK) {
            return status;
        }

        member_key_view.data = workspace->member_key.bytes;
        member_key_view.length = workspace->member_key.length;
        status = storage_get_exact(
            storage,
            txn,
            member_key_view,
            workspace->member_value,
            sizeof(workspace->member_value),
            &member_value_len,
            inout_fence);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_NOT_FOUND
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }

        status = encode_head_index_record(
            workspace,
            &workspace->member_key,
            member_value_len,
            &value_len);
        if (status != NINLIL_OK) {
            return status;
        }

        status = put_encoded(
            storage,
            txn,
            NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT,
            &workspace->domain_key,
            workspace->encoded_value,
            value_len,
            inout_fence);
        if (status != NINLIL_OK) {
            return status;
        }
    }

    status = encode_clock_uninitialized(workspace, &value_len);
    if (status != NINLIL_OK) {
        return status;
    }
    return put_encoded(
        storage,
        txn,
        NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT,
        &workspace->domain_key,
        workspace->encoded_value,
        value_len,
        inout_fence);
}


/*
 * Same-txn bootstrap-17 authority re-proof against L2b1-accepted validation.
 *
 * Canonical expected bytes: build_bootstrap_plan(accepted) + record_at(i).
 * Stored bytes: get exact. Require byte-exact match for all 17 (binding,
 * identity, zero counters, capacity limits/epochs). Partial or race
 * replacement → CORRUPT. validate_snapshot is structural only — never used
 * alone as authority match.
 */
static ninlil_status_t prove_bootstrap_17_authority(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *ws,
    uint32_t *inout_fence)
{
    ninlil_model_runtime_store_encoded_snapshot_t encoded;
    ninlil_status_t status;
    uint32_t index;
    uint32_t value_len = 0u;

    (void)memset(&encoded, 0, sizeof(encoded));
    (void)memset(&ws->bootstrap_validated, 0, sizeof(ws->bootstrap_validated));
    (void)memset(ws->bootstrap_encoded, 0, sizeof(ws->bootstrap_encoded));
    (void)memset(&ws->bootstrap_plan, 0, sizeof(ws->bootstrap_plan));
    (void)memset(&ws->bootstrap_record, 0, sizeof(ws->bootstrap_record));

    status = ninlil_model_runtime_store_build_bootstrap_plan(
        accepted_validation, &ws->bootstrap_plan);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_INVALID_ARGUMENT
            ? NINLIL_E_INVALID_ARGUMENT
            : NINLIL_E_STORAGE_CORRUPT;
    }

    for (index = 0u; index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_bytes_view_t key_view;
        uint8_t *slot = &ws->bootstrap_encoded[BOOTSTRAP_ENCODED_OFFSETS[index]];
        uint32_t cap = BOOTSTRAP_ENCODED_CAPS[index];

        status = ninlil_model_runtime_store_bootstrap_record_at(
            &ws->bootstrap_plan, index, &ws->bootstrap_record);
        if (status != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ws->bootstrap_record.value_length == 0u
            || ws->bootstrap_record.value_length > cap
            || ws->bootstrap_record.value_length
                > sizeof(ws->bootstrap_record.value)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }

        key_view.data = ws->bootstrap_record.key.bytes;
        key_view.length = ws->bootstrap_record.key.length;
        value_len = 0u;
        status = storage_get_exact(
            storage, txn, key_view, slot, cap, &value_len, inout_fence);
        if (status == NINLIL_E_NOT_FOUND) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (status != NINLIL_OK) {
            return status;
        }
        /* Authority match: exact length + exact bytes vs plan record_at. */
        if (value_len != ws->bootstrap_record.value_length
            || memcmp(slot, ws->bootstrap_record.value, value_len) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        encoded.values[index].data = slot;
        encoded.values[index].length = value_len;
    }

    /* Structural internal consistency (not a substitute for authority). */
    status = ninlil_model_runtime_store_validate_snapshot(
        &encoded, &ws->bootstrap_validated);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_UNSUPPORTED
            ? NINLIL_E_UNSUPPORTED
            : NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t begin_txn(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    ninlil_storage_status_t st;
    ninlil_storage_txn_t txn = NULL;

    *out_txn = NULL;
    st = storage->begin(storage->user, *inout_handle, mode, &txn);
    if ((st == NINLIL_STORAGE_OK) != (txn != NULL)) {
        /*
         * Shape violation (OK+NULL / non-OK+nonnull): consume unexpected
         * txn if present; keep cleanup_status; fence always; primary CORRUPT.
         */
        if (txn != NULL) {
            ninlil_storage_status_t rb =
                storage->rollback(storage->user, txn);
            if (out_result != NULL) {
                out_result->cleanup_status = rb;
            }
            if (rb != NINLIL_STORAGE_OK
                || storage_status_requires_fence(rb)) {
                /* already fencing for shape; sticky cleanup already recorded */
            }
        }
        fence_handle(storage, inout_handle, out_result);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (st != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(st)) {
            fence_handle(storage, inout_handle, out_result);
        }
        return map_storage_to_public(st);
    }
    *out_txn = txn;
    return NINLIL_OK;
}

ninlil_status_t ninlil_stage5_empty_metadata_commit(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_status_t status;
    uint32_t present_count = 0u;
    uint32_t fence = 0u;

    if (!prevalidate_common(
            storage,
            inout_handle,
            accepted_validation,
            workspace,
            out_result,
            1)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    result_init(out_result);

    status = begin_txn(
        storage, inout_handle, NINLIL_STORAGE_READ_WRITE, &txn, out_result);
    if (status != NINLIL_OK) {
        return status;
    }

    /* Authority bootstrap-17 before any domain classify/write. */
    status = prove_bootstrap_17_authority(
        storage, txn, accepted_validation, workspace, &fence);
    if (status != NINLIL_OK) {
        return rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
    }

    status = classify_expected_presence(
        storage, txn, workspace, &present_count, &fence);
    if (status != NINLIL_OK) {
        return rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
    }

    status = prove_namespace_no_surplus(storage, txn, workspace, &fence);
    if (status != NINLIL_OK) {
        return rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
    }

    if (present_count == 0u) {
        status = write_all_metadata(storage, txn, workspace, &fence);
        if (status != NINLIL_OK) {
            return rollback_finish(
                storage, inout_handle, txn, status, fence, out_result);
        }
        /* commit consumes txn for every status; never rollback after. */
        status = commit_and_map(storage, inout_handle, txn, out_result);
        if (status == NINLIL_OK) {
            out_result->wrote_metadata = 1u;
        }
        return status;
    }

    if (present_count == NINLIL_STAGE5_EMPTY_METADATA_RECORD_COUNT) {
        /*
         * Exact 16: content/binding must match; TRUSTED clock is accepted
         * and never rewritten to UNINITIALIZED (mutation 0).
         */
        status = validate_all_expected_in_txn(
            storage, txn, workspace, NULL, &fence);
        return rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
    }

    /* Partial 1..15: fail closed, no put/commit. */
    return rollback_finish(
        storage, inout_handle, txn, NINLIL_E_STORAGE_CORRUPT, fence, out_result);
}

ninlil_status_t ninlil_stage5_empty_metadata_validate(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_status_t status;
    uint32_t fence = 0u;
    uint32_t clock_trusted = 0u;

    if (!prevalidate_common(
            storage,
            inout_handle,
            accepted_validation,
            workspace,
            out_result,
            0)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    result_init(out_result);

    status = begin_txn(
        storage, inout_handle, NINLIL_STORAGE_READ_ONLY, &txn, out_result);
    if (status != NINLIL_OK) {
        return status;
    }

    status = prove_bootstrap_17_authority(
        storage, txn, accepted_validation, workspace, &fence);
    if (status != NINLIL_OK) {
        status = rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
        out_result->clock_trusted = 0u;
        return status;
    }

    status = prebuild_expected_keys(workspace);
    if (status != NINLIL_OK) {
        status = rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
        out_result->clock_trusted = 0u;
        return status;
    }

    status = prove_namespace_no_surplus(storage, txn, workspace, &fence);
    if (status != NINLIL_OK) {
        status = rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
        out_result->clock_trusted = 0u;
        return status;
    }

    status = validate_all_expected_in_txn(
        storage, txn, workspace, &clock_trusted, &fence);
    /*
     * docs/14 L374: RO success candidate adopted only after rollback OK.
     * Primary failure keeps primary; rb fail → cleanup + fence.
     */
    status = rollback_finish(
        storage, inout_handle, txn, status, fence, out_result);
    if (status != NINLIL_OK) {
        out_result->clock_trusted = 0u;
        return status;
    }
    out_result->clock_trusted = clock_trusted;
    return NINLIL_OK;
}

static ninlil_status_t validate_trusted_sample(
    const ninlil_time_sample_t *sample)
{
    if (sample == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (sample->abi_version != NINLIL_ABI_VERSION) {
        return NINLIL_E_ABI_MISMATCH;
    }
    if (sample->struct_size != (uint16_t)sizeof(ninlil_time_sample_t)) {
        return NINLIL_E_ABI_MISMATCH;
    }
    if (sample->reserved_zero != 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (sample->trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!id_is_nonzero(&sample->clock_epoch_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_stage5_clock_baseline_commit_trusted(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_time_sample_t *trusted_sample,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_status_t status;
    ninlil_model_domain_body_clock_baseline_t body;
    ninlil_model_domain_common_header_t hdr;
    ninlil_model_domain_typed_record_t typed;
    ninlil_bytes_view_t identity;
    ninlil_bytes_view_t body_view;
    ninlil_bytes_view_t key_view;
    uint32_t body_len = 0u;
    uint32_t enc_len = 0u;
    uint32_t old_len = 0u;
    uint64_t next_generation = 0u;
    uint64_t next_revision = 0u;
    uint32_t fence = 0u;

    if (!prevalidate_common(
            storage,
            inout_handle,
            accepted_validation,
            workspace,
            out_result,
            1)
        || trusted_sample == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(trusted_sample, sizeof(*trusted_sample),
            storage, sizeof(*storage))
        || !ranges_are_disjoint(trusted_sample, sizeof(*trusted_sample),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(trusted_sample, sizeof(*trusted_sample),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(trusted_sample, sizeof(*trusted_sample),
            out_result, sizeof(*out_result))
        || !ranges_are_disjoint(trusted_sample, sizeof(*trusted_sample),
            accepted_validation, sizeof(*accepted_validation))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = validate_trusted_sample(trusted_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    result_init(out_result);

    status = begin_txn(
        storage, inout_handle, NINLIL_STORAGE_READ_WRITE, &txn, out_result);
    if (status != NINLIL_OK) {
        return status;
    }

    status = prove_bootstrap_17_authority(
        storage, txn, accepted_validation, workspace, &fence);
    if (status != NINLIL_OK) {
        return rollback_finish(
            storage, inout_handle, txn, status, fence, out_result);
    }

    status = build_clock_key(&workspace->domain_key);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, status, fence, out_result);
    }
    key_view.data = workspace->domain_key.bytes;
    key_view.length = workspace->domain_key.length;

    status = storage_get_exact(
        storage,
        txn,
        key_view,
        workspace->encoded_value,
        sizeof(workspace->encoded_value),
        &old_len,
        &fence);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, status == NINLIL_E_NOT_FOUND
                ? NINLIL_E_STORAGE_CORRUPT
                : status, fence, out_result);
    }
    status = ninlil_model_domain_validate_typed_record(
        key_view,
        (ninlil_bytes_view_t){workspace->encoded_value, old_len},
        &typed);
    if (status != NINLIL_OK
        || typed.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
        return rollback_finish(storage, inout_handle, txn, NINLIL_E_STORAGE_CORRUPT, fence, out_result);
    }

    /*
     * Already TRUSTED: this API is first UNINITIALIZED→TRUSTED only.
     * Idempotent retry: exact same epoch + now → OK / mutation 0.
     * Any other sample (epoch change, now advance/regress) → CONFLICT /
     * mutation 0. Later accepted-sample updates are a different API.
     */
    if (typed.clock_baseline.baseline_state
        == NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
        if (memcmp(
                typed.clock_baseline.trusted_clock_epoch,
                trusted_sample->clock_epoch_id.bytes,
                16u)
                == 0
            && typed.clock_baseline.last_trusted_now_ms
                == trusted_sample->now_ms) {
            return rollback_finish(
                storage, inout_handle, txn, NINLIL_OK, fence, out_result);
        }
        return rollback_finish(
            storage, inout_handle, txn, NINLIL_E_CONFLICT, fence, out_result);
    }
    if (typed.clock_baseline.baseline_state
        != NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
        return rollback_finish(storage, inout_handle, txn, NINLIL_E_STORAGE_CORRUPT, fence, out_result);
    }

    if (typed.clock_baseline.publish_generation == UINT64_MAX
        || typed.envelope.header.record_revision == UINT64_MAX) {
        return rollback_finish(storage, inout_handle, txn, NINLIL_E_DEGRADED, fence, out_result);
    }
    next_generation = typed.clock_baseline.publish_generation + 1u;
    next_revision = typed.envelope.header.record_revision + 1u;
    if (next_generation == 0u || next_revision == 0u) {
        return rollback_finish(storage, inout_handle, txn, NINLIL_E_DEGRADED, fence, out_result);
    }

    (void)memset(&body, 0, sizeof(body));
    body.baseline_state = NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED;
    body.reserved = 0u;
    (void)memcpy(
        body.trusted_clock_epoch,
        trusted_sample->clock_epoch_id.bytes,
        16u);
    body.last_trusted_now_ms = trusted_sample->now_ms;
    body.publish_generation = next_generation;

    status = ninlil_model_domain_encode_body_clock_baseline(
        &body, workspace->clock_body, sizeof(workspace->clock_body), &body_len);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, status, fence, out_result);
    }

    identity.data = NULL;
    identity.length = 0u;
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE;
    hdr.flags = 0u;
    hdr.record_revision = next_revision;
    hdr.body_length = body_len;
    status = ninlil_model_domain_primary_id_from_identity(
        NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON, identity, hdr.primary_id);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, status, fence, out_result);
    }
    (void)memset(hdr.head_witness_digest, 0, 32u);
    (void)memset(hdr.primary_value_digest, 0, 32u);

    body_view.data = workspace->clock_body;
    body_view.length = body_len;
    status = ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body_view,
        workspace->encoded_value,
        sizeof(workspace->encoded_value),
        &enc_len);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, status, fence, out_result);
    }
    status = ninlil_model_domain_validate_typed_record(
        key_view,
        (ninlil_bytes_view_t){workspace->encoded_value, enc_len},
        &typed);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, NINLIL_E_STORAGE_CORRUPT, fence, out_result);
    }

    status = put_encoded(
        storage,
        txn,
        NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT,
        &workspace->domain_key,
        workspace->encoded_value,
        enc_len,
        &fence);
    if (status != NINLIL_OK) {
        return rollback_finish(storage, inout_handle, txn, status, fence, out_result);
    }

    /* commit consumes txn for every status; never rollback after. */
    return commit_and_map(storage, inout_handle, txn, out_result);
}
