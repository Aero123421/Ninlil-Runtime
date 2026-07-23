#include "v1_durable_allowlist.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "runtime_store_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

const ninlil_v1_durable_allowlist_row_t g_ninlil_v1_durable_allowlist_table[
    NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT] = {
    {NINLIL_V1_DURABLE_KIND_RS_BINDING, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_BINDING"},
    {NINLIL_V1_DURABLE_KIND_RS_IDENTITY, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_IDENTITY"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_TRANSACTION, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_COUNTER_TRANSACTION"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_ORDERED_INPUT,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_COUNTER_ORDERED_INPUT"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_ASSIGNED_OWNER,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_COUNTER_ASSIGNED_OWNER"},
    {NINLIL_V1_DURABLE_KIND_RS_COUNTER_VISITED_OWNER,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_COUNTER_VISITED_OWNER"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_SERVICE, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_SERVICE"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TRANSACTION,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_TRANSACTION"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TARGET, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_TARGET"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_OUTBOX_BYTES,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_OUTBOX_BYTES"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DELIVERY, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_DELIVERY"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_COUNT,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_EVENT_SPOOL_COUNT"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_BYTES,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_EVENT_SPOOL_BYTES"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_RESULT_CACHE,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_RESULT_CACHE"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVIDENCE, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_EVIDENCE"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_INGRESS, NINLIL_V1_DURABLE_OWNER_S1,
        "RS_CAPACITY_INGRESS"},
    {NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DEFERRED_TOKEN,
        NINLIL_V1_DURABLE_OWNER_S1, "RS_CAPACITY_DEFERRED_TOKEN"},
    {NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_WITNESS_HEAD_INDEX"},
    {NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE, NINLIL_V1_DURABLE_OWNER_S1,
        "DOM_CLOCK_BASELINE"}
};

static ninlil_v1_durable_record_kind_t key_id_to_kind(
    ninlil_model_runtime_store_key_id_t key_id)
{
    switch (key_id) {
    case NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING:
        return NINLIL_V1_DURABLE_KIND_RS_BINDING;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY:
        return NINLIL_V1_DURABLE_KIND_RS_IDENTITY;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_TRANSACTION;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_ORDERED_INPUT;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ASSIGNED_OWNER:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_ASSIGNED_OWNER;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER:
        return NINLIL_V1_DURABLE_KIND_RS_COUNTER_VISITED_OWNER;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_SERVICE;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TRANSACTION:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TRANSACTION;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TARGET:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TARGET;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_OUTBOX_BYTES;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DELIVERY;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_COUNT:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_COUNT;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_BYTES:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_BYTES;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_RESULT_CACHE:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_RESULT_CACHE;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVIDENCE:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVIDENCE;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_INGRESS:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_INGRESS;
    case NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN:
        return NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DEFERRED_TOKEN;
    default:
        return (ninlil_v1_durable_record_kind_t)0;
    }
}

static ninlil_status_t classify_runtime_store_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    ninlil_model_runtime_store_key_id_t key_id;
    ninlil_status_t status;

    (void)value;
    status = ninlil_model_runtime_store_parse_key(key, &key_id);
    if (status != NINLIL_OK) {
        return status;
    }
    *out_kind = key_id_to_kind(key_id);
    if (*out_kind == (ninlil_v1_durable_record_kind_t)0) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

static ninlil_status_t classify_domain_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    ninlil_model_domain_key_class_t key_class;
    ninlil_model_domain_typed_record_t typed;
    ninlil_status_t status;

    status = ninlil_model_domain_classify_key(key, &key_class);
    if (status != NINLIL_OK) {
        return status;
    }
    if (key_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (key_class != NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_domain_validate_typed_record(key, value, &typed);
    if (status != NINLIL_OK) {
        return status;
    }
    if (typed.family != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX;
        return NINLIL_OK;
    }
    if (typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
        *out_kind = NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE;
        return NINLIL_OK;
    }
    return NINLIL_E_UNSUPPORTED;
}

ninlil_status_t ninlil_v1_durable_classify_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind)
{
    if (out_kind == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_kind = (ninlil_v1_durable_record_kind_t)0;
    if ((key.length != 0u && key.data == NULL)
        || (value.length != 0u && value.data == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (key.length >= 8u
        && key.data != NULL
        && key.data[7] == 0x01u
        && (key.data[8] == 0x01u || key.data[8] == 0x02u
            || key.data[8] == 0x03u || key.data[8] == 0x04u)) {
        return classify_runtime_store_row(key, value, out_kind);
    }
    return classify_domain_row(key, value, out_kind);
}

static int operation_allows_kind(
    ninlil_v1_durable_operation_t operation,
    ninlil_v1_durable_record_kind_t kind)
{
    switch (operation) {
    case NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT:
        return kind >= NINLIL_V1_DURABLE_KIND_RS_BINDING
            && kind <= NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DEFERRED_TOKEN;
    case NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT:
        return kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX
            || kind == NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE;
    case NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT:
        return kind == NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE;
    default:
        return 0;
    }
}

static ninlil_status_t validate_allowed_state(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t kind)
{
    ninlil_model_domain_typed_record_t typed;
    ninlil_status_t status;

    if (kind != NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX
        && kind != NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE) {
        return NINLIL_OK;
    }
    status = ninlil_model_domain_validate_typed_record(key, value, &typed);
    if (status != NINLIL_OK) {
        return status;
    }
    if (kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX) {
        if (typed.witness_head_index.index_state
                != NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_OK;
    }
    if (operation == NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT) {
        if (typed.clock_baseline.baseline_state
                != NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_OK;
    }
    if (operation == NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT) {
        if (typed.clock_baseline.baseline_state
                != NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_OK;
    }
    return NINLIL_E_UNSUPPORTED;
}

ninlil_status_t ninlil_v1_durable_writer_gate_check(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_v1_durable_record_kind_t kind;
    ninlil_status_t status;

    if (operation < NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT
        || operation > NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_v1_durable_classify_row(key, value, &kind);
    if (status != NINLIL_OK) {
        return status;
    }
    if (!operation_allows_kind(operation, kind)) {
        return NINLIL_E_UNSUPPORTED;
    }
    return validate_allowed_state(operation, key, value, kind);
}

static ninlil_status_t map_storage_status(ninlil_storage_status_t status)
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

static int storage_put_status_requires_fence(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_COMMIT_UNKNOWN
        || (status != NINLIL_STORAGE_OK
            && status != NINLIL_STORAGE_NOT_FOUND
            && status != NINLIL_STORAGE_BUSY
            && status != NINLIL_STORAGE_NO_SPACE
            && status != NINLIL_STORAGE_IO_ERROR
            && status != NINLIL_STORAGE_CORRUPT
            && status != NINLIL_STORAGE_BUFFER_TOO_SMALL
            && status != NINLIL_STORAGE_UNSUPPORTED_SCHEMA);
}

static void storage_put_fence_or(uint32_t *inout_fence, ninlil_storage_status_t status)
{
    if (inout_fence != NULL && storage_put_status_requires_fence(status) != 0) {
        *inout_fence = 1u;
    }
}

ninlil_status_t ninlil_v1_durable_storage_put(
    ninlil_v1_durable_operation_t operation,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *inout_fence)
{
    ninlil_status_t gate_status;
    ninlil_storage_status_t put_status;

    if (storage == NULL || storage->put == NULL || txn == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    gate_status = ninlil_v1_durable_writer_gate_check(operation, key, value);
    if (gate_status != NINLIL_OK) {
        return gate_status;
    }
    put_status = storage->put(storage->user, txn, key, value);
    storage_put_fence_or(inout_fence, put_status);
    return map_storage_status(put_status);
}

static void publication_reject(
    ninlil_v1_durable_recovery_publication_result_t *out_result,
    ninlil_v1_durable_recovery_reject_reason_t reason)
{
    out_result->adopted = 0u;
    out_result->success_evidence_count = 0u;
    out_result->reject_reason = reason;
}

static ninlil_status_t publication_gate_from_counts(
    uint32_t ok_count,
    uint32_t corrupt_count,
    uint32_t unknown_count,
    uint32_t external_count,
    uint32_t success_evidence_rows,
    ninlil_v1_durable_recovery_publication_result_t *out_result)
{
    if (ok_count > 0u
        && (corrupt_count > 0u || unknown_count > 0u || external_count > 0u)) {
        publication_reject(out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_MIXED);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (corrupt_count != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (unknown_count != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN);
        return NINLIL_E_UNSUPPORTED;
    }
    if (external_count != 0u) {
        publication_reject(out_result,
            NINLIL_V1_DURABLE_RECOVERY_REJECT_ALLOWLIST_EXTERNAL);
        return NINLIL_E_UNSUPPORTED;
    }

    out_result->adopted = 1u;
    out_result->success_evidence_count = success_evidence_rows;
    out_result->reject_reason = NINLIL_V1_DURABLE_RECOVERY_REJECT_NONE;
    return NINLIL_OK;
}

static void publication_classify_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *ok_count,
    uint32_t *corrupt_count,
    uint32_t *unknown_count,
    uint32_t *external_count)
{
    ninlil_v1_durable_record_kind_t kind;
    ninlil_status_t status = ninlil_v1_durable_classify_row(key, value, &kind);

    if (status == NINLIL_E_STORAGE_CORRUPT) {
        *corrupt_count += 1u;
        return;
    }
    if (status == NINLIL_E_UNSUPPORTED) {
        *unknown_count += 1u;
        return;
    }
    if (status != NINLIL_OK) {
        *corrupt_count += 1u;
        return;
    }
    if (kind < NINLIL_V1_DURABLE_KIND_RS_BINDING
        || kind > NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE) {
        *external_count += 1u;
        return;
    }
    *ok_count += 1u;
}

ninlil_status_t ninlil_v1_durable_recovery_publication_gate(
    const ninlil_bytes_view_t *row_keys,
    const ninlil_bytes_view_t *row_values,
    uint32_t row_count,
    uint32_t commit_unknown_active,
    ninlil_v1_durable_recovery_publication_result_t *out_result)
{
    uint32_t index;
    uint32_t ok_count = 0u;
    uint32_t corrupt_count = 0u;
    uint32_t unknown_count = 0u;
    uint32_t external_count = 0u;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (row_count != 0u
        && (row_keys == NULL || row_values == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (commit_unknown_active != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }

    for (index = 0u; index < row_count; ++index) {
        publication_classify_row(
            row_keys[index],
            row_values[index],
            &ok_count,
            &corrupt_count,
            &unknown_count,
            &external_count);
    }

    return publication_gate_from_counts(
        ok_count,
        corrupt_count,
        unknown_count,
        external_count,
        row_count,
        out_result);
}

ninlil_status_t ninlil_v1_durable_recovery_publication_gate_storage(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    uint32_t commit_unknown_active,
    ninlil_v1_durable_recovery_publication_result_t *out_result)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    uint32_t ok_count = 0u;
    uint32_t corrupt_count = 0u;
    uint32_t unknown_count = 0u;
    uint32_t external_count = 0u;
    uint32_t row_count = 0u;
    uint8_t key_buf[255];
    uint8_t value_buf[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_bytes_view_t prefix;

    if (out_result == NULL || storage == NULL || handle == NULL
        || storage->begin == NULL || storage->iter_open == NULL
        || storage->iter_next == NULL || storage->iter_close == NULL
        || storage->rollback == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (commit_unknown_active != 0u) {
        publication_reject(
            out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }

    st = storage->begin(
        storage->user, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }

    prefix.data = NULL;
    prefix.length = 0u;
    st = storage->iter_open(storage->user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return map_storage_status(st);
    }

    for (;;) {
        key.data = key_buf;
        key.capacity = (uint32_t)sizeof(key_buf);
        key.length = 0u;
        value.data = value_buf;
        value.capacity = (uint32_t)sizeof(value_buf);
        value.length = 0u;
        st = storage->iter_next(storage->user, iter, &key, &value);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            publication_reject(
                out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return map_storage_status(st);
        }
        if (row_count == UINT32_MAX) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            publication_reject(
                out_result, NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        row_count += 1u;
        publication_classify_row(
            (ninlil_bytes_view_t){key.data, key.length},
            (ninlil_bytes_view_t){value.data, value.length},
            &ok_count,
            &corrupt_count,
            &unknown_count,
            &external_count);
    }

    storage->iter_close(storage->user, iter);
    st = storage->rollback(storage->user, txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_status(st);
    }

    return publication_gate_from_counts(
        ok_count,
        corrupt_count,
        unknown_count,
        external_count,
        row_count,
        out_result);
}

ninlil_status_t ninlil_v1_durable_probe_disallowed_writer_kind(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    (void)operation;
    (void)key;
    (void)value;
    return NINLIL_E_UNSUPPORTED;
}
