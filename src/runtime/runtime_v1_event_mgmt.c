#include "runtime_v1_event_mgmt.h"

#include "domain_store_codec.h"
#include "resource_ledger_batch.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_event_ledger_codec.h"
#include "runtime_v1_transaction_codec.h"
#include "runtime_store_codec.h"

#include <string.h>

#define NINLIL_RT_V1_MARKER_ES ((uint16_t)0x4553u)
#define NINLIL_RT_V1_TXN_MARKER_BYTES ((uint32_t)18u)
#define EVENT_OPERATION_SCHEMA_MAJOR ((uint16_t)1u)
#define EVENT_OPERATION_SCHEMA_MINOR ((uint16_t)0u)

typedef enum operation_lookup_kind {
    OPERATION_LOOKUP_ABSENT = 0,
    OPERATION_LOOKUP_REPLAY = 1,
    OPERATION_LOOKUP_CONFLICT = 2
} operation_lookup_kind_t;

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void saturating_increment_u64(uint64_t *value)
{
    if (*value != UINT64_MAX) {
        *value += 1u;
    }
}

static int id_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;

    if (id == NULL) {
        return 0;
    }
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int id_equal(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    return left != NULL && right != NULL
        && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int bytes_nonzero(const uint8_t *bytes, uint32_t length)
{
    uint32_t index;

    if (bytes == NULL) {
        return 0;
    }
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static void encode_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void encode_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

static uint16_t decode_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t decode_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24)
        | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8)
        | (uint32_t)in[3];
}

static uint64_t decode_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56)
        | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40)
        | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24)
        | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8)
        | (uint64_t)in[7];
}

static int event_operation_reason_valid(uint16_t prefix, uint32_t reason)
{
    if (prefix == NINLIL_RT_V1_EVENT_RESUME_PREFIX) {
        return reason == NINLIL_RESUME_CONNECTIVITY_REMEDIATED
            || reason == NINLIL_RESUME_CAPACITY_REMEDIATED
            || reason == NINLIL_RESUME_APPLICATION_REMEDIATED
            || reason == NINLIL_RESUME_OPERATOR_OVERRIDE
            || reason == NINLIL_RESUME_TEST;
    }
    if (prefix == NINLIL_RT_V1_EVENT_DISCARD_PREFIX) {
        return reason == NINLIL_DISCARD_DEVICE_DECOMMISSIONED
            || reason == NINLIL_DISCARD_INVALID_EVENT
            || reason == NINLIL_DISCARD_OPERATOR_OVERRIDE
            || reason == NINLIL_DISCARD_TEST_CLEANUP;
    }
    return 0;
}

/*
 * Legacy small-marker codec is retained only for source compatibility with
 * the pre-ledger private test seam. Durable classification now requires the
 * operation-keyed NEL1 ledger codec and rejects these values.
 */
ninlil_status_t ninlil_rt_v1_event_operation_marker_encode(
    uint16_t prefix,
    const ninlil_id128_t *operation_id,
    uint32_t reason,
    uint64_t prior_spool_revision,
    uint8_t out_value[NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES])
{
    uint32_t crc;

    if (operation_id == NULL || out_value == NULL
        || !id_nonzero(operation_id)
        || prior_spool_revision == 0u
        || !event_operation_reason_valid(prefix, reason)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(
        out_value, 0, NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES);
    out_value[0] = 0x4eu;
    out_value[1] = 0x45u;
    out_value[2] =
        prefix == NINLIL_RT_V1_EVENT_RESUME_PREFIX ? 0x52u : 0x44u;
    out_value[3] = 0x31u;
    encode_u16_be(&out_value[4], EVENT_OPERATION_SCHEMA_MAJOR);
    encode_u16_be(&out_value[6], EVENT_OPERATION_SCHEMA_MINOR);
    (void)memcpy(&out_value[8], operation_id->bytes, 16u);
    encode_u32_be(&out_value[24], reason);
    encode_u64_be(&out_value[28], prior_spool_revision);
    crc = ninlil_model_domain_crc32c(
        out_value, NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES - 4u);
    encode_u32_be(
        &out_value[NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES - 4u], crc);
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_event_operation_marker_validate(
    uint16_t expected_prefix,
    ninlil_bytes_view_t value)
{
    ninlil_id128_t operation_id;
    uint32_t reason;
    uint32_t stored_crc;
    uint32_t computed_crc;
    uint8_t expected_magic;

    if (value.data == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (value.length != NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    expected_magic = expected_prefix == NINLIL_RT_V1_EVENT_RESUME_PREFIX
        ? 0x52u
        : expected_prefix == NINLIL_RT_V1_EVENT_DISCARD_PREFIX
        ? 0x44u
        : 0xffu;
    if (value.data[0] != 0x4eu || value.data[1] != 0x45u
        || value.data[2] != expected_magic || value.data[3] != 0x31u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (decode_u16_be(&value.data[4]) != EVENT_OPERATION_SCHEMA_MAJOR
        || decode_u16_be(&value.data[6]) != EVENT_OPERATION_SCHEMA_MINOR) {
        return NINLIL_E_UNSUPPORTED;
    }
    stored_crc = decode_u32_be(
        &value.data[NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES - 4u]);
    computed_crc = ninlil_model_domain_crc32c(
        value.data, NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES - 4u);
    if (stored_crc != computed_crc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(operation_id.bytes, &value.data[8], 16u);
    reason = decode_u32_be(&value.data[24]);
    if (!id_nonzero(&operation_id)
        || !event_operation_reason_valid(expected_prefix, reason)
        || decode_u64_be(&value.data[28]) == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t map_storage_status(
    ninlil_runtime_t *runtime,
    ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    saturating_increment_u64(&runtime->metrics.storage_failures);
    switch (status) {
    case NINLIL_STORAGE_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_STORAGE_NO_SPACE:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    case NINLIL_STORAGE_IO_ERROR:
        return NINLIL_E_STORAGE;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        return NINLIL_E_UNSUPPORTED;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        return NINLIL_E_STORAGE_CORRUPT;
    default:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static int storage_status_requires_fence(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_COMMIT_UNKNOWN
        || (status != NINLIL_STORAGE_OK
            && status != NINLIL_STORAGE_NOT_FOUND
            && status != NINLIL_STORAGE_BUFFER_TOO_SMALL
            && status != NINLIL_STORAGE_NO_SPACE
            && status != NINLIL_STORAGE_IO_ERROR
            && status != NINLIL_STORAGE_CORRUPT
            && status != NINLIL_STORAGE_BUSY
            && status != NINLIL_STORAGE_UNSUPPORTED_SCHEMA);
}

static ninlil_status_t begin_storage_transaction(
    ninlil_runtime_t *runtime,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_status_t storage_status;

    *out_transaction = NULL;
    storage_status = storage->begin(
        storage->user, runtime->storage, mode, out_transaction);
    if ((storage_status == NINLIL_STORAGE_OK)
            != (*out_transaction != NULL)) {
        if (*out_transaction != NULL) {
            (void)storage->rollback(storage->user, *out_transaction);
            *out_transaction = NULL;
        }
        runtime->commit_unknown_fence = 1u;
        return map_storage_status(runtime, NINLIL_STORAGE_CORRUPT);
    }
    return map_storage_status(runtime, storage_status);
}

static ninlil_status_t open_storage_iterator(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_status_t storage_status;

    *out_iterator = NULL;
    storage_status = storage->iter_open(
        storage->user, storage_txn, prefix, out_iterator);
    if ((storage_status == NINLIL_STORAGE_OK)
            != (*out_iterator != NULL)) {
        if (*out_iterator != NULL) {
            storage->iter_close(storage->user, *out_iterator);
            *out_iterator = NULL;
        }
        runtime->commit_unknown_fence = 1u;
        return map_storage_status(runtime, NINLIL_STORAGE_CORRUPT);
    }
    return map_storage_status(runtime, storage_status);
}

static ninlil_status_t read_exact(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_bytes_view_t key,
    uint32_t *out_found,
    uint32_t *out_length)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t storage_status;
    uint8_t *const expected_data = runtime->durable_scan_value;
    const uint32_t expected_capacity =
        (uint32_t)sizeof(runtime->durable_scan_value);

    *out_found = 0u;
    *out_length = 0u;
    value.data = expected_data;
    value.capacity = expected_capacity;
    value.length = 0u;
    storage_status =
        storage->get(storage->user, storage_txn, key, &value);
    if (storage_status_requires_fence(storage_status)) {
        runtime->commit_unknown_fence = 1u;
    }
    if (value.data != expected_data || value.capacity != expected_capacity) {
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
        if (value.length != 0u) {
            runtime->commit_unknown_fence = 1u;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (value.length != 0u) {
            runtime->commit_unknown_fence = 1u;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return map_storage_status(runtime, storage_status);
    }
    if (value.length > expected_capacity || value.length == 0u) {
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_found = 1u;
    *out_length = value.length;
    return NINLIL_OK;
}

static ninlil_status_t close_read_transaction(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_status_t status)
{
    ninlil_storage_status_t rollback_status =
        runtime->platform->storage->rollback(
            runtime->platform->storage->user, storage_txn);

    if (status != NINLIL_OK) {
        return status;
    }
    return map_storage_status(runtime, rollback_status);
}

static int ledger_matches_key(
    const ninlil_rt_v1_event_ledger_record_t *record,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *operation_id)
{
    return record != NULL
        && id_equal(&record->transaction_id, transaction_id)
        && id_equal(&record->operation_id, operation_id);
}

static int ledger_matches_transaction(
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_v1_event_ledger_record_t *record)
{
    if (transaction == NULL || record == NULL
        || transaction->family != NINLIL_FAMILY_EVENT_FACT
        || record->record_revision != 1u
        || !id_equal(&record->transaction_id, &transaction->transaction_id)
        || !id_equal(&record->event_id, &transaction->event_id)
        || record->ordered_sequence == 0u
        || record->ordered_sequence > transaction->ordered_input_sequence
        || record->replay_spool_revision > transaction->spool_revision) {
        return 0;
    }
    if (record->operation_kind
        == NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME) {
        return record->replay_retry_cycle_id >= 2u
            && record->replay_retry_cycle_id
                <= transaction->retry_cycle_id
            && record->replay_spool_released == 0u;
    }
    if (record->operation_kind
        == NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD) {
        return transaction->event_discarded != 0u
            && transaction->terminal != 0u
            && transaction->reservation_active == 0u
            && transaction->payload_length == 0u
            && transaction->outcome_recorded != 0u
            && transaction->outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE
            && transaction->reason
                == NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT
            && id_equal(
                &record->expected_event_id, &transaction->event_id)
            && record->expected_content_digest_algorithm
                == transaction->content_digest.algorithm
            && memcmp(
                record->expected_content_digest,
                transaction->content_digest.bytes,
                sizeof(record->expected_content_digest)) == 0
            && record->ordered_sequence
                == transaction->ordered_input_sequence
            && record->replay_spool_revision
                == transaction->spool_revision
            && record->replay_spool_released == 1u;
    }
    return 0;
}

static ninlil_status_t lookup_operation(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_id128_t *operation_id,
    ninlil_rt_v1_event_ledger_kind_t requested_kind,
    const uint8_t request_digest[NINLIL_SHA256_BYTES],
    operation_lookup_kind_t *out_lookup,
    ninlil_rt_v1_event_ledger_record_t *out_record)
{
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_rt_v1_event_ledger_record_t resume_record;
    ninlil_rt_v1_event_ledger_record_t discard_record;
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint32_t resume_found = 0u;
    uint32_t discard_found = 0u;
    uint32_t value_length = 0u;
    ninlil_status_t status;
    const ninlil_id128_t *transaction_id = &transaction->transaction_id;

    *out_lookup = OPERATION_LOOKUP_ABSENT;
    status = begin_storage_transaction(
        runtime, NINLIL_STORAGE_READ_ONLY, &storage_txn);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_rt_v1_event_ledger_key(
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        transaction_id,
        operation_id,
        key);
    status = read_exact(
        runtime,
        storage_txn,
        (ninlil_bytes_view_t){key, sizeof(key)},
        &resume_found,
        &value_length);
    if (status == NINLIL_OK && resume_found != 0u) {
        status = ninlil_rt_v1_event_ledger_decode(
            (ninlil_bytes_view_t){
                runtime->durable_scan_value, value_length},
            &resume_record);
        if (status == NINLIL_OK
            && (!ledger_matches_key(
                    &resume_record, transaction_id, operation_id)
                || !ledger_matches_transaction(
                    transaction, &resume_record)
                || resume_record.operation_kind
                    != NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME)) {
            status = NINLIL_E_STORAGE_CORRUPT;
        }
    }
    if (status == NINLIL_OK) {
        ninlil_rt_v1_event_ledger_key(
            NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
            transaction_id,
            operation_id,
            key);
        status = read_exact(
            runtime,
            storage_txn,
            (ninlil_bytes_view_t){key, sizeof(key)},
            &discard_found,
            &value_length);
        if (status == NINLIL_OK && discard_found != 0u) {
            status = ninlil_rt_v1_event_ledger_decode(
                (ninlil_bytes_view_t){
                    runtime->durable_scan_value, value_length},
                &discard_record);
            if (status == NINLIL_OK
                && (!ledger_matches_key(
                        &discard_record, transaction_id, operation_id)
                    || !ledger_matches_transaction(
                        transaction, &discard_record)
                    || discard_record.operation_kind
                        != NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD)) {
                status = NINLIL_E_STORAGE_CORRUPT;
            }
        }
    }
    status = close_read_transaction(runtime, storage_txn, status);
    if (status != NINLIL_OK) {
        return status;
    }
    if (resume_found != 0u && discard_found != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (resume_found != 0u) {
        if (requested_kind != NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME
            || memcmp(
                resume_record.canonical_request_digest,
                request_digest,
                NINLIL_SHA256_BYTES) != 0) {
            *out_lookup = OPERATION_LOOKUP_CONFLICT;
            return NINLIL_OK;
        }
        *out_lookup = OPERATION_LOOKUP_REPLAY;
        *out_record = resume_record;
        return NINLIL_OK;
    }
    if (discard_found != 0u) {
        if (requested_kind != NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD
            || memcmp(
                discard_record.canonical_request_digest,
                request_digest,
                NINLIL_SHA256_BYTES) != 0) {
            *out_lookup = OPERATION_LOOKUP_CONFLICT;
            return NINLIL_OK;
        }
        *out_lookup = OPERATION_LOOKUP_REPLAY;
        *out_record = discard_record;
    }
    return NINLIL_OK;
}

static ninlil_status_t count_resume_operations(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    uint32_t *out_count,
    ninlil_id128_t *out_latest_operation_id,
    uint64_t *out_latest_ordered_sequence,
    uint64_t *out_ordered_sequences,
    uint32_t ordered_sequence_capacity)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_rt_v1_event_ledger_record_t record;
    uint8_t prefix[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES];
    uint8_t key_bytes[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t previous_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t storage_status;
    ninlil_status_t status;
    uint32_t count = 0u;
    uint32_t have_previous = 0u;
    uint64_t seen_cycles[NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS];
    uint64_t seen_spool_revisions[
        NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS];
    uint64_t seen_ordered_sequences[
        NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS];
    uint64_t latest_cycle = 0u;
    const ninlil_id128_t *transaction_id = &transaction->transaction_id;

    *out_count = 0u;
    (void)memset(out_latest_operation_id, 0, sizeof(*out_latest_operation_id));
    *out_latest_ordered_sequence = 0u;
    status = begin_storage_transaction(
        runtime, NINLIL_STORAGE_READ_ONLY, &storage_txn);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_rt_v1_event_ledger_transaction_prefix(
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        transaction_id,
        prefix);
    status = open_storage_iterator(
        runtime,
        storage_txn,
        (ninlil_bytes_view_t){prefix, sizeof(prefix)},
        &iterator);
    if (status != NINLIL_OK) {
        return close_read_transaction(runtime, storage_txn, status);
    }
    for (;;) {
        uint8_t *const expected_key_data = key_bytes;
        uint8_t *const expected_value_data = runtime->durable_scan_value;

        key.data = expected_key_data;
        key.capacity = (uint32_t)sizeof(key_bytes);
        key.length = 0u;
        value.data = expected_value_data;
        value.capacity = (uint32_t)sizeof(runtime->durable_scan_value);
        value.length = 0u;
        storage_status = storage->iter_next(
            storage->user, iterator, &key, &value);
        if (key.data != expected_key_data
            || key.capacity != sizeof(key_bytes)
            || value.data != expected_value_data
            || value.capacity != sizeof(runtime->durable_scan_value)) {
            runtime->commit_unknown_fence = 1u;
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                runtime->commit_unknown_fence = 1u;
                status = NINLIL_E_STORAGE_CORRUPT;
            }
            break;
        }
        if (storage_status_requires_fence(storage_status)) {
            runtime->commit_unknown_fence = 1u;
        }
        if (storage_status != NINLIL_STORAGE_OK) {
            if (key.length != 0u || value.length != 0u) {
                runtime->commit_unknown_fence = 1u;
                status = NINLIL_E_STORAGE_CORRUPT;
                break;
            }
            status = map_storage_status(runtime, storage_status);
            break;
        }
        if (key.length != sizeof(key_bytes)
            || value.length < NINLIL_RT_V1_EVENT_LEDGER_RECORD_MIN_BYTES
            || value.length > NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES
            || memcmp(key.data, prefix, sizeof(prefix)) != 0) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        if (have_previous != 0u
            && memcmp(previous_key, key.data, sizeof(previous_key)) >= 0) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        (void)memcpy(previous_key, key.data, sizeof(previous_key));
        have_previous = 1u;
        status = ninlil_rt_v1_event_ledger_decode(
            (ninlil_bytes_view_t){value.data, value.length}, &record);
        if (status != NINLIL_OK
            || record.operation_kind
                != NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME
            || !ledger_matches_transaction(transaction, &record)
            || !id_equal(&record.transaction_id, transaction_id)
            || memcmp(
                record.operation_id.bytes,
                &key.data[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES],
                sizeof(record.operation_id.bytes)) != 0) {
            status = status == NINLIL_OK
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
            break;
        }
        if (count >= NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        if (out_ordered_sequences != NULL
            && count >= ordered_sequence_capacity) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        {
            uint32_t cycle_index;

            for (cycle_index = 0u; cycle_index < count; ++cycle_index) {
                if (seen_cycles[cycle_index]
                        == record.replay_retry_cycle_id
                    || seen_spool_revisions[cycle_index]
                        == record.replay_spool_revision
                    || seen_ordered_sequences[cycle_index]
                        == record.ordered_sequence
                    || ((seen_cycles[cycle_index]
                                < record.replay_retry_cycle_id)
                        != (seen_spool_revisions[cycle_index]
                                < record.replay_spool_revision))
                    || ((seen_cycles[cycle_index]
                                < record.replay_retry_cycle_id)
                        != (seen_ordered_sequences[cycle_index]
                                < record.ordered_sequence))) {
                    status = NINLIL_E_STORAGE_CORRUPT;
                    break;
                }
            }
            if (status != NINLIL_OK) {
                break;
            }
        }
        seen_cycles[count] = record.replay_retry_cycle_id;
        seen_spool_revisions[count] = record.replay_spool_revision;
        seen_ordered_sequences[count] = record.ordered_sequence;
        if (out_ordered_sequences != NULL) {
            out_ordered_sequences[count] = record.ordered_sequence;
        }
        count += 1u;
        if (record.replay_retry_cycle_id > latest_cycle) {
            latest_cycle = record.replay_retry_cycle_id;
            *out_latest_operation_id = record.operation_id;
            *out_latest_ordered_sequence = record.ordered_sequence;
        }
    }
    storage->iter_close(storage->user, iterator);
    status = close_read_transaction(runtime, storage_txn, status);
    if (status == NINLIL_OK) {
        *out_count = count;
    }
    return status;
}

static ninlil_status_t count_discard_operations(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    uint32_t *out_count,
    uint64_t *out_ordered_sequence)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_rt_v1_event_ledger_record_t record;
    uint8_t prefix[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES];
    uint8_t key_bytes[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t previous_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t storage_status;
    ninlil_status_t status;
    uint32_t count = 0u;
    uint32_t have_previous = 0u;
    const ninlil_id128_t *transaction_id = &transaction->transaction_id;

    *out_count = 0u;
    *out_ordered_sequence = 0u;
    status = begin_storage_transaction(
        runtime, NINLIL_STORAGE_READ_ONLY, &storage_txn);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_rt_v1_event_ledger_transaction_prefix(
        NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
        transaction_id,
        prefix);
    status = open_storage_iterator(
        runtime,
        storage_txn,
        (ninlil_bytes_view_t){prefix, sizeof(prefix)},
        &iterator);
    if (status != NINLIL_OK) {
        return close_read_transaction(runtime, storage_txn, status);
    }
    for (;;) {
        uint8_t *const expected_key_data = key_bytes;
        uint8_t *const expected_value_data = runtime->durable_scan_value;

        key.data = expected_key_data;
        key.capacity = (uint32_t)sizeof(key_bytes);
        key.length = 0u;
        value.data = expected_value_data;
        value.capacity = (uint32_t)sizeof(runtime->durable_scan_value);
        value.length = 0u;
        storage_status = storage->iter_next(
            storage->user, iterator, &key, &value);
        if (key.data != expected_key_data
            || key.capacity != sizeof(key_bytes)
            || value.data != expected_value_data
            || value.capacity != sizeof(runtime->durable_scan_value)) {
            runtime->commit_unknown_fence = 1u;
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                runtime->commit_unknown_fence = 1u;
                status = NINLIL_E_STORAGE_CORRUPT;
            }
            break;
        }
        if (storage_status_requires_fence(storage_status)) {
            runtime->commit_unknown_fence = 1u;
        }
        if (storage_status != NINLIL_STORAGE_OK) {
            if (key.length != 0u || value.length != 0u) {
                runtime->commit_unknown_fence = 1u;
                status = NINLIL_E_STORAGE_CORRUPT;
                break;
            }
            status = map_storage_status(runtime, storage_status);
            break;
        }
        if (key.length != sizeof(key_bytes)
            || value.length < NINLIL_RT_V1_EVENT_LEDGER_RECORD_MIN_BYTES
            || value.length > NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES
            || memcmp(key.data, prefix, sizeof(prefix)) != 0
            || (have_previous != 0u
                && memcmp(
                    previous_key, key.data, sizeof(previous_key)) >= 0)) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        (void)memcpy(previous_key, key.data, sizeof(previous_key));
        have_previous = 1u;
        status = ninlil_rt_v1_event_ledger_decode(
            (ninlil_bytes_view_t){value.data, value.length}, &record);
        if (status != NINLIL_OK
            || record.operation_kind
                != NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD
            || !ledger_matches_transaction(transaction, &record)
            || !id_equal(&record.transaction_id, transaction_id)
            || memcmp(
                record.operation_id.bytes,
                &key.data[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES],
                sizeof(record.operation_id.bytes)) != 0) {
            status = status == NINLIL_OK
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
            break;
        }
        if (count != 0u) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        count = 1u;
        *out_ordered_sequence = record.ordered_sequence;
    }
    storage->iter_close(storage->user, iterator);
    status = close_read_transaction(runtime, storage_txn, status);
    if (status == NINLIL_OK) {
        *out_count = count;
    }
    return status;
}

#define NINLIL_RT_V1_MAX_MANAGEMENT_ORDERED_SEQUENCES                       \
    (NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS + 1u)

static ninlil_status_t collect_management_ordered_sequences(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    uint64_t out_sequences[NINLIL_RT_V1_MAX_MANAGEMENT_ORDERED_SEQUENCES],
    uint32_t *out_count)
{
    ninlil_id128_t latest_resume_operation_id;
    uint64_t latest_resume_ordered_sequence;
    uint64_t discard_ordered_sequence;
    uint32_t resume_count;
    uint32_t discard_count;
    ninlil_status_t status;

    *out_count = 0u;
    if (transaction->family != NINLIL_FAMILY_EVENT_FACT) {
        return NINLIL_OK;
    }
    status = count_resume_operations(
        runtime,
        transaction,
        &resume_count,
        &latest_resume_operation_id,
        &latest_resume_ordered_sequence,
        out_sequences,
        NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS);
    if (status != NINLIL_OK) {
        return status;
    }
    status = count_discard_operations(
        runtime,
        transaction,
        &discard_count,
        &discard_ordered_sequence);
    if (status != NINLIL_OK) {
        return status;
    }
    if (discard_count != 0u) {
        out_sequences[resume_count] = discard_ordered_sequence;
    }
    *out_count = resume_count + discard_count;
    return NINLIL_OK;
}

static int ordered_sequence_sets_overlap(
    uint64_t transaction_sequence_left,
    const uint64_t *management_sequences_left,
    uint32_t management_count_left,
    uint64_t transaction_sequence_right,
    const uint64_t *management_sequences_right,
    uint32_t management_count_right)
{
    uint32_t left;
    uint32_t right;

    if (transaction_sequence_left != 0u
        && transaction_sequence_left == transaction_sequence_right) {
        return 1;
    }
    for (left = 0u; left < management_count_left; ++left) {
        if (management_sequences_left[left] == 0u) {
            continue;
        }
        if (management_sequences_left[left] == transaction_sequence_right) {
            return 1;
        }
        for (right = 0u; right < management_count_right; ++right) {
            if (management_sequences_left[left]
                == management_sequences_right[right]) {
                return 1;
            }
        }
    }
    if (transaction_sequence_left != 0u) {
        for (right = 0u; right < management_count_right; ++right) {
            if (transaction_sequence_left
                == management_sequences_right[right]) {
                return 1;
            }
        }
    }
    return 0;
}

static ninlil_status_t validate_all_event_ledgers(
    ninlil_runtime_t *runtime,
    uint16_t ledger_prefix,
    ninlil_rt_v1_event_ledger_kind_t expected_kind,
    uint64_t last_ordered_input_sequence)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_rt_v1_event_ledger_record_t record;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t key_transaction_id;
    ninlil_id128_t key_operation_id;
    uint8_t prefix[2];
    uint8_t key_bytes[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t previous_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t opposite_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t storage_status;
    ninlil_status_t status;
    uint32_t have_previous = 0u;

    encode_u16_be(prefix, ledger_prefix);
    status = begin_storage_transaction(
        runtime, NINLIL_STORAGE_READ_ONLY, &storage_txn);
    if (status != NINLIL_OK) {
        return status;
    }
    status = open_storage_iterator(
        runtime,
        storage_txn,
        (ninlil_bytes_view_t){prefix, sizeof(prefix)},
        &iterator);
    if (status != NINLIL_OK) {
        return close_read_transaction(runtime, storage_txn, status);
    }
    for (;;) {
        uint8_t *const expected_key_data = key_bytes;
        uint8_t *const expected_value_data = runtime->durable_scan_value;

        key.data = expected_key_data;
        key.capacity = (uint32_t)sizeof(key_bytes);
        key.length = 0u;
        value.data = expected_value_data;
        value.capacity = (uint32_t)sizeof(runtime->durable_scan_value);
        value.length = 0u;
        storage_status = storage->iter_next(
            storage->user, iterator, &key, &value);
        if (key.data != expected_key_data
            || key.capacity != sizeof(key_bytes)
            || value.data != expected_value_data
            || value.capacity != sizeof(runtime->durable_scan_value)) {
            runtime->commit_unknown_fence = 1u;
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                runtime->commit_unknown_fence = 1u;
                status = NINLIL_E_STORAGE_CORRUPT;
            }
            break;
        }
        if (storage_status_requires_fence(storage_status)) {
            runtime->commit_unknown_fence = 1u;
        }
        if (storage_status != NINLIL_STORAGE_OK) {
            if (key.length != 0u || value.length != 0u) {
                runtime->commit_unknown_fence = 1u;
                status = NINLIL_E_STORAGE_CORRUPT;
                break;
            }
            status = map_storage_status(runtime, storage_status);
            break;
        }
        if (key.length != sizeof(key_bytes)
            || value.length < NINLIL_RT_V1_EVENT_LEDGER_RECORD_MIN_BYTES
            || value.length > NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES
            || memcmp(key.data, prefix, sizeof(prefix)) != 0
            || (have_previous != 0u
                && memcmp(
                    previous_key, key.data, sizeof(previous_key)) >= 0)) {
            status = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        (void)memcpy(previous_key, key.data, sizeof(previous_key));
        have_previous = 1u;
        (void)memcpy(
            key_transaction_id.bytes,
            &key.data[2],
            sizeof(key_transaction_id.bytes));
        (void)memcpy(
            key_operation_id.bytes,
            &key.data[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES],
            sizeof(key_operation_id.bytes));
        status = ninlil_rt_v1_event_ledger_decode(
            (ninlil_bytes_view_t){value.data, value.length}, &record);
        transaction =
            status == NINLIL_OK
            ? ninlil_rt_find_transaction(runtime, &key_transaction_id)
            : NULL;
        if (status != NINLIL_OK
            || record.operation_kind != expected_kind
            || !ledger_matches_key(
                &record, &key_transaction_id, &key_operation_id)
            || transaction == NULL
            || !ledger_matches_transaction(transaction, &record)
            || record.ordered_sequence > last_ordered_input_sequence) {
            status = status == NINLIL_OK
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
            break;
        }
        if (expected_kind == NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME) {
            uint32_t opposite_found = 0u;
            uint32_t opposite_length = 0u;

            ninlil_rt_v1_event_ledger_key(
                NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
                &key_transaction_id,
                &key_operation_id,
                opposite_key);
            status = read_exact(
                runtime,
                storage_txn,
                (ninlil_bytes_view_t){
                    opposite_key, sizeof(opposite_key)},
                &opposite_found,
                &opposite_length);
            if (status != NINLIL_OK || opposite_found != 0u) {
                status = status == NINLIL_OK
                    ? NINLIL_E_STORAGE_CORRUPT
                    : status;
                break;
            }
        }
    }
    storage->iter_close(storage->user, iterator);
    return close_read_transaction(runtime, storage_txn, status);
}

static ninlil_status_t read_ordered_input_counter(
    ninlil_runtime_t *runtime,
    ninlil_model_runtime_store_counter_t *out_counter)
{
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_model_runtime_store_key_t key;
    ninlil_model_runtime_store_counter_t counter;
    uint32_t found = 0u;
    uint32_t value_length = 0u;
    ninlil_status_t status;

    status = ninlil_model_runtime_store_build_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT, &key);
    if (status != NINLIL_OK) {
        return status;
    }
    status = begin_storage_transaction(
        runtime, NINLIL_STORAGE_READ_ONLY, &storage_txn);
    if (status != NINLIL_OK) {
        return status;
    }
    status = read_exact(
        runtime,
        storage_txn,
        (ninlil_bytes_view_t){key.bytes, key.length},
        &found,
        &value_length);
    if (status == NINLIL_OK && found == 0u) {
        status = NINLIL_E_STORAGE_CORRUPT;
    }
    if (status == NINLIL_OK) {
        status = ninlil_model_runtime_store_decode_counter(
            NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
            (ninlil_bytes_view_t){
                runtime->durable_scan_value, value_length},
            &counter);
    }
    status = close_read_transaction(runtime, storage_txn, status);
    if (status == NINLIL_OK) {
        *out_counter = counter;
    }
    return status;
}

ninlil_status_t ninlil_rt_v1_event_ledger_boot_validate(
    ninlil_runtime_t *runtime)
{
    ninlil_model_runtime_store_counter_t ordered_counter;
    ninlil_status_t status;
    uint32_t index;

    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = read_ordered_input_counter(runtime, &ordered_counter);
    if (status == NINLIL_OK) {
        status = validate_all_event_ledgers(
        runtime,
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME,
        ordered_counter.value);
    }
    if (status == NINLIL_OK) {
        status = validate_all_event_ledgers(
            runtime,
            NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
            NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD,
            ordered_counter.value);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[index];
        ninlil_id128_t latest_resume_operation_id;
        uint64_t latest_resume_ordered_sequence;
        uint64_t discard_ordered_sequence;
        uint32_t resume_count;
        uint32_t discard_count;

        if (transaction->in_use == 0u) {
            continue;
        }
        if (transaction->ordered_input_sequence > ordered_counter.value) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (transaction->family != NINLIL_FAMILY_EVENT_FACT) {
            if (transaction->resume_op_count != 0u
                || id_nonzero(&transaction->last_resume_operation_id)
                || transaction->event_discarded != 0u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            continue;
        }
        status = count_resume_operations(
            runtime,
            transaction,
            &resume_count,
            &latest_resume_operation_id,
            &latest_resume_ordered_sequence,
            NULL,
            0u);
        if (status != NINLIL_OK) {
            return status;
        }
        if (resume_count != transaction->resume_op_count
            || (resume_count == 0u
                && id_nonzero(&transaction->last_resume_operation_id))
            || (resume_count != 0u
                && !id_equal(
                    &latest_resume_operation_id,
                    &transaction->last_resume_operation_id))) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = count_discard_operations(
            runtime,
            transaction,
            &discard_count,
            &discard_ordered_sequence);
        if (status != NINLIL_OK) {
            return status;
        }
        if (discard_count != transaction->event_discarded) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (discard_count != 0u
            && resume_count != 0u
            && discard_ordered_sequence
                <= latest_resume_ordered_sequence) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    /*
     * An ordered input number names exactly one logical input operation.
     * A management ledger and its own transaction snapshot may repeat that
     * number because they are the two atomic representations of the same
     * operation.  No record belonging to a different transaction may reuse
     * it.  Compare one bounded transaction pair at a time so boot validation
     * remains heap-free.
     */
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *left =
            &runtime->transactions[index];
        uint64_t left_management[
            NINLIL_RT_V1_MAX_MANAGEMENT_ORDERED_SEQUENCES];
        uint32_t left_management_count;
        uint32_t right_index;

        if (left->in_use == 0u) {
            continue;
        }
        status = collect_management_ordered_sequences(
            runtime,
            left,
            left_management,
            &left_management_count);
        if (status != NINLIL_OK) {
            return status;
        }
        for (right_index = index + 1u;
             right_index < runtime->transaction_capacity;
             ++right_index) {
            const ninlil_rt_transaction_slot_t *right =
                &runtime->transactions[right_index];
            uint64_t right_management[
                NINLIL_RT_V1_MAX_MANAGEMENT_ORDERED_SEQUENCES];
            uint32_t right_management_count;

            if (right->in_use == 0u) {
                continue;
            }
            status = collect_management_ordered_sequences(
                runtime,
                right,
                right_management,
                &right_management_count);
            if (status != NINLIL_OK) {
                return status;
            }
            if (ordered_sequence_sets_overlap(
                    left->ordered_input_sequence,
                    left_management,
                    left_management_count,
                    right->ordered_input_sequence,
                    right_management,
                    right_management_count)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
    }
    runtime->last_assigned_ordered_input_sequence =
        ordered_counter.value;
    if (ordered_counter.value == UINT64_MAX) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
    }
    return NINLIL_OK;
}

static void txn_marker_key(
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES],
    uint16_t prefix,
    const ninlil_id128_t *transaction_id)
{
    encode_u16_be(key, prefix);
    (void)memcpy(
        &key[2], transaction_id->bytes, sizeof(transaction_id->bytes));
}

static ninlil_status_t storage_txn_commit_full(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;

    return map_storage_status(
        runtime,
        storage->commit(
            storage->user, storage_txn, NINLIL_DURABILITY_FULL));
}

static ninlil_status_t durable_put(
    ninlil_runtime_t *runtime,
    ninlil_v1_durable_operation_t operation,
    ninlil_storage_txn_t storage_txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_status_t status = ninlil_v1_durable_storage_put(
        operation,
        runtime->platform->storage,
        storage_txn,
        key,
        value,
        &runtime->commit_unknown_fence);

    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
    }
    return status;
}

static ninlil_status_t stage_ordered_input_counter(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_v1_durable_operation_t operation,
    uint64_t ordered_input_sequence)
{
    ninlil_model_runtime_store_key_t key;
    ninlil_model_runtime_store_counter_t counter;
    uint8_t value[NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES];
    uint32_t value_length = 0u;
    ninlil_status_t status;

    (void)memset(&counter, 0, sizeof(counter));
    counter.kind = NINLIL_MODEL_RUNTIME_STORE_COUNTER_ORDERED_INPUT;
    counter.value = ordered_input_sequence;
    counter.exhausted_marker =
        ordered_input_sequence == UINT64_MAX ? 1u : 0u;
    status = ninlil_model_runtime_store_build_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT, &key);
    if (status == NINLIL_OK) {
        status = ninlil_model_runtime_store_encode_counter(
            NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
            &counter,
            value,
            (uint32_t)sizeof(value),
            &value_length);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    return durable_put(
        runtime,
        operation,
        storage_txn,
        (ninlil_bytes_view_t){key.bytes, key.length},
        (ninlil_bytes_view_t){value, value_length});
}

static ninlil_status_t build_committed_management_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    uint64_t management_bytes,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_input_t input;
    ninlil_model_capacity_batch_result_t result;
    ninlil_status_t status;

    if (current == NULL || out_ledger == NULL || management_bytes == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&input, 0, sizeof(input));
    input.current = *current;
    input.operation = NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    input.request_count = 1u;
    input.requests[0].kind = NINLIL_RESOURCE_EVENT_SPOOL_BYTES;
    input.requests[0].amount = management_bytes;
    status = ninlil_model_capacity_batch_transition(&input, &result);
    if (status != NINLIL_OK) {
        return status;
    }
    if (result.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_ledger = result.next;
    return NINLIL_OK;
}

static ninlil_status_t commit_event_mgmt_transition(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_transaction_slot_t *candidate,
    uint16_t operation_prefix,
    ninlil_v1_durable_operation_t operation,
    const ninlil_id128_t *operation_id,
    const uint8_t *ledger_value,
    uint32_t ledger_value_length)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_rt_transaction_slot_t *committed =
        &runtime->transaction_decode_scratch;
    uint8_t ledger_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t state_key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    uint32_t state_value_length = 0u;
    uint32_t committed_payload_length;
    uint64_t management_bytes;
    int releases_reservation;
    ninlil_status_t status;

    if (transaction->record_revision == UINT64_MAX
        || runtime->last_assigned_ordered_input_sequence == UINT64_MAX
        || candidate->ordered_input_sequence
            != runtime->last_assigned_ordered_input_sequence + 1u
        || !id_equal(
            &transaction->transaction_id, &candidate->transaction_id)) {
        return NINLIL_E_DEGRADED;
    }
    *committed = *candidate;
    committed->record_revision = transaction->record_revision + 1u;
    if (operation_prefix == NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX) {
        management_bytes = 256u;
    } else if (
        operation_prefix == NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX) {
        management_bytes = 512u;
    } else {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = build_committed_management_resource_ledger(
        &runtime->resource_ledger,
        management_bytes,
        &runtime->resource_ledger_scratch);
    if (status != NINLIL_OK) {
        return status;
    }
    releases_reservation =
        committed->event_discarded != 0u
        && transaction->reservation_active != 0u;
    if (releases_reservation) {
        /*
         * Capacity release accounts the pre-discard payload while retaining
         * successful management-operation logical bytes. The durable
         * transaction snapshot itself still erases the payload.
         */
        committed_payload_length = committed->payload_length;
        committed->payload_length = transaction->payload_length;
        status = ninlil_rt_v1_build_released_resource_ledger_from(
            &runtime->resource_ledger_scratch,
            committed,
            &runtime->resource_ledger_scratch);
        committed->payload_length = committed_payload_length;
        if (status != NINLIL_OK) {
            return status;
        }
        committed->reservation_active = 0u;
    }
    status = ninlil_rt_v1_transaction_record_encode(
        committed,
        runtime->transaction_codec_bytes,
        (uint32_t)sizeof(runtime->transaction_codec_bytes),
        &state_value_length);
    if (status != NINLIL_OK) {
        return status;
    }
    status = begin_storage_transaction(
        runtime, NINLIL_STORAGE_READ_WRITE, &storage_txn);
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_rt_v1_event_ledger_key(
        operation_prefix,
        &transaction->transaction_id,
        operation_id,
        ledger_key);
    status = durable_put(
        runtime,
        operation,
        storage_txn,
        (ninlil_bytes_view_t){ledger_key, sizeof(ledger_key)},
        (ninlil_bytes_view_t){ledger_value, ledger_value_length});
    if (status == NINLIL_OK) {
        txn_marker_key(
            state_key,
            NINLIL_RT_V1_MARKER_ES,
            &transaction->transaction_id);
        status = durable_put(
            runtime,
            NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT,
            storage_txn,
            (ninlil_bytes_view_t){state_key, sizeof(state_key)},
            (ninlil_bytes_view_t){
                runtime->transaction_codec_bytes, state_value_length});
    }
    if (status == NINLIL_OK && releases_reservation) {
        txn_marker_key(
            state_key,
            NINLIL_RT_V1_MARKER_RV,
            &transaction->transaction_id);
        status = map_storage_status(
            runtime,
            storage->erase(
                storage->user,
                storage_txn,
                (ninlil_bytes_view_t){state_key, sizeof(state_key)}));
    }
    if (status == NINLIL_OK) {
        status = stage_ordered_input_counter(
            runtime,
            storage_txn,
            operation,
            committed->ordered_input_sequence);
    }
    if (status == NINLIL_OK) {
        status = ninlil_rt_v1_stage_resource_ledger(
            runtime,
            storage_txn,
            operation,
            &runtime->resource_ledger_scratch);
    }
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, storage_txn);
        return status;
    }
    status = storage_txn_commit_full(runtime, storage_txn);
    if (status == NINLIL_OK) {
        runtime->resource_ledger = runtime->resource_ledger_scratch;
        runtime->last_assigned_ordered_input_sequence =
            committed->ordered_input_sequence;
        if (committed->ordered_input_sequence == UINT64_MAX) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        }
        *transaction = *committed;
    }
    return status;
}

static void zero_resume_result(ninlil_event_resume_result_t *out_result)
{
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
}

static void zero_discard_result(ninlil_event_discard_result_t *out_result)
{
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
}

static int request_header_valid(
    uint16_t abi_version,
    uint16_t struct_size,
    size_t expected_size)
{
    return abi_version == NINLIL_ABI_VERSION
        && struct_size == (uint16_t)expected_size;
}

static int metadata_valid(ninlil_bytes_view_t metadata)
{
    return metadata.data != NULL
        && metadata.length >= 1u
        && metadata.length <= NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES;
}

static int resume_request_valid(
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request)
{
    return id_nonzero(transaction_id)
        && request_header_valid(
            request->abi_version, request->struct_size, sizeof(*request))
        && id_nonzero(&request->operation_id)
        && id_nonzero(&request->actor_id)
        && request->expected_spool_revision != 0u
        && event_operation_reason_valid(
            NINLIL_RT_V1_EVENT_RESUME_PREFIX, request->resume_reason)
        && request->reserved_zero == 0u
        && metadata_valid(request->audit_metadata);
}

static int discard_request_valid(
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request)
{
    return id_nonzero(transaction_id)
        && request_header_valid(
            request->abi_version, request->struct_size, sizeof(*request))
        && id_nonzero(&request->operation_id)
        && id_nonzero(&request->actor_id)
        && id_nonzero(&request->expected_event_id)
        && request->expected_content_digest.algorithm
            == NINLIL_DIGEST_SHA256
        && request->expected_content_digest.reserved_zero == 0u
        && bytes_nonzero(
            request->expected_content_digest.bytes, NINLIL_SHA256_BYTES)
        && request->expected_spool_revision != 0u
        && event_operation_reason_valid(
            NINLIL_RT_V1_EVENT_DISCARD_PREFIX, request->discard_reason)
        && request->acknowledge_required_receipt_absent == 1u
        && metadata_valid(request->audit_metadata);
}

static ninlil_status_t read_trusted_clock(
    ninlil_runtime_t *runtime,
    ninlil_time_sample_t *out_sample)
{
    ninlil_port_status_t port_status;

    (void)memset(out_sample, 0, sizeof(*out_sample));
    port_status = runtime->platform->clock->now(
        runtime->platform->clock->user, out_sample);
    if (port_status == NINLIL_PORT_TEMPORARY_FAILURE
        || (port_status == NINLIL_PORT_OK
            && out_sample->trust == NINLIL_CLOCK_UNCERTAIN)) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (port_status != NINLIL_PORT_OK
        || out_sample->abi_version != NINLIL_ABI_VERSION
        || out_sample->struct_size != sizeof(*out_sample)
        || out_sample->trust != NINLIL_CLOCK_TRUSTED
        || !id_nonzero(&out_sample->clock_epoch_id)
        || out_sample->reserved_zero != 0u) {
        return NINLIL_E_DEGRADED;
    }
    return NINLIL_OK;
}

static ninlil_status_t catch_up_targeted_management(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *sample)
{
    ninlil_rt_v1_step_delivery_result_t catch_up_result;
    uint32_t changed = 0u;

    (void)memset(&catch_up_result, 0, sizeof(catch_up_result));
    return ninlil_rt_v1_targeted_management_catch_up(
        runtime,
        transaction,
        sample,
        UINT32_MAX,
        &catch_up_result,
        &changed);
}

static uint64_t current_retry_cycle(
    const ninlil_rt_transaction_slot_t *transaction)
{
    return transaction->retry_cycle_id;
}

static void set_resume_semantic(
    ninlil_event_resume_result_t *out_result,
    const ninlil_event_resume_request_t *request,
    const ninlil_rt_transaction_slot_t *transaction,
    ninlil_event_resume_kind_t kind,
    ninlil_reason_t reason)
{
    out_result->kind = kind;
    out_result->reason = reason;
    out_result->operation_id = request->operation_id;
    out_result->retry_cycle_id = current_retry_cycle(transaction);
    out_result->spool_revision = transaction->spool_revision;
}

static void set_discard_semantic(
    ninlil_event_discard_result_t *out_result,
    const ninlil_event_discard_request_t *request,
    const ninlil_rt_transaction_slot_t *transaction,
    ninlil_event_discard_kind_t kind,
    ninlil_reason_t reason)
{
    out_result->kind = kind;
    out_result->reason = reason;
    out_result->operation_id = request->operation_id;
    out_result->spool_revision = transaction->spool_revision;
}

static void replay_resume(
    const ninlil_rt_v1_event_ledger_record_t *record,
    ninlil_event_resume_result_t *out_result)
{
    out_result->kind = record->replay_result_kind;
    out_result->reason = record->replay_result_reason;
    out_result->operation_id = record->operation_id;
    out_result->retry_cycle_id = record->replay_retry_cycle_id;
    out_result->spool_revision = record->replay_spool_revision;
}

static void replay_discard(
    const ninlil_rt_v1_event_ledger_record_t *record,
    ninlil_event_discard_result_t *out_result)
{
    out_result->kind = record->replay_result_kind;
    out_result->reason = record->replay_result_reason;
    out_result->operation_id = record->operation_id;
    out_result->audit_clock_epoch_id = record->audit_clock_epoch_id;
    out_result->audit_committed_at_ms =
        record->audit_committed_at_ms;
    out_result->spool_revision = record->replay_spool_revision;
    out_result->spool_released = record->replay_spool_released;
}

static void clear_resume_cycle_state(
    ninlil_rt_transaction_slot_t *candidate)
{
    uint32_t index;

    candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    candidate->pending_dispatch = 1u;
    candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    candidate->delivery_count = 0u;
    candidate->attempt_count = 0u;
    candidate->attempt_prepared = 0u;
    (void)memset(
        &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
    (void)memset(
        candidate->attempt_ids, 0, sizeof(candidate->attempt_ids));
    candidate->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    candidate->next_retry_ms = 0u;
    (void)memset(
        &candidate->next_retry_clock_epoch_id,
        0,
        sizeof(candidate->next_retry_clock_epoch_id));
    candidate->token_state = NINLIL_RT_TOKEN_NONE;
    candidate->deferred_wait = 0u;
    (void)memset(
        &candidate->token_clock_epoch_id,
        0,
        sizeof(candidate->token_clock_epoch_id));
    candidate->token_generation = 0u;
    candidate->delivery_started_at_ms = 0u;
    candidate->token_expires_at_ms = 0u;
    candidate->application_completion_timeout_ms = 0u;
    for (index = 0u; index < candidate->bound_target_count; ++index) {
        candidate->bound_targets[index].pending_dispatch = 1u;
    }
}

static void fill_resume_ledger(
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_event_resume_request_t *request,
    const uint8_t request_digest[NINLIL_SHA256_BYTES],
    uint64_t ordered_input_sequence,
    uint64_t next_retry_cycle_id,
    ninlil_rt_v1_event_ledger_record_t *out_record)
{
    (void)memset(out_record, 0, sizeof(*out_record));
    out_record->operation_kind =
        NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME;
    out_record->record_revision = 1u;
    out_record->ordered_sequence = ordered_input_sequence;
    out_record->transaction_id = transaction->transaction_id;
    out_record->event_id = transaction->event_id;
    out_record->operation_id = request->operation_id;
    out_record->actor_id = request->actor_id;
    (void)memcpy(
        out_record->canonical_request_digest,
        request_digest,
        NINLIL_SHA256_BYTES);
    out_record->expected_spool_revision =
        request->expected_spool_revision;
    out_record->request_reason = request->resume_reason;
    out_record->metadata_length = request->audit_metadata.length;
    (void)memcpy(
        out_record->metadata,
        request->audit_metadata.data,
        request->audit_metadata.length);
    out_record->replay_result_kind =
        NINLIL_EVENT_RESUME_ALREADY_RESUMED;
    out_record->replay_result_reason = NINLIL_REASON_NONE;
    out_record->replay_retry_cycle_id = next_retry_cycle_id;
    out_record->replay_spool_revision = transaction->spool_revision + 1u;
}

static void fill_discard_ledger(
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_event_discard_request_t *request,
    const uint8_t request_digest[NINLIL_SHA256_BYTES],
    const ninlil_time_sample_t *sample,
    uint64_t ordered_input_sequence,
    ninlil_rt_v1_event_ledger_record_t *out_record)
{
    (void)memset(out_record, 0, sizeof(*out_record));
    out_record->operation_kind =
        NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD;
    out_record->record_revision = 1u;
    out_record->ordered_sequence = ordered_input_sequence;
    out_record->transaction_id = transaction->transaction_id;
    out_record->event_id = transaction->event_id;
    out_record->operation_id = request->operation_id;
    out_record->actor_id = request->actor_id;
    (void)memcpy(
        out_record->canonical_request_digest,
        request_digest,
        NINLIL_SHA256_BYTES);
    out_record->expected_spool_revision =
        request->expected_spool_revision;
    out_record->expected_event_id = request->expected_event_id;
    out_record->expected_content_digest_algorithm =
        request->expected_content_digest.algorithm;
    (void)memcpy(
        out_record->expected_content_digest,
        request->expected_content_digest.bytes,
        NINLIL_SHA256_BYTES);
    out_record->request_reason = request->discard_reason;
    out_record->acknowledge_flag =
        request->acknowledge_required_receipt_absent;
    out_record->metadata_length = request->audit_metadata.length;
    (void)memcpy(
        out_record->metadata,
        request->audit_metadata.data,
        request->audit_metadata.length);
    out_record->audit_clock_epoch_id = sample->clock_epoch_id;
    out_record->audit_committed_at_ms = sample->now_ms;
    out_record->replay_result_kind =
        NINLIL_EVENT_DISCARD_ALREADY_DISCARDED;
    out_record->replay_result_reason =
        NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    out_record->replay_spool_revision = transaction->spool_revision + 1u;
    out_record->replay_spool_released = 1u;
}

ninlil_status_t ninlil_rt_v1_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_rt_v1_event_ledger_record_t ledger_record;
    ninlil_time_sample_t sample;
    operation_lookup_kind_t lookup;
    uint8_t request_digest[NINLIL_SHA256_BYTES];
    uint8_t ledger_value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint64_t next_ordered_input_sequence;
    uint32_t ledger_value_length = 0u;
    uint32_t resume_count = 0u;
    ninlil_id128_t latest_resume_operation_id;
    uint64_t latest_resume_ordered_sequence;
    ninlil_status_t status;

    if (runtime == NULL || transaction_id == NULL || request == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    zero_resume_result(out_result);
    if (!resume_request_valid(transaction_id, request)) {
        return request->abi_version != NINLIL_ABI_VERSION
                || request->struct_size != sizeof(*request)
            ? NINLIL_E_ABI_MISMATCH
            : NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return NINLIL_E_UNSUPPORTED;
    }
    transaction = ninlil_rt_find_transaction(runtime, transaction_id);
    if (transaction == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (transaction->family != NINLIL_FAMILY_EVENT_FACT) {
        out_result->kind = NINLIL_EVENT_RESUME_NOT_EVENT_FACT;
        out_result->reason = NINLIL_REASON_EVENT_FACT_IMMUTABLE;
        out_result->operation_id = request->operation_id;
        return NINLIL_OK;
    }
    status = ninlil_rt_v1_event_resume_request_digest(
        transaction_id, request, request_digest);
    if (status != NINLIL_OK) {
        return status;
    }
    status = lookup_operation(
        runtime,
        transaction,
        &request->operation_id,
        NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME,
        request_digest,
        &lookup,
        &ledger_record);
    if (status != NINLIL_OK) {
        return status;
    }
    if (lookup == OPERATION_LOOKUP_REPLAY) {
        replay_resume(&ledger_record, out_result);
        return NINLIL_OK;
    }
    if (lookup == OPERATION_LOOKUP_CONFLICT) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_CONFLICT,
            NINLIL_REASON_RESUME_CONFLICT);
        return NINLIL_OK;
    }
    status = read_trusted_clock(runtime, &sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = catch_up_targeted_management(
        runtime, transaction, &sample);
    if (status != NINLIL_OK) {
        zero_resume_result(out_result);
        return status;
    }
    if (transaction->event_discarded != 0u) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_ALREADY_DISCARDED,
            NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT);
        return NINLIL_OK;
    }
    if (transaction->terminal != 0u
        || transaction->reservation_active == 0u) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_ALREADY_RELEASED,
            NINLIL_REASON_REQUIRED_EVIDENCE_MET);
        return NINLIL_OK;
    }
    if (transaction->delivery_phase != NINLIL_RT_DELIVERY_PARKED) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_NOT_PARKED,
            NINLIL_REASON_NONE);
        return NINLIL_OK;
    }
    if (transaction->event_park_cause
        == NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_NOT_RESUMABLE,
            NINLIL_REASON_COUNTER_EXHAUSTED);
        return NINLIL_OK;
    }
    if (request->expected_spool_revision != transaction->spool_revision) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_STALE_SPOOL_REVISION,
            NINLIL_REASON_STALE_SPOOL_REVISION);
        return NINLIL_OK;
    }
    status = count_resume_operations(
        runtime,
        transaction,
        &resume_count,
        &latest_resume_operation_id,
        &latest_resume_ordered_sequence,
        NULL,
        0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (transaction->resume_op_count != resume_count
        || (resume_count == 0u
            && id_nonzero(&transaction->last_resume_operation_id))
        || (resume_count != 0u
            && !id_equal(
                &transaction->last_resume_operation_id,
                &latest_resume_operation_id))) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (resume_count >= NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS) {
        set_resume_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_RESUME_LIMIT_EXHAUSTED,
            NINLIL_REASON_CAPACITY_EXHAUSTED);
        return NINLIL_OK;
    }
    if (transaction->spool_revision == UINT64_MAX
        || transaction->retry_cycle_id == UINT64_MAX) {
        return NINLIL_E_DEGRADED;
    }
    if (runtime->last_assigned_ordered_input_sequence == UINT64_MAX) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    next_ordered_input_sequence =
        runtime->last_assigned_ordered_input_sequence + 1u;
    candidate = &runtime->transaction_scratch;
    status = ninlil_rt_v1_begin_event_retry_cycle(
        transaction, candidate);
    if (status != NINLIL_OK) {
        return status;
    }
    candidate->spool_revision += 1u;
    candidate->ordered_input_sequence = next_ordered_input_sequence;
    candidate->resume_op_count = resume_count + 1u;
    candidate->last_resume_operation_id = request->operation_id;
    clear_resume_cycle_state(candidate);
    fill_resume_ledger(
        transaction,
        request,
        request_digest,
        next_ordered_input_sequence,
        candidate->retry_cycle_id,
        &ledger_record);
    status = ninlil_rt_v1_event_ledger_encode(
        &ledger_record,
        ledger_value,
        (uint32_t)sizeof(ledger_value),
        &ledger_value_length);
    if (status != NINLIL_OK) {
        return status;
    }
    status = commit_event_mgmt_transition(
        runtime,
        transaction,
        candidate,
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        NINLIL_V1_DURABLE_OP_EVENT_RESUME_COMMIT,
        &request->operation_id,
        ledger_value,
        ledger_value_length);
    if (status != NINLIL_OK) {
        zero_resume_result(out_result);
        return status;
    }
    runtime->pending_work = 1u;
    saturating_increment_u64(&runtime->metrics.events_resumed);
    out_result->kind = NINLIL_EVENT_RESUME_RESUMED;
    out_result->reason = NINLIL_REASON_NONE;
    out_result->operation_id = request->operation_id;
    out_result->retry_cycle_id = ledger_record.replay_retry_cycle_id;
    out_result->spool_revision = ledger_record.replay_spool_revision;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_rt_v1_event_ledger_record_t ledger_record;
    ninlil_time_sample_t sample;
    operation_lookup_kind_t lookup;
    uint8_t request_digest[NINLIL_SHA256_BYTES];
    uint8_t ledger_value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint64_t next_ordered_input_sequence;
    uint32_t ledger_value_length = 0u;
    uint32_t index;
    ninlil_status_t status;

    if (runtime == NULL || transaction_id == NULL || request == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    zero_discard_result(out_result);
    if (!discard_request_valid(transaction_id, request)) {
        return request->abi_version != NINLIL_ABI_VERSION
                || request->struct_size != sizeof(*request)
            ? NINLIL_E_ABI_MISMATCH
            : NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return NINLIL_E_UNSUPPORTED;
    }
    transaction = ninlil_rt_find_transaction(runtime, transaction_id);
    if (transaction == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (transaction->family != NINLIL_FAMILY_EVENT_FACT) {
        out_result->kind = NINLIL_EVENT_DISCARD_NOT_EVENT_FACT;
        out_result->reason = NINLIL_REASON_EVENT_FACT_IMMUTABLE;
        out_result->operation_id = request->operation_id;
        return NINLIL_OK;
    }
    status = ninlil_rt_v1_event_discard_request_digest(
        transaction_id, request, request_digest);
    if (status != NINLIL_OK) {
        return status;
    }
    status = lookup_operation(
        runtime,
        transaction,
        &request->operation_id,
        NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD,
        request_digest,
        &lookup,
        &ledger_record);
    if (status != NINLIL_OK) {
        return status;
    }
    if (lookup == OPERATION_LOOKUP_REPLAY) {
        replay_discard(&ledger_record, out_result);
        return NINLIL_OK;
    }
    if (lookup == OPERATION_LOOKUP_CONFLICT) {
        set_discard_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_DISCARD_CONFLICT,
            NINLIL_REASON_DISCARD_CONFLICT);
        return NINLIL_OK;
    }
    status = read_trusted_clock(runtime, &sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = catch_up_targeted_management(
        runtime, transaction, &sample);
    if (status != NINLIL_OK) {
        zero_discard_result(out_result);
        return status;
    }
    if (transaction->event_discarded != 0u) {
        set_discard_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_DISCARD_ALREADY_DISCARDED,
            NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT);
        return NINLIL_OK;
    }
    if (transaction->terminal != 0u
        || transaction->reservation_active == 0u) {
        set_discard_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_DISCARD_ALREADY_RELEASED,
            NINLIL_REASON_REQUIRED_EVIDENCE_MET);
        return NINLIL_OK;
    }
    if (request->expected_spool_revision != transaction->spool_revision) {
        set_discard_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_DISCARD_STALE_SPOOL_REVISION,
            NINLIL_REASON_STALE_SPOOL_REVISION);
        return NINLIL_OK;
    }
    if (!id_equal(&request->expected_event_id, &transaction->event_id)
        || request->expected_content_digest.algorithm
            != transaction->content_digest.algorithm
        || memcmp(
            request->expected_content_digest.bytes,
            transaction->content_digest.bytes,
            sizeof(transaction->content_digest.bytes)) != 0) {
        set_discard_semantic(
            out_result,
            request,
            transaction,
            NINLIL_EVENT_DISCARD_CONFLICT,
            NINLIL_REASON_DISCARD_CONFLICT);
        return NINLIL_OK;
    }
    if (transaction->spool_revision == UINT64_MAX) {
        return NINLIL_E_DEGRADED;
    }
    if (runtime->last_assigned_ordered_input_sequence == UINT64_MAX) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    next_ordered_input_sequence =
        runtime->last_assigned_ordered_input_sequence + 1u;
    fill_discard_ledger(
        transaction,
        request,
        request_digest,
        &sample,
        next_ordered_input_sequence,
        &ledger_record);
    status = ninlil_rt_v1_event_ledger_encode(
        &ledger_record,
        ledger_value,
        (uint32_t)sizeof(ledger_value),
        &ledger_value_length);
    if (status != NINLIL_OK) {
        return status;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->spool_revision += 1u;
    candidate->ordered_input_sequence = next_ordered_input_sequence;
    candidate->event_discarded = 1u;
    candidate->terminal = 1u;
    candidate->pending_dispatch = 0u;
    candidate->outcome_recorded = 1u;
    candidate->outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
    candidate->reason =
        NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
    candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    candidate->payload_length = 0u;
    candidate->inline_payload_length = 0u;
    (void)memset(
        candidate->owned_payload, 0, sizeof(candidate->owned_payload));
    candidate->token_state = NINLIL_RT_TOKEN_NONE;
    candidate->deferred_wait = 0u;
    candidate->pending_dispatch = 0u;
    for (index = 0u; index < candidate->bound_target_count; ++index) {
        ninlil_rt_target_slot_t *target =
            &candidate->bound_targets[index];

        target->terminal = 1u;
        target->pending_dispatch = 0u;
        target->attempt_prepared = 0u;
        (void)memset(
            &target->active_attempt_id,
            0,
            sizeof(target->active_attempt_id));
        target->send_observation_closed = 0u;
        target->send_observed_at_ms = 0u;
        (void)memset(
            &target->send_observed_clock_epoch_id,
            0,
            sizeof(target->send_observed_clock_epoch_id));
        target->next_retry_ms = 0u;
        (void)memset(
            &target->next_retry_clock_epoch_id,
            0,
            sizeof(target->next_retry_clock_epoch_id));
        target->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        target->outcome =
            NINLIL_OUTCOME_FAILED_DEFINITIVE;
        target->reason =
            NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    }
    status = commit_event_mgmt_transition(
        runtime,
        transaction,
        candidate,
        NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
        NINLIL_V1_DURABLE_OP_EVENT_DISCARD_COMMIT,
        &request->operation_id,
        ledger_value,
        ledger_value_length);
    if (status != NINLIL_OK) {
        zero_discard_result(out_result);
        return status;
    }
    if (runtime->nonterminal_transaction_count != 0u) {
        runtime->nonterminal_transaction_count -= 1u;
    }
    saturating_increment_u64(&runtime->metrics.events_discarded);
    saturating_increment_u64(
        &runtime->metrics.transactions_failed_definitive);
    out_result->kind = NINLIL_EVENT_DISCARD_DISCARDED;
    out_result->reason =
        NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    out_result->operation_id = request->operation_id;
    out_result->audit_clock_epoch_id = sample.clock_epoch_id;
    out_result->audit_committed_at_ms = sample.now_ms;
    out_result->spool_revision = ledger_record.replay_spool_revision;
    out_result->spool_released = 1u;
    return NINLIL_OK;
}
