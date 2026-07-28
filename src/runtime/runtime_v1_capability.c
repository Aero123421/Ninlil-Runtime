#include "runtime_v1_capability.h"

#include "domain_store_codec.h"
#include "resource_ledger_batch.h"
#include "runtime_store_codec.h"

#include <string.h>

#define NINLIL_RT_V1_U6_MAX_PAYLOAD_BYTES 926u
#define RESERVATION_MAGIC_0 0x4eu
#define RESERVATION_MAGIC_1 0x52u
#define RESERVATION_MAGIC_2 0x56u
#define RESERVATION_MAGIC_3 0x31u
#define RESERVATION_SCHEMA_MAJOR 1u
#define RESERVATION_SCHEMA_MINOR 0u

static const ninlil_rt_v1_bearer_limit_row_t g_bearer_limit_table[] = {
    {NINLIL_RT_V1_BEARER_ROUTE_SIMULATED, 926u, "SIMULATED/U6"},
    {NINLIL_RT_V1_BEARER_ROUTE_U6, 926u, "U6"}
};

static const uint32_t g_bearer_limit_table_count =
    (uint32_t)(sizeof(g_bearer_limit_table) / sizeof(g_bearer_limit_table[0]));

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

static ninlil_status_t map_storage_mutation_status(
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

ninlil_rt_v1_bearer_route_t ninlil_rt_v1_default_bearer_route(void)
{
    return NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;
}

uint32_t ninlil_rt_v1_bearer_payload_limit(
    ninlil_rt_v1_bearer_route_t route)
{
    uint32_t index;

    for (index = 0u; index < g_bearer_limit_table_count; ++index) {
        if (g_bearer_limit_table[index].route == route) {
            return g_bearer_limit_table[index].max_single_frame_payload_bytes;
        }
    }
    return 0u;
}

int ninlil_rt_v1_bearer_admits_payload(
    ninlil_rt_v1_bearer_route_t route,
    uint32_t payload_length)
{
    uint32_t limit = ninlil_rt_v1_bearer_payload_limit(route);

    if (limit == 0u) {
        return 0;
    }
    return payload_length <= limit;
}

uint8_t ninlil_rt_v1_semantic_priority_for_family(ninlil_family_t family)
{
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        return 8u;
    }
    if (family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED) {
        return 7u;
    }
    if (family == NINLIL_FAMILY_LATEST_STATE_RESERVED) {
        return 5u;
    }
    if (family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return 4u;
    }
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        return 3u;
    }
    return 0u;
}

ninlil_status_t ninlil_rt_v1_build_logical_payload_desc(
    ninlil_family_t family,
    uint32_t payload_length,
    uint64_t effect_deadline_ms,
    ninlil_rt_v1_logical_payload_desc_t *out_desc)
{
    if (out_desc == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_desc, 0, sizeof(*out_desc));
    out_desc->total_logical_bytes = payload_length;
    out_desc->fragment_count = 1u;
    out_desc->effect_deadline_ms = effect_deadline_ms;
    out_desc->semantic_priority = ninlil_rt_v1_semantic_priority_for_family(family);
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_build_logical_fragment_desc(
    uint32_t payload_length,
    ninlil_rt_v1_logical_fragment_desc_t *out_desc)
{
    if (out_desc == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_desc, 0, sizeof(*out_desc));
    out_desc->fragment_index = 0u;
    out_desc->fragment_logical_bytes = payload_length;
    out_desc->fragment_count = 1u;
    return NINLIL_OK;
}

int ninlil_rt_v1_txn_queue_order_less(
    const ninlil_rt_transaction_slot_t *left,
    const ninlil_rt_transaction_slot_t *right)
{
    if (left->semantic_priority != right->semantic_priority) {
        return left->semantic_priority > right->semantic_priority;
    }
    if (left->effect_deadline_ms != right->effect_deadline_ms) {
        if (left->effect_deadline_ms == 0u
            || left->effect_deadline_ms >= NINLIL_NO_DEADLINE) {
            return 0;
        }
        if (right->effect_deadline_ms == 0u
            || right->effect_deadline_ms >= NINLIL_NO_DEADLINE) {
            return 1;
        }
        return left->effect_deadline_ms < right->effect_deadline_ms;
    }
    return left->transaction_sequence < right->transaction_sequence;
}

ninlil_status_t ninlil_rt_v1_check_bearer_payload_admission(
    ninlil_rt_v1_bearer_route_t route,
    uint32_t payload_length,
    ninlil_submission_result_t *out_result)
{
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ninlil_rt_v1_bearer_admits_payload(route, payload_length)) {
        return NINLIL_OK;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version, &out_result->struct_size, sizeof(*out_result));
    out_result->kind = NINLIL_SUBMISSION_REJECTED;
    out_result->reason = NINLIL_REASON_INVALID_PAYLOAD_LENGTH;
    out_result->retry_guidance = NINLIL_RETRY_NEVER;
    return NINLIL_OK;
}

static ninlil_status_t storage_txn_commit_full(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;

    return map_storage_mutation_status(
        runtime,
        storage->commit(storage->user, txn, NINLIL_DURABILITY_FULL));
}

static void txn_marker_key(uint8_t *key, uint16_t prefix, const ninlil_id128_t *txn_id)
{
    key[0] = (uint8_t)(prefix >> 8);
    key[1] = (uint8_t)(prefix & 0xffu);
    (void)memcpy(&key[2], txn_id->bytes, sizeof(txn_id->bytes));
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

ninlil_status_t ninlil_rt_v1_reservation_marker_encode(
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route,
    uint8_t out_value[NINLIL_RT_V1_RESERVATION_MARKER_BYTES])
{
    uint32_t crc;

    if (out_value == NULL
        || !ninlil_rt_v1_bearer_admits_payload(route, payload_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_value, 0, NINLIL_RT_V1_RESERVATION_MARKER_BYTES);
    out_value[0] = RESERVATION_MAGIC_0;
    out_value[1] = RESERVATION_MAGIC_1;
    out_value[2] = RESERVATION_MAGIC_2;
    out_value[3] = RESERVATION_MAGIC_3;
    encode_u16_be(&out_value[4], RESERVATION_SCHEMA_MAJOR);
    encode_u16_be(&out_value[6], RESERVATION_SCHEMA_MINOR);
    encode_u32_be(&out_value[8], payload_length);
    out_value[12] = (uint8_t)route;
    out_value[13] = 1u;
    crc = ninlil_model_domain_crc32c(
        out_value, NINLIL_RT_V1_RESERVATION_MARKER_BYTES - 4u);
    encode_u32_be(
        &out_value[NINLIL_RT_V1_RESERVATION_MARKER_BYTES - 4u], crc);
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_reservation_marker_decode(
    ninlil_bytes_view_t value,
    uint32_t *out_payload_length,
    ninlil_rt_v1_bearer_route_t *out_route)
{
    uint32_t payload_length;
    ninlil_rt_v1_bearer_route_t route;
    uint32_t index;
    uint32_t stored_crc;
    uint32_t computed_crc;

    if (value.data == NULL || out_payload_length == NULL || out_route == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (value.length != NINLIL_RT_V1_RESERVATION_MARKER_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (value.data[0] != RESERVATION_MAGIC_0
        || value.data[1] != RESERVATION_MAGIC_1
        || value.data[2] != RESERVATION_MAGIC_2
        || value.data[3] != RESERVATION_MAGIC_3) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (decode_u16_be(&value.data[4]) != RESERVATION_SCHEMA_MAJOR
        || decode_u16_be(&value.data[6]) != RESERVATION_SCHEMA_MINOR) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (value.data[13] != 1u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    for (index = 14u;
         index < NINLIL_RT_V1_RESERVATION_MARKER_BYTES - 4u;
         ++index) {
        if (value.data[index] != 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    stored_crc = decode_u32_be(
        &value.data[NINLIL_RT_V1_RESERVATION_MARKER_BYTES - 4u]);
    computed_crc = ninlil_model_domain_crc32c(
        value.data, NINLIL_RT_V1_RESERVATION_MARKER_BYTES - 4u);
    if (stored_crc != computed_crc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    payload_length = decode_u32_be(&value.data[8]);
    route = (ninlil_rt_v1_bearer_route_t)value.data[12];
    if (!ninlil_rt_v1_bearer_admits_payload(route, payload_length)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_payload_length = payload_length;
    *out_route = route;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_reservation_marker_validate(
    ninlil_bytes_view_t value)
{
    uint32_t payload_length = 0u;
    ninlil_rt_v1_bearer_route_t route =
        NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;

    return ninlil_rt_v1_reservation_marker_decode(
        value, &payload_length, &route);
}

ninlil_status_t ninlil_rt_v1_commit_reservation_marker(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    ninlil_status_t status;

    if (runtime == NULL || transaction_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    status = map_storage_mutation_status(
        runtime,
        storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn));
    if (status != NINLIL_OK) {
        return status;
    }

    status = ninlil_rt_v1_stage_reservation_marker(
        runtime,
        txn,
        NINLIL_V1_DURABLE_OP_RESERVATION_COMMIT,
        transaction_id,
        payload_length,
        route);
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    return storage_txn_commit_full(runtime, txn);
}

ninlil_status_t ninlil_rt_v1_stage_reservation_marker(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_v1_durable_operation_t operation,
    const ninlil_id128_t *transaction_id,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route)
{
    uint8_t key[18];
    uint8_t value[NINLIL_RT_V1_RESERVATION_MARKER_BYTES];
    ninlil_status_t status;

    if (runtime == NULL || storage_txn == NULL || transaction_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    txn_marker_key(key, NINLIL_RT_V1_MARKER_RV, transaction_id);
    status = ninlil_rt_v1_reservation_marker_encode(
        payload_length, route, value);
    if (status != NINLIL_OK) {
        return status;
    }
    return ninlil_v1_durable_storage_put(
        operation,
        runtime->platform->storage,
        storage_txn,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, sizeof(value)},
        &runtime->commit_unknown_fence);
}

static ninlil_model_runtime_store_key_id_t capacity_key_id_for_index(
    uint32_t index)
{
    return (ninlil_model_runtime_store_key_id_t)(
        (uint32_t)NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE + index);
}

static void project_capacity_entry(
    const ninlil_model_capacity_entry_t *entry,
    ninlil_model_runtime_store_capacity_t *out_capacity)
{
    (void)memset(out_capacity, 0, sizeof(*out_capacity));
    out_capacity->kind = entry->kind;
    out_capacity->limit = entry->limit;
    out_capacity->used = entry->used;
    out_capacity->reserved = entry->reserved;
    out_capacity->high_water = entry->high_water;
    out_capacity->capacity_epoch = entry->capacity_epoch;
    out_capacity->blocked = entry->blocked;
    out_capacity->counter_exhausted =
        entry->counter_exhausted_marker;
}

ninlil_status_t ninlil_rt_v1_stage_resource_ledger(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_v1_durable_operation_t operation,
    const ninlil_model_resource_ledger_t *ledger)
{
    uint32_t index;

    if (runtime == NULL || storage_txn == NULL || ledger == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        ninlil_model_runtime_store_key_t key;
        ninlil_model_runtime_store_capacity_t capacity;
        uint8_t value[NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES];
        uint32_t value_length = 0u;
        ninlil_model_runtime_store_key_id_t key_id =
            capacity_key_id_for_index(index);
        ninlil_status_t status;

        status = ninlil_model_runtime_store_build_key(key_id, &key);
        if (status != NINLIL_OK) {
            return status;
        }
        project_capacity_entry(&ledger->entries[index], &capacity);
        status = ninlil_model_runtime_store_encode_capacity(
            key_id,
            &capacity,
            value,
            (uint32_t)sizeof(value),
            &value_length);
        if (status != NINLIL_OK) {
            return status;
        }
        status = ninlil_v1_durable_storage_put(
            operation,
            runtime->platform->storage,
            storage_txn,
            (ninlil_bytes_view_t){key.bytes, key.length},
            (ninlil_bytes_view_t){value, value_length},
            &runtime->commit_unknown_fence);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_restore_resource_ledger_row(
    ninlil_runtime_t *runtime,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *out_recognized)
{
    ninlil_model_runtime_store_key_id_t key_id;
    ninlil_model_runtime_store_capacity_t capacity;
    ninlil_model_capacity_entry_t *entry;
    uint32_t index;
    ninlil_status_t status;

    if (runtime == NULL || out_recognized == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_recognized = 0u;
    if (key.data == NULL || key.length != 10u
        || key.data[8] != 0x04u) {
        return NINLIL_OK;
    }
    status = ninlil_model_runtime_store_parse_key(key, &key_id);
    if (status != NINLIL_OK) {
        return status;
    }
    if (key_id < NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE
        || key_id
            > NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    index = (uint32_t)key_id
        - (uint32_t)NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE;
    if ((runtime->resource_ledger_restore_mask & (1u << index)) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&capacity, 0, sizeof(capacity));
    status = ninlil_model_runtime_store_decode_capacity(
        key_id, value, &capacity);
    if (status != NINLIL_OK) {
        return status;
    }
    if (capacity.kind != (ninlil_resource_kind_t)(index + 1u)
        || capacity.limit != runtime->capacity_limits.values[index]) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    entry = &runtime->resource_ledger.entries[index];
    entry->kind = capacity.kind;
    entry->limit = capacity.limit;
    entry->used = capacity.used;
    entry->reserved = capacity.reserved;
    entry->high_water = capacity.high_water;
    entry->capacity_epoch = capacity.capacity_epoch;
    entry->blocked = capacity.blocked;
    entry->counter_exhausted_marker = capacity.counter_exhausted;
    runtime->resource_ledger_restore_mask |= 1u << index;
    *out_recognized = 1u;
    return NINLIL_OK;
}

static int add_release_request(
    ninlil_model_capacity_batch_request_t *requests,
    uint32_t *count,
    ninlil_resource_kind_t kind,
    uint64_t used_release,
    uint64_t reserved_release)
{
    if (used_release == 0u && reserved_release == 0u) {
        return 1;
    }
    if (*count >= NINLIL_MODEL_RESOURCE_KIND_COUNT) {
        return 0;
    }
    if (*count > 0u && requests[*count - 1u].kind >= kind) {
        return 0;
    }
    requests[*count].kind = kind;
    requests[*count].amount = 0u;
    requests[*count].used_release = used_release;
    requests[*count].reserved_release = reserved_release;
    /*
     * Every release below increases availability for the exact resource
     * class that could have blocked this transaction.  The pure ledger model
     * clears a persisted blocked flag and advances its epoch atomically.
     */
    requests[*count].reopens_blocked_class = 1u;
    *count += 1u;
    return 1;
}

ninlil_status_t ninlil_rt_v1_build_released_resource_ledger_from(
    const ninlil_model_resource_ledger_t *current,
    const ninlil_rt_transaction_slot_t *txn,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_input_t batch_in;
    ninlil_model_capacity_batch_result_t batch_out;
    uint32_t request_count = 0u;
    ninlil_status_t status;

    if (current == NULL || txn == NULL || out_ledger == NULL
        || txn->reservation_active == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&batch_in, 0, sizeof(batch_in));
    batch_in.current = *current;
    batch_in.operation = NINLIL_MODEL_CAPACITY_BATCH_RELEASE;

    if (txn->family == NINLIL_FAMILY_DESIRED_STATE) {
        if (!add_release_request(
                batch_in.requests,
                &request_count,
                NINLIL_RESOURCE_OUTBOX_BYTES,
                txn->payload_length,
                0u)) {
            return NINLIL_E_INTERNAL;
        }
    } else {
        uint64_t used_management =
            (uint64_t)txn->resume_op_count * 256u
            + (txn->event_discarded != 0u ? 512u : 0u);

        if (used_management
            > NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (!add_release_request(
                batch_in.requests,
                &request_count,
                NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
                1u,
                0u)
            || !add_release_request(
                batch_in.requests,
                &request_count,
                NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
                txn->payload_length,
                NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES
                    - used_management)) {
            return NINLIL_E_INTERNAL;
        }
    }

    batch_in.request_count = request_count;
    status = ninlil_model_capacity_batch_transition(&batch_in, &batch_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (batch_out.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_RELEASED) {
        return NINLIL_E_INTERNAL;
    }
    *out_ledger = batch_out.next;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_build_released_resource_ledger(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn,
    ninlil_model_resource_ledger_t *out_ledger)
{
    if (runtime == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return ninlil_rt_v1_build_released_resource_ledger_from(
        &runtime->resource_ledger, txn, out_ledger);
}

ninlil_status_t ninlil_rt_v1_build_evidence_committed_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_input_t batch_in;
    ninlil_model_capacity_batch_result_t batch_out;
    ninlil_status_t status;

    if (current == NULL || out_ledger == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&batch_in, 0, sizeof(batch_in));
    batch_in.current = *current;
    batch_in.operation = NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    batch_in.request_count = 1u;
    batch_in.requests[0].kind = NINLIL_RESOURCE_EVIDENCE;
    batch_in.requests[0].amount = 1u;
    status = ninlil_model_capacity_batch_transition(&batch_in, &batch_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (batch_out.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_ledger = batch_out.next;
    return NINLIL_OK;
}

static void add_acquire_request(
    ninlil_model_capacity_batch_input_t *batch,
    ninlil_resource_kind_t kind)
{
    ninlil_model_capacity_batch_request_t *request =
        &batch->requests[batch->request_count];

    request->kind = kind;
    request->amount = 1u;
    batch->request_count += 1u;
}

static ninlil_status_t build_acquired_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    ninlil_model_capacity_batch_input_t *input,
    ninlil_model_capacity_batch_action_t *out_action,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_result_t reserved;
    ninlil_model_capacity_batch_result_t committed;
    ninlil_status_t status;

    input->current = *current;
    input->operation = NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    status = ninlil_model_capacity_batch_transition(input, &reserved);
    if (status != NINLIL_OK) {
        return status;
    }
    *out_action = reserved.action;
    *out_ledger = reserved.next;
    if (reserved.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED) {
        return NINLIL_OK;
    }

    input->current = reserved.next;
    input->operation = NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    status = ninlil_model_capacity_batch_transition(input, &committed);
    if (status != NINLIL_OK) {
        return status;
    }
    if (committed.action
        != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_action = committed.action;
    *out_ledger = committed.next;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_build_callback_start_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    uint32_t first_callback,
    ninlil_model_capacity_batch_action_t *out_action,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_input_t input;
    if (current == NULL || out_action == NULL || out_ledger == NULL
        || first_callback > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&input, 0, sizeof(input));
    if (first_callback != 0u) {
        add_acquire_request(&input, NINLIL_RESOURCE_RESULT_CACHE);
    }
    add_acquire_request(&input, NINLIL_RESOURCE_DEFERRED_TOKEN);
    return build_acquired_resource_ledger(
        current, &input, out_action, out_ledger);
}

ninlil_status_t ninlil_rt_v1_build_inbound_delivery_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    ninlil_model_capacity_batch_action_t *out_action,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_input_t input;

    if (current == NULL || out_action == NULL || out_ledger == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&input, 0, sizeof(input));
    add_acquire_request(&input, NINLIL_RESOURCE_DELIVERY);
    return build_acquired_resource_ledger(
        current, &input, out_action, out_ledger);
}

ninlil_status_t ninlil_rt_v1_build_inbound_released_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    uint64_t delivery_count,
    uint64_t deferred_token_count,
    ninlil_model_resource_ledger_t *out_ledger)
{
    ninlil_model_capacity_batch_input_t input;
    ninlil_model_capacity_batch_result_t result;
    uint32_t request_count = 0u;
    ninlil_status_t status;

    if (current == NULL || out_ledger == NULL
        || (delivery_count == 0u && deferred_token_count == 0u)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&input, 0, sizeof(input));
    input.current = *current;
    input.operation = NINLIL_MODEL_CAPACITY_BATCH_RELEASE;
    if (!add_release_request(
            input.requests,
            &request_count,
            NINLIL_RESOURCE_DELIVERY,
            delivery_count,
            0u)
        || !add_release_request(
            input.requests,
            &request_count,
            NINLIL_RESOURCE_DEFERRED_TOKEN,
            deferred_token_count,
            0u)) {
        return NINLIL_E_INTERNAL;
    }
    input.request_count = request_count;
    status = ninlil_model_capacity_batch_transition(&input, &result);
    if (status != NINLIL_OK) {
        return status;
    }
    if (result.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_RELEASED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_ledger = result.next;
    return NINLIL_OK;
}

static int checked_add_u64(uint64_t *value, uint64_t amount)
{
    if (*value > UINT64_MAX - amount) {
        return 0;
    }
    *value += amount;
    return 1;
}

static int add_expected_resource(
    uint64_t used[NINLIL_MODEL_RESOURCE_KIND_COUNT],
    uint64_t reserved[NINLIL_MODEL_RESOURCE_KIND_COUNT],
    ninlil_resource_kind_t kind,
    uint64_t used_amount,
    uint64_t reserved_amount)
{
    uint32_t index;

    if (kind < NINLIL_RESOURCE_SERVICE
        || kind > NINLIL_RESOURCE_DEFERRED_TOKEN) {
        return 0;
    }
    index = (uint32_t)kind - 1u;
    return checked_add_u64(&used[index], used_amount)
        && checked_add_u64(&reserved[index], reserved_amount);
}

ninlil_status_t ninlil_rt_v1_validate_restored_resource_ledger(
    const ninlil_runtime_t *runtime)
{
    uint64_t expected_used[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    uint64_t expected_reserved[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    uint32_t index;

    if (runtime == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(expected_used, 0, sizeof(expected_used));
    (void)memset(expected_reserved, 0, sizeof(expected_reserved));

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *txn =
            &runtime->transactions[index];
        uint64_t evidence_used;
        uint64_t evidence_reserved;
        uint64_t used_management;

        if (txn->in_use == 0u) {
            continue;
        }
        if (txn->origin_admission == 0u) {
            /*
             * Canonical inbound ownership:
             * - token_generation != 0 proves callback-start acquired the
             *   retained RESULT_CACHE row;
             * - the delivery stays nonterminal until Receipt/Disposition
             *   terminalization;
             * - only ACTIVE owns a DEFERRED_TOKEN slot.
             *
             * INGRESS is intentionally absent here: this V1 Runtime has no
             * independent unreduced durable ingress row.  Counting the same
             * canonical transaction as both DELIVERY and INGRESS would be a
             * restart-dependent double charge.
             */
            if (txn->token_generation != 0u
                && !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_RESULT_CACHE,
                    1u,
                    0u)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (txn->terminal == 0u
                && txn->event_discarded == 0u
                && !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_DELIVERY,
                    1u,
                    0u)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (txn->token_state == NINLIL_RT_TOKEN_ACTIVE
                && !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_DEFERRED_TOKEN,
                    1u,
                    0u)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            continue;
        }
        if (txn->bound_target_count == 0u
            || txn->reservation_evidence_units == 0u
            || txn->evidence_recorded
                >= txn->reservation_evidence_units) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        evidence_used = 1u + (uint64_t)txn->evidence_recorded;
        evidence_reserved =
            (uint64_t)txn->reservation_evidence_units - evidence_used;
        if (!add_expected_resource(
                expected_used,
                expected_reserved,
                NINLIL_RESOURCE_TRANSACTION,
                1u,
                0u)
            || !add_expected_resource(
                expected_used,
                expected_reserved,
                NINLIL_RESOURCE_TARGET,
                txn->bound_target_count,
                0u)
            || !add_expected_resource(
                expected_used,
                expected_reserved,
                NINLIL_RESOURCE_EVIDENCE,
                evidence_used,
                evidence_reserved)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (txn->family == NINLIL_FAMILY_DESIRED_STATE) {
            uint32_t should_hold_payload =
                txn->terminal == 0u && txn->event_discarded == 0u;

            if (txn->reservation_active != should_hold_payload) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (txn->reservation_active != 0u
                && !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_OUTBOX_BYTES,
                    txn->payload_length,
                    0u)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            continue;
        }
        if (txn->family != NINLIL_FAMILY_EVENT_FACT) {
            return NINLIL_E_STORAGE_CORRUPT;
        }

        used_management = (uint64_t)txn->resume_op_count * 256u
            + (txn->event_discarded != 0u ? 512u : 0u);
        if (used_management
            > NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (txn->terminal == 0u && txn->event_discarded == 0u) {
            if (txn->reservation_active == 0u
                || !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
                    1u,
                    0u)
                || !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
                    (uint64_t)txn->payload_length + used_management,
                    NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES
                        - used_management)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            if (txn->reservation_active != 0u
                || !add_expected_resource(
                    expected_used,
                    expected_reserved,
                    NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
                    used_management,
                    0u)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
    }

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        const ninlil_model_capacity_entry_t *entry =
            &runtime->resource_ledger.entries[index];

        if (entry->kind != (ninlil_resource_kind_t)(index + 1u)
            || entry->limit != runtime->capacity_limits.values[index]
            || entry->used != expected_used[index]
            || entry->reserved != expected_reserved[index]) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_release_transaction_reservation(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn)
{
    ninlil_model_resource_ledger_t next;
    ninlil_status_t status;

    if (runtime == NULL || txn == NULL || txn->reservation_active == 0u) {
        return NINLIL_OK;
    }
    status = ninlil_rt_v1_build_released_resource_ledger(
        runtime, txn, &next);
    if (status != NINLIL_OK) {
        return status;
    }
    runtime->resource_ledger = next;
    txn->reservation_active = 0u;
    return NINLIL_OK;
}
