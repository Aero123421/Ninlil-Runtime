#include "runtime_v1_capability.h"

#include "resource_ledger_batch.h"

#include <string.h>

#define NINLIL_RT_V1_U6_MAX_PAYLOAD_BYTES 926u

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

void ninlil_rt_v1_encode_tx_admission_marker_v2(
    uint8_t *value,
    ninlil_family_t family,
    const ninlil_id128_t *service_app_id,
    uint64_t effect_deadline_ms,
    uint64_t generation,
    uint8_t semantic_priority,
    uint32_t payload_length,
    uint64_t admitted_at_ms)
{
    (void)memset(value, 0, NINLIL_RT_V1_TX_ADMISSION_MARKER_V2_BYTES);
    value[0] = (uint8_t)family;
    if (service_app_id != NULL) {
        (void)memcpy(&value[1], service_app_id->bytes, 16u);
    }
    (void)memcpy(&value[17], &effect_deadline_ms, sizeof(effect_deadline_ms));
    (void)memcpy(&value[25], &generation, sizeof(generation));
    value[33] = semantic_priority;
    (void)memcpy(&value[34], &payload_length, sizeof(payload_length));
    (void)memcpy(&value[38], &admitted_at_ms, sizeof(admitted_at_ms));
}

void ninlil_rt_v1_decode_tx_admission_marker(
    ninlil_bytes_view_t value,
    ninlil_family_t *out_family,
    ninlil_id128_t *out_service_app_id,
    uint64_t *out_effect_deadline_ms,
    uint64_t *out_generation,
    uint8_t *out_semantic_priority,
    uint32_t *out_payload_length,
    uint64_t *out_admitted_at_ms)
{
    if (out_family != NULL) {
        *out_family = NINLIL_FAMILY_DESIRED_STATE;
    }
    if (out_service_app_id != NULL) {
        (void)memset(out_service_app_id, 0, sizeof(*out_service_app_id));
    }
    if (out_effect_deadline_ms != NULL) {
        *out_effect_deadline_ms = 0u;
    }
    if (out_generation != NULL) {
        *out_generation = 0u;
    }
    if (out_semantic_priority != NULL) {
        *out_semantic_priority = 0u;
    }
    if (out_payload_length != NULL) {
        *out_payload_length = 0u;
    }
    if (out_admitted_at_ms != NULL) {
        *out_admitted_at_ms = 0u;
    }
    if (value.length < NINLIL_RT_V1_TX_ADMISSION_MARKER_V1_BYTES
        || value.data == NULL) {
        return;
    }
    if (out_family != NULL) {
        *out_family = (ninlil_family_t)value.data[0];
    }
    if (out_service_app_id != NULL) {
        (void)memcpy(
            out_service_app_id->bytes, &value.data[1], sizeof(out_service_app_id->bytes));
    }
    if (out_effect_deadline_ms != NULL) {
        (void)memcpy(
            out_effect_deadline_ms, &value.data[17], sizeof(*out_effect_deadline_ms));
    }
    if (out_generation != NULL) {
        (void)memcpy(out_generation, &value.data[25], sizeof(*out_generation));
    }
    if (value.length >= NINLIL_RT_V1_TX_ADMISSION_MARKER_V2_BYTES) {
        if (out_semantic_priority != NULL) {
            *out_semantic_priority = value.data[33];
        }
        if (out_payload_length != NULL) {
            (void)memcpy(
                out_payload_length, &value.data[34], sizeof(*out_payload_length));
        }
        if (out_admitted_at_ms != NULL) {
            (void)memcpy(
                out_admitted_at_ms, &value.data[38], sizeof(*out_admitted_at_ms));
        }
    }
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
    ninlil_storage_status_t status = storage->commit(
        storage->user, txn, NINLIL_DURABILITY_FULL);

    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_STORAGE_BUSY) {
        return NINLIL_E_WOULD_BLOCK;
    }
    if (status == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (status == NINLIL_STORAGE_IO_ERROR) {
        return NINLIL_E_STORAGE;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static void txn_marker_key(uint8_t *key, uint16_t prefix, const ninlil_id128_t *txn_id)
{
    key[0] = (uint8_t)(prefix >> 8);
    key[1] = (uint8_t)(prefix & 0xffu);
    (void)memcpy(&key[2], txn_id->bytes, 14u);
}

static void encode_reservation_marker(
    uint8_t *value,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route)
{
    (void)memset(value, 0, 32u);
    (void)memcpy(&value[0], &payload_length, sizeof(payload_length));
    value[4] = (uint8_t)route;
    value[5] = 1u;
}

ninlil_status_t ninlil_rt_v1_commit_reservation_marker(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    uint8_t key[16];
    uint8_t value[32];
    ninlil_status_t status;

    if (runtime == NULL || transaction_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    if (storage->begin(
            storage->user, runtime->storage, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    txn_marker_key(key, NINLIL_RT_V1_MARKER_RV, transaction_id);
    encode_reservation_marker(value, payload_length, route);

    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_RESERVATION_COMMIT,
        storage,
        txn,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, sizeof(value)},
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    return storage_txn_commit_full(runtime, txn);
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
    requests[*count].reopens_blocked_class = 0u;
    *count += 1u;
    return 1;
}

ninlil_status_t ninlil_rt_v1_release_transaction_reservation(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn)
{
    ninlil_model_capacity_batch_input_t batch_in;
    ninlil_model_capacity_batch_result_t batch_out;
    uint32_t request_count = 0u;
    ninlil_status_t status;

    if (runtime == NULL || txn == NULL || txn->reservation_active == 0u) {
        return NINLIL_OK;
    }

    (void)memset(&batch_in, 0, sizeof(batch_in));
    batch_in.current = runtime->resource_ledger;
    batch_in.operation = NINLIL_MODEL_CAPACITY_BATCH_RELEASE;

    if (!add_release_request(
            batch_in.requests,
            &request_count,
            NINLIL_RESOURCE_TRANSACTION,
            1u,
            0u)
        || !add_release_request(
            batch_in.requests,
            &request_count,
            NINLIL_RESOURCE_TARGET,
            1u,
            0u)) {
        return NINLIL_E_INTERNAL;
    }
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
                txn->payload_length + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES,
                0u)) {
            return NINLIL_E_INTERNAL;
        }
    }
    if (!add_release_request(
            batch_in.requests,
            &request_count,
            NINLIL_RESOURCE_EVIDENCE,
            1u,
            txn->reservation_evidence_units > 1u
                ? txn->reservation_evidence_units - 1u
                : 0u)) {
        return NINLIL_E_INTERNAL;
    }

    batch_in.request_count = request_count;
    status = ninlil_model_capacity_batch_transition(&batch_in, &batch_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (batch_out.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_RELEASED) {
        return NINLIL_E_INTERNAL;
    }
    runtime->resource_ledger = batch_out.next;
    txn->reservation_active = 0u;
    return NINLIL_OK;
}
