#include "runtime_v1_event_mgmt.h"

#include "runtime_v1_delivery_durable.h"

#include <string.h>

#define NINLIL_RT_V1_MARKER_ES 0x4553u
#define NINLIL_RT_V1_MARKER_ER 0x4552u
#define NINLIL_RT_V1_MARKER_ED 0x4544u
#define NINLIL_RT_V1_TXN_MARKER_BYTES 16u
#define NINLIL_RT_V1_MARKER_VALUE_BYTES 32u
#define NINLIL_RT_V1_MAX_EVENT_RESUME_OPS 8u

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static int id_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int digest_nonzero(const ninlil_digest256_t *digest)
{
    uint32_t index;

    if (digest == NULL || digest->algorithm != NINLIL_DIGEST_SHA256) {
        return 0;
    }
    for (index = 0u; index < sizeof(digest->bytes); ++index) {
        if (digest->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static void txn_marker_key(uint8_t *key, uint16_t prefix, const ninlil_id128_t *txn_id)
{
    key[0] = (uint8_t)(prefix >> 8);
    key[1] = (uint8_t)(prefix & 0xffu);
    (void)memcpy(&key[2], txn_id->bytes, 14u);
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

static ninlil_status_t commit_event_mgmt_marker(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation,
    const uint8_t *value,
    uint32_t value_length)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t txn = NULL;
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    ninlil_status_t status;

    if (storage->begin(
            storage->user, runtime->storage, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    txn_marker_key(key, prefix, transaction_id);
    status = ninlil_v1_durable_storage_put(
        operation,
        storage,
        txn,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, value_length},
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    return storage_txn_commit_full(runtime, txn);
}

static void zero_resume_result(ninlil_event_resume_result_t *out_result)
{
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version, &out_result->struct_size, sizeof(*out_result));
}

static void zero_discard_result(ninlil_event_discard_result_t *out_result)
{
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version, &out_result->struct_size, sizeof(*out_result));
}

ninlil_status_t ninlil_rt_v1_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;
    ninlil_status_t status;
    uint8_t marker[NINLIL_RT_V1_MARKER_VALUE_BYTES];
    ninlil_time_sample_t sample;

    zero_resume_result(out_result);
    if (runtime == NULL || transaction_id == NULL || request == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!id_nonzero(transaction_id) || !id_nonzero(&request->operation_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (runtime->config.role != NINLIL_ROLE_CONTROLLER) {
        return NINLIL_E_UNSUPPORTED;
    }

    txn = ninlil_rt_find_transaction(runtime, transaction_id);
    if (txn == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (txn->family != NINLIL_FAMILY_EVENT_FACT) {
        out_result->kind = NINLIL_EVENT_RESUME_NOT_EVENT_FACT;
        return NINLIL_OK;
    }
    if (txn->event_discarded != 0u) {
        out_result->kind = NINLIL_EVENT_RESUME_ALREADY_DISCARDED;
        return NINLIL_OK;
    }
    if (txn->delivery_phase != NINLIL_RT_DELIVERY_PARKED) {
        out_result->kind = NINLIL_EVENT_RESUME_NOT_PARKED;
        return NINLIL_OK;
    }
    if (txn->event_park_cause == NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED) {
        out_result->kind = NINLIL_EVENT_RESUME_NOT_RESUMABLE;
        return NINLIL_OK;
    }
    if (request->expected_spool_revision != txn->spool_revision) {
        out_result->kind = NINLIL_EVENT_RESUME_STALE_SPOOL_REVISION;
        out_result->spool_revision = txn->spool_revision;
        return NINLIL_OK;
    }
    if (txn->resume_op_count >= NINLIL_RT_V1_MAX_EVENT_RESUME_OPS) {
        out_result->kind = NINLIL_EVENT_RESUME_LIMIT_EXHAUSTED;
        return NINLIL_OK;
    }
    if (memcmp(
            request->operation_id.bytes,
            txn->last_resume_operation_id.bytes,
            sizeof(request->operation_id.bytes))
        == 0) {
        out_result->kind = NINLIL_EVENT_RESUME_ALREADY_RESUMED;
        out_result->operation_id = request->operation_id;
        out_result->spool_revision = txn->spool_revision;
        return NINLIL_OK;
    }

    if (runtime->platform->clock->now(
            runtime->platform->clock->user, &sample)
        != NINLIL_PORT_OK) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }

    (void)memset(marker, 0, sizeof(marker));
    (void)memcpy(&marker[0], request->operation_id.bytes, 16u);
    marker[16] = (uint8_t)request->resume_reason;
    (void)memcpy(&marker[20], &txn->spool_revision, sizeof(txn->spool_revision));

    status = commit_event_mgmt_marker(
        runtime,
        transaction_id,
        NINLIL_RT_V1_MARKER_ER,
        NINLIL_V1_DURABLE_OP_EVENT_RESUME_COMMIT,
        marker,
        sizeof(marker));
    if (status != NINLIL_OK) {
        return status;
    }

    txn->spool_revision += 1u;
    txn->resume_op_count += 1u;
    txn->last_resume_operation_id = request->operation_id;
    txn->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    txn->pending_dispatch = 1u;
    txn->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    runtime->pending_work = 1u;

    {
        uint8_t spool_marker[NINLIL_RT_V1_MARKER_VALUE_BYTES];
        (void)memset(spool_marker, 0, sizeof(spool_marker));
        spool_marker[0] = 1u;
        (void)memcpy(&spool_marker[4], &txn->spool_revision, sizeof(txn->spool_revision));
        (void)commit_event_mgmt_marker(
            runtime,
            transaction_id,
            NINLIL_RT_V1_MARKER_ES,
            NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT,
            spool_marker,
            sizeof(spool_marker));
    }

    out_result->kind = NINLIL_EVENT_RESUME_RESUMED;
    out_result->reason = NINLIL_REASON_NONE;
    out_result->operation_id = request->operation_id;
    out_result->spool_revision = txn->spool_revision;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;
    ninlil_status_t status;
    uint8_t marker[NINLIL_RT_V1_MARKER_VALUE_BYTES];
    ninlil_time_sample_t sample;

    zero_discard_result(out_result);
    if (runtime == NULL || transaction_id == NULL || request == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!id_nonzero(transaction_id) || !id_nonzero(&request->operation_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (request->acknowledge_required_receipt_absent != 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (runtime->config.role != NINLIL_ROLE_CONTROLLER) {
        return NINLIL_E_UNSUPPORTED;
    }

    txn = ninlil_rt_find_transaction(runtime, transaction_id);
    if (txn == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (txn->family != NINLIL_FAMILY_EVENT_FACT) {
        out_result->kind = NINLIL_EVENT_DISCARD_NOT_EVENT_FACT;
        return NINLIL_OK;
    }
    if (txn->event_discarded != 0u) {
        out_result->kind = NINLIL_EVENT_DISCARD_ALREADY_DISCARDED;
        out_result->operation_id = request->operation_id;
        out_result->spool_revision = txn->spool_revision;
        return NINLIL_OK;
    }
    if (id_nonzero(&request->expected_event_id)
        && memcmp(
            request->expected_event_id.bytes,
            txn->event_id.bytes,
            sizeof(txn->event_id.bytes))
            != 0) {
        out_result->kind = NINLIL_EVENT_DISCARD_CONFLICT;
        return NINLIL_OK;
    }
    if (digest_nonzero(&request->expected_content_digest)
        && memcmp(
            request->expected_content_digest.bytes,
            txn->content_digest.bytes,
            sizeof(txn->content_digest.bytes))
            != 0) {
        out_result->kind = NINLIL_EVENT_DISCARD_CONFLICT;
        return NINLIL_OK;
    }
    if (request->expected_spool_revision != txn->spool_revision) {
        out_result->kind = NINLIL_EVENT_DISCARD_STALE_SPOOL_REVISION;
        out_result->spool_revision = txn->spool_revision;
        return NINLIL_OK;
    }

    if (runtime->platform->clock->now(
            runtime->platform->clock->user, &sample)
        != NINLIL_PORT_OK) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }

    (void)memset(marker, 0, sizeof(marker));
    (void)memcpy(&marker[0], request->operation_id.bytes, 16u);
    marker[16] = (uint8_t)request->discard_reason;
    (void)memcpy(&marker[20], &txn->spool_revision, sizeof(txn->spool_revision));

    status = commit_event_mgmt_marker(
        runtime,
        transaction_id,
        NINLIL_RT_V1_MARKER_ED,
        NINLIL_V1_DURABLE_OP_EVENT_DISCARD_COMMIT,
        marker,
        sizeof(marker));
    if (status != NINLIL_OK) {
        return status;
    }

    txn->spool_revision += 1u;
    txn->event_discarded = 1u;
    txn->terminal = 1u;
    txn->pending_dispatch = 0u;
    txn->outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
    txn->reason = NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    runtime->nonterminal_transaction_count -= 1u;

    {
        uint8_t spool_marker[NINLIL_RT_V1_MARKER_VALUE_BYTES];
        (void)memset(spool_marker, 0, sizeof(spool_marker));
        spool_marker[0] = 3u;
        (void)memcpy(&spool_marker[4], &txn->spool_revision, sizeof(txn->spool_revision));
        (void)commit_event_mgmt_marker(
            runtime,
            transaction_id,
            NINLIL_RT_V1_MARKER_ES,
            NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT,
            spool_marker,
            sizeof(spool_marker));
    }

    out_result->kind = NINLIL_EVENT_DISCARD_DISCARDED;
    out_result->reason = NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    out_result->operation_id = request->operation_id;
    out_result->audit_clock_epoch_id = sample.clock_epoch_id;
    out_result->audit_committed_at_ms = sample.now_ms;
    out_result->spool_revision = txn->spool_revision;
    out_result->spool_released = 1u;
    return NINLIL_OK;
}
