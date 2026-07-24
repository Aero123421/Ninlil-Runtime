#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_bearer_wire.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_family_capability.h"

#include "domain_store_codec.h"

#include <stdint.h>
#include <string.h>

#define NINLIL_RT_V1_MARKER_TX 0x5458u
#define NINLIL_RT_V1_MARKER_DS 0x4453u
#define NINLIL_RT_V1_MARKER_EV 0x4556u
#define NINLIL_RT_V1_MARKER_OC 0x4f43u
#define NINLIL_RT_V1_MARKER_ES 0x4553u
#define NINLIL_RT_V1_MARKER_RT 0x5254u

#define NINLIL_RT_V1_TXN_MARKER_BYTES 16u
#define NINLIL_RT_V1_MARKER_VALUE_BYTES 32u
#define NINLIL_RT_V1_DEFAULT_RETRY_BUDGET 3u

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
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

static ninlil_status_t durable_put(
    ninlil_runtime_t *runtime,
    ninlil_v1_durable_operation_t operation,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    return ninlil_v1_durable_storage_put(
        operation,
        runtime->platform->storage,
        txn,
        key,
        value,
        &runtime->commit_unknown_fence);
}

static ninlil_rt_service_slot_t *find_receiver_for_txn(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use == 0u || slot->attached == 0u) {
            continue;
        }
        if (memcmp(
                slot->descriptor.local_application_instance_id.bytes,
                txn->service_app_id.bytes,
                sizeof(txn->service_app_id.bytes))
            != 0) {
            continue;
        }
        if (txn->family == NINLIL_FAMILY_EVENT_FACT
            && slot->callbacks.on_delivery != NULL) {
            return slot;
        }
        if ((txn->family == NINLIL_FAMILY_LATEST_STATE_RESERVED
                || txn->family == NINLIL_FAMILY_MEASUREMENT_RESERVED)
            && slot->callbacks.on_delivery != NULL) {
            return slot;
        }
        if ((txn->family == NINLIL_FAMILY_DESIRED_STATE
                || txn->family == NINLIL_FAMILY_TRANSFER_RESERVED
                || txn->family == NINLIL_FAMILY_CONFIG_RESERVED)
            && slot->model_service.local_side
                == NINLIL_MODEL_LOCAL_SUBMISSION_SENDER) {
            return slot;
        }
    }
    return NULL;
}

static void encode_delivery_marker(
    uint8_t *value,
    uint8_t phase,
    uint64_t delivery_count,
    ninlil_outcome_t outcome,
    ninlil_reason_t reason)
{
    (void)memset(value, 0, NINLIL_RT_V1_MARKER_VALUE_BYTES);
    value[0] = phase;
    value[1] = (uint8_t)(delivery_count & 0xffu);
    value[2] = (uint8_t)outcome;
    value[3] = (uint8_t)reason;
    value[4] = (uint8_t)((delivery_count >> 8) & 0xffu);
    value[5] = (uint8_t)((delivery_count >> 16) & 0xffu);
    value[6] = (uint8_t)((delivery_count >> 24) & 0xffu);
}

static void decode_delivery_marker(
    ninlil_bytes_view_t value,
    uint8_t *out_phase,
    uint64_t *out_delivery_count,
    ninlil_outcome_t *out_outcome,
    ninlil_reason_t *out_reason)
{
    if (value.length < 7u || value.data == NULL) {
        return;
    }
    *out_phase = value.data[0];
    *out_delivery_count =
        (uint64_t)value.data[1]
        | ((uint64_t)value.data[4] << 8)
        | ((uint64_t)value.data[5] << 16)
        | ((uint64_t)value.data[6] << 24);
    *out_outcome = (ninlil_outcome_t)value.data[2];
    *out_reason = (ninlil_reason_t)value.data[3];
}

static void encode_event_spool_marker(
    uint8_t *value,
    uint32_t state,
    uint64_t spool_revision,
    uint32_t park_cause)
{
    (void)memset(value, 0, NINLIL_RT_V1_MARKER_VALUE_BYTES);
    value[0] = (uint8_t)state;
    (void)memcpy(&value[4], &spool_revision, sizeof(spool_revision));
    value[12] = (uint8_t)(park_cause & 0xffu);
    value[13] = (uint8_t)((park_cause >> 8) & 0xffu);
}

static void decode_event_spool_marker(
    ninlil_bytes_view_t value,
    uint32_t *out_state,
    uint64_t *out_spool_revision,
    uint32_t *out_park_cause)
{
    if (value.length < 14u || value.data == NULL) {
        return;
    }
    *out_state = (uint32_t)value.data[0];
    (void)memcpy(out_spool_revision, &value.data[4], sizeof(*out_spool_revision));
    *out_park_cause =
        (uint32_t)value.data[12] | ((uint32_t)value.data[13] << 8);
}

static void encode_retry_marker(
    uint8_t *value,
    uint32_t retry_budget,
    uint64_t next_retry_ms)
{
    (void)memset(value, 0, NINLIL_RT_V1_MARKER_VALUE_BYTES);
    value[0] = (uint8_t)retry_budget;
    (void)memcpy(&value[4], &next_retry_ms, sizeof(next_retry_ms));
}

static void decode_retry_marker(
    ninlil_bytes_view_t value,
    uint32_t *out_retry_budget,
    uint64_t *out_next_retry_ms)
{
    if (value.length < 12u || value.data == NULL) {
        return;
    }
    *out_retry_budget = (uint32_t)value.data[0];
    (void)memcpy(out_next_retry_ms, &value.data[4], sizeof(*out_next_retry_ms));
}

static ninlil_status_t commit_event_spool(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    uint32_t state,
    uint32_t park_cause)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t txn_storage = NULL;
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    uint8_t value[NINLIL_RT_V1_MARKER_VALUE_BYTES];
    ninlil_status_t status;

    if (storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn_storage)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    txn_marker_key(key, NINLIL_RT_V1_MARKER_ES, &txn->transaction_id);
    encode_event_spool_marker(
        value, state, txn->spool_revision, park_cause);

    status = durable_put(
        runtime,
        NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT,
        txn_storage,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, sizeof(value)});
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn_storage);
        return status;
    }
    return storage_txn_commit_full(runtime, txn_storage);
}

static ninlil_status_t commit_retry_state(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t txn_storage = NULL;
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    uint8_t value[NINLIL_RT_V1_MARKER_VALUE_BYTES];
    ninlil_status_t status;

    if (storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn_storage)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    txn_marker_key(key, NINLIL_RT_V1_MARKER_RT, &txn->transaction_id);
    encode_retry_marker(value, txn->retry_budget, txn->next_retry_ms);

    status = durable_put(
        runtime,
        NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT,
        txn_storage,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, sizeof(value)});
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn_storage);
        return status;
    }
    return storage_txn_commit_full(runtime, txn_storage);
}

ninlil_status_t ninlil_rt_v1_commit_delivery_marker(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation,
    uint8_t phase)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t txn_storage = NULL;
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    uint8_t value[NINLIL_RT_V1_MARKER_VALUE_BYTES];
    ninlil_status_t status;

    if (storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn_storage)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    txn_marker_key(key, prefix, &txn->transaction_id);
    encode_delivery_marker(
        value,
        phase,
        txn->delivery_count,
        txn->outcome,
        txn->reason);

    status = durable_put(
        runtime,
        operation,
        txn_storage,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, sizeof(value)});
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn_storage);
        return status;
    }
    return storage_txn_commit_full(runtime, txn_storage);
}

static ninlil_status_t park_event_fact(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    uint32_t park_cause)
{
    txn->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
    txn->pending_dispatch = 0u;
    txn->event_park_cause = park_cause;
    txn->spool_revision += 1u;
    return commit_event_spool(runtime, txn, 2u, park_cause);
}

static ninlil_status_t dispatch_desired_state_sender(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    if (ninlil_rt_v1_bearer_path_available(runtime)) {
        if (txn->delivery_phase == NINLIL_RT_DELIVERY_NONE
            || txn->delivery_phase == NINLIL_RT_DELIVERY_QUEUED) {
            return ninlil_rt_v1_bearer_send_desired_application(
                runtime, txn, clock_sample, out_result);
        }
        if (txn->delivery_phase == NINLIL_RT_DELIVERY_STARTED
            && txn->evidence_recorded == 0u) {
            return NINLIL_OK;
        }
        if (txn->outcome_recorded != 0u) {
            return NINLIL_OK;
        }
        return NINLIL_OK;
    }

    if (txn->delivery_phase == NINLIL_RT_DELIVERY_NONE) {
        txn->delivery_count = 1u;
        status = ninlil_rt_v1_commit_delivery_marker(
            runtime,
            txn,
            NINLIL_RT_V1_MARKER_DS,
            NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT,
            1u);
        if (status != NINLIL_OK) {
            return status;
        }
        txn->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
        out_result->transitions_consumed += 1u;
    }

    if (txn->evidence_recorded == 0u) {
        txn->outcome = NINLIL_OUTCOME_NONE;
        txn->reason = NINLIL_REASON_NONE;
        status = ninlil_rt_v1_commit_delivery_marker(
            runtime,
            txn,
            NINLIL_RT_V1_MARKER_EV,
            NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
            2u);
        if (status != NINLIL_OK) {
            return status;
        }
        txn->evidence_recorded = 1u;
        txn->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
        out_result->transitions_consumed += 1u;
    }

    if (txn->outcome_recorded == 0u) {
        txn->outcome = NINLIL_OUTCOME_SATISFIED;
        txn->reason = NINLIL_REASON_NONE;
        status = ninlil_rt_v1_commit_delivery_marker(
            runtime,
            txn,
            NINLIL_RT_V1_MARKER_OC,
            NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT,
            3u);
        if (status != NINLIL_OK) {
            return status;
        }
        txn->outcome_recorded = 1u;
        txn->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        txn->terminal = 1u;
        txn->pending_dispatch = 0u;
        runtime->nonterminal_transaction_count -= 1u;
        out_result->transitions_consumed += 1u;
    }
    return NINLIL_OK;
}

static ninlil_status_t dispatch_event_fact_receiver(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_rt_service_slot_t *receiver,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_delivery_token_t token;
    ninlil_delivery_view_t delivery_view;
    ninlil_application_result_t app_result;
    ninlil_callback_action_t action;
    ninlil_status_t status;

    if (txn->evidence_recorded != 0u) {
        if (txn->outcome_recorded == 0u) {
            txn->outcome = NINLIL_OUTCOME_SATISFIED;
            status = ninlil_rt_v1_commit_delivery_marker(
                runtime,
                txn,
                NINLIL_RT_V1_MARKER_OC,
                NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT,
                3u);
            if (status != NINLIL_OK) {
                return status;
            }
            txn->outcome_recorded = 1u;
            txn->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
            txn->terminal = 1u;
            runtime->nonterminal_transaction_count -= 1u;
            out_result->transitions_consumed += 1u;
        }
        txn->pending_dispatch = 0u;
        return NINLIL_OK;
    }

    if (txn->delivery_phase < NINLIL_RT_DELIVERY_STARTED) {
        txn->delivery_count += 1u;
        status = ninlil_rt_v1_commit_delivery_marker(
            runtime,
            txn,
            NINLIL_RT_V1_MARKER_DS,
            NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT,
            1u);
        if (status != NINLIL_OK) {
            return status;
        }
        txn->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
        out_result->transitions_consumed += 1u;
    }

    if (receiver->callbacks.on_delivery == NULL) {
        return park_event_fact(
            runtime, txn, NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE);
    }

    (void)memset(&token, 0, sizeof(token));
    set_header(&token.abi_version, &token.struct_size, sizeof(token));
    token.context_id = runtime->config.runtime_id;
    token.clock_epoch_id = clock_sample->clock_epoch_id;
    token.generation = txn->delivery_count;
    token.expires_at_ms = txn->effect_deadline_ms;

    (void)memset(&delivery_view, 0, sizeof(delivery_view));
    set_header(
        &delivery_view.abi_version,
        &delivery_view.struct_size,
        sizeof(delivery_view));
    delivery_view.transaction_id = txn->transaction_id;
    delivery_view.event_id = txn->event_id;
    delivery_view.content_digest = txn->content_digest;
    delivery_view.generation = txn->generation;
    delivery_view.delivery_count = txn->delivery_count;
    delivery_view.required_evidence = NINLIL_EVIDENCE_APPLIED;
    delivery_view.deadline_clock_epoch_id = clock_sample->clock_epoch_id;
    delivery_view.absolute_effect_deadline_ms = txn->effect_deadline_ms;

    (void)memset(&app_result, 0, sizeof(app_result));
    set_header(&app_result.abi_version, &app_result.struct_size, sizeof(app_result));

    if (txn->family == NINLIL_FAMILY_LATEST_STATE_RESERVED) {
        if (!ninlil_rt_v1_family_latest_state_apply(
                ninlil_rt_v1_family_workspace(runtime),
                &receiver->descriptor.local_application_instance_id,
                txn->generation,
                &app_result)) {
            if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                txn->pending_dispatch = 0u;
                return NINLIL_OK;
            }
            return NINLIL_E_INVALID_STATE;
        }
    } else if (txn->family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        if (!ninlil_rt_v1_family_measurement_batch_accept(
                ninlil_rt_v1_family_workspace(runtime),
                &receiver->descriptor.local_application_instance_id,
                txn->generation,
                txn->payload_length,
                &app_result)) {
            if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                txn->pending_dispatch = 0u;
                return NINLIL_OK;
            }
            return NINLIL_E_INVALID_STATE;
        }
    }

    runtime->in_callback = 1u;
    action = receiver->callbacks.on_delivery(
        receiver->callbacks.user,
        &token,
        &delivery_view,
        &app_result);
    runtime->in_callback = 0u;
    out_result->callbacks_invoked += 1u;

    if (action == NINLIL_CALLBACK_FATAL
        || action == NINLIL_CALLBACK_DEFER
        || (action == NINLIL_CALLBACK_COMPLETE
            && app_result.kind != NINLIL_APP_RESULT_POSITIVE_EVIDENCE)) {
        txn->pending_dispatch = 0u;
        return NINLIL_OK;
    }

    if (action != NINLIL_CALLBACK_COMPLETE) {
        return NINLIL_OK;
    }

    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_EV,
        NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
        2u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->evidence_recorded = 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    out_result->transitions_consumed += 1u;

    txn->outcome = NINLIL_OUTCOME_SATISFIED;
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_OC,
        NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT,
        3u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->outcome_recorded = 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
    txn->terminal = 1u;
    txn->pending_dispatch = 0u;
    runtime->nonterminal_transaction_count -= 1u;
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

static int txn_needs_work(const ninlil_rt_transaction_slot_t *txn)
{
    if (txn->in_use == 0u || txn->terminal != 0u || txn->event_discarded != 0u) {
        return 0;
    }
    if (txn->pending_dispatch != 0u) {
        return 1;
    }
    if (txn->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && txn->family == NINLIL_FAMILY_EVENT_FACT) {
        return 0;
    }
    if (txn->delivery_phase < NINLIL_RT_DELIVERY_OUTCOME
        && txn->outcome_recorded == 0u) {
        return 1;
    }
    return 0;
}

static int endpoint_has_pending_uplink_dispatch(const ninlil_runtime_t *runtime)
{
    uint32_t index;

    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return 0;
    }
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *txn = &runtime->transactions[index];
        if (txn->in_use != 0u && txn->terminal == 0u && txn->pending_dispatch != 0u
            && ninlil_rt_v1_family_is_uplink(txn->family)) {
            return 1;
        }
    }
    return 0;
}

static ninlil_status_t commit_terminal_outcome(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_outcome_t outcome,
    ninlil_reason_t reason,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    if (txn->outcome_recorded != 0u) {
        return NINLIL_OK;
    }
    txn->outcome = outcome;
    txn->reason = reason;
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_OC,
        NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT,
        3u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->outcome_recorded = 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
    txn->terminal = 1u;
    txn->pending_dispatch = 0u;
    runtime->nonterminal_transaction_count -= 1u;
    status = ninlil_rt_v1_release_transaction_reservation(runtime, txn);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

static ninlil_status_t handle_bearer_receipt_timeout(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;
    uint64_t receipt_deadline_ms;

    if (!ninlil_rt_v1_bearer_path_available(runtime)
        || runtime->config.role != NINLIL_ROLE_CONTROLLER
        || !ninlil_rt_v1_family_is_downlink(txn->family)
        || txn->delivery_phase != NINLIL_RT_DELIVERY_STARTED
        || txn->evidence_recorded != 0u
        || txn->pending_dispatch != 0u) {
        return NINLIL_OK;
    }
    receipt_deadline_ms = txn->admitted_at_ms + 1000u;
    if (clock_sample->now_ms < receipt_deadline_ms) {
        return NINLIL_OK;
    }
    if (txn->retry_budget == 0u) {
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT,
            out_result);
    }
    txn->retry_budget -= 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    txn->pending_dispatch = 1u;
    status = commit_retry_state(runtime, txn);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

static ninlil_status_t handle_timeout_retry(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    if (!ninlil_rt_v1_family_is_downlink(txn->family)
        || txn->effect_deadline_ms == 0u
        || txn->effect_deadline_ms >= NINLIL_NO_DEADLINE) {
        return NINLIL_OK;
    }
    if (clock_sample->now_ms <= txn->effect_deadline_ms) {
        return NINLIL_OK;
    }
    if (txn->retry_budget == 0u) {
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH,
            out_result);
    }
    if (clock_sample->now_ms < txn->next_retry_ms) {
        return NINLIL_OK;
    }

    txn->retry_budget -= 1u;
    if (txn->retry_backoff_ms == 0u) {
        txn->retry_backoff_ms = 100u;
    }
    txn->next_retry_ms = clock_sample->now_ms + txn->retry_backoff_ms;
    if (txn->retry_budget == 0u) {
        txn->pending_dispatch = 0u;
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT,
            out_result);
    }
    txn->pending_dispatch = 1u;
    status = commit_retry_state(runtime, txn);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_delivery_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t ingress_budget,
    uint32_t callback_budget,
    uint32_t transition_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    uint32_t order_capacity;
    uint32_t order_count = 0u;
    uint32_t index;
    uint32_t pass;
    ninlil_status_t status = NINLIL_OK;
    int defer_ingress = 0;

    if (runtime == NULL || clock_sample == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    defer_ingress = endpoint_has_pending_uplink_dispatch(runtime);
    if (!defer_ingress) {
        status = ninlil_rt_v1_bearer_ingress_step(
            runtime,
            clock_sample,
            &ingress_budget,
            callback_budget,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
    }

    order_capacity = runtime->transaction_capacity;
    if (order_capacity == 0u) {
        return NINLIL_OK;
    }
    {
        uint32_t stack_order[64];
        uint32_t *order;

        if (order_capacity > (uint32_t)(sizeof(stack_order) / sizeof(stack_order[0]))) {
            order_capacity = (uint32_t)(sizeof(stack_order) / sizeof(stack_order[0]));
        }
        order = stack_order;

        for (index = 0u; index < runtime->transaction_capacity; ++index) {
            if (!txn_needs_work(&runtime->transactions[index])) {
                continue;
            }
            if (order_count >= order_capacity) {
                break;
            }
            order[order_count] = index;
            order_count += 1u;
        }

        for (pass = 0u; pass < order_count; ++pass) {
            uint32_t best = pass;
            uint32_t candidate;

            for (candidate = pass + 1u; candidate < order_count; ++candidate) {
                if (ninlil_rt_v1_txn_queue_order_less(
                        &runtime->transactions[order[candidate]],
                        &runtime->transactions[order[best]])) {
                    best = candidate;
                }
            }
            if (best != pass) {
                uint32_t tmp = order[pass];
                order[pass] = order[best];
                order[best] = tmp;
            }
        }

        for (pass = 0u; pass < order_count; ++pass) {
            ninlil_rt_transaction_slot_t *txn =
                &runtime->transactions[order[pass]];
            ninlil_rt_service_slot_t *receiver;

            status = handle_timeout_retry(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            status = handle_bearer_receipt_timeout(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            if (transition_budget != 0u
                && out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }

            if (txn->family == NINLIL_FAMILY_EVENT_FACT
                && txn->delivery_phase == NINLIL_RT_DELIVERY_NONE
                && txn->pending_dispatch != 0u
                && runtime->config.role == NINLIL_ROLE_ENDPOINT
                && !ninlil_rt_v1_bearer_path_available(runtime)) {
                status = park_event_fact(
                    runtime,
                    txn,
                    NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE);
                if (status != NINLIL_OK) {
                    return status;
                }
                out_result->transitions_consumed += 1u;
                continue;
            }

            if (ninlil_rt_v1_family_is_uplink(txn->family)
                && runtime->config.role == NINLIL_ROLE_ENDPOINT
                && txn->pending_dispatch != 0u
                && ninlil_rt_v1_bearer_path_available(runtime)) {
                status = ninlil_rt_v1_bearer_send_uplink_application(
                    runtime, txn, clock_sample, out_result);
                if (status != NINLIL_OK) {
                    return status;
                }
                continue;
            }

            receiver = find_receiver_for_txn(runtime, txn);
            if (ninlil_rt_v1_family_is_downlink(txn->family)
                && receiver != NULL
                && txn->pending_dispatch != 0u) {
                status = dispatch_desired_state_sender(
                    runtime, txn, clock_sample, out_result);
                if (status != NINLIL_OK) {
                    return status;
                }
                if (txn->terminal != 0u) {
                    status = ninlil_rt_v1_release_transaction_reservation(
                        runtime, txn);
                    if (status != NINLIL_OK) {
                        return status;
                    }
                }
                continue;
            }

            if ((txn->family == NINLIL_FAMILY_EVENT_FACT
                    || txn->family == NINLIL_FAMILY_LATEST_STATE_RESERVED
                    || txn->family == NINLIL_FAMILY_MEASUREMENT_RESERVED)
                && receiver != NULL
                && txn->pending_dispatch != 0u
                && txn->delivery_phase != NINLIL_RT_DELIVERY_PARKED) {
                if (callback_budget != 0u
                    && out_result->callbacks_invoked >= callback_budget) {
                    out_result->work_remaining = 1u;
                    return NINLIL_OK;
                }
                status = dispatch_event_fact_receiver(
                    runtime, txn, receiver, clock_sample, out_result);
                if (status != NINLIL_OK) {
                    return status;
                }
                if (txn->terminal != 0u) {
                    status = ninlil_rt_v1_release_transaction_reservation(
                        runtime, txn);
                    if (status != NINLIL_OK) {
                        return status;
                    }
                }
                continue;
            }

            if (txn->pending_dispatch != 0u) {
                if (!(ninlil_rt_v1_family_is_downlink(txn->family)
                        && runtime->config.role == NINLIL_ROLE_CONTROLLER
                        && ninlil_rt_v1_bearer_path_available(runtime))) {
                    txn->pending_dispatch = 0u;
                }
            }
        }
    }

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        if (txn_needs_work(&runtime->transactions[index])) {
            out_result->work_remaining = 1u;
            break;
        }
    }
    if (out_result->work_remaining == 0u) {
        runtime->pending_work = 0u;
    }
    if (defer_ingress) {
        status = ninlil_rt_v1_bearer_ingress_step(
            runtime,
            clock_sample,
            &ingress_budget,
            callback_budget,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    return NINLIL_OK;
}

void ninlil_rt_v1_encode_tx_admission_marker(
    uint8_t *value,
    ninlil_family_t family,
    const ninlil_id128_t *service_app_id,
    uint64_t effect_deadline_ms,
    uint64_t generation)
{
    ninlil_rt_v1_encode_tx_admission_marker_v2(
        value,
        family,
        service_app_id,
        effect_deadline_ms,
        generation,
        ninlil_rt_v1_semantic_priority_for_family(family),
        0u,
        0u);
}

static ninlil_status_t delivery_restart_scan_pass(
    ninlil_runtime_t *runtime,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    uint32_t tx_admission_only)
{
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    uint8_t key_buf[255];
    uint8_t value_buf[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_bytes_view_t prefix;

    prefix.data = NULL;
    prefix.length = 0u;
    st = storage->iter_open(storage->user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    for (;;) {
        ninlil_id128_t txn_id;
        ninlil_rt_transaction_slot_t *slot;
        int is_tx_marker;

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
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            return NINLIL_E_STORAGE;
        }
        if (key.length < NINLIL_RT_V1_TXN_MARKER_BYTES || key.data == NULL) {
            continue;
        }

        is_tx_marker = key.data[0] == 0x54u && key.data[1] == 0x58u;
        if (tx_admission_only != 0u) {
            if (is_tx_marker == 0) {
                continue;
            }
        } else if (is_tx_marker != 0) {
            continue;
        }

        (void)memset(&txn_id, 0, sizeof(txn_id));
        (void)memcpy(txn_id.bytes, &key.data[2], 14u);

        if (is_tx_marker != 0) {
            ninlil_family_t family = NINLIL_FAMILY_DESIRED_STATE;
            ninlil_id128_t service_app_id;
            uint64_t effect_deadline_ms = 0u;
            uint64_t generation = 0u;
            uint8_t semantic_priority = 0u;
            uint32_t payload_length = 0u;
            uint64_t admitted_at_ms = 0u;

            slot = ninlil_rt_find_transaction(runtime, &txn_id);
            if (slot == NULL) {
                slot = ninlil_rt_alloc_transaction(runtime);
                if (slot == NULL) {
                    continue;
                }
                runtime->nonterminal_transaction_count += 1u;
            }
            (void)memset(&service_app_id, 0, sizeof(service_app_id));
            ninlil_rt_v1_decode_tx_admission_marker(
                (ninlil_bytes_view_t){value.data, value.length},
                &family,
                &service_app_id,
                &effect_deadline_ms,
                &generation,
                &semantic_priority,
                &payload_length,
                &admitted_at_ms);

            slot->in_use = 1u;
            slot->transaction_id = txn_id;
            slot->family = family;
            slot->service_app_id = service_app_id;
            slot->effect_deadline_ms = effect_deadline_ms;
            slot->generation = generation;
            slot->semantic_priority = semantic_priority;
            if (semantic_priority == 0u) {
                slot->semantic_priority =
                    ninlil_rt_v1_semantic_priority_for_family(family);
            }
            slot->payload_length = payload_length;
            slot->admitted_at_ms = admitted_at_ms;
            slot->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
            slot->pending_dispatch = 1u;
            slot->retry_budget = NINLIL_RT_V1_DEFAULT_RETRY_BUDGET;
            slot->retry_backoff_ms = 100u;
            if (slot->spool_revision == 0u) {
                slot->spool_revision = 1u;
            }
            runtime->pending_work = 1u;
            continue;
        }

        slot = ninlil_rt_find_transaction(runtime, &txn_id);
        if (slot == NULL) {
            continue;
        }

        if (key.data[0] == 0x44u && key.data[1] == 0x53u) {
            uint8_t phase = 0u;
            uint64_t delivery_count = 0u;
            ninlil_outcome_t outcome = NINLIL_OUTCOME_NONE;
            ninlil_reason_t reason = NINLIL_REASON_NONE;

            decode_delivery_marker(
                (ninlil_bytes_view_t){value.data, value.length},
                &phase,
                &delivery_count,
                &outcome,
                &reason);
            slot->delivery_count = delivery_count;
            slot->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
            continue;
        }

        if (key.data[0] == 0x45u && key.data[1] == 0x56u) {
            slot->evidence_recorded = 1u;
            slot->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
            continue;
        }

        if (key.data[0] == 0x4fu && key.data[1] == 0x43u) {
            uint8_t phase = 0u;
            uint64_t delivery_count = 0u;
            ninlil_outcome_t outcome = NINLIL_OUTCOME_NONE;
            ninlil_reason_t reason = NINLIL_REASON_NONE;

            decode_delivery_marker(
                (ninlil_bytes_view_t){value.data, value.length},
                &phase,
                &delivery_count,
                &outcome,
                &reason);
            slot->outcome = outcome;
            slot->reason = reason;
            slot->outcome_recorded = 1u;
            slot->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
            slot->terminal = 1u;
            slot->pending_dispatch = 0u;
            continue;
        }

        if (key.data[0] == 0x45u && key.data[1] == 0x53u) {
            uint32_t state = 0u;
            uint32_t park_cause = 0u;

            decode_event_spool_marker(
                (ninlil_bytes_view_t){value.data, value.length},
                &state,
                &slot->spool_revision,
                &park_cause);
            if (state == 2u) {
                slot->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
                slot->event_park_cause = park_cause;
                slot->pending_dispatch = 0u;
            } else if (state == 3u) {
                slot->event_discarded = 1u;
                slot->terminal = 1u;
                slot->pending_dispatch = 0u;
            } else if (state == 1u) {
                slot->pending_dispatch = 1u;
                slot->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
            }
            continue;
        }

        if (key.data[0] == 0x52u && key.data[1] == 0x56u) {
            if (value.length >= 4u && value.data != NULL) {
                (void)memcpy(
                    &slot->payload_length, &value.data[0], sizeof(slot->payload_length));
                slot->bearer_route = value.data[4];
                slot->reservation_active = 1u;
            }
            continue;
        }

        if (key.data[0] == 0x52u && key.data[1] == 0x54u) {
            decode_retry_marker(
                (ninlil_bytes_view_t){value.data, value.length},
                &slot->retry_budget,
                &slot->next_retry_ms);
            continue;
        }
    }

    storage->iter_close(storage->user, iter);
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_delivery_restart_scan(
    ninlil_runtime_t *runtime)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    ninlil_status_t status;

    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;

    st = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    status = delivery_restart_scan_pass(runtime, storage, txn, 1u);
    if (status == NINLIL_OK) {
        status = delivery_restart_scan_pass(runtime, storage, txn, 0u);
    }

    (void)storage->rollback(storage->user, txn);
    return status;
}
