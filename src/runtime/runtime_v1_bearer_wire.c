#include "runtime_v1_bearer_wire.h"

#include "runtime_v1_capability.h"
#include "runtime_v1_family_capability.h"
#include "submission_preflight.h"

#include <string.h>

#define NINLIL_RT_V1_MARKER_DS 0x4453u
#define NINLIL_RT_V1_MARKER_EV 0x4556u
#define NINLIL_RT_V1_MARKER_OC 0x4f43u
#define NINLIL_RT_V1_MARKER_ES 0x4553u
#define NINLIL_RT_V1_MARKER_RT 0x5254u
#define NINLIL_RT_V1_BEARER_STATE_KEY_BYTES 18u
#define NINLIL_RT_V1_BEARER_STATE_VALUE_BYTES 48u
#define NINLIL_RT_V1_BEARER_STATE_MAGIC_BYTES 8u

static const uint8_t NINLIL_RT_V1_BEARER_STATE_MAGIC[
    NINLIL_RT_V1_BEARER_STATE_MAGIC_BYTES] = {
    0x4eu, 0x42u, 0x53u, 0x31u, 0x00u, 0x01u, 0x00u, 0x00u
};

static int bytes_are_zero(const void *value, size_t length);

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

static void store_u64_be(uint8_t *out, uint64_t value)
{
    uint32_t index;

    for (index = 0u; index < 8u; ++index) {
        out[index] = (uint8_t)(value >> (56u - index * 8u));
    }
}

static uint64_t load_u64_be(const uint8_t *input)
{
    uint64_t value = 0u;
    uint32_t index;

    for (index = 0u; index < 8u; ++index) {
        value = (value << 8) | input[index];
    }
    return value;
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
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
    default:
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static void encode_bearer_state_marker(
    const ninlil_bearer_state_t *state,
    const ninlil_time_sample_t *clock_sample,
    uint8_t value[NINLIL_RT_V1_BEARER_STATE_VALUE_BYTES])
{
    (void)memset(value, 0, NINLIL_RT_V1_BEARER_STATE_VALUE_BYTES);
    (void)memcpy(
        value,
        NINLIL_RT_V1_BEARER_STATE_MAGIC,
        sizeof(NINLIL_RT_V1_BEARER_STATE_MAGIC));
    store_u64_be(&value[8], state->availability_epoch);
    value[19] = (uint8_t)state->available;
    (void)memcpy(&value[24], clock_sample->clock_epoch_id.bytes, 16u);
    store_u64_be(&value[40], clock_sample->now_ms);
}

ninlil_status_t ninlil_rt_v1_bearer_state_marker_validate(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    uint64_t availability_epoch;
    uint32_t available;

    if ((key.length != 0u && key.data == NULL)
        || (value.length != 0u && value.data == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (key.data == NULL || key.length < 2u
        || key.data[0] != 0x42u || key.data[1] != 0x53u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (key.length != NINLIL_RT_V1_BEARER_STATE_KEY_BYTES) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (bytes_are_zero(&key.data[2], 16u)
        || value.data == NULL
        || value.length != NINLIL_RT_V1_BEARER_STATE_VALUE_BYTES
        || memcmp(
            value.data,
            NINLIL_RT_V1_BEARER_STATE_MAGIC,
            sizeof(NINLIL_RT_V1_BEARER_STATE_MAGIC)) != 0
        || !bytes_are_zero(&value.data[16], 3u)
        || !bytes_are_zero(&value.data[20], 4u)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    availability_epoch = load_u64_be(&value.data[8]);
    available = value.data[19];
    if (availability_epoch == 0u || available > 1u
        || bytes_are_zero(&value.data[24], 16u)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t commit_bearer_state_marker(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_state_t *state,
    const ninlil_time_sample_t *clock_sample)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_status_t status;
    uint8_t key[NINLIL_RT_V1_BEARER_STATE_KEY_BYTES];
    uint8_t value[NINLIL_RT_V1_BEARER_STATE_VALUE_BYTES];

    key[0] = 0x42u;
    key[1] = 0x53u;
    (void)memcpy(&key[2], runtime->config.runtime_id.bytes, 16u);
    encode_bearer_state_marker(state, clock_sample, value);
    storage_status = storage->begin(
        storage->user,
        runtime->storage,
        NINLIL_STORAGE_READ_WRITE,
        &transaction);
    status = map_storage_mutation_status(runtime, storage_status);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_BEARER_STATE_COMMIT,
        storage,
        transaction,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){value, sizeof(value)},
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        (void)storage->rollback(storage->user, transaction);
        return status;
    }
    storage_status = storage->commit(
        storage->user, transaction, NINLIL_DURABILITY_FULL);
    status = map_storage_mutation_status(runtime, storage_status);
    if (status != NINLIL_OK) {
        return status;
    }
    runtime->bearer_state_present = 1u;
    runtime->bearer_available = state->available;
    runtime->bearer_availability_epoch = state->availability_epoch;
    runtime->bearer_observed_clock_epoch_id = clock_sample->clock_epoch_id;
    runtime->bearer_observed_at_ms = clock_sample->now_ms;
    return NINLIL_OK;
}

int ninlil_rt_v1_bearer_restore_state_marker(
    ninlil_runtime_t *runtime,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_status_t status;

    if (key.data == NULL || key.length < 2u
        || key.data[0] != 0x42u || key.data[1] != 0x53u) {
        return 0;
    }
    status = ninlil_rt_v1_bearer_state_marker_validate(key, value);
    if (runtime == NULL || status != NINLIL_OK
        || memcmp(&key.data[2], runtime->config.runtime_id.bytes, 16u) != 0) {
        return -1;
    }
    runtime->bearer_state_present = 1u;
    runtime->bearer_available = value.data[19];
    runtime->bearer_availability_epoch = load_u64_be(&value.data[8]);
    (void)memcpy(
        runtime->bearer_observed_clock_epoch_id.bytes,
        &value.data[24],
        16u);
    runtime->bearer_observed_at_ms = load_u64_be(&value.data[40]);
    return 1;
}

static void note_satisfied_terminal(
    ninlil_runtime_t *runtime,
    ninlil_outcome_t outcome,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    out_result->transactions_terminalized += 1u;
    if (outcome == NINLIL_OUTCOME_SATISFIED) {
        saturating_increment_u64(&runtime->metrics.transactions_satisfied);
    } else if (outcome == NINLIL_OUTCOME_EXPIRED) {
        saturating_increment_u64(&runtime->metrics.transactions_expired);
    }
}

static void note_bearer_send(
    ninlil_runtime_t *runtime,
    ninlil_bearer_status_t status,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    out_result->bearer_sends += 1u;
    if (status == NINLIL_BEARER_WOULD_BLOCK) {
        saturating_increment_u64(&runtime->metrics.bearer_would_block);
    }
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

static int bearer_message_logical_bytes(
    const ninlil_bearer_message_t *message,
    uint32_t *out_bytes)
{
    uint64_t total = 455u;
    uint64_t additions[5];
    uint32_t index;

    if (message == NULL || out_bytes == NULL
        || message->service.namespace_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || message->service.service_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || message->service.schema_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || (message->payload.length == 0u
            && message->payload.data != NULL)
        || (message->payload.length != 0u
            && message->payload.data == NULL)
        || (message->evidence.length == 0u
            && message->evidence.data != NULL)
        || (message->evidence.length != 0u
            && message->evidence.data == NULL)) {
        return 0;
    }
    additions[0] = message->service.namespace_id.length;
    additions[1] = message->service.service_id.length;
    additions[2] = message->service.schema_id.length;
    additions[3] = message->payload.length;
    additions[4] = message->evidence.length;
    for (index = 0u; index < 5u; ++index) {
        if (total > UINT32_MAX - additions[index]) {
            return 0;
        }
        total += additions[index];
    }
    *out_bytes = (uint32_t)total;
    return 1;
}

typedef enum ninlil_rt_send_observation_kind {
    NINLIL_RT_SEND_OBS_ACCEPTED_OR_POSSIBLE = 1,
    NINLIL_RT_SEND_OBS_WOULD_RETRY = 2,
    NINLIL_RT_SEND_OBS_DENIED = 3
} ninlil_rt_send_observation_kind_t;

typedef enum ninlil_rt_tx_gate_observation_kind {
    NINLIL_RT_TX_GATE_ACQUIRED = 1,
    NINLIL_RT_TX_GATE_RETRY = 2,
    NINLIL_RT_TX_GATE_DENIED = 3,
    NINLIL_RT_TX_GATE_CONTRACT_FAULT = 4
} ninlil_rt_tx_gate_observation_kind_t;

static ninlil_status_t acquire_fresh_tx_permit(
    ninlil_runtime_t *runtime,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *step_sample,
    ninlil_tx_permit_t *out_permit,
    ninlil_time_sample_t *out_fresh_sample,
    ninlil_rt_tx_gate_observation_kind_t *out_observation)
{
    const ninlil_tx_gate_ops_t *tx_gate = runtime->platform->tx_gate;
    ninlil_port_status_t clock_status;
    ninlil_tx_gate_status_t gate_status;
    int permit_zero;
    int permit_valid;

    (void)memset(out_permit, 0, sizeof(*out_permit));
    (void)memset(out_fresh_sample, 0, sizeof(*out_fresh_sample));
    *out_observation = NINLIL_RT_TX_GATE_CONTRACT_FAULT;
    clock_status = runtime->platform->clock->now(
        runtime->platform->clock->user, out_fresh_sample);
    if (clock_status != NINLIL_PORT_OK
        || out_fresh_sample->trust != NINLIL_CLOCK_TRUSTED
        || !id_nonzero(&out_fresh_sample->clock_epoch_id)
        || memcmp(
            out_fresh_sample->clock_epoch_id.bytes,
            step_sample->clock_epoch_id.bytes,
            sizeof(step_sample->clock_epoch_id.bytes)) != 0
        || out_fresh_sample->now_ms < step_sample->now_ms) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return clock_status == NINLIL_PORT_TEMPORARY_FAILURE
                || (clock_status == NINLIL_PORT_OK
                    && out_fresh_sample->trust
                        == NINLIL_CLOCK_UNCERTAIN)
            ? NINLIL_E_CLOCK_UNCERTAIN
            : NINLIL_E_DEGRADED;
    }

    gate_status = tx_gate->acquire(
        tx_gate->user, request, out_fresh_sample, out_permit);
    permit_zero = bytes_are_zero(out_permit, sizeof(*out_permit));
    permit_valid =
        out_permit->abi_version == NINLIL_ABI_VERSION
        && out_permit->struct_size == sizeof(*out_permit)
        && id_nonzero(&out_permit->permit_id)
        && memcmp(
            out_permit->attempt_id.bytes,
            request->attempt_id.bytes,
            sizeof(request->attempt_id.bytes)) == 0
        && memcmp(
            out_permit->clock_epoch_id.bytes,
            out_fresh_sample->clock_epoch_id.bytes,
            sizeof(out_fresh_sample->clock_epoch_id.bytes)) == 0
        && out_permit->expires_at_ms > out_fresh_sample->now_ms;
    if (gate_status == NINLIL_TX_GATE_OK && permit_valid) {
        *out_observation = NINLIL_RT_TX_GATE_ACQUIRED;
        return NINLIL_OK;
    }
    if (gate_status == NINLIL_TX_GATE_TEMPORARY && permit_zero) {
        *out_observation = NINLIL_RT_TX_GATE_RETRY;
        return NINLIL_OK;
    }
    if (gate_status == NINLIL_TX_GATE_DENIED && permit_zero) {
        *out_observation = NINLIL_RT_TX_GATE_DENIED;
        return NINLIL_OK;
    }
    if (gate_status == NINLIL_TX_GATE_OK
        && id_nonzero(&out_permit->permit_id)) {
        tx_gate->release_unused(tx_gate->user, out_permit);
    }
    runtime->health = NINLIL_HEALTH_DEGRADED;
    runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
    *out_observation = NINLIL_RT_TX_GATE_CONTRACT_FAULT;
    return NINLIL_OK;
}

static ninlil_status_t commit_application_gate_observation(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    ninlil_rt_tx_gate_observation_kind_t observation,
    const ninlil_time_sample_t *fresh_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;
    ninlil_status_t status;
    uint32_t contract_fault =
        observation == NINLIL_RT_TX_GATE_CONTRACT_FAULT;

    *candidate = *transaction;
    if (observation == NINLIL_RT_TX_GATE_RETRY
        && transaction->retry_budget != 0u) {
        if (candidate->retry_backoff_ms == 0u) {
            candidate->retry_backoff_ms = 100u;
        }
        if (fresh_sample->now_ms
            > UINT64_MAX - candidate->retry_backoff_ms) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
        candidate->pending_dispatch = 1u;
        candidate->attempt_prepared = 0u;
        (void)memset(
            &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
        candidate->reason = NINLIL_REASON_TRANSPORT_RETRY;
        candidate->next_retry_clock_epoch_id =
            fresh_sample->clock_epoch_id;
        candidate->next_retry_ms =
            fresh_sample->now_ms + candidate->retry_backoff_ms;
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_RT,
            NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
    } else if (transaction->family == NINLIL_FAMILY_EVENT_FACT) {
        if (candidate->spool_revision == UINT64_MAX) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
        candidate->pending_dispatch = 0u;
        candidate->event_park_cause =
            observation == NINLIL_RT_TX_GATE_RETRY
            ? NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
            : NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION;
        candidate->spool_revision += 1u;
        if (runtime->bearer_state_present != 0u
            && runtime->bearer_availability_epoch
                > candidate->last_bearer_availability_epoch) {
            candidate->last_bearer_availability_epoch =
                runtime->bearer_availability_epoch;
        }
        if (candidate->last_bearer_availability_epoch
            > candidate->last_consumed_bearer_availability_epoch) {
            candidate->last_consumed_bearer_availability_epoch =
                candidate->last_bearer_availability_epoch;
        }
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_ES,
            NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT);
        if (status == NINLIL_OK) {
            out_result->events_parked += 1u;
            saturating_increment_u64(&runtime->metrics.events_parked);
        }
    } else {
        candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        candidate->pending_dispatch = 0u;
        candidate->outcome_recorded = 1u;
        candidate->terminal = 1u;
        candidate->outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
        candidate->reason =
            observation == NINLIL_RT_TX_GATE_RETRY
            ? NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT
            : NINLIL_REASON_APPLICATION_FAILED;
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_OC,
            NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT);
        if (status == NINLIL_OK) {
            if (runtime->nonterminal_transaction_count > 0u) {
                runtime->nonterminal_transaction_count -= 1u;
            }
            out_result->transactions_terminalized += 1u;
            saturating_increment_u64(
                &runtime->metrics.transactions_failed_definitive);
        }
    }
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    return contract_fault != 0u ? NINLIL_E_DEGRADED : NINLIL_OK;
}

static int bearer_status_is_known(ninlil_bearer_status_t status)
{
    return status >= NINLIL_BEARER_OK
        && status <= NINLIL_BEARER_CORRUPT;
}

static int send_result_header_is_valid(
    const ninlil_bearer_send_result_t *result,
    uint64_t minimum_epoch)
{
    return result->abi_version == NINLIL_ABI_VERSION
        && result->struct_size == sizeof(*result)
        && result->reserved_zero == 0u
        && result->availability_epoch != 0u
        && result->availability_epoch >= minimum_epoch;
}

static ninlil_rt_send_observation_kind_t classify_send_observation(
    ninlil_bearer_status_t status,
    const ninlil_bearer_send_result_t *result,
    uint64_t minimum_epoch,
    uint32_t *out_contract_fault)
{
    int header_valid = send_result_header_is_valid(result, minimum_epoch);
    int zero_kind = result->kind == 0u;

    *out_contract_fault = 0u;
    if (status == NINLIL_BEARER_OK && header_valid
        && (result->kind == NINLIL_BEARER_SEND_ACCEPTED
            || result->kind == NINLIL_BEARER_SEND_DURABLE_CUSTODY)) {
        return NINLIL_RT_SEND_OBS_ACCEPTED_OR_POSSIBLE;
    }
    if ((status == NINLIL_BEARER_WOULD_BLOCK
            || status == NINLIL_BEARER_UNAVAILABLE)
        && header_valid && zero_kind) {
        return NINLIL_RT_SEND_OBS_WOULD_RETRY;
    }
    if (status == NINLIL_BEARER_DENIED
        && header_valid && zero_kind) {
        return NINLIL_RT_SEND_OBS_DENIED;
    }
    if (status == NINLIL_BEARER_LOST_UNKNOWN
        && header_valid && zero_kind) {
        return NINLIL_RT_SEND_OBS_ACCEPTED_OR_POSSIBLE;
    }

    *out_contract_fault =
        status == NINLIL_BEARER_CORRUPT
        || status == NINLIL_BEARER_EMPTY
        || !bearer_status_is_known(status)
        || !header_valid
        || !zero_kind
        || status == NINLIL_BEARER_OK;
    return NINLIL_RT_SEND_OBS_ACCEPTED_OR_POSSIBLE;
}

static uint64_t observed_availability_epoch(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_bearer_send_result_t *result)
{
    uint64_t epoch = runtime->step_bearer_availability_epoch;

    if (transaction->last_bearer_availability_epoch > epoch) {
        epoch = transaction->last_bearer_availability_epoch;
    }
    if (result->availability_epoch > epoch
        && result->abi_version == NINLIL_ABI_VERSION
        && result->struct_size == sizeof(*result)
        && result->reserved_zero == 0u) {
        epoch = result->availability_epoch;
    }
    return epoch;
}

static ninlil_status_t commit_application_send_observation(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    ninlil_bearer_status_t send_status,
    const ninlil_bearer_send_result_t *send_result,
    const ninlil_time_sample_t *clock_sample,
    const ninlil_tx_permit_t *permit,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;
    ninlil_rt_send_observation_kind_t observation;
    uint64_t minimum_epoch = runtime->step_bearer_availability_epoch;
    uint32_t contract_fault = 0u;
    ninlil_status_t status;

    *candidate = *transaction;
    if (transaction->last_bearer_availability_epoch > minimum_epoch) {
        minimum_epoch = transaction->last_bearer_availability_epoch;
    }
    observation = classify_send_observation(
        send_status, send_result, minimum_epoch, &contract_fault);
    if (observation == NINLIL_RT_SEND_OBS_ACCEPTED_OR_POSSIBLE) {
        candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
        candidate->pending_dispatch = 0u;
        candidate->send_observation_closed = 1u;
        candidate->send_observed_clock_epoch_id =
            clock_sample->clock_epoch_id;
        candidate->send_observed_at_ms = clock_sample->now_ms;
        candidate->last_bearer_availability_epoch =
            observed_availability_epoch(runtime, transaction, send_result);
        candidate->next_retry_ms = 0u;
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_DS,
            NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT);
        if (status != NINLIL_OK) {
            return status;
        }
        out_result->transitions_consumed += 1u;
        if (contract_fault != 0u) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
            return NINLIL_E_DEGRADED;
        }
        return NINLIL_OK;
    }

    runtime->platform->tx_gate->release_unused(
        runtime->platform->tx_gate->user, permit);
    if (observation == NINLIL_RT_SEND_OBS_DENIED) {
        if (transaction->family == NINLIL_FAMILY_EVENT_FACT) {
            if (candidate->spool_revision == UINT64_MAX) {
                runtime->health = NINLIL_HEALTH_DEGRADED;
                runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
                return NINLIL_E_DEGRADED;
            }
            candidate->pending_dispatch = 0u;
            candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
            candidate->event_park_cause =
                NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION;
            candidate->spool_revision += 1u;
            if (runtime->bearer_state_present != 0u
                && runtime->bearer_availability_epoch
                    > candidate->last_bearer_availability_epoch) {
                candidate->last_bearer_availability_epoch =
                    runtime->bearer_availability_epoch;
            }
            if (candidate->last_bearer_availability_epoch
                > candidate->last_consumed_bearer_availability_epoch) {
                candidate->last_consumed_bearer_availability_epoch =
                    candidate->last_bearer_availability_epoch;
            }
            status = ninlil_rt_v1_commit_transaction_snapshot(
                runtime,
                transaction,
                candidate,
                NINLIL_RT_V1_MARKER_ES,
                NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT);
            if (status != NINLIL_OK) {
                return status;
            }
            out_result->transitions_consumed += 1u;
            out_result->events_parked += 1u;
            saturating_increment_u64(&runtime->metrics.events_parked);
            return NINLIL_OK;
        }
        candidate->pending_dispatch = 0u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        candidate->outcome_recorded = 1u;
        candidate->terminal = 1u;
        candidate->outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
        candidate->reason = NINLIL_REASON_APPLICATION_FAILED;
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_OC,
            NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT);
        if (status != NINLIL_OK) {
            return status;
        }
        if (runtime->nonterminal_transaction_count > 0u) {
            runtime->nonterminal_transaction_count -= 1u;
        }
        out_result->transitions_consumed += 1u;
        out_result->transactions_terminalized += 1u;
        saturating_increment_u64(
            &runtime->metrics.transactions_failed_definitive);
        return NINLIL_OK;
    }

    if (transaction->family == NINLIL_FAMILY_EVENT_FACT) {
        if (candidate->spool_revision == UINT64_MAX) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        candidate->pending_dispatch = 0u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
        candidate->event_park_cause =
            NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE;
        candidate->spool_revision += 1u;
        candidate->last_bearer_availability_epoch =
            observed_availability_epoch(
                runtime, transaction, send_result);
        if (candidate->last_bearer_availability_epoch
            > candidate->last_consumed_bearer_availability_epoch) {
            candidate->last_consumed_bearer_availability_epoch =
                candidate->last_bearer_availability_epoch;
        }
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_ES,
            NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT);
        if (status != NINLIL_OK) {
            return status;
        }
        out_result->transitions_consumed += 1u;
        out_result->events_parked += 1u;
        saturating_increment_u64(&runtime->metrics.events_parked);
        return NINLIL_OK;
    }

    candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    candidate->pending_dispatch = 1u;
    candidate->attempt_prepared = 0u;
    (void)memset(
        &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
    candidate->reason = NINLIL_REASON_TRANSPORT_RETRY;
    if (candidate->retry_backoff_ms == 0u) {
        candidate->retry_backoff_ms = 100u;
    }
    if (clock_sample->now_ms
        > UINT64_MAX - candidate->retry_backoff_ms) {
        return NINLIL_E_DEGRADED;
    }
    candidate->next_retry_ms =
        clock_sample->now_ms + candidate->retry_backoff_ms;
    candidate->next_retry_clock_epoch_id = clock_sample->clock_epoch_id;
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        transaction,
        candidate,
        NINLIL_RT_V1_MARKER_RT,
        NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

int ninlil_rt_v1_bearer_path_available(ninlil_runtime_t *runtime)
{
    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->bearer == NULL || runtime->bearer == NULL) {
        return 0;
    }
    if (runtime->in_step != 0u) {
        return runtime->step_bearer_state_valid != 0u
            && runtime->step_bearer_available != 0u;
    }
    return runtime->bearer_state_present != 0u
        && runtime->bearer_available != 0u;
}

static int bytes_are_zero(const void *value, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int header_is_current(
    uint16_t abi_version,
    uint16_t struct_size,
    size_t expected_size)
{
    return abi_version == NINLIL_ABI_VERSION
        && struct_size == expected_size;
}

static int id_equal(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int id_is_zero(const ninlil_id128_t *id)
{
    return !id_nonzero(id);
}

static int digest_is_valid(const ninlil_digest256_t *digest)
{
    return digest->algorithm == NINLIL_DIGEST_SHA256
        && digest->reserved_zero == 0u
        && !bytes_are_zero(digest->bytes, sizeof(digest->bytes));
}

static int digest_equal(
    const ninlil_digest256_t *left,
    const ninlil_digest256_t *right)
{
    return left->algorithm == right->algorithm
        && left->reserved_zero == right->reserved_zero
        && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int text_id_is_canonical(const ninlil_text_id_t *text)
{
    return text->length > 0u
        && text->length <= NINLIL_MAX_TEXT_ID_BYTES
        && bytes_are_zero(
            &text->bytes[text->length],
            sizeof(text->bytes) - text->length);
}

static int text_id_equal(
    const ninlil_text_id_t *left,
    const ninlil_text_id_t *right)
{
    return left->length == right->length
        && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int identity_presence_shape_is_valid(
    uint32_t flags,
    const ninlil_id128_t *device_id,
    const ninlil_id128_t *installation_id,
    const ninlil_id128_t *site_domain_id,
    uint64_t binding_epoch,
    uint64_t membership_epoch)
{
    const uint32_t known = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    int has_device =
        (flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u;
    int has_installation =
        (flags & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u;
    int has_site =
        (flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u;

    return (flags & ~known) == 0u
        && has_device == (id_nonzero(device_id) != 0)
        && has_installation == (id_nonzero(installation_id) != 0)
        && has_site == (id_nonzero(site_domain_id) != 0)
        && (binding_epoch != 0u) == (has_device || has_installation)
        && (membership_epoch != 0u) == has_site;
}

static int local_identity_is_valid(
    const ninlil_local_identity_t *identity)
{
    return header_is_current(
            identity->abi_version,
            identity->struct_size,
            sizeof(*identity))
        && identity->reserved_zero == 0u
        && identity_presence_shape_is_valid(
            identity->flags,
            &identity->device_id,
            &identity->installation_id,
            &identity->site_domain_id,
            identity->binding_epoch,
            identity->membership_epoch);
}

static int local_identity_equal(
    const ninlil_local_identity_t *left,
    const ninlil_local_identity_t *right)
{
    return header_is_current(
            left->abi_version, left->struct_size, sizeof(*left))
        && header_is_current(
            right->abi_version, right->struct_size, sizeof(*right))
        && id_equal(&left->device_id, &right->device_id)
        && id_equal(&left->installation_id, &right->installation_id)
        && id_equal(&left->site_domain_id, &right->site_domain_id)
        && left->binding_epoch == right->binding_epoch
        && left->membership_epoch == right->membership_epoch
        && left->flags == right->flags
        && left->reserved_zero == right->reserved_zero;
}

static int party_is_valid(const ninlil_party_t *party)
{
    return header_is_current(
            party->abi_version, party->struct_size, sizeof(*party))
        && id_nonzero(&party->runtime_id)
        && id_nonzero(&party->application_instance_id)
        && local_identity_is_valid(&party->local_identity);
}

static int party_equal(
    const ninlil_party_t *left,
    const ninlil_party_t *right)
{
    return header_is_current(
            left->abi_version, left->struct_size, sizeof(*left))
        && header_is_current(
            right->abi_version, right->struct_size, sizeof(*right))
        && id_equal(&left->runtime_id, &right->runtime_id)
        && id_equal(
            &left->application_instance_id,
            &right->application_instance_id)
        && local_identity_equal(
            &left->local_identity, &right->local_identity);
}

static int target_is_valid(const ninlil_concrete_target_t *target)
{
    return header_is_current(
            target->abi_version, target->struct_size, sizeof(*target))
        && id_nonzero(&target->target_runtime_id)
        && id_nonzero(&target->target_application_instance_id)
        && target->reserved_zero == 0u
        && identity_presence_shape_is_valid(
            target->flags,
            &target->device_id,
            &target->installation_id,
            &target->site_domain_id,
            target->binding_epoch,
            target->membership_epoch);
}

static int target_equal(
    const ninlil_concrete_target_t *left,
    const ninlil_concrete_target_t *right)
{
    return header_is_current(
            left->abi_version, left->struct_size, sizeof(*left))
        && header_is_current(
            right->abi_version, right->struct_size, sizeof(*right))
        && id_equal(&left->target_runtime_id, &right->target_runtime_id)
        && id_equal(
            &left->target_application_instance_id,
            &right->target_application_instance_id)
        && id_equal(&left->device_id, &right->device_id)
        && id_equal(&left->installation_id, &right->installation_id)
        && id_equal(&left->site_domain_id, &right->site_domain_id)
        && left->binding_epoch == right->binding_epoch
        && left->membership_epoch == right->membership_epoch
        && left->flags == right->flags
        && left->reserved_zero == right->reserved_zero;
}

static int service_is_valid(const ninlil_service_identity_t *service)
{
    return header_is_current(
            service->abi_version, service->struct_size, sizeof(*service))
        && text_id_is_canonical(&service->namespace_id)
        && text_id_is_canonical(&service->service_id)
        && text_id_is_canonical(&service->schema_id)
        && service->descriptor_revision != 0u
        && digest_is_valid(&service->descriptor_digest)
        && service->schema_major != 0u
        && (ninlil_rt_v1_family_is_downlink(service->family)
            || ninlil_rt_v1_family_is_uplink(service->family));
}

static int service_equal(
    const ninlil_service_identity_t *left,
    const ninlil_service_identity_t *right)
{
    return header_is_current(
            left->abi_version, left->struct_size, sizeof(*left))
        && header_is_current(
            right->abi_version, right->struct_size, sizeof(*right))
        && text_id_equal(&left->namespace_id, &right->namespace_id)
        && text_id_equal(&left->service_id, &right->service_id)
        && text_id_equal(&left->schema_id, &right->schema_id)
        && left->descriptor_revision == right->descriptor_revision
        && digest_equal(
            &left->descriptor_digest, &right->descriptor_digest)
        && left->schema_major == right->schema_major
        && left->schema_minor == right->schema_minor
        && left->family == right->family;
}

static int evidence_stage_is_known_nonzero(ninlil_evidence_stage_t stage)
{
    return stage == NINLIL_EVIDENCE_RECEIVED
        || stage == NINLIL_EVIDENCE_DURABLY_RECORDED
        || stage == NINLIL_EVIDENCE_APPLIED
        || stage == NINLIL_EVIDENCE_VERIFIED;
}

static int empty_view_is_canonical(ninlil_bytes_view_t view)
{
    return view.data == NULL && view.length == 0u;
}

static int nonempty_or_empty_view_is_canonical(
    ninlil_bytes_view_t view,
    uint32_t maximum_length)
{
    return view.length <= maximum_length
        && ((view.length == 0u && view.data == NULL)
            || (view.length != 0u && view.data != NULL));
}

static int zero_evidence_time(const ninlil_time_sample_t *sample)
{
    return sample->abi_version == 0u
        && sample->struct_size == 0u
        && id_is_zero(&sample->clock_epoch_id)
        && sample->now_ms == 0u
        && sample->trust == 0u
        && sample->reserved_zero == 0u;
}

static int receipt_evidence_time_is_valid(
    const ninlil_time_sample_t *sample)
{
    return header_is_current(
            sample->abi_version, sample->struct_size, sizeof(*sample))
        && id_nonzero(&sample->clock_epoch_id)
        && (sample->trust == NINLIL_CLOCK_TRUSTED
            || sample->trust == NINLIL_CLOCK_UNCERTAIN)
        && sample->reserved_zero == 0u;
}

static int family_binding_is_valid(
    const ninlil_bearer_message_t *message)
{
    if (ninlil_rt_v1_family_is_downlink(message->service.family)) {
        return id_is_zero(&message->event_id)
            && message->generation != 0u
            && id_nonzero(&message->deadline_clock_epoch_id)
            && message->absolute_effect_deadline_ms != 0u
            && message->absolute_effect_deadline_ms < NINLIL_NO_DEADLINE;
    }
    if (ninlil_rt_v1_family_is_uplink(message->service.family)) {
        int identity_valid =
            message->service.family == NINLIL_FAMILY_EVENT_FACT
            ? id_nonzero(&message->event_id)
                && message->generation == 0u
            : id_is_zero(&message->event_id)
                && message->generation != 0u;

        return identity_valid
            && id_is_zero(&message->deadline_clock_epoch_id)
            && message->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
            && message->evidence_grace_ms == 0u;
    }
    return 0;
}

static int application_unused_fields_are_canonical(
    const ninlil_bearer_message_t *message)
{
    return message->flags == 0u
        && message->receipt_stage == NINLIL_EVIDENCE_NONE
        && message->disposition == NINLIL_DISPOSITION_NONE
        && message->effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE
        && message->retry_guidance == NINLIL_RETRY_NEVER
        && message->cancel_kind == 0u
        && message->retry_delay_ms == 0u
        && zero_evidence_time(&message->evidence_time)
        && empty_view_is_canonical(message->evidence);
}

static int target_matches_local_receiver(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_service_slot_t *receiver,
    const ninlil_concrete_target_t *target)
{
    int has_device;
    int has_installation;
    int has_site;

    if (!target_is_valid(target)
        || !id_equal(
            &target->target_runtime_id, &runtime->config.runtime_id)
        || !id_equal(
            &target->target_application_instance_id,
            &receiver->descriptor.local_application_instance_id)) {
        return 0;
    }
    has_device = (target->flags & NINLIL_TARGET_HAS_DEVICE) != 0u;
    has_installation =
        (target->flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u;
    has_site = (target->flags & NINLIL_TARGET_HAS_SITE) != 0u;
    return target_is_valid(target)
        && (!has_device
            || ((runtime->config.identity_flags
                    & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u
                && id_equal(
                    &target->device_id, &runtime->config.device_id)))
        && (!has_installation
            || ((runtime->config.identity_flags
                    & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u
                && id_equal(
                    &target->installation_id,
                    &runtime->config.installation_id)))
        && (!(has_device || has_installation)
            || target->binding_epoch == runtime->config.binding_epoch)
        && (!has_site
            || ((runtime->config.identity_flags
                    & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u
                && id_equal(
                    &target->site_domain_id,
                    &runtime->config.site_domain_id)
                && target->membership_epoch
                    == runtime->config.membership_epoch));
}

static int reverse_source_matches_target(
    const ninlil_party_t *source,
    const ninlil_concrete_target_t *original_target)
{
    return party_is_valid(source)
        && id_equal(&source->runtime_id, &original_target->target_runtime_id)
        && id_equal(
            &source->application_instance_id,
            &original_target->target_application_instance_id)
        && id_equal(
            &source->local_identity.device_id,
            &original_target->device_id)
        && id_equal(
            &source->local_identity.installation_id,
            &original_target->installation_id)
        && id_equal(
            &source->local_identity.site_domain_id,
            &original_target->site_domain_id)
        && source->local_identity.binding_epoch
            == original_target->binding_epoch
        && source->local_identity.membership_epoch
            == original_target->membership_epoch
        && source->local_identity.flags == original_target->flags;
}

static int reverse_target_matches_source(
    const ninlil_concrete_target_t *target,
    const ninlil_party_t *original_source)
{
    return target_is_valid(target)
        && id_equal(
            &target->target_runtime_id, &original_source->runtime_id)
        && id_equal(
            &target->target_application_instance_id,
            &original_source->application_instance_id)
        && id_equal(
            &target->device_id,
            &original_source->local_identity.device_id)
        && id_equal(
            &target->installation_id,
            &original_source->local_identity.installation_id)
        && id_equal(
            &target->site_domain_id,
            &original_source->local_identity.site_domain_id)
        && target->binding_epoch
            == original_source->local_identity.binding_epoch
        && target->membership_epoch
            == original_source->local_identity.membership_epoch
        && target->flags == original_source->local_identity.flags;
}

static int message_common_shape_is_valid(
    const ninlil_bearer_message_t *message)
{
    return message != NULL
        && header_is_current(
            message->abi_version, message->struct_size, sizeof(*message))
        && id_nonzero(&message->transaction_id)
        && id_nonzero(&message->attempt_id)
        && party_is_valid(&message->source)
        && target_is_valid(&message->target)
        && service_is_valid(&message->service)
        && digest_is_valid(&message->content_digest)
        && evidence_stage_is_known_nonzero(message->required_evidence)
        && family_binding_is_valid(message);
}

static int application_binding_matches_transaction(
    const ninlil_bearer_message_t *message,
    const ninlil_rt_transaction_slot_t *transaction)
{
    return transaction->origin_admission == 0u
        && party_equal(&message->source, &transaction->source)
        && service_equal(&message->service, &transaction->service)
        && digest_equal(
            &message->content_digest, &transaction->content_digest)
        && message->service.family == transaction->family
        && message->required_evidence == transaction->required_evidence
        && id_equal(&message->event_id, &transaction->event_id)
        && message->generation == transaction->generation
        && id_equal(
            &message->deadline_clock_epoch_id,
            &transaction->deadline_clock_epoch_id)
        && message->absolute_effect_deadline_ms
            == transaction->effect_deadline_ms
        && message->evidence_grace_ms
            == transaction->evidence_grace_ms
        && transaction->bound_target_count == 1u
        && target_equal(
            &message->target,
            &transaction->bound_targets[0].target)
        && message->payload.length == transaction->payload_length
        && (message->payload.length == 0u
            || memcmp(
                message->payload.data,
                transaction->owned_payload,
                message->payload.length) == 0);
}

static int application_message_is_valid(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_service_slot_t *receiver,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_bearer_message_t *message)
{
    uint32_t evidence_bit;

    if (!message_common_shape_is_valid(message)
        || message->kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || !application_unused_fields_are_canonical(message)
        || !nonempty_or_empty_view_is_canonical(
            message->payload,
            NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES)
        || message->payload.length > receiver->descriptor.logical_payload_limit
        || !service_equal(&message->service, &receiver->model_service.identity)
        || !target_matches_local_receiver(runtime, receiver, &message->target)) {
        return 0;
    }
    evidence_bit = NINLIL_EVIDENCE_MASK(message->required_evidence);
    if ((receiver->descriptor.supported_evidence_mask & evidence_bit) == 0u
        || (ninlil_rt_v1_family_is_downlink(message->service.family)
            && message->evidence_grace_ms
                > receiver->descriptor.maximum_evidence_grace_ms)) {
        return 0;
    }
    return transaction == NULL
        || application_binding_matches_transaction(message, transaction);
}

static int receipt_stage_supported(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    ninlil_evidence_stage_t stage)
{
    uint32_t index;
    uint32_t bit = NINLIL_EVIDENCE_MASK(stage);

    for (index = 0u; index < runtime->service_capacity; ++index) {
        const ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use != 0u
            && id_equal(
                &slot->descriptor.local_application_instance_id,
                &transaction->service_app_id)) {
            return (slot->descriptor.supported_evidence_mask & bit) != 0u;
        }
    }
    /*
     * A valid Receipt may arrive before a durable service is reattached
     * after restart. The canonical transaction still constrains the known
     * stage and required stage; attachment must not make ingress lossy.
     */
    return 1;
}

static int receipt_message_is_valid(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_bearer_message_t *message)
{
    if (transaction == NULL
        || transaction->origin_admission == 0u
        || transaction->bound_target_count != 1u
        || !message_common_shape_is_valid(message)
        || message->kind != NINLIL_BEARER_MESSAGE_RECEIPT
        || message->flags != 0u
        || !id_equal(&message->attempt_id, &transaction->attempt_id)
        || !reverse_source_matches_target(
            &message->source,
            &transaction->bound_targets[0].target)
        || !reverse_target_matches_source(
            &message->target, &transaction->source)
        || !service_equal(&message->service, &transaction->service)
        || !digest_equal(
            &message->content_digest, &transaction->content_digest)
        || !id_equal(&message->event_id, &transaction->event_id)
        || message->generation != transaction->generation
        || !id_equal(
            &message->deadline_clock_epoch_id,
            &transaction->deadline_clock_epoch_id)
        || message->absolute_effect_deadline_ms
            != transaction->effect_deadline_ms
        || message->evidence_grace_ms
            != transaction->evidence_grace_ms
        || message->required_evidence != transaction->required_evidence
        || !evidence_stage_is_known_nonzero(message->receipt_stage)
        || !receipt_stage_supported(
            runtime, transaction, message->receipt_stage)
        || message->disposition != NINLIL_DISPOSITION_NONE
        || message->effect_certainty != NINLIL_EFFECT_CERTAINTY_NONE
        || message->retry_guidance != NINLIL_RETRY_NEVER
        || message->cancel_kind != 0u
        || message->retry_delay_ms != 0u
        || !receipt_evidence_time_is_valid(&message->evidence_time)
        || !empty_view_is_canonical(message->payload)
        || !nonempty_or_empty_view_is_canonical(
            message->evidence, NINLIL_MAX_EVIDENCE_BYTES)) {
        return 0;
    }
    return family_binding_is_valid(message);
}

ninlil_status_t ninlil_rt_v1_bearer_snapshot_step_state(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t transition_budget,
    uint32_t *out_transitions_consumed,
    uint32_t *out_work_remaining)
{
    const ninlil_bearer_ops_t *bearer;
    ninlil_bearer_state_t state;
    ninlil_bearer_status_t status;

    if (runtime == NULL || clock_sample == NULL
        || out_transitions_consumed == NULL || out_work_remaining == NULL
        || runtime->platform == NULL
        || runtime->platform->bearer == NULL || runtime->bearer == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_transitions_consumed = 0u;
    *out_work_remaining = 0u;
    runtime->step_bearer_state_valid = 0u;
    runtime->step_bearer_available = 0u;
    runtime->step_bearer_availability_epoch = 0u;
    bearer = runtime->platform->bearer;
    if (bearer->state == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&state, 0, sizeof(state));
    status = bearer->state(bearer->user, runtime->bearer, &state);
    if (status == NINLIL_BEARER_WOULD_BLOCK
        || status == NINLIL_BEARER_UNAVAILABLE) {
        return bytes_are_zero(&state, sizeof(state))
            ? NINLIL_OK : NINLIL_E_DEGRADED;
    }
    if (status == NINLIL_BEARER_DENIED
        && bytes_are_zero(&state, sizeof(state))) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_APPLICATION_FAILED;
        return NINLIL_E_DEGRADED;
    }
    if (status != NINLIL_BEARER_OK
        || state.abi_version != NINLIL_ABI_VERSION
        || state.struct_size != sizeof(state)
        || state.availability_epoch == 0u
        || state.available > 1u
        || state.reserved_zero != 0u) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    if (runtime->bearer_state_present != 0u) {
        if (state.availability_epoch
            < runtime->bearer_availability_epoch) {
            return NINLIL_OK;
        }
        if (state.availability_epoch
            == runtime->bearer_availability_epoch) {
            if (state.available != runtime->bearer_available) {
                runtime->health = NINLIL_HEALTH_DEGRADED;
                runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
                return NINLIL_E_DEGRADED;
            }
            runtime->step_bearer_state_valid = 1u;
            runtime->step_bearer_available = state.available;
            runtime->step_bearer_availability_epoch =
                state.availability_epoch;
            return NINLIL_OK;
        }
    }
    if (transition_budget == 0u) {
        *out_work_remaining = 1u;
        return NINLIL_OK;
    }
    status = commit_bearer_state_marker(runtime, &state, clock_sample);
    if (status != NINLIL_OK) {
        return status;
    }

    *out_transitions_consumed = 1u;
    runtime->step_bearer_state_valid = 1u;
    runtime->step_bearer_available = state.available;
    runtime->step_bearer_availability_epoch = state.availability_epoch;
    return NINLIL_OK;
}

static ninlil_rt_service_slot_t *find_downlink_receiver(
    ninlil_runtime_t *runtime,
    ninlil_family_t family)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];
        if (slot->in_use == 0u || slot->attached == 0u) {
            continue;
        }
        if (slot->descriptor.family != family) {
            continue;
        }
        if (slot->model_service.local_side
            != NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER) {
            continue;
        }
        if (slot->callbacks.on_delivery == NULL) {
            continue;
        }
        return slot;
    }
    return NULL;
}

static ninlil_rt_service_slot_t *find_uplink_receiver(
    ninlil_runtime_t *runtime,
    ninlil_family_t family)
{
    return find_downlink_receiver(runtime, family);
}

static ninlil_rt_service_slot_t *find_uplink_sender(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];
        if (slot->in_use == 0u || slot->attached == 0u) {
            continue;
        }
        if (slot->descriptor.family != txn->family) {
            continue;
        }
        if (slot->model_service.local_side
            != NINLIL_MODEL_LOCAL_SUBMISSION_SENDER) {
            continue;
        }
        if (memcmp(
                slot->descriptor.local_application_instance_id.bytes,
                txn->service_app_id.bytes,
                sizeof(txn->service_app_id.bytes))
            != 0) {
            continue;
        }
        return slot;
    }
    return NULL;
}

static ninlil_status_t complete_receipt_for_txn(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    int required_reached;
    int becomes_terminal = 0;
    ninlil_outcome_t terminal_outcome = NINLIL_OUTCOME_NONE;
    ninlil_status_t status;
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;

    *candidate = *txn;
    candidate->evidence_recorded = 1u;
    candidate->receipt_pending = 0u;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    if (candidate->family == NINLIL_FAMILY_EVENT_FACT) {
        if (candidate->spool_revision == UINT64_MAX) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        candidate->spool_revision += 1u;
    }
    required_reached =
        candidate->latest_evidence >= candidate->required_evidence;
    if (required_reached) {
        if (!ninlil_rt_v1_family_is_downlink(candidate->family)) {
            terminal_outcome = NINLIL_OUTCOME_SATISFIED;
            candidate->reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
            becomes_terminal = 1;
        } else if (candidate->deadline_verdict == NINLIL_DEADLINE_MET) {
            terminal_outcome = NINLIL_OUTCOME_SATISFIED;
            candidate->reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
            becomes_terminal = 1;
        } else if (candidate->deadline_verdict
                   == NINLIL_DEADLINE_MISSED) {
            terminal_outcome = NINLIL_OUTCOME_EXPIRED;
            candidate->reason = NINLIL_REASON_REQUIRED_EVIDENCE_LATE;
            candidate->has_late_evidence = 1u;
            becomes_terminal = 1;
        }
    }
    if (becomes_terminal) {
        candidate->outcome = terminal_outcome;
        candidate->outcome_recorded = 1u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        candidate->terminal = 1u;
        candidate->pending_dispatch = 0u;
        candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    }
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_EV,
        NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    if (becomes_terminal) {
        if (runtime->nonterminal_transaction_count > 0u) {
            runtime->nonterminal_transaction_count -= 1u;
        }
        if (terminal_outcome == NINLIL_OUTCOME_EXPIRED) {
            saturating_increment_u64(&runtime->metrics.late_evidence);
        }
        note_satisfied_terminal(runtime, terminal_outcome, out_result);
    }
    return NINLIL_OK;
}

static ninlil_status_t send_application_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result);

static ninlil_status_t handle_incoming_downlink_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;

    if (runtime->config.role != NINLIL_ROLE_CONTROLLER) {
        return NINLIL_OK;
    }
    txn = ninlil_rt_find_transaction(runtime, &message->transaction_id);
    if (txn == NULL || !ninlil_rt_v1_family_is_downlink(txn->family)
        || !id_nonzero(&message->attempt_id)
        || memcmp(
            message->attempt_id.bytes,
            txn->attempt_id.bytes,
            sizeof(message->attempt_id.bytes)) != 0) {
        return NINLIL_OK;
    }
    return complete_receipt_for_txn(runtime, txn, out_result);
}

static ninlil_status_t handle_incoming_uplink_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;

    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return NINLIL_OK;
    }
    txn = ninlil_rt_find_transaction(runtime, &message->transaction_id);
    if (txn == NULL || !ninlil_rt_v1_family_is_uplink(txn->family)
        || !id_nonzero(&message->attempt_id)
        || memcmp(
            message->attempt_id.bytes,
            txn->attempt_id.bytes,
            sizeof(message->attempt_id.bytes)) != 0) {
        return NINLIL_OK;
    }
    return complete_receipt_for_txn(runtime, txn, out_result);
}

static ninlil_status_t handle_incoming_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    status = handle_incoming_downlink_receipt(runtime, message, out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    return handle_incoming_uplink_receipt(runtime, message, out_result);
}

static ninlil_status_t handle_incoming_downlink_application(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_family_t wire_family = NINLIL_FAMILY_DESIRED_STATE;
    ninlil_rt_service_slot_t *receiver;
    ninlil_rt_transaction_slot_t *txn;
    ninlil_delivery_token_t token;
    ninlil_delivery_view_t delivery_view;
    ninlil_application_result_t app_result;
    const ninlil_application_result_t *resolved_result = &app_result;
    ninlil_callback_action_t action;
    ninlil_status_t status;
    uint32_t may_invoke = 0u;
    uint32_t may_resolve = 0u;

    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return NINLIL_OK;
    }
    if (message->kind != NINLIL_BEARER_MESSAGE_APPLICATION) {
        return NINLIL_OK;
    }
    wire_family = message->service.family;
    if (!ninlil_rt_v1_family_is_downlink(wire_family)) {
        return NINLIL_OK;
    }
    receiver = find_downlink_receiver(runtime, wire_family);
    if (receiver == NULL) {
        return NINLIL_OK;
    }
    txn = ninlil_rt_find_transaction(runtime, &message->transaction_id);
    if (txn == NULL) {
        return NINLIL_E_INVALID_STATE;
    }
    if (txn->evidence_recorded != 0u) {
        /* Dedup: evidence already durable — skip callback, still ACK. */
    } else if (out_result->callbacks_invoked >= callback_budget) {
        out_result->work_remaining = 1u;
        return NINLIL_OK;
    } else {
        (void)memset(&token, 0, sizeof(token));
        set_header(&token.abi_version, &token.struct_size, sizeof(token));
        token.context_id = txn->transaction_id;
        token.clock_epoch_id = txn->token_clock_epoch_id;
        token.generation = txn->token_generation;
        token.expires_at_ms = txn->token_expires_at_ms;
        (void)memset(&delivery_view, 0, sizeof(delivery_view));
        set_header(
            &delivery_view.abi_version,
            &delivery_view.struct_size,
            sizeof(delivery_view));
        delivery_view.transaction_id = message->transaction_id;
        delivery_view.attempt_id = message->attempt_id;
        delivery_view.event_id = message->event_id;
        delivery_view.source = message->source;
        delivery_view.local_target = message->target;
        delivery_view.service = message->service;
        delivery_view.content_digest = message->content_digest;
        delivery_view.generation = message->generation;
        delivery_view.delivery_count = txn->delivery_count;
        delivery_view.required_evidence = message->required_evidence;
        delivery_view.deadline_clock_epoch_id =
            message->deadline_clock_epoch_id;
        delivery_view.absolute_effect_deadline_ms = message->absolute_effect_deadline_ms;
        delivery_view.evidence_grace_ms = message->evidence_grace_ms;
        delivery_view.payload = message->payload;
        (void)memset(&app_result, 0, sizeof(app_result));
        set_header(&app_result.abi_version, &app_result.struct_size, sizeof(app_result));
        status = ninlil_rt_v1_callback_preflight(
            runtime, txn, clock_sample, out_result, &may_invoke);
        if (status != NINLIL_OK || may_invoke == 0u) {
            return status;
        }
        if (wire_family == NINLIL_FAMILY_TRANSFER_RESERVED) {
            ninlil_rt_v1_family_workspace_t *ws =
                ninlil_rt_v1_family_workspace(runtime);
            if (!ninlil_rt_v1_family_bounded_transfer_begin(
                    ws,
                    &message->transaction_id,
                    (uint32_t)message->generation)) {
                return NINLIL_OK;
            }
            if (!ninlil_rt_v1_family_bounded_transfer_receive(
                    ws,
                    &message->transaction_id,
                    (uint32_t)message->payload.length,
                    1)) {
                (void)ninlil_rt_v1_family_bounded_transfer_abort(
                    ws, &message->transaction_id);
                return NINLIL_OK;
            }
            if (!ninlil_rt_v1_family_bounded_transfer_may_apply(
                    ws, &message->transaction_id)) {
                return NINLIL_OK;
            }
        } else if (wire_family == NINLIL_FAMILY_CONFIG_RESERVED) {
            uint8_t stage = NINLIL_RT_V1_CONFIG_STAGE_STAGED;
            if (message->payload.length > 0u && message->payload.data != NULL) {
                stage = message->payload.data[0];
            }
            if (!ninlil_rt_v1_family_config_revision_advance(
                    ninlil_rt_v1_family_workspace(runtime),
                    &receiver->descriptor.local_application_instance_id,
                    message->generation,
                    stage,
                    &app_result)) {
                if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                    return NINLIL_OK;
                }
                (void)ninlil_rt_v1_family_config_revision_rollback(
                    ninlil_rt_v1_family_workspace(runtime),
                    &receiver->descriptor.local_application_instance_id);
                return NINLIL_OK;
            }
        }
        ninlil_rt_v1_before_application_callback(runtime);
        out_result->callbacks_invoked += 1u;
        saturating_increment_u64(
            &runtime->metrics.application_callback_invocations);
        runtime->in_callback = 1u;
        action = receiver->callbacks.on_delivery(
            receiver->callbacks.user,
            &token,
            &delivery_view,
            &app_result);
        runtime->in_callback = 0u;
        if (action == NINLIL_CALLBACK_COMPLETE) {
            resolved_result =
                ninlil_rt_v1_capture_callback_complete_result(
                    runtime, &app_result);
        }
        ninlil_rt_v1_after_application_callback(runtime);
        if (action == NINLIL_CALLBACK_COMPLETE) {
            status = ninlil_rt_v1_callback_complete_postflight(
                runtime,
                txn,
                clock_sample,
                out_result,
                &may_resolve);
            if (status != NINLIL_OK || may_resolve == 0u) {
                return status;
            }
        }
        status = ninlil_rt_v1_resolve_callback(
            runtime,
            txn,
            action,
            resolved_result,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
        return NINLIL_OK;
    }

    return send_application_receipt(
        runtime, message, clock_sample, send_budget, out_result);
}

static ninlil_status_t send_application_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    const ninlil_tx_gate_ops_t *tx_gate;
    ninlil_tx_request_t tx_request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t receipt;
    ninlil_bearer_send_result_t send_result;
    ninlil_bearer_status_t send_status;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;
    ninlil_rt_send_observation_kind_t observation;
    uint32_t contract_fault = 0u;
    uint32_t logical_bytes;
    uint64_t minimum_epoch;
    ninlil_status_t status;
    ninlil_time_sample_t fresh_sample;
    ninlil_rt_tx_gate_observation_kind_t gate_observation;
    int became_terminal = 0;

    bearer = runtime->platform->bearer;
    tx_gate = runtime->platform->tx_gate;
    if (bearer == NULL || tx_gate == NULL || runtime->bearer == NULL) {
        return NINLIL_OK;
    }
    if (out_result->bearer_sends >= send_budget) {
        out_result->work_remaining = 1u;
        return NINLIL_OK;
    }
    transaction = ninlil_rt_find_transaction(
        runtime, &message->transaction_id);
    if (transaction == NULL
        || transaction->evidence_recorded == 0u
        || transaction->application_result_kind
            != NINLIL_APP_RESULT_POSITIVE_EVIDENCE
        || !evidence_stage_is_known_nonzero(
            transaction->latest_evidence)
        || transaction->application_evidence_length
            > NINLIL_MAX_EVIDENCE_BYTES) {
        return NINLIL_E_INVALID_STATE;
    }
    if (transaction->reverse_receipt_closed != 0u) {
        saturating_increment_u64(
            &runtime->metrics.duplicate_logical_delivery);
        return NINLIL_OK;
    }
    (void)memset(&receipt, 0, sizeof(receipt));
    set_header(&receipt.abi_version, &receipt.struct_size, sizeof(receipt));
    receipt.kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    receipt.transaction_id = message->transaction_id;
    receipt.attempt_id = message->attempt_id;
    receipt.event_id = message->event_id;
    receipt.service = message->service;
    receipt.content_digest = message->content_digest;
    receipt.generation = message->generation;
    receipt.deadline_clock_epoch_id = message->deadline_clock_epoch_id;
    receipt.absolute_effect_deadline_ms =
        message->absolute_effect_deadline_ms;
    receipt.evidence_grace_ms = message->evidence_grace_ms;
    receipt.required_evidence = message->required_evidence;
    receipt.receipt_stage = transaction->latest_evidence;
    if (transaction->application_evidence_length != 0u) {
        receipt.evidence.data = transaction->application_evidence;
        receipt.evidence.length =
            transaction->application_evidence_length;
    }
    receipt.source.runtime_id = message->target.target_runtime_id;
    receipt.source.application_instance_id =
        message->target.target_application_instance_id;
    receipt.source.local_identity.device_id = message->target.device_id;
    receipt.source.local_identity.installation_id =
        message->target.installation_id;
    receipt.source.local_identity.site_domain_id =
        message->target.site_domain_id;
    receipt.source.local_identity.binding_epoch =
        message->target.binding_epoch;
    receipt.source.local_identity.membership_epoch =
        message->target.membership_epoch;
    receipt.source.local_identity.flags = message->target.flags;
    set_header(
        &receipt.source.abi_version,
        &receipt.source.struct_size,
        sizeof(receipt.source));
    set_header(
        &receipt.source.local_identity.abi_version,
        &receipt.source.local_identity.struct_size,
        sizeof(receipt.source.local_identity));
    receipt.target.target_runtime_id = message->source.runtime_id;
    receipt.target.target_application_instance_id =
        message->source.application_instance_id;
    receipt.target.device_id = message->source.local_identity.device_id;
    receipt.target.installation_id =
        message->source.local_identity.installation_id;
    receipt.target.site_domain_id =
        message->source.local_identity.site_domain_id;
    receipt.target.binding_epoch =
        message->source.local_identity.binding_epoch;
    receipt.target.membership_epoch =
        message->source.local_identity.membership_epoch;
    receipt.target.flags = message->source.local_identity.flags;
    set_header(
        &receipt.target.abi_version,
        &receipt.target.struct_size,
        sizeof(receipt.target));
    if (!bearer_message_logical_bytes(&receipt, &logical_bytes)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    (void)memset(&tx_request, 0, sizeof(tx_request));
    set_header(&tx_request.abi_version, &tx_request.struct_size, sizeof(tx_request));
    tx_request.transaction_id = message->transaction_id;
    tx_request.attempt_id = message->attempt_id;
    tx_request.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    tx_request.logical_bytes = logical_bytes;
    tx_request.content_digest = message->content_digest;
    status = acquire_fresh_tx_permit(
        runtime,
        &tx_request,
        clock_sample,
        &permit,
        &fresh_sample,
        &gate_observation);
    if (status != NINLIL_OK) {
        return status;
    }
    if (gate_observation != NINLIL_RT_TX_GATE_ACQUIRED) {
        if (transaction == NULL) {
            return gate_observation == NINLIL_RT_TX_GATE_CONTRACT_FAULT
                ? NINLIL_E_DEGRADED : NINLIL_OK;
        }
        *candidate = *transaction;
        if (gate_observation == NINLIL_RT_TX_GATE_RETRY) {
            if (candidate->retry_backoff_ms == 0u) {
                candidate->retry_backoff_ms = 100u;
            }
            if (fresh_sample.now_ms
                > UINT64_MAX - candidate->retry_backoff_ms) {
                runtime->health = NINLIL_HEALTH_DEGRADED;
                runtime->degraded_reason =
                    NINLIL_REASON_COUNTER_EXHAUSTED;
                return NINLIL_E_DEGRADED;
            }
            candidate->next_retry_ms =
                fresh_sample.now_ms + candidate->retry_backoff_ms;
            candidate->next_retry_clock_epoch_id =
                fresh_sample.clock_epoch_id;
            status = ninlil_rt_v1_commit_transaction_snapshot(
                runtime,
                transaction,
                candidate,
                NINLIL_RT_V1_MARKER_RT,
                NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
        } else {
            candidate->reverse_receipt_closed = 1u;
            candidate->ingress_pending = 0u;
            candidate->pending_dispatch = 0u;
            candidate->next_retry_ms = 0u;
            (void)memset(
                &candidate->next_retry_clock_epoch_id,
                0,
                sizeof(candidate->next_retry_clock_epoch_id));
            if (candidate->evidence_recorded != 0u
                && candidate->latest_evidence
                    >= candidate->required_evidence) {
                became_terminal = candidate->terminal == 0u;
                candidate->terminal = 1u;
                candidate->outcome_recorded = 1u;
                candidate->outcome = NINLIL_OUTCOME_SATISFIED;
                candidate->reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
                candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
            }
            status = ninlil_rt_v1_commit_transaction_snapshot(
                runtime,
                transaction,
                candidate,
                NINLIL_RT_V1_MARKER_EV,
                NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT);
        }
        if (status != NINLIL_OK) {
            return status;
        }
        out_result->transitions_consumed += 1u;
        if (became_terminal) {
            if (runtime->nonterminal_transaction_count > 0u) {
                runtime->nonterminal_transaction_count -= 1u;
            }
            note_satisfied_terminal(
                runtime, NINLIL_OUTCOME_SATISFIED, out_result);
        }
        return gate_observation == NINLIL_RT_TX_GATE_CONTRACT_FAULT
            ? NINLIL_E_DEGRADED : NINLIL_OK;
    }
    receipt.evidence_time = fresh_sample;
    (void)memset(&send_result, 0, sizeof(send_result));
    send_status = bearer->send(
        bearer->user,
        runtime->bearer,
        &permit,
        &receipt,
        &send_result);
    note_bearer_send(runtime, send_status, out_result);
    if (transaction == NULL) {
        if (send_status == NINLIL_BEARER_WOULD_BLOCK
            || send_status == NINLIL_BEARER_UNAVAILABLE
            || send_status == NINLIL_BEARER_DENIED) {
            tx_gate->release_unused(tx_gate->user, &permit);
        }
        return NINLIL_OK;
    }

    minimum_epoch = runtime->step_bearer_availability_epoch;
    if (transaction->last_bearer_availability_epoch > minimum_epoch) {
        minimum_epoch = transaction->last_bearer_availability_epoch;
    }
    observation = classify_send_observation(
        send_status, &send_result, minimum_epoch, &contract_fault);
    *candidate = *transaction;
    if (observation == NINLIL_RT_SEND_OBS_WOULD_RETRY) {
        tx_gate->release_unused(tx_gate->user, &permit);
        if (candidate->retry_backoff_ms == 0u) {
            candidate->retry_backoff_ms = 100u;
        }
        if (fresh_sample.now_ms
            > UINT64_MAX - candidate->retry_backoff_ms) {
            return NINLIL_E_DEGRADED;
        }
        candidate->next_retry_ms =
            fresh_sample.now_ms + candidate->retry_backoff_ms;
        candidate->next_retry_clock_epoch_id =
            fresh_sample.clock_epoch_id;
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_RT,
            NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
    } else {
        if (observation == NINLIL_RT_SEND_OBS_DENIED) {
            tx_gate->release_unused(tx_gate->user, &permit);
        }
        candidate->reverse_receipt_closed = 1u;
        candidate->ingress_pending = 0u;
        candidate->pending_dispatch = 0u;
        candidate->next_retry_ms = 0u;
        (void)memset(
            &candidate->next_retry_clock_epoch_id,
            0,
            sizeof(candidate->next_retry_clock_epoch_id));
        candidate->last_bearer_availability_epoch =
            observed_availability_epoch(
                runtime, transaction, &send_result);
        if (candidate->evidence_recorded != 0u
            && candidate->latest_evidence >= candidate->required_evidence) {
            became_terminal = candidate->terminal == 0u;
            candidate->terminal = 1u;
            candidate->outcome_recorded = 1u;
            candidate->outcome = NINLIL_OUTCOME_SATISFIED;
            candidate->reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
            candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        }
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_EV,
            NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    if (became_terminal) {
        if (runtime->nonterminal_transaction_count > 0u) {
            runtime->nonterminal_transaction_count -= 1u;
        }
        note_satisfied_terminal(
            runtime, NINLIL_OUTCOME_SATISFIED, out_result);
    }
    if (contract_fault != 0u) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    return NINLIL_OK;
}

static ninlil_status_t handle_incoming_uplink_application(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_family_t wire_family;
    ninlil_rt_service_slot_t *receiver;
    ninlil_rt_transaction_slot_t *txn;
    ninlil_delivery_token_t token;
    ninlil_delivery_view_t delivery_view;
    ninlil_application_result_t app_result;
    const ninlil_application_result_t *resolved_result = &app_result;
    ninlil_callback_action_t action;
    ninlil_status_t status;
    uint32_t may_invoke = 0u;
    uint32_t may_resolve = 0u;

    if (runtime->config.role != NINLIL_ROLE_CONTROLLER
        || message->kind != NINLIL_BEARER_MESSAGE_APPLICATION) {
        return NINLIL_OK;
    }
    wire_family = message->service.family;
    if (!ninlil_rt_v1_family_is_uplink(wire_family)) {
        return NINLIL_OK;
    }
    receiver = find_uplink_receiver(runtime, wire_family);
    if (receiver == NULL) {
        return NINLIL_OK;
    }
    txn = ninlil_rt_find_transaction(runtime, &message->transaction_id);
    if (txn == NULL) {
        return NINLIL_E_INVALID_STATE;
    }
    if (txn->evidence_recorded != 0u) {
        return send_application_receipt(
            runtime, message, clock_sample, send_budget, out_result);
    }
    if (out_result->callbacks_invoked >= callback_budget) {
        out_result->work_remaining = 1u;
        return NINLIL_OK;
    }
    (void)memset(&token, 0, sizeof(token));
    set_header(&token.abi_version, &token.struct_size, sizeof(token));
    token.context_id = txn->transaction_id;
    token.clock_epoch_id = txn->token_clock_epoch_id;
    token.generation = txn->token_generation;
    token.expires_at_ms = txn->token_expires_at_ms;
    (void)memset(&delivery_view, 0, sizeof(delivery_view));
    set_header(
        &delivery_view.abi_version,
        &delivery_view.struct_size,
        sizeof(delivery_view));
    delivery_view.transaction_id = message->transaction_id;
    delivery_view.attempt_id = message->attempt_id;
    delivery_view.event_id = message->event_id;
    delivery_view.source = message->source;
    delivery_view.local_target = message->target;
    delivery_view.service = message->service;
    delivery_view.content_digest = message->content_digest;
    delivery_view.generation = message->generation;
    delivery_view.delivery_count = txn->delivery_count;
    delivery_view.required_evidence = message->required_evidence;
    delivery_view.deadline_clock_epoch_id =
        message->deadline_clock_epoch_id;
    delivery_view.absolute_effect_deadline_ms = message->absolute_effect_deadline_ms;
    delivery_view.evidence_grace_ms = message->evidence_grace_ms;
    delivery_view.payload = message->payload;
    (void)memset(&app_result, 0, sizeof(app_result));
    set_header(&app_result.abi_version, &app_result.struct_size, sizeof(app_result));
    status = ninlil_rt_v1_callback_preflight(
        runtime, txn, clock_sample, out_result, &may_invoke);
    if (status != NINLIL_OK || may_invoke == 0u) {
        return status;
    }
    if (wire_family == NINLIL_FAMILY_LATEST_STATE_RESERVED) {
        if (!ninlil_rt_v1_family_latest_state_apply(
                ninlil_rt_v1_family_workspace(runtime),
                &receiver->descriptor.local_application_instance_id,
                message->generation,
                &app_result)) {
            if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                return NINLIL_OK;
            }
            return NINLIL_E_INVALID_STATE;
        }
    } else if (wire_family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        if (!ninlil_rt_v1_family_measurement_batch_accept(
                ninlil_rt_v1_family_workspace(runtime),
                &receiver->descriptor.local_application_instance_id,
                message->generation,
                (uint32_t)message->payload.length,
                &app_result)) {
            if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                return NINLIL_OK;
            }
            return NINLIL_E_INVALID_STATE;
        }
    }
    ninlil_rt_v1_before_application_callback(runtime);
    out_result->callbacks_invoked += 1u;
    saturating_increment_u64(
        &runtime->metrics.application_callback_invocations);
    runtime->in_callback = 1u;
    action = receiver->callbacks.on_delivery(
        receiver->callbacks.user,
        &token,
        &delivery_view,
        &app_result);
    runtime->in_callback = 0u;
    if (action == NINLIL_CALLBACK_COMPLETE) {
        resolved_result = ninlil_rt_v1_capture_callback_complete_result(
            runtime, &app_result);
    }
    ninlil_rt_v1_after_application_callback(runtime);
    if (action == NINLIL_CALLBACK_COMPLETE) {
        status = ninlil_rt_v1_callback_complete_postflight(
            runtime,
            txn,
            clock_sample,
            out_result,
            &may_resolve);
        if (status != NINLIL_OK || may_resolve == 0u) {
            return status;
        }
    }
    status = ninlil_rt_v1_resolve_callback(
        runtime,
        txn,
        action,
        resolved_result,
        out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    return NINLIL_OK;
}

static ninlil_status_t handle_incoming_application(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    status = handle_incoming_downlink_application(
        runtime,
        message,
        clock_sample,
        callback_budget,
        send_budget,
        out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    return handle_incoming_uplink_application(
        runtime,
        message,
        clock_sample,
        callback_budget,
        send_budget,
        out_result);
}

ninlil_status_t ninlil_rt_v1_bearer_reduce_pending_ingress(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    uint32_t transition_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_bearer_message_t message;
    uint32_t required_transitions;

    if (runtime == NULL || transaction == NULL || clock_sample == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (transaction->receipt_pending != 0u) {
        if (transition_budget - out_result->transitions_consumed < 1u) {
            out_result->work_remaining = 1u;
            return NINLIL_OK;
        }
        (void)memset(&message, 0, sizeof(message));
        set_header(
            &message.abi_version, &message.struct_size, sizeof(message));
        message.kind = NINLIL_BEARER_MESSAGE_RECEIPT;
        message.transaction_id = transaction->transaction_id;
        message.attempt_id = transaction->attempt_id;
        message.content_digest = transaction->content_digest;
        return handle_incoming_receipt(runtime, &message, out_result);
    }
    if (transaction->ingress_pending == 0u) {
        return NINLIL_OK;
    }
    if (transaction->evidence_recorded == 0u
        && transaction->token_state == NINLIL_RT_TOKEN_NONE) {
        if (transition_budget - out_result->transitions_consumed < 1u) {
            out_result->work_remaining = 1u;
            return NINLIL_OK;
        }
        return ninlil_rt_v1_prepare_callback_start(
            runtime,
            transaction,
            clock_sample,
            transaction->application_completion_timeout_ms,
            out_result);
    }
    if (transaction->token_state == NINLIL_RT_TOKEN_RECOVERY_REQUIRED
        || transaction->token_state == NINLIL_RT_TOKEN_EXPIRED
        || transaction->deferred_wait != 0u) {
        return NINLIL_OK;
    }
    required_transitions = 1u;
    if (transition_budget - out_result->transitions_consumed
            < required_transitions
        || (transaction->evidence_recorded == 0u
            && out_result->callbacks_invoked >= callback_budget)
        || (transaction->evidence_recorded != 0u
            && transaction->reverse_receipt_closed == 0u
            && out_result->bearer_sends >= send_budget)) {
        out_result->work_remaining = 1u;
        return NINLIL_OK;
    }

    (void)memset(&message, 0, sizeof(message));
    set_header(&message.abi_version, &message.struct_size, sizeof(message));
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message.transaction_id = transaction->transaction_id;
    message.attempt_id = transaction->attempt_id;
    message.event_id = transaction->event_id;
    message.source = transaction->source;
    message.service = transaction->service;
    message.content_digest = transaction->content_digest;
    message.generation = transaction->generation;
    message.deadline_clock_epoch_id =
        transaction->deadline_clock_epoch_id;
    message.absolute_effect_deadline_ms =
        transaction->effect_deadline_ms;
    message.evidence_grace_ms = transaction->evidence_grace_ms;
    message.required_evidence = transaction->required_evidence;
    if (transaction->bound_target_count > 0u
        && transaction->bound_targets[0].in_use != 0u) {
        message.target = transaction->bound_targets[0].target;
    }
    if (transaction->payload_length != 0u) {
        message.payload.data = transaction->owned_payload;
        message.payload.length = transaction->payload_length;
    }
    return handle_incoming_application(
        runtime,
        &message,
        clock_sample,
        callback_budget,
        send_budget,
        out_result);
}

static ninlil_rt_service_slot_t *find_ingress_receiver(
    ninlil_runtime_t *runtime,
    ninlil_family_t family)
{
    return find_downlink_receiver(runtime, family);
}

static ninlil_status_t commit_received_message_copy(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;
    ninlil_rt_service_slot_t *receiver = NULL;
    uint32_t is_new = 0u;
    uint16_t marker = NINLIL_RT_V1_MARKER_DS;
    ninlil_v1_durable_operation_t operation =
        NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT;
    ninlil_status_t status;

    if (runtime->last_assigned_ordered_input_sequence == UINT64_MAX) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    transaction = ninlil_rt_find_transaction(
        runtime, &message->transaction_id);
    if (message->kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        receiver = find_ingress_receiver(runtime, message->service.family);
        if (receiver == NULL
            || !application_message_is_valid(
                runtime, receiver, transaction, message)) {
            return NINLIL_OK;
        }
        if (transaction != NULL
            && (transaction->terminal != 0u
                || transaction->event_discarded != 0u
                || transaction->ingress_pending != 0u
                || transaction->evidence_recorded != 0u)) {
            int new_attempt =
                !id_equal(&message->attempt_id, &transaction->attempt_id);

            saturating_increment_u64(
                &runtime->metrics.duplicate_logical_delivery);
            if (transaction->event_discarded == 0u
                && transaction->evidence_recorded != 0u
                && transaction->application_result_kind
                    == NINLIL_APP_RESULT_POSITIVE_EVIDENCE
                && evidence_stage_is_known_nonzero(
                    transaction->latest_evidence)
                && transaction->application_evidence_length
                    <= NINLIL_MAX_EVIDENCE_BYTES
                && (transaction->reverse_receipt_closed != 0u
                    || transaction->ingress_pending == 0u
                    || new_attempt)) {
                *candidate = *transaction;
                candidate->ordered_input_sequence =
                    runtime->last_assigned_ordered_input_sequence + 1u;
                candidate->attempt_id = message->attempt_id;
                candidate->reverse_receipt_closed = 0u;
                candidate->ingress_pending = 1u;
                candidate->next_retry_ms = 0u;
                (void)memset(
                    &candidate->next_retry_clock_epoch_id,
                    0,
                    sizeof(candidate->next_retry_clock_epoch_id));
                status = ninlil_rt_v1_commit_ordered_input_snapshot(
                    runtime,
                    transaction,
                    candidate,
                    NINLIL_RT_V1_MARKER_DS,
                    NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT);
                if (status != NINLIL_OK) {
                    return status;
                }
                runtime->pending_work = 1u;
                out_result->transitions_consumed += 1u;
            } else if (transaction->event_discarded == 0u
                && transaction->evidence_recorded == 0u
                && new_attempt) {
                *candidate = *transaction;
                candidate->ordered_input_sequence =
                    runtime->last_assigned_ordered_input_sequence + 1u;
                candidate->attempt_id = message->attempt_id;
                status = ninlil_rt_v1_commit_ordered_input_snapshot(
                    runtime,
                    transaction,
                    candidate,
                    NINLIL_RT_V1_MARKER_DS,
                    NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT);
                if (status != NINLIL_OK) {
                    return status;
                }
                runtime->pending_work = 1u;
                out_result->transitions_consumed += 1u;
            }
            return NINLIL_OK;
        }
    } else if (message->kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        if (!receipt_message_is_valid(runtime, transaction, message)) {
            return NINLIL_OK;
        }
        if (transaction->terminal != 0u) {
            saturating_increment_u64(
                &runtime->metrics.duplicate_logical_delivery);
            return NINLIL_OK;
        }
        if (transaction->evidence_recorded != 0u
            && message->receipt_stage <= transaction->latest_evidence) {
            saturating_increment_u64(
                &runtime->metrics.duplicate_logical_delivery);
            return NINLIL_OK;
        }
    } else {
        return NINLIL_OK;
    }

    if (transaction == NULL) {
        if (runtime->nonterminal_transaction_count
            >= runtime->config.limits.max_nonterminal_transactions) {
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        transaction = ninlil_rt_alloc_transaction(runtime);
        if (transaction == NULL) {
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        (void)memset(transaction, 0, sizeof(*transaction));
        transaction->transaction_id = message->transaction_id;
        is_new = 1u;
    }
    *candidate = *transaction;
    candidate->in_use = 1u;
    candidate->ordered_input_sequence =
        runtime->last_assigned_ordered_input_sequence + 1u;
    if (message->kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        marker = NINLIL_RT_V1_MARKER_EV;
        operation = NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT;
        candidate->receipt_pending = 1u;
        candidate->evidence_recorded = 1u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
        candidate->latest_evidence = message->receipt_stage;
        candidate->application_result_kind =
            NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
        candidate->application_disposition = NINLIL_DISPOSITION_NONE;
        candidate->application_result_reason = NINLIL_REASON_NONE;
        candidate->application_effect_certainty =
            NINLIL_EFFECT_CERTAINTY_NONE;
        candidate->application_retry_guidance = NINLIL_RETRY_NEVER;
        candidate->application_retry_delay_ms = 0u;
        candidate->application_evidence_length =
            (uint32_t)message->evidence.length;
        (void)memset(
            candidate->application_evidence,
            0,
            sizeof(candidate->application_evidence));
        if (message->evidence.length != 0u) {
            (void)memcpy(
                candidate->application_evidence,
                message->evidence.data,
                message->evidence.length);
        }
        if (ninlil_rt_v1_family_is_downlink(transaction->family)) {
            if (message->evidence_time.trust == NINLIL_CLOCK_TRUSTED
                && id_equal(
                    &message->evidence_time.clock_epoch_id,
                    &transaction->deadline_clock_epoch_id)) {
                candidate->deadline_verdict =
                    message->evidence_time.now_ms
                            <= transaction->effect_deadline_ms
                    ? NINLIL_DEADLINE_MET
                    : NINLIL_DEADLINE_MISSED;
            } else if (clock_sample->trust == NINLIL_CLOCK_TRUSTED
                && id_equal(
                           &clock_sample->clock_epoch_id,
                           &transaction->deadline_clock_epoch_id)
                && clock_sample->now_ms
                    <= transaction->effect_deadline_ms) {
                candidate->deadline_verdict =
                    NINLIL_DEADLINE_MET;
            } else {
                candidate->deadline_verdict =
                    NINLIL_DEADLINE_INDETERMINATE;
            }
        }
    } else {
        candidate->origin_admission = 0u;
        candidate->attempt_id = message->attempt_id;
        candidate->source = message->source;
        /*
         * The registered descriptor is the local authoritative service
         * identity. Compact bearers may omit descriptor metadata after route
         * selection; never persist that lossy wire projection as canonical
         * transaction state.
         */
        candidate->service = receiver->model_service.identity;
        candidate->service_app_id =
            receiver->descriptor.local_application_instance_id;
        candidate->event_id = message->event_id;
        candidate->content_digest = message->content_digest;
        candidate->family = message->service.family;
        candidate->required_evidence = message->required_evidence;
        candidate->generation = message->generation;
        candidate->effect_deadline_ms =
            message->absolute_effect_deadline_ms;
        candidate->evidence_grace_ms = message->evidence_grace_ms;
        candidate->deadline_clock_epoch_id =
            message->deadline_clock_epoch_id;
        candidate->admission_clock_epoch_id =
            clock_sample->clock_epoch_id;
        candidate->admitted_at_ms = clock_sample->now_ms;
        candidate->attempt_receipt_timeout_ms =
            receiver->descriptor.attempt_receipt_timeout_ms;
        candidate->retry_backoff_ms =
            receiver->descriptor.retry_backoff_ms;
        candidate->application_completion_timeout_ms =
            receiver->descriptor.application_completion_timeout_ms;
        candidate->payload_length = message->payload.length;
        if (message->payload.length != 0u) {
            (void)memcpy(
                candidate->owned_payload,
                message->payload.data,
                message->payload.length);
        }
        candidate->semantic_priority =
            ninlil_rt_v1_semantic_priority_for_family(candidate->family);
        candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
        candidate->pending_dispatch = 1u;
        candidate->ingress_pending = 1u;
        candidate->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
        candidate->retry_cycle_id =
            candidate->family == NINLIL_FAMILY_EVENT_FACT ? 1u : 0u;
        candidate->attempt_in_cycle = 0u;
        candidate->cumulative_attempts = 0u;
        candidate->spool_revision =
            candidate->family == NINLIL_FAMILY_EVENT_FACT ? 1u : 0u;
        candidate->bearer_route =
            (uint8_t)ninlil_rt_v1_default_bearer_route();
        candidate->bound_target_count = 1u;
        candidate->bound_targets[0].in_use = 1u;
        candidate->bound_targets[0].pending_dispatch = 1u;
        candidate->bound_targets[0].target = message->target;
        if (is_new != 0u) {
            if (runtime->transaction_sequence == UINT64_MAX) {
                (void)memset(transaction, 0, sizeof(*transaction));
                runtime->health = NINLIL_HEALTH_DEGRADED;
                runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
                return NINLIL_E_DEGRADED;
            }
            candidate->transaction_sequence =
                runtime->transaction_sequence + 1u;
        }
    }

    status = ninlil_rt_v1_commit_ordered_input_snapshot(
        runtime,
        transaction,
        candidate,
        marker,
        operation);
    if (status != NINLIL_OK) {
        if (is_new != 0u) {
            (void)memset(transaction, 0, sizeof(*transaction));
        }
        return status;
    }
    if (is_new != 0u) {
        runtime->transaction_sequence =
            transaction->transaction_sequence;
        runtime->transaction_count += 1u;
        runtime->nonterminal_transaction_count += 1u;
    }
    runtime->pending_work = 1u;
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_bearer_ingress_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *inout_ingress_budget,
    uint32_t callback_budget,
    uint32_t transition_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    ninlil_bearer_message_t message;
    ninlil_bearer_status_t status;
    ninlil_status_t result = NINLIL_OK;

    if (!ninlil_rt_v1_bearer_path_available(runtime)) {
        return NINLIL_OK;
    }
    (void)callback_budget;
    (void)send_budget;
    if (inout_ingress_budget == NULL || *inout_ingress_budget == 0u) {
        return NINLIL_OK;
    }
    bearer = runtime->platform->bearer;
    for (;;) {
        if (*inout_ingress_budget == 0u) {
            break;
        }
        if (out_result->transitions_consumed >= transition_budget) {
            out_result->work_remaining = 1u;
            break;
        }
        (void)memset(&message, 0, sizeof(message));
        status = bearer->receive_next(bearer->user, runtime->bearer, &message);
        if (status == NINLIL_BEARER_EMPTY) {
            break;
        }
        if (status != NINLIL_BEARER_OK) {
            break;
        }
        *inout_ingress_budget -= 1u;
        result = commit_received_message_copy(
            runtime, &message, clock_sample, out_result);
        bearer->release_received(bearer->user, runtime->bearer, &message);
        out_result->ingress_processed += 1u;
        if (result != NINLIL_OK) {
            return result;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_bearer_send_desired_application(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    ninlil_tx_request_t tx_request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t message;
    ninlil_bearer_send_result_t send_result;
    ninlil_bearer_status_t send_status;
    ninlil_id128_t attempt_id;
    ninlil_time_sample_t fresh_sample;
    ninlil_rt_tx_gate_observation_kind_t gate_observation;
    ninlil_status_t status;
    uint32_t logical_bytes;
    uint32_t index;
    ninlil_rt_service_slot_t *sender = NULL;

    if (!ninlil_rt_v1_bearer_path_available(runtime)
        || runtime->config.role != NINLIL_ROLE_CONTROLLER
        || !ninlil_rt_v1_family_is_downlink(txn->family)) {
        return NINLIL_OK;
    }
    if (txn->delivery_phase != NINLIL_RT_DELIVERY_NONE
        && txn->delivery_phase != NINLIL_RT_DELIVERY_QUEUED) {
        return NINLIL_OK;
    }
    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];
        if (slot->in_use != 0u && slot->attached != 0u
            && slot->descriptor.family == txn->family
            && slot->model_service.local_side
                == NINLIL_MODEL_LOCAL_SUBMISSION_SENDER
            && id_nonzero(&slot->descriptor.local_application_instance_id)
            && memcmp(
                slot->descriptor.local_application_instance_id.bytes,
                txn->service_app_id.bytes,
                sizeof(txn->service_app_id.bytes))
                == 0) {
            sender = slot;
            break;
        }
    }
    if (sender == NULL) {
        return NINLIL_OK;
    }
    bearer = runtime->platform->bearer;
    if (txn->attempt_prepared == 0u || !id_nonzero(&txn->attempt_id)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    attempt_id = txn->attempt_id;
    (void)memset(&message, 0, sizeof(message));
    set_header(&message.abi_version, &message.struct_size, sizeof(message));
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message.transaction_id = txn->transaction_id;
    message.attempt_id = attempt_id;
    message.event_id = txn->event_id;
    message.content_digest = txn->content_digest;
    message.generation = txn->generation;
    message.deadline_clock_epoch_id = txn->deadline_clock_epoch_id;
    message.absolute_effect_deadline_ms = txn->effect_deadline_ms;
    message.evidence_grace_ms = txn->evidence_grace_ms;
    message.required_evidence = txn->required_evidence;
    message.service = sender->model_service.identity;
    message.source = sender->model_service.source;
    if (txn->bound_target_count == 0u
        || txn->bound_targets[0].in_use == 0u) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    message.target = txn->bound_targets[0].target;
    if (txn->payload_length != 0u) {
        message.payload.data = txn->owned_payload;
        message.payload.length = txn->payload_length;
    }
    if (!bearer_message_logical_bytes(&message, &logical_bytes)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    (void)memset(&tx_request, 0, sizeof(tx_request));
    set_header(&tx_request.abi_version, &tx_request.struct_size, sizeof(tx_request));
    tx_request.transaction_id = txn->transaction_id;
    tx_request.attempt_id = attempt_id;
    tx_request.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    tx_request.logical_bytes = logical_bytes;
    tx_request.content_digest = txn->content_digest;
    status = acquire_fresh_tx_permit(
        runtime,
        &tx_request,
        clock_sample,
        &permit,
        &fresh_sample,
        &gate_observation);
    if (status != NINLIL_OK) {
        return status;
    }
    if (gate_observation != NINLIL_RT_TX_GATE_ACQUIRED) {
        return commit_application_gate_observation(
            runtime,
            txn,
            gate_observation,
            &fresh_sample,
            out_result);
    }
    (void)memset(&send_result, 0, sizeof(send_result));
    send_status = bearer->send(
        bearer->user,
        runtime->bearer,
        &permit,
        &message,
        &send_result);
    note_bearer_send(runtime, send_status, out_result);
    return commit_application_send_observation(
        runtime,
        txn,
        send_status,
        &send_result,
        &fresh_sample,
        &permit,
        out_result);
}

ninlil_status_t ninlil_rt_v1_bearer_send_uplink_application(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    ninlil_tx_request_t tx_request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t message;
    ninlil_bearer_send_result_t send_result;
    ninlil_bearer_status_t send_status;
    ninlil_id128_t attempt_id;
    ninlil_rt_service_slot_t *sender;
    ninlil_time_sample_t fresh_sample;
    ninlil_rt_tx_gate_observation_kind_t gate_observation;
    ninlil_status_t status;
    uint32_t logical_bytes;

    if (!ninlil_rt_v1_bearer_path_available(runtime)
        || runtime->config.role != NINLIL_ROLE_ENDPOINT
        || !ninlil_rt_v1_family_is_uplink(txn->family)) {
        return NINLIL_OK;
    }
    if (txn->delivery_phase != NINLIL_RT_DELIVERY_NONE
        && txn->delivery_phase != NINLIL_RT_DELIVERY_QUEUED) {
        return NINLIL_OK;
    }
    sender = find_uplink_sender(runtime, txn);
    if (sender == NULL) {
        return NINLIL_OK;
    }
    bearer = runtime->platform->bearer;
    if (txn->attempt_prepared == 0u || !id_nonzero(&txn->attempt_id)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    attempt_id = txn->attempt_id;
    (void)memset(&message, 0, sizeof(message));
    set_header(&message.abi_version, &message.struct_size, sizeof(message));
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message.transaction_id = txn->transaction_id;
    message.attempt_id = attempt_id;
    message.event_id = txn->event_id;
    message.content_digest = txn->content_digest;
    message.generation = txn->generation;
    message.deadline_clock_epoch_id = txn->deadline_clock_epoch_id;
    message.absolute_effect_deadline_ms = txn->effect_deadline_ms;
    message.evidence_grace_ms = txn->evidence_grace_ms;
    message.required_evidence = txn->required_evidence;
    message.service = sender->model_service.identity;
    message.source = sender->model_service.source;
    if (txn->bound_target_count == 0u
        || txn->bound_targets[0].in_use == 0u) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    message.target = txn->bound_targets[0].target;
    if (txn->payload_length != 0u) {
        message.payload.data = txn->owned_payload;
        message.payload.length = txn->payload_length;
    }
    if (!bearer_message_logical_bytes(&message, &logical_bytes)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_DEGRADED;
    }
    (void)memset(&tx_request, 0, sizeof(tx_request));
    set_header(&tx_request.abi_version, &tx_request.struct_size, sizeof(tx_request));
    tx_request.transaction_id = txn->transaction_id;
    tx_request.attempt_id = attempt_id;
    tx_request.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    tx_request.logical_bytes = logical_bytes;
    tx_request.content_digest = txn->content_digest;
    (void)memset(&permit, 0, sizeof(permit));
    status = acquire_fresh_tx_permit(
        runtime,
        &tx_request,
        clock_sample,
        &permit,
        &fresh_sample,
        &gate_observation);
    if (status != NINLIL_OK) {
        return status;
    }
    if (gate_observation != NINLIL_RT_TX_GATE_ACQUIRED) {
        return commit_application_gate_observation(
            runtime,
            txn,
            gate_observation,
            &fresh_sample,
            out_result);
    }
    (void)memset(&send_result, 0, sizeof(send_result));
    send_status = bearer->send(
        bearer->user,
        runtime->bearer,
        &permit,
        &message,
        &send_result);
    note_bearer_send(runtime, send_status, out_result);
    return commit_application_send_observation(
        runtime,
        txn,
        send_status,
        &send_result,
        &fresh_sample,
        &permit,
        out_result);
}
