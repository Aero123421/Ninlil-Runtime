/* SPDX-License-Identifier: Apache-2.0 */
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_bearer_wire.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_event_ledger_codec.h"
#include "runtime_v1_event_mgmt.h"
#include "runtime_v1_family_capability.h"
#include "runtime_v1_spine_durable.h"
#include "runtime_v1_target_resolver.h"
#include "runtime_v1_transaction_codec.h"

#include "domain_store_codec.h"
#include "runtime_store_codec.h"

#include <stdint.h>
#include <string.h>

#define NINLIL_RT_V1_MARKER_TX 0x5458u
#define NINLIL_RT_V1_MARKER_CN 0x434eu
#define NINLIL_RT_V1_MARKER_DS 0x4453u
#define NINLIL_RT_V1_MARKER_EV 0x4556u
#define NINLIL_RT_V1_MARKER_OC 0x4f43u
#define NINLIL_RT_V1_MARKER_ES 0x4553u
#define NINLIL_RT_V1_MARKER_RT 0x5254u
#define NINLIL_RT_V1_MARKER_AP 0x4150u

#define NINLIL_RT_V1_TXN_MARKER_BYTES 18u
#define NINLIL_RT_V1_MARKER_VALUE_BYTES 32u
#define NINLIL_RT_V1_MAX_SCHEDULABLE_TRANSACTIONS 256u
#define NINLIL_RT_V1_MAX_ACTIVE_TOKENS 32u
#define NINLIL_RT_V1_RESTART_EXPECTED_RESERVATION ((uint32_t)0x80000000u)

static ninlil_status_t handle_delivery_token_timeout(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result);

static int checked_evidence_close(
    const ninlil_rt_transaction_slot_t *txn,
    uint64_t *out_close_at_ms);

static int desired_effect_deadline_needs_reduction(
    const ninlil_rt_transaction_slot_t *txn);

static int desired_evidence_close_needs_reduction(
    const ninlil_rt_transaction_slot_t *txn);

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

static int id_equal(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int id_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < (uint32_t)sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int trusted_time_sample_is_valid(const ninlil_time_sample_t *sample)
{
    return sample != NULL
        && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == sizeof(*sample)
        && id_nonzero(&sample->clock_epoch_id)
        && sample->trust == NINLIL_CLOCK_TRUSTED
        && sample->reserved_zero == 0u;
}

static int uncertain_time_sample_is_valid(const ninlil_time_sample_t *sample)
{
    return sample != NULL
        && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == sizeof(*sample)
        && id_nonzero(&sample->clock_epoch_id)
        && sample->trust == NINLIL_CLOCK_UNCERTAIN
        && sample->reserved_zero == 0u;
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
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_STORAGE_IO;
        return NINLIL_E_STORAGE_CORRUPT;
    default:
        runtime->commit_unknown_fence = 1u;
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_STORAGE_IO;
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static void note_terminal_outcome(
    ninlil_runtime_t *runtime,
    ninlil_outcome_t outcome,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    out_result->transactions_terminalized += 1u;
    switch (outcome) {
    case NINLIL_OUTCOME_SATISFIED:
        saturating_increment_u64(
            &runtime->metrics.transactions_satisfied);
        break;
    case NINLIL_OUTCOME_EXPIRED:
        saturating_increment_u64(
            &runtime->metrics.transactions_expired);
        break;
    case NINLIL_OUTCOME_FAILED_DEFINITIVE:
        saturating_increment_u64(
            &runtime->metrics.transactions_failed_definitive);
        break;
    case NINLIL_OUTCOME_UNKNOWN:
        saturating_increment_u64(
            &runtime->metrics.transactions_outcome_unknown);
        break;
    default:
        break;
    }
}

static int event_cycle_summary_time(
    const ninlil_rt_transaction_slot_t *current,
    ninlil_id128_t *out_epoch,
    uint64_t *out_ended_at_ms)
{
    *out_epoch = current->send_observed_clock_epoch_id;
    *out_ended_at_ms = current->send_observed_at_ms;
    if (current->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && current->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
        && current->send_observation_closed != 0u) {
        if (current->attempt_receipt_timeout_ms == 0u
            || current->send_observed_at_ms
                > UINT64_MAX - current->attempt_receipt_timeout_ms) {
            return 0;
        }
        *out_ended_at_ms = current->send_observed_at_ms
            + current->attempt_receipt_timeout_ms;
    }
    return 1;
}

ninlil_status_t ninlil_rt_v1_begin_event_retry_cycle(
    const ninlil_rt_transaction_slot_t *current,
    ninlil_rt_transaction_slot_t *candidate)
{
    ninlil_rt_event_retry_summary_t completed;
    uint32_t index;

    if (current == NULL || candidate == NULL
        || current->family != NINLIL_FAMILY_EVENT_FACT
        || current->retry_cycle_id == 0u
        || current->retry_cycle_id == UINT64_MAX
        || current->attempt_in_cycle
            > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || current->attempt_in_cycle != current->attempt_count
        || current->retry_summary_count
            > NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS) {
        return NINLIL_E_INVALID_STATE;
    }
    *candidate = *current;
    (void)memset(&completed, 0, sizeof(completed));
    completed.retry_cycle_id = current->retry_cycle_id;
    completed.attempt_count = current->attempt_in_cycle;
    completed.delivery_possible_any =
        current->send_observation_closed != 0u
            || current->delivery_count != 0u;
    completed.last_reason = current->reason;
    if (!event_cycle_summary_time(
            current,
            &completed.last_observed_clock_epoch_id,
            &completed.last_observed_at_ms)) {
        return NINLIL_E_DEGRADED;
    }

    if (candidate->retry_summary_count
        == NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS) {
        const ninlil_rt_event_retry_summary_t *oldest =
            &candidate->retry_summaries[0];

        if (candidate->older_retry_cycle_count == UINT64_MAX
            || candidate->older_retry_attempt_count
                > UINT64_MAX - oldest->attempt_count) {
            return NINLIL_E_DEGRADED;
        }
        candidate->older_retry_cycle_count += 1u;
        candidate->older_retry_attempt_count += oldest->attempt_count;
        candidate->older_retry_delivery_possible_any =
            candidate->older_retry_delivery_possible_any != 0u
                || oldest->delivery_possible_any != 0u;
        candidate->older_retry_last_reason = oldest->last_reason;
        candidate->older_retry_last_observed_clock_epoch_id =
            oldest->last_observed_clock_epoch_id;
        candidate->older_retry_last_observed_at_ms =
            oldest->last_observed_at_ms;
        for (index = 1u;
             index < NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS;
             ++index) {
            candidate->retry_summaries[index - 1u] =
                candidate->retry_summaries[index];
        }
        candidate->retry_summaries[
            NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS - 1u] = completed;
    } else {
        candidate->retry_summaries[candidate->retry_summary_count] =
            completed;
        candidate->retry_summary_count += 1u;
    }
    candidate->retry_cycle_id += 1u;
    candidate->attempt_in_cycle = 0u;
    candidate->attempt_count = 0u;
    candidate->attempt_prepared = 0u;
    (void)memset(&candidate->attempt_id, 0, sizeof(candidate->attempt_id));
    (void)memset(
        candidate->attempt_ids, 0, sizeof(candidate->attempt_ids));
    candidate->delivery_count = 0u;
    candidate->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
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

    /*
     * Route by complete service identity (namespace + service + schema +
     * revision + digest + family + app instance). Family-only first-match
     * silently dropped messages for a second service in the same family.
     */
    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use == 0u || slot->attached == 0u) {
            continue;
        }
        if (!ninlil_rt_service_descriptor_matches_transaction(
                &slot->descriptor, txn)) {
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
        if (slot->callbacks.on_delivery != NULL) {
            return slot;
        }
    }
    return NULL;
}

static ninlil_rt_service_slot_t *find_attached_service_for_txn(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use != 0u
            && slot->attached != 0u
            && ninlil_rt_service_descriptor_matches_transaction(
                &slot->descriptor, txn)) {
            return slot;
        }
    }
    return NULL;
}

/*
 * Durable SERVICE registry identity for origin quota accounting.
 * Independent of callback attachment: Stage5 restore leaves slots
 * unattached until re-register, but quota still must track terminal
 * FULL groups that run on runtime_step before reattach.
 * Exact uniqueness: 0 matches / 2+ matches are CORRUPT.
 */
static ninlil_status_t find_origin_service_for_quota(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn,
    ninlil_rt_service_slot_t **out_slot)
{
    uint32_t index;
    uint32_t match_count = 0u;
    ninlil_rt_service_slot_t *found = NULL;

    if (out_slot != NULL) {
        *out_slot = NULL;
    }
    if (runtime == NULL || txn == NULL || out_slot == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use == 0u) {
            continue;
        }
        if (!ninlil_rt_service_descriptor_matches_transaction(
                &slot->descriptor, txn)) {
            continue;
        }
        match_count += 1u;
        if (match_count == 1u) {
            found = slot;
        }
    }
    if (match_count == 0u || match_count > 1u || found == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (found->quota_inflight == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_slot = found;
    return NINLIL_OK;
}

static ninlil_rt_service_slot_t *find_callback_receiver_for_txn(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use == 0u || slot->attached == 0u
            || slot->callbacks.on_delivery == NULL
            || !ninlil_rt_service_descriptor_matches_transaction(
                &slot->descriptor, txn)) {
            continue;
        }
        return slot;
    }
    return NULL;
}

static int is_transaction_snapshot_prefix(const uint8_t *key, uint32_t length)
{
    uint16_t prefix;

    if (key == NULL || length < 2u) {
        return 0;
    }
    prefix = (uint16_t)(((uint16_t)key[0] << 8) | (uint16_t)key[1]);
    return prefix == NINLIL_RT_V1_MARKER_CN
        || prefix == NINLIL_RT_V1_MARKER_DS
        || prefix == NINLIL_RT_V1_MARKER_EV
        || prefix == NINLIL_RT_V1_MARKER_OC
        || prefix == NINLIL_RT_V1_MARKER_ES
        || prefix == NINLIL_RT_V1_MARKER_RT
        || prefix == NINLIL_RT_V1_MARKER_AP;
}

ninlil_status_t ninlil_rt_v1_commit_delivery_marker(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation,
    uint8_t phase)
{
    ninlil_rt_transaction_slot_t *candidate;

    if (runtime == NULL || txn == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    if (phase == 1u) {
        candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    } else if (phase == 2u) {
        candidate->evidence_recorded = 1u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
        if (candidate->latest_evidence < candidate->required_evidence) {
            candidate->latest_evidence = candidate->required_evidence;
        }
    } else if (phase == 3u) {
        candidate->outcome_recorded = 1u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        candidate->terminal = 1u;
        candidate->pending_dispatch = 0u;
    }
    return ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        prefix,
        operation);
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

static ninlil_status_t commit_resource_ledger_only(
    ninlil_runtime_t *runtime,
    ninlil_v1_durable_operation_t operation,
    const ninlil_model_resource_ledger_t *candidate)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_status_t status;

    if (runtime == NULL || candidate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    status = map_storage_mutation_status(
        runtime,
        storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &storage_txn));
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_v1_stage_resource_ledger(
        runtime, storage_txn, operation, candidate);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, storage_txn);
        return status;
    }
    status = storage_txn_commit_full(runtime, storage_txn);
    if (status == NINLIL_OK) {
        runtime->resource_ledger = *candidate;
    }
    return status;
}

static ninlil_status_t commit_transaction_snapshot_internal(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_transaction_slot_t *candidate,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation,
    int ordered_input_commit,
    const char *before_commit_hook,
    const char *after_commit_hook)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t storage_txn = NULL;
    ninlil_rt_transaction_slot_t *committed;
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    uint32_t value_length = 0u;
    ninlil_status_t status;
    int releases_reservation;
    int commits_first_evidence;
    int ledger_changed;
    int closes_inflight;
    int admits_inbound_delivery;
    int starts_inbound_callback;
    int releases_inbound_deferred;
    int releases_inbound_delivery;
    int stage_origin_quota = 0;
    uint32_t evidenced_targets_before = 0u;
    uint32_t evidenced_targets_after = 0u;
    uint32_t target_index;
    ninlil_rt_service_slot_t *quota_slot = NULL;
    ninlil_rt_service_slot_t quota_snapshot;

    if (runtime == NULL || transaction == NULL || candidate == NULL
        || memcmp(
            transaction->transaction_id.bytes,
            candidate->transaction_id.bytes,
            sizeof(transaction->transaction_id.bytes)) != 0) {
        return NINLIL_E_DEGRADED;
    }
    if (ordered_input_commit != 0
        && (runtime->last_assigned_ordered_input_sequence == UINT64_MAX
            || candidate->ordered_input_sequence
                != runtime->last_assigned_ordered_input_sequence + 1u)) {
        return NINLIL_E_DEGRADED;
    }
    committed = &runtime->transaction_decode_scratch;
    *committed = *candidate;
    committed->record_revision =
        transaction->record_revision == UINT64_MAX
        ? UINT64_MAX : transaction->record_revision + 1u;
    for (target_index = 0u;
         target_index < transaction->bound_target_count;
         ++target_index) {
        if (transaction->bound_targets[target_index].in_use != 0u
            && transaction->bound_targets[target_index]
                    .evidence_recorded
                != 0u) {
            evidenced_targets_before += 1u;
        }
    }
    for (target_index = 0u;
         target_index < committed->bound_target_count;
         ++target_index) {
        if (committed->bound_targets[target_index].in_use != 0u
            && committed->bound_targets[target_index]
                    .evidence_recorded
                != 0u) {
            evidenced_targets_after += 1u;
        }
    }
    commits_first_evidence =
        transaction->origin_admission != 0u
        && evidenced_targets_after == evidenced_targets_before + 1u;
    releases_reservation =
        (committed->terminal != 0u || committed->event_discarded != 0u)
        && transaction->reservation_active != 0u;
    closes_inflight =
        transaction->terminal == 0u
        && transaction->event_discarded == 0u
        && (committed->terminal != 0u
            || committed->event_discarded != 0u);
    admits_inbound_delivery =
        transaction->in_use == 0u
        && committed->in_use != 0u
        && committed->origin_admission == 0u
        && committed->terminal == 0u
        && committed->event_discarded == 0u;
    starts_inbound_callback =
        transaction->origin_admission == 0u
        && transaction->token_state != NINLIL_RT_TOKEN_ACTIVE
        && committed->token_state == NINLIL_RT_TOKEN_ACTIVE;
    releases_inbound_deferred =
        transaction->origin_admission == 0u
        && transaction->token_state == NINLIL_RT_TOKEN_ACTIVE
        && committed->token_state != NINLIL_RT_TOKEN_ACTIVE;
    releases_inbound_delivery =
        transaction->origin_admission == 0u && closes_inflight;
    /*
     * Origin terminal / discard must durable-decrement SERVICE quota in the
     * same FULL storage transaction as the TX + resource ledger (Accepted
     * docs). Lookup uses durable service identity, not callback attachment
     * (restart may terminalize before reattach). Missing / duplicate slot
     * or zero inflight is CORRUPT before begin/commit — never silent skip,
     * never RAM-only fallback for origin.
     */
    if (closes_inflight != 0 && transaction->origin_admission != 0u) {
        status = find_origin_service_for_quota(
            runtime, committed, &quota_slot);
        if (status != NINLIL_OK) {
            return status;
        }
        quota_snapshot = *quota_slot;
        quota_snapshot.quota_inflight -= 1u;
        stage_origin_quota = 1;
    }
    ledger_changed = commits_first_evidence || releases_reservation
        || admits_inbound_delivery || starts_inbound_callback
        || releases_inbound_deferred || releases_inbound_delivery;
    if (ledger_changed) {
        runtime->resource_ledger_scratch = runtime->resource_ledger;
    }
    if (admits_inbound_delivery || starts_inbound_callback) {
        ninlil_model_capacity_batch_action_t capacity_action;

        if (admits_inbound_delivery) {
            status = ninlil_rt_v1_build_inbound_delivery_resource_ledger(
                &runtime->resource_ledger_scratch,
                &capacity_action,
                &runtime->resource_ledger_scratch);
        } else {
            status = ninlil_rt_v1_build_callback_start_resource_ledger(
                &runtime->resource_ledger_scratch,
                transaction->token_generation == 0u ? 1u : 0u,
                &capacity_action,
                &runtime->resource_ledger_scratch);
        }
        if (status != NINLIL_OK) {
            return status;
        }
        if (capacity_action
                == NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED) {
            status = commit_resource_ledger_only(
                runtime, operation, &runtime->resource_ledger_scratch);
            return status == NINLIL_OK
                ? NINLIL_E_CAPACITY_EXHAUSTED
                : status;
        }
        if (capacity_action
                == NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED) {
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        if (capacity_action
                == NINLIL_MODEL_CAPACITY_BATCH_COUNTER_EXHAUSTED) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        if (capacity_action
                != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    if (commits_first_evidence) {
        status = ninlil_rt_v1_build_evidence_committed_resource_ledger(
            &runtime->resource_ledger_scratch,
            &runtime->resource_ledger_scratch);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    if (releases_reservation) {
        status = ninlil_rt_v1_build_released_resource_ledger_from(
            &runtime->resource_ledger_scratch,
            committed,
            &runtime->resource_ledger_scratch);
        if (status != NINLIL_OK) {
            return status;
        }
        committed->reservation_active = 0u;
    }
    if (releases_inbound_deferred || releases_inbound_delivery) {
        status = ninlil_rt_v1_build_inbound_released_resource_ledger(
            &runtime->resource_ledger_scratch,
            releases_inbound_delivery ? 1u : 0u,
            releases_inbound_deferred ? 1u : 0u,
            &runtime->resource_ledger_scratch);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    status = ninlil_rt_v1_transaction_record_encode(
        committed,
        runtime->transaction_codec_bytes,
        (uint32_t)sizeof(runtime->transaction_codec_bytes),
        &value_length);
    if (status != NINLIL_OK) {
        return status;
    }
    storage = runtime->platform->storage;
    status = map_storage_mutation_status(
        runtime,
        storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &storage_txn));
    if (status != NINLIL_OK) {
        return status;
    }
    txn_marker_key(key, prefix, &transaction->transaction_id);
    status = durable_put(
        runtime,
        operation,
        storage_txn,
        (ninlil_bytes_view_t){key, sizeof(key)},
        (ninlil_bytes_view_t){
            runtime->transaction_codec_bytes, value_length});
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        (void)storage->rollback(storage->user, storage_txn);
        return status;
    }
    if (releases_reservation) {
        txn_marker_key(
            key,
            NINLIL_RT_V1_MARKER_RV,
            &transaction->transaction_id);
        status = map_storage_mutation_status(
            runtime,
            storage->erase(
                storage->user,
                storage_txn,
                (ninlil_bytes_view_t){key, sizeof(key)}));
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, storage_txn);
            return status;
        }
    }
    if (ledger_changed) {
        status = ninlil_rt_v1_stage_resource_ledger(
            runtime,
            storage_txn,
            operation,
            &runtime->resource_ledger_scratch);
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, storage_txn);
            return status;
        }
    }
    if (stage_origin_quota != 0) {
        status = ninlil_rt_v1_spine_service_ledger_stage(
            runtime, storage_txn, &quota_snapshot, operation);
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, storage_txn);
            return status;
        }
    }
    if (ordered_input_commit != 0) {
        status = stage_ordered_input_counter(
            runtime,
            storage_txn,
            operation,
            committed->ordered_input_sequence);
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, storage_txn);
            return status;
        }
    }
    if (before_commit_hook != NULL
        && runtime->private_transition_hook != NULL) {
        runtime->private_transition_hook(
            runtime->private_transition_hook_user, before_commit_hook);
    }
    status = storage_txn_commit_full(runtime, storage_txn);
    if (status == NINLIL_OK && after_commit_hook != NULL
        && runtime->private_transition_hook != NULL) {
        runtime->private_transition_hook(
            runtime->private_transition_hook_user, after_commit_hook);
    }
    if (status == NINLIL_OK) {
        if (ledger_changed) {
            runtime->resource_ledger = runtime->resource_ledger_scratch;
        }
        if (ordered_input_commit != 0) {
            runtime->last_assigned_ordered_input_sequence =
                committed->ordered_input_sequence;
            if (committed->ordered_input_sequence == UINT64_MAX) {
                runtime->health = NINLIL_HEALTH_DEGRADED;
                runtime->degraded_reason =
                    NINLIL_REASON_COUNTER_EXHAUSTED;
            }
        }
        *transaction = *committed;
        /*
         * RAM publication only after FULL commit OK. COMMIT_UNKNOWN /
         * storage failure leaves pre-commit inflight and durable row
         * dual-truth for restart recovery — no speculative RAM decrement.
         */
        if (stage_origin_quota != 0) {
            quota_slot->quota_inflight = quota_snapshot.quota_inflight;
        } else if (
            closes_inflight != 0 && committed->origin_admission == 0u) {
            ninlil_rt_service_slot_t *slot =
                find_attached_service_for_txn(runtime, committed);

            if (slot != NULL && slot->quota_inflight > 0u) {
                slot->quota_inflight -= 1u;
            }
        }
    }
    return status;
}

ninlil_status_t ninlil_rt_v1_commit_transaction_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_transaction_slot_t *candidate,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation)
{
    return commit_transaction_snapshot_internal(
        runtime,
        transaction,
        candidate,
        prefix,
        operation,
        0,
        NULL,
        NULL);
}

ninlil_status_t ninlil_rt_v1_commit_ordered_input_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_transaction_slot_t *candidate,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation)
{
    return commit_transaction_snapshot_internal(
        runtime,
        transaction,
        candidate,
        prefix,
        operation,
        1,
        NULL,
        NULL);
}

static int positive_application_result_shape_is_valid(
    const ninlil_application_result_t *result)
{
    return result != NULL
        && result->abi_version == NINLIL_ABI_VERSION
        && result->struct_size >= sizeof(*result)
        && result->kind == NINLIL_APP_RESULT_POSITIVE_EVIDENCE
        && result->evidence_stage > NINLIL_EVIDENCE_NONE
        && result->evidence_stage <= NINLIL_EVIDENCE_VERIFIED
        && result->disposition == NINLIL_DISPOSITION_NONE
        && result->reason == NINLIL_REASON_NONE
        && result->effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE
        && result->retry_guidance == NINLIL_RETRY_NEVER
        && result->retry_delay_ms == 0u
        && result->evidence.length <= NINLIL_MAX_EVIDENCE_BYTES
        && (result->evidence.length == 0u
            || result->evidence.data != NULL);
}

static int positive_application_result_is_valid(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_application_result_t *result)
{
    ninlil_rt_service_slot_t *receiver;

    receiver = runtime == NULL || transaction == NULL
        ? NULL
        : find_callback_receiver_for_txn(runtime, transaction);
    return transaction != NULL
        && receiver != NULL
        && positive_application_result_shape_is_valid(result)
        && result->evidence_stage >= transaction->required_evidence
        && (receiver->descriptor.supported_evidence_mask
            & NINLIL_EVIDENCE_MASK(result->evidence_stage)) != 0u;
}

static void set_recovery_result(
    ninlil_rt_transaction_slot_t *candidate,
    ninlil_reason_t reason)
{
    candidate->terminal = 0u;
    candidate->evidence_recorded = 0u;
    candidate->outcome_recorded = 0u;
    candidate->latest_evidence = NINLIL_EVIDENCE_NONE;
    candidate->outcome = NINLIL_OUTCOME_NONE;
    candidate->reason = reason;
    candidate->application_result_kind = 0u;
    candidate->application_disposition = NINLIL_DISPOSITION_NONE;
    candidate->application_result_reason = reason;
    candidate->application_effect_certainty =
        NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    candidate->application_retry_guidance =
        reason == NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT
        ? NINLIL_RETRY_SAME_AFTER
        : NINLIL_RETRY_OPERATOR_ACTION;
    candidate->application_retry_delay_ms = 0u;
    candidate->application_evidence_length = 0u;
    (void)memset(
        candidate->application_evidence,
        0,
        sizeof(candidate->application_evidence));
}

static void suppress_same_callback_replay(
    ninlil_rt_transaction_slot_t *transaction)
{
    /*
     * The durable truth is still ACTIVE after a definite failed commit, so
     * retain the token for destroy/restart recovery.  Close only the live
     * dispatch projections to prevent the already-entered callback from being
     * invoked again in this process.
     */
    transaction->deferred_wait = 0u;
    transaction->pending_dispatch = 0u;
    transaction->ingress_pending = 0u;
}

static ninlil_status_t commit_callback_recovery_fence(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    ninlil_rt_token_state_t token_state,
    ninlil_reason_t reason,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const char *before_hook;
    const char *after_hook;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_status_t status;

    if (runtime == NULL || transaction == NULL || out_result == NULL
        || transaction->token_state != NINLIL_RT_TOKEN_ACTIVE
        || (token_state != NINLIL_RT_TOKEN_EXPIRED
            && token_state != NINLIL_RT_TOKEN_RECOVERY_REQUIRED)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->token_state = token_state;
    candidate->deferred_wait = 0u;
    candidate->pending_dispatch = 0u;
    candidate->ingress_pending = 0u;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
    set_recovery_result(candidate, reason);
    if (runtime->config.role == NINLIL_ROLE_CONTROLLER) {
        before_hook = "controller.before_callback_recovery_commit";
        after_hook = "controller.after_callback_recovery_commit";
    } else {
        before_hook = "endpoint.before_callback_recovery_commit";
        after_hook = "endpoint.after_callback_recovery_commit";
    }
    status = commit_transaction_snapshot_internal(
        runtime,
        transaction,
        candidate,
        NINLIL_RT_V1_MARKER_EV,
        NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
        0,
        before_hook,
        after_hook);
    if (status != NINLIL_OK) {
        suppress_same_callback_replay(transaction);
        return status;
    }
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_callback_preflight(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *step_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_may_invoke)
{
    ninlil_time_sample_t fresh_sample;
    ninlil_port_status_t clock_status;
    ninlil_status_t status;

    if (runtime == NULL || transaction == NULL || step_sample == NULL
        || out_result == NULL || out_may_invoke == NULL
        || transaction->token_state != NINLIL_RT_TOKEN_ACTIVE
        || !trusted_time_sample_is_valid(step_sample)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_may_invoke = 0u;
    (void)memset(&fresh_sample, 0, sizeof(fresh_sample));
    clock_status = runtime->platform->clock->now(
        runtime->platform->clock->user, &fresh_sample);
    if (clock_status == NINLIL_PORT_TEMPORARY_FAILURE
        || (clock_status == NINLIL_PORT_OK
            && uncertain_time_sample_is_valid(&fresh_sample))) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (clock_status != NINLIL_PORT_OK
        || !trusted_time_sample_is_valid(&fresh_sample)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_DEGRADED;
    }
    status = ninlil_rt_accept_trusted_clock_sample(runtime, &fresh_sample);
    if (status != NINLIL_OK) {
        status = commit_callback_recovery_fence(
            runtime,
            transaction,
            NINLIL_RT_TOKEN_RECOVERY_REQUIRED,
            NINLIL_REASON_OUTCOME_UNKNOWN,
            out_result);
        return status != NINLIL_OK ? status : NINLIL_E_DEGRADED;
    }
    if (!id_equal(
            &fresh_sample.clock_epoch_id, &step_sample->clock_epoch_id)
        || !id_equal(
            &fresh_sample.clock_epoch_id,
            &transaction->token_clock_epoch_id)) {
        status = commit_callback_recovery_fence(
            runtime,
            transaction,
            NINLIL_RT_TOKEN_EXPIRED,
            NINLIL_REASON_OUTCOME_UNKNOWN,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (fresh_sample.now_ms < step_sample->now_ms
        || fresh_sample.now_ms < transaction->delivery_started_at_ms) {
        status = commit_callback_recovery_fence(
            runtime,
            transaction,
            NINLIL_RT_TOKEN_RECOVERY_REQUIRED,
            NINLIL_REASON_OUTCOME_UNKNOWN,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_DEGRADED;
    }
    if (fresh_sample.now_ms > transaction->token_expires_at_ms) {
        return handle_delivery_token_timeout(
            runtime, transaction, &fresh_sample, out_result);
    }
    *out_may_invoke = 1u;
    return NINLIL_OK;
}

const ninlil_application_result_t *ninlil_rt_v1_capture_callback_complete_result(
    ninlil_runtime_t *runtime,
    const ninlil_application_result_t *result)
{
    if (runtime == NULL) {
        return NULL;
    }
    (void)memset(
        &runtime->callback_result_scratch,
        0,
        sizeof(runtime->callback_result_scratch));
    (void)memset(
        runtime->callback_evidence_scratch,
        0,
        sizeof(runtime->callback_evidence_scratch));
    if (result == NULL) {
        return &runtime->callback_result_scratch;
    }
    runtime->callback_result_scratch = *result;
    if (result->evidence.length <= sizeof(runtime->callback_evidence_scratch)
        && (result->evidence.length == 0u
            || result->evidence.data != NULL)) {
        if (result->evidence.length != 0u) {
            (void)memcpy(
                runtime->callback_evidence_scratch,
                result->evidence.data,
                result->evidence.length);
        }
        runtime->callback_result_scratch.evidence.data =
            result->evidence.length == 0u
            ? NULL : runtime->callback_evidence_scratch;
    } else {
        runtime->callback_result_scratch.evidence.data = NULL;
    }
    return &runtime->callback_result_scratch;
}

static void dispatch_application_callback_hook(
    ninlil_runtime_t *runtime,
    const char *controller_name,
    const char *endpoint_name)
{
    const char *name;

    if (runtime == NULL || runtime->private_transition_hook == NULL) {
        return;
    }
    name = runtime->config.role == NINLIL_ROLE_CONTROLLER
        ? controller_name : endpoint_name;
    runtime->private_transition_hook(
        runtime->private_transition_hook_user, name);
}

void ninlil_rt_v1_before_application_callback(
    ninlil_runtime_t *runtime)
{
    dispatch_application_callback_hook(
        runtime,
        "controller.before_application_callback",
        "endpoint.before_application_callback");
}

void ninlil_rt_v1_after_application_callback(
    ninlil_runtime_t *runtime)
{
    dispatch_application_callback_hook(
        runtime,
        "controller.after_application_callback",
        "endpoint.after_application_callback");
}

ninlil_status_t ninlil_rt_v1_callback_complete_postflight(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *step_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_may_resolve)
{
    ninlil_time_sample_t fresh_sample;
    ninlil_port_status_t clock_status;
    ninlil_status_t status;
    ninlil_status_t result_status;
    ninlil_rt_token_state_t fence_state;

    if (runtime == NULL || transaction == NULL || step_sample == NULL
        || out_result == NULL || out_may_resolve == NULL
        || transaction->token_state != NINLIL_RT_TOKEN_ACTIVE
        || !trusted_time_sample_is_valid(step_sample)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_may_resolve = 0u;
    (void)memset(&fresh_sample, 0, sizeof(fresh_sample));
    clock_status = runtime->platform->clock->now(
        runtime->platform->clock->user, &fresh_sample);
    if (clock_status == NINLIL_PORT_TEMPORARY_FAILURE
        || (clock_status == NINLIL_PORT_OK
            && uncertain_time_sample_is_valid(&fresh_sample))) {
        result_status = NINLIL_E_CLOCK_UNCERTAIN;
        fence_state = NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
    } else if (clock_status != NINLIL_PORT_OK
        || !trusted_time_sample_is_valid(&fresh_sample)) {
        result_status = NINLIL_E_DEGRADED;
        fence_state = NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
    } else if (ninlil_rt_accept_trusted_clock_sample(
            runtime, &fresh_sample) != NINLIL_OK) {
        result_status = NINLIL_E_DEGRADED;
        fence_state = NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
    } else if (!id_equal(
            &fresh_sample.clock_epoch_id, &step_sample->clock_epoch_id)
        || !id_equal(
            &fresh_sample.clock_epoch_id,
            &transaction->token_clock_epoch_id)) {
        result_status = NINLIL_E_CLOCK_UNCERTAIN;
        fence_state = NINLIL_RT_TOKEN_EXPIRED;
    } else if (fresh_sample.now_ms < step_sample->now_ms
        || fresh_sample.now_ms < transaction->delivery_started_at_ms) {
        result_status = NINLIL_E_DEGRADED;
        fence_state = NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
    } else if (fresh_sample.now_ms > transaction->token_expires_at_ms) {
        return handle_delivery_token_timeout(
            runtime, transaction, &fresh_sample, out_result);
    } else {
        *out_may_resolve = 1u;
        return NINLIL_OK;
    }

    status = commit_callback_recovery_fence(
        runtime,
        transaction,
        fence_state,
        NINLIL_REASON_OUTCOME_UNKNOWN,
        out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    runtime->health = NINLIL_HEALTH_DEGRADED;
    runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
    return result_status;
}

ninlil_status_t ninlil_rt_v1_prepare_callback_start(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample,
    uint64_t application_completion_timeout_ms,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_status_t status;

    if (runtime == NULL || transaction == NULL || clock_sample == NULL
        || out_result == NULL
        || !trusted_time_sample_is_valid(clock_sample)
        || application_completion_timeout_ms == 0u
        || application_completion_timeout_ms
            > NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (transaction->token_state == NINLIL_RT_TOKEN_ACTIVE) {
        return NINLIL_OK;
    }
    if (transaction->delivery_phase == NINLIL_RT_DELIVERY_STARTED
        || transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED
        || transaction->delivery_count == UINT64_MAX
        || clock_sample->now_ms
            > UINT64_MAX - application_completion_timeout_ms) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }

    candidate = &runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->delivery_count += 1u;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    candidate->token_state = NINLIL_RT_TOKEN_ACTIVE;
    candidate->deferred_wait = 0u;
    candidate->token_clock_epoch_id = clock_sample->clock_epoch_id;
    candidate->token_generation = candidate->delivery_count;
    candidate->delivery_started_at_ms = clock_sample->now_ms;
    candidate->token_expires_at_ms =
        clock_sample->now_ms + application_completion_timeout_ms;
    candidate->application_completion_timeout_ms =
        application_completion_timeout_ms;
    candidate->application_result_kind = 0u;
    candidate->application_disposition = NINLIL_DISPOSITION_NONE;
    candidate->application_result_reason = NINLIL_REASON_NONE;
    candidate->application_effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NONE;
    candidate->application_retry_guidance = NINLIL_RETRY_NEVER;
    candidate->application_retry_delay_ms = 0u;
    candidate->application_evidence_length = 0u;
    (void)memset(
        candidate->application_evidence,
        0,
        sizeof(candidate->application_evidence));
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
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_resolve_callback(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    ninlil_callback_action_t action,
    const ninlil_application_result_t *result,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_status_t status;
    int valid_positive;

    if (runtime == NULL || transaction == NULL || out_result == NULL
        || transaction->token_state != NINLIL_RT_TOKEN_ACTIVE) {
        return NINLIL_E_INVALID_STATE;
    }
    if (action == NINLIL_CALLBACK_DEFER) {
        transaction->deferred_wait = 1u;
        transaction->pending_dispatch = 0u;
        transaction->ingress_pending = 0u;
        return NINLIL_OK;
    }

    valid_positive = action == NINLIL_CALLBACK_COMPLETE
        && positive_application_result_is_valid(
            runtime, transaction, result);
    if (!valid_positive) {
        ninlil_reason_t recovery_reason =
            action == NINLIL_CALLBACK_FATAL
            ? NINLIL_REASON_APPLICATION_FAILED
            : NINLIL_REASON_CALLBACK_CONTRACT;

        status = commit_callback_recovery_fence(
            runtime,
            transaction,
            NINLIL_RT_TOKEN_RECOVERY_REQUIRED,
            recovery_reason,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = recovery_reason;
        return NINLIL_OK;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->deferred_wait = 0u;
    candidate->pending_dispatch = 0u;
    candidate->token_state = NINLIL_RT_TOKEN_CONSUMED;
    candidate->evidence_recorded = 1u;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    candidate->latest_evidence = result->evidence_stage;
    candidate->application_result_kind = result->kind;
    candidate->application_disposition = result->disposition;
    candidate->application_result_reason = result->reason;
    candidate->application_effect_certainty =
        result->effect_certainty;
    candidate->application_retry_guidance =
        result->retry_guidance;
    candidate->application_retry_delay_ms =
        result->retry_delay_ms;
    candidate->application_evidence_length =
        (uint32_t)result->evidence.length;
    (void)memset(
        candidate->application_evidence,
        0,
        sizeof(candidate->application_evidence));
    if (result->evidence.length != 0u) {
        (void)memcpy(
            candidate->application_evidence,
            result->evidence.data,
            result->evidence.length);
    }
    if (candidate->origin_admission == 0u) {
        candidate->ingress_pending = 1u;
    } else {
        candidate->pending_dispatch = 1u;
    }
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        transaction,
        candidate,
        NINLIL_RT_V1_MARKER_EV,
        NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT);
    if (status != NINLIL_OK) {
        suppress_same_callback_replay(transaction);
        return status;
    }
    out_result->transitions_consumed += 1u;
    if (transaction->ingress_pending != 0u
        || transaction->pending_dispatch != 0u) {
        runtime->pending_work = 1u;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_complete_deferred_delivery(
    ninlil_runtime_t *runtime,
    const ninlil_delivery_token_t *token,
    const ninlil_application_result_t *result)
{
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_rt_v1_step_delivery_result_t completion;
    ninlil_time_sample_t sample;
    ninlil_port_status_t clock_status;
    ninlil_status_t status;

    if (!positive_application_result_shape_is_valid(result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    transaction =
        ninlil_rt_find_transaction(runtime, &token->context_id);
    if (transaction == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (transaction->token_state != NINLIL_RT_TOKEN_ACTIVE
        || transaction->deferred_wait == 0u
        || transaction->token_generation != token->generation
        || memcmp(
            transaction->token_clock_epoch_id.bytes,
            token->clock_epoch_id.bytes,
            sizeof(token->clock_epoch_id.bytes)) != 0
        || transaction->token_expires_at_ms != token->expires_at_ms) {
        return NINLIL_E_INVALID_STATE;
    }
    if (!positive_application_result_is_valid(
            runtime, transaction, result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    clock_status = runtime->platform->clock->now(
        runtime->platform->clock->user, &sample);
    if (clock_status == NINLIL_PORT_TEMPORARY_FAILURE
        || (clock_status == NINLIL_PORT_OK
            && sample.trust == NINLIL_CLOCK_UNCERTAIN)) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (clock_status != NINLIL_PORT_OK
        || !trusted_time_sample_is_valid(&sample)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_DEGRADED;
    }
    status = ninlil_rt_accept_trusted_clock_sample(runtime, &sample);
    if (status != NINLIL_OK) {
        return status;
    }
    if (memcmp(
            sample.clock_epoch_id.bytes,
            token->clock_epoch_id.bytes,
            sizeof(token->clock_epoch_id.bytes)) != 0) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        runtime->pending_work = 1u;
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (sample.now_ms < transaction->delivery_started_at_ms) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_DEGRADED;
    }
    if (sample.now_ms > token->expires_at_ms) {
        candidate = &runtime->transaction_scratch;
        *candidate = *transaction;
        candidate->token_state = NINLIL_RT_TOKEN_EXPIRED;
        candidate->deferred_wait = 0u;
        candidate->pending_dispatch = 0u;
        candidate->ingress_pending = 0u;
        candidate->delivery_phase =
            NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
        set_recovery_result(
            candidate,
            NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT);
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            transaction,
            candidate,
            NINLIL_RT_V1_MARKER_EV,
            NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT);
        if (status != NINLIL_OK) {
            return status;
        }
        saturating_increment_u64(
            &runtime->metrics.delivery_token_timeouts);
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason =
            NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT;
        return NINLIL_E_INVALID_STATE;
    }
    (void)memset(&completion, 0, sizeof(completion));
    return ninlil_rt_v1_resolve_callback(
        runtime,
        transaction,
        NINLIL_CALLBACK_COMPLETE,
        result,
        &completion);
}

static int destroy_token_less(
    const ninlil_rt_transaction_slot_t *left,
    const ninlil_rt_transaction_slot_t *right)
{
    int by_context = memcmp(
        left->transaction_id.bytes,
        right->transaction_id.bytes,
        sizeof(left->transaction_id.bytes));

    if (by_context != 0) {
        return by_context < 0;
    }
    return left->token_generation < right->token_generation;
}

ninlil_status_t ninlil_rt_v1_collect_destroy_token_order(
    const ninlil_runtime_t *runtime,
    uint32_t *out_order,
    uint32_t order_capacity,
    uint32_t *out_count)
{
    uint32_t index;
    uint32_t count = 0u;

    if (runtime == NULL || out_count == NULL
        || (order_capacity != 0u && out_order == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_count = 0u;
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        uint32_t insert_at;
        uint32_t move;

        if (runtime->transactions[index].in_use == 0u
            || runtime->transactions[index].token_state
                != NINLIL_RT_TOKEN_ACTIVE) {
            continue;
        }
        if (count == order_capacity) {
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        insert_at = count;
        while (insert_at > 0u
            && destroy_token_less(
                &runtime->transactions[index],
                &runtime->transactions[out_order[insert_at - 1u]])) {
            insert_at -= 1u;
        }
        for (move = count; move > insert_at; --move) {
            out_order[move] = out_order[move - 1u];
        }
        out_order[insert_at] = index;
        count += 1u;
    }
    *out_count = count;
    return NINLIL_OK;
}

static void make_destroy_recovery_candidate(
    const ninlil_rt_transaction_slot_t *transaction,
    ninlil_rt_transaction_slot_t *candidate)
{
    *candidate = *transaction;
    candidate->record_revision = transaction->record_revision + 1u;
    candidate->token_state = NINLIL_RT_TOKEN_EXPIRED;
    candidate->deferred_wait = 0u;
    candidate->pending_dispatch = 0u;
    candidate->ingress_pending = 0u;
    candidate->delivery_phase =
        NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
    set_recovery_result(candidate, NINLIL_REASON_OUTCOME_UNKNOWN);
}

static ninlil_status_t map_destroy_group_status(ninlil_status_t status)
{
    /*
     * Once create has accepted the namespace schema, an unsupported schema
     * or writer-shape result inside the closed destroy operation is durable
     * corruption, not a feature-negotiation outcome.
     */
    return status == NINLIL_E_UNSUPPORTED
        ? NINLIL_E_STORAGE_CORRUPT
        : status;
}

ninlil_status_t ninlil_rt_v1_fence_active_tokens_for_destroy(
    ninlil_runtime_t *runtime)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t storage_txn = NULL;
    uint32_t order[NINLIL_RT_V1_MAX_ACTIVE_TOKENS];
    uint32_t active_count = 0u;
    uint32_t ordinal;
    uint8_t key[NINLIL_RT_V1_TXN_MARKER_BYTES];
    ninlil_status_t status;

    if (runtime == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_v1_collect_destroy_token_order(
        runtime,
        order,
        (uint32_t)(sizeof(order) / sizeof(order[0])),
        &active_count);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_CAPACITY_EXHAUSTED
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }
    if (active_count == 0u) {
        return NINLIL_OK;
    }
    for (ordinal = 0u; ordinal < active_count; ++ordinal) {
        const ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[order[ordinal]];

        if (transaction->record_revision == UINT64_MAX) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    status = ninlil_rt_v1_build_inbound_released_resource_ledger(
        &runtime->resource_ledger,
        0u,
        active_count,
        &runtime->resource_ledger_scratch);
    if (status != NINLIL_OK) {
        return status == NINLIL_E_INVALID_STATE
            ? NINLIL_E_STORAGE_CORRUPT
            : status;
    }

    storage = runtime->platform->storage;
    status = map_storage_mutation_status(
        runtime,
        storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &storage_txn));
    if (status != NINLIL_OK) {
        return map_destroy_group_status(status);
    }
    for (ordinal = 0u; ordinal < active_count; ++ordinal) {
        ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[order[ordinal]];
        uint32_t value_length = 0u;

        make_destroy_recovery_candidate(
            transaction, &runtime->transaction_scratch);
        status = ninlil_rt_v1_transaction_record_encode(
            &runtime->transaction_scratch,
            runtime->transaction_codec_bytes,
            (uint32_t)sizeof(runtime->transaction_codec_bytes),
            &value_length);
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, storage_txn);
            return map_destroy_group_status(status);
        }
        txn_marker_key(
            key, NINLIL_RT_V1_MARKER_EV, &transaction->transaction_id);
        status = durable_put(
            runtime,
            NINLIL_V1_DURABLE_OP_DESTROY_RECOVERY_COMMIT,
            storage_txn,
            (ninlil_bytes_view_t){key, sizeof(key)},
            (ninlil_bytes_view_t){
                runtime->transaction_codec_bytes, value_length});
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, storage_txn);
            return map_destroy_group_status(status);
        }
    }
    status = ninlil_rt_v1_stage_resource_ledger(
        runtime,
        storage_txn,
        NINLIL_V1_DURABLE_OP_DESTROY_RECOVERY_COMMIT,
        &runtime->resource_ledger_scratch);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, storage_txn);
        return map_destroy_group_status(status);
    }
    if (runtime->private_transition_hook != NULL) {
        runtime->private_transition_hook(
            runtime->private_transition_hook_user,
            "runtime.before_destroy_recovery_commit");
    }
    status = storage_txn_commit_full(runtime, storage_txn);
    if (status != NINLIL_OK) {
        return map_destroy_group_status(status);
    }
    if (runtime->private_transition_hook != NULL) {
        runtime->private_transition_hook(
            runtime->private_transition_hook_user,
            "runtime.after_destroy_recovery_commit");
    }

    runtime->resource_ledger = runtime->resource_ledger_scratch;
    for (ordinal = 0u; ordinal < active_count; ++ordinal) {
        ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[order[ordinal]];

        make_destroy_recovery_candidate(
            transaction, &runtime->transaction_scratch);
        *transaction = runtime->transaction_scratch;
    }
    return NINLIL_OK;
}

static ninlil_status_t park_event_fact(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    uint32_t park_cause,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;
    ninlil_rt_transaction_slot_t *candidate;

    if (txn->spool_revision == UINT64_MAX) {
        return NINLIL_E_DEGRADED;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
    candidate->pending_dispatch = 0u;
    candidate->event_park_cause = park_cause;
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
        txn,
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

static ninlil_status_t dispatch_desired_state_sender(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
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
    /*
     * Absence of a Bearer path is not positive application evidence.  Keep
     * the admitted command non-terminal until a real send/Receipt path makes
     * progress, or the normal deadline reducer produces the normative
     * terminal outcome.
     */
    (void)clock_sample;
    (void)out_result;
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
    const ninlil_application_result_t *resolved_result = &app_result;
    ninlil_time_sample_t callback_start_sample;
    ninlil_callback_action_t action;
    ninlil_port_status_t clock_status;
    ninlil_status_t status;
    ninlil_rt_transaction_slot_t *candidate;
    uint32_t may_invoke = 0u;
    uint32_t may_resolve = 0u;

    if (txn->evidence_recorded != 0u) {
        if (txn->outcome_recorded == 0u) {
            candidate = &runtime->transaction_scratch;
            *candidate = *txn;
            candidate->outcome = NINLIL_OUTCOME_SATISFIED;
            candidate->outcome_recorded = 1u;
            candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
            candidate->terminal = 1u;
            candidate->pending_dispatch = 0u;
            status = ninlil_rt_v1_commit_transaction_snapshot(
                runtime,
                txn,
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
            note_terminal_outcome(runtime, txn->outcome, out_result);
        }
        return NINLIL_OK;
    }

    if (receiver->callbacks.on_delivery == NULL) {
        return park_event_fact(
            runtime,
            txn,
            NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE,
            out_result);
    }
    (void)memset(&callback_start_sample, 0, sizeof(callback_start_sample));
    clock_status = runtime->platform->clock->now(
        runtime->platform->clock->user, &callback_start_sample);
    if (clock_status == NINLIL_PORT_TEMPORARY_FAILURE
        || (clock_status == NINLIL_PORT_OK
            && uncertain_time_sample_is_valid(&callback_start_sample))) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (clock_status != NINLIL_PORT_OK
        || !trusted_time_sample_is_valid(&callback_start_sample)
        || memcmp(
            callback_start_sample.clock_epoch_id.bytes,
            clock_sample->clock_epoch_id.bytes,
            sizeof(callback_start_sample.clock_epoch_id.bytes)) != 0
        || callback_start_sample.now_ms < clock_sample->now_ms) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_DEGRADED;
    }
    status = ninlil_rt_accept_trusted_clock_sample(
        runtime, &callback_start_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_v1_prepare_callback_start(
        runtime,
        txn,
        &callback_start_sample,
        receiver->descriptor.application_completion_timeout_ms,
        out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_v1_callback_preflight(
        runtime, txn, clock_sample, out_result, &may_invoke);
    if (status != NINLIL_OK || may_invoke == 0u) {
        return status;
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
    delivery_view.transaction_id = txn->transaction_id;
    delivery_view.attempt_id = txn->attempt_id;
    delivery_view.event_id = txn->event_id;
    delivery_view.source = txn->source;
    if (txn->bound_target_count != 0u) {
        delivery_view.local_target =
            txn->bound_targets[0].target;
    }
    delivery_view.service = txn->service;
    delivery_view.content_digest = txn->content_digest;
    delivery_view.generation = txn->generation;
    delivery_view.delivery_count = txn->delivery_count;
    delivery_view.required_evidence = txn->required_evidence;
    delivery_view.deadline_clock_epoch_id =
        txn->deadline_clock_epoch_id;
    delivery_view.absolute_effect_deadline_ms = txn->effect_deadline_ms;
    delivery_view.evidence_grace_ms = txn->evidence_grace_ms;
    delivery_view.payload.data = txn->inline_payload_length == 0u
        ? NULL : txn->owned_payload;
    delivery_view.payload.length = txn->inline_payload_length;

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
    if (action != NINLIL_CALLBACK_COMPLETE
        || txn->evidence_recorded == 0u) {
        return NINLIL_OK;
    }

    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    candidate->outcome = NINLIL_OUTCOME_SATISFIED;
    candidate->outcome_recorded = 1u;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
    candidate->terminal = 1u;
    candidate->pending_dispatch = 0u;
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
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
    note_terminal_outcome(runtime, txn->outcome, out_result);
    return NINLIL_OK;
}

static int checked_receipt_deadline(
    const ninlil_rt_transaction_slot_t *txn,
    uint64_t *out_deadline)
{
    if (txn->send_observation_closed == 0u
        || txn->attempt_receipt_timeout_ms == 0u
        || txn->send_observed_at_ms
            > UINT64_MAX - txn->attempt_receipt_timeout_ms) {
        return 0;
    }
    *out_deadline =
        txn->send_observed_at_ms + txn->attempt_receipt_timeout_ms;
    return 1;
}

int ninlil_rt_v1_transaction_has_invalid_active_receipt_timer(
    const ninlil_rt_transaction_slot_t *transaction)
{
    uint64_t ignored_deadline;
    uint32_t index;
    int root_started_timer;
    int parked_cycle_timer;

    if (transaction == NULL || transaction->in_use == 0u
        || transaction->terminal != 0u
        || transaction->origin_admission == 0u) {
        return 0;
    }
    root_started_timer =
        transaction->delivery_phase == NINLIL_RT_DELIVERY_STARTED
        && transaction->evidence_recorded == 0u
        && transaction->pending_dispatch == 0u
        && transaction->send_observation_closed != 0u;
    parked_cycle_timer =
        transaction->family == NINLIL_FAMILY_EVENT_FACT
        && transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
        && transaction->send_observation_closed != 0u;
    if ((root_started_timer || parked_cycle_timer)
        && !checked_receipt_deadline(transaction, &ignored_deadline)) {
        return 1;
    }
    for (index = 0u; index < transaction->bound_target_count; ++index) {
        const ninlil_rt_target_slot_t *target =
            &transaction->bound_targets[index];

        if (target->in_use != 0u && target->terminal == 0u
            && target->delivery_phase == NINLIL_RT_DELIVERY_STARTED
            && target->evidence_recorded == 0u
            && target->pending_dispatch == 0u
            && target->send_observation_closed != 0u
            && (transaction->attempt_receipt_timeout_ms == 0u
                || target->send_observed_at_ms
                    > UINT64_MAX
                        - transaction->attempt_receipt_timeout_ms)) {
            return 1;
        }
    }
    return 0;
}

static int timer_is_due(
    const ninlil_time_sample_t *sample,
    const ninlil_id128_t *epoch,
    uint64_t deadline)
{
    return id_equal(&sample->clock_epoch_id, epoch)
        && sample->now_ms >= deadline;
}

static int delivery_token_timeout_is_due(
    const ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *sample)
{
    if (txn->token_state != NINLIL_RT_TOKEN_ACTIVE) {
        return 0;
    }
    if (!id_equal(&sample->clock_epoch_id, &txn->token_clock_epoch_id)) {
        return 1;
    }
    return sample->now_ms > txn->token_expires_at_ms;
}

static int txn_needs_work(
    const ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample)
{
    uint64_t evidence_close_at_ms;
    uint64_t receipt_deadline;
    uint32_t target_index;

    if (txn->in_use == 0u || txn->event_discarded != 0u) {
        return 0;
    }
    if (txn->terminal != 0u) {
        return txn->origin_admission == 0u
            && txn->evidence_recorded != 0u
            && txn->ingress_pending != 0u
            && txn->reverse_receipt_closed == 0u
            && (txn->next_retry_ms == 0u
                || timer_is_due(
                    clock_sample,
                    &txn->next_retry_clock_epoch_id,
                    txn->next_retry_ms));
    }
    if (txn->family == NINLIL_FAMILY_DESIRED_STATE
        && txn->origin_admission != 0u) {
        for (target_index = 0u;
             target_index < txn->bound_target_count;
             ++target_index) {
            const ninlil_rt_target_slot_t *target =
                &txn->bound_targets[target_index];

            if (target->in_use == 0u || target->terminal != 0u) {
                continue;
            }
            if (target->pending_dispatch != 0u
                && (target->next_retry_ms == 0u
                    || timer_is_due(
                        clock_sample,
                        &target->next_retry_clock_epoch_id,
                        target->next_retry_ms))) {
                return 1;
            }
            if (target->send_observation_closed != 0u
                && txn->attempt_receipt_timeout_ms != 0u
                && target->send_observed_at_ms
                    <= UINT64_MAX - txn->attempt_receipt_timeout_ms
                && timer_is_due(
                    clock_sample,
                    &target->send_observed_clock_epoch_id,
                    target->send_observed_at_ms
                        + txn->attempt_receipt_timeout_ms)) {
                return 1;
            }
        }
    }
    if (txn->receipt_pending != 0u) {
        return 1;
    }
    if (delivery_token_timeout_is_due(txn, clock_sample)) {
        return 1;
    }
    if (txn->ingress_pending != 0u) {
        return txn->next_retry_ms == 0u
            || timer_is_due(
                clock_sample,
                &txn->next_retry_clock_epoch_id,
                txn->next_retry_ms);
    }
    if (txn->pending_dispatch != 0u) {
        return txn->next_retry_ms == 0u
            || timer_is_due(
                clock_sample,
                &txn->next_retry_clock_epoch_id,
                txn->next_retry_ms);
    }
    if (txn->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && txn->family == NINLIL_FAMILY_EVENT_FACT) {
        return 0;
    }
    if (txn->delivery_phase == NINLIL_RT_DELIVERY_EVIDENCED
        && txn->outcome_recorded == 0u) {
        return 1;
    }
    if (txn->delivery_phase == NINLIL_RT_DELIVERY_STARTED
        && txn->evidence_recorded == 0u
        && checked_receipt_deadline(txn, &receipt_deadline)
        && timer_is_due(
            clock_sample,
            &txn->send_observed_clock_epoch_id,
            receipt_deadline)) {
        return 1;
    }
    if (txn->effect_deadline_ms != 0u
        && txn->effect_deadline_ms < NINLIL_NO_DEADLINE
        && desired_effect_deadline_needs_reduction(txn)
        && timer_is_due(
            clock_sample,
            &txn->deadline_clock_epoch_id,
            txn->effect_deadline_ms)) {
        return 1;
    }
    if (checked_evidence_close(txn, &evidence_close_at_ms)
        && desired_evidence_close_needs_reduction(txn)
        && timer_is_due(
            clock_sample,
            &txn->deadline_clock_epoch_id,
            evidence_close_at_ms)) {
        return 1;
    }
    return 0;
}

static ninlil_status_t handle_delivery_token_timeout(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_reason_t reason;
    ninlil_status_t status;
    int same_epoch;

    if (!delivery_token_timeout_is_due(txn, clock_sample)) {
        return NINLIL_OK;
    }
    same_epoch =
        id_equal(&clock_sample->clock_epoch_id, &txn->token_clock_epoch_id);
    reason = same_epoch
        ? NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT
        : NINLIL_REASON_OUTCOME_UNKNOWN;
    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    candidate->token_state = NINLIL_RT_TOKEN_EXPIRED;
    candidate->deferred_wait = 0u;
    candidate->pending_dispatch = 0u;
    candidate->ingress_pending = 0u;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
    set_recovery_result(candidate, reason);
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
    if (same_epoch) {
        saturating_increment_u64(
            &runtime->metrics.delivery_token_timeouts);
    }
    runtime->health = NINLIL_HEALTH_DEGRADED;
    runtime->degraded_reason = same_epoch
        ? NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT
        : NINLIL_REASON_CLOCK_UNCERTAIN;
    return NINLIL_OK;
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

/*
 * MFDT custody keeps only the logical length in NTS3; the bytes themselves
 * live in NM3S.  Until the Runtime scheduler owns the MFDT worker, this shape
 * must remain durable pending work and must never be synthesized as an empty
 * single-frame APPLICATION message.
 */
static int transaction_waits_for_mfdt_scheduler(
    const ninlil_rt_transaction_slot_t *txn)
{
    return txn != NULL
#if defined(NINLIL_MFDT_V1_PRIVATE)
        && txn->origin_admission != 0u
#endif
        && txn->bearer_route
            == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1
        && txn->payload_length > 0u
        && txn->inline_payload_length == 0u;
}

uint32_t ninlil_rt_v1_delivery_collect_work_order(
    const ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *out_order,
    uint32_t order_capacity)
{
    uint32_t order_count = 0u;
    uint32_t index;
    uint32_t pass;

    if (runtime == NULL || clock_sample == NULL || out_order == NULL
        || order_capacity == 0u) {
        return 0u;
    }
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        if (!txn_needs_work(
                &runtime->transactions[index], clock_sample)) {
            continue;
        }
        if (order_count >= order_capacity) {
            break;
        }
        out_order[order_count] = index;
        order_count += 1u;
    }
    for (pass = 0u; pass < order_count; ++pass) {
        uint32_t best = pass;
        uint32_t candidate;

        for (candidate = pass + 1u; candidate < order_count; ++candidate) {
            if (ninlil_rt_v1_txn_queue_order_less(
                    &runtime->transactions[out_order[candidate]],
                    &runtime->transactions[out_order[best]])) {
                best = candidate;
            }
        }
        if (best != pass) {
            uint32_t tmp = out_order[pass];
            out_order[pass] = out_order[best];
            out_order[best] = tmp;
        }
    }
    return order_count;
}

static int availability_resumable_park_cause(uint32_t park_cause)
{
    return park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
        || park_cause == NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE
        || park_cause == NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLE;
}

static int event_accepts_availability_epoch(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction)
{
    uint64_t epoch = runtime->step_bearer_availability_epoch;

    return runtime->config.role == NINLIL_ROLE_ENDPOINT
        && runtime->step_bearer_state_valid != 0u
        && runtime->step_bearer_available != 0u
        && epoch != 0u
        && transaction->in_use != 0u
        && transaction->terminal == 0u
        && transaction->origin_admission != 0u
        && transaction->family == NINLIL_FAMILY_EVENT_FACT
        && transaction->event_discarded == 0u
        && transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && availability_resumable_park_cause(
            transaction->event_park_cause)
        && epoch > transaction->last_bearer_availability_epoch
        && epoch
            > transaction->last_consumed_bearer_availability_epoch;
}

static void clear_automatic_resume_cycle_state(
    ninlil_rt_transaction_slot_t *candidate)
{
    uint32_t index;

    candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    candidate->pending_dispatch = 1u;
    candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    candidate->reason = NINLIL_REASON_NONE;
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
    (void)memset(
        &candidate->send_observed_clock_epoch_id,
        0,
        sizeof(candidate->send_observed_clock_epoch_id));
    candidate->send_observed_at_ms = 0u;
    candidate->send_observation_closed = 0u;
    candidate->reverse_receipt_closed = 0u;
    candidate->ingress_pending = 0u;
    candidate->receipt_pending = 0u;
    for (index = 0u; index < candidate->bound_target_count; ++index) {
        candidate->bound_targets[index].pending_dispatch = 1u;
    }
}

static ninlil_status_t fail_automatic_resume_clock_guard(
    ninlil_runtime_t *runtime,
    ninlil_status_t status)
{
    runtime->health = NINLIL_HEALTH_DEGRADED;
    runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
    return status;
}

static ninlil_status_t guard_automatic_resume_chronology(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample)
{
    uint64_t cycle_ended_at_ms;

    if (!trusted_time_sample_is_valid(clock_sample)
        || runtime->bearer_state_present == 0u
        || runtime->step_bearer_availability_epoch == 0u
        || runtime->step_bearer_availability_epoch
            != runtime->bearer_availability_epoch
        || !id_nonzero(&runtime->bearer_observed_clock_epoch_id)) {
        return fail_automatic_resume_clock_guard(
            runtime, NINLIL_E_DEGRADED);
    }
    if (!id_equal(
            &clock_sample->clock_epoch_id,
            &runtime->bearer_observed_clock_epoch_id)) {
        return fail_automatic_resume_clock_guard(
            runtime, NINLIL_E_CLOCK_UNCERTAIN);
    }
    if (clock_sample->now_ms < runtime->bearer_observed_at_ms) {
        return fail_automatic_resume_clock_guard(
            runtime, NINLIL_E_DEGRADED);
    }

    if (transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
        && transaction->send_observation_closed != 0u) {
        if (transaction->attempt_receipt_timeout_ms == 0u
            || transaction->send_observed_at_ms
                > UINT64_MAX - transaction->attempt_receipt_timeout_ms) {
            return fail_automatic_resume_clock_guard(
                runtime, NINLIL_E_DEGRADED);
        }
        if (!id_equal(
                &clock_sample->clock_epoch_id,
                &transaction->send_observed_clock_epoch_id)) {
            return fail_automatic_resume_clock_guard(
                runtime, NINLIL_E_CLOCK_UNCERTAIN);
        }
        cycle_ended_at_ms = transaction->send_observed_at_ms
            + transaction->attempt_receipt_timeout_ms;
        if (clock_sample->now_ms < cycle_ended_at_ms) {
            return fail_automatic_resume_clock_guard(
                runtime, NINLIL_E_DEGRADED);
        }
    }
    return NINLIL_OK;
}

static ninlil_status_t automatic_availability_resume_one(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t transition_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_resumed)
{
    ninlil_rt_transaction_slot_t *transaction = NULL;
    ninlil_rt_transaction_slot_t *candidate;
    uint32_t index;
    ninlil_status_t status;

    *out_resumed = 0u;
    if (runtime->step_bearer_state_valid == 0u
        || runtime->step_bearer_available == 0u) {
        return NINLIL_OK;
    }
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        ninlil_rt_transaction_slot_t *current =
            &runtime->transactions[index];

        if (!event_accepts_availability_epoch(runtime, current)) {
            continue;
        }
        if (transaction == NULL
            || current->transaction_sequence
                < transaction->transaction_sequence) {
            transaction = current;
        }
    }
    if (transaction == NULL) {
        return NINLIL_OK;
    }
    if (transition_budget == 0u) {
        out_result->work_remaining = 1u;
        runtime->pending_work = 1u;
        return NINLIL_OK;
    }
    status = guard_automatic_resume_chronology(
        runtime, transaction, clock_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    if (transaction->spool_revision == UINT64_MAX) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    candidate = &runtime->transaction_scratch;
    status = ninlil_rt_v1_begin_event_retry_cycle(
        transaction, candidate);
    if (status != NINLIL_OK) {
        if (status == NINLIL_E_DEGRADED) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        }
        return status;
    }
    candidate->spool_revision += 1u;
    candidate->last_bearer_availability_epoch =
        runtime->step_bearer_availability_epoch;
    candidate->last_consumed_bearer_availability_epoch =
        runtime->step_bearer_availability_epoch;
    clear_automatic_resume_cycle_state(candidate);
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
    out_result->work_remaining = 1u;
    runtime->pending_work = 1u;
    saturating_increment_u64(&runtime->metrics.events_resumed);
    *out_resumed = 1u;
    return NINLIL_OK;
}

static ninlil_status_t commit_terminal_outcome(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_outcome_t outcome,
    ninlil_reason_t reason,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_outcome_t recorded_outcome = outcome;
    uint32_t target_index = 0u;
    uint32_t scan;

    if (txn->outcome_recorded != 0u) {
        return NINLIL_OK;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    if (candidate->family == NINLIL_FAMILY_DESIRED_STATE
        && candidate->origin_admission != 0u) {
        ninlil_rt_target_slot_t *target;
        int activated = 0;

        if (!ninlil_rt_v1_active_target(candidate, &target_index)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        target = &candidate->bound_targets[target_index];
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
        target->outcome = outcome;
        target->reason = reason;
        if (outcome == NINLIL_OUTCOME_EXPIRED) {
            target->deadline_verdict = NINLIL_DEADLINE_MISSED;
        }
        for (scan = 1u;
             scan <= candidate->bound_target_count;
             ++scan) {
            uint32_t next =
                (target_index + scan) % candidate->bound_target_count;
            ninlil_rt_target_slot_t *next_target =
                &candidate->bound_targets[next];

            if (next_target->in_use != 0u
                && next_target->terminal == 0u) {
                ninlil_rt_v1_activate_target(candidate, next);
                activated = 1;
                break;
            }
        }
        if (!activated) {
            candidate->active_target_index =
                NINLIL_RT_V1_NO_ACTIVE_TARGET;
            candidate->attempt_prepared = 0u;
            (void)memset(
                &candidate->attempt_id,
                0,
                sizeof(candidate->attempt_id));
            candidate->pending_dispatch = 0u;
        }
        ninlil_rt_v1_refresh_target_aggregate(candidate);
        recorded_outcome = candidate->outcome;
    } else {
        candidate->outcome = outcome;
        candidate->reason = reason;
        candidate->outcome_recorded = 1u;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        candidate->terminal = 1u;
        candidate->pending_dispatch = 0u;
    }
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_OC,
        NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    if (candidate->terminal != 0u) {
        if (runtime->nonterminal_transaction_count > 0u) {
            runtime->nonterminal_transaction_count -= 1u;
        }
        note_terminal_outcome(runtime, recorded_outcome, out_result);
        status = ninlil_rt_v1_release_transaction_reservation(
            runtime, txn);
        if (status != NINLIL_OK) {
            return status;
        }
    } else {
        out_result->work_remaining = 1u;
        runtime->pending_work = 1u;
    }
    return NINLIL_OK;
}

static int attempt_id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int attempt_id_is_in_use(
    const ninlil_runtime_t *runtime,
    const ninlil_id128_t *attempt_id)
{
    uint32_t index;

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *candidate =
            &runtime->transactions[index];
        uint32_t attempt_index;

        if (candidate->in_use == 0u) {
            continue;
        }
        for (attempt_index = 0u;
             attempt_index < candidate->attempt_count
                && attempt_index < NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN;
             ++attempt_index) {
            if (id_equal(
                    &candidate->attempt_ids[attempt_index],
                    attempt_id)) {
                return 1;
            }
        }
    }
    return 0;
}

static int desired_retry_apply_contract_is_safe(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction)
{
    const ninlil_rt_service_slot_t *matched = NULL;
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        const ninlil_rt_service_slot_t *slot =
            &runtime->services[index];

        if (slot->in_use == 0u
            || !ninlil_rt_service_descriptor_matches_transaction(
                &slot->descriptor, transaction)) {
            continue;
        }
        if (matched != NULL) {
            return 0;
        }
        matched = slot;
    }
    return matched != NULL
        && (matched->descriptor.apply_contract == NINLIL_APPLY_IDEMPOTENT
            || matched->descriptor.apply_contract
                == NINLIL_APPLY_APPLICATION_DEDUP);
}

static ninlil_status_t prepare_application_attempt(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_id128_t attempt_id;
    ninlil_port_status_t entropy_status;
    ninlil_status_t status;
    uint32_t draw;
    uint32_t target_index = 0u;
    int found = 0;

    if (txn->attempt_prepared != 0u) {
        return NINLIL_OK;
    }
    if (txn->family == NINLIL_FAMILY_DESIRED_STATE
        && !ninlil_rt_v1_active_target(txn, &target_index)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (txn->cumulative_attempts == UINT64_MAX
        || (txn->family == NINLIL_FAMILY_EVENT_FACT
            && txn->attempt_in_cycle
                >= NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    if (txn->retry_budget == 0u
        || txn->attempt_count >= NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN) {
        if (txn->family == NINLIL_FAMILY_EVENT_FACT) {
            return park_event_fact(
                runtime,
                txn,
                NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT,
                out_result);
        }
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_FAILED_DEFINITIVE,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT,
            out_result);
    }

    (void)memset(&attempt_id, 0, sizeof(attempt_id));
    for (draw = 0u; draw < 4u; ++draw) {
        entropy_status = runtime->platform->entropy->fill(
            runtime->platform->entropy->user,
            attempt_id.bytes,
            (uint32_t)sizeof(attempt_id.bytes));
        if (entropy_status == NINLIL_PORT_OK
            && !attempt_id_is_zero(&attempt_id)
            && !attempt_id_is_in_use(runtime, &attempt_id)) {
            found = 1;
            break;
        }
        (void)memset(&attempt_id, 0, sizeof(attempt_id));
    }
    if (!found) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_ENTROPY;
    }

    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    candidate->attempt_id = attempt_id;
    candidate->attempt_prepared = 1u;
    candidate->attempt_ids[candidate->attempt_count] = attempt_id;
    candidate->attempt_target_indices[candidate->attempt_count] =
        (uint8_t)target_index;
    candidate->attempt_count += 1u;
    candidate->cumulative_attempts += 1u;
    if (candidate->family == NINLIL_FAMILY_EVENT_FACT) {
        candidate->attempt_in_cycle += 1u;
    }
    candidate->retry_budget -= 1u;
    candidate->send_observation_closed = 0u;
    candidate->send_observed_at_ms = 0u;
    (void)memset(
        &candidate->send_observed_clock_epoch_id,
        0,
        sizeof(candidate->send_observed_clock_epoch_id));
    if (candidate->origin_admission != 0u
        && candidate->family == NINLIL_FAMILY_DESIRED_STATE
        && target_index < candidate->bound_target_count) {
        ninlil_rt_target_slot_t *target =
            &candidate->bound_targets[target_index];

        target->active_attempt_id = attempt_id;
        target->attempt_prepared = 1u;
        target->retry_budget -= 1u;
        target->attempt_in_cycle += 1u;
        target->cumulative_attempts += 1u;
        target->send_observation_closed = 0u;
        target->send_observed_at_ms = 0u;
        (void)memset(
            &target->send_observed_clock_epoch_id,
            0,
            sizeof(target->send_observed_clock_epoch_id));
        target->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
        target->pending_dispatch = 1u;
    }
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_AP,
        NINLIL_V1_DURABLE_OP_APPLICATION_ATTEMPT_PREPARE_COMMIT);
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
    uint32_t target_index = 0u;

    if (runtime->config.role != NINLIL_ROLE_CONTROLLER
        || !ninlil_rt_v1_family_is_downlink(txn->family)
        || txn->delivery_phase != NINLIL_RT_DELIVERY_STARTED
        || txn->evidence_recorded != 0u
        || txn->pending_dispatch != 0u
        || txn->send_observation_closed == 0u) {
        return NINLIL_OK;
    }
    if (txn->family == NINLIL_FAMILY_DESIRED_STATE
        && txn->origin_admission != 0u
        && !ninlil_rt_v1_active_target(txn, &target_index)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (!checked_receipt_deadline(txn, &receipt_deadline_ms)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    if (!timer_is_due(
            clock_sample,
            &txn->send_observed_clock_epoch_id,
            receipt_deadline_ms)) {
        return NINLIL_OK;
    }
    if (txn->family == NINLIL_FAMILY_DESIRED_STATE
        && txn->origin_admission != 0u) {
        ninlil_rt_transaction_slot_t *candidate =
            &runtime->transaction_scratch;
        ninlil_rt_target_slot_t *target;
        uint32_t scan;
        int activated = 0;
        int retry_is_safe;
        uint64_t retry_not_before_ms = 0u;

        *candidate = *txn;
        target = &candidate->bound_targets[target_index];
        retry_is_safe = txn->retry_backoff_ms != 0u
            && clock_sample->now_ms
                <= UINT64_MAX - txn->retry_backoff_ms;
        if (retry_is_safe) {
            retry_not_before_ms =
                clock_sample->now_ms + txn->retry_backoff_ms;
        }
        retry_is_safe = retry_is_safe
            && target->retry_budget != 0u
            && desired_retry_apply_contract_is_safe(runtime, txn)
            && target->deadline_verdict == NINLIL_DEADLINE_PENDING
            && id_equal(
                &txn->send_observed_clock_epoch_id,
                &txn->deadline_clock_epoch_id)
            && retry_not_before_ms < txn->effect_deadline_ms;
        target->delivery_phase = retry_is_safe
            ? NINLIL_RT_DELIVERY_QUEUED
            : NINLIL_RT_DELIVERY_STARTED;
        target->pending_dispatch = retry_is_safe ? 1u : 0u;
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
        if (retry_is_safe) {
            target->next_retry_ms = retry_not_before_ms;
            target->next_retry_clock_epoch_id =
                clock_sample->clock_epoch_id;
        } else {
            target->next_retry_ms = 0u;
            (void)memset(
                &target->next_retry_clock_epoch_id,
                0,
                sizeof(target->next_retry_clock_epoch_id));
        }
        /*
         * ACCEPTED/possible delivery timeout is not no-effect proof.  The
         * existing durable target reason is the current NTS3 authority for
         * EFFECT_POSSIBLE while deadline_verdict correctly remains PENDING
         * until the separate effect-deadline reducer runs.
         */
        target->reason =
            NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING;

        candidate->active_target_index =
            NINLIL_RT_V1_NO_ACTIVE_TARGET;
        candidate->attempt_prepared = 0u;
        (void)memset(
            &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
        candidate->send_observation_closed = 0u;
        candidate->send_observed_at_ms = 0u;
        (void)memset(
            &candidate->send_observed_clock_epoch_id,
            0,
            sizeof(candidate->send_observed_clock_epoch_id));
        candidate->next_retry_ms = 0u;
        (void)memset(
            &candidate->next_retry_clock_epoch_id,
            0,
            sizeof(candidate->next_retry_clock_epoch_id));

        /* Other exact targets may still be dispatched before the deadline. */
        for (scan = 1u;
             scan < candidate->bound_target_count;
             ++scan) {
            uint32_t next =
                (target_index + scan) % candidate->bound_target_count;
            ninlil_rt_target_slot_t *next_target =
                &candidate->bound_targets[next];

            if (next_target->in_use != 0u
                && next_target->terminal == 0u
                && next_target->pending_dispatch != 0u) {
                ninlil_rt_v1_activate_target(candidate, next);
                activated = 1;
                break;
            }
        }
        if (!activated) {
            ninlil_rt_v1_activate_target(candidate, target_index);
        }
        ninlil_rt_v1_refresh_target_aggregate(candidate);
        if (candidate->active_target_index == target_index) {
            candidate->reason =
                NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING;
            candidate->deadline_verdict = target->deadline_verdict;
        }
        status = commit_transaction_snapshot_internal(
            runtime,
            txn,
            candidate,
            NINLIL_RT_V1_MARKER_RT,
            NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT,
            0,
            "controller.before_command_attempt_timeout_commit",
            "controller.after_command_attempt_timeout_commit");
        if (status != NINLIL_OK) {
            return status;
        }
        out_result->transitions_consumed += 1u;
        return NINLIL_OK;
    }
    if (txn->retry_budget == 0u) {
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_FAILED_DEFINITIVE,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT,
            out_result);
    }
    {
        ninlil_rt_transaction_slot_t *candidate =
            &runtime->transaction_scratch;
        uint64_t retry_not_before_ms;

        if (txn->retry_backoff_ms == 0u
            || clock_sample->now_ms
                > UINT64_MAX - txn->retry_backoff_ms) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        retry_not_before_ms =
            clock_sample->now_ms + txn->retry_backoff_ms;

        *candidate = *txn;
        candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
        candidate->pending_dispatch = 1u;
        candidate->attempt_prepared = 0u;
        (void)memset(
            &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
        candidate->send_observation_closed = 0u;
        candidate->send_observed_at_ms = 0u;
        (void)memset(
            &candidate->send_observed_clock_epoch_id,
            0,
            sizeof(candidate->send_observed_clock_epoch_id));
        candidate->next_retry_ms = retry_not_before_ms;
        candidate->next_retry_clock_epoch_id =
            clock_sample->clock_epoch_id;
        if (candidate->family == NINLIL_FAMILY_DESIRED_STATE
            && candidate->origin_admission != 0u) {
            ninlil_rt_target_slot_t *target =
                &candidate->bound_targets[target_index];
            uint32_t scan;

            target->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
            target->pending_dispatch = 1u;
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
            target->next_retry_ms = retry_not_before_ms;
            target->next_retry_clock_epoch_id =
                clock_sample->clock_epoch_id;
            target->reason = NINLIL_REASON_TRANSPORT_RETRY;
            for (scan = 1u;
                 scan <= candidate->bound_target_count;
                 ++scan) {
                uint32_t next =
                    (target_index + scan)
                    % candidate->bound_target_count;
                ninlil_rt_target_slot_t *next_target =
                    &candidate->bound_targets[next];

                if (next_target->in_use != 0u
                    && next_target->terminal == 0u) {
                    ninlil_rt_v1_activate_target(
                        candidate, next);
                    break;
                }
            }
            ninlil_rt_v1_refresh_target_aggregate(candidate);
        }
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            txn,
            candidate,
            NINLIL_RT_V1_MARKER_RT,
            NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

static ninlil_status_t handle_event_endpoint_receipt_timeout(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_status_t status;
    uint64_t receipt_deadline_ms;
    uint64_t retry_not_before_ms = 0u;
    int parks_cycle;

    if (runtime->config.role != NINLIL_ROLE_ENDPOINT
        || txn->family != NINLIL_FAMILY_EVENT_FACT
        || txn->origin_admission == 0u
        || txn->delivery_phase != NINLIL_RT_DELIVERY_STARTED
        || txn->evidence_recorded != 0u
        || txn->pending_dispatch != 0u
        || txn->send_observation_closed == 0u) {
        return NINLIL_OK;
    }
    if (!checked_receipt_deadline(txn, &receipt_deadline_ms)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    if (!timer_is_due(
            clock_sample,
            &txn->send_observed_clock_epoch_id,
            receipt_deadline_ms)) {
        return NINLIL_OK;
    }
    parks_cycle = txn->retry_budget == 0u;
    if (parks_cycle && txn->spool_revision == UINT64_MAX) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    if (!parks_cycle) {
        if (txn->retry_backoff_ms == 0u
            || clock_sample->now_ms
                > UINT64_MAX - txn->retry_backoff_ms) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
            return NINLIL_E_DEGRADED;
        }
        retry_not_before_ms =
            clock_sample->now_ms + txn->retry_backoff_ms;
    }
    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    candidate->attempt_prepared = 0u;
    (void)memset(
        &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
    candidate->next_retry_ms = 0u;
    (void)memset(
        &candidate->next_retry_clock_epoch_id,
        0,
        sizeof(candidate->next_retry_clock_epoch_id));
    if (parks_cycle) {
        /*
         * Keep the accepted send chronology durable while the exhausted
         * cycle is parked.  The next resume first transfers this tuple into
         * retry history, then clears the live-cycle observation.
         */
        candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
        candidate->pending_dispatch = 0u;
        candidate->event_park_cause =
            NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT;
        candidate->reason =
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT;
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
            txn,
            candidate,
            NINLIL_RT_V1_MARKER_ES,
            NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT);
    } else {
        candidate->send_observation_closed = 0u;
        candidate->send_observed_at_ms = 0u;
        (void)memset(
            &candidate->send_observed_clock_epoch_id,
            0,
            sizeof(candidate->send_observed_clock_epoch_id));
        candidate->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
        candidate->pending_dispatch = 1u;
        candidate->reason = NINLIL_REASON_TRANSPORT_RETRY;
        candidate->next_retry_ms = retry_not_before_ms;
        candidate->next_retry_clock_epoch_id =
            clock_sample->clock_epoch_id;
        status = ninlil_rt_v1_commit_transaction_snapshot(
            runtime,
            txn,
            candidate,
            NINLIL_RT_V1_MARKER_RT,
            NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    if (parks_cycle) {
        out_result->events_parked += 1u;
        saturating_increment_u64(&runtime->metrics.events_parked);
    }
    runtime->pending_work = 1u;
    return NINLIL_OK;
}

static ninlil_status_t handle_timeout_retry(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result);

static ninlil_status_t handle_evidence_close(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result);

static int checked_evidence_close(
    const ninlil_rt_transaction_slot_t *txn,
    uint64_t *out_close_at_ms)
{
    if (txn->effect_deadline_ms == 0u
        || txn->effect_deadline_ms >= NINLIL_NO_DEADLINE
        || txn->effect_deadline_ms
            > UINT64_MAX - txn->evidence_grace_ms) {
        return 0;
    }
    *out_close_at_ms =
        txn->effect_deadline_ms + txn->evidence_grace_ms;
    return 1;
}

static int desired_effect_deadline_needs_reduction(
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    if (txn->family != NINLIL_FAMILY_DESIRED_STATE
        || txn->origin_admission == 0u) {
        return 1;
    }
    for (index = 0u; index < txn->bound_target_count; ++index) {
        const ninlil_rt_target_slot_t *target =
            &txn->bound_targets[index];

        if (target->in_use != 0u && target->terminal == 0u
            && (target->deadline_verdict
                    != NINLIL_DEADLINE_INDETERMINATE
                || target->reason
                    != NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING)) {
            return 1;
        }
    }
    return 0;
}

static int desired_evidence_close_needs_reduction(
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    if (txn->family != NINLIL_FAMILY_DESIRED_STATE
        || txn->origin_admission == 0u) {
        return 0;
    }
    for (index = 0u; index < txn->bound_target_count; ++index) {
        const ninlil_rt_target_slot_t *target =
            &txn->bound_targets[index];

        if (target->in_use != 0u && target->terminal == 0u
            && target->deadline_verdict
                == NINLIL_DEADLINE_INDETERMINATE
            && target->reason
                == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING) {
            return 1;
        }
    }
    return 0;
}

static int timer_precedes_management(
    const ninlil_time_sample_t *sample,
    const ninlil_id128_t *epoch,
    uint64_t deadline,
    uint32_t timer_priority,
    uint32_t management_priority)
{
    return id_equal(&sample->clock_epoch_id, epoch)
        && (deadline < sample->now_ms
            || (deadline == sample->now_ms
                && timer_priority < management_priority));
}

static int epoch_differs_from_sample(
    const ninlil_time_sample_t *sample,
    const ninlil_id128_t *epoch)
{
    return id_nonzero(epoch)
        && !id_equal(&sample->clock_epoch_id, epoch);
}

static int targeted_management_has_cross_epoch_correctness_timer(
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *sample)
{
    uint64_t ignored_deadline;
    uint32_t index;

    if (transaction->token_state == NINLIL_RT_TOKEN_ACTIVE
        && epoch_differs_from_sample(
            sample, &transaction->token_clock_epoch_id)) {
        return 1;
    }
    if (transaction->terminal == 0u
        && transaction->next_retry_ms != 0u
        && epoch_differs_from_sample(
            sample, &transaction->next_retry_clock_epoch_id)) {
        return 1;
    }
    if (transaction->terminal == 0u
        && transaction->effect_deadline_ms != 0u
        && transaction->effect_deadline_ms < NINLIL_NO_DEADLINE
        && (desired_effect_deadline_needs_reduction(transaction)
            || (checked_evidence_close(transaction, &ignored_deadline)
                && desired_evidence_close_needs_reduction(transaction)))
        && epoch_differs_from_sample(
            sample, &transaction->deadline_clock_epoch_id)) {
        return 1;
    }
    if (transaction->terminal == 0u
        && transaction->delivery_phase == NINLIL_RT_DELIVERY_STARTED
        && transaction->evidence_recorded == 0u
        && transaction->pending_dispatch == 0u
        && checked_receipt_deadline(transaction, &ignored_deadline)
        && epoch_differs_from_sample(
            sample, &transaction->send_observed_clock_epoch_id)) {
        return 1;
    }
    if (transaction->terminal == 0u
        && transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED
        && transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
        && transaction->send_observation_closed != 0u
        && checked_receipt_deadline(transaction, &ignored_deadline)
        && epoch_differs_from_sample(
            sample, &transaction->send_observed_clock_epoch_id)) {
        return 1;
    }
    if (transaction->terminal != 0u) {
        return 0;
    }
    for (index = 0u; index < transaction->bound_target_count; ++index) {
        const ninlil_rt_target_slot_t *target =
            &transaction->bound_targets[index];

        if (target->in_use != 0u && target->terminal == 0u
            && target->next_retry_ms != 0u
            && epoch_differs_from_sample(
                sample, &target->next_retry_clock_epoch_id)) {
            return 1;
        }
        if (transaction->attempt_receipt_timeout_ms != 0u
            && target->in_use != 0u && target->terminal == 0u
            && target->delivery_phase == NINLIL_RT_DELIVERY_STARTED
            && target->evidence_recorded == 0u
            && target->pending_dispatch == 0u
            && target->send_observation_closed != 0u
            && target->send_observed_at_ms
                <= UINT64_MAX - transaction->attempt_receipt_timeout_ms
            && epoch_differs_from_sample(
                sample, &target->send_observed_clock_epoch_id)) {
            return 1;
        }
    }
    return 0;
}

typedef enum targeted_timer_kind {
    TARGETED_TIMER_NONE = 0,
    TARGETED_TIMER_TOKEN = 1,
    TARGETED_TIMER_EFFECT_DEADLINE = 2,
    TARGETED_TIMER_EVIDENCE_CLOSE = 3,
    TARGETED_TIMER_CONTROLLER_RECEIPT = 4,
    TARGETED_TIMER_EVENT_RECEIPT = 5
} targeted_timer_kind_t;

typedef struct targeted_timer_candidate {
    targeted_timer_kind_t kind;
    uint64_t logical_time_ms;
    uint32_t priority;
} targeted_timer_candidate_t;

static void consider_targeted_timer(
    targeted_timer_candidate_t *best,
    targeted_timer_kind_t kind,
    uint64_t logical_time_ms,
    uint32_t priority)
{
    if (best->kind == TARGETED_TIMER_NONE
        || logical_time_ms < best->logical_time_ms
        || (logical_time_ms == best->logical_time_ms
            && priority < best->priority)) {
        best->kind = kind;
        best->logical_time_ms = logical_time_ms;
        best->priority = priority;
    }
}

ninlil_status_t ninlil_rt_v1_targeted_management_catch_up(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample,
    uint32_t transition_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_changed,
    uint32_t management_priority)
{
    uint32_t transitions_at_entry;
    ninlil_status_t status;

    if (runtime == NULL || transaction == NULL || clock_sample == NULL
        || out_result == NULL || out_changed == NULL
        || transaction->in_use == 0u
        || (management_priority
                != NINLIL_RT_V1_INPUT_PRIORITY_CANCEL_OR_DISCARD
            && management_priority
                != NINLIL_RT_V1_INPUT_PRIORITY_EVENT_RESUME
            && management_priority
                != NINLIL_RT_V1_INPUT_PRIORITY_SCHEDULER_AFTER_READY)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_changed = 0u;
    if (ninlil_rt_v1_transaction_has_invalid_active_receipt_timer(
            transaction)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_DEGRADED;
    }
    /*
     * Different clock epochs are not numerically comparable.  The current
     * public/storage tranche has no canonical durable Recovery Fence state,
     * so targeted management must fail closed before any ordered or ledger
     * mutation instead of silently stepping past an old-epoch timer.
     */
    if (management_priority
            != NINLIL_RT_V1_INPUT_PRIORITY_SCHEDULER_AFTER_READY
        && targeted_management_has_cross_epoch_correctness_timer(
            transaction, clock_sample)) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    transitions_at_entry = out_result->transitions_consumed;
    for (;;) {
        uint32_t transitions_before = out_result->transitions_consumed;
        targeted_timer_candidate_t candidate;
        uint64_t receipt_deadline_ms = 0u;
        uint64_t evidence_close_at_ms = 0u;

        /*
         * NTS3 represents an already-persisted Receipt but not its durable
         * ingress logical time. It is the current priority-1 authority and
         * is reduced first. Disposition/CancelResult/Delivery/reconcile stay
         * OPEN until their canonical ingress/state exists; no state is
         * synthesized here.
         */
        if (transaction->receipt_pending != 0u) {
            status = ninlil_rt_v1_bearer_reduce_pending_ingress(
                runtime,
                transaction,
                clock_sample,
                0u,
                transition_budget,
                0u,
                out_result);
            if (status != NINLIL_OK) {
                return status;
            }
        }
        if (out_result->transitions_consumed != transitions_before) {
            continue;
        }
        if (out_result->transitions_consumed >= transition_budget) {
            out_result->work_remaining = 1u;
            break;
        }

        (void)memset(&candidate, 0, sizeof(candidate));
        if (transaction->token_state == NINLIL_RT_TOKEN_ACTIVE
            && id_equal(
                &clock_sample->clock_epoch_id,
                &transaction->token_clock_epoch_id)
            && clock_sample->now_ms
                > transaction->token_expires_at_ms
            && timer_precedes_management(
                clock_sample,
                &transaction->token_clock_epoch_id,
                transaction->token_expires_at_ms,
                4u,
                management_priority)) {
            consider_targeted_timer(
                &candidate,
                TARGETED_TIMER_TOKEN,
                transaction->token_expires_at_ms,
                4u);
        }
        if (transaction->terminal == 0u
            && transaction->effect_deadline_ms != 0u
            && transaction->effect_deadline_ms < NINLIL_NO_DEADLINE
            && desired_effect_deadline_needs_reduction(transaction)
            && timer_precedes_management(
                clock_sample,
                &transaction->deadline_clock_epoch_id,
                transaction->effect_deadline_ms,
                5u,
                management_priority)) {
            consider_targeted_timer(
                &candidate,
                TARGETED_TIMER_EFFECT_DEADLINE,
                transaction->effect_deadline_ms,
                5u);
        }
        if (transaction->terminal == 0u
            && checked_evidence_close(
                transaction, &evidence_close_at_ms)
            && desired_evidence_close_needs_reduction(transaction)
            && timer_precedes_management(
                clock_sample,
                &transaction->deadline_clock_epoch_id,
                evidence_close_at_ms,
                6u,
                management_priority)) {
            consider_targeted_timer(
                &candidate,
                TARGETED_TIMER_EVIDENCE_CLOSE,
                evidence_close_at_ms,
                6u);
        }
        if (runtime->config.role == NINLIL_ROLE_CONTROLLER
            && transaction->delivery_phase
                == NINLIL_RT_DELIVERY_STARTED
            && transaction->evidence_recorded == 0u
            && transaction->pending_dispatch == 0u
            && checked_receipt_deadline(
                transaction, &receipt_deadline_ms)
            && timer_precedes_management(
                clock_sample,
                &transaction->send_observed_clock_epoch_id,
                receipt_deadline_ms,
                7u,
                management_priority)) {
            consider_targeted_timer(
                &candidate,
                TARGETED_TIMER_CONTROLLER_RECEIPT,
                receipt_deadline_ms,
                7u);
        }
        if (runtime->config.role == NINLIL_ROLE_ENDPOINT
            && transaction->family == NINLIL_FAMILY_EVENT_FACT
            && transaction->origin_admission != 0u
            && transaction->delivery_phase
                == NINLIL_RT_DELIVERY_STARTED
            && transaction->evidence_recorded == 0u
            && transaction->pending_dispatch == 0u
            && checked_receipt_deadline(
                transaction, &receipt_deadline_ms)
            && timer_precedes_management(
                clock_sample,
                &transaction->send_observed_clock_epoch_id,
                receipt_deadline_ms,
                7u,
                management_priority)) {
            consider_targeted_timer(
                &candidate,
                TARGETED_TIMER_EVENT_RECEIPT,
                receipt_deadline_ms,
                7u);
        }

        switch (candidate.kind) {
        case TARGETED_TIMER_TOKEN:
            status = handle_delivery_token_timeout(
                runtime, transaction, clock_sample, out_result);
            break;
        case TARGETED_TIMER_EFFECT_DEADLINE:
            status = handle_timeout_retry(
                runtime, transaction, clock_sample, out_result);
            break;
        case TARGETED_TIMER_EVIDENCE_CLOSE:
            status = handle_evidence_close(
                runtime, transaction, clock_sample, out_result);
            break;
        case TARGETED_TIMER_CONTROLLER_RECEIPT:
            status = handle_bearer_receipt_timeout(
                runtime, transaction, clock_sample, out_result);
            break;
        case TARGETED_TIMER_EVENT_RECEIPT:
            status = handle_event_endpoint_receipt_timeout(
                runtime, transaction, clock_sample, out_result);
            break;
        case TARGETED_TIMER_NONE:
        default:
            status = NINLIL_OK;
            break;
        }
        if (status != NINLIL_OK) {
            return status;
        }
        if (out_result->transitions_consumed == transitions_before) {
            break;
        }
    }
    *out_changed = out_result->transitions_consumed != transitions_at_entry;
    return NINLIL_OK;
}

static ninlil_status_t reduce_desired_effect_deadline(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;
    ninlil_status_t status;
    uint32_t index;
    uint32_t effect_possible_count = 0u;

    *candidate = *txn;
    for (index = 0u; index < candidate->bound_target_count; ++index) {
        ninlil_rt_target_slot_t *target =
            &candidate->bound_targets[index];

        if (target->in_use == 0u || target->terminal != 0u) {
            continue;
        }
        if (target->attempt_prepared != 0u
            || target->send_observation_closed != 0u
            || target->reason
                == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING) {
            target->deadline_verdict =
                NINLIL_DEADLINE_INDETERMINATE;
            target->reason =
                NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING;
            target->pending_dispatch = 0u;
            target->next_retry_ms = 0u;
            (void)memset(
                &target->next_retry_clock_epoch_id,
                0,
                sizeof(target->next_retry_clock_epoch_id));
            effect_possible_count += 1u;
            continue;
        }
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
        target->deadline_verdict = NINLIL_DEADLINE_MISSED;
        target->outcome = NINLIL_OUTCOME_EXPIRED;
        target->reason =
            NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH;
    }
    if (effect_possible_count != 0u) {
        uint32_t active = NINLIL_RT_V1_NO_ACTIVE_TARGET;

        for (index = 0u; index < candidate->bound_target_count; ++index) {
            const ninlil_rt_target_slot_t *target =
                &candidate->bound_targets[index];

            if (target->in_use != 0u && target->terminal == 0u
                && target->deadline_verdict
                    == NINLIL_DEADLINE_INDETERMINATE) {
                active = index;
                break;
            }
        }
        candidate->active_target_index = active;
        if (active != NINLIL_RT_V1_NO_ACTIVE_TARGET) {
            ninlil_rt_v1_activate_target(candidate, active);
        }
        candidate->deadline_verdict =
            NINLIL_DEADLINE_INDETERMINATE;
    } else {
        candidate->active_target_index =
            NINLIL_RT_V1_NO_ACTIVE_TARGET;
        candidate->attempt_prepared = 0u;
        (void)memset(
            &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
        candidate->deadline_verdict = NINLIL_DEADLINE_MISSED;
    }
    ninlil_rt_v1_refresh_target_aggregate(candidate);
    if (effect_possible_count != 0u) {
        candidate->deadline_verdict =
            NINLIL_DEADLINE_INDETERMINATE;
        candidate->reason =
            NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING;
    }
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_OC,
        NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT);
    if (status != NINLIL_OK) {
        return status;
    }
    out_result->transitions_consumed += 1u;
    if (candidate->terminal != 0u) {
        if (runtime->nonterminal_transaction_count > 0u) {
            runtime->nonterminal_transaction_count -= 1u;
        }
        note_terminal_outcome(runtime, candidate->outcome, out_result);
    }
    return NINLIL_OK;
}

static ninlil_status_t handle_evidence_close(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *candidate =
        &runtime->transaction_scratch;
    uint64_t evidence_close_at_ms;
    ninlil_status_t status;
    uint32_t index;
    uint32_t closed_count = 0u;

    if (txn->terminal != 0u
        || txn->family != NINLIL_FAMILY_DESIRED_STATE
        || txn->origin_admission == 0u
        || !checked_evidence_close(txn, &evidence_close_at_ms)
        || !timer_is_due(
            clock_sample,
            &txn->deadline_clock_epoch_id,
            evidence_close_at_ms)) {
        return NINLIL_OK;
    }
    *candidate = *txn;
    for (index = 0u; index < candidate->bound_target_count; ++index) {
        ninlil_rt_target_slot_t *target =
            &candidate->bound_targets[index];

        if (target->in_use == 0u || target->terminal != 0u
            || target->deadline_verdict
                != NINLIL_DEADLINE_INDETERMINATE
            || target->reason
                != NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING) {
            continue;
        }
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
        target->outcome = NINLIL_OUTCOME_UNKNOWN;
        target->reason =
            NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING;
        closed_count += 1u;
    }
    if (closed_count == 0u) {
        return NINLIL_OK;
    }
    candidate->active_target_index =
        NINLIL_RT_V1_NO_ACTIVE_TARGET;
    candidate->attempt_prepared = 0u;
    (void)memset(
        &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
    ninlil_rt_v1_refresh_target_aggregate(candidate);
    if (candidate->terminal == 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    candidate->deadline_verdict =
        NINLIL_DEADLINE_INDETERMINATE;
    candidate->reason =
        NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING;
    status = commit_transaction_snapshot_internal(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_OC,
        NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT,
        0,
        "controller.before_evidence_close_commit",
        "controller.after_evidence_close_commit");
    if (status != NINLIL_OK) {
        return status;
    }
    if (runtime->nonterminal_transaction_count > 0u) {
        runtime->nonterminal_transaction_count -= 1u;
    }
    out_result->transitions_consumed += 1u;
    note_terminal_outcome(runtime, candidate->outcome, out_result);
    return NINLIL_OK;
}

static ninlil_status_t handle_timeout_retry(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;
    ninlil_rt_transaction_slot_t *candidate;

    if (!ninlil_rt_v1_family_is_downlink(txn->family)
        || txn->effect_deadline_ms == 0u
        || txn->effect_deadline_ms >= NINLIL_NO_DEADLINE) {
        return NINLIL_OK;
    }
    if (clock_sample->now_ms < txn->effect_deadline_ms) {
        return NINLIL_OK;
    }
    if (txn->family == NINLIL_FAMILY_DESIRED_STATE
        && txn->origin_admission != 0u) {
        if (!desired_effect_deadline_needs_reduction(txn)) {
            return NINLIL_OK;
        }
        return reduce_desired_effect_deadline(
            runtime, txn, out_result);
    }
    if ((txn->delivery_phase == NINLIL_RT_DELIVERY_NONE
            || txn->delivery_phase == NINLIL_RT_DELIVERY_QUEUED)
        && txn->send_observation_closed == 0u
        && txn->evidence_recorded == 0u) {
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH,
            out_result);
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

    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    candidate->retry_budget -= 1u;
    if (candidate->retry_backoff_ms == 0u) {
        candidate->retry_backoff_ms = 100u;
    }
    if (clock_sample->now_ms
        > UINT64_MAX - candidate->retry_backoff_ms) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_COUNTER_EXHAUSTED;
        return NINLIL_E_DEGRADED;
    }
    candidate->next_retry_ms =
        clock_sample->now_ms + candidate->retry_backoff_ms;
    candidate->next_retry_clock_epoch_id = clock_sample->clock_epoch_id;
    if (candidate->retry_budget == 0u) {
        return commit_terminal_outcome(
            runtime,
            txn,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT,
            out_result);
    }
    candidate->pending_dispatch = 1u;
    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_RT,
        NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT);
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
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    uint32_t order_capacity;
    uint32_t order_count = 0u;
    uint32_t index;
    uint32_t pass;
    uint32_t availability_resumed = 0u;
    ninlil_status_t status = NINLIL_OK;
    int defer_ingress = 0;

    if (runtime == NULL || clock_sample == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        if (ninlil_rt_v1_transaction_has_invalid_active_receipt_timer(
                &runtime->transactions[index])) {
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_CLOCK_UNCERTAIN;
            return NINLIL_E_DEGRADED;
        }
    }

    status = automatic_availability_resume_one(
        runtime,
        clock_sample,
        transition_budget,
        out_result,
        &availability_resumed);
    if (status != NINLIL_OK) {
        return status;
    }
    if (availability_resumed != 0u
        || out_result->work_remaining != 0u) {
        return NINLIL_OK;
    }

    defer_ingress = endpoint_has_pending_uplink_dispatch(runtime);
    if (!defer_ingress) {
        status = ninlil_rt_v1_bearer_ingress_step(
            runtime,
            clock_sample,
            &ingress_budget,
            callback_budget,
            transition_budget,
            send_budget,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
        if (out_result->ingress_processed != 0u) {
            out_result->work_remaining = 1u;
            runtime->pending_work = 1u;
            return NINLIL_OK;
        }
    }

    order_capacity = runtime->transaction_capacity;
    if (order_capacity == 0u) {
        return NINLIL_OK;
    }
    {
        uint32_t stack_order[
            NINLIL_RT_V1_MAX_SCHEDULABLE_TRANSACTIONS];
        uint32_t *order;

        if (order_capacity > (uint32_t)(sizeof(stack_order) / sizeof(stack_order[0]))) {
            order_capacity = (uint32_t)(sizeof(stack_order) / sizeof(stack_order[0]));
        }
        order = stack_order;

        order_count = ninlil_rt_v1_delivery_collect_work_order(
            runtime, clock_sample, order, order_capacity);

        for (pass = 0u; pass < order_count; ++pass) {
            ninlil_rt_transaction_slot_t *txn =
                &runtime->transactions[order[pass]];
            ninlil_rt_service_slot_t *receiver;
            uint32_t required_transitions;
            uint32_t transitions_before;
            uint32_t catch_up_changed = 0u;

            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }
            if (transaction_waits_for_mfdt_scheduler(txn)) {
                /*
                 * No timeout, attempt, permit, retry, normal bearer send, or
                 * terminal transition is consumed while the MFDT scheduler
                 * seam is unavailable. Preserve ADMITTED_READY/pending across
                 * steps and restart, and tell the owner loop that work
                 * remains.
                 */
                out_result->work_remaining = 1u;
                runtime->pending_work = 1u;
                continue;
            }
            status = ninlil_rt_v1_targeted_management_catch_up(
                runtime,
                txn,
                clock_sample,
                transition_budget,
                out_result,
                &catch_up_changed,
                NINLIL_RT_V1_INPUT_PRIORITY_SCHEDULER_AFTER_READY);
            if (status != NINLIL_OK) {
                return status;
            }
            if (txn->terminal != 0u) {
                /*
                 * A receiver-side transaction becomes terminal once its
                 * Receipt send is durably observed.  A later APPLICATION
                 * attempt may reopen only that cached reverse Receipt.  Keep
                 * terminal outcome authority intact while allowing the
                 * requeued ingress work to send the Receipt for the fresh
                 * attempt id.
                 */
                if (txn->origin_admission == 0u
                    && txn->evidence_recorded != 0u
                    && txn->ingress_pending != 0u
                    && txn->reverse_receipt_closed == 0u) {
                    status = ninlil_rt_v1_bearer_reduce_pending_ingress(
                        runtime,
                        txn,
                        clock_sample,
                        callback_budget,
                        transition_budget,
                        send_budget,
                        out_result);
                    if (status != NINLIL_OK) {
                        return status;
                    }
                }
                continue;
            }
            if (catch_up_changed != 0u
                && txn->family == NINLIL_FAMILY_EVENT_FACT) {
                continue;
            }
            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }
            if (txn->family == NINLIL_FAMILY_DESIRED_STATE
                && txn->origin_admission != 0u) {
                if (!ninlil_rt_v1_select_dispatch_target(
                        txn, clock_sample, NULL)) {
                    continue;
                }
            }
            status = handle_delivery_token_timeout(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            if (txn->token_state == NINLIL_RT_TOKEN_EXPIRED) {
                continue;
            }
            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }
            if (txn->ingress_pending != 0u) {
                status = ninlil_rt_v1_bearer_reduce_pending_ingress(
                    runtime,
                    txn,
                    clock_sample,
                    callback_budget,
                    transition_budget,
                    send_budget,
                    out_result);
                if (status != NINLIL_OK) {
                    return status;
                }
                continue;
            }
            status = handle_timeout_retry(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            if (txn->terminal != 0u) {
                continue;
            }
            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }
            transitions_before = out_result->transitions_consumed;
            status = handle_evidence_close(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            if (out_result->transitions_consumed != transitions_before
                || txn->terminal != 0u) {
                continue;
            }
            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }
            transitions_before = out_result->transitions_consumed;
            status = handle_event_endpoint_receipt_timeout(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            if (out_result->transitions_consumed != transitions_before) {
                continue;
            }
            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }
            status = handle_bearer_receipt_timeout(
                runtime, txn, clock_sample, out_result);
            if (status != NINLIL_OK) {
                return status;
            }
            if (txn->terminal != 0u) {
                continue;
            }
            if (out_result->transitions_consumed >= transition_budget) {
                out_result->work_remaining = 1u;
                return NINLIL_OK;
            }

            if (txn->family == NINLIL_FAMILY_EVENT_FACT
                && (txn->delivery_phase == NINLIL_RT_DELIVERY_NONE
                    || txn->delivery_phase == NINLIL_RT_DELIVERY_QUEUED)
                && txn->pending_dispatch != 0u
                && runtime->config.role == NINLIL_ROLE_ENDPOINT
                && !ninlil_rt_v1_bearer_path_available(runtime)) {
                status = park_event_fact(
                    runtime,
                    txn,
                    NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE,
                    out_result);
                if (status != NINLIL_OK) {
                    return status;
                }
                continue;
            }

            if (ninlil_rt_v1_family_is_uplink(txn->family)
                && runtime->config.role == NINLIL_ROLE_ENDPOINT
                && txn->pending_dispatch != 0u
                && ninlil_rt_v1_bearer_path_available(runtime)) {
                if (txn->attempt_prepared == 0u) {
                    status = prepare_application_attempt(
                        runtime, txn, out_result);
                    if (status != NINLIL_OK) {
                        return status;
                    }
                    continue;
                }
                if (out_result->bearer_sends >= send_budget) {
                    out_result->work_remaining = 1u;
                    return NINLIL_OK;
                }
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
                required_transitions = 0u;
                if (ninlil_rt_v1_bearer_path_available(runtime)) {
                    if (txn->attempt_prepared == 0u) {
                        status = prepare_application_attempt(
                            runtime, txn, out_result);
                        if (status != NINLIL_OK) {
                            return status;
                        }
                        continue;
                    }
                    required_transitions = 1u;
                    if (out_result->bearer_sends >= send_budget) {
                        out_result->work_remaining = 1u;
                        return NINLIL_OK;
                    }
                }
                if (required_transitions
                    > transition_budget - out_result->transitions_consumed) {
                    out_result->work_remaining = 1u;
                    return NINLIL_OK;
                }
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
                required_transitions =
                    txn->evidence_recorded != 0u
                    ? (txn->outcome_recorded == 0u ? 1u : 0u)
                    : (txn->delivery_phase < NINLIL_RT_DELIVERY_STARTED
                            ? 3u
                            : 2u);
                if (required_transitions
                        > transition_budget
                            - out_result->transitions_consumed
                    || (txn->evidence_recorded == 0u
                        && out_result->callbacks_invoked >= callback_budget)) {
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
        if (txn_needs_work(
                &runtime->transactions[index], clock_sample)) {
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
            transition_budget,
            send_budget,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
    }
    return NINLIL_OK;
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
        ninlil_rt_transaction_slot_t *restored =
            &runtime->transaction_scratch;
        ninlil_status_t status;
        uint16_t marker_prefix;
        int is_tx_marker;

        key.data = key_buf;
        key.capacity = (uint32_t)sizeof(key_buf);
        key.length = 0u;
        value.data = runtime->durable_scan_value;
        value.capacity = NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES;
        value.length = 0u;
        st = storage->iter_next(storage->user, iter, &key, &value);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            return NINLIL_E_STORAGE;
        }
        if (key.length < 2u || key.data == NULL) {
            continue;
        }

        marker_prefix =
            (uint16_t)(((uint16_t)key.data[0] << 8) | key.data[1]);
        is_tx_marker = marker_prefix == NINLIL_RT_V1_MARKER_TX;
        if (tx_admission_only != 0u) {
            if (is_tx_marker == 0) {
                continue;
            }
        } else if (is_tx_marker != 0) {
            continue;
        }

        if (tx_admission_only == 0u) {
            uint32_t capacity_recognized = 0u;
            int bearer_state_restore =
                ninlil_rt_v1_bearer_restore_state_marker(
                    runtime,
                    (ninlil_bytes_view_t){key.data, key.length},
                    (ninlil_bytes_view_t){value.data, value.length});

            if (bearer_state_restore < 0) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (bearer_state_restore > 0) {
                continue;
            }
            status = ninlil_rt_v1_restore_resource_ledger_row(
                runtime,
                (ninlil_bytes_view_t){key.data, key.length},
                (ninlil_bytes_view_t){value.data, value.length},
                &capacity_recognized);
            if (status != NINLIL_OK) {
                storage->iter_close(storage->user, iter);
                return status;
            }
            if (capacity_recognized != 0u) {
                continue;
            }
        }

        if (is_tx_marker != 0) {
            if (key.length != NINLIL_RT_V1_TXN_MARKER_BYTES) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_UNSUPPORTED;
            }
            (void)memcpy(
                txn_id.bytes, &key.data[2], sizeof(txn_id.bytes));
            if (value.length == 33u || value.length == 46u) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_UNSUPPORTED;
            }
            status = ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){value.data, value.length},
                &runtime->transaction_decode_scratch,
                restored);
            if (status != NINLIL_OK) {
                storage->iter_close(storage->user, iter);
                return status;
            }
            if (memcmp(
                    restored->transaction_id.bytes,
                    txn_id.bytes,
                    sizeof(txn_id.bytes)) != 0
                || restored->origin_admission == 0u
                || restored->transaction_sequence == 0u
                || restored->record_revision == 0u) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (restored->reservation_active != 0u) {
                restored->reservation_evidence_units |=
                    NINLIL_RT_V1_RESTART_EXPECTED_RESERVATION;
                restored->reservation_active = 0u;
            }
            slot = ninlil_rt_find_transaction(runtime, &txn_id);
            if (slot == NULL) {
                slot = ninlil_rt_alloc_transaction(runtime);
            }
            if (slot == NULL) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_CAPACITY_EXHAUSTED;
            }
            *slot = *restored;
            continue;
        }

        if (is_transaction_snapshot_prefix(key.data, key.length)) {
            if (key.length != NINLIL_RT_V1_TXN_MARKER_BYTES) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_UNSUPPORTED;
            }
            (void)memcpy(
                txn_id.bytes, &key.data[2], sizeof(txn_id.bytes));
            status = ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){value.data, value.length},
                &runtime->transaction_decode_scratch,
                restored);
            if (status != NINLIL_OK) {
                storage->iter_close(storage->user, iter);
                return status;
            }
            if (memcmp(
                    restored->transaction_id.bytes,
                    txn_id.bytes,
                    sizeof(txn_id.bytes)) != 0
                || restored->record_revision == 0u) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (restored->reservation_active != 0u) {
                restored->reservation_evidence_units |=
                    NINLIL_RT_V1_RESTART_EXPECTED_RESERVATION;
                restored->reservation_active = 0u;
            }
            slot = ninlil_rt_find_transaction(runtime, &txn_id);
            if (slot == NULL) {
                if (restored->origin_admission != 0u) {
                    storage->iter_close(storage->user, iter);
                    return NINLIL_E_STORAGE_CORRUPT;
                }
                slot = ninlil_rt_alloc_transaction(runtime);
                if (slot == NULL) {
                    storage->iter_close(storage->user, iter);
                    return NINLIL_E_CAPACITY_EXHAUSTED;
                }
            }
            if (restored->origin_admission != slot->origin_admission) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            if (restored->record_revision > slot->record_revision) {
                *slot = *restored;
            } else if (restored->record_revision == slot->record_revision
                && memcmp(restored, slot, sizeof(*restored)) != 0) {
                /*
                 * Revision is the identity of one canonical snapshot.
                 * Two marker families may retain the same revision only when
                 * their decoded canonical contents are byte-for-byte equal.
                 */
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            continue;
        }

        if (marker_prefix == NINLIL_RT_V1_EVENT_RESUME_PREFIX
            || marker_prefix == NINLIL_RT_V1_EVENT_DISCARD_PREFIX) {
            ninlil_rt_v1_event_ledger_record_t event_record;
            ninlil_rt_v1_event_ledger_kind_t expected_kind =
                marker_prefix == NINLIL_RT_V1_EVENT_RESUME_PREFIX
                ? NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME
                : NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD;

            if (key.length != NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_UNSUPPORTED;
            }
            status = ninlil_rt_v1_event_ledger_validate(
                expected_kind,
                (ninlil_bytes_view_t){value.data, value.length});
            if (status != NINLIL_OK) {
                storage->iter_close(storage->user, iter);
                return status;
            }
            (void)memset(&event_record, 0, sizeof(event_record));
            status = ninlil_rt_v1_event_ledger_decode(
                (ninlil_bytes_view_t){value.data, value.length},
                &event_record);
            if (status != NINLIL_OK
                || event_record.operation_kind != expected_kind
                || memcmp(
                    event_record.transaction_id.bytes,
                    &key.data[2],
                    sizeof(event_record.transaction_id.bytes)) != 0
                || memcmp(
                    event_record.operation_id.bytes,
                    &key.data[
                        NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES],
                    sizeof(event_record.operation_id.bytes)) != 0) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            continue;
        }

        if (marker_prefix == NINLIL_RT_V1_MARKER_RV) {
            uint32_t payload_length = 0u;
            ninlil_rt_v1_bearer_route_t route =
                NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;

            if (key.length != NINLIL_RT_V1_TXN_MARKER_BYTES) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_UNSUPPORTED;
            }
            (void)memcpy(
                txn_id.bytes, &key.data[2], sizeof(txn_id.bytes));
            status = ninlil_rt_v1_reservation_marker_decode(
                (ninlil_bytes_view_t){value.data, value.length},
                &payload_length,
                &route);
            if (status != NINLIL_OK) {
                storage->iter_close(storage->user, iter);
                return status;
            }
            slot = ninlil_rt_find_transaction(runtime, &txn_id);
            if (slot == NULL
                || slot->payload_length != payload_length
                || (slot->bearer_route != 0u
                    && slot->bearer_route != (uint8_t)route)) {
                storage->iter_close(storage->user, iter);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            slot->bearer_route = (uint8_t)route;
            slot->reservation_active = 1u;
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
    {
#if defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    && (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING != 0)
        /*
         * Domain create pre-seeds capacity from accepted limits after T0–T6.
         * Preserve a complete pre-seed so LAB capacity-marker mismatch cannot
         * fence Domain publication; still scan TX/delivery markers.
         */
        uint32_t domain_capacity_preseeded =
            (runtime->resource_ledger_restore_mask
                == ((1u << NINLIL_MODEL_RESOURCE_KIND_COUNT) - 1u))
            ? 1u
            : 0u;
#else
        uint32_t domain_capacity_preseeded = 0u;
#endif
        if (domain_capacity_preseeded == 0u) {
            runtime->resource_ledger_restore_mask = 0u;
        }

    st = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    status = delivery_restart_scan_pass(runtime, storage, txn, 1u);
    if (status == NINLIL_OK) {
        status = delivery_restart_scan_pass(runtime, storage, txn, 0u);
    }
    if (status == NINLIL_OK
        && runtime->resource_ledger_restore_mask
            != ((1u << NINLIL_MODEL_RESOURCE_KIND_COUNT) - 1u)) {
        if (domain_capacity_preseeded != 0u) {
            /* Keep pre-seeded Domain capacity; ignore partial LAB overlay. */
            runtime->resource_ledger_restore_mask =
                (1u << NINLIL_MODEL_RESOURCE_KIND_COUNT) - 1u;
        } else {
            status = NINLIL_E_STORAGE_CORRUPT;
        }
    }
    }

    (void)storage->rollback(storage->user, txn);
    if (status == NINLIL_OK) {
        uint32_t index;

        runtime->transaction_count = 0u;
        runtime->nonterminal_transaction_count = 0u;
        runtime->pending_work = 0u;
        for (index = 0u; index < runtime->transaction_capacity; ++index) {
            ninlil_rt_transaction_slot_t *slot =
                &runtime->transactions[index];

            if (slot->in_use == 0u) {
                continue;
            }
            {
                uint32_t expected_reservation =
                    (slot->reservation_evidence_units
                        & NINLIL_RT_V1_RESTART_EXPECTED_RESERVATION)
                    != 0u;

                slot->reservation_evidence_units &=
                    ~NINLIL_RT_V1_RESTART_EXPECTED_RESERVATION;
                if (expected_reservation != slot->reservation_active) {
                    return NINLIL_E_STORAGE_CORRUPT;
                }
            }
            if (slot->token_state == NINLIL_RT_TOKEN_ACTIVE) {
                ninlil_rt_transaction_slot_t *candidate =
                    &runtime->transaction_scratch;

                *candidate = *slot;
                candidate->token_state =
                    NINLIL_RT_TOKEN_EXPIRED;
                candidate->deferred_wait = 0u;
                candidate->pending_dispatch = 0u;
                candidate->ingress_pending = 0u;
                candidate->delivery_phase =
                    NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
                set_recovery_result(
                    candidate, NINLIL_REASON_OUTCOME_UNKNOWN);
                status = ninlil_rt_v1_commit_transaction_snapshot(
                    runtime,
                    slot,
                    candidate,
                    NINLIL_RT_V1_MARKER_EV,
                    NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT);
                if (status != NINLIL_OK) {
                    return status;
                }
                runtime->health = NINLIL_HEALTH_DEGRADED;
                runtime->degraded_reason =
                    NINLIL_REASON_OUTCOME_UNKNOWN;
            }
            runtime->transaction_count += 1u;
            if (slot->transaction_sequence > runtime->transaction_sequence) {
                runtime->transaction_sequence =
                    slot->transaction_sequence;
            }
            if (slot->terminal == 0u && slot->event_discarded == 0u) {
                runtime->nonterminal_transaction_count += 1u;
            } else {
                slot->reservation_active = 0u;
            }
            if (slot->terminal == 0u && slot->event_discarded == 0u
                && slot->delivery_phase != NINLIL_RT_DELIVERY_PARKED
                && slot->pending_dispatch != 0u) {
                runtime->pending_work = 1u;
            }
#if defined(NINLIL_MFDT_V1_PRIVATE)
            /*
             * The private Runtime owner opens and recovers its derived MFDT
             * sidecar when explicitly configured.  Foundation restore never
             * consults the legacy process-global spine or invents custody.
             */
            if (slot->terminal == 0u && slot->event_discarded == 0u
                && slot->bearer_route
                    == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
                runtime->pending_work = 1u;
            }
#endif
        }
        status = ninlil_rt_v1_validate_restored_resource_ledger(runtime);
        if (status == NINLIL_OK) {
            status = ninlil_rt_v1_event_ledger_boot_validate(runtime);
        }
    }
    return status;
}
