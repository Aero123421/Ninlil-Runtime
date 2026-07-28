#include "runtime_v1_spine_durable.h"

#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"
#include "submission_admission.h"
#include "submission_canonical_v1.h"
#include "submission_preflight.h"

#include <string.h>

#define NINLIL_RT_V1_MARKER_CN 0x434eu

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

static int id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < (uint32_t)sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
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

ninlil_status_t ninlil_rt_v1_spine_service_register_commit(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    uint32_t *inout_slot_index)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t begin_status;
    ninlil_status_t status;
    uint8_t marker_key[32];
    uint8_t marker_value[16];
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;

    (void)descriptor;
    (void)inout_slot_index;
    begin_status = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_WRITE, &txn);
    if (begin_status != NINLIL_STORAGE_OK) {
        return map_storage_mutation_status(runtime, begin_status);
    }

    marker_key[0] = 0x4eu;
    marker_key[1] = 0x52u;
    marker_key[2] = 0x53u;
    marker_key[3] = (uint8_t)(*inout_slot_index & 0xffu);
    (void)memset(&marker_key[4], 0, sizeof(marker_key) - 4u);
    (void)memset(marker_value, 0xA1, sizeof(marker_value));
    key = (ninlil_bytes_view_t){marker_key, 4u};
    value = (ninlil_bytes_view_t){marker_value, sizeof(marker_value)};

    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT,
        storage,
        txn,
        key,
        value,
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    return storage_txn_commit_full(runtime, txn);
}

static ninlil_model_descriptor_contract_extension_t descriptor_contract_from(
    const ninlil_service_descriptor_t *descriptor)
{
    ninlil_model_descriptor_contract_extension_t contract;

    (void)memset(&contract, 0, sizeof(contract));
    contract.direction = descriptor->direction;
    contract.admission_authority = descriptor->admission_authority;
    contract.apply_contract = descriptor->apply_contract;
    contract.custody_policy = descriptor->custody_policy;
    contract.target_limit = descriptor->target_limit;
    contract.max_attempts_per_target_per_cycle =
        descriptor->max_attempts_per_target_per_cycle;
    contract.attempt_receipt_timeout_ms =
        descriptor->attempt_receipt_timeout_ms;
    contract.retry_backoff_ms = descriptor->retry_backoff_ms;
    contract.application_completion_timeout_ms =
        descriptor->application_completion_timeout_ms;
    contract.required_dedup_window_ms = descriptor->required_dedup_window_ms;
    return contract;
}

static void copy_grant_snapshot(
    ninlil_model_origin_grant_snapshot_t *out_grant,
    const ninlil_origin_authorization_decision_t *decision)
{
    out_grant->provider_id = decision->provider_id;
    out_grant->provider_revision = decision->provider_revision;
    out_grant->decision_digest = decision->decision_digest;
    out_grant->grant_id = decision->grant_id;
    out_grant->grant_revision = decision->grant_revision;
    out_grant->clock_epoch_id = decision->clock_epoch_id;
    out_grant->evaluated_at_ms = decision->evaluated_at_ms;
    out_grant->valid_from_ms = decision->valid_from_ms;
    out_grant->expires_at_ms = decision->expires_at_ms;
    out_grant->retry_delay_ms = decision->retry_delay_ms;
    out_grant->max_payload_bytes = decision->max_payload_bytes;
    out_grant->max_active_spool_count = decision->max_active_spool_count;
    out_grant->max_active_spool_bytes = decision->max_active_spool_bytes;
    out_grant->rate_window_ms = decision->rate_window_ms;
    out_grant->max_admissions_per_window = decision->max_admissions_per_window;
    out_grant->max_attempts_per_retry_cycle =
        decision->max_attempts_per_retry_cycle;
}

static ninlil_status_t fill_origin_authority(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    ninlil_model_submission_preflight_input_t *input,
    const ninlil_time_sample_t *admission_sample)
{
    const ninlil_origin_authorization_ops_t *origin;
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    ninlil_origin_auth_status_t auth_status;

    if (slot->model_service.family != NINLIL_FAMILY_EVENT_FACT
        && slot->model_service.family != NINLIL_FAMILY_LATEST_STATE_RESERVED
        && slot->model_service.family != NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE;
        return NINLIL_OK;
    }

    origin = runtime->platform->origin_authorization;
    if (origin == NULL || origin->evaluate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    request.environment = runtime->config.environment;
    request.source = slot->model_service.source;
    if (submission->target_count == 1u && submission->targets != NULL) {
        request.target = submission->targets[0];
    }
    request.service = slot->model_service.identity;
    request.event_id = submission->event_id;
    request.content_digest = submission->content_digest;
    request.required_evidence = submission->required_evidence;
    request.payload_length = (uint32_t)submission->payload.length;
    request.active_spool_count =
        (uint32_t)input->event_grant_usage.active_spool_count;
    request.admissions_in_current_window =
        (uint32_t)input->quota.admissions_in_window;
    request.active_spool_bytes = input->event_grant_usage.active_spool_bytes;
    if (input->clock.now_ms >= 10000u) {
        request.current_window_started_at_ms =
            input->clock.now_ms - (input->clock.now_ms % 10000u);
    } else {
        request.current_window_started_at_ms = 0u;
    }
    request.now = *admission_sample;

    (void)memset(&decision, 0, sizeof(decision));
    auth_status = origin->evaluate(origin->user, &request, &decision);
    if (auth_status == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_TEMPORARY_FAILURE;
        return NINLIL_OK;
    }
    if (auth_status == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_PERMANENT_OR_INVALID;
        return NINLIL_OK;
    }
    if (auth_status != NINLIL_ORIGIN_AUTH_OK) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (decision.allowed == 0u) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_DENY;
        input->authority.deny_reason = decision.reason;
        input->authority.deny_guidance = decision.retry_guidance;
        input->authority.deny_retry_delay_ms = decision.retry_delay_ms;
        copy_grant_snapshot(&input->authority.grant, &decision);
        return NINLIL_OK;
    }

    input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_ALLOW;
    copy_grant_snapshot(&input->authority.grant, &decision);
    return NINLIL_OK;
}

static ninlil_status_t fill_preflight_input(
    ninlil_model_submission_preflight_input_t *input,
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_time_sample_t *admission_sample)
{
    ninlil_status_t status;

    (void)memset(input, 0, sizeof(*input));
    input->service = slot->model_service;
    input->submission.schema_major = submission->schema_major;
    input->submission.schema_minor = submission->schema_minor;
    input->submission.target_count = submission->target_count;
    if (submission->target_count == 1u && submission->targets != NULL) {
        input->submission.target = submission->targets[0];
    }
    input->submission.required_evidence = submission->required_evidence;
    input->submission.payload_length = submission->payload.length;
    input->submission.content_digest = submission->content_digest;
    input->submission.content_digest_matches = 1u;
    input->submission.effect_deadline_ms = submission->effect_deadline_ms;
    input->submission.evidence_grace_ms = submission->evidence_grace_ms;
    input->submission.event_id = submission->event_id;
    input->submission.generation = submission->generation;
    if (submission->idempotency_key.length > 0u
        && submission->idempotency_key.length <= 64u
        && submission->idempotency_key.data != NULL) {
        input->submission.idempotency_key.length =
            (uint8_t)submission->idempotency_key.length;
        (void)memcpy(
            input->submission.idempotency_key.bytes,
            submission->idempotency_key.data,
            submission->idempotency_key.length);
    }
    status = ninlil_rt_canonical_submission_digest_v1(
        &slot->descriptor,
        submission,
        &input->submission.canonical_submission_digest);
    if (status != NINLIL_OK) {
        return status;
    }
    input->clock.state = NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED;
    input->clock.clock_epoch_id = admission_sample->clock_epoch_id;
    input->clock.now_ms = admission_sample->now_ms;
    input->last_transaction_sequence = runtime->transaction_sequence;
    input->last_scheduler_owner_sequence =
        runtime->last_assigned_scheduler_owner_sequence;
    status = fill_origin_authority(
        runtime, slot, submission, input, admission_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    input->quota.inflight_count = slot->quota_inflight;
    input->quota.admissions_in_window = slot->quota_admissions;
    input->quota.payload_bytes_in_window = slot->quota_payload_bytes;
    input->quota.window_is_current = 1u;
    input->resource_ledger = runtime->resource_ledger;
    input->caller_key_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
    input->event_id_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
    return NINLIL_OK;
}

static ninlil_status_t read_admission_clock(
    ninlil_runtime_t *runtime,
    ninlil_time_sample_t *out_sample)
{
    ninlil_port_status_t status;

    (void)memset(out_sample, 0, sizeof(*out_sample));
    status = runtime->platform->clock->now(
        runtime->platform->clock->user, out_sample);
    if (status == NINLIL_PORT_TEMPORARY_FAILURE) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (status != NINLIL_PORT_OK
        || out_sample->abi_version != NINLIL_ABI_VERSION
        || out_sample->struct_size != sizeof(*out_sample)
        || out_sample->trust != NINLIL_CLOCK_TRUSTED
        || id_is_zero(&out_sample->clock_epoch_id)
        || out_sample->reserved_zero != 0u) {
        return NINLIL_E_DEGRADED;
    }
    return NINLIL_OK;
}

static ninlil_status_t fill_transaction_id_draws(
    ninlil_runtime_t *runtime,
    ninlil_model_id_allocation_input_t *input)
{
    uint32_t index;

    for (index = 0u;
         index < NINLIL_MODEL_TRANSACTION_ID_MAX_DRAWS;
         ++index) {
        ninlil_model_transaction_id_draw_t *draw = &input->draws[index];
        ninlil_port_status_t status;

        draw->ordinal = index + 1u;
        status = runtime->platform->entropy->fill(
            runtime->platform->entropy->user,
            draw->candidate.bytes,
            (uint32_t)sizeof(draw->candidate.bytes));
        input->draw_count = index + 1u;
        if (status == NINLIL_PORT_TEMPORARY_FAILURE) {
            draw->entropy_state =
                NINLIL_MODEL_ENTROPY_DRAW_TEMPORARY_FAILURE;
            draw->collision_state =
                NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
            continue;
        }
        if (status != NINLIL_PORT_OK) {
            draw->entropy_state =
                NINLIL_MODEL_ENTROPY_DRAW_PERMANENT_FAILURE;
            draw->collision_state =
                NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
            continue;
        }
        draw->entropy_state = NINLIL_MODEL_ENTROPY_DRAW_FULL;
        if (id_is_zero(&draw->candidate)) {
            draw->collision_state =
                NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
            continue;
        }
        draw->collision_state =
            ninlil_rt_find_transaction(runtime, &draw->candidate) == NULL
            ? NINLIL_MODEL_TRANSACTION_ID_UNIQUE
            : NINLIL_MODEL_TRANSACTION_ID_COLLISION;
        if (draw->collision_state == NINLIL_MODEL_TRANSACTION_ID_UNIQUE) {
            return NINLIL_OK;
        }
    }
    return NINLIL_OK;
}

static void fill_admitted_transaction(
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_model_admission_write_set_t *write_set,
    const ninlil_time_sample_t *admission_sample)
{
    (void)memset(transaction, 0, sizeof(*transaction));
    transaction->in_use = 1u;
    transaction->origin_admission = 1u;
    transaction->transaction_id = write_set->transaction_id;
    transaction->service_app_id =
        slot->descriptor.local_application_instance_id;
    transaction->event_id = submission->event_id;
    transaction->source = write_set->plan.source;
    transaction->service = write_set->plan.service;
    transaction->content_digest = submission->content_digest;
    transaction->family = slot->model_service.family;
    transaction->required_evidence = submission->required_evidence;
    transaction->latest_evidence =
        write_set->initial_family_snapshot.latest_evidence;
    transaction->deadline_verdict =
        write_set->initial_family_snapshot.deadline_verdict;
    transaction->transaction_sequence =
        write_set->plan.transaction_sequence;
    transaction->record_revision =
        write_set->transaction_record_revision;
    transaction->pending_dispatch = 1u;
    transaction->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    transaction->effect_deadline_ms =
        write_set->plan.absolute_effect_deadline_ms;
    transaction->evidence_grace_ms = submission->evidence_grace_ms;
    transaction->admission_clock_epoch_id =
        write_set->plan.admission_clock_epoch_id;
    transaction->deadline_clock_epoch_id =
        write_set->plan.deadline_clock_epoch_id;
    transaction->generation = submission->generation;
    transaction->payload_length = (uint32_t)submission->payload.length;
    if (submission->payload.length != 0u) {
        (void)memcpy(
            transaction->owned_payload,
            submission->payload.data,
            submission->payload.length);
    }
    transaction->semantic_priority =
        ninlil_rt_v1_semantic_priority_for_family(slot->model_service.family);
    transaction->bearer_route =
        (uint8_t)ninlil_rt_v1_default_bearer_route();
    transaction->reservation_active = 1u;
    transaction->reservation_evidence_units =
        slot->model_service.max_evidence_per_target + 1u;
    transaction->admitted_at_ms = admission_sample->now_ms;
    transaction->attempt_receipt_timeout_ms =
        slot->descriptor.attempt_receipt_timeout_ms;
    transaction->retry_backoff_ms = slot->descriptor.retry_backoff_ms;
    transaction->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    transaction->retry_cycle_id =
        transaction->family == NINLIL_FAMILY_EVENT_FACT ? 1u : 0u;
    transaction->attempt_in_cycle = 0u;
    transaction->cumulative_attempts = 0u;
    transaction->spool_revision =
        transaction->family == NINLIL_FAMILY_EVENT_FACT
        ? (write_set->event_spool_revision != 0u
                ? write_set->event_spool_revision : 1u)
        : 0u;
    transaction->assurance = write_set->assurance;
    transaction->bound_target_count = 1u;
    transaction->bound_targets[0].in_use = 1u;
    transaction->bound_targets[0].pending_dispatch = 1u;
    transaction->bound_targets[0].target = write_set->plan.target;
}

ninlil_status_t ninlil_rt_v1_spine_submit_admission(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result)
{
    ninlil_model_submission_preflight_input_t preflight_in;
    ninlil_model_submission_preflight_result_t preflight_out;
    ninlil_model_id_allocation_input_t alloc_in;
    ninlil_model_id_allocation_result_t alloc_out;
    ninlil_model_admission_commit_input_t commit_in;
    ninlil_model_admission_commit_result_t commit_out;
    ninlil_rt_transaction_slot_t *txn_slot;
    ninlil_rt_transaction_slot_t *admitted_transaction;
    ninlil_time_sample_t admission_sample;
    ninlil_status_t status;
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    uint8_t marker_key[32];
    uint32_t marker_value_length = 0u;

    status = read_admission_clock(runtime, &admission_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = fill_preflight_input(
        &preflight_in, runtime, slot, submission, &admission_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_submission_preflight(&preflight_in, &preflight_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (preflight_out.action == NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL) {
        *out_result = preflight_out.public_result;
        return preflight_out.api_status;
    }
    if (preflight_out.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_CAPACITY_BLOCK_COMMIT_REQUIRED) {
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
        status = ninlil_rt_v1_stage_resource_ledger(
            runtime,
            txn,
            NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
            &preflight_out.capacity_block.next_ledger);
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, txn);
            return status;
        }
        status = storage_txn_commit_full(runtime, txn);
        if (status != NINLIL_OK) {
            return status;
        }
        runtime->resource_ledger =
            preflight_out.capacity_block.next_ledger;
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_OK;
    }
    if (preflight_out.action
        != NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION) {
        return NINLIL_E_INTERNAL;
    }

    status = ninlil_rt_v1_check_bearer_payload_admission(
        ninlil_rt_v1_default_bearer_route(),
        (uint32_t)submission->payload.length,
        out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    if (out_result->kind == NINLIL_SUBMISSION_REJECTED) {
        return NINLIL_OK;
    }

    if (runtime->nonterminal_transaction_count
        >= runtime->config.limits.max_nonterminal_transactions) {
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_OK;
    }

    (void)memset(&alloc_in, 0, sizeof(alloc_in));
    alloc_in.preflight_plan = preflight_out.admission;
    alloc_in.descriptor_contract = descriptor_contract_from(&slot->descriptor);
    alloc_in.payload.length = submission->payload.length;
    if (submission->payload.length > 0u && submission->payload.data != NULL) {
        alloc_in.payload.length = submission->payload.length;
        alloc_in.payload.content_verified = 1u;
        alloc_in.payload.verified_content_digest = submission->content_digest;
        (void)memcpy(
            alloc_in.payload.bytes,
            submission->payload.data,
            submission->payload.length);
    }
    status = fill_transaction_id_draws(runtime, &alloc_in);
    if (status != NINLIL_OK) {
        return status;
    }

    status = ninlil_model_reduce_transaction_id_allocation(
        &alloc_in, &alloc_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (alloc_out.action != NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT) {
        *out_result = alloc_out.public_result;
        return alloc_out.api_status;
    }

    txn_slot = ninlil_rt_alloc_transaction(runtime);
    if (txn_slot == NULL) {
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_OK;
    }

    admitted_transaction = &runtime->transaction_scratch;
    fill_admitted_transaction(
        admitted_transaction,
        slot,
        submission,
        &alloc_out.write_set,
        &admission_sample);
    status = ninlil_rt_v1_transaction_record_encode(
        admitted_transaction,
        runtime->transaction_codec_bytes,
        NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES,
        &marker_value_length);
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
            &txn));
    if (status != NINLIL_OK) {
        return status;
    }

    marker_key[0] = 0x54u;
    marker_key[1] = 0x58u;
    (void)memcpy(
        &marker_key[2],
        alloc_out.write_set.transaction_id.bytes,
        sizeof(alloc_out.write_set.transaction_id.bytes));

    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        storage,
        txn,
        (ninlil_bytes_view_t){marker_key, 18u},
        (ninlil_bytes_view_t){
            runtime->transaction_codec_bytes, marker_value_length},
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        (void)storage->rollback(storage->user, txn);
        return status;
    }

    status = ninlil_rt_v1_stage_reservation_marker(
        runtime,
        txn,
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        &alloc_out.write_set.transaction_id,
        (uint32_t)submission->payload.length,
        ninlil_rt_v1_default_bearer_route());
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    status = ninlil_rt_v1_stage_resource_ledger(
        runtime,
        txn,
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        &preflight_out.admission.resources.committed_ledger);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }

    (void)memset(&commit_in, 0, sizeof(commit_in));
    commit_in.write_set = alloc_out.write_set;
    commit_in.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
    status = ninlil_model_reduce_admission_commit(&commit_in, &commit_out);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    if (commit_out.api_status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        *out_result = commit_out.public_result;
        return commit_out.api_status;
    }

    status = storage_txn_commit_full(runtime, txn);
    if (status != NINLIL_OK) {
        return status;
    }

    runtime->transaction_sequence =
        admitted_transaction->transaction_sequence;
    runtime->transaction_count += 1u;
    runtime->nonterminal_transaction_count += 1u;
    runtime->resource_ledger =
        preflight_out.admission.resources.committed_ledger;
    slot->quota_inflight += 1u;
    slot->quota_admissions += 1u;
    slot->quota_payload_bytes += submission->payload.length;

    *txn_slot = *admitted_transaction;
    runtime->pending_work = 1u;

    *out_result = commit_out.public_result;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_spine_cancel_admission(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;
    ninlil_rt_transaction_slot_t *candidate;
    int terminalized;
    ninlil_status_t status;

    if (runtime == NULL || transaction_id == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    txn = ninlil_rt_find_transaction(runtime, transaction_id);
    if (txn == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (txn->family != NINLIL_FAMILY_DESIRED_STATE) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (txn->cancel_kind != 0u) {
        out_result->kind = txn->cancel_kind;
        out_result->reason = txn->reason;
        out_result->current_outcome = txn->outcome;
        return NINLIL_OK;
    }
    if (txn->terminal != 0u) {
        out_result->kind = NINLIL_CANCEL_ALREADY_TERMINAL;
        out_result->reason = txn->reason;
        out_result->current_outcome = txn->outcome;
        return NINLIL_OK;
    }

    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    terminalized = candidate->pending_dispatch != 0u;
    if (terminalized != 0) {
        candidate->cancel_kind = NINLIL_CANCEL_FENCED_BEFORE_DISPATCH;
        candidate->reason = NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH;
        candidate->outcome = NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
        candidate->terminal = 1u;
        candidate->pending_dispatch = 0u;
        candidate->outcome_recorded = 1u;
    } else {
        candidate->cancel_kind = NINLIL_CANCEL_PENDING_REMOTE_FENCE;
        candidate->reason = NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE;
        candidate->outcome = NINLIL_OUTCOME_NONE;
    }

    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_CN,
        NINLIL_V1_DURABLE_OP_CANCEL_ADMISSION_COMMIT);
    if (status != NINLIL_OK) {
        return status;
    }
    if (terminalized != 0) {
        runtime->nonterminal_transaction_count -= 1u;
    }

    out_result->kind = txn->cancel_kind;
    out_result->reason = txn->reason;
    out_result->current_outcome = txn->outcome;
    return NINLIL_OK;
}
