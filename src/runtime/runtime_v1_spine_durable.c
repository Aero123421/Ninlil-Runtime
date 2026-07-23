#include "runtime_v1_spine_durable.h"

#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"
#include "submission_admission.h"
#include "submission_canonical_v1.h"
#include "submission_preflight.h"

#include <string.h>

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void set_id(ninlil_id128_t *id, uint8_t value)
{
    (void)memset(id, 0, sizeof(*id));
    id->bytes[sizeof(id->bytes) - 1u] = value;
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
        return NINLIL_E_STORAGE;
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
    ninlil_model_submission_preflight_input_t *input)
{
    const ninlil_origin_authorization_ops_t *origin;
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    ninlil_origin_auth_status_t auth_status;

    if (slot->model_service.family != NINLIL_FAMILY_EVENT_FACT) {
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
    request.current_window_started_at_ms = input->clock.now_ms;
    request.now = runtime->started_sample;

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
    const ninlil_submission_t *submission)
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
    input->clock.clock_epoch_id = runtime->started_sample.clock_epoch_id;
    input->clock.now_ms = runtime->started_sample.now_ms;
    input->last_transaction_sequence = runtime->transaction_sequence;
    input->last_scheduler_owner_sequence =
        runtime->last_assigned_scheduler_owner_sequence;
    status = fill_origin_authority(runtime, slot, submission, input);
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
    ninlil_status_t status;
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    uint8_t marker_key[32];
    uint8_t marker_value[NINLIL_RT_V1_TX_ADMISSION_MARKER_V2_BYTES];

    status = fill_preflight_input(&preflight_in, runtime, slot, submission);
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
    set_id(&alloc_in.draws[0].candidate, 0x42u);
    alloc_in.draws[0].ordinal = 1u;
    alloc_in.draws[0].entropy_state = NINLIL_MODEL_ENTROPY_DRAW_FULL;
    alloc_in.draws[0].collision_state = NINLIL_MODEL_TRANSACTION_ID_UNIQUE;
    alloc_in.draw_count = 1u;

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

    storage = runtime->platform->storage;
    if (storage->begin(
            storage->user, runtime->storage, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    marker_key[0] = 0x54u;
    marker_key[1] = 0x58u;
    (void)memcpy(&marker_key[2], alloc_out.write_set.transaction_id.bytes, 14u);
    ninlil_rt_v1_encode_tx_admission_marker_v2(
        marker_value,
        slot->model_service.family,
        &slot->descriptor.local_application_instance_id,
        submission->effect_deadline_ms,
        submission->generation,
        ninlil_rt_v1_semantic_priority_for_family(slot->model_service.family),
        (uint32_t)submission->payload.length,
        runtime->started_sample.now_ms);

    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        storage,
        txn,
        (ninlil_bytes_view_t){marker_key, 16u},
        (ninlil_bytes_view_t){marker_value, sizeof(marker_value)},
        &runtime->commit_unknown_fence);
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

    status = ninlil_rt_v1_commit_reservation_marker(
        runtime,
        &alloc_out.write_set.transaction_id,
        (uint32_t)submission->payload.length,
        ninlil_rt_v1_default_bearer_route());
    if (status != NINLIL_OK) {
        return status;
    }

    runtime->transaction_sequence += 1u;
    runtime->nonterminal_transaction_count += 1u;
    runtime->resource_ledger =
        preflight_out.admission.resources.committed_ledger;
    slot->quota_inflight += 1u;
    slot->quota_admissions += 1u;
    slot->quota_payload_bytes += submission->payload.length;

    txn_slot->in_use = 1u;
    txn_slot->terminal = 0u;
    txn_slot->transaction_id = alloc_out.write_set.transaction_id;
    txn_slot->service_app_id = slot->descriptor.local_application_instance_id;
    txn_slot->family = slot->model_service.family;
    txn_slot->transaction_sequence = runtime->transaction_sequence;
    txn_slot->pending_dispatch = 1u;
    txn_slot->cancel_kind = 0u;
    txn_slot->outcome = NINLIL_OUTCOME_NONE;
    txn_slot->reason = NINLIL_REASON_NONE;
    txn_slot->service_app_id = slot->descriptor.local_application_instance_id;
    txn_slot->event_id = submission->event_id;
    txn_slot->content_digest = submission->content_digest;
    txn_slot->effect_deadline_ms = submission->effect_deadline_ms;
    txn_slot->generation = submission->generation;
    txn_slot->payload_length = (uint32_t)submission->payload.length;
    txn_slot->semantic_priority =
        ninlil_rt_v1_semantic_priority_for_family(slot->model_service.family);
    txn_slot->bearer_route = (uint8_t)ninlil_rt_v1_default_bearer_route();
    txn_slot->admitted_at_ms = runtime->started_sample.now_ms;
    txn_slot->retry_backoff_ms = slot->descriptor.retry_backoff_ms;
    if (txn_slot->retry_backoff_ms == 0u) {
        txn_slot->retry_backoff_ms = 100u;
    }
    txn_slot->reservation_active = 1u;
    txn_slot->reservation_evidence_units =
        slot->model_service.max_evidence_per_target + 1u;
    txn_slot->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    txn_slot->retry_budget = 3u;
    txn_slot->spool_revision = 1u;
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
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn_storage = NULL;
    uint8_t marker_key[32];
    uint8_t marker_value[16];
    ninlil_status_t status;

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

    storage = runtime->platform->storage;
    if (storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn_storage)
        != NINLIL_STORAGE_OK) {
        return NINLIL_E_STORAGE;
    }

    marker_key[0] = 0x43u;
    marker_key[1] = 0x4eu;
    (void)memcpy(&marker_key[2], transaction_id->bytes, 14u);
    (void)memset(marker_value, 0xC3, sizeof(marker_value));

    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_CANCEL_ADMISSION_COMMIT,
        storage,
        txn_storage,
        (ninlil_bytes_view_t){marker_key, 16u},
        (ninlil_bytes_view_t){marker_value, sizeof(marker_value)},
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn_storage);
        return status;
    }
    status = storage_txn_commit_full(runtime, txn_storage);
    if (status != NINLIL_OK) {
        return status;
    }

    if (txn->pending_dispatch != 0u) {
        txn->cancel_kind = NINLIL_CANCEL_FENCED_BEFORE_DISPATCH;
        txn->reason = NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH;
        txn->outcome = NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
        txn->terminal = 1u;
        txn->pending_dispatch = 0u;
        runtime->nonterminal_transaction_count -= 1u;
    } else {
        txn->cancel_kind = NINLIL_CANCEL_PENDING_REMOTE_FENCE;
        txn->reason = NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE;
        txn->outcome = NINLIL_OUTCOME_NONE;
    }

    out_result->kind = txn->cancel_kind;
    out_result->reason = txn->reason;
    out_result->current_outcome = txn->outcome;
    return NINLIL_OK;
}
