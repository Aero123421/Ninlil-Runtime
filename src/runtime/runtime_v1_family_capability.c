#include "runtime_v1_family_capability.h"

#include "family_capability_model.h"

#include <string.h>

#define NINLIL_RT_V1_MEASUREMENT_RETENTION_WINDOW 16u

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static int id_equal(const ninlil_id128_t *left, const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

int ninlil_rt_v1_family_is_uplink(ninlil_family_t family)
{
    return ninlil_model_family_is_uplink(family);
}

int ninlil_rt_v1_family_is_downlink(ninlil_family_t family)
{
    return ninlil_model_family_is_downlink(family);
}

int ninlil_rt_v1_family_is_b5_lab(ninlil_family_t family)
{
    return ninlil_model_family_is_b5_lab(family);
}

int ninlil_rt_v1_family_descriptor_role_valid(
    ninlil_role_t role,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_model_local_submission_side_t *out_side)
{
    if (descriptor->family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || descriptor->family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        if (descriptor->direction != NINLIL_DIRECTION_UPLINK
            || descriptor->admission_authority
                != NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
            || descriptor->apply_contract == NINLIL_APPLY_ATOMIC_PARTICIPANT_RESERVED) {
            return 0;
        }
        if (role == NINLIL_ROLE_ENDPOINT) {
            if (callbacks->on_delivery != NULL || callbacks->on_reconcile != NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_SENDER;
            return 1;
        }
        if (role == NINLIL_ROLE_CONTROLLER) {
            if (callbacks->on_delivery == NULL || callbacks->on_reconcile == NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER;
            return 1;
        }
        return 0;
    }
    if (descriptor->family == NINLIL_FAMILY_TRANSFER_RESERVED
        || descriptor->family == NINLIL_FAMILY_CONFIG_RESERVED) {
        if (descriptor->direction != NINLIL_DIRECTION_DOWNLINK
            || descriptor->admission_authority
                != NINLIL_AUTHORITY_CONTROLLER_ONLY
            || descriptor->apply_contract == NINLIL_APPLY_ATOMIC_PARTICIPANT_RESERVED) {
            return 0;
        }
        if (role == NINLIL_ROLE_CONTROLLER) {
            if (callbacks->on_delivery != NULL || callbacks->on_reconcile != NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_SENDER;
            return 1;
        }
        if (role == NINLIL_ROLE_ENDPOINT) {
            if (callbacks->on_delivery == NULL) {
                return -1;
            }
            if (descriptor->apply_contract == NINLIL_APPLY_APPLICATION_DEDUP
                && callbacks->on_reconcile == NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER;
            return 1;
        }
        return 0;
    }
    return 0;
}

int ninlil_rt_v1_family_descriptor_semantics_valid(
    const ninlil_service_descriptor_t *descriptor)
{
    if (ninlil_rt_v1_family_is_uplink(descriptor->family)) {
        return descriptor->minimum_deadline_ms == NINLIL_NO_DEADLINE
            && descriptor->maximum_deadline_ms == NINLIL_NO_DEADLINE
            && descriptor->maximum_evidence_grace_ms == 0u;
    }
    if (ninlil_rt_v1_family_is_downlink(descriptor->family)
        && descriptor->family != NINLIL_FAMILY_DESIRED_STATE) {
        return descriptor->minimum_deadline_ms > 0u
            && descriptor->minimum_deadline_ms <= descriptor->maximum_deadline_ms
            && descriptor->maximum_deadline_ms < NINLIL_NO_DEADLINE
            && descriptor->maximum_evidence_grace_ms > 0u;
    }
    return 0;
}

static int id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

int ninlil_rt_v1_family_submission_identity_valid(
    ninlil_family_t family,
    const ninlil_submission_t *submission)
{
    if (family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED
        || family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED) {
        return id_is_zero(&submission->event_id) && submission->generation != 0u;
    }
    return 0;
}

static ninlil_rt_v1_latest_state_scope_t *find_latest_scope(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    int allocate)
{
    uint32_t index;
    ninlil_rt_v1_latest_state_scope_t *free_slot = NULL;

    for (index = 0u; index < NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY; ++index) {
        ninlil_rt_v1_latest_state_scope_t *slot = &ws->latest_state[index];
        if (slot->in_use != 0u
            && id_equal(&slot->service_app_id, service_app_id)) {
            return slot;
        }
        if (slot->in_use == 0u && free_slot == NULL) {
            free_slot = slot;
        }
    }
    if (!allocate || free_slot == NULL) {
        return NULL;
    }
    free_slot->in_use = 1u;
    free_slot->service_app_id = *service_app_id;
    free_slot->last_applied_generation = 0u;
    return free_slot;
}

int ninlil_rt_v1_family_latest_state_apply(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    uint64_t generation,
    ninlil_application_result_t *out_result)
{
    ninlil_rt_v1_latest_state_scope_t *scope;

    if (ws == NULL || service_app_id == NULL || out_result == NULL) {
        return 0;
    }
    scope = find_latest_scope(ws, service_app_id, 1);
    if (scope == NULL) {
        return 0;
    }
    if (generation <= scope->last_applied_generation) {
        (void)memset(out_result, 0, sizeof(*out_result));
        set_header(
            &out_result->abi_version,
            &out_result->struct_size,
            sizeof(*out_result));
        out_result->kind = NINLIL_APP_RESULT_DISPOSITION;
        out_result->disposition = NINLIL_DISPOSITION_STALE_NOT_APPLIED;
        out_result->reason = NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION;
        out_result->retry_guidance = NINLIL_RETRY_NEVER;
        return 0;
    }
    scope->last_applied_generation = generation;
    return 1;
}

static ninlil_rt_v1_measurement_scope_t *find_measurement_scope(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    int allocate)
{
    uint32_t index;
    ninlil_rt_v1_measurement_scope_t *free_slot = NULL;

    for (index = 0u; index < NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY; ++index) {
        ninlil_rt_v1_measurement_scope_t *slot = &ws->measurement[index];
        if (slot->in_use != 0u
            && id_equal(&slot->service_app_id, service_app_id)) {
            return slot;
        }
        if (slot->in_use == 0u && free_slot == NULL) {
            free_slot = slot;
        }
    }
    if (!allocate || free_slot == NULL) {
        return NULL;
    }
    free_slot->in_use = 1u;
    free_slot->service_app_id = *service_app_id;
    free_slot->highest_batch_sequence = 0u;
    free_slot->retained_through_sequence = 0u;
    return free_slot;
}

int ninlil_rt_v1_family_measurement_batch_accept(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    uint64_t batch_sequence,
    uint32_t payload_length,
    ninlil_application_result_t *out_result)
{
    ninlil_rt_v1_measurement_scope_t *scope;
    uint64_t retention_floor;

    if (ws == NULL || service_app_id == NULL || out_result == NULL
        || payload_length == 0u) {
        return 0;
    }
    scope = find_measurement_scope(ws, service_app_id, 1);
    if (scope == NULL) {
        return 0;
    }
    if (batch_sequence <= scope->highest_batch_sequence) {
        (void)memset(out_result, 0, sizeof(*out_result));
        set_header(
            &out_result->abi_version,
            &out_result->struct_size,
            sizeof(*out_result));
        out_result->kind = NINLIL_APP_RESULT_DISPOSITION;
        out_result->disposition = NINLIL_DISPOSITION_STALE_NOT_APPLIED;
        out_result->reason = NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION;
        out_result->retry_guidance = NINLIL_RETRY_NEVER;
        return 0;
    }
    if (scope->highest_batch_sequence != 0u
        && batch_sequence
            < scope->highest_batch_sequence + NINLIL_RT_V1_MEASUREMENT_RETENTION_WINDOW) {
        scope->highest_batch_sequence = batch_sequence;
        if (scope->retained_through_sequence == 0u
            || batch_sequence - NINLIL_RT_V1_MEASUREMENT_RETENTION_WINDOW
                > scope->retained_through_sequence) {
            retention_floor =
                batch_sequence - NINLIL_RT_V1_MEASUREMENT_RETENTION_WINDOW;
            scope->retained_through_sequence = retention_floor;
        }
        return 1;
    }
    scope->highest_batch_sequence = batch_sequence;
    if (batch_sequence > NINLIL_RT_V1_MEASUREMENT_RETENTION_WINDOW) {
        scope->retained_through_sequence =
            batch_sequence - NINLIL_RT_V1_MEASUREMENT_RETENTION_WINDOW;
    }
    return 1;
}

static ninlil_rt_v1_transfer_scope_t *find_transfer_scope(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id,
    int allocate)
{
    uint32_t index;
    ninlil_rt_v1_transfer_scope_t *free_slot = NULL;

    for (index = 0u; index < NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY; ++index) {
        ninlil_rt_v1_transfer_scope_t *slot = &ws->transfer[index];
        if (slot->in_use != 0u
            && id_equal(&slot->transaction_id, transaction_id)) {
            return slot;
        }
        if (slot->in_use == 0u && free_slot == NULL) {
            free_slot = slot;
        }
    }
    if (!allocate || free_slot == NULL) {
        return NULL;
    }
    (void)memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = 1u;
    free_slot->transaction_id = *transaction_id;
    free_slot->state = NINLIL_RT_V1_TRANSFER_STATE_NONE;
    return free_slot;
}

int ninlil_rt_v1_family_bounded_transfer_begin(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id,
    uint32_t total_bytes)
{
    ninlil_rt_v1_transfer_scope_t *scope;

    if (ws == NULL || transaction_id == NULL || total_bytes == 0u) {
        return 0;
    }
    scope = find_transfer_scope(ws, transaction_id, 1);
    if (scope == NULL) {
        return 0;
    }
    scope->state = NINLIL_RT_V1_TRANSFER_STATE_RECEIVING;
    scope->expected_total_bytes = total_bytes;
    scope->bytes_received = 0u;
    scope->apply_count = 0u;
    return 1;
}

int ninlil_rt_v1_family_bounded_transfer_receive(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id,
    uint32_t chunk_bytes,
    int complete)
{
    ninlil_rt_v1_transfer_scope_t *scope;

    if (ws == NULL || transaction_id == NULL || chunk_bytes == 0u) {
        return 0;
    }
    scope = find_transfer_scope(ws, transaction_id, 0);
    if (scope == NULL
        || scope->state != NINLIL_RT_V1_TRANSFER_STATE_RECEIVING) {
        return 0;
    }
    if (scope->bytes_received + chunk_bytes > scope->expected_total_bytes) {
        scope->state = NINLIL_RT_V1_TRANSFER_STATE_ABORTED;
        return 0;
    }
    scope->bytes_received += chunk_bytes;
    if (complete != 0
        && scope->bytes_received == scope->expected_total_bytes) {
        scope->state = NINLIL_RT_V1_TRANSFER_STATE_COMPLETE;
    }
    return 1;
}

int ninlil_rt_v1_family_bounded_transfer_abort(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id)
{
    ninlil_rt_v1_transfer_scope_t *scope;

    if (ws == NULL || transaction_id == NULL) {
        return 0;
    }
    scope = find_transfer_scope(ws, transaction_id, 0);
    if (scope == NULL) {
        return 0;
    }
    scope->state = NINLIL_RT_V1_TRANSFER_STATE_ABORTED;
    scope->apply_count = 0u;
    return 1;
}

int ninlil_rt_v1_family_bounded_transfer_may_apply(
    const ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id)
{
    const ninlil_rt_v1_transfer_scope_t *scope;
    uint32_t index;

    if (ws == NULL || transaction_id == NULL) {
        return 0;
    }
    for (index = 0u; index < NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY; ++index) {
        scope = &ws->transfer[index];
        if (scope->in_use != 0u
            && id_equal(&scope->transaction_id, transaction_id)) {
            return scope->state == NINLIL_RT_V1_TRANSFER_STATE_COMPLETE;
        }
    }
    return 0;
}

static ninlil_rt_v1_config_scope_t *find_config_scope(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    int allocate)
{
    uint32_t index;
    ninlil_rt_v1_config_scope_t *free_slot = NULL;

    for (index = 0u; index < NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY; ++index) {
        ninlil_rt_v1_config_scope_t *slot = &ws->config[index];
        if (slot->in_use != 0u
            && id_equal(&slot->service_app_id, service_app_id)) {
            return slot;
        }
        if (slot->in_use == 0u && free_slot == NULL) {
            free_slot = slot;
        }
    }
    if (!allocate || free_slot == NULL) {
        return NULL;
    }
    (void)memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = 1u;
    free_slot->service_app_id = *service_app_id;
    return free_slot;
}

int ninlil_rt_v1_family_config_revision_advance(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    uint64_t revision,
    uint8_t requested_stage,
    ninlil_application_result_t *out_result)
{
    ninlil_rt_v1_config_scope_t *scope;

    if (ws == NULL || service_app_id == NULL || out_result == NULL
        || revision == 0u) {
        return 0;
    }
    scope = find_config_scope(ws, service_app_id, 1);
    if (scope == NULL) {
        return 0;
    }
    if (scope->active_revision != 0u
        && revision < scope->active_revision) {
        (void)memset(out_result, 0, sizeof(*out_result));
        set_header(
            &out_result->abi_version,
            &out_result->struct_size,
            sizeof(*out_result));
        out_result->kind = NINLIL_APP_RESULT_DISPOSITION;
        out_result->disposition = NINLIL_DISPOSITION_INVALID_PAYLOAD;
        out_result->reason = NINLIL_REASON_INVALID_PAYLOAD_LENGTH;
        out_result->retry_guidance = NINLIL_RETRY_MODIFIED;
        return 0;
    }
    if (requested_stage == NINLIL_RT_V1_CONFIG_STAGE_STAGED) {
        scope->stage = NINLIL_RT_V1_CONFIG_STAGE_STAGED;
        scope->active_revision = revision;
        return 1;
    }
    if (requested_stage == NINLIL_RT_V1_CONFIG_STAGE_VALIDATE) {
        if (scope->stage != NINLIL_RT_V1_CONFIG_STAGE_STAGED
            || scope->active_revision != revision) {
            return 0;
        }
        scope->stage = NINLIL_RT_V1_CONFIG_STAGE_VALIDATE;
        return 1;
    }
    if (requested_stage == NINLIL_RT_V1_CONFIG_STAGE_COMMIT) {
        if (scope->stage != NINLIL_RT_V1_CONFIG_STAGE_VALIDATE
            || scope->active_revision != revision) {
            return 0;
        }
        scope->stage = NINLIL_RT_V1_CONFIG_STAGE_COMMIT;
        scope->last_known_good_revision = revision;
        return 1;
    }
    return 0;
}

void ninlil_rt_v1_family_config_revision_rollback(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id)
{
    ninlil_rt_v1_config_scope_t *scope;

    if (ws == NULL || service_app_id == NULL) {
        return;
    }
    scope = find_config_scope(ws, service_app_id, 0);
    if (scope == NULL) {
        return;
    }
    if (scope->last_known_good_revision != 0u) {
        scope->active_revision = scope->last_known_good_revision;
        scope->stage = NINLIL_RT_V1_CONFIG_STAGE_COMMIT;
        return;
    }
    scope->stage = 0u;
    scope->active_revision = 0u;
}

ninlil_rt_v1_family_workspace_t *ninlil_rt_v1_family_workspace(
    ninlil_runtime_t *runtime)
{
    if (runtime == NULL) {
        return NULL;
    }
    return &runtime->family_workspace;
}
