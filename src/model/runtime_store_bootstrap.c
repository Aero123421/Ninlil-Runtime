#include "runtime_store_bootstrap.h"

#include <string.h>

static int ranges_are_disjoint(
    const void *left, size_t left_length,
    const void *right, size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;

    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - left_start
        || right_length > UINTPTR_MAX - right_start) {
        return 0;
    }
    return left_start + left_length <= right_start
        || right_start + right_length <= left_start;
}

static int id_is_nonzero(const ninlil_id128_t *id)
{
    size_t index;
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int id_is_equal(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    size_t index;
    for (index = 0u; index < sizeof(left->bytes); ++index) {
        if (left->bytes[index] != right->bytes[index]) {
            return 0;
        }
    }
    return 1;
}

static int identity_is_valid(
    const ninlil_model_runtime_store_identity_t *identity)
{
    const uint32_t known = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    const int installation = (identity->flags
        & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u;

    return (identity->flags & ~known) == 0u
        && (identity->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u
        && (identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u
        && id_is_nonzero(&identity->device_id)
        && installation == id_is_nonzero(&identity->installation_id)
        && id_is_nonzero(&identity->site_domain_id)
        && identity->binding_epoch != 0u
        && identity->membership_epoch != 0u;
}

static int binding_is_equal(
    const ninlil_model_runtime_store_binding_t *left,
    const ninlil_model_runtime_store_binding_t *right)
{
#define SAME_LIMIT(field) (left->limits.field == right->limits.field)
    return left->storage_schema == right->storage_schema
        && left->role == right->role
        && left->environment == right->environment
        && id_is_equal(&left->runtime_id, &right->runtime_id)
        && SAME_LIMIT(max_services)
        && SAME_LIMIT(max_nonterminal_transactions)
        && SAME_LIMIT(max_targets_per_transaction)
        && SAME_LIMIT(max_logical_payload_bytes)
        && SAME_LIMIT(max_durable_outbox_payload_bytes)
        && SAME_LIMIT(max_attempts_per_target_per_cycle)
        && SAME_LIMIT(max_cancel_attempts_per_transaction)
        && SAME_LIMIT(max_evidence_per_target)
        && SAME_LIMIT(max_retained_terminal_transactions)
        && SAME_LIMIT(max_nonterminal_deliveries)
        && SAME_LIMIT(max_event_spool_count)
        && SAME_LIMIT(max_event_spool_bytes)
        && SAME_LIMIT(max_result_cache_entries)
        && SAME_LIMIT(max_retained_dispositions)
        && SAME_LIMIT(max_ingress_per_step)
        && SAME_LIMIT(max_callbacks_per_step)
        && SAME_LIMIT(max_state_transitions_per_step)
        && SAME_LIMIT(max_bearer_sends_per_step)
        && SAME_LIMIT(max_deferred_tokens)
        && left->terminal_retention_ms == right->terminal_retention_ms
        && left->result_cache_retention_ms
            == right->result_cache_retention_ms
        && left->observation_retention_ms
            == right->observation_retention_ms;
#undef SAME_LIMIT
}

static ninlil_status_t project_config(
    const ninlil_model_runtime_validation_result_t *validation,
    ninlil_model_runtime_store_binding_t *out_binding,
    ninlil_model_runtime_store_identity_t *out_identity)
{
    const ninlil_model_runtime_config_projection_t *config;
    ninlil_resource_limits_t projected_limits;
    ninlil_model_capacity_limits_t derived;
    uint32_t index;

    if (out_binding == NULL || out_identity == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(validation,
            validation == NULL ? 0u : sizeof(*validation),
            out_binding, sizeof(*out_binding))
        || !ranges_are_disjoint(validation,
            validation == NULL ? 0u : sizeof(*validation),
            out_identity, sizeof(*out_identity))
        || !ranges_are_disjoint(out_binding, sizeof(*out_binding),
            out_identity, sizeof(*out_identity))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_binding, 0, sizeof(*out_binding));
    (void)memset(out_identity, 0, sizeof(*out_identity));
    if (validation == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    config = &validation->accepted_config;
    if (validation->status != NINLIL_OK
        || validation->failure_field
            != NINLIL_MODEL_RUNTIME_VALIDATION_NONE) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&projected_limits, 0, sizeof(projected_limits));
#define COPY_PROJECTED_LIMIT(field) \
    projected_limits.field = config->limits.field
    COPY_PROJECTED_LIMIT(max_services);
    COPY_PROJECTED_LIMIT(max_nonterminal_transactions);
    COPY_PROJECTED_LIMIT(max_targets_per_transaction);
    COPY_PROJECTED_LIMIT(max_logical_payload_bytes);
    COPY_PROJECTED_LIMIT(max_durable_outbox_payload_bytes);
    COPY_PROJECTED_LIMIT(max_attempts_per_target_per_cycle);
    COPY_PROJECTED_LIMIT(max_cancel_attempts_per_transaction);
    COPY_PROJECTED_LIMIT(max_evidence_per_target);
    COPY_PROJECTED_LIMIT(max_retained_terminal_transactions);
    COPY_PROJECTED_LIMIT(max_nonterminal_deliveries);
    COPY_PROJECTED_LIMIT(max_event_spool_count);
    COPY_PROJECTED_LIMIT(max_event_spool_bytes);
    COPY_PROJECTED_LIMIT(max_result_cache_entries);
    COPY_PROJECTED_LIMIT(max_retained_dispositions);
    COPY_PROJECTED_LIMIT(max_ingress_per_step);
    COPY_PROJECTED_LIMIT(max_callbacks_per_step);
    COPY_PROJECTED_LIMIT(max_state_transitions_per_step);
    COPY_PROJECTED_LIMIT(max_bearer_sends_per_step);
    COPY_PROJECTED_LIMIT(max_deferred_tokens);
#undef COPY_PROJECTED_LIMIT
    if (ninlil_model_runtime_derive_capacity_limits(
            &projected_limits, &derived) != NINLIL_OK) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        if (derived.values[index]
            != validation->capacity_limits.values[index]) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }

    out_binding->storage_schema = NINLIL_STORAGE_SCHEMA_M1A;
    out_binding->role = config->role;
    out_binding->environment = config->environment;
    out_binding->runtime_id = config->runtime_id;
#define COPY_LIMIT(field) out_binding->limits.field = config->limits.field
    COPY_LIMIT(max_services);
    COPY_LIMIT(max_nonterminal_transactions);
    COPY_LIMIT(max_targets_per_transaction);
    COPY_LIMIT(max_logical_payload_bytes);
    COPY_LIMIT(max_durable_outbox_payload_bytes);
    COPY_LIMIT(max_attempts_per_target_per_cycle);
    COPY_LIMIT(max_cancel_attempts_per_transaction);
    COPY_LIMIT(max_evidence_per_target);
    COPY_LIMIT(max_retained_terminal_transactions);
    COPY_LIMIT(max_nonterminal_deliveries);
    COPY_LIMIT(max_event_spool_count);
    COPY_LIMIT(max_event_spool_bytes);
    COPY_LIMIT(max_result_cache_entries);
    COPY_LIMIT(max_retained_dispositions);
    COPY_LIMIT(max_ingress_per_step);
    COPY_LIMIT(max_callbacks_per_step);
    COPY_LIMIT(max_state_transitions_per_step);
    COPY_LIMIT(max_bearer_sends_per_step);
    COPY_LIMIT(max_deferred_tokens);
#undef COPY_LIMIT
    out_binding->terminal_retention_ms = config->terminal_retention_ms;
    out_binding->result_cache_retention_ms =
        config->result_cache_retention_ms;
    out_binding->observation_retention_ms =
        config->observation_retention_ms;

    out_identity->flags = config->identity_flags;
    out_identity->device_id = config->device_id;
    out_identity->installation_id = config->installation_id;
    out_identity->site_domain_id = config->site_domain_id;
    out_identity->binding_epoch = config->binding_epoch;
    out_identity->membership_epoch = config->membership_epoch;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_validate_snapshot(
    const ninlil_model_runtime_store_encoded_snapshot_t *encoded,
    ninlil_model_runtime_store_validated_snapshot_t *out_snapshot)
{
    uint32_t index;
    uint32_t other;
    uint32_t saw_corrupt = 0u;
    uint32_t saw_unsupported = 0u;

    if (out_snapshot == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded == NULL) {
        (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded, sizeof(*encoded),
            out_snapshot, sizeof(*out_snapshot))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_bytes_view_t value = encoded->values[index];
        size_t value_length = value.data == NULL ? 0u : value.length;
        if (!ranges_are_disjoint(value.data, value_length,
                encoded, sizeof(*encoded))
            || !ranges_are_disjoint(value.data, value_length,
                out_snapshot, sizeof(*out_snapshot))) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        for (other = 0u; other < index; ++other) {
            ninlil_bytes_view_t prior = encoded->values[other];
            size_t prior_length = prior.data == NULL ? 0u : prior.length;
            if (!ranges_are_disjoint(value.data, value_length,
                    prior.data, prior_length)) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
        }
    }
    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        if ((encoded->values[index].length == 0u
                && encoded->values[index].data != NULL)
            || (encoded->values[index].length != 0u
                && encoded->values[index].data == NULL)) {
            (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_status_t status;
        ninlil_model_runtime_store_key_id_t key_id =
            (ninlil_model_runtime_store_key_id_t)(index + 1u);
        if (index == 0u) {
            status = ninlil_model_runtime_store_decode_binding(
                key_id, encoded->values[index], &out_snapshot->binding);
        } else if (index == 1u) {
            status = ninlil_model_runtime_store_decode_identity(
                key_id, encoded->values[index], &out_snapshot->identity);
        } else if (index < 6u) {
            status = ninlil_model_runtime_store_decode_counter(
                key_id, encoded->values[index],
                &out_snapshot->counters[index - 2u]);
        } else {
            status = ninlil_model_runtime_store_decode_capacity(
                key_id, encoded->values[index],
                &out_snapshot->capacities[index - 6u]);
        }
        if (status == NINLIL_E_UNSUPPORTED) {
            saw_unsupported = 1u;
        } else if (status != NINLIL_OK) {
            saw_corrupt = 1u;
        }
    }
    if (saw_corrupt != 0u) {
        (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (saw_unsupported != 0u) {
        (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_classify_presence(
    const ninlil_model_runtime_store_presence_input_t *input,
    ninlil_model_runtime_store_presence_class_t *out_class)
{
    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input == NULL) {
        *out_class = NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NONE;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(input, sizeof(*input),
            out_class, sizeof(*out_class))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NONE;
    if ((input->present_mask
            & ~NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK) != 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->present_mask == NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK) {
        *out_class =
            NINLIL_MODEL_RUNTIME_STORE_PRESENCE_ALL_PRESENT_UNVALIDATED;
        return NINLIL_OK;
    }
    if (input->present_mask != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (input->zero_record_scan
            < NINLIL_MODEL_RUNTIME_STORE_SCAN_NOT_CONFIRMED
        || input->zero_record_scan > NINLIL_MODEL_RUNTIME_STORE_SCAN_MIXED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->zero_record_scan == NINLIL_MODEL_RUNTIME_STORE_SCAN_EMPTY) {
        *out_class = NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NEW;
        return NINLIL_OK;
    }
    if (input->zero_record_scan
        == NINLIL_MODEL_RUNTIME_STORE_SCAN_RECOGNIZABLE_FUTURE) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (input->zero_record_scan
        == NINLIL_MODEL_RUNTIME_STORE_SCAN_NOT_CONFIRMED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

ninlil_status_t ninlil_model_runtime_store_compare_binding(
    const ninlil_model_runtime_store_validated_snapshot_t *stored,
    const ninlil_model_runtime_store_binding_t *candidate,
    ninlil_model_runtime_store_binding_comparison_t *out_comparison)
{
    if (out_comparison == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(stored,
            stored == NULL ? 0u : sizeof(*stored),
            candidate, candidate == NULL ? 0u : sizeof(*candidate))
        || !ranges_are_disjoint(stored,
            stored == NULL ? 0u : sizeof(*stored),
            out_comparison, sizeof(*out_comparison))
        || !ranges_are_disjoint(candidate,
            candidate == NULL ? 0u : sizeof(*candidate),
            out_comparison, sizeof(*out_comparison))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_comparison = NINLIL_MODEL_RUNTIME_STORE_BINDING_COMPARISON_NONE;
    if (stored == NULL || candidate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_comparison = binding_is_equal(&stored->binding, candidate)
        ? NINLIL_MODEL_RUNTIME_STORE_BINDING_EXACT
        : NINLIL_MODEL_RUNTIME_STORE_BINDING_UNSUPPORTED;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_decide_identity(
    const ninlil_model_runtime_store_validated_snapshot_t *stored,
    const ninlil_model_runtime_store_identity_t *requested,
    ninlil_model_runtime_store_identity_decision_t *out_decision)
{
    const ninlil_model_runtime_store_identity_t *stored_identity;
    uint32_t stored_installation;
    uint32_t requested_installation;
    uint32_t stored_site;
    uint32_t requested_site;
    int installation_exact;
    int site_exact;

    if (out_decision == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(stored,
            stored == NULL ? 0u : sizeof(*stored),
            requested, requested == NULL ? 0u : sizeof(*requested))
        || !ranges_are_disjoint(stored,
            stored == NULL ? 0u : sizeof(*stored),
            out_decision, sizeof(*out_decision))
        || !ranges_are_disjoint(requested,
            requested == NULL ? 0u : sizeof(*requested),
            out_decision, sizeof(*out_decision))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_DECISION_NONE;
    if (stored == NULL || requested == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    stored_identity = &stored->identity;
    if (!identity_is_valid(stored_identity)
        || !identity_is_valid(requested)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if ((stored_identity->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE)
            != (requested->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE)
        || !id_is_equal(&stored_identity->device_id,
            &requested->device_id)) {
        *out_decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT;
        return NINLIL_OK;
    }
    stored_installation = stored_identity->flags
        & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    requested_installation = requested->flags
        & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    stored_site = stored_identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE;
    requested_site = requested->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE;
    installation_exact = stored_installation == requested_installation
        && id_is_equal(&stored_identity->installation_id,
            &requested->installation_id)
        && stored_identity->binding_epoch == requested->binding_epoch;
    site_exact = stored_site == requested_site
        && id_is_equal(&stored_identity->site_domain_id,
            &requested->site_domain_id)
        && stored_identity->membership_epoch == requested->membership_epoch;
    if (installation_exact && site_exact) {
        *out_decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT;
    } else if ((!installation_exact
            && requested->binding_epoch <= stored_identity->binding_epoch)
        || (!site_exact
            && requested->membership_epoch
                <= stored_identity->membership_epoch)) {
        *out_decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT;
    } else {
        *out_decision =
            NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_bootstrap_record_at(
    const ninlil_model_runtime_store_bootstrap_plan_t *plan,
    uint32_t index,
    ninlil_model_runtime_store_bootstrap_record_t *out_record)
{
    ninlil_model_runtime_store_key_id_t key_id;
    ninlil_status_t status;

    if (out_record == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (plan == NULL) {
        (void)memset(out_record, 0, sizeof(*out_record));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(plan, sizeof(*plan),
            out_record, sizeof(*out_record))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_record, 0, sizeof(*out_record));
    if (plan->record_count
            != NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT
        || plan->logical_bytes
            != NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_LOGICAL_BYTES
        || plan->encoded_key_value_bytes
            != NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES
        || index >= NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    key_id = (ninlil_model_runtime_store_key_id_t)(index + 1u);
    status = ninlil_model_runtime_store_build_key(key_id, &out_record->key);
    if (status != NINLIL_OK) {
        (void)memset(out_record, 0, sizeof(*out_record));
        return status;
    }
    if (index == 0u) {
        status = ninlil_model_runtime_store_encode_binding(
            &plan->binding, out_record->value,
            sizeof(out_record->value), &out_record->value_length);
    } else if (index == 1u) {
        status = ninlil_model_runtime_store_encode_identity(
            &plan->identity, out_record->value,
            sizeof(out_record->value), &out_record->value_length);
    } else if (index < 6u) {
        ninlil_model_runtime_store_counter_t counter;
        counter.kind = (ninlil_model_runtime_store_counter_kind_t)(index - 1u);
        counter.value = 0u;
        counter.exhausted_marker = 0u;
        status = ninlil_model_runtime_store_encode_counter(
            key_id, &counter, out_record->value,
            sizeof(out_record->value), &out_record->value_length);
    } else {
        ninlil_model_runtime_store_capacity_t capacity;
        uint32_t capacity_index = index - 6u;
        capacity.kind = (ninlil_resource_kind_t)(capacity_index + 1u);
        capacity.limit = plan->capacity_limits.values[capacity_index];
        capacity.used = 0u;
        capacity.reserved = 0u;
        capacity.high_water = 0u;
        capacity.capacity_epoch = 1u;
        capacity.blocked = 0u;
        capacity.counter_exhausted = 0u;
        status = ninlil_model_runtime_store_encode_capacity(
            key_id, &capacity, out_record->value,
            sizeof(out_record->value), &out_record->value_length);
    }
    if (status != NINLIL_OK) {
        (void)memset(out_record, 0, sizeof(*out_record));
    }
    return status;
}

ninlil_status_t ninlil_model_runtime_store_build_bootstrap_plan(
    const ninlil_model_runtime_validation_result_t *validation,
    ninlil_model_runtime_store_bootstrap_plan_t *out_plan)
{
    ninlil_model_runtime_store_bootstrap_record_t record;
    uint32_t index;
    uint32_t encoded_bytes = 0u;
    uint32_t logical_bytes = 0u;

    if (out_plan == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(validation,
            validation == NULL ? 0u : sizeof(*validation),
            out_plan, sizeof(*out_plan))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_plan, 0, sizeof(*out_plan));
    if (validation == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (project_config(validation,
            &out_plan->binding, &out_plan->identity) != NINLIL_OK) {
        (void)memset(out_plan, 0, sizeof(*out_plan));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    out_plan->capacity_limits = validation->capacity_limits;
    out_plan->record_count = NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
    out_plan->encoded_key_value_bytes =
        NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES;
    out_plan->logical_bytes =
        NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_LOGICAL_BYTES;

    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        uint32_t entry_bytes;
        ninlil_status_t status =
            ninlil_model_runtime_store_bootstrap_record_at(
                out_plan, index, &record);
        if (status != NINLIL_OK
            || record.key.length > UINT32_MAX - 16u
            || record.value_length
                > UINT32_MAX - 16u - record.key.length) {
            (void)memset(out_plan, 0, sizeof(*out_plan));
            return status == NINLIL_OK ? NINLIL_E_INVALID_ARGUMENT : status;
        }
        entry_bytes = 16u + record.key.length + record.value_length;
        if (encoded_bytes > UINT32_MAX
                - record.key.length - record.value_length) {
            (void)memset(out_plan, 0, sizeof(*out_plan));
            return NINLIL_E_INVALID_ARGUMENT;
        }
        encoded_bytes += record.key.length + record.value_length;
        if (logical_bytes > UINT32_MAX - entry_bytes) {
            (void)memset(out_plan, 0, sizeof(*out_plan));
            return NINLIL_E_INVALID_ARGUMENT;
        }
        logical_bytes += entry_bytes;
    }
    if (encoded_bytes
            != NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES
        || logical_bytes
            != NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_LOGICAL_BYTES) {
        (void)memset(out_plan, 0, sizeof(*out_plan));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}
