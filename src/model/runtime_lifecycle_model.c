#include "runtime_lifecycle_model.h"

#include <stddef.h>
#include <string.h>

static int header_is_current(uint16_t version, uint16_t size, size_t required)
{
    return version == NINLIL_ABI_VERSION && (size_t)size >= required;
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

static int id_is_zero(const ninlil_id128_t *id)
{
    return !id_is_nonzero(id);
}

static int checked_add(uint64_t left, uint64_t right, uint64_t *out)
{
    if (left > UINT64_MAX - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

static int checked_multiply(uint64_t left, uint64_t right, uint64_t *out)
{
    if (left != 0u && right > UINT64_MAX / left) {
        return 0;
    }
    *out = left * right;
    return 1;
}

static void set_validation_failure(
    ninlil_model_runtime_validation_result_t *result,
    ninlil_status_t status,
    ninlil_model_runtime_validation_failure_field_t field)
{
    (void)memset(&result->capacity_limits, 0,
        sizeof(result->capacity_limits));
    (void)memset(&result->accepted_config, 0,
        sizeof(result->accepted_config));
    result->status = status;
    result->failure_field = field;
}

static void project_accepted_config(
    const ninlil_runtime_config_t *config,
    ninlil_model_runtime_config_projection_t *projection)
{
    projection->role = config->role;
    projection->environment = config->environment;
    projection->runtime_id = config->runtime_id;
    projection->identity_flags = config->local_identity.flags;
    projection->device_id = config->local_identity.device_id;
    projection->installation_id = config->local_identity.installation_id;
    projection->site_domain_id = config->local_identity.site_domain_id;
    projection->binding_epoch = config->local_identity.binding_epoch;
    projection->membership_epoch = config->local_identity.membership_epoch;
#define COPY_ACCEPTED_LIMIT(field) \
    projection->limits.field = config->limits.field
    COPY_ACCEPTED_LIMIT(max_services);
    COPY_ACCEPTED_LIMIT(max_nonterminal_transactions);
    COPY_ACCEPTED_LIMIT(max_targets_per_transaction);
    COPY_ACCEPTED_LIMIT(max_logical_payload_bytes);
    COPY_ACCEPTED_LIMIT(max_durable_outbox_payload_bytes);
    COPY_ACCEPTED_LIMIT(max_attempts_per_target_per_cycle);
    COPY_ACCEPTED_LIMIT(max_cancel_attempts_per_transaction);
    COPY_ACCEPTED_LIMIT(max_evidence_per_target);
    COPY_ACCEPTED_LIMIT(max_retained_terminal_transactions);
    COPY_ACCEPTED_LIMIT(max_nonterminal_deliveries);
    COPY_ACCEPTED_LIMIT(max_event_spool_count);
    COPY_ACCEPTED_LIMIT(max_event_spool_bytes);
    COPY_ACCEPTED_LIMIT(max_result_cache_entries);
    COPY_ACCEPTED_LIMIT(max_retained_dispositions);
    COPY_ACCEPTED_LIMIT(max_ingress_per_step);
    COPY_ACCEPTED_LIMIT(max_callbacks_per_step);
    COPY_ACCEPTED_LIMIT(max_state_transitions_per_step);
    COPY_ACCEPTED_LIMIT(max_bearer_sends_per_step);
    COPY_ACCEPTED_LIMIT(max_deferred_tokens);
#undef COPY_ACCEPTED_LIMIT
    projection->terminal_retention_ms = config->terminal_retention_ms;
    projection->result_cache_retention_ms =
        config->result_cache_retention_ms;
    projection->observation_retention_ms = config->observation_retention_ms;
}

static int required_platform_pointers_are_present(
    const ninlil_platform_ops_t *platform)
{
    return platform->allocator != NULL
        && platform->execution != NULL
        && platform->clock != NULL
        && platform->entropy != NULL
        && platform->storage != NULL
        && platform->bearer != NULL
        && platform->tx_gate != NULL
        && platform->origin_authorization != NULL;
}

static int nested_headers_are_current(const ninlil_platform_ops_t *platform)
{
    return header_is_current(platform->allocator->abi_version,
            platform->allocator->struct_size, sizeof(*platform->allocator))
        && header_is_current(platform->execution->abi_version,
            platform->execution->struct_size, sizeof(*platform->execution))
        && header_is_current(platform->clock->abi_version,
            platform->clock->struct_size, sizeof(*platform->clock))
        && header_is_current(platform->entropy->abi_version,
            platform->entropy->struct_size, sizeof(*platform->entropy))
        && header_is_current(platform->storage->abi_version,
            platform->storage->struct_size, sizeof(*platform->storage))
        && header_is_current(platform->bearer->abi_version,
            platform->bearer->struct_size, sizeof(*platform->bearer))
        && header_is_current(platform->tx_gate->abi_version,
            platform->tx_gate->struct_size, sizeof(*platform->tx_gate))
        && header_is_current(platform->origin_authorization->abi_version,
            platform->origin_authorization->struct_size,
            sizeof(*platform->origin_authorization));
}

static int required_platform_functions_are_present(
    const ninlil_platform_ops_t *platform)
{
    const ninlil_storage_ops_t *storage = platform->storage;
    const ninlil_bearer_ops_t *bearer = platform->bearer;

    return platform->allocator->allocate != NULL
        && platform->allocator->deallocate != NULL
        && platform->execution->current_context_id != NULL
        && platform->clock->now != NULL
        && platform->entropy->fill != NULL
        && storage->open != NULL
        && storage->close != NULL
        && storage->begin != NULL
        && storage->get != NULL
        && storage->put != NULL
        && storage->erase != NULL
        && storage->iter_open != NULL
        && storage->iter_next != NULL
        && storage->iter_close != NULL
        && storage->capacity != NULL
        && storage->commit != NULL
        && storage->rollback != NULL
        && bearer->open != NULL
        && bearer->close != NULL
        && bearer->send != NULL
        && bearer->receive_next != NULL
        && bearer->release_received != NULL
        && bearer->state != NULL
        && platform->tx_gate->acquire != NULL
        && platform->tx_gate->release_unused != NULL
        && platform->origin_authorization->evaluate != NULL;
}

static int local_identity_shape_is_valid(
    const ninlil_local_identity_t *identity)
{
    const uint32_t device = identity->flags
        & NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    const uint32_t installation = identity->flags
        & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    const uint32_t site = identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE;

    return device != 0u
        && site != 0u
        && ((device != 0u) == id_is_nonzero(&identity->device_id))
        && ((installation != 0u)
            == id_is_nonzero(&identity->installation_id))
        && ((site != 0u) == id_is_nonzero(&identity->site_domain_id))
        && (((device | installation) != 0u)
            == (identity->binding_epoch != 0u))
        && ((site != 0u) == (identity->membership_epoch != 0u));
}

static int limits_meet_lower_and_conditional(
    ninlil_role_t role,
    const ninlil_resource_limits_t *limits)
{
    if (limits->max_services < 1u
        || limits->max_nonterminal_transactions < 1u
        || limits->max_targets_per_transaction < 1u
        || limits->max_logical_payload_bytes < 1u
        || limits->max_attempts_per_target_per_cycle
            < NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || limits->max_cancel_attempts_per_transaction < 1u
        || limits->max_evidence_per_target < 1u
        || limits->max_retained_terminal_transactions < 1u
        || limits->max_nonterminal_deliveries < 1u
        || limits->max_result_cache_entries < 1u
        || limits->max_retained_dispositions < 1u
        || limits->max_ingress_per_step < 1u
        || limits->max_callbacks_per_step < 1u
        || limits->max_state_transitions_per_step < 2u
        || limits->max_bearer_sends_per_step < 1u
        || limits->max_deferred_tokens < 1u) {
        return 0;
    }

    if (role == NINLIL_ROLE_CONTROLLER) {
        return limits->max_durable_outbox_payload_bytes >= 1u;
    }

    if (limits->max_event_spool_count == 0u) {
        return limits->max_event_spool_bytes == 0u;
    }
    return limits->max_event_spool_bytes
        >= NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES;
}

static int limits_meet_cross_field(
    ninlil_role_t role,
    const ninlil_resource_limits_t *limits)
{
    if (limits->max_deferred_tokens > limits->max_nonterminal_deliveries
        || limits->max_nonterminal_deliveries
            > limits->max_nonterminal_transactions
        || limits->max_event_spool_count
            > limits->max_nonterminal_transactions) {
        return 0;
    }
    return role != NINLIL_ROLE_CONTROLLER
        || limits->max_durable_outbox_payload_bytes
            >= limits->max_logical_payload_bytes;
}

static int retentions_are_valid(const ninlil_runtime_config_t *config)
{
    return config->terminal_retention_ms >= 1u
        && config->terminal_retention_ms <= NINLIL_M1A_MAX_RETENTION_MS
        && config->result_cache_retention_ms >= 1u
        && config->result_cache_retention_ms
            <= config->terminal_retention_ms
        && config->observation_retention_ms <= NINLIL_M1A_MAX_RETENTION_MS;
}

static int limits_fit_profile_upper(
    ninlil_role_t role,
    const ninlil_resource_limits_t *limits)
{
    const uint32_t service_max = role == NINLIL_ROLE_CONTROLLER ? 16u : 8u;
    const uint32_t transaction_max =
        role == NINLIL_ROLE_CONTROLLER ? 256u : 32u;
    const uint32_t retained_max =
        role == NINLIL_ROLE_CONTROLLER ? 2048u : 64u;

    if (limits->max_services > service_max
        || limits->max_nonterminal_transactions > transaction_max
        || limits->max_targets_per_transaction > 1u
        || limits->max_logical_payload_bytes > 1024u
        || limits->max_attempts_per_target_per_cycle
            > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || limits->max_cancel_attempts_per_transaction > 1u
        || limits->max_evidence_per_target > 8u
        || limits->max_retained_terminal_transactions > retained_max
        || limits->max_nonterminal_deliveries > 32u
        || limits->max_result_cache_entries > 64u
        || limits->max_retained_dispositions > 64u
        || limits->max_ingress_per_step > 64u
        || limits->max_callbacks_per_step > 64u
        || limits->max_state_transitions_per_step > 64u
        || limits->max_bearer_sends_per_step > 64u
        || limits->max_deferred_tokens > 32u) {
        return 0;
    }

    if (role == NINLIL_ROLE_CONTROLLER) {
        return limits->max_durable_outbox_payload_bytes <= 262144u
            && limits->max_event_spool_count == 0u
            && limits->max_event_spool_bytes == 0u;
    }
    return limits->max_durable_outbox_payload_bytes == 0u
        && limits->max_event_spool_count <= 32u
        && limits->max_event_spool_bytes <= 32768u;
}

ninlil_status_t ninlil_model_runtime_derive_capacity_limits(
    const ninlil_resource_limits_t *limits,
    ninlil_model_capacity_limits_t *out_limits)
{
    uint64_t transaction_limit;
    uint64_t target_limit;
    uint64_t result_cache_limit;
    uint64_t evidence_per_target;
    uint64_t evidence_limit;

    if (out_limits == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_limits, 0, sizeof(*out_limits));
    if (limits == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (!checked_add(limits->max_nonterminal_transactions,
            limits->max_retained_terminal_transactions,
            &transaction_limit)
        || !checked_multiply(transaction_limit,
            limits->max_targets_per_transaction, &target_limit)
        || !checked_add(limits->max_result_cache_entries,
            limits->max_retained_dispositions, &result_cache_limit)
        || !checked_add(limits->max_evidence_per_target, 1u,
            &evidence_per_target)
        || !checked_multiply(target_limit, evidence_per_target,
            &evidence_limit)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    out_limits->values[NINLIL_RESOURCE_SERVICE - 1u] =
        limits->max_services;
    out_limits->values[NINLIL_RESOURCE_TRANSACTION - 1u] = transaction_limit;
    out_limits->values[NINLIL_RESOURCE_TARGET - 1u] = target_limit;
    out_limits->values[NINLIL_RESOURCE_OUTBOX_BYTES - 1u] =
        limits->max_durable_outbox_payload_bytes;
    out_limits->values[NINLIL_RESOURCE_DELIVERY - 1u] =
        limits->max_nonterminal_deliveries;
    out_limits->values[NINLIL_RESOURCE_EVENT_SPOOL_COUNT - 1u] =
        limits->max_event_spool_count;
    out_limits->values[NINLIL_RESOURCE_EVENT_SPOOL_BYTES - 1u] =
        limits->max_event_spool_bytes;
    out_limits->values[NINLIL_RESOURCE_RESULT_CACHE - 1u] =
        result_cache_limit;
    out_limits->values[NINLIL_RESOURCE_EVIDENCE - 1u] = evidence_limit;
    out_limits->values[NINLIL_RESOURCE_INGRESS - 1u] =
        limits->max_ingress_per_step;
    out_limits->values[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u] =
        limits->max_deferred_tokens;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_validate_and_derive(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_model_runtime_validation_result_t *out_result)
{
    ninlil_model_capacity_limits_t derived;
    const uint32_t known_identity_flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (config == NULL) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_POINTER);
        return out_result->status;
    }
    if (platform == NULL) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_POINTER);
        return out_result->status;
    }
    if (!header_is_current(config->abi_version,
            config->struct_size, sizeof(*config))) {
        set_validation_failure(out_result, NINLIL_E_ABI_MISMATCH,
            NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER);
        return out_result->status;
    }
    if (!header_is_current(platform->abi_version,
            platform->struct_size, sizeof(*platform))) {
        set_validation_failure(out_result, NINLIL_E_ABI_MISMATCH,
            NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_HEADER);
        return out_result->status;
    }
    if (!header_is_current(config->local_identity.abi_version,
            config->local_identity.struct_size,
            sizeof(config->local_identity))
        || !header_is_current(config->limits.abi_version,
            config->limits.struct_size, sizeof(config->limits))) {
        set_validation_failure(out_result, NINLIL_E_ABI_MISMATCH,
            NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER);
        return out_result->status;
    }
    if (!required_platform_pointers_are_present(platform)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_POINTER);
        return out_result->status;
    }
    if (!nested_headers_are_current(platform)) {
        set_validation_failure(out_result, NINLIL_E_ABI_MISMATCH,
            NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_HEADER);
        return out_result->status;
    }
    if (!required_platform_functions_are_present(platform)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_REQUIRED_FUNCTION);
        return out_result->status;
    }
    if (config->reserved_zero != 0u
        || config->limits.reserved_zero != 0u
        || config->local_identity.reserved_zero != 0u
        || (config->local_identity.flags & ~known_identity_flags) != 0u) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_RESERVED);
        return out_result->status;
    }
    if (config->role < NINLIL_ROLE_CONTROLLER
        || config->role > NINLIL_ROLE_CELL_AGENT_RESERVED) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ROLE);
        return out_result->status;
    }
    if (config->environment < NINLIL_ENV_TEST
        || config->environment > NINLIL_ENV_PRODUCTION_RESERVED) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ENVIRONMENT);
        return out_result->status;
    }
    if (config->role == NINLIL_ROLE_CELL_AGENT_RESERVED) {
        set_validation_failure(out_result, NINLIL_E_UNSUPPORTED,
            NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ROLE);
        return out_result->status;
    }
    if (config->environment != NINLIL_ENV_TEST) {
        set_validation_failure(out_result, NINLIL_E_UNSUPPORTED,
            NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ENVIRONMENT);
        return out_result->status;
    }
    if (config->storage_namespace.length < 1u
        || config->storage_namespace.length > 255u
        || config->storage_namespace.data == NULL) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_NAMESPACE);
        return out_result->status;
    }
    if (!id_is_nonzero(&config->runtime_id)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_RUNTIME_ID);
        return out_result->status;
    }
    if (!local_identity_shape_is_valid(&config->local_identity)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY);
        return out_result->status;
    }
    if (!limits_meet_lower_and_conditional(config->role, &config->limits)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_LOWER_OR_CONDITIONAL);
        return out_result->status;
    }
    if (!limits_meet_cross_field(config->role, &config->limits)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD);
        return out_result->status;
    }
    if (!retentions_are_valid(config)) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION);
        return out_result->status;
    }
    if (ninlil_model_runtime_derive_capacity_limits(
            &config->limits, &derived) != NINLIL_OK) {
        set_validation_failure(out_result, NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_CAPACITY_DERIVATION_OVERFLOW);
        return out_result->status;
    }
    if (!limits_fit_profile_upper(config->role, &config->limits)) {
        set_validation_failure(out_result, NINLIL_E_UNSUPPORTED,
            NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_PROFILE_UPPER);
        return out_result->status;
    }

    out_result->status = NINLIL_OK;
    out_result->failure_field = NINLIL_MODEL_RUNTIME_VALIDATION_NONE;
    out_result->capacity_limits = derived;
    project_accepted_config(config, &out_result->accepted_config);
    return NINLIL_OK;
}

static void set_gate(
    ninlil_model_runtime_create_gate_t *gate,
    ninlil_status_t status,
    uint32_t continue_create,
    uint32_t close_handle)
{
    gate->api_status = status;
    gate->continue_create = continue_create;
    gate->close_returned_handle = close_handle;
}

ninlil_status_t ninlil_model_runtime_map_storage_open(
    ninlil_storage_status_t port_status,
    uint32_t handle_present,
    ninlil_model_runtime_create_gate_t *out_gate)
{
    if (out_gate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_gate, 0, sizeof(*out_gate));
    if (handle_present > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if ((port_status == NINLIL_STORAGE_OK && handle_present == 0u)
        || (port_status != NINLIL_STORAGE_OK && handle_present != 0u)) {
        set_gate(out_gate, NINLIL_E_STORAGE_CORRUPT, 0u,
            handle_present != 0u);
        return NINLIL_OK;
    }

    switch (port_status) {
    case NINLIL_STORAGE_OK:
        set_gate(out_gate, NINLIL_OK, 1u, 0u);
        break;
    case NINLIL_STORAGE_BUSY:
        set_gate(out_gate, NINLIL_E_WOULD_BLOCK, 0u, 0u);
        break;
    case NINLIL_STORAGE_NO_SPACE:
        set_gate(out_gate, NINLIL_E_CAPACITY_EXHAUSTED, 0u, 0u);
        break;
    case NINLIL_STORAGE_IO_ERROR:
        set_gate(out_gate, NINLIL_E_STORAGE, 0u, 0u);
        break;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        set_gate(out_gate, NINLIL_E_STORAGE_CORRUPT, 0u, 0u);
        break;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        set_gate(out_gate, NINLIL_E_UNSUPPORTED, 0u, 0u);
        break;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        set_gate(out_gate, NINLIL_E_STORAGE_COMMIT_UNKNOWN, 0u, 0u);
        break;
    default:
        set_gate(out_gate, NINLIL_E_STORAGE_CORRUPT, 0u, 0u);
        break;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_map_bearer_open(
    ninlil_bearer_status_t port_status,
    uint32_t handle_present,
    ninlil_model_runtime_create_gate_t *out_gate)
{
    if (out_gate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_gate, 0, sizeof(*out_gate));
    if (handle_present > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if ((port_status == NINLIL_BEARER_OK && handle_present == 0u)
        || (port_status != NINLIL_BEARER_OK && handle_present != 0u)) {
        set_gate(out_gate, NINLIL_E_DEGRADED, 0u,
            handle_present != 0u);
        return NINLIL_OK;
    }

    switch (port_status) {
    case NINLIL_BEARER_OK:
        set_gate(out_gate, NINLIL_OK, 1u, 0u);
        break;
    case NINLIL_BEARER_WOULD_BLOCK:
    case NINLIL_BEARER_UNAVAILABLE:
        set_gate(out_gate, NINLIL_E_WOULD_BLOCK, 0u, 0u);
        break;
    case NINLIL_BEARER_DENIED:
        set_gate(out_gate, NINLIL_E_UNSUPPORTED, 0u, 0u);
        break;
    case NINLIL_BEARER_EMPTY:
    case NINLIL_BEARER_LOST_UNKNOWN:
    case NINLIL_BEARER_CORRUPT:
    default:
        set_gate(out_gate, NINLIL_E_DEGRADED, 0u, 0u);
        break;
    }
    return NINLIL_OK;
}

static int failure_sample_shape_is_closed(const ninlil_time_sample_t *sample)
{
    return sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == sizeof(*sample)
        && id_is_zero(&sample->clock_epoch_id)
        && sample->now_ms == 0u
        && sample->trust == 0u
        && sample->reserved_zero == 0u;
}

static int clock_baseline_shape_is_valid(
    const ninlil_model_runtime_clock_input_t *input)
{
    if (input->has_external_baseline > 1u) {
        return 0;
    }
    if (input->has_external_baseline == 0u) {
        return id_is_zero(&input->external_baseline_clock_epoch_id)
            && input->external_baseline_now_ms == 0u;
    }
    return id_is_nonzero(&input->external_baseline_clock_epoch_id);
}

ninlil_status_t ninlil_model_runtime_classify_clock_with_external_baseline(
    const ninlil_model_runtime_clock_input_t *input,
    ninlil_model_runtime_create_gate_t *out_gate)
{
    if (out_gate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_gate, 0, sizeof(*out_gate));
    if (input == NULL || !clock_baseline_shape_is_valid(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (input->port_status == NINLIL_PORT_TEMPORARY_FAILURE) {
        if (failure_sample_shape_is_closed(&input->sample)) {
            set_gate(out_gate, NINLIL_E_CLOCK_UNCERTAIN, 0u, 0u);
        } else {
            set_gate(out_gate, NINLIL_E_DEGRADED, 0u, 0u);
        }
        return NINLIL_OK;
    }
    if (input->port_status == NINLIL_PORT_PERMANENT_FAILURE) {
        set_gate(out_gate, NINLIL_E_DEGRADED, 0u, 0u);
        return NINLIL_OK;
    }
    if (input->port_status != NINLIL_PORT_OK
        || !header_is_current(input->sample.abi_version,
            input->sample.struct_size, sizeof(input->sample))
        || input->sample.reserved_zero != 0u
        || !id_is_nonzero(&input->sample.clock_epoch_id)
        || (input->sample.trust != NINLIL_CLOCK_TRUSTED
            && input->sample.trust != NINLIL_CLOCK_UNCERTAIN)) {
        set_gate(out_gate, NINLIL_E_DEGRADED, 0u, 0u);
        return NINLIL_OK;
    }
    if (input->sample.trust == NINLIL_CLOCK_UNCERTAIN) {
        set_gate(out_gate, NINLIL_E_CLOCK_UNCERTAIN, 0u, 0u);
        return NINLIL_OK;
    }
    if (input->has_external_baseline != 0u
        && memcmp(&input->sample.clock_epoch_id,
            &input->external_baseline_clock_epoch_id,
            sizeof(input->sample.clock_epoch_id)) == 0
        && input->sample.now_ms < input->external_baseline_now_ms) {
        set_gate(out_gate, NINLIL_E_DEGRADED, 0u, 0u);
        return NINLIL_OK;
    }
    set_gate(out_gate, NINLIL_OK, 1u, 0u);
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_project_health(
    const uint64_t active_reference_count[
        NINLIL_MODEL_RUNTIME_HEALTH_PRIORITY_COUNT],
    ninlil_model_runtime_health_projection_t *out_projection)
{
    static const ninlil_reason_t REASONS[
        NINLIL_MODEL_RUNTIME_HEALTH_PRIORITY_COUNT] = {
        NINLIL_REASON_STORAGE_IO,
        NINLIL_REASON_STORAGE_COMMIT_UNKNOWN,
        NINLIL_REASON_CALLBACK_CONTRACT,
        NINLIL_REASON_APPLICATION_FAILED,
        NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE,
        NINLIL_REASON_CLOCK_UNCERTAIN,
        NINLIL_REASON_COUNTER_EXHAUSTED,
        NINLIL_REASON_OUTCOME_UNKNOWN
    };
    size_t index;

    if (out_projection == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_projection, 0, sizeof(*out_projection));
    if (active_reference_count == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_HEALTH_PRIORITY_COUNT;
         ++index) {
        if (active_reference_count[index] != 0u) {
            out_projection->health = NINLIL_HEALTH_DEGRADED;
            out_projection->degraded_reason = REASONS[index];
            return NINLIL_OK;
        }
    }
    out_projection->health = NINLIL_HEALTH_OK;
    out_projection->degraded_reason = NINLIL_REASON_NONE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_project_stage9_health(
    const ninlil_model_runtime_stage9_health_input_t *input,
    ninlil_model_runtime_health_projection_t *out_projection)
{
    if (out_projection == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_projection, 0, sizeof(*out_projection));
    if (input == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->storage_recovery_complete > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->storage_recovery_complete == 0u
        || input->durable_active_reference_count[0] != 0u
        || input->durable_active_reference_count[1] != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    return ninlil_model_runtime_project_health(
        input->durable_active_reference_count, out_projection);
}

ninlil_status_t ninlil_model_runtime_map_metrics_entropy(
    const ninlil_model_runtime_entropy_observation_t *observations,
    uint32_t observation_count,
    ninlil_model_runtime_entropy_result_t *out_result)
{
    uint32_t index;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (observations == NULL || observation_count < 1u
        || observation_count > NINLIL_MODEL_RUNTIME_METRICS_ENTROPY_ATTEMPTS) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    for (index = 0u; index < observation_count; ++index) {
        if (observations[index].port_status == NINLIL_PORT_OK
            && id_is_nonzero(&observations[index].candidate)) {
            out_result->api_status = NINLIL_OK;
            out_result->action = NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED;
            out_result->calls_consumed = index + 1u;
            out_result->metrics_epoch_id = observations[index].candidate;
            return NINLIL_OK;
        }
    }

    out_result->calls_consumed = observation_count;
    if (observation_count
        < NINLIL_MODEL_RUNTIME_METRICS_ENTROPY_ATTEMPTS) {
        out_result->api_status = NINLIL_OK;
        out_result->action = NINLIL_MODEL_RUNTIME_ENTROPY_MORE_REQUIRED;
    } else {
        out_result->api_status = NINLIL_E_ENTROPY;
        out_result->action = NINLIL_MODEL_RUNTIME_ENTROPY_EXHAUSTED;
    }
    return NINLIL_OK;
}
