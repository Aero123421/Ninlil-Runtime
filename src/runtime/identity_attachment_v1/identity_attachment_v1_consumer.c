/* SPDX-License-Identifier: Apache-2.0 */
#include "identity_attachment_v1_consumer.h"

#include <string.h>

static void secure_zero(void *data, size_t size)
{
    volatile uint8_t *cursor = (volatile uint8_t *)data;

    while (size != 0u) {
        *cursor++ = 0u;
        --size;
    }
}

static int bytes_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    return memcmp(left, right, size) == 0;
}

static int bytes_nonzero(const uint8_t *value, size_t size)
{
    size_t index;
    uint8_t combined = 0u;

    for (index = 0u; index < size; ++index) {
        combined |= value[index];
    }
    return combined != 0u;
}

static int known_status(ninlil_status_t status)
{
    switch (status) {
    case NINLIL_OK:
    case NINLIL_E_INVALID_ARGUMENT:
    case NINLIL_E_ABI_MISMATCH:
    case NINLIL_E_UNSUPPORTED:
    case NINLIL_E_WRONG_THREAD:
    case NINLIL_E_REENTRANT:
    case NINLIL_E_BUFFER_TOO_SMALL:
    case NINLIL_E_NOT_FOUND:
    case NINLIL_E_CONFLICT:
    case NINLIL_E_CAPACITY_EXHAUSTED:
    case NINLIL_E_STORAGE:
    case NINLIL_E_STORAGE_CORRUPT:
    case NINLIL_E_STORAGE_COMMIT_UNKNOWN:
    case NINLIL_E_CLOCK_UNCERTAIN:
    case NINLIL_E_WOULD_BLOCK:
    case NINLIL_E_INVALID_STATE:
    case NINLIL_E_DEGRADED:
    case NINLIL_IDENTITY_ATTACHMENT_E_AUTHENTICATION_FAILED:
        return 1;
    default:
        return 0;
    }
}

static ninlil_status_t provider_status(ninlil_status_t status)
{
    if (!known_status(status)) {
        return NINLIL_E_INVALID_STATE;
    }
    /* Public Runtime's numeric 19 is reserved INTERNAL, never claim auth. */
    return status == NINLIL_IDENTITY_ATTACHMENT_E_AUTHENTICATION_FAILED
        ? NINLIL_E_DEGRADED : status;
}

static int prefix_header_ok(uint32_t abi_version, uint32_t struct_size,
    size_t minimum_size)
{
    return abi_version == NINLIL_IDENTITY_ATTACHMENT_PROVIDER_ABI_V1
        && struct_size >= minimum_size;
}

static int opaque_header_ok(uint32_t abi_version, uint32_t struct_size,
    size_t exact_size)
{
    return abi_version == NINLIL_IDENTITY_ATTACHMENT_PROVIDER_ABI_V1
        && struct_size == exact_size;
}

static int valid_scope(uint32_t value)
{
    return value == NINLIL_IDENTITY_SCOPE_LOCAL_ACTIVE_SESSION
        || value == NINLIL_IDENTITY_SCOPE_PEER_ACTIVE_SESSION
        || value == NINLIL_IDENTITY_SCOPE_CONTROLLER_ACTIVE_SESSION;
}

static int valid_usage(uint32_t value)
{
    return value != 0u && (value & ~NINLIL_KEY_USAGE_ALLOWED_MASK) == 0u;
}

static int valid_invalidation_reason(uint32_t value)
{
    return value >= NINLIL_IDENTITY_INVALIDATION_REVOKED
        && value <= NINLIL_IDENTITY_INVALIDATION_PROVIDER_RESTARTED;
}

static int provider_structural_ok(
    const ninlil_identity_attachment_provider_v1_t *provider)
{
    return provider != NULL
        && prefix_header_ok(provider->abi_version, provider->struct_size,
            sizeof(*provider))
        && provider->resolve_binding != NULL
        && provider->validate_binding != NULL
        && provider->perform_key_operation != NULL
        && provider->release_binding != NULL
        && provider->subscribe_invalidation != NULL
        && provider->unsubscribe_invalidation != NULL;
}

static int binding_matches_config(
    const ninlil_identity_attachment_consumer_v1_t *consumer,
    const ninlil_identity_attachment_binding_handle_v1_t *binding)
{
    const ninlil_identity_attachment_consumer_config_v1_t *config =
        &consumer->config;

    return opaque_header_ok(binding->abi_version, binding->struct_size,
            sizeof(*binding))
        && bytes_equal(binding->provider_instance_id, config->provider_instance_id,
            sizeof(binding->provider_instance_id))
        && binding->provider_generation == config->provider_generation
        && bytes_equal(binding->runtime_instance_id, config->runtime_instance_id,
            sizeof(binding->runtime_instance_id))
        && binding->runtime_generation == config->runtime_generation
        && bytes_equal(binding->module_instance_id, config->module_instance_id,
            sizeof(binding->module_instance_id))
        && binding->module_generation == config->module_generation;
}

static int config_ids_and_generations_ok(
    const ninlil_identity_attachment_consumer_config_v1_t *config)
{
    return bytes_nonzero(config->provider_instance_id,
            sizeof(config->provider_instance_id))
        && config->provider_generation != 0u
        && bytes_nonzero(config->runtime_instance_id,
            sizeof(config->runtime_instance_id))
        && config->runtime_generation != 0u
        && bytes_nonzero(config->module_instance_id,
            sizeof(config->module_instance_id))
        && config->module_generation != 0u
        && bytes_nonzero(config->subject_identity_id,
            sizeof(config->subject_identity_id));
}

static int snapshot_fields_ok(
    const ninlil_identity_attachment_binding_snapshot_v1_t *snapshot,
    const ninlil_identity_attachment_consumer_config_v1_t *config)
{
    return bytes_nonzero(snapshot->stable_identity_id,
            sizeof(snapshot->stable_identity_id))
        && bytes_equal(snapshot->stable_identity_id, config->subject_identity_id,
            sizeof(snapshot->stable_identity_id))
        && snapshot->credential_revision != 0u
        && bytes_nonzero(snapshot->identity_binding_digest,
            sizeof(snapshot->identity_binding_digest))
        && bytes_nonzero(snapshot->membership_authority_id,
            sizeof(snapshot->membership_authority_id))
        && snapshot->membership_epoch != 0u
        && bytes_nonzero(snapshot->membership_set_digest,
            sizeof(snapshot->membership_set_digest))
        && bytes_nonzero(snapshot->attachment_id, sizeof(snapshot->attachment_id))
        && snapshot->attachment_generation != 0u
        && bytes_nonzero(snapshot->session_id, sizeof(snapshot->session_id))
        && snapshot->session_generation != 0u
        && bytes_nonzero(snapshot->security_context_id,
            sizeof(snapshot->security_context_id))
        && snapshot->security_epoch != 0u
        && bytes_nonzero(snapshot->expiry_authority_id,
            sizeof(snapshot->expiry_authority_id))
        && snapshot->expiry_epoch != 0u
        && snapshot->invalidation_epoch != 0u;
}

static int resolve_result_ok(const ninlil_identity_attachment_consumer_v1_t *consumer,
    const ninlil_identity_attachment_resolve_result_v1_t *result)
{
    const ninlil_identity_attachment_binding_snapshot_v1_t *snapshot =
        &result->snapshot;
    const ninlil_identity_attachment_binding_handle_v1_t *binding =
        &result->binding_handle;
    const ninlil_nonexporting_key_handle_v1_t *key = &result->key_handle;

    return prefix_header_ok(result->abi_version, result->struct_size,
            sizeof(*result))
        && result->binding_verdict == NINLIL_IDENTITY_BINDING_VALID
        && result->flags == 0u
        && prefix_header_ok(snapshot->abi_version, snapshot->struct_size,
            sizeof(*snapshot))
        && binding_matches_config(consumer, binding)
        && bytes_equal(snapshot->provider_instance_id,
            consumer->config.provider_instance_id,
            sizeof(snapshot->provider_instance_id))
        && snapshot->provider_generation == consumer->config.provider_generation
        && bytes_equal(snapshot->runtime_instance_id,
            consumer->config.runtime_instance_id,
            sizeof(snapshot->runtime_instance_id))
        && snapshot->runtime_generation == consumer->config.runtime_generation
        && bytes_equal(snapshot->module_instance_id,
            consumer->config.module_instance_id,
            sizeof(snapshot->module_instance_id))
        && snapshot->module_generation == consumer->config.module_generation
        && snapshot_fields_ok(snapshot, &consumer->config)
        && bytes_nonzero(binding->binding_handle_id,
            sizeof(binding->binding_handle_id))
        && binding->binding_handle_generation != 0u
        && bytes_nonzero(binding->opaque_token, sizeof(binding->opaque_token))
        && opaque_header_ok(key->abi_version, key->struct_size, sizeof(*key))
        && bytes_equal(key->provider_instance_id, binding->provider_instance_id,
            sizeof(key->provider_instance_id))
        && key->provider_generation == binding->provider_generation
        && bytes_equal(key->binding_handle_id, binding->binding_handle_id,
            sizeof(key->binding_handle_id))
        && key->binding_handle_generation == binding->binding_handle_generation
        && bytes_nonzero(key->key_handle_id, sizeof(key->key_handle_id))
        && key->key_generation != 0u
        && bytes_nonzero(key->opaque_token, sizeof(key->opaque_token))
        && valid_usage(key->usage_mask)
        && (key->usage_mask & consumer->config.required_usage_mask)
            == consumer->config.required_usage_mask
        && key->flags == NINLIL_KEY_HANDLE_REQUIRED_FLAGS_MASK;
}

static int validate_result_ok(
    const ninlil_identity_attachment_binding_snapshot_v1_t *snapshot,
    const ninlil_identity_attachment_validate_result_v1_t *result)
{
    return prefix_header_ok(result->abi_version, result->struct_size,
            sizeof(*result))
        && result->binding_verdict == NINLIL_IDENTITY_BINDING_VALID
        && result->flags == 0u
        && result->authoritative_invalidation_epoch == snapshot->invalidation_epoch
        && result->authoritative_expiry_epoch == snapshot->expiry_epoch;
}

static int subscription_matches_binding(
    const ninlil_identity_attachment_consumer_v1_t *consumer,
    const ninlil_identity_attachment_subscription_handle_v1_t *subscription)
{
    const ninlil_identity_attachment_binding_handle_v1_t *binding =
        &consumer->binding_handle;

    return opaque_header_ok(subscription->abi_version, subscription->struct_size,
            sizeof(*subscription))
        && bytes_equal(subscription->provider_instance_id,
            binding->provider_instance_id, sizeof(subscription->provider_instance_id))
        && subscription->provider_generation == binding->provider_generation
        && bytes_equal(subscription->binding_handle_id, binding->binding_handle_id,
            sizeof(subscription->binding_handle_id))
        && subscription->binding_handle_generation
            == binding->binding_handle_generation
        && bytes_nonzero(subscription->subscription_id,
            sizeof(subscription->subscription_id))
        && subscription->subscription_generation != 0u
        && bytes_nonzero(subscription->opaque_token,
            sizeof(subscription->opaque_token));
}

static void fence(ninlil_identity_attachment_consumer_v1_t *consumer)
{
    consumer->fenced = NINLIL_IDENTITY_ATTACHMENT_TRUE;
    if (consumer->state != NINLIL_IDENTITY_ATTACHMENT_CONSUMER_EMPTY
        && consumer->state != NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING) {
        consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_PREPARED_FENCED;
    }
}

static void on_invalidation(void *context,
    const ninlil_identity_attachment_invalidation_event_v1_t *event)
{
    ninlil_identity_attachment_consumer_v1_t *consumer = context;

    if (consumer == NULL) {
        return;
    }
    /* Every callback, malformed included, is a fence before return. */
    fence(consumer);
    if (event == NULL
        || !prefix_header_ok(event->abi_version, event->struct_size, sizeof(*event))
        || event->flags != 0u || event->reserved_zero != 0u
        || !valid_invalidation_reason(event->reason)
        || event->changed_floor_mask == 0u
        || (event->changed_floor_mask & ~NINLIL_IDENTITY_FLOOR_ALLOWED_MASK) != 0u
        || !binding_matches_config(consumer, &event->binding_handle)
        || !bytes_equal(event->binding_handle.binding_handle_id,
            consumer->binding_handle.binding_handle_id,
            sizeof(event->binding_handle.binding_handle_id))
        || !bytes_equal(event->binding_handle.opaque_token,
            consumer->binding_handle.opaque_token,
            sizeof(event->binding_handle.opaque_token))
        || event->provider_generation != consumer->binding_handle.provider_generation
        || event->binding_handle_generation
            != consumer->binding_handle.binding_handle_generation
        || event->key_generation != consumer->key_handle.key_generation) {
        return;
    }
}

static void init_header(void *data, size_t size, uint32_t *abi_version,
    uint32_t *struct_size)
{
    (void)memset(data, 0, size);
    *abi_version = NINLIL_IDENTITY_ATTACHMENT_PROVIDER_ABI_V1;
    *struct_size = (uint32_t)size;
}

static ninlil_status_t release_binding(
    ninlil_identity_attachment_consumer_v1_t *consumer)
{
    ninlil_identity_attachment_release_request_v1_t request;
    ninlil_identity_attachment_release_result_v1_t result;
    ninlil_status_t status;

    init_header(&request, sizeof(request), &request.abi_version,
        &request.struct_size);
    request.binding_handle = consumer->binding_handle;
    init_header(&result, sizeof(result), &result.abi_version, &result.struct_size);
    status = provider_status(consumer->provider.release_binding(
        consumer->provider.context, &request, &result));
    if (status != NINLIL_OK) {
        secure_zero(&request, sizeof(request));
        secure_zero(&result, sizeof(result));
        return status;
    }
    if (!prefix_header_ok(result.abi_version, result.struct_size, sizeof(result))
        || result.flags != 0u
        || result.released != NINLIL_IDENTITY_ATTACHMENT_TRUE) {
        secure_zero(&request, sizeof(request));
        secure_zero(&result, sizeof(result));
        return NINLIL_E_INVALID_STATE;
    }
    secure_zero(&consumer->binding_handle, sizeof(consumer->binding_handle));
    secure_zero(&consumer->binding_snapshot,
        sizeof(consumer->binding_snapshot));
    secure_zero(&consumer->key_handle, sizeof(consumer->key_handle));
    consumer->has_binding = NINLIL_IDENTITY_ATTACHMENT_FALSE;
    secure_zero(&request, sizeof(request));
    secure_zero(&result, sizeof(result));
    return NINLIL_OK;
}

static ninlil_status_t begin_call(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    uint64_t owner_context_id)
{
    if (consumer == NULL || owner_context_id == 0u
        || owner_context_id != consumer->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    if (consumer->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    consumer->in_call = NINLIL_IDENTITY_ATTACHMENT_TRUE;
    return NINLIL_OK;
}

static void end_call(ninlil_identity_attachment_consumer_v1_t *consumer)
{
    consumer->in_call = NINLIL_IDENTITY_ATTACHMENT_FALSE;
}

ninlil_status_t ninlil_identity_attachment_consumer_v1_init(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    const ninlil_identity_attachment_consumer_config_v1_t *config,
    const ninlil_identity_attachment_provider_v1_t *provider)
{
    if (consumer == NULL || config == NULL || !provider_structural_ok(provider)
        || config->owner_context_id == 0u || !config_ids_and_generations_ok(config)
        || !valid_scope(config->binding_scope)
        || !valid_usage(config->required_usage_mask)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    secure_zero(consumer, sizeof(*consumer));
    consumer->owner_context_id = config->owner_context_id;
    consumer->config = *config;
    consumer->provider = *provider;
    consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_EMPTY;
    consumer->fenced = NINLIL_IDENTITY_ATTACHMENT_TRUE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_identity_attachment_consumer_v1_prepare(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    uint64_t owner_context_id)
{
    ninlil_identity_attachment_resolve_request_v1_t resolve_request;
    ninlil_identity_attachment_resolve_result_v1_t resolve_result;
    ninlil_identity_attachment_validate_request_v1_t validate_request;
    ninlil_identity_attachment_validate_result_v1_t validate_result;
    ninlil_identity_attachment_subscribe_request_v1_t subscribe_request;
    ninlil_identity_attachment_subscribe_result_v1_t subscribe_result;
    ninlil_status_t status;

    status = begin_call(consumer, owner_context_id);
    if (status != NINLIL_OK) {
        return status;
    }
    if (consumer->state != NINLIL_IDENTITY_ATTACHMENT_CONSUMER_EMPTY
        || consumer->has_binding != 0u || consumer->has_subscription != 0u) {
        end_call(consumer);
        return NINLIL_E_INVALID_STATE;
    }
    init_header(&resolve_request, sizeof(resolve_request),
        &resolve_request.abi_version, &resolve_request.struct_size);
    (void)memcpy(resolve_request.provider_instance_id,
        consumer->config.provider_instance_id,
        sizeof(resolve_request.provider_instance_id));
    resolve_request.provider_generation = consumer->config.provider_generation;
    (void)memcpy(resolve_request.runtime_instance_id,
        consumer->config.runtime_instance_id,
        sizeof(resolve_request.runtime_instance_id));
    resolve_request.runtime_generation = consumer->config.runtime_generation;
    (void)memcpy(resolve_request.module_instance_id,
        consumer->config.module_instance_id,
        sizeof(resolve_request.module_instance_id));
    resolve_request.module_generation = consumer->config.module_generation;
    resolve_request.binding_scope = consumer->config.binding_scope;
    resolve_request.requested_usage_mask = consumer->config.required_usage_mask;
    (void)memcpy(resolve_request.subject_identity_id,
        consumer->config.subject_identity_id,
        sizeof(resolve_request.subject_identity_id));
    resolve_request.deadline_tick = consumer->config.deadline_tick;
    init_header(&resolve_result, sizeof(resolve_result),
        &resolve_result.abi_version, &resolve_result.struct_size);
    status = provider_status(consumer->provider.resolve_binding(
        consumer->provider.context, &resolve_request, &resolve_result));
    if (status != NINLIL_OK || !resolve_result_ok(consumer, &resolve_result)) {
        secure_zero(&resolve_request, sizeof(resolve_request));
        secure_zero(&resolve_result, sizeof(resolve_result));
        end_call(consumer);
        return status == NINLIL_OK ? NINLIL_E_INVALID_STATE : status;
    }
    consumer->binding_handle = resolve_result.binding_handle;
    consumer->binding_snapshot = resolve_result.snapshot;
    consumer->key_handle = resolve_result.key_handle;
    consumer->has_binding = NINLIL_IDENTITY_ATTACHMENT_TRUE;
    fence(consumer);
    secure_zero(&resolve_request, sizeof(resolve_request));
    secure_zero(&resolve_result, sizeof(resolve_result));

    init_header(&validate_request, sizeof(validate_request),
        &validate_request.abi_version, &validate_request.struct_size);
    validate_request.binding_handle = consumer->binding_handle;
    validate_request.required_usage_mask = consumer->config.required_usage_mask;
    validate_request.deadline_tick = consumer->config.deadline_tick;
    init_header(&validate_result, sizeof(validate_result),
        &validate_result.abi_version, &validate_result.struct_size);
    status = provider_status(consumer->provider.validate_binding(
        consumer->provider.context, &validate_request, &validate_result));
    if (status != NINLIL_OK || !validate_result_ok(&consumer->binding_snapshot,
            &validate_result)) {
        ninlil_status_t release_status = release_binding(consumer);
        secure_zero(&validate_request, sizeof(validate_request));
        secure_zero(&validate_result, sizeof(validate_result));
        end_call(consumer);
        if (release_status != NINLIL_OK) {
            consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING;
        } else {
            secure_zero(consumer, sizeof(*consumer));
        }
        if (release_status != NINLIL_OK) {
            return release_status;
        }
        return status == NINLIL_OK ? NINLIL_E_INVALID_STATE : status;
    }

    init_header(&subscribe_request, sizeof(subscribe_request),
        &subscribe_request.abi_version, &subscribe_request.struct_size);
    subscribe_request.binding_handle = consumer->binding_handle;
    subscribe_request.callback_context = consumer;
    subscribe_request.on_invalidation = on_invalidation;
    init_header(&subscribe_result, sizeof(subscribe_result),
        &subscribe_result.abi_version, &subscribe_result.struct_size);
    status = provider_status(consumer->provider.subscribe_invalidation(
        consumer->provider.context, &subscribe_request, &subscribe_result));
    if (status != NINLIL_OK) {
        ninlil_status_t release_status = release_binding(consumer);
        secure_zero(&subscribe_request, sizeof(subscribe_request));
        secure_zero(&subscribe_result, sizeof(subscribe_result));
        end_call(consumer);
        if (release_status != NINLIL_OK) {
            consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING;
        } else {
            secure_zero(consumer, sizeof(*consumer));
        }
        return release_status != NINLIL_OK ? release_status : status;
    }
    if (!prefix_header_ok(subscribe_result.abi_version,
            subscribe_result.struct_size, sizeof(subscribe_result))
        || subscribe_result.flags != 0u || subscribe_result.reserved_zero != 0u
        || !subscription_matches_binding(consumer,
            &subscribe_result.subscription_handle)) {
        /* A provider may have retained callback_context despite bad output. */
        secure_zero(&subscribe_request, sizeof(subscribe_request));
        secure_zero(&subscribe_result, sizeof(subscribe_result));
        consumer->subscription_uncertain = NINLIL_IDENTITY_ATTACHMENT_TRUE;
        consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING;
        end_call(consumer);
        return NINLIL_E_INVALID_STATE;
    }
    consumer->subscription_handle = subscribe_result.subscription_handle;
    consumer->has_subscription = NINLIL_IDENTITY_ATTACHMENT_TRUE;
    if (subscribe_result.subscribed_invalidation_epoch
        != consumer->binding_snapshot.invalidation_epoch) {
        /* A structurally valid handle permits close to drain callbacks safely. */
        secure_zero(&validate_request, sizeof(validate_request));
        secure_zero(&validate_result, sizeof(validate_result));
        secure_zero(&subscribe_request, sizeof(subscribe_request));
        secure_zero(&subscribe_result, sizeof(subscribe_result));
        consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING;
        end_call(consumer);
        return NINLIL_E_INVALID_STATE;
    }
    /* This kernel has no NIAF single-writer.  Never publish availability. */
    consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_PREPARED_FENCED;
    fence(consumer);
    secure_zero(&validate_request, sizeof(validate_request));
    secure_zero(&validate_result, sizeof(validate_result));
    secure_zero(&subscribe_request, sizeof(subscribe_request));
    secure_zero(&subscribe_result, sizeof(subscribe_result));
    end_call(consumer);
    return NINLIL_OK;
}

ninlil_status_t ninlil_identity_attachment_consumer_v1_close(
    ninlil_identity_attachment_consumer_v1_t *consumer,
    uint64_t owner_context_id)
{
    ninlil_status_t status;

    status = begin_call(consumer, owner_context_id);
    if (status != NINLIL_OK) {
        return status;
    }
    fence(consumer);
    consumer->state = NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING;
    if (consumer->subscription_uncertain != 0u) {
        end_call(consumer);
        return NINLIL_E_INVALID_STATE;
    }
    if (consumer->has_subscription != 0u) {
        ninlil_identity_attachment_unsubscribe_request_v1_t request;
        ninlil_identity_attachment_unsubscribe_result_v1_t result;

        init_header(&request, sizeof(request), &request.abi_version,
            &request.struct_size);
        request.subscription_handle = consumer->subscription_handle;
        init_header(&result, sizeof(result), &result.abi_version,
            &result.struct_size);
        status = provider_status(consumer->provider.unsubscribe_invalidation(
            consumer->provider.context, &request, &result));
        if (status != NINLIL_OK
            || !prefix_header_ok(result.abi_version, result.struct_size,
                sizeof(result))
            || result.flags != 0u
            || result.callbacks_drained != NINLIL_IDENTITY_ATTACHMENT_TRUE) {
            secure_zero(&request, sizeof(request));
            secure_zero(&result, sizeof(result));
            end_call(consumer);
            return status == NINLIL_OK ? NINLIL_E_INVALID_STATE : status;
        }
        secure_zero(&consumer->subscription_handle,
            sizeof(consumer->subscription_handle));
        consumer->has_subscription = NINLIL_IDENTITY_ATTACHMENT_FALSE;
        secure_zero(&request, sizeof(request));
        secure_zero(&result, sizeof(result));
    }
    if (consumer->has_binding != 0u) {
        status = release_binding(consumer);
        if (status != NINLIL_OK) {
            end_call(consumer);
            return status;
        }
    }
    secure_zero(consumer, sizeof(*consumer));
    return NINLIL_OK;
}

uint32_t ninlil_identity_attachment_consumer_v1_available(
    const ninlil_identity_attachment_consumer_v1_t *consumer)
{
    (void)consumer;
    return NINLIL_IDENTITY_ATTACHMENT_FALSE;
}
