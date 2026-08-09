/* SPDX-License-Identifier: Apache-2.0 */
#include "identity_attachment_v1/identity_attachment_v1_consumer.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "requirement failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef enum fake_mode {
    FAKE_OK = 0,
    FAKE_CROSS_RUNTIME,
    FAKE_CROSS_MODULE,
    FAKE_CROSS_PROVIDER,
    FAKE_STALE,
    FAKE_EXPIRED,
    FAKE_REVOKED,
    FAKE_SUPERSEDED,
    FAKE_BAD_KEY_FLAGS,
    FAKE_AUTH_FAILURE,
    FAKE_UNKNOWN_STATUS,
    FAKE_BAD_HEADER,
    FAKE_VALIDATE_ROLLBACK,
    FAKE_VALIDATE_FORWARD,
    FAKE_SUBSCRIBE_EPOCH_ROLLBACK,
    FAKE_SUBSCRIBE_EPOCH_FORWARD,
    FAKE_REENTRY,
    FAKE_SUBSCRIBE_FAIL,
    FAKE_SUBSCRIBE_BAD_OUTPUT,
    FAKE_SUBSCRIBE_INVALIDATES,
    FAKE_UNSUBSCRIBE_FAIL,
    FAKE_UNSUBSCRIBE_UNDRAINED,
    FAKE_RELEASE_BAD_BOOLEAN
} fake_mode_t;

typedef struct fake_provider {
    fake_mode_t mode;
    uint8_t seed;
    uint32_t calls[8];
    uint32_t call_count;
    ninlil_identity_attachment_on_invalidation_v1_fn callback;
    void *callback_context;
    ninlil_identity_attachment_consumer_v1_t *reentrant_consumer;
    uint64_t reentrant_owner;
    ninlil_status_t reentry_status;
    ninlil_status_t release_status;
} fake_provider_t;

enum {
    CALL_RESOLVE = 1,
    CALL_VALIDATE = 2,
    CALL_SUBSCRIBE = 3,
    CALL_UNSUBSCRIBE = 4,
    CALL_RELEASE = 5
};

static void set_id(uint8_t value[16], uint8_t seed)
{
    uint32_t index;

    for (index = 0u; index < 16u; ++index) {
        value[index] = (uint8_t)(seed + index);
    }
}

static void header(void *object, size_t size, uint32_t *abi_version,
    uint32_t *struct_size)
{
    (void)memset(object, 0, size);
    *abi_version = NINLIL_IDENTITY_ATTACHMENT_PROVIDER_ABI_V1;
    *struct_size = (uint32_t)size;
}

static void call(fake_provider_t *provider, uint32_t value)
{
    provider->calls[provider->call_count++] = value;
}

static void fill_result(
    const ninlil_identity_attachment_resolve_request_v1_t *request,
    ninlil_identity_attachment_resolve_result_v1_t *result,
    uint8_t seed)
{
    header(result, sizeof(*result), &result->abi_version, &result->struct_size);
    result->binding_verdict = NINLIL_IDENTITY_BINDING_VALID;
    header(&result->snapshot, sizeof(result->snapshot),
        &result->snapshot.abi_version, &result->snapshot.struct_size);
    (void)memcpy(result->snapshot.provider_instance_id,
        request->provider_instance_id, 16u);
    result->snapshot.provider_generation = request->provider_generation;
    (void)memcpy(result->snapshot.runtime_instance_id,
        request->runtime_instance_id, 16u);
    result->snapshot.runtime_generation = request->runtime_generation;
    (void)memcpy(result->snapshot.module_instance_id,
        request->module_instance_id, 16u);
    result->snapshot.module_generation = request->module_generation;
    (void)memcpy(result->snapshot.stable_identity_id,
        request->subject_identity_id, 16u);
    result->snapshot.credential_revision = 1u;
    (void)memset(result->snapshot.identity_binding_digest, 0xa1,
        sizeof(result->snapshot.identity_binding_digest));
    set_id(result->snapshot.membership_authority_id, (uint8_t)(seed + 2u));
    result->snapshot.membership_epoch = 1u;
    (void)memset(result->snapshot.membership_set_digest, 0xa2,
        sizeof(result->snapshot.membership_set_digest));
    set_id(result->snapshot.attachment_id, (uint8_t)(seed + 3u));
    result->snapshot.attachment_generation = 1u;
    set_id(result->snapshot.session_id, (uint8_t)(seed + 4u));
    result->snapshot.session_generation = 1u;
    set_id(result->snapshot.security_context_id, (uint8_t)(seed + 5u));
    result->snapshot.security_epoch = 1u;
    set_id(result->snapshot.expiry_authority_id, (uint8_t)(seed + 6u));
    result->snapshot.expiry_epoch = 1u;
    result->snapshot.not_before_tick = 1u;
    result->snapshot.expires_at_tick = 2u;
    result->snapshot.invalidation_epoch = 1u;
    header(&result->binding_handle, sizeof(result->binding_handle),
        &result->binding_handle.abi_version, &result->binding_handle.struct_size);
    (void)memcpy(result->binding_handle.provider_instance_id,
        request->provider_instance_id, 16u);
    result->binding_handle.provider_generation = request->provider_generation;
    set_id(result->binding_handle.binding_handle_id, (uint8_t)(seed + 7u));
    result->binding_handle.binding_handle_generation = 9u;
    (void)memset(result->binding_handle.opaque_token, 0xb1,
        sizeof(result->binding_handle.opaque_token));
    (void)memcpy(result->binding_handle.runtime_instance_id,
        request->runtime_instance_id, 16u);
    result->binding_handle.runtime_generation = request->runtime_generation;
    (void)memcpy(result->binding_handle.module_instance_id,
        request->module_instance_id, 16u);
    result->binding_handle.module_generation = request->module_generation;
    header(&result->key_handle, sizeof(result->key_handle),
        &result->key_handle.abi_version, &result->key_handle.struct_size);
    (void)memcpy(result->key_handle.provider_instance_id,
        request->provider_instance_id, 16u);
    result->key_handle.provider_generation = request->provider_generation;
    (void)memcpy(result->key_handle.binding_handle_id,
        result->binding_handle.binding_handle_id, 16u);
    result->key_handle.binding_handle_generation = 9u;
    set_id(result->key_handle.key_handle_id, (uint8_t)(seed + 8u));
    result->key_handle.key_generation = 10u;
    result->key_handle.usage_mask = NINLIL_KEY_USAGE_AUTH_TAG;
    result->key_handle.flags = NINLIL_KEY_HANDLE_REQUIRED_FLAGS_MASK;
    (void)memset(result->key_handle.opaque_token, 0xb2,
        sizeof(result->key_handle.opaque_token));
}

static ninlil_status_t fake_resolve(void *context,
    const ninlil_identity_attachment_resolve_request_v1_t *request,
    ninlil_identity_attachment_resolve_result_v1_t *result)
{
    fake_provider_t *provider = context;

    call(provider, CALL_RESOLVE);
    if (result->abi_version != NINLIL_IDENTITY_ATTACHMENT_PROVIDER_ABI_V1
        || result->struct_size != sizeof(*result)) {
        return NINLIL_E_INVALID_STATE;
    }
    fill_result(request, result, provider->seed);
    if (provider->mode == FAKE_REENTRY) {
        provider->reentry_status = ninlil_identity_attachment_consumer_v1_prepare(
            provider->reentrant_consumer, provider->reentrant_owner);
    }
    switch (provider->mode) {
    case FAKE_CROSS_RUNTIME:
        result->snapshot.runtime_instance_id[0] ^= 1u;
        break;
    case FAKE_CROSS_MODULE:
        result->binding_handle.module_instance_id[0] ^= 1u;
        break;
    case FAKE_CROSS_PROVIDER:
        result->key_handle.provider_instance_id[0] ^= 1u;
        break;
    case FAKE_STALE:
        result->binding_verdict = NINLIL_IDENTITY_BINDING_STALE;
        break;
    case FAKE_EXPIRED:
        result->binding_verdict = NINLIL_IDENTITY_BINDING_EXPIRED;
        break;
    case FAKE_REVOKED:
        result->binding_verdict = NINLIL_IDENTITY_BINDING_REVOKED;
        break;
    case FAKE_SUPERSEDED:
        result->binding_verdict = NINLIL_IDENTITY_BINDING_SUPERSEDED;
        break;
    case FAKE_BAD_KEY_FLAGS:
        result->key_handle.flags = 0u;
        break;
    case FAKE_AUTH_FAILURE:
        return NINLIL_IDENTITY_ATTACHMENT_E_AUTHENTICATION_FAILED;
    case FAKE_UNKNOWN_STATUS:
        return (ninlil_status_t)99;
    case FAKE_BAD_HEADER:
        result->abi_version = 2u;
        break;
    default:
        break;
    }
    return NINLIL_OK;
}

static ninlil_status_t fake_validate(void *context,
    const ninlil_identity_attachment_validate_request_v1_t *request,
    ninlil_identity_attachment_validate_result_v1_t *result)
{
    fake_provider_t *provider = context;

    (void)request;
    call(provider, CALL_VALIDATE);
    header(result, sizeof(*result), &result->abi_version, &result->struct_size);
    result->binding_verdict = NINLIL_IDENTITY_BINDING_VALID;
    result->authoritative_invalidation_epoch = 1u;
    result->authoritative_expiry_epoch = 1u;
    if (provider->mode == FAKE_VALIDATE_ROLLBACK) {
        result->authoritative_invalidation_epoch = 0u;
    } else if (provider->mode == FAKE_VALIDATE_FORWARD) {
        result->authoritative_invalidation_epoch = 2u;
    }
    return NINLIL_OK;
}

static ninlil_status_t fake_key_operation(void *context,
    const ninlil_identity_attachment_key_operation_request_v1_t *request,
    ninlil_identity_attachment_key_operation_result_v1_t *result)
{
    (void)context;
    (void)request;
    header(result, sizeof(*result), &result->abi_version, &result->struct_size);
    return NINLIL_E_UNSUPPORTED;
}

static ninlil_status_t fake_release(void *context,
    const ninlil_identity_attachment_release_request_v1_t *request,
    ninlil_identity_attachment_release_result_v1_t *result)
{
    fake_provider_t *provider = context;

    (void)request;
    call(provider, CALL_RELEASE);
    header(result, sizeof(*result), &result->abi_version, &result->struct_size);
    if (provider->release_status != NINLIL_OK) {
        return provider->release_status;
    }
    result->released = provider->mode == FAKE_RELEASE_BAD_BOOLEAN ? 2u
        : NINLIL_IDENTITY_ATTACHMENT_TRUE;
    return NINLIL_OK;
}

static ninlil_status_t fake_subscribe(void *context,
    const ninlil_identity_attachment_subscribe_request_v1_t *request,
    ninlil_identity_attachment_subscribe_result_v1_t *result)
{
    fake_provider_t *provider = context;

    call(provider, CALL_SUBSCRIBE);
    provider->callback = request->on_invalidation;
    provider->callback_context = request->callback_context;
    if (provider->mode == FAKE_SUBSCRIBE_INVALIDATES) {
        provider->callback(provider->callback_context, NULL);
    }
    if (provider->mode == FAKE_SUBSCRIBE_FAIL) {
        return NINLIL_E_CONFLICT;
    }
    header(result, sizeof(*result), &result->abi_version, &result->struct_size);
    header(&result->subscription_handle, sizeof(result->subscription_handle),
        &result->subscription_handle.abi_version,
        &result->subscription_handle.struct_size);
    (void)memcpy(result->subscription_handle.provider_instance_id,
        request->binding_handle.provider_instance_id, 16u);
    result->subscription_handle.provider_generation =
        request->binding_handle.provider_generation;
    (void)memcpy(result->subscription_handle.binding_handle_id,
        request->binding_handle.binding_handle_id, 16u);
    result->subscription_handle.binding_handle_generation =
        request->binding_handle.binding_handle_generation;
    set_id(result->subscription_handle.subscription_id, (uint8_t)(provider->seed + 9u));
    result->subscription_handle.subscription_generation = 11u;
    (void)memset(result->subscription_handle.opaque_token, 0xb3,
        sizeof(result->subscription_handle.opaque_token));
    result->subscribed_invalidation_epoch = 1u;
    if (provider->mode == FAKE_SUBSCRIBE_EPOCH_ROLLBACK) {
        result->subscribed_invalidation_epoch = 0u;
    } else if (provider->mode == FAKE_SUBSCRIBE_EPOCH_FORWARD) {
        result->subscribed_invalidation_epoch = 2u;
    }
    if (provider->mode == FAKE_SUBSCRIBE_BAD_OUTPUT) {
        result->abi_version = 2u;
    }
    return NINLIL_OK;
}

static ninlil_status_t fake_unsubscribe(void *context,
    const ninlil_identity_attachment_unsubscribe_request_v1_t *request,
    ninlil_identity_attachment_unsubscribe_result_v1_t *result)
{
    fake_provider_t *provider = context;

    (void)request;
    call(provider, CALL_UNSUBSCRIBE);
    if (provider->mode == FAKE_UNSUBSCRIBE_FAIL) {
        return NINLIL_E_WOULD_BLOCK;
    }
    header(result, sizeof(*result), &result->abi_version, &result->struct_size);
    result->callbacks_drained = provider->mode == FAKE_UNSUBSCRIBE_UNDRAINED
        ? NINLIL_IDENTITY_ATTACHMENT_FALSE : NINLIL_IDENTITY_ATTACHMENT_TRUE;
    return NINLIL_OK;
}

static ninlil_identity_attachment_provider_v1_t fake_descriptor(
    fake_provider_t *provider)
{
    ninlil_identity_attachment_provider_v1_t descriptor;

    header(&descriptor, sizeof(descriptor), &descriptor.abi_version,
        &descriptor.struct_size);
    descriptor.context = provider;
    descriptor.resolve_binding = fake_resolve;
    descriptor.validate_binding = fake_validate;
    descriptor.perform_key_operation = fake_key_operation;
    descriptor.release_binding = fake_release;
    descriptor.subscribe_invalidation = fake_subscribe;
    descriptor.unsubscribe_invalidation = fake_unsubscribe;
    return descriptor;
}

static ninlil_identity_attachment_consumer_config_v1_t fake_config(uint8_t seed)
{
    ninlil_identity_attachment_consumer_config_v1_t config;

    (void)memset(&config, 0, sizeof(config));
    config.owner_context_id = (uint64_t)seed + 100u;
    set_id(config.provider_instance_id, seed);
    config.provider_generation = 1u;
    set_id(config.runtime_instance_id, (uint8_t)(seed + 16u));
    config.runtime_generation = 2u;
    set_id(config.module_instance_id, (uint8_t)(seed + 32u));
    config.module_generation = 3u;
    set_id(config.subject_identity_id, (uint8_t)(seed + 48u));
    config.binding_scope = NINLIL_IDENTITY_SCOPE_LOCAL_ACTIVE_SESSION;
    config.required_usage_mask = NINLIL_KEY_USAGE_AUTH_TAG;
    config.deadline_tick = 1000u;
    return config;
}

static int test_isolation_and_prepare(void)
{
    fake_provider_t provider_a = { .seed = 1u };
    fake_provider_t provider_b = { .seed = 101u };
    ninlil_identity_attachment_consumer_v1_t consumer_a;
    ninlil_identity_attachment_consumer_v1_t consumer_b;
    ninlil_identity_attachment_consumer_config_v1_t config_a = fake_config(1u);
    ninlil_identity_attachment_consumer_config_v1_t config_b = fake_config(101u);
    ninlil_identity_attachment_provider_v1_t descriptor_a = fake_descriptor(&provider_a);
    ninlil_identity_attachment_provider_v1_t descriptor_b = fake_descriptor(&provider_b);

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer_a, &config_a, &descriptor_a) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer_b, &config_b, &descriptor_b) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer_a, config_a.owner_context_id) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer_b, config_b.owner_context_id) == NINLIL_OK);
    REQUIRE(provider_a.callback_context == &consumer_a);
    REQUIRE(provider_b.callback_context == &consumer_b);
    REQUIRE(consumer_a.state == NINLIL_IDENTITY_ATTACHMENT_CONSUMER_PREPARED_FENCED);
    REQUIRE(ninlil_identity_attachment_consumer_v1_available(&consumer_a) == 0u);
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer_a, config_a.owner_context_id) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer_b, config_b.owner_context_id) == NINLIL_OK);
    return 0;
}

static int test_rejected_results(void)
{
    static const fake_mode_t modes[] = {
        FAKE_CROSS_RUNTIME, FAKE_CROSS_MODULE, FAKE_CROSS_PROVIDER,
        FAKE_STALE, FAKE_EXPIRED, FAKE_REVOKED, FAKE_SUPERSEDED,
        FAKE_BAD_KEY_FLAGS, FAKE_AUTH_FAILURE, FAKE_UNKNOWN_STATUS,
        FAKE_BAD_HEADER, FAKE_VALIDATE_ROLLBACK, FAKE_VALIDATE_FORWARD
    };
    uint32_t index;

    for (index = 0u; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        fake_provider_t provider = { .mode = modes[index], .seed = (uint8_t)(20u + index) };
        ninlil_identity_attachment_consumer_v1_t consumer;
        ninlil_identity_attachment_consumer_config_v1_t config =
            fake_config((uint8_t)(20u + index));
        ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

        REQUIRE(ninlil_identity_attachment_consumer_v1_init(
            &consumer, &config, &descriptor) == NINLIL_OK);
        ninlil_status_t status = ninlil_identity_attachment_consumer_v1_prepare(
            &consumer, config.owner_context_id);
        REQUIRE(status != NINLIL_OK);
        if (modes[index] == FAKE_AUTH_FAILURE) {
            REQUIRE(status == NINLIL_E_DEGRADED);
        }
        if (modes[index] == FAKE_UNKNOWN_STATUS || modes[index] == FAKE_BAD_HEADER
            || modes[index] == FAKE_VALIDATE_ROLLBACK
            || modes[index] == FAKE_VALIDATE_FORWARD) {
            REQUIRE(status == NINLIL_E_INVALID_STATE);
        }
        REQUIRE(ninlil_identity_attachment_consumer_v1_available(&consumer) == 0u);
        REQUIRE(consumer.has_binding == 0u);
    }
    return 0;
}

static int test_epoch_gaps_close_with_known_handle(void)
{
    static const fake_mode_t modes[] = {
        FAKE_SUBSCRIBE_EPOCH_ROLLBACK, FAKE_SUBSCRIBE_EPOCH_FORWARD
    };
    uint32_t index;
    fake_provider_t validate_provider = { .mode = FAKE_VALIDATE_FORWARD, .seed = 59u };
    ninlil_identity_attachment_consumer_v1_t validate_consumer;
    ninlil_identity_attachment_consumer_config_v1_t validate_config = fake_config(59u);
    ninlil_identity_attachment_provider_v1_t validate_descriptor =
        fake_descriptor(&validate_provider);

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &validate_consumer, &validate_config, &validate_descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &validate_consumer, validate_config.owner_context_id) == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_identity_attachment_consumer_v1_available(&validate_consumer) == 0u);
    REQUIRE(validate_consumer.owner_context_id == 0u);
    REQUIRE(validate_provider.call_count == 3u);
    REQUIRE(validate_provider.calls[0] == CALL_RESOLVE
        && validate_provider.calls[1] == CALL_VALIDATE
        && validate_provider.calls[2] == CALL_RELEASE);

    for (index = 0u; index < sizeof(modes) / sizeof(modes[0]); ++index) {
        fake_provider_t provider = { .mode = modes[index], .seed = (uint8_t)(60u + index) };
        ninlil_identity_attachment_consumer_v1_t consumer;
        ninlil_identity_attachment_consumer_config_v1_t config =
            fake_config((uint8_t)(60u + index));
        ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

        REQUIRE(ninlil_identity_attachment_consumer_v1_init(
            &consumer, &config, &descriptor) == NINLIL_OK);
        REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
            &consumer, config.owner_context_id) == NINLIL_E_INVALID_STATE);
        REQUIRE(ninlil_identity_attachment_consumer_v1_available(&consumer) == 0u);
        REQUIRE(consumer.state == NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING);
        REQUIRE(consumer.subscription_uncertain == NINLIL_IDENTITY_ATTACHMENT_FALSE);
        REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
        REQUIRE(consumer.has_subscription == NINLIL_IDENTITY_ATTACHMENT_TRUE);
        REQUIRE(ninlil_identity_attachment_consumer_v1_close(
            &consumer, config.owner_context_id) == NINLIL_OK);
        REQUIRE(provider.call_count == 5u);
        REQUIRE(provider.calls[0] == CALL_RESOLVE && provider.calls[1] == CALL_VALIDATE
            && provider.calls[2] == CALL_SUBSCRIBE
            && provider.calls[3] == CALL_UNSUBSCRIBE
            && provider.calls[4] == CALL_RELEASE);
    }
    return 0;
}

static int test_prepare_cleanup_retry(void)
{
    fake_provider_t provider = { .mode = FAKE_VALIDATE_ROLLBACK, .seed = 66u,
        .release_status = NINLIL_E_WOULD_BLOCK };
    ninlil_identity_attachment_consumer_v1_t consumer;
    ninlil_identity_attachment_consumer_config_v1_t config = fake_config(66u);
    ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_E_WOULD_BLOCK);
    REQUIRE(consumer.state == NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING);
    REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    REQUIRE(ninlil_identity_attachment_consumer_v1_available(&consumer) == 0u);
    provider.release_status = NINLIL_OK;
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_OK);

    provider.mode = FAKE_SUBSCRIBE_FAIL;
    provider.release_status = NINLIL_E_WOULD_BLOCK;
    provider.call_count = 0u;
    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_E_WOULD_BLOCK);
    REQUIRE(consumer.state == NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING);
    REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    provider.release_status = NINLIL_OK;
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_OK);
    return 0;
}

static int test_config_owner_and_reentry(void)
{
    fake_provider_t provider = { .mode = FAKE_REENTRY, .seed = 110u };
    ninlil_identity_attachment_consumer_v1_t consumer;
    ninlil_identity_attachment_consumer_config_v1_t config = fake_config(110u);
    ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

    config.runtime_generation = 0u;
    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_E_INVALID_ARGUMENT);
    config = fake_config(110u);
    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id + 1u) == NINLIL_E_WRONG_THREAD);
    provider.reentrant_consumer = &consumer;
    provider.reentrant_owner = config.owner_context_id;
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_OK);
    REQUIRE(provider.reentry_status == NINLIL_E_REENTRANT);
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_OK);
    return 0;
}

static int test_subscribe_and_close_fail_closed(void)
{
    fake_provider_t provider = { .mode = FAKE_SUBSCRIBE_FAIL, .seed = 70u };
    ninlil_identity_attachment_consumer_v1_t consumer;
    ninlil_identity_attachment_consumer_config_v1_t config = fake_config(70u);
    ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_E_CONFLICT);
    REQUIRE(provider.call_count == 4u);
    REQUIRE(provider.calls[0] == CALL_RESOLVE && provider.calls[1] == CALL_VALIDATE);
    REQUIRE(provider.calls[2] == CALL_SUBSCRIBE && provider.calls[3] == CALL_RELEASE);
    REQUIRE(consumer.has_binding == 0u);
    return 0;
}

static int test_invalidation_and_unsubscribe_retry(void)
{
    fake_provider_t provider = { .mode = FAKE_SUBSCRIBE_INVALIDATES, .seed = 80u };
    ninlil_identity_attachment_consumer_v1_t consumer;
    ninlil_identity_attachment_consumer_config_v1_t config = fake_config(80u);
    ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_OK);
    REQUIRE(consumer.fenced == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    provider.mode = FAKE_UNSUBSCRIBE_FAIL;
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_E_WOULD_BLOCK);
    REQUIRE(consumer.has_subscription == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    provider.mode = FAKE_UNSUBSCRIBE_UNDRAINED;
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_E_INVALID_STATE);
    REQUIRE(consumer.has_subscription == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    provider.mode = FAKE_OK;
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_OK);
    return 0;
}

static int test_malformed_subscribe_quarantine(void)
{
    fake_provider_t provider = { .mode = FAKE_SUBSCRIBE_BAD_OUTPUT, .seed = 85u };
    ninlil_identity_attachment_consumer_v1_t consumer;
    ninlil_identity_attachment_consumer_config_v1_t config = fake_config(85u);
    ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);
    uint32_t calls_after_prepare;

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_E_INVALID_STATE);
    REQUIRE(consumer.state == NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING);
    REQUIRE(consumer.subscription_uncertain == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    REQUIRE(provider.callback_context == &consumer && provider.callback != NULL);
    calls_after_prepare = provider.call_count;
    consumer.fenced = NINLIL_IDENTITY_ATTACHMENT_FALSE;
    provider.callback(provider.callback_context, NULL);
    REQUIRE(consumer.fenced == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    REQUIRE(consumer.state == NINLIL_IDENTITY_ATTACHMENT_CONSUMER_CLOSING);
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_E_INVALID_STATE);
    REQUIRE(provider.call_count == calls_after_prepare);
    REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    return 0;
}

static int test_release_boolean_retry(void)
{
    fake_provider_t provider = { .mode = FAKE_RELEASE_BAD_BOOLEAN, .seed = 90u };
    ninlil_identity_attachment_consumer_v1_t consumer;
    ninlil_identity_attachment_consumer_config_v1_t config = fake_config(90u);
    ninlil_identity_attachment_provider_v1_t descriptor = fake_descriptor(&provider);

    REQUIRE(ninlil_identity_attachment_consumer_v1_init(
        &consumer, &config, &descriptor) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_prepare(
        &consumer, config.owner_context_id) == NINLIL_OK);
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_E_INVALID_STATE);
    REQUIRE(consumer.has_binding == NINLIL_IDENTITY_ATTACHMENT_TRUE);
    provider.mode = FAKE_OK;
    REQUIRE(ninlil_identity_attachment_consumer_v1_close(
        &consumer, config.owner_context_id) == NINLIL_OK);
    return 0;
}

int main(void)
{
    REQUIRE(test_isolation_and_prepare() == 0);
    REQUIRE(test_rejected_results() == 0);
    REQUIRE(test_epoch_gaps_close_with_known_handle() == 0);
    REQUIRE(test_prepare_cleanup_retry() == 0);
    REQUIRE(test_subscribe_and_close_fail_closed() == 0);
    REQUIRE(test_invalidation_and_unsubscribe_retry() == 0);
    REQUIRE(test_malformed_subscribe_quarantine() == 0);
    REQUIRE(test_release_boolean_retry() == 0);
    REQUIRE(test_config_owner_and_reentry() == 0);
    (void)printf("identity_attachment_v1_consumer_test: PASS\n");
    return 0;
}
