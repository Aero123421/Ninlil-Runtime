/*
 * V1-LAB unit 2b: durable delivery path, event_resume/discard, restart.
 */

#include "deterministic_entropy.h"
#include "domain_store_codec.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_store_codec.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_transaction_codec.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "v1-runtime-delivery-test";
static const uint8_t TEST_ENDPOINT_NAMESPACE[] =
    "v1-runtime-delivery-endpoint";
static const uint8_t TEST_IDEM_EVENT_A[] = "event-idem-a";
static const char NS_TEXT[] = "org.ninlil.examples";
static const char EVT_TEXT[] = "event-fact";

static uint32_t g_delivery_calls;
static uint32_t g_fail_delivery;
static uint32_t g_defer_delivery;
static ninlil_delivery_token_t g_deferred_token;
static uint8_t g_sync_evidence[4] = {0x91u, 0x92u, 0x93u, 0x94u};

typedef enum callback_clock_fault {
    CALLBACK_CLOCK_FAULT_NONE = 0,
    CALLBACK_CLOCK_FAULT_TEMPORARY = 1,
    CALLBACK_CLOCK_FAULT_UNCERTAIN = 2,
    CALLBACK_CLOCK_FAULT_PERMANENT = 3,
    CALLBACK_CLOCK_FAULT_INVALID = 4,
    CALLBACK_CLOCK_FAULT_EPOCH = 5,
    CALLBACK_CLOCK_FAULT_ROLLBACK = 6,
    CALLBACK_CLOCK_FAULT_EXPIRY = 7,
    CALLBACK_CLOCK_FAULT_INVALID_RESERVED = 8,
    CALLBACK_CLOCK_FAULT_INVALID_VERSION = 9
} callback_clock_fault_t;

typedef enum callback_storage_fault {
    CALLBACK_STORAGE_FAULT_NONE = 0,
    CALLBACK_STORAGE_FAULT_DEFINITE = 1,
    CALLBACK_STORAGE_FAULT_CU_NOT_COMMITTED = 2,
    CALLBACK_STORAGE_FAULT_CU_COMMITTED = 3
} callback_storage_fault_t;

typedef struct callback_fault_context {
    ninlil_runtime_t *runtime;
    ninlil_test_clock_t *clock;
    ninlil_test_storage_t *storage;
    callback_clock_fault_t clock_fault;
    callback_storage_fault_t storage_fault;
    uint64_t rollback_now_ms;
    uint32_t clock_scripted;
    uint32_t storage_scripted;
    uint32_t controller_recovery_hook;
    uint32_t recovery_before_hook_count;
    uint32_t recovery_after_hook_count;
    uint32_t application_before_hook_count;
    uint32_t application_effect_hook_count;
    uint32_t application_after_hook_count;
    uint32_t callback_entry_saw_before_hook;
    uint32_t effect_hook_saw_callback_entry;
    uint32_t after_hook_saw_callback_return;
    uint32_t after_hook_saw_result_copy;
    uint32_t callback_returned;
    uint32_t unexpected_hook_count;
} callback_fault_context_t;

typedef struct delivery_env {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_bearer_t *bearer_fixture;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    ninlil_concrete_target_t target;
    uint8_t payload[16];
} delivery_env_t;

static int setup_active_inbound_deliveries(
    delivery_env_t *env,
    const uint8_t *transaction_tags,
    uint32_t transaction_count,
    uint32_t delivery_limit,
    uint32_t deferred_limit,
    ninlil_status_t expected_step_status);
static int setup_active_inbound_deliveries_at(
    delivery_env_t *env,
    const uint8_t *transaction_tags,
    uint32_t transaction_count,
    uint32_t delivery_limit,
    uint32_t deferred_limit,
    uint64_t initial_time_ms,
    ninlil_status_t expected_step_status);

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static void set_txn_id(ninlil_id128_t *id, uint8_t first)
{
    set_id(id, first);
    id->bytes[14] = 0u;
    id->bytes[15] = 0u;
}

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static ninlil_origin_auth_status_t origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)memset(decision, 0, sizeof(*decision));
    set_header(&decision->abi_version, &decision->struct_size, sizeof(*decision));
    decision->allowed = 1u;
    decision->reason = NINLIL_REASON_NONE;
    decision->retry_guidance = NINLIL_RETRY_NEVER;
    set_id(&decision->provider_id, 0x07u);
    decision->provider_revision = 1u;
    set_digest(&decision->decision_digest, 0x08u);
    set_id(&decision->grant_id, 0x09u);
    decision->grant_revision = 1u;
    decision->clock_epoch_id = request->now.clock_epoch_id;
    decision->evaluated_at_ms = request->now.now_ms;
    decision->valid_from_ms = request->now.now_ms;
    decision->expires_at_ms = request->now.now_ms + 86400000u;
    decision->max_payload_bytes = 1024u;
    decision->max_active_spool_count = 32u;
    decision->max_active_spool_bytes = 32768u;
    decision->rate_window_ms = 10000u;
    decision->max_admissions_per_window = 20u;
    decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static ninlil_callback_action_t delivery_complete_cb(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    (void)user;
    (void)token;
    (void)delivery;
    g_delivery_calls += 1u;
    if (g_fail_delivery != 0u) {
        return NINLIL_CALLBACK_FATAL;
    }
    if (g_defer_delivery != 0u) {
        g_deferred_token = *token;
        return NINLIL_CALLBACK_DEFER;
    }
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_callback_action_t delivery_complete_after_clock_advance_cb(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    ninlil_test_clock_t *clock = (ninlil_test_clock_t *)user;

    (void)token;
    (void)delivery;
    g_delivery_calls += 1u;
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    out_sync_result->retry_guidance = NINLIL_RETRY_NEVER;
    out_sync_result->evidence.data = g_sync_evidence;
    out_sync_result->evidence.length = sizeof(g_sync_evidence);
    (void)ninlil_test_clock_advance(clock, 2u);
    return NINLIL_CALLBACK_COMPLETE;
}

static void observe_callback_recovery_hook(void *user, const char *name)
{
    callback_fault_context_t *context =
        (callback_fault_context_t *)user;
    const char *before_name = context->controller_recovery_hook != 0u
        ? "controller.before_callback_recovery_commit"
        : "endpoint.before_callback_recovery_commit";
    const char *after_name = context->controller_recovery_hook != 0u
        ? "controller.after_callback_recovery_commit"
        : "endpoint.after_callback_recovery_commit";
    const char *application_before_name =
        context->controller_recovery_hook != 0u
        ? "controller.before_application_callback"
        : "endpoint.before_application_callback";
    const char *application_after_name =
        context->controller_recovery_hook != 0u
        ? "controller.after_application_callback"
        : "endpoint.after_application_callback";
    const char *application_effect_name =
        context->controller_recovery_hook != 0u
        ? "controller.after_application_effect"
        : "endpoint.after_application_effect";

    if (strcmp(name, before_name) == 0) {
        context->recovery_before_hook_count += 1u;
    } else if (strcmp(name, after_name) == 0) {
        context->recovery_after_hook_count += 1u;
    } else if (strcmp(name, application_before_name) == 0) {
        context->application_before_hook_count += 1u;
        if (context->application_before_hook_count != 1u
            || context->application_effect_hook_count != 0u
            || context->application_after_hook_count != 0u
            || context->callback_returned != 0u) {
            context->unexpected_hook_count += 1u;
        }
    } else if (strcmp(name, application_effect_name) == 0) {
        context->application_effect_hook_count += 1u;
        if (context->application_effect_hook_count == 1u
            && context->application_before_hook_count == 1u
            && context->application_after_hook_count == 0u
            && context->callback_entry_saw_before_hook == 1u
            && context->callback_returned == 0u) {
            context->effect_hook_saw_callback_entry = 1u;
        } else {
            context->unexpected_hook_count += 1u;
        }
    } else if (strcmp(name, application_after_name) == 0) {
        context->application_after_hook_count += 1u;
        if (context->application_after_hook_count == 1u
            && context->application_before_hook_count == 1u
            && context->application_effect_hook_count == 1u
            && context->callback_returned != 0u) {
            context->after_hook_saw_callback_return = 1u;
            if (context->runtime != NULL
                && context->runtime->callback_result_scratch.evidence.data
                    == context->runtime->callback_evidence_scratch
                && context->runtime->callback_result_scratch.evidence.length
                    == sizeof(g_sync_evidence)
                && memcmp(
                    context->runtime->callback_evidence_scratch,
                    g_sync_evidence,
                    sizeof(g_sync_evidence))
                    == 0) {
                context->after_hook_saw_result_copy = 1u;
            } else {
                context->unexpected_hook_count += 1u;
            }
        } else {
            context->unexpected_hook_count += 1u;
        }
    } else {
        context->unexpected_hook_count += 1u;
    }
}

static void dispatch_application_effect_hook(
    callback_fault_context_t *context)
{
    const char *name;

    if (context->runtime == NULL
        || context->runtime->private_transition_hook == NULL) {
        return;
    }
    name = context->runtime->config.role == NINLIL_ROLE_CONTROLLER
        ? "controller.after_application_effect"
        : "endpoint.after_application_effect";
    context->runtime->private_transition_hook(
        context->runtime->private_transition_hook_user, name);
}

static ninlil_callback_action_t delivery_complete_with_post_fault_cb(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    callback_fault_context_t *context =
        (callback_fault_context_t *)user;
    ninlil_time_sample_t sample;

    (void)delivery;
    g_delivery_calls += 1u;
    if (context->application_before_hook_count == 1u
        && context->application_effect_hook_count == 0u
        && context->application_after_hook_count == 0u
        && context->callback_returned == 0u) {
        context->callback_entry_saw_before_hook = 1u;
    } else {
        context->unexpected_hook_count += 1u;
    }
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    out_sync_result->retry_guidance = NINLIL_RETRY_NEVER;
    out_sync_result->evidence.data = g_sync_evidence;
    out_sync_result->evidence.length = sizeof(g_sync_evidence);
    dispatch_application_effect_hook(context);

    (void)memset(&sample, 0, sizeof(sample));
    set_header(&sample.abi_version, &sample.struct_size, sizeof(sample));
    sample.clock_epoch_id = token->clock_epoch_id;
    sample.now_ms = context->rollback_now_ms + 1u;
    sample.trust = NINLIL_CLOCK_TRUSTED;
    if (context->clock_fault == CALLBACK_CLOCK_FAULT_TEMPORARY) {
        context->clock_scripted = (uint32_t)ninlil_test_clock_script(
            context->clock,
            NINLIL_PORT_TEMPORARY_FAILURE,
            NULL,
            1u);
    } else if (context->clock_fault == CALLBACK_CLOCK_FAULT_UNCERTAIN) {
        sample.trust = NINLIL_CLOCK_UNCERTAIN;
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else if (context->clock_fault == CALLBACK_CLOCK_FAULT_PERMANENT) {
        context->clock_scripted = (uint32_t)ninlil_test_clock_script(
            context->clock,
            NINLIL_PORT_PERMANENT_FAILURE,
            NULL,
            1u);
    } else if (context->clock_fault == CALLBACK_CLOCK_FAULT_INVALID) {
        sample.struct_size = (uint16_t)(sizeof(sample) - 1u);
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else if (context->clock_fault
        == CALLBACK_CLOCK_FAULT_INVALID_RESERVED) {
        sample.reserved_zero = 1u;
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else if (context->clock_fault
        == CALLBACK_CLOCK_FAULT_INVALID_VERSION) {
        sample.abi_version = (uint16_t)(NINLIL_ABI_VERSION + 1u);
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else if (context->clock_fault == CALLBACK_CLOCK_FAULT_EPOCH) {
        sample.clock_epoch_id.bytes[0] ^= 0x5au;
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else if (context->clock_fault == CALLBACK_CLOCK_FAULT_ROLLBACK) {
        sample.now_ms = context->rollback_now_ms;
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else if (context->clock_fault == CALLBACK_CLOCK_FAULT_EXPIRY) {
        sample.now_ms = token->expires_at_ms + 1u;
        context->clock_scripted = (uint32_t)ninlil_test_clock_script_raw(
            context->clock, NINLIL_PORT_OK, &sample, 1u);
    } else {
        context->clock_scripted = 1u;
    }

    if (context->storage_fault == CALLBACK_STORAGE_FAULT_DEFINITE) {
        context->storage_scripted =
            (uint32_t)ninlil_test_storage_fault_enqueue(
                context->storage,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_IO_ERROR,
                1u,
                0,
                0);
    } else if (context->storage_fault
        == CALLBACK_STORAGE_FAULT_CU_NOT_COMMITTED) {
        context->storage_scripted =
            (uint32_t)ninlil_test_storage_fault_enqueue(
                context->storage,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                0);
    } else if (context->storage_fault
        == CALLBACK_STORAGE_FAULT_CU_COMMITTED) {
        context->storage_scripted =
            (uint32_t)ninlil_test_storage_fault_enqueue(
                context->storage,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                1);
    } else {
        context->storage_scripted = 1u;
    }
    context->callback_returned = 1u;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t reconcile_noop_cb(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static ninlil_runtime_config_t config_controller(uint32_t max_services)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = TEST_NAMESPACE;
    config.storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    set_header(
        &config.limits.abi_version, &config.limits.struct_size, sizeof(config.limits));
    config.limits.max_services = max_services;
    config.limits.max_nonterminal_transactions = 27u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    config.limits.max_nonterminal_deliveries = 12u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 17u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = 12u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static ninlil_runtime_config_t config_endpoint(uint32_t max_services)
{
    ninlil_runtime_config_t config = config_controller(max_services);
    config.role = NINLIL_ROLE_ENDPOINT;
    set_id(&config.runtime_id, 0x11u);
    config.limits.max_services = max_services > 8u ? 8u : max_services;
    config.limits.max_nonterminal_transactions = 32u;
    config.limits.max_durable_outbox_payload_bytes = 0u;
    config.limits.max_nonterminal_deliveries = 32u;
    config.limits.max_event_spool_count = 32u;
    config.limits.max_event_spool_bytes = 32768u;
    return config;
}

static int platform_init(delivery_env_t *env)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_bearer_config_t bearer_config;

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 4u;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = 1048576u;

    env->allocator = ninlil_test_allocator_create();
    env->execution = ninlil_test_execution_create(1u);
    env->clock = ninlil_test_clock_create();
    env->entropy = ninlil_test_entropy_create(0x3b3b3b3bu, 1u);
    env->storage_fixture = ninlil_test_storage_create(&storage_config);
    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 32u;
    bearer_config.max_bytes_per_direction = 65536u;
    bearer_config.max_permits = 32u;
    bearer_config.permit_issuer_id.bytes[0] = 0x80u;
    bearer_config.permit_issuer_id.bytes[15] = 0x01u;
    bearer_config.initial_clock_epoch_id.bytes[0] = 0xa0u;
    bearer_config.initial_clock_epoch_id.bytes[15] = 0x01u;
    env->bearer_fixture = ninlil_test_bearer_create(&bearer_config);
    if (env->allocator == NULL || env->execution == NULL || env->clock == NULL
        || env->entropy == NULL || env->storage_fixture == NULL
        || env->bearer_fixture == NULL) {
        return 0;
    }

    set_header(
        &env->origin.abi_version, &env->origin.struct_size, sizeof(env->origin));
    env->origin.evaluate = origin_allow;

    set_header(
        &env->platform.abi_version, &env->platform.struct_size, sizeof(env->platform));
    env->platform.allocator = ninlil_test_allocator_ops(env->allocator);
    env->platform.execution = ninlil_test_execution_ops(env->execution);
    env->platform.clock = ninlil_test_clock_ops(env->clock);
    env->platform.entropy = ninlil_test_entropy_ops(env->entropy);
    env->platform.storage = ninlil_test_storage_ops(env->storage_fixture);
    env->platform.bearer = ninlil_test_bearer_ops(env->bearer_fixture);
    env->platform.tx_gate = ninlil_test_bearer_tx_gate_ops(env->bearer_fixture);
    env->platform.origin_authorization = &env->origin;
    return 1;
}

static void platform_teardown(delivery_env_t *env)
{
    if (env->runtime != NULL) {
        (void)ninlil_runtime_destroy(env->runtime);
        env->runtime = NULL;
    }
    if (env->bearer_fixture != NULL) {
        ninlil_test_bearer_destroy(env->bearer_fixture);
        env->bearer_fixture = NULL;
    }
    if (env->storage_fixture != NULL) {
        ninlil_test_storage_destroy(env->storage_fixture);
        env->storage_fixture = NULL;
    }
    if (env->entropy != NULL) {
        ninlil_test_entropy_destroy(env->entropy);
        env->entropy = NULL;
    }
    if (env->clock != NULL) {
        ninlil_test_clock_destroy(env->clock);
        env->clock = NULL;
    }
    if (env->execution != NULL) {
        ninlil_test_execution_destroy(env->execution);
        env->execution = NULL;
    }
    if (env->allocator != NULL) {
        (void)ninlil_test_allocator_destroy(env->allocator);
        env->allocator = NULL;
    }
    (void)memset(env, 0, sizeof(*env));
}

static ninlil_service_descriptor_t desired_descriptor(uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor;
    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)"absolute-state";
    descriptor.service_id.length = sizeof("absolute-state") - 1u;
    descriptor.schema_id.data = (const uint8_t *)"absolute-state";
    descriptor.schema_id.length = sizeof("absolute-state") - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x11u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 1000u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 5000u;
    descriptor.maximum_deadline_ms = 5000u;
    descriptor.maximum_evidence_grace_ms = 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    return descriptor;
}

static ninlil_service_descriptor_t event_fact_descriptor(uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor;
    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)EVT_TEXT;
    descriptor.service_id.length = sizeof(EVT_TEXT) - 1u;
    descriptor.schema_id.data = (const uint8_t *)EVT_TEXT;
    descriptor.schema_id.length = sizeof(EVT_TEXT) - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x33u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_EVENT_FACT;
    descriptor.direction = NINLIL_DIRECTION_UPLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 1000u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = NINLIL_NO_DEADLINE;
    descriptor.maximum_deadline_ms = NINLIL_NO_DEADLINE;
    descriptor.maximum_evidence_grace_ms = 0u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    return descriptor;
}

static int env_create(delivery_env_t *env, ninlil_role_t role)
{
    env->config = role == NINLIL_ROLE_ENDPOINT
        ? config_endpoint(4u)
        : config_controller(4u);
    return ninlil_runtime_create(&env->config, &env->platform, &env->runtime)
        == NINLIL_OK;
}

static int env_register(
    delivery_env_t *env,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks)
{
    return ninlil_service_register(
               env->runtime, descriptor, callbacks, &env->service)
        == NINLIL_OK;
}

static void fill_step_budget(ninlil_step_budget_t *budget)
{
    (void)memset(budget, 0, sizeof(*budget));
    set_header(&budget->abi_version, &budget->struct_size, sizeof(*budget));
    budget->max_ingress_messages = 4u;
    budget->max_callbacks = 4u;
    budget->max_state_transitions = 8u;
    budget->max_bearer_sends = 4u;
}

static void fill_controller_target(ninlil_concrete_target_t *target)
{
    (void)memset(target, 0, sizeof(*target));
    set_header(&target->abi_version, &target->struct_size, sizeof(*target));
    set_id(&target->target_runtime_id, 0x10u);
    set_id(&target->target_application_instance_id, 0x81u);
    set_id(&target->device_id, 0x82u);
    set_id(&target->site_domain_id, 0x83u);
    target->binding_epoch = 1u;
    target->membership_epoch = 1u;
    target->flags = NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;
}

static void set_payload_sha256(
    ninlil_digest256_t *digest,
    const uint8_t *payload,
    uint32_t length)
{
    ninlil_model_domain_digest_t actual;

    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    (void)ninlil_model_domain_sha256(payload, length, &actual);
    (void)memcpy(digest->bytes, actual.bytes, sizeof(digest->bytes));
}

static void fill_desired_submission(
    delivery_env_t *env,
    ninlil_submission_t *submission,
    uint8_t digest_tag)
{
    static const uint8_t idem_key[] = "delivery-idem";

    (void)digest_tag;
    (void)memset(submission, 0, sizeof(*submission));
    set_header(&submission->abi_version, &submission->struct_size, sizeof(*submission));
    submission->schema_major = 1u;
    fill_controller_target(&env->target);
    submission->targets = &env->target;
    submission->target_count = 1u;
    submission->required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission->effect_deadline_ms = 5000u;
    submission->evidence_grace_ms = 1000u;
    submission->generation = 1u;
    submission->idempotency_key.data = idem_key;
    submission->idempotency_key.length = sizeof(idem_key) - 1u;
    submission->payload.data = env->payload;
    submission->payload.length = sizeof(env->payload);
    /* Vary payload by digest_tag so distinct submissions get distinct digests. */
    env->payload[0] = digest_tag;
    set_payload_sha256(
        &submission->content_digest, env->payload, sizeof(env->payload));
}

static void fill_event_submission(
    delivery_env_t *env,
    ninlil_submission_t *submission,
    uint8_t digest_tag,
    uint8_t event_tag,
    const uint8_t *idem_key,
    size_t idem_key_length)
{
    (void)memset(submission, 0, sizeof(*submission));
    set_header(&submission->abi_version, &submission->struct_size, sizeof(*submission));
    submission->schema_major = 1u;
    fill_controller_target(&env->target);
    submission->targets = &env->target;
    submission->target_count = 1u;
    submission->required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission->effect_deadline_ms = NINLIL_NO_DEADLINE;
    submission->evidence_grace_ms = 0u;
    submission->generation = 0u;
    set_id(&submission->event_id, event_tag);
    submission->idempotency_key.data = idem_key;
    submission->idempotency_key.length = idem_key_length;
    submission->payload.data = env->payload;
    submission->payload.length = sizeof(env->payload);
    env->payload[0] = digest_tag;
    set_payload_sha256(
        &submission->content_digest, env->payload, sizeof(env->payload));
}

static int seed_parked_event_txn(
    ninlil_test_storage_t *storage_fixture,
    ninlil_bytes_view_t storage_namespace,
    const ninlil_id128_t *txn_id,
    uint8_t app_tag,
    uint64_t spool_revision)
{
    const ninlil_storage_ops_t *storage = ninlil_test_storage_ops(storage_fixture);
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_id128_t app_id;
    ninlil_rt_transaction_slot_t snapshot;
    ninlil_model_runtime_store_key_t delivery_key;
    ninlil_model_runtime_store_capacity_t delivery_capacity;
    uint8_t es_key[18];
    uint8_t es_value[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t delivery_value[NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES];
    ninlil_mut_bytes_t delivery_view = {
        .data = delivery_value,
        .capacity = sizeof(delivery_value),
        .length = 0u
    };
    uint32_t es_value_length = 0u;
    uint32_t delivery_value_length = 0u;

    if (storage->open(
            storage->user,
            storage_namespace,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle)
        != NINLIL_STORAGE_OK) {
        return 0;
    }
    if (storage->begin(
            storage->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        (void)storage->close(storage->user, handle);
        return 0;
    }

    set_id(&app_id, app_tag);

    es_key[0] = 0x45u;
    es_key[1] = 0x53u;
    (void)memcpy(&es_key[2], txn_id->bytes, sizeof(txn_id->bytes));
    (void)memset(&snapshot, 0, sizeof(snapshot));
    snapshot.in_use = 1u;
    /*
     * This fixture represents a Controller-side inbound Event delivery, not
     * a local origin admission.  It therefore has no TX admission root, RV
     * reservation, or origin resource-ledger ownership.  It does own one
     * durable inbound-delivery slot until the delivery becomes terminal.
     */
    snapshot.origin_admission = 0u;
    snapshot.transaction_id = *txn_id;
    set_id(&snapshot.attempt_id, 0x6au);
    snapshot.service_app_id = app_id;
    set_id(&snapshot.event_id, 0x71u);
    set_header(
        &snapshot.source.abi_version,
        &snapshot.source.struct_size,
        sizeof(snapshot.source));
    set_id(&snapshot.source.runtime_id, 0x72u);
    snapshot.source.application_instance_id = app_id;
    set_header(
        &snapshot.source.local_identity.abi_version,
        &snapshot.source.local_identity.struct_size,
        sizeof(snapshot.source.local_identity));
    set_header(
        &snapshot.service.abi_version,
        &snapshot.service.struct_size,
        sizeof(snapshot.service));
    snapshot.service.namespace_id.length = (uint8_t)(sizeof(NS_TEXT) - 1u);
    (void)memcpy(
        snapshot.service.namespace_id.bytes,
        NS_TEXT,
        sizeof(NS_TEXT) - 1u);
    snapshot.service.service_id.length = (uint8_t)(sizeof(EVT_TEXT) - 1u);
    (void)memcpy(
        snapshot.service.service_id.bytes,
        EVT_TEXT,
        sizeof(EVT_TEXT) - 1u);
    /*
     * Must match event_fact_descriptor() identity exactly so complete
     * service-identity routing (not family-only) can deliver.
     */
    snapshot.service.schema_id.length = (uint8_t)(sizeof(EVT_TEXT) - 1u);
    (void)memcpy(
        snapshot.service.schema_id.bytes, EVT_TEXT, sizeof(EVT_TEXT) - 1u);
    snapshot.service.descriptor_revision = 1u;
    set_digest(&snapshot.service.descriptor_digest, 0x33u);
    snapshot.service.schema_major = 1u;
    snapshot.service.schema_minor = 0u;
    snapshot.service.family = NINLIL_FAMILY_EVENT_FACT;
    set_digest(&snapshot.content_digest, 0x74u);
    snapshot.family = NINLIL_FAMILY_EVENT_FACT;
    snapshot.required_evidence = NINLIL_EVIDENCE_APPLIED;
    snapshot.deadline_verdict = NINLIL_DEADLINE_NOT_APPLICABLE;
    snapshot.transaction_sequence = 1u;
    snapshot.record_revision = 1u;
    snapshot.delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    snapshot.pending_dispatch = 1u;
    snapshot.spool_revision = spool_revision;
    snapshot.retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    snapshot.retry_cycle_id = 1u;
    snapshot.effect_deadline_ms = NINLIL_NO_DEADLINE;
    snapshot.bearer_route = 1u;
    snapshot.bound_target_count = 1u;
    snapshot.bound_targets[0].in_use = 1u;
    set_header(
        &snapshot.bound_targets[0].target.abi_version,
        &snapshot.bound_targets[0].target.struct_size,
        sizeof(snapshot.bound_targets[0].target));
    set_id(
        &snapshot.bound_targets[0].target.target_runtime_id, 0x75u);
    snapshot.bound_targets[0].target.target_application_instance_id =
        app_id;
    if (ninlil_rt_v1_transaction_record_encode(
            &snapshot,
            es_value,
            (uint32_t)sizeof(es_value),
            &es_value_length)
        != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        (void)storage->close(storage->user, handle);
        return 0;
    }
    if (storage->put(
            storage->user,
            txn,
            (ninlil_bytes_view_t){es_key, sizeof(es_key)},
            (ninlil_bytes_view_t){es_value, es_value_length})
        != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        (void)storage->close(storage->user, handle);
        return 0;
    }
    if (ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY,
            &delivery_key)
            != NINLIL_OK
        || storage->get(
            storage->user,
            txn,
            (ninlil_bytes_view_t){
                delivery_key.bytes, delivery_key.length},
            &delivery_view)
            != NINLIL_STORAGE_OK
        || ninlil_model_runtime_store_decode_capacity(
            NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY,
            (ninlil_bytes_view_t){
                delivery_value, delivery_view.length},
            &delivery_capacity)
            != NINLIL_OK
        || delivery_capacity.used >= delivery_capacity.limit) {
        (void)storage->rollback(storage->user, txn);
        (void)storage->close(storage->user, handle);
        return 0;
    }
    delivery_capacity.used += 1u;
    if (delivery_capacity.high_water < delivery_capacity.used) {
        delivery_capacity.high_water = delivery_capacity.used;
    }
    if (ninlil_model_runtime_store_encode_capacity(
            NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY,
            &delivery_capacity,
            delivery_value,
            (uint32_t)sizeof(delivery_value),
            &delivery_value_length)
            != NINLIL_OK
        || storage->put(
            storage->user,
            txn,
            (ninlil_bytes_view_t){
                delivery_key.bytes, delivery_key.length},
            (ninlil_bytes_view_t){
                delivery_value, delivery_value_length})
            != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        (void)storage->close(storage->user, handle);
        return 0;
    }

    if (storage->commit(storage->user, txn, NINLIL_DURABILITY_FULL)
        != NINLIL_STORAGE_OK) {
        (void)storage->close(storage->user, handle);
        return 0;
    }
    (void)storage->close(storage->user, handle);
    return 1;
}

static int seed_legacy_transaction_record(
    ninlil_test_storage_t *storage_fixture,
    ninlil_bytes_view_t storage_namespace,
    uint32_t legacy_length)
{
    const ninlil_storage_ops_t *storage =
        ninlil_test_storage_ops(storage_fixture);
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    uint8_t key[18];
    uint8_t value[46];

    if (legacy_length != 33u && legacy_length != sizeof(value)) {
        return 0;
    }
    if (storage->open(
            storage->user,
            storage_namespace,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle)
        != NINLIL_STORAGE_OK) {
        return 0;
    }
    if (storage->begin(
            storage->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        (void)storage->close(storage->user, handle);
        return 0;
    }
    (void)memset(key, 0x51, sizeof(key));
    key[0] = 0x54u;
    key[1] = 0x58u;
    (void)memset(value, 0, sizeof(value));
    value[0] = 0x4eu;
    value[1] = 0x54u;
    value[2] = 0x53u;
    value[3] = 0x32u;
    if (storage->put(
            storage->user,
            txn,
            (ninlil_bytes_view_t){key, sizeof(key)},
            (ninlil_bytes_view_t){value, legacy_length})
        != NINLIL_STORAGE_OK
        || storage->commit(storage->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        (void)storage->close(storage->user, handle);
        return 0;
    }
    (void)storage->close(storage->user, handle);
    return 1;
}

static int corrupt_durable_active_token_deferred_wait(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *token_clock_epoch_id)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    ninlil_storage_txn_t txn = NULL;
    uint8_t key[18];
    uint8_t value_bytes[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    ninlil_mut_bytes_t value = {
        .data = value_bytes,
        .capacity = sizeof(value_bytes),
        .length = 0u
    };
    uint32_t index;
    uint32_t match = UINT32_MAX;
    uint32_t match_count = 0u;
    uint32_t crc;

    if (storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn)
        != NINLIL_STORAGE_OK) {
        return 0;
    }
    key[0] = 0x44u;
    key[1] = 0x53u;
    (void)memcpy(&key[2], transaction_id->bytes, sizeof(transaction_id->bytes));
    if (storage->get(
            storage->user,
            txn,
            (ninlil_bytes_view_t){key, sizeof(key)},
            &value)
        != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return 0;
    }
    for (index = 8u;
         index + sizeof(token_clock_epoch_id->bytes)
            <= value.length - 4u;
         ++index) {
        if (memcmp(
                &value_bytes[index],
                token_clock_epoch_id->bytes,
                sizeof(token_clock_epoch_id->bytes)) == 0
            && value_bytes[index - 8u] == 0u
            && value_bytes[index - 7u] == 0u
            && value_bytes[index - 6u] == 0u
            && value_bytes[index - 5u] == NINLIL_RT_TOKEN_ACTIVE
            && value_bytes[index - 4u] == 0u
            && value_bytes[index - 3u] == 0u
            && value_bytes[index - 2u] == 0u
            && value_bytes[index - 1u] == 0u) {
            match = index;
            match_count += 1u;
        }
    }
    if (match_count != 1u || match < 4u) {
        (void)storage->rollback(storage->user, txn);
        return 0;
    }
    value_bytes[match - 4u] = 0u;
    value_bytes[match - 3u] = 0u;
    value_bytes[match - 2u] = 0u;
    value_bytes[match - 1u] = 1u;
    crc = ninlil_model_domain_crc32c(value_bytes, value.length - 4u);
    value_bytes[value.length - 4u] = (uint8_t)(crc >> 24u);
    value_bytes[value.length - 3u] = (uint8_t)(crc >> 16u);
    value_bytes[value.length - 2u] = (uint8_t)(crc >> 8u);
    value_bytes[value.length - 1u] = (uint8_t)crc;
    if (storage->put(
            storage->user,
            txn,
            (ninlil_bytes_view_t){key, sizeof(key)},
            (ninlil_bytes_view_t){value_bytes, value.length})
            != NINLIL_STORAGE_OK
        || storage->commit(storage->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return 0;
    }
    return 1;
}

static int run_legacy_transaction_restart_reject(uint32_t legacy_length)
{
    delivery_env_t env;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(seed_legacy_transaction_record(
        env.storage_fixture,
        (ninlil_bytes_view_t){
            TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
        legacy_length));
    env.config = config_controller(4u);
    status = ninlil_runtime_create(
        &env.config, &env.platform, &env.runtime);
    REQUIRE(status == NINLIL_E_UNSUPPORTED
        || status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env.runtime == NULL);
    platform_teardown(&env);
    return 0;
}

static int test_legacy_transaction_restart_rejects_fail_closed(void)
{
    REQUIRE(run_legacy_transaction_restart_reject(33u) == 0);
    REQUIRE(run_legacy_transaction_restart_reject(46u) == 0);
    return 0;
}

static int controller_register_event_receiver(
    delivery_env_t *env,
    uint8_t app_tag,
    const ninlil_service_callbacks_t *callbacks)
{
    ninlil_service_descriptor_t descriptor = event_fact_descriptor(app_tag);
    return env_register(env, &descriptor, callbacks);
}

static int test_desired_state_unavailable_never_satisfies(void)
{
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_transaction_slot_t *transaction;
    uint64_t send_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    descriptor = desired_descriptor(0x70u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x22u);

    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result) == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    fill_step_budget(&budget);
    send_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->evidence_recorded == 0u);
    REQUIRE(transaction->latest_evidence == NINLIL_EVIDENCE_NONE);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_NONE);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->evidence_recorded == 0u);
    REQUIRE(transaction->latest_evidence == NINLIL_EVIDENCE_NONE);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_NONE);

    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal != 0u);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_EXPIRED);
    REQUIRE(transaction->latest_evidence == NINLIL_EVIDENCE_NONE);

    platform_teardown(&env);
    return 0;
}

static int test_transaction_capacity_retains_terminal_rows_at_boundary(void)
{
    static const uint8_t idem_keys[4][8] = {
        {'c', 'a', 'p', '-', '0', '0', '0', '1'},
        {'c', 'a', 'p', '-', '0', '0', '0', '2'},
        {'c', 'a', 'p', '-', '0', '0', '0', '3'},
        {'c', 'a', 'p', '-', '0', '0', '0', '4'}
    };
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_id128_t transaction_ids[3];
    ninlil_rt_transaction_slot_t *transaction;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_nonterminal_transactions = 1u;
    env.config.limits.max_retained_terminal_transactions = 2u;
    env.config.limits.max_nonterminal_deliveries = 1u;
    env.config.limits.max_deferred_tokens = 1u;
    env.config.terminal_retention_ms = 20000u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env.runtime->transaction_capacity == 3u);

    descriptor = desired_descriptor(0x70u);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));
    fill_step_budget(&budget);

    for (index = 0u; index < 2u; ++index) {
        fill_desired_submission(
            &env, &submission, (uint8_t)(0x72u + index));
        submission.generation = (uint64_t)index + 1u;
        submission.idempotency_key.data = idem_keys[index];
        submission.idempotency_key.length = sizeof(idem_keys[index]);
        (void)memset(&submit_result, 0, sizeof(submit_result));
        set_header(
            &submit_result.abi_version,
            &submit_result.struct_size,
            sizeof(submit_result));
        REQUIRE(ninlil_submit(
                    env.service, &submission, &submit_result)
            == NINLIL_OK);
        REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
            == 1u);
        transaction_ids[index] = submit_result.transaction_id;

        REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &transaction_ids[index]);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->terminal != 0u);
        REQUIRE(transaction->outcome == NINLIL_OUTCOME_EXPIRED);
        REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
            == 0u);
    }

    fill_desired_submission(&env, &submission, 0x74u);
    submission.generation = 3u;
    submission.idempotency_key.data = idem_keys[2];
    submission.idempotency_key.length = sizeof(idem_keys[2]);
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
        == 1u);
    transaction_ids[2] = submit_result.transaction_id;
    REQUIRE(env.runtime->transaction_count == 3u);
    REQUIRE(env.runtime->nonterminal_transaction_count == 1u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env.runtime->transaction_capacity == 3u);
    REQUIRE(env.runtime->transaction_count == 3u);
    REQUIRE(env.runtime->nonterminal_transaction_count == 1u);
    for (index = 0u; index < 3u; ++index) {
        transaction = ninlil_rt_find_transaction(
            env.runtime, &transaction_ids[index]);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->terminal == (index < 2u ? 1u : 0u));
    }

    REQUIRE(env_register(&env, &descriptor, &callbacks));
    REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
        == 1u);
    fill_desired_submission(&env, &submission, 0x75u);
    submission.generation = 4u;
    submission.idempotency_key.data = idem_keys[3];
    submission.idempotency_key.length = sizeof(idem_keys[3]);
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(submit_result.reason == NINLIL_REASON_CAPACITY_EXHAUSTED);
    REQUIRE(env.runtime->transaction_count == 3u);
    REQUIRE(env.runtime->nonterminal_transaction_count == 1u);

    platform_teardown(&env);
    return 0;
}

static int test_service_inflight_quota_reconstructed_after_restart(void)
{
    static const uint8_t first_idem[] = "restart-inflight-1";
    static const uint8_t second_idem[] = "restart-inflight-2";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_nonterminal_transactions = 2u;
    env.config.limits.max_retained_terminal_transactions = 2u;
    env.config.limits.max_nonterminal_deliveries = 2u;
    env.config.limits.max_deferred_tokens = 2u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);

    descriptor = desired_descriptor(0x76u);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x76u);
    submission.idempotency_key.data = first_idem;
    submission.idempotency_key.length = sizeof(first_idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.runtime->nonterminal_transaction_count == 1u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env.runtime->nonterminal_transaction_count == 1u);
    REQUIRE(env_register(&env, &descriptor, &callbacks));
    REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
        == 1u);

    fill_desired_submission(&env, &submission, 0x77u);
    submission.generation = 2u;
    submission.idempotency_key.data = second_idem;
    submission.idempotency_key.length = sizeof(second_idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(submit_result.reason == NINLIL_REASON_CAPACITY_EXHAUSTED);
    REQUIRE(env.runtime->nonterminal_transaction_count == 1u);

    platform_teardown(&env);
    return 0;
}

static int test_terminal_quota_decrement_matches_exact_service(void)
{
    static const uint8_t service_b_name[] = "absolute-state-b";
    static const uint8_t idem_a1[] = "service-a-1";
    static const uint8_t idem_a2[] = "service-a-2";
    static const uint8_t idem_b1[] = "service-b-1";
    static const uint8_t idem_b2[] = "service-b-2";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t result_a;
    ninlil_submission_result_t result_b;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor_a;
    ninlil_service_descriptor_t descriptor_b;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service_a;
    ninlil_service_t *service_b;
    ninlil_rt_transaction_slot_t *transaction_a;
    ninlil_rt_transaction_slot_t *transaction_b;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_nonterminal_transactions = 2u;
    env.config.limits.max_retained_terminal_transactions = 2u;
    env.config.limits.max_nonterminal_deliveries = 2u;
    env.config.limits.max_deferred_tokens = 2u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);

    descriptor_a = desired_descriptor(0x78u);
    descriptor_a.inflight_limit = 1u;
    descriptor_b = desired_descriptor(0x78u);
    descriptor_b.service_id.data = service_b_name;
    descriptor_b.service_id.length = sizeof(service_b_name) - 1u;
    descriptor_b.minimum_deadline_ms = 10000u;
    descriptor_b.maximum_deadline_ms = 10000u;
    descriptor_b.inflight_limit = 1u;
    set_digest(&descriptor_b.descriptor_digest, 0x12u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor_a, &callbacks));
    service_a = env.service;
    REQUIRE(env_register(&env, &descriptor_b, &callbacks));
    service_b = env.service;

    fill_desired_submission(&env, &submission, 0x78u);
    submission.idempotency_key.data = idem_a1;
    submission.idempotency_key.length = sizeof(idem_a1) - 1u;
    (void)memset(&result_a, 0, sizeof(result_a));
    set_header(&result_a.abi_version, &result_a.struct_size, sizeof(result_a));
    REQUIRE(ninlil_submit(service_a, &submission, &result_a) == NINLIL_OK);
    REQUIRE(result_a.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    fill_desired_submission(&env, &submission, 0x79u);
    submission.effect_deadline_ms = 10000u;
    submission.idempotency_key.data = idem_b1;
    submission.idempotency_key.length = sizeof(idem_b1) - 1u;
    (void)memset(&result_b, 0, sizeof(result_b));
    set_header(&result_b.abi_version, &result_b.struct_size, sizeof(result_b));
    REQUIRE(ninlil_submit(service_b, &submission, &result_b) == NINLIL_OK);
    REQUIRE(result_b.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    transaction_a = ninlil_rt_find_transaction(
        env.runtime, &result_a.transaction_id);
    transaction_b = ninlil_rt_find_transaction(
        env.runtime, &result_b.transaction_id);
    REQUIRE(transaction_a != NULL);
    REQUIRE(transaction_b != NULL);
    REQUIRE(ninlil_rt_service_descriptor_matches_transaction(
                &descriptor_a, transaction_a));
    REQUIRE(!ninlil_rt_service_descriptor_matches_transaction(
                &descriptor_b, transaction_a));
    REQUIRE(ninlil_rt_service_descriptor_matches_transaction(
                &descriptor_b, transaction_b));
    REQUIRE(!ninlil_rt_service_descriptor_matches_transaction(
                &descriptor_a, transaction_b));

    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction_a->terminal != 0u);
    REQUIRE(transaction_b->terminal == 0u);
    REQUIRE(env.runtime->services[service_a->slot_index].quota_inflight == 0u);
    REQUIRE(env.runtime->services[service_b->slot_index].quota_inflight == 1u);

    fill_desired_submission(&env, &submission, 0x7au);
    submission.generation = 2u;
    submission.effect_deadline_ms = 10000u;
    submission.idempotency_key.data = idem_b2;
    submission.idempotency_key.length = sizeof(idem_b2) - 1u;
    (void)memset(&result_b, 0, sizeof(result_b));
    set_header(&result_b.abi_version, &result_b.struct_size, sizeof(result_b));
    REQUIRE(ninlil_submit(service_b, &submission, &result_b) == NINLIL_OK);
    REQUIRE(result_b.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result_b.reason == NINLIL_REASON_CAPACITY_EXHAUSTED);

    fill_desired_submission(&env, &submission, 0x7bu);
    submission.generation = 2u;
    submission.idempotency_key.data = idem_a2;
    submission.idempotency_key.length = sizeof(idem_a2) - 1u;
    (void)memset(&result_a, 0, sizeof(result_a));
    set_header(&result_a.abi_version, &result_a.struct_size, sizeof(result_a));
    REQUIRE(ninlil_submit(service_a, &submission, &result_a) == NINLIL_OK);
    REQUIRE(result_a.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.runtime->nonterminal_transaction_count == 2u);

    platform_teardown(&env);
    return 0;
}

/*
 * Counterexample fix: restart restores SERVICE unattached; runtime_step may
 * terminalize deadline before reattach. Durable quota must still decrement
 * in the terminal FULL group so reattach + next submit is not false capacity.
 */
static int test_origin_terminal_quota_before_reattach_after_restart(void)
{
    static const uint8_t first_idem[] = "quota-reattach-1";
    static const uint8_t second_idem[] = "quota-reattach-2";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_service_slot_t *restored_slot;
    uint32_t index;
    uint32_t restored_services;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_nonterminal_transactions = 2u;
    env.config.limits.max_retained_terminal_transactions = 2u;
    env.config.limits.max_nonterminal_deliveries = 2u;
    env.config.limits.max_deferred_tokens = 2u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);

    descriptor = desired_descriptor(0x7cu);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x7cu);
    submission.idempotency_key.data = first_idem;
    submission.idempotency_key.length = sizeof(first_idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
        == 1u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;

    /* Restart: TX + SERVICE ledger restored; services stay unattached. */
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    restored_services = 0u;
    restored_slot = NULL;
    for (index = 0u; index < env.runtime->service_capacity; ++index) {
        if (env.runtime->services[index].in_use != 0u) {
            restored_services += 1u;
            restored_slot = &env.runtime->services[index];
            REQUIRE(restored_slot->attached == 0u);
            REQUIRE(restored_slot->quota_inflight == 1u);
        }
    }
    REQUIRE(restored_services == 1u);
    REQUIRE(restored_slot != NULL);

    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->origin_admission != 0u);

    /* Terminalize on step before application reattach. */
    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal != 0u);
    REQUIRE(restored_slot->attached == 0u);
    REQUIRE(restored_slot->quota_inflight == 0u);

    /* Reattach then next submit must not false-reject on capacity. */
    REQUIRE(env_register(&env, &descriptor, &callbacks));
    REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
        == 0u);
    fill_desired_submission(&env, &submission, 0x7du);
    submission.generation = 2u;
    submission.idempotency_key.data = second_idem;
    submission.idempotency_key.length = sizeof(second_idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.runtime->services[env.service->slot_index].quota_inflight
        == 1u);

    platform_teardown(&env);
    return 0;
}

/* Origin terminal with zero inflight is CORRUPT (no silent skip). */
static int test_origin_terminal_zero_inflight_is_corrupt(void)
{
    static const uint8_t idem[] = "quota-zero-inflight";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_service_slot_t *slot;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    descriptor = desired_descriptor(0x7eu);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x7eu);
    submission.idempotency_key.data = idem;
    submission.idempotency_key.length = sizeof(idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    slot = &env.runtime->services[env.service->slot_index];
    REQUIRE(slot->quota_inflight == 1u);
    /* Corrupt relation: inflight cleared without durable terminal. */
    slot->quota_inflight = 0u;

    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_STORAGE_CORRUPT);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    /* Terminal not published on CORRUPT pre-commit fail-closed. */
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(slot->quota_inflight == 0u);

    platform_teardown(&env);
    return 0;
}

/* Origin terminal with no matching service row is CORRUPT. */
static int test_origin_terminal_missing_service_row_is_corrupt(void)
{
    static const uint8_t idem[] = "quota-missing-service";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_transaction_slot_t *transaction;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    descriptor = desired_descriptor(0x7fu);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x7fu);
    submission.idempotency_key.data = idem;
    submission.idempotency_key.length = sizeof(idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    /* Drop all in-use service slots (identity relation gone). */
    for (index = 0u; index < env.runtime->service_capacity; ++index) {
        env.runtime->services[index].in_use = 0u;
        env.runtime->services[index].attached = 0u;
    }
    env.service = NULL;

    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_STORAGE_CORRUPT);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);

    platform_teardown(&env);
    return 0;
}

/* Duplicate matching SERVICE identities for one origin TX is CORRUPT. */
static int test_origin_terminal_duplicate_service_row_is_corrupt(void)
{
    static const uint8_t idem[] = "quota-duplicate-service";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_service_slot_t *primary;
    ninlil_rt_service_slot_t *dup;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    descriptor = desired_descriptor(0x80u);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x80u);
    submission.idempotency_key.data = idem;
    submission.idempotency_key.length = sizeof(idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    primary = &env.runtime->services[env.service->slot_index];
    REQUIRE(primary->quota_inflight == 1u);
    dup = NULL;
    for (index = 0u; index < env.runtime->service_capacity; ++index) {
        if (env.runtime->services[index].in_use == 0u) {
            dup = &env.runtime->services[index];
            break;
        }
    }
    REQUIRE(dup != NULL);
    /* Clone durable identity into a second in-use slot (corrupt multi-match). */
    *dup = *primary;
    (void)memset(&dup->public_handle, 0, sizeof(dup->public_handle));
    dup->attached = 0u;
    dup->quota_inflight = 1u;

    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_STORAGE_CORRUPT);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(primary->quota_inflight == 1u);

    platform_teardown(&env);
    return 0;
}

/*
 * COMMIT_UNKNOWN on origin terminal FULL: no RAM quota publication; TX stays
 * non-terminal or dual-truth without published inflight decrement.
 */
static int test_origin_terminal_commit_unknown_no_ram_quota_publish(void)
{
    static const uint8_t idem[] = "quota-cu-no-ram";
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_service_slot_t *slot;
    uint64_t inflight_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    descriptor = desired_descriptor(0x81u);
    descriptor.inflight_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x81u);
    submission.idempotency_key.data = idem;
    submission.idempotency_key.length = sizeof(idem) - 1u;
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    slot = &env.runtime->services[env.service->slot_index];
    inflight_before = slot->quota_inflight;
    REQUIRE(inflight_before == 1u);

    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        0));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    /* RAM must not publish decremented inflight on CU. */
    REQUIRE(slot->quota_inflight == inflight_before);
    REQUIRE(env.runtime->commit_unknown_fence != 0u);

    platform_teardown(&env);
    return 0;
}

static int test_callback_failure_no_false_success(void)
{
    delivery_env_t env;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_callbacks_t callbacks;
    ninlil_id128_t txn_id;
    ninlil_runtime_config_t config;

    g_delivery_calls = 0u;
    g_fail_delivery = 1u;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_txn_id(&txn_id, 0x77u);
    config = config_controller(4u);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)ninlil_runtime_destroy(env.runtime);
    env.runtime = NULL;
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        config.storage_namespace,
        &txn_id,
        0x71u,
        2u));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = delivery_complete_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(controller_register_event_receiver(&env, 0x71u, &callbacks));

    fill_step_budget(&budget);
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);
    {
        ninlil_rt_transaction_slot_t *transaction =
            ninlil_rt_find_transaction(env.runtime, &txn_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->token_state
            == NINLIL_RT_TOKEN_RECOVERY_REQUIRED);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
        REQUIRE(transaction->reason == NINLIL_REASON_APPLICATION_FAILED);
        REQUIRE(transaction->pending_dispatch == 0u);
    }

    g_fail_delivery = 0u;
    platform_teardown(&env);
    return 0;
}

static int run_deferred_delivery_case(int mode)
{
    delivery_env_t env;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_callbacks_t callbacks;
    ninlil_application_result_t result;
    ninlil_metrics_snapshot_t metrics;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t txn_id;
    ninlil_runtime_config_t config;
    uint8_t evidence[4] = {0x41u, 0x42u, 0x43u, 0x44u};

    g_delivery_calls = 0u;
    g_fail_delivery = 0u;
    g_defer_delivery = 1u;
    (void)memset(&g_deferred_token, 0, sizeof(g_deferred_token));
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_txn_id(&txn_id, (uint8_t)(0x7bu + mode));
    config = config_controller(4u);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        config.storage_namespace,
        &txn_id,
        0x76u,
        2u));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = delivery_complete_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(controller_register_event_receiver(&env, 0x76u, &callbacks));

    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);
    transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_ACTIVE);
    REQUIRE(transaction->deferred_wait == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 1u);
    REQUIRE(memcmp(
                g_deferred_token.context_id.bytes,
                txn_id.bytes,
                sizeof(txn_id.bytes))
        == 0);
    REQUIRE(g_deferred_token.generation == transaction->delivery_count);

    if (mode == 1) {
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
        env.runtime = NULL;
        ninlil_test_storage_simulate_crash(env.storage_fixture);
        REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
        transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->token_state
            == NINLIL_RT_TOKEN_EXPIRED);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
        REQUIRE(transaction->reason == NINLIL_REASON_OUTCOME_UNKNOWN);
        REQUIRE(transaction->application_result_reason
            == NINLIL_REASON_OUTCOME_UNKNOWN);
        REQUIRE(transaction->application_effect_certainty
            == NINLIL_EFFECT_CERTAINTY_POSSIBLE);
        REQUIRE(transaction->evidence_recorded == 0u);
        REQUIRE(transaction->outcome_recorded == 0u);
        REQUIRE(transaction->pending_dispatch == 0u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
            == 1u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
            == 1u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
            == 0u);
        platform_teardown(&env);
        g_defer_delivery = 0u;
        return 0;
    }

    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    result.kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    result.evidence_stage = NINLIL_EVIDENCE_APPLIED;
    result.retry_guidance = NINLIL_RETRY_NEVER;
    result.evidence.data = evidence;
    result.evidence.length = sizeof(evidence);
    if (mode == 2) {
        REQUIRE(step_result.has_next_wake == 1u);
        REQUIRE(step_result.next_wake_at_ms
            == transaction->token_expires_at_ms + 1u);
        REQUIRE(ninlil_test_clock_advance(
            env.clock,
            transaction->application_completion_timeout_ms + 1u));
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
            == NINLIL_OK);
        REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_EXPIRED);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
        REQUIRE(transaction->reason
            == NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT);
        REQUIRE(transaction->deferred_wait == 0u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
            == 1u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
            == 1u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
            == 0u);
        REQUIRE(ninlil_delivery_complete(
                    env.runtime, &g_deferred_token, &result)
            == NINLIL_E_INVALID_STATE);
        (void)memset(&metrics, 0, sizeof(metrics));
        set_header(
            &metrics.abi_version,
            &metrics.struct_size,
            sizeof(metrics));
        REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics)
            == NINLIL_OK);
        REQUIRE(metrics.delivery_token_timeouts == 1u);
        platform_teardown(&env);
        g_defer_delivery = 0u;
        return 0;
    }
    REQUIRE(ninlil_delivery_complete(
                env.runtime, &g_deferred_token, &result)
        == NINLIL_OK);
    (void)memset(evidence, 0, sizeof(evidence));
    transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_CONSUMED);
    REQUIRE(transaction->evidence_recorded == 1u);
    REQUIRE(transaction->application_result_kind
        == NINLIL_APP_RESULT_POSITIVE_EVIDENCE);
    REQUIRE(transaction->application_evidence_length == 4u);
    REQUIRE(transaction->application_evidence[0] == 0x41u);
    REQUIRE(transaction->application_evidence[1] == 0x42u);
    REQUIRE(transaction->application_evidence[2] == 0x43u);
    REQUIRE(transaction->application_evidence[3] == 0x44u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 0u);
    REQUIRE(ninlil_delivery_complete(
                env.runtime, &g_deferred_token, &result)
        == NINLIL_E_INVALID_STATE);
    fill_step_budget(&budget);
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == 0u);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->application_evidence_length == 4u);
    REQUIRE(transaction->application_evidence[0] == 0x41u);
    REQUIRE(transaction->application_evidence[3] == 0x44u);

    platform_teardown(&env);
    g_defer_delivery = 0u;
    return 0;
}

static int test_deferred_delivery_complete_and_restart_fence(void)
{
    REQUIRE(run_deferred_delivery_case(0) == 0);
    REQUIRE(run_deferred_delivery_case(1) == 0);
    REQUIRE(run_deferred_delivery_case(2) == 0);
    return 0;
}

static int test_sync_completion_expiring_inside_callback_never_commits_success(
    void)
{
    delivery_env_t env;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_descriptor_t descriptor;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t transaction_id;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 999u));
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&transaction_id, 0x6du);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &transaction_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);

    descriptor = event_fact_descriptor(0x76u);
    descriptor.application_completion_timeout_ms = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.user = env.clock;
    callbacks.on_delivery =
        delivery_complete_after_clock_advance_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    g_delivery_calls = 0u;
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_started_at_ms == 999u);
    REQUIRE(transaction->token_expires_at_ms == 1000u);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_EXPIRED);
    REQUIRE(transaction->delivery_phase
        == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
    REQUIRE(transaction->reason
        == NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT);
    REQUIRE(transaction->evidence_recorded == 0u);
    REQUIRE(transaction->application_evidence_length == 0u);
    REQUIRE(step_result.callbacks_invoked == 1u);
    REQUIRE(step_result.state_transitions == 3u);
    REQUIRE(env.runtime->metrics.delivery_token_timeouts == 1u);
    platform_teardown(&env);
    return 0;
}

typedef enum callback_fault_route {
    CALLBACK_FAULT_ROUTE_DOWNLINK = 0,
    CALLBACK_FAULT_ROUTE_UPLINK = 1,
    CALLBACK_FAULT_ROUTE_EVENT_FACT = 2
} callback_fault_route_t;

static int storage_last_commit_is_full(
    const ninlil_test_storage_t *storage)
{
    size_t count = ninlil_test_storage_trace_count(storage);

    while (count > 0u) {
        const ninlil_test_storage_trace_record_t *record =
            ninlil_test_storage_trace_at(storage, count - 1u);

        if (record != NULL
            && record->operation == NINLIL_TEST_STORAGE_OP_COMMIT) {
            return record->durability == NINLIL_DURABILITY_FULL;
        }
        count -= 1u;
    }
    return 0;
}

static void fill_inbound_application_message(
    delivery_env_t *env,
    callback_fault_route_t route,
    uint8_t app_tag,
    const ninlil_id128_t *transaction_id,
    ninlil_bearer_message_t *message)
{
    ninlil_rt_service_slot_t *service_slot =
        &env->runtime->services[env->service->slot_index];

    (void)memset(message, 0, sizeof(*message));
    set_header(
        &message->abi_version, &message->struct_size, sizeof(*message));
    message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message->transaction_id = *transaction_id;
    set_txn_id(&message->attempt_id, 0xb0u);
    set_header(
        &message->source.abi_version,
        &message->source.struct_size,
        sizeof(message->source));
    set_id(&message->source.runtime_id, 0xb1u);
    set_id(&message->source.application_instance_id, 0xb2u);
    set_header(
        &message->source.local_identity.abi_version,
        &message->source.local_identity.struct_size,
        sizeof(message->source.local_identity));
    set_header(
        &message->target.abi_version,
        &message->target.struct_size,
        sizeof(message->target));
    message->target.target_runtime_id = env->runtime->config.runtime_id;
    set_id(&message->target.target_application_instance_id, app_tag);
    message->service = service_slot->model_service.identity;
    set_digest(&message->content_digest, 0xb3u);
    message->required_evidence = NINLIL_EVIDENCE_APPLIED;
    message->payload.data = env->payload;
    message->payload.length = 4u;
    if (route == CALLBACK_FAULT_ROUTE_DOWNLINK) {
        message->generation = 1u;
        message->deadline_clock_epoch_id =
            env->runtime->started_sample.clock_epoch_id;
        message->absolute_effect_deadline_ms = 5000u;
        message->evidence_grace_ms = 1000u;
    } else {
        /* EventFact / uplink receiver: event_id required, generation 0. */
        set_txn_id(&message->event_id, 0xe1u);
        message->generation = 0u;
        message->absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
        message->evidence_grace_ms = 0u;
    }
}

static int step_delivery_once(
    delivery_env_t *env,
    ninlil_status_t *out_status,
    ninlil_step_result_t *out_result)
{
    ninlil_step_budget_t budget;

    fill_step_budget(&budget);
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    *out_status = ninlil_runtime_step(env->runtime, &budget, out_result);
    return 1;
}

static int setup_active_callback_fault_route(
    callback_fault_route_t route,
    delivery_env_t *env,
    callback_fault_context_t *context,
    ninlil_id128_t *transaction_id)
{
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_bearer_message_t message;
    ninlil_bearer_state_t available_state;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_v1_step_delivery_result_t delivery_result;
    ninlil_step_result_t step_result;
    ninlil_status_t step_status;
    uint8_t app_tag;
    uint32_t step;

    (void)memset(env, 0, sizeof(*env));
    REQUIRE(platform_init(env));
    REQUIRE(ninlil_test_clock_advance(env->clock, 100u));
    (void)memset(context, 0, sizeof(*context));
    context->clock = env->clock;
    context->storage = env->storage_fixture;
    context->rollback_now_ms = 99u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.user = context;
    callbacks.on_delivery = delivery_complete_with_post_fault_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    g_delivery_calls = 0u;

    if (route == CALLBACK_FAULT_ROUTE_EVENT_FACT) {
        app_tag = 0x76u;
        set_txn_id(transaction_id, 0xc0u);
        env->config = config_controller(4u);
        REQUIRE(ninlil_runtime_create(
                    &env->config, &env->platform, &env->runtime)
            == NINLIL_OK);
        REQUIRE(ninlil_runtime_destroy(env->runtime) == NINLIL_OK);
        env->runtime = NULL;
        REQUIRE(seed_parked_event_txn(
            env->storage_fixture,
            env->config.storage_namespace,
            transaction_id,
            app_tag,
            2u));
        REQUIRE(ninlil_runtime_create(
                    &env->config, &env->platform, &env->runtime)
            == NINLIL_OK);
        transaction =
            ninlil_rt_find_transaction(env->runtime, transaction_id);
        REQUIRE(transaction != NULL);
        (void)memset(&delivery_result, 0, sizeof(delivery_result));
        REQUIRE(ninlil_rt_v1_prepare_callback_start(
                    env->runtime,
                    transaction,
                    &env->runtime->started_sample,
                    10u,
                    &delivery_result)
            == NINLIL_OK);
        descriptor = event_fact_descriptor(app_tag);
        descriptor.application_completion_timeout_ms = 10u;
        REQUIRE(env_register(env, &descriptor, &callbacks));
        REQUIRE(g_delivery_calls == 0u);
        context->runtime = env->runtime;
        context->controller_recovery_hook = 1u;
        env->runtime->private_transition_hook =
            observe_callback_recovery_hook;
        env->runtime->private_transition_hook_user = context;
        return 0;
    }

    if (route == CALLBACK_FAULT_ROUTE_DOWNLINK) {
        app_tag = 0x81u;
        set_txn_id(transaction_id, 0xc1u);
        env->config = config_endpoint(4u);
        descriptor = desired_descriptor(app_tag);
        descriptor.application_completion_timeout_ms = 10u;
        REQUIRE(ninlil_runtime_create(
                    &env->config, &env->platform, &env->runtime)
            == NINLIL_OK);
        REQUIRE(ninlil_test_bearer_set_path_up(
            env->bearer_fixture, &env->config.runtime_id, 1));
        (void)memset(&available_state, 0, sizeof(available_state));
        set_header(
            &available_state.abi_version,
            &available_state.struct_size,
            sizeof(available_state));
        available_state.availability_epoch = 2u;
        available_state.available = 1u;
        REQUIRE(ninlil_test_bearer_raw_state_enqueue(
            env->bearer_fixture,
            NINLIL_BEARER_OK,
            &available_state,
            16u));
        REQUIRE(env_register(env, &descriptor, &callbacks));
        fill_inbound_application_message(
            env, route, app_tag, transaction_id, &message);
        REQUIRE(ninlil_test_bearer_raw_receive_enqueue(
            env->bearer_fixture, NINLIL_BEARER_OK, &message, 1u));
        for (step = 0u; step < 4u; ++step) {
            REQUIRE(step_delivery_once(
                env, &step_status, &step_result));
            REQUIRE(step_status == NINLIL_OK);
            transaction =
                ninlil_rt_find_transaction(env->runtime, transaction_id);
            if (transaction != NULL
                && transaction->token_state == NINLIL_RT_TOKEN_ACTIVE) {
                break;
            }
        }
        transaction = ninlil_rt_find_transaction(env->runtime, transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_ACTIVE);
        REQUIRE(transaction->pending_dispatch != 0u);
        REQUIRE(transaction->ingress_pending != 0u);
        REQUIRE(g_delivery_calls == 0u);
        context->runtime = env->runtime;
        context->controller_recovery_hook = 0u;
        env->runtime->private_transition_hook =
            observe_callback_recovery_hook;
        env->runtime->private_transition_hook_user = context;
        return 0;
    }

    /*
     * UPLINK (former reserved-family path) and EVENT_FACT share the M1a
     * EventFact controller receiver setup via seeded durable transaction.
     */
    app_tag = route == CALLBACK_FAULT_ROUTE_UPLINK ? 0x82u : 0x76u;
    set_txn_id(
        transaction_id, route == CALLBACK_FAULT_ROUTE_UPLINK ? 0xc2u : 0xc0u);
    env->config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env->config, &env->platform, &env->runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env->runtime) == NINLIL_OK);
    env->runtime = NULL;
    REQUIRE(seed_parked_event_txn(
        env->storage_fixture,
        env->config.storage_namespace,
        transaction_id,
        app_tag,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env->config, &env->platform, &env->runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(env->runtime, transaction_id);
    REQUIRE(transaction != NULL);
    (void)memset(&delivery_result, 0, sizeof(delivery_result));
    REQUIRE(ninlil_rt_v1_prepare_callback_start(
                env->runtime,
                transaction,
                &env->runtime->started_sample,
                10u,
                &delivery_result)
        == NINLIL_OK);
    descriptor = event_fact_descriptor(app_tag);
    descriptor.application_completion_timeout_ms = 10u;
    REQUIRE(env_register(env, &descriptor, &callbacks));
    REQUIRE(g_delivery_calls == 0u);
    context->runtime = env->runtime;
    context->controller_recovery_hook = 1u;
    env->runtime->private_transition_hook =
        observe_callback_recovery_hook;
    env->runtime->private_transition_hook_user = context;
    return 0;
}

static int script_callback_preflight_fault(
    delivery_env_t *env,
    const ninlil_rt_transaction_slot_t *transaction,
    callback_clock_fault_t clock_fault,
    uint32_t safe_count)
{
    ninlil_time_sample_t safe_sample;
    ninlil_time_sample_t fault_sample;

    safe_sample = env->runtime->started_sample;
    safe_sample.now_ms = transaction->delivery_started_at_ms;
    REQUIRE(ninlil_test_clock_script_raw(
        env->clock, NINLIL_PORT_OK, &safe_sample, safe_count));
    fault_sample = safe_sample;
    if (clock_fault == CALLBACK_CLOCK_FAULT_TEMPORARY) {
        REQUIRE(ninlil_test_clock_script(
            env->clock, NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u));
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_UNCERTAIN) {
        fault_sample.trust = NINLIL_CLOCK_UNCERTAIN;
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_PERMANENT) {
        REQUIRE(ninlil_test_clock_script(
            env->clock, NINLIL_PORT_PERMANENT_FAILURE, NULL, 1u));
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_INVALID) {
        fault_sample.struct_size =
            (uint16_t)(sizeof(fault_sample) - 1u);
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else if (clock_fault
        == CALLBACK_CLOCK_FAULT_INVALID_RESERVED) {
        fault_sample.reserved_zero = 1u;
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else if (clock_fault
        == CALLBACK_CLOCK_FAULT_INVALID_VERSION) {
        fault_sample.abi_version =
            (uint16_t)(NINLIL_ABI_VERSION + 1u);
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_EPOCH) {
        fault_sample.clock_epoch_id.bytes[0] ^= 0x5au;
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_ROLLBACK) {
        REQUIRE(transaction->delivery_started_at_ms != 0u);
        fault_sample.now_ms =
            transaction->delivery_started_at_ms - 1u;
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_EXPIRY) {
        fault_sample.now_ms = transaction->token_expires_at_ms + 1u;
        REQUIRE(ninlil_test_clock_script_raw(
            env->clock, NINLIL_PORT_OK, &fault_sample, 1u));
    } else {
        REQUIRE(0);
    }
    return 0;
}

static int run_callback_preflight_fault_case(
    callback_fault_route_t route,
    callback_clock_fault_t clock_fault)
{
    delivery_env_t env;
    callback_fault_context_t context;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_step_result_t step_result;
    ninlil_id128_t transaction_id;
    ninlil_status_t step_status;
    ninlil_status_t expected_status;
    ninlil_rt_token_state_t expected_state;
    ninlil_reason_t expected_reason = NINLIL_REASON_NONE;
    uint64_t revision_before;
    uint32_t pending_before;
    uint32_t ingress_before;
    uint32_t expected_recovery_hooks = 0u;
    uint32_t durable_fence = 0u;
    uint32_t safe_count =
        route == CALLBACK_FAULT_ROUTE_DOWNLINK ? 1u : 2u;

    REQUIRE(setup_active_callback_fault_route(
                route, &env, &context, &transaction_id)
        == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    revision_before = transaction->record_revision;
    pending_before = transaction->pending_dispatch;
    ingress_before = transaction->ingress_pending;
    REQUIRE(script_callback_preflight_fault(
                &env, transaction, clock_fault, safe_count)
        == 0);

    if (clock_fault == CALLBACK_CLOCK_FAULT_TEMPORARY
        || clock_fault == CALLBACK_CLOCK_FAULT_UNCERTAIN) {
        expected_status = NINLIL_E_CLOCK_UNCERTAIN;
        expected_state = NINLIL_RT_TOKEN_ACTIVE;
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_PERMANENT
        || clock_fault == CALLBACK_CLOCK_FAULT_INVALID
        || clock_fault == CALLBACK_CLOCK_FAULT_INVALID_RESERVED
        || clock_fault == CALLBACK_CLOCK_FAULT_INVALID_VERSION) {
        expected_status = NINLIL_E_DEGRADED;
        expected_state = NINLIL_RT_TOKEN_ACTIVE;
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_EPOCH) {
        expected_status = NINLIL_E_CLOCK_UNCERTAIN;
        expected_state = NINLIL_RT_TOKEN_EXPIRED;
        expected_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        expected_recovery_hooks = 1u;
        durable_fence = 1u;
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_ROLLBACK) {
        expected_status = NINLIL_E_DEGRADED;
        expected_state = NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
        expected_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        expected_recovery_hooks = 1u;
        durable_fence = 1u;
    } else {
        REQUIRE(clock_fault == CALLBACK_CLOCK_FAULT_EXPIRY);
        expected_status = NINLIL_OK;
        expected_state = NINLIL_RT_TOKEN_EXPIRED;
        expected_reason =
            NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT;
        durable_fence = 1u;
    }

    REQUIRE(step_delivery_once(&env, &step_status, &step_result));
    REQUIRE(step_status == expected_status);
    REQUIRE(g_delivery_calls == 0u);
    REQUIRE(step_result.callbacks_invoked == 0u);
    REQUIRE(context.application_before_hook_count == 0u);
    REQUIRE(context.application_effect_hook_count == 0u);
    REQUIRE(context.application_after_hook_count == 0u);
    REQUIRE(context.callback_entry_saw_before_hook == 0u);
    REQUIRE(context.effect_hook_saw_callback_entry == 0u);
    REQUIRE(context.after_hook_saw_callback_return == 0u);
    REQUIRE(context.after_hook_saw_result_copy == 0u);
    REQUIRE(context.recovery_before_hook_count
        == expected_recovery_hooks);
    REQUIRE(context.recovery_after_hook_count
        == expected_recovery_hooks);
    REQUIRE(context.unexpected_hook_count == 0u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->token_state == expected_state);
    REQUIRE(transaction->evidence_recorded == 0u);
    REQUIRE(transaction->application_evidence_length == 0u);
    if (durable_fence != 0u) {
        REQUIRE(transaction->record_revision == revision_before + 1u);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
        REQUIRE(transaction->reason == expected_reason);
        REQUIRE(transaction->pending_dispatch == 0u);
        REQUIRE(transaction->ingress_pending == 0u);
        REQUIRE(transaction->application_effect_certainty
            == NINLIL_EFFECT_CERTAINTY_POSSIBLE);
        REQUIRE(storage_last_commit_is_full(env.storage_fixture));
    } else {
        REQUIRE(transaction->record_revision == revision_before);
        REQUIRE(transaction->pending_dispatch == pending_before);
        REQUIRE(transaction->ingress_pending == ingress_before);
        REQUIRE(transaction->reason == NINLIL_REASON_NONE);
    }

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    platform_teardown(&env);
    return 0;
}

static int run_callback_clock_fault_case(
    callback_fault_route_t route,
    callback_clock_fault_t clock_fault,
    callback_storage_fault_t storage_fault,
    int pre_callback_expiry)
{
    delivery_env_t env;
    callback_fault_context_t context;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_step_result_t step_result;
    ninlil_time_sample_t safe_sample;
    ninlil_time_sample_t expired_sample;
    ninlil_id128_t transaction_id;
    ninlil_runtime_t *crashed_runtime;
    ninlil_status_t step_status;
    ninlil_status_t repeat_status;
    uint32_t expected_calls = pre_callback_expiry != 0 ? 0u : 1u;
    uint32_t safe_count =
        route == CALLBACK_FAULT_ROUTE_DOWNLINK ? 1u : 2u;
    uint32_t expected_before_hooks =
        pre_callback_expiry != 0
            || clock_fault == CALLBACK_CLOCK_FAULT_EXPIRY
        ? 0u : 1u;
    uint32_t expected_after_hooks =
        expected_before_hooks != 0u
            && storage_fault == CALLBACK_STORAGE_FAULT_NONE
        ? 1u : 0u;
    ninlil_rt_token_state_t expected_live_state;
    ninlil_reason_t expected_reason;

    REQUIRE(setup_active_callback_fault_route(
                route, &env, &context, &transaction_id)
        == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    if (pre_callback_expiry != 0) {
        safe_sample = env.runtime->started_sample;
        safe_sample.now_ms = transaction->delivery_started_at_ms;
        expired_sample = safe_sample;
        expired_sample.now_ms = transaction->token_expires_at_ms + 1u;
        REQUIRE(ninlil_test_clock_script_raw(
            env.clock, NINLIL_PORT_OK, &safe_sample, safe_count));
        REQUIRE(ninlil_test_clock_script_raw(
            env.clock, NINLIL_PORT_OK, &expired_sample, 1u));
    } else {
        context.clock_fault = clock_fault;
        context.storage_fault = storage_fault;
    }

    REQUIRE(step_delivery_once(&env, &step_status, &step_result));
    if (storage_fault == CALLBACK_STORAGE_FAULT_DEFINITE) {
        REQUIRE(step_status == NINLIL_E_STORAGE);
    } else if (storage_fault
        == CALLBACK_STORAGE_FAULT_CU_NOT_COMMITTED
        || storage_fault == CALLBACK_STORAGE_FAULT_CU_COMMITTED) {
        REQUIRE(step_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    } else if (pre_callback_expiry != 0
        || clock_fault == CALLBACK_CLOCK_FAULT_EXPIRY) {
        REQUIRE(step_status == NINLIL_OK);
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_PERMANENT
        || clock_fault == CALLBACK_CLOCK_FAULT_INVALID
        || clock_fault == CALLBACK_CLOCK_FAULT_INVALID_RESERVED
        || clock_fault == CALLBACK_CLOCK_FAULT_INVALID_VERSION
        || clock_fault == CALLBACK_CLOCK_FAULT_ROLLBACK) {
        REQUIRE(step_status == NINLIL_E_DEGRADED);
    } else {
        REQUIRE(step_status == NINLIL_E_CLOCK_UNCERTAIN);
    }
    REQUIRE(g_delivery_calls == expected_calls);
    REQUIRE(step_result.callbacks_invoked == expected_calls);
    if (pre_callback_expiry == 0) {
        REQUIRE(context.clock_scripted == 1u);
        REQUIRE(context.storage_scripted == 1u);
    }
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->evidence_recorded == 0u);
    REQUIRE(transaction->application_evidence_length == 0u);
    REQUIRE(transaction->pending_dispatch == 0u);
    REQUIRE(transaction->ingress_pending == 0u);
    REQUIRE(context.recovery_before_hook_count
        == expected_before_hooks);
    REQUIRE(context.recovery_after_hook_count == expected_after_hooks);
    REQUIRE(context.application_before_hook_count == expected_calls);
    REQUIRE(context.application_effect_hook_count == expected_calls);
    REQUIRE(context.application_after_hook_count == expected_calls);
    REQUIRE(context.callback_entry_saw_before_hook == expected_calls);
    REQUIRE(context.effect_hook_saw_callback_entry == expected_calls);
    REQUIRE(context.after_hook_saw_callback_return == expected_calls);
    REQUIRE(context.after_hook_saw_result_copy == expected_calls);
    REQUIRE(context.unexpected_hook_count == 0u);

    if (storage_fault != CALLBACK_STORAGE_FAULT_NONE) {
        expected_live_state = NINLIL_RT_TOKEN_ACTIVE;
        expected_reason = NINLIL_REASON_NONE;
    } else if (pre_callback_expiry != 0
        || clock_fault == CALLBACK_CLOCK_FAULT_EXPIRY) {
        expected_live_state = NINLIL_RT_TOKEN_EXPIRED;
        expected_reason =
            NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT;
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_EPOCH) {
        expected_live_state = NINLIL_RT_TOKEN_EXPIRED;
        expected_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
    } else {
        expected_live_state = NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
        expected_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
    }
    REQUIRE(transaction->token_state == expected_live_state);
    if (storage_fault == CALLBACK_STORAGE_FAULT_NONE) {
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
        REQUIRE(transaction->reason == expected_reason);
        REQUIRE(transaction->application_effect_certainty
            == NINLIL_EFFECT_CERTAINTY_POSSIBLE);
        REQUIRE(storage_last_commit_is_full(env.storage_fixture));
    }

    if (storage_fault == CALLBACK_STORAGE_FAULT_CU_NOT_COMMITTED
        || storage_fault == CALLBACK_STORAGE_FAULT_CU_COMMITTED) {
        REQUIRE(step_delivery_once(&env, &repeat_status, &step_result));
        REQUIRE(repeat_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    } else {
        REQUIRE(step_delivery_once(&env, &repeat_status, &step_result));
        REQUIRE(repeat_status == NINLIL_OK);
    }
    REQUIRE(g_delivery_calls == expected_calls);
    REQUIRE(context.recovery_before_hook_count
        == expected_before_hooks);
    REQUIRE(context.recovery_after_hook_count == expected_after_hooks);
    REQUIRE(context.application_before_hook_count == expected_calls);
    REQUIRE(context.application_effect_hook_count == expected_calls);
    REQUIRE(context.application_after_hook_count == expected_calls);
    REQUIRE(context.callback_entry_saw_before_hook == expected_calls);
    REQUIRE(context.effect_hook_saw_callback_entry == expected_calls);
    REQUIRE(context.after_hook_saw_callback_return == expected_calls);
    REQUIRE(context.after_hook_saw_result_copy == expected_calls);
    REQUIRE(context.unexpected_hook_count == 0u);

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    crashed_runtime = env.runtime;
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    (void)ninlil_runtime_destroy(crashed_runtime);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_phase
        == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_EXPIRED
        || transaction->token_state
            == NINLIL_RT_TOKEN_RECOVERY_REQUIRED);
    REQUIRE(transaction->evidence_recorded == 0u);
    REQUIRE(transaction->application_evidence_length == 0u);
    REQUIRE(transaction->pending_dispatch == 0u);
    REQUIRE(transaction->ingress_pending == 0u);
    REQUIRE(transaction->application_effect_certainty
        == NINLIL_EFFECT_CERTAINTY_POSSIBLE);
    REQUIRE(g_delivery_calls == expected_calls);
    platform_teardown(&env);
    return 0;
}

static int test_all_callback_paths_fresh_clock_and_restart_fences(void)
{
    static const callback_clock_fault_t preflight_faults[] = {
        CALLBACK_CLOCK_FAULT_TEMPORARY,
        CALLBACK_CLOCK_FAULT_UNCERTAIN,
        CALLBACK_CLOCK_FAULT_PERMANENT,
        CALLBACK_CLOCK_FAULT_INVALID,
        CALLBACK_CLOCK_FAULT_INVALID_RESERVED,
        CALLBACK_CLOCK_FAULT_INVALID_VERSION,
        CALLBACK_CLOCK_FAULT_EPOCH,
        CALLBACK_CLOCK_FAULT_ROLLBACK,
        CALLBACK_CLOCK_FAULT_EXPIRY
    };
    callback_fault_route_t route;
    uint32_t fault_index;

    for (route = CALLBACK_FAULT_ROUTE_DOWNLINK;
         route <= CALLBACK_FAULT_ROUTE_EVENT_FACT;
         route = (callback_fault_route_t)(route + 1)) {
        for (fault_index = 0u;
             fault_index
                < (uint32_t)(sizeof(preflight_faults)
                    / sizeof(preflight_faults[0]));
             ++fault_index) {
            REQUIRE(run_callback_preflight_fault_case(
                        route, preflight_faults[fault_index])
                == 0);
        }
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_TEMPORARY,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_UNCERTAIN,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_PERMANENT,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_INVALID,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_INVALID_RESERVED,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_INVALID_VERSION,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_EPOCH,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_ROLLBACK,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_EXPIRY,
                    CALLBACK_STORAGE_FAULT_NONE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_TEMPORARY,
                    CALLBACK_STORAGE_FAULT_DEFINITE,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_TEMPORARY,
                    CALLBACK_STORAGE_FAULT_CU_NOT_COMMITTED,
                    0)
            == 0);
        REQUIRE(run_callback_clock_fault_case(
                    route,
                    CALLBACK_CLOCK_FAULT_TEMPORARY,
                    CALLBACK_STORAGE_FAULT_CU_COMMITTED,
                    0)
            == 0);
    }
    return 0;
}

static int test_all_callback_paths_safe_completion_deep_copy(void)
{
    static const uint8_t expected_evidence[] = {
        0x91u, 0x92u, 0x93u, 0x94u
    };
    callback_fault_route_t route;

    for (route = CALLBACK_FAULT_ROUTE_DOWNLINK;
         route <= CALLBACK_FAULT_ROUTE_EVENT_FACT;
         route = (callback_fault_route_t)(route + 1)) {
        delivery_env_t env;
        callback_fault_context_t context;
        ninlil_rt_transaction_slot_t *transaction;
        ninlil_step_result_t step_result;
        ninlil_id128_t transaction_id;
        ninlil_status_t step_status;

        (void)memcpy(
            g_sync_evidence,
            expected_evidence,
            sizeof(expected_evidence));
        REQUIRE(setup_active_callback_fault_route(
                    route, &env, &context, &transaction_id)
            == 0);
        REQUIRE(step_delivery_once(&env, &step_status, &step_result));
        REQUIRE(step_status == NINLIL_OK);
        REQUIRE(g_delivery_calls == 1u);
        REQUIRE(step_result.callbacks_invoked == 1u);
        REQUIRE(context.recovery_before_hook_count == 0u);
        REQUIRE(context.recovery_after_hook_count == 0u);
        REQUIRE(context.application_before_hook_count == 1u);
        REQUIRE(context.application_effect_hook_count == 1u);
        REQUIRE(context.application_after_hook_count == 1u);
        REQUIRE(context.callback_entry_saw_before_hook == 1u);
        REQUIRE(context.effect_hook_saw_callback_entry == 1u);
        REQUIRE(context.after_hook_saw_callback_return == 1u);
        REQUIRE(context.after_hook_saw_result_copy == 1u);
        REQUIRE(context.unexpected_hook_count == 0u);
        transaction =
            ninlil_rt_find_transaction(env.runtime, &transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_CONSUMED);
        REQUIRE(transaction->evidence_recorded == 1u);
        REQUIRE(transaction->application_evidence_length
            == sizeof(expected_evidence));
        REQUIRE(memcmp(
                    transaction->application_evidence,
                    expected_evidence,
                    sizeof(expected_evidence))
            == 0);

        (void)memset(g_sync_evidence, 0, sizeof(g_sync_evidence));
        REQUIRE(memcmp(
                    transaction->application_evidence,
                    expected_evidence,
                    sizeof(expected_evidence))
            == 0);
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
        env.runtime = NULL;
        REQUIRE(ninlil_runtime_create(
                    &env.config, &env.platform, &env.runtime)
            == NINLIL_OK);
        transaction =
            ninlil_rt_find_transaction(env.runtime, &transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_CONSUMED);
        REQUIRE(transaction->evidence_recorded == 1u);
        REQUIRE(transaction->application_evidence_length
            == sizeof(expected_evidence));
        REQUIRE(memcmp(
                    transaction->application_evidence,
                    expected_evidence,
                    sizeof(expected_evidence))
            == 0);
        REQUIRE(g_delivery_calls == 1u);
        platform_teardown(&env);
    }
    (void)memcpy(
        g_sync_evidence, expected_evidence, sizeof(expected_evidence));
    return 0;
}

static int test_delivery_complete_validation_order_and_clock_fences(void)
{
    static const uint8_t tags[] = {0x6eu};
    delivery_env_t env;
    ninlil_application_result_t result;
    ninlil_delivery_token_t token;
    ninlil_time_sample_t sample;
    ninlil_id128_t other_epoch;
    uint8_t evidence[1] = {0x5au};
    uint64_t commit_before;
    uint64_t clock_before;

    REQUIRE(setup_active_inbound_deliveries_at(
                &env, tags, 1u, 1u, 1u, 999u, NINLIL_OK)
        == 0);
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    result.kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    result.evidence_stage = NINLIL_EVIDENCE_APPLIED;
    result.retry_guidance = NINLIL_RETRY_NEVER;
    result.evidence.data = evidence;
    result.evidence.length = sizeof(evidence);
    commit_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    clock_before = ninlil_test_clock_call_count(env.clock);

    token = g_deferred_token;
    set_txn_id(&token.context_id, 0x7eu);
    REQUIRE(ninlil_delivery_complete(env.runtime, &token, &result)
        == NINLIL_E_NOT_FOUND);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);

    (void)memset(&sample, 0, sizeof(sample));
    set_header(&sample.abi_version, &sample.struct_size, sizeof(sample));
    set_id(&other_epoch, 0xe1u);
    sample.clock_epoch_id = other_epoch;
    sample.now_ms = g_deferred_token.expires_at_ms;
    sample.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &sample, 1u));
    REQUIRE(ninlil_delivery_complete(
                env.runtime, &g_deferred_token, &result)
        == NINLIL_E_CLOCK_UNCERTAIN);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);

    sample.clock_epoch_id = g_deferred_token.clock_epoch_id;
    sample.now_ms = 998u;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &sample, 1u));
    REQUIRE(ninlil_delivery_complete(
                env.runtime, &g_deferred_token, &result)
        == NINLIL_E_DEGRADED);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);
    REQUIRE(ninlil_rt_find_transaction(
                env.runtime, &g_deferred_token.context_id)->token_state
        == NINLIL_RT_TOKEN_ACTIVE);
    platform_teardown(&env);
    g_defer_delivery = 0u;
    return 0;
}

typedef struct destroy_hook_observation {
    uint32_t before_count;
    uint32_t after_count;
} destroy_hook_observation_t;

static void observe_destroy_hook(void *user, const char *name)
{
    destroy_hook_observation_t *observation =
        (destroy_hook_observation_t *)user;

    if (strcmp(name, "runtime.before_destroy_recovery_commit") == 0) {
        observation->before_count += 1u;
    } else if (strcmp(name, "runtime.after_destroy_recovery_commit") == 0) {
        observation->after_count += 1u;
    }
}

static int setup_active_inbound_deliveries_at(
    delivery_env_t *env,
    const uint8_t *transaction_tags,
    uint32_t transaction_count,
    uint32_t delivery_limit,
    uint32_t deferred_limit,
    uint64_t initial_time_ms,
    ninlil_status_t expected_step_status)
{
    ninlil_service_callbacks_t callbacks;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    uint32_t index;

    (void)memset(env, 0, sizeof(*env));
    REQUIRE(platform_init(env));
    if (initial_time_ms != 0u) {
        REQUIRE(ninlil_test_clock_advance(env->clock, initial_time_ms));
    }
    env->config = config_controller(4u);
    env->config.limits.max_nonterminal_deliveries = delivery_limit;
    env->config.limits.max_deferred_tokens = deferred_limit;
    REQUIRE(ninlil_runtime_create(
                &env->config, &env->platform, &env->runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env->runtime) == NINLIL_OK);
    env->runtime = NULL;
    for (index = 0u; index < transaction_count; ++index) {
        ninlil_id128_t transaction_id;

        set_txn_id(&transaction_id, transaction_tags[index]);
        REQUIRE(seed_parked_event_txn(
            env->storage_fixture,
            env->config.storage_namespace,
            &transaction_id,
            0x76u,
            2u + index));
    }
    REQUIRE(ninlil_runtime_create(
                &env->config, &env->platform, &env->runtime)
        == NINLIL_OK);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = delivery_complete_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(controller_register_event_receiver(env, 0x76u, &callbacks));

    g_delivery_calls = 0u;
    g_fail_delivery = 0u;
    g_defer_delivery = 1u;
    (void)memset(&g_deferred_token, 0, sizeof(g_deferred_token));
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env->runtime, &budget, &step_result)
        == expected_step_status);
    return 0;
}

static int setup_active_inbound_deliveries(
    delivery_env_t *env,
    const uint8_t *transaction_tags,
    uint32_t transaction_count,
    uint32_t delivery_limit,
    uint32_t deferred_limit,
    ninlil_status_t expected_step_status)
{
    return setup_active_inbound_deliveries_at(
        env,
        transaction_tags,
        transaction_count,
        delivery_limit,
        deferred_limit,
        0u,
        expected_step_status);
}

static int recovery_tuple_is_exact(
    const ninlil_rt_transaction_slot_t *transaction)
{
    return transaction != NULL
        && transaction->token_state == NINLIL_RT_TOKEN_EXPIRED
        && transaction->delivery_phase
            == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED
        && transaction->reason == NINLIL_REASON_OUTCOME_UNKNOWN
        && transaction->application_result_kind == 0u
        && transaction->application_disposition
            == NINLIL_DISPOSITION_NONE
        && transaction->application_result_reason
            == NINLIL_REASON_OUTCOME_UNKNOWN
        && transaction->application_effect_certainty
            == NINLIL_EFFECT_CERTAINTY_POSSIBLE
        && transaction->application_retry_guidance
            == NINLIL_RETRY_OPERATOR_ACTION
        && transaction->application_retry_delay_ms == 0u
        && transaction->application_evidence_length == 0u
        && transaction->evidence_recorded == 0u
        && transaction->outcome_recorded == 0u
        && transaction->outcome == NINLIL_OUTCOME_NONE
        && transaction->terminal == 0u;
}

static int read_capacity_entry(
    ninlil_runtime_t *runtime,
    ninlil_resource_kind_t kind,
    ninlil_capacity_entry_t *out_entry)
{
    ninlil_capacity_entry_t
        entries[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    ninlil_capacity_snapshot_t snapshot;
    uint32_t index;

    if (kind < NINLIL_RESOURCE_SERVICE
        || kind > NINLIL_RESOURCE_DEFERRED_TOKEN
        || out_entry == NULL) {
        return 0;
    }
    (void)memset(entries, 0, sizeof(entries));
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        set_header(
            &entries[index].abi_version,
            &entries[index].struct_size,
            sizeof(entries[index]));
    }
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.entries = entries;
    snapshot.entry_capacity = NINLIL_MODEL_RESOURCE_KIND_COUNT;
    if (ninlil_capacity_snapshot(runtime, &snapshot) != NINLIL_OK
        || snapshot.entry_count != NINLIL_MODEL_RESOURCE_KIND_COUNT
        || entries[kind - 1u].kind != kind) {
        return 0;
    }
    *out_entry = entries[kind - 1u];
    return 1;
}

static int test_destroy_recovery_group_is_atomic_and_ordered(void)
{
    static const uint8_t tags[] = {0x90u, 0x70u, 0x80u};
    delivery_env_t env;
    destroy_hook_observation_t hooks;
    uint32_t order[3];
    uint32_t count = 0u;
    uint32_t index;
    uint64_t begin_before;
    uint64_t put_before;
    uint64_t commit_before;

    REQUIRE(setup_active_inbound_deliveries(
                &env,
                tags,
                (uint32_t)(sizeof(tags) / sizeof(tags[0])),
                3u,
                3u,
                NINLIL_OK)
        == 0);
    REQUIRE(g_delivery_calls == 3u);
    REQUIRE(ninlil_rt_v1_collect_destroy_token_order(
                env.runtime,
                order,
                (uint32_t)(sizeof(order) / sizeof(order[0])),
                &count)
        == NINLIL_OK);
    REQUIRE(count == 3u);
    REQUIRE(env.runtime->transactions[order[0]].transaction_id.bytes[0]
        == 0x70u);
    REQUIRE(env.runtime->transactions[order[1]].transaction_id.bytes[0]
        == 0x80u);
    REQUIRE(env.runtime->transactions[order[2]].transaction_id.bytes[0]
        == 0x90u);

    (void)memset(&hooks, 0, sizeof(hooks));
    env.runtime->private_transition_hook = observe_destroy_hook;
    env.runtime->private_transition_hook_user = &hooks;
    begin_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);
    put_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(hooks.before_count == 1u);
    REQUIRE(hooks.after_count == 1u);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN)
        == begin_before + 1u);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before + 1u);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == put_before + count + NINLIL_MODEL_RESOURCE_KIND_COUNT);

    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    for (index = 0u; index < count; ++index) {
        ninlil_id128_t transaction_id;

        set_txn_id(&transaction_id, tags[index]);
        REQUIRE(recovery_tuple_is_exact(
            ninlil_rt_find_transaction(env.runtime, &transaction_id)));
    }
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == count);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
        == count);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 0u);
    platform_teardown(&env);
    g_defer_delivery = 0u;
    return 0;
}

static int test_destroy_without_active_tokens_has_no_storage_mutation(void)
{
    delivery_env_t env;
    destroy_hook_observation_t hooks;
    uint64_t begin_before;
    uint64_t put_before;
    uint64_t commit_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&hooks, 0, sizeof(hooks));
    env.runtime->private_transition_hook = observe_destroy_hook;
    env.runtime->private_transition_hook_user = &hooks;
    begin_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);
    put_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(hooks.before_count == 0u);
    REQUIRE(hooks.after_count == 0u);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN)
        == begin_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == put_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_before);
    platform_teardown(&env);
    return 0;
}

static int test_destroy_order_uses_generation_as_secondary_key(void)
{
    ninlil_runtime_t runtime;
    ninlil_rt_transaction_slot_t transactions[3];
    uint32_t order[3];
    uint32_t count = 0u;

    (void)memset(&runtime, 0, sizeof(runtime));
    (void)memset(transactions, 0, sizeof(transactions));
    runtime.transactions = transactions;
    runtime.transaction_capacity = 3u;
    transactions[0].in_use = 1u;
    transactions[0].token_state = NINLIL_RT_TOKEN_ACTIVE;
    set_id(&transactions[0].transaction_id, 0x20u);
    transactions[0].token_generation = 9u;
    transactions[1].in_use = 1u;
    transactions[1].token_state = NINLIL_RT_TOKEN_ACTIVE;
    transactions[1].transaction_id = transactions[0].transaction_id;
    transactions[1].token_generation = 3u;
    transactions[2].in_use = 1u;
    transactions[2].token_state = NINLIL_RT_TOKEN_ACTIVE;
    set_id(&transactions[2].transaction_id, 0x10u);
    transactions[2].token_generation = 99u;

    REQUIRE(ninlil_rt_v1_collect_destroy_token_order(
                &runtime,
                order,
                (uint32_t)(sizeof(order) / sizeof(order[0])),
                &count)
        == NINLIL_OK);
    REQUIRE(count == 3u);
    REQUIRE(order[0] == 2u);
    REQUIRE(order[1] == 1u);
    REQUIRE(order[2] == 0u);
    return 0;
}

static int run_destroy_recovery_fault_case(
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t raw_status,
    int has_unknown_truth,
    int committed_truth,
    ninlil_status_t expected_status,
    uint32_t expected_before_hooks)
{
    static const uint8_t tags[] = {0x71u, 0x81u};
    delivery_env_t env;
    destroy_hook_observation_t hooks;
    uint32_t index;

    REQUIRE(setup_active_inbound_deliveries(
                &env, tags, 2u, 2u, 2u, NINLIL_OK)
        == 0);
    (void)memset(&hooks, 0, sizeof(hooks));
    env.runtime->private_transition_hook = observe_destroy_hook;
    env.runtime->private_transition_hook_user = &hooks;
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage_fixture,
        operation,
        raw_status,
        1u,
        has_unknown_truth,
        committed_truth));
    REQUIRE(ninlil_runtime_destroy(env.runtime) == expected_status);
    env.runtime = NULL;
    REQUIRE(hooks.before_count == expected_before_hooks);
    REQUIRE(hooks.after_count == 0u);

    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    for (index = 0u; index < 2u; ++index) {
        ninlil_id128_t transaction_id;

        set_txn_id(&transaction_id, tags[index]);
        REQUIRE(recovery_tuple_is_exact(
            ninlil_rt_find_transaction(env.runtime, &transaction_id)));
    }
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 0u);
    platform_teardown(&env);
    g_defer_delivery = 0u;
    return 0;
}

static int test_destroy_recovery_group_fault_matrix(void)
{
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_BEGIN,
                NINLIL_STORAGE_BUSY,
                0,
                0,
                NINLIL_E_WOULD_BLOCK,
                0u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_BEGIN,
                NINLIL_STORAGE_NO_SPACE,
                0,
                0,
                NINLIL_E_CAPACITY_EXHAUSTED,
                0u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_PUT,
                NINLIL_STORAGE_IO_ERROR,
                0,
                0,
                NINLIL_E_STORAGE,
                0u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_PUT,
                NINLIL_STORAGE_CORRUPT,
                0,
                0,
                NINLIL_E_STORAGE_CORRUPT,
                0u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_IO_ERROR,
                0,
                0,
                NINLIL_E_STORAGE,
                1u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_UNSUPPORTED_SCHEMA,
                0,
                0,
                NINLIL_E_STORAGE_CORRUPT,
                1u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1,
                0,
                NINLIL_E_STORAGE_COMMIT_UNKNOWN,
                1u)
        == 0);
    REQUIRE(run_destroy_recovery_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1,
                1,
                NINLIL_E_STORAGE_COMMIT_UNKNOWN,
                1u)
        == 0);
    return 0;
}

static int run_callback_start_fault_case(
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t raw_status,
    int has_unknown_truth,
    int committed_truth,
    ninlil_status_t expected_status)
{
    delivery_env_t env;
    ninlil_id128_t transaction_id;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_v1_step_delivery_result_t delivery_result;
    ninlil_model_resource_ledger_t ledger_before;
    ninlil_time_sample_t sample;
    uint64_t revision_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&transaction_id, 0x79u);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &transaction_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    revision_before = transaction->record_revision;
    ledger_before = env.runtime->resource_ledger;
    sample = env.runtime->started_sample;
    (void)memset(&delivery_result, 0, sizeof(delivery_result));
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage_fixture,
        operation,
        raw_status,
        1u,
        has_unknown_truth,
        committed_truth));
    REQUIRE(ninlil_rt_v1_prepare_callback_start(
                env.runtime,
                transaction,
                &sample,
                60000u,
                &delivery_result)
        == expected_status);
    REQUIRE(transaction->record_revision == revision_before);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_NONE);
    REQUIRE(transaction->token_generation == 0u);
    REQUIRE(delivery_result.callbacks_invoked == 0u);
    REQUIRE(delivery_result.transitions_consumed == 0u);
    REQUIRE(memcmp(
                &env.runtime->resource_ledger,
                &ledger_before,
                sizeof(ledger_before))
        == 0);

    if (expected_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
        REQUIRE(ninlil_runtime_destroy(env.runtime)
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    } else {
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    }
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    if (expected_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN
        && committed_truth != 0) {
        REQUIRE(recovery_tuple_is_exact(transaction));
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
            == 1u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
            == 1u);
    } else {
        REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_NONE);
        REQUIRE(transaction->token_generation == 0u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
            == 1u);
        REQUIRE(env.runtime->resource_ledger
                .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
            == 0u);
    }
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 0u);
    platform_teardown(&env);
    return 0;
}

static int test_callback_start_fault_matrix_has_no_false_callback(void)
{
    REQUIRE(run_callback_start_fault_case(
                NINLIL_TEST_STORAGE_OP_BEGIN,
                NINLIL_STORAGE_BUSY,
                0,
                0,
                NINLIL_E_WOULD_BLOCK)
        == 0);
    REQUIRE(run_callback_start_fault_case(
                NINLIL_TEST_STORAGE_OP_PUT,
                NINLIL_STORAGE_IO_ERROR,
                0,
                0,
                NINLIL_E_STORAGE)
        == 0);
    REQUIRE(run_callback_start_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_IO_ERROR,
                0,
                0,
                NINLIL_E_STORAGE)
        == 0);
    REQUIRE(run_callback_start_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1,
                0,
                NINLIL_E_STORAGE_COMMIT_UNKNOWN)
        == 0);
    REQUIRE(run_callback_start_fault_case(
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1,
                1,
                NINLIL_E_STORAGE_COMMIT_UNKNOWN)
        == 0);
    return 0;
}

static void apply_clock_shape_fault(
    ninlil_time_sample_t *sample,
    callback_clock_fault_t clock_fault)
{
    if (clock_fault == CALLBACK_CLOCK_FAULT_INVALID_VERSION) {
        sample->abi_version =
            (uint16_t)(NINLIL_ABI_VERSION + 1u);
    } else if (clock_fault == CALLBACK_CLOCK_FAULT_INVALID) {
        sample->struct_size = (uint16_t)(sizeof(*sample) - 1u);
    } else if (clock_fault
        == CALLBACK_CLOCK_FAULT_INVALID_RESERVED) {
        sample->reserved_zero = 1u;
    }
}

static int run_runtime_clock_shape_fault_case(
    callback_clock_fault_t clock_fault,
    int fault_at_callback_start)
{
    delivery_env_t env;
    callback_fault_context_t context;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_model_resource_ledger_t ledger_before;
    ninlil_step_result_t step_result;
    ninlil_time_sample_t safe_sample;
    ninlil_time_sample_t fault_sample;
    ninlil_id128_t transaction_id;
    ninlil_status_t step_status;
    uint64_t revision_before;
    uint32_t pending_before;
    uint32_t ingress_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 100u));
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&transaction_id, 0x7au);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &transaction_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    (void)memset(&context, 0, sizeof(context));
    context.clock = env.clock;
    context.storage = env.storage_fixture;
    context.runtime = env.runtime;
    context.controller_recovery_hook = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version,
        &callbacks.struct_size,
        sizeof(callbacks));
    callbacks.user = &context;
    callbacks.on_delivery = delivery_complete_with_post_fault_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    descriptor = event_fact_descriptor(0x76u);
    descriptor.application_completion_timeout_ms = 10u;
    REQUIRE(env_register(&env, &descriptor, &callbacks));
    env.runtime->private_transition_hook =
        observe_callback_recovery_hook;
    env.runtime->private_transition_hook_user = &context;
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_NONE);
    revision_before = transaction->record_revision;
    ledger_before = env.runtime->resource_ledger;
    pending_before = transaction->pending_dispatch;
    ingress_before = transaction->ingress_pending;
    safe_sample = env.runtime->started_sample;
    fault_sample = safe_sample;
    apply_clock_shape_fault(&fault_sample, clock_fault);
    if (fault_at_callback_start != 0) {
        REQUIRE(ninlil_test_clock_script_raw(
            env.clock, NINLIL_PORT_OK, &safe_sample, 1u));
    }
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &fault_sample, 1u));
    g_delivery_calls = 0u;

    REQUIRE(step_delivery_once(&env, &step_status, &step_result));
    REQUIRE(step_status == NINLIL_E_DEGRADED);
    REQUIRE(g_delivery_calls == 0u);
    REQUIRE(step_result.callbacks_invoked == 0u);
    REQUIRE(context.application_before_hook_count == 0u);
    REQUIRE(context.application_effect_hook_count == 0u);
    REQUIRE(context.application_after_hook_count == 0u);
    REQUIRE(context.recovery_before_hook_count == 0u);
    REQUIRE(context.recovery_after_hook_count == 0u);
    REQUIRE(context.unexpected_hook_count == 0u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_NONE);
    REQUIRE(transaction->token_generation == 0u);
    REQUIRE(transaction->record_revision == revision_before);
    REQUIRE(transaction->pending_dispatch == pending_before);
    REQUIRE(transaction->ingress_pending == ingress_before);
    REQUIRE(memcmp(
                &env.runtime->resource_ledger,
                &ledger_before,
                sizeof(ledger_before))
        == 0);

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_clock_sample_shapes_fail_closed_before_active_token(void)
{
    static const callback_clock_fault_t clock_faults[] = {
        CALLBACK_CLOCK_FAULT_INVALID_VERSION,
        CALLBACK_CLOCK_FAULT_INVALID,
        CALLBACK_CLOCK_FAULT_INVALID_RESERVED
    };
    delivery_env_t env;
    ninlil_id128_t transaction_id;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_v1_step_delivery_result_t delivery_result;
    ninlil_model_resource_ledger_t ledger_before;
    ninlil_time_sample_t sample;
    uint64_t revision_before;
    uint64_t commits_before;
    uint32_t fault_index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&transaction_id, 0x7bu);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &transaction_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    revision_before = transaction->record_revision;
    commits_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    ledger_before = env.runtime->resource_ledger;
    for (fault_index = 0u;
         fault_index
            < (uint32_t)(sizeof(clock_faults)
                / sizeof(clock_faults[0]));
         ++fault_index) {
        sample = env.runtime->started_sample;
        apply_clock_shape_fault(
            &sample, clock_faults[fault_index]);
        (void)memset(&delivery_result, 0, sizeof(delivery_result));
        REQUIRE(ninlil_rt_v1_prepare_callback_start(
                    env.runtime,
                    transaction,
                    &sample,
                    10u,
                    &delivery_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_NONE);
        REQUIRE(transaction->token_generation == 0u);
        REQUIRE(transaction->record_revision == revision_before);
        REQUIRE(delivery_result.callbacks_invoked == 0u);
        REQUIRE(delivery_result.transitions_consumed == 0u);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture,
                    NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before);
        REQUIRE(memcmp(
                    &env.runtime->resource_ledger,
                    &ledger_before,
                    sizeof(ledger_before))
            == 0);
    }
    platform_teardown(&env);

    for (fault_index = 0u;
         fault_index
            < (uint32_t)(sizeof(clock_faults)
                / sizeof(clock_faults[0]));
         ++fault_index) {
        REQUIRE(run_runtime_clock_shape_fault_case(
                    clock_faults[fault_index], 0)
            == 0);
        REQUIRE(run_runtime_clock_shape_fault_case(
                    clock_faults[fault_index], 1)
            == 0);
    }
    return 0;
}

static int test_create_recovers_active_token_before_bearer_open_failure(void)
{
    delivery_env_t env;
    ninlil_id128_t transaction_id;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_v1_step_delivery_result_t delivery_result;
    ninlil_time_sample_t sample;
    uint64_t commits_before;
    uint64_t opens_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&transaction_id, 0x6fu);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &transaction_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    sample = env.runtime->started_sample;
    (void)memset(&delivery_result, 0, sizeof(delivery_result));
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        1));
    REQUIRE(ninlil_rt_v1_prepare_callback_start(
                env.runtime,
                transaction,
                &sample,
                60000u,
                &delivery_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);

    REQUIRE(ninlil_test_bearer_raw_open_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_UNAVAILABLE,
        0,
        1u));
    commits_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    opens_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_OPEN);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_E_WOULD_BLOCK);
    REQUIRE(env.runtime == NULL);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commits_before + 1u);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_OPEN)
        == opens_before + 1u);

    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(recovery_tuple_is_exact(
        ninlil_rt_find_transaction(env.runtime, &transaction_id)));
    platform_teardown(&env);
    return 0;
}

static int test_second_inbound_admission_is_rejected_before_durable_commit(void)
{
    delivery_env_t env;
    ninlil_id128_t first_id;
    ninlil_id128_t second_id;
    ninlil_rt_transaction_slot_t *first;
    ninlil_rt_transaction_slot_t *empty_slot;
    ninlil_rt_transaction_slot_t candidate;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_descriptor_t descriptor;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_status_t admission_status;
    uint64_t ordered_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_nonterminal_transactions = 2u;
    env.config.limits.max_nonterminal_deliveries = 1u;
    env.config.limits.max_deferred_tokens = 1u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&first_id, 0x51u);
    set_txn_id(&second_id, 0x61u);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &first_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    first = ninlil_rt_find_transaction(env.runtime, &first_id);
    REQUIRE(first != NULL);
    REQUIRE(env.runtime->transaction_count == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == 1u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = delivery_complete_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    descriptor = event_fact_descriptor(0x76u);
    descriptor.inflight_limit = 2u;
    REQUIRE(env_register(&env, &descriptor, &callbacks));
    g_delivery_calls = 0u;
    fill_step_budget(&budget);
    budget.max_callbacks = 0u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(step_result.callbacks_invoked == 0u);
    REQUIRE(g_delivery_calls == 0u);
    REQUIRE(first->token_state == NINLIL_RT_TOKEN_NONE);
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    empty_slot = ninlil_rt_alloc_transaction(env.runtime);
    REQUIRE(empty_slot != NULL);
    REQUIRE(empty_slot->in_use == 0u);
    empty_slot->transaction_id = second_id;
    candidate = *first;
    candidate.transaction_id = second_id;
    set_txn_id(&candidate.attempt_id, 0x62u);
    set_txn_id(&candidate.event_id, 0x63u);
    candidate.transaction_sequence = first->transaction_sequence + 1u;
    candidate.ordered_input_sequence = ordered_before + 1u;

    admission_status = ninlil_rt_v1_commit_ordered_input_snapshot(
        env.runtime,
        empty_slot,
        &candidate,
        0x4453u,
        NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT);
    REQUIRE(admission_status == NINLIL_E_CAPACITY_EXHAUSTED);
    REQUIRE(empty_slot->in_use == 0u);
    REQUIRE(ninlil_rt_find_transaction(env.runtime, &second_id) == NULL);
    REQUIRE(env.runtime->transaction_count == 1u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].blocked
        == 1u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_rt_find_transaction(env.runtime, &first_id) != NULL);
    REQUIRE(ninlil_rt_find_transaction(env.runtime, &second_id) == NULL);
    REQUIRE(env.runtime->transaction_count == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_restart_rejects_noncanonical_nts3_token_tuple(void)
{
    delivery_env_t env;
    ninlil_id128_t transaction_id;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_v1_step_delivery_result_t delivery_result;
    ninlil_time_sample_t sample;
    ninlil_runtime_t *crashed_runtime;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    set_txn_id(&transaction_id, 0x64u);
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        env.config.storage_namespace,
        &transaction_id,
        0x76u,
        2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &transaction_id);
    REQUIRE(transaction != NULL);
    sample = env.runtime->started_sample;
    (void)memset(&delivery_result, 0, sizeof(delivery_result));
    REQUIRE(ninlil_rt_v1_prepare_callback_start(
                env.runtime,
                transaction,
                &sample,
                60000u,
                &delivery_result)
        == NINLIL_OK);
    REQUIRE(corrupt_durable_active_token_deferred_wait(
        env.runtime,
        &transaction_id,
        &transaction->token_clock_epoch_id));

    crashed_runtime = env.runtime;
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    (void)ninlil_runtime_destroy(crashed_runtime);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env.runtime == NULL);
    platform_teardown(&env);
    return 0;
}

static int test_callback_capacity_is_acquired_before_callback(void)
{
    static const uint8_t tags[] = {0x70u, 0x80u};
    delivery_env_t env;
    ninlil_application_result_t result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_capacity_entry_t capacity;

    REQUIRE(setup_active_inbound_deliveries(
                &env,
                tags,
                2u,
                2u,
                1u,
                NINLIL_E_CAPACITY_EXHAUSTED)
        == 0);
    REQUIRE(g_delivery_calls == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DELIVERY - 1u].used
        == 2u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_RESULT_CACHE - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 1u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].blocked
        == 1u);
    REQUIRE(read_capacity_entry(
        env.runtime, NINLIL_RESOURCE_DEFERRED_TOKEN, &capacity));
    REQUIRE(capacity.limit == 1u);
    REQUIRE(capacity.used == 1u);
    REQUIRE(capacity.reserved == 0u);
    REQUIRE(capacity.high_water == 1u);

    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    result.kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    result.evidence_stage = NINLIL_EVIDENCE_APPLIED;
    result.retry_guidance = NINLIL_RETRY_NEVER;
    REQUIRE(ninlil_delivery_complete(
                env.runtime, &g_deferred_token, &result)
        == NINLIL_OK);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 0u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].blocked
        == 0u);
    REQUIRE(read_capacity_entry(
        env.runtime, NINLIL_RESOURCE_DEFERRED_TOKEN, &capacity));
    REQUIRE(capacity.used == 0u);
    REQUIRE(capacity.reserved == 0u);

    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(g_delivery_calls == 2u);
    REQUIRE(env.runtime->resource_ledger
            .entries[NINLIL_RESOURCE_DEFERRED_TOKEN - 1u].used
        == 1u);
    platform_teardown(&env);
    g_defer_delivery = 0u;
    return 0;
}

#if 0
static int test_event_resume_discard_flow(void)
{
    delivery_env_t env;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_service_callbacks_t callbacks;
    ninlil_id128_t txn_id;
    ninlil_id128_t op_id;
    ninlil_runtime_config_t config;
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_bearer_t *bearer_fixture;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    ninlil_metrics_snapshot_t metrics;

    g_delivery_calls = 0u;
    g_fail_delivery = 0u;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_txn_id(&txn_id, 0x78u);
    config = config_controller(4u);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)ninlil_runtime_destroy(env.runtime);
    env.runtime = NULL;
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        config.storage_namespace,
        &txn_id,
        0x72u,
        2u));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = delivery_complete_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(controller_register_event_receiver(&env, 0x72u, &callbacks));

    (void)memset(&resume_request, 0, sizeof(resume_request));
    set_header(
        &resume_request.abi_version,
        &resume_request.struct_size,
        sizeof(resume_request));
    set_id(&op_id, 0xa1u);
    resume_request.operation_id = op_id;
    resume_request.expected_spool_revision = 2u;
    resume_request.resume_reason = NINLIL_RESUME_TEST;
    REQUIRE(ninlil_event_resume(
                env.runtime, &txn_id, &resume_request, &resume_result)
        == NINLIL_OK);
    REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_RESUMED);
    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.events_resumed == 1u);

    fill_step_budget(&budget);
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);

    fill_step_budget(&budget);
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);

    allocator = env.allocator;
    execution = env.execution;
    clock = env.clock;
    entropy = env.entropy;
    storage_fixture = env.storage_fixture;
    bearer_fixture = env.bearer_fixture;
    origin = env.origin;
    platform = env.platform;
    env.allocator = NULL;
    env.execution = NULL;
    env.clock = NULL;
    env.entropy = NULL;
    env.storage_fixture = NULL;
    env.bearer_fixture = NULL;
    (void)ninlil_runtime_destroy(env.runtime);
    env.runtime = NULL;

    env.allocator = allocator;
    env.execution = execution;
    env.clock = clock;
    env.entropy = entropy;
    env.storage_fixture = storage_fixture;
    env.bearer_fixture = bearer_fixture;
    env.origin = origin;
    env.platform = platform;
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.events_resumed == 0u);
    REQUIRE(controller_register_event_receiver(&env, 0x72u, &callbacks));
    fill_step_budget(&budget);
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);

    platform_teardown(&env);
    return 0;
}

static int test_event_discard_commit_metrics_and_restart(void)
{
    delivery_env_t env;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_metrics_snapshot_t metrics;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t txn_id;
    ninlil_runtime_config_t config;
    uint64_t revision_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_txn_id(&txn_id, 0x7au);
    config = config_controller(4u);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        config.storage_namespace,
        &txn_id,
        0x75u,
        2u));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
    REQUIRE(transaction != NULL);
    revision_before = transaction->record_revision;

    (void)memset(&discard_request, 0, sizeof(discard_request));
    set_header(
        &discard_request.abi_version,
        &discard_request.struct_size,
        sizeof(discard_request));
    set_id(&discard_request.operation_id, 0xa4u);
    discard_request.expected_spool_revision = 2u;
    discard_request.discard_reason = NINLIL_DISCARD_TEST_CLEANUP;
    discard_request.acknowledge_required_receipt_absent = 1u;
    REQUIRE(ninlil_event_discard(
                env.runtime, &txn_id, &discard_request, &discard_result)
        == NINLIL_OK);
    REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
    REQUIRE(discard_result.spool_revision == 3u);
    transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->event_discarded == 1u);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(transaction->record_revision == revision_before + 1u);
    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.events_discarded == 1u);
    REQUIRE(metrics.transactions_failed_definitive == 1u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    transaction = ninlil_rt_find_transaction(env.runtime, &txn_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->event_discarded == 1u);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(transaction->record_revision == revision_before + 1u);
    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.events_discarded == 0u);
    REQUIRE(metrics.transactions_failed_definitive == 0u);

    platform_teardown(&env);
    return 0;
}

static int test_event_discard_stale_revision(void)
{
    delivery_env_t env;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_service_callbacks_t callbacks;
    ninlil_id128_t txn_id;
    ninlil_id128_t op_id;
    ninlil_runtime_config_t config;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_txn_id(&txn_id, 0x79u);
    config = config_controller(4u);
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)ninlil_runtime_destroy(env.runtime);
    env.runtime = NULL;
    REQUIRE(seed_parked_event_txn(
        env.storage_fixture,
        config.storage_namespace,
        &txn_id,
        0x73u,
        2u));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = delivery_complete_cb;
    callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(controller_register_event_receiver(&env, 0x73u, &callbacks));

    (void)memset(&discard_request, 0, sizeof(discard_request));
    set_header(
        &discard_request.abi_version,
        &discard_request.struct_size,
        sizeof(discard_request));
    set_id(&op_id, 0xa3u);
    discard_request.operation_id = op_id;
    discard_request.expected_spool_revision = 999u;
    discard_request.discard_reason = NINLIL_DISCARD_TEST_CLEANUP;
    discard_request.acknowledge_required_receipt_absent = 1u;

    REQUIRE(ninlil_event_discard(
                env.runtime, &txn_id, &discard_request, &discard_result)
        == NINLIL_OK);
    REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_STALE_SPOOL_REVISION);

    platform_teardown(&env);
    return 0;
}
#endif

static int test_endpoint_event_availability_resume_once_and_restart(void)
{
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_bearer_state_t available_state;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_ENDPOINT));
    descriptor = event_fact_descriptor(0x74u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_event_submission(
        &env,
        &submission,
        0x77u,
        0x93u,
        TEST_IDEM_EVENT_A,
        sizeof(TEST_IDEM_EVENT_A) - 1u);
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));

    REQUIRE(ninlil_submit(env.service, &submission, &submit_result) == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    fill_step_budget(&budget);
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    REQUIRE(transaction->event_park_cause
        == NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE);
    REQUIRE(transaction->retry_cycle_id == 1u);
    REQUIRE(transaction->last_bearer_availability_epoch == 1u);
    REQUIRE(transaction->last_consumed_bearer_availability_epoch == 1u);

    (void)memset(&available_state, 0, sizeof(available_state));
    set_header(
        &available_state.abi_version,
        &available_state.struct_size,
        sizeof(available_state));
    available_state.availability_epoch = 2u;
    available_state.available = 1u;
    REQUIRE(ninlil_test_bearer_raw_state_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_OK,
        &available_state,
        2u));

    fill_step_budget(&budget);
    budget.max_state_transitions = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(step_result.state_transitions == 1u);
    REQUIRE(transaction->retry_cycle_id == 1u);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);

    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(step_result.state_transitions == 1u);
    REQUIRE(transaction->retry_cycle_id == 2u);
    REQUIRE(transaction->attempt_in_cycle == 0u);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_QUEUED);
    REQUIRE(transaction->last_bearer_availability_epoch == 2u);
    REQUIRE(transaction->last_consumed_bearer_availability_epoch == 2u);

    REQUIRE(ninlil_test_bearer_raw_state_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_OK,
        &available_state,
        1u));
    fill_step_budget(&budget);
    budget.max_state_transitions = 0u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction->retry_cycle_id == 2u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(env_create(&env, NINLIL_ROLE_ENDPOINT));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->retry_cycle_id == 2u);
    REQUIRE(transaction->last_bearer_availability_epoch == 2u);
    REQUIRE(transaction->last_consumed_bearer_availability_epoch == 2u);

    REQUIRE(ninlil_test_bearer_raw_state_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_OK,
        &available_state,
        1u));
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction->retry_cycle_id == 2u);

    platform_teardown(&env);
    return 0;
}

static int test_event_resume_wrong_role(void)
{
    delivery_env_t env;
    ninlil_id128_t txn_id;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    static const uint8_t metadata[] = {0x01u};

    (void)memset(&env, 0, sizeof(env));
    set_id(&txn_id, 0x99u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    set_id(&request.operation_id, 0xa9u);
    set_id(&request.actor_id, 0xaau);
    request.expected_spool_revision = 1u;
    request.resume_reason = NINLIL_RESUME_TEST;
    request.audit_metadata.data = metadata;
    request.audit_metadata.length = sizeof(metadata);
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(env.runtime, &txn_id, &request, &result)
        == NINLIL_E_UNSUPPORTED);
    platform_teardown(&env);
    return 0;
}

static int test_event_discard_invalid_ack(void)
{
    delivery_env_t env;
    ninlil_id128_t txn_id;
    ninlil_event_discard_request_t request;
    ninlil_event_discard_result_t result;
    static const uint8_t metadata[] = {0x02u};

    (void)memset(&env, 0, sizeof(env));
    set_id(&txn_id, 0x98u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_ENDPOINT));
    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    set_id(&request.operation_id, 0xabu);
    set_id(&request.actor_id, 0xacu);
    set_id(&request.expected_event_id, 0xadu);
    set_digest(&request.expected_content_digest, 0xaeu);
    request.expected_spool_revision = 1u;
    request.discard_reason = NINLIL_DISCARD_TEST_CLEANUP;
    request.acknowledge_required_receipt_absent = 0u;
    request.audit_metadata.data = metadata;
    request.audit_metadata.length = sizeof(metadata);
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(env.runtime, &txn_id, &request, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

static int test_bearer_state_once_budget_and_restart(void)
{
    delivery_env_t env;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    uint64_t state_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    state_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_STATE);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_STATE)
        == state_calls + 1u);
    REQUIRE(step_result.state_transitions == 0u);
    REQUIRE(step_result.more_work == 1u);

    budget.max_state_transitions = 1u;
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    state_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_STATE);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_STATE)
        == state_calls + 1u);
    REQUIRE(step_result.state_transitions == 1u);

    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    state_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_STATE);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_STATE)
        == state_calls + 1u);
    REQUIRE(step_result.state_transitions == 0u);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(step_result.state_transitions == 0u);

    platform_teardown(&env);
    return 0;
}

static int public_attempt_state_is(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_state_t expected_state)
{
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target;
    ninlil_query_t query;
    ninlil_transaction_page_t page;
    ninlil_transaction_summary_t item;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    snapshot.targets = &target;
    snapshot.target_capacity = 1u;
    REQUIRE(ninlil_transaction_query(runtime, transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state == expected_state);
    REQUIRE(snapshot.reason == NINLIL_REASON_NONE);
    REQUIRE(snapshot.target_count == 1u);
    REQUIRE(target.state == expected_state);
    REQUIRE(target.reason == NINLIL_REASON_NONE);
    REQUIRE(target.cumulative_attempts == 1u);

    (void)memset(&query, 0, sizeof(query));
    set_header(&query.abi_version, &query.struct_size, sizeof(query));
    query.include_nonterminal = 1u;
    query.family_mask = NINLIL_FAMILY_MASK_DESIRED_STATE;
    (void)memset(&page, 0, sizeof(page));
    set_header(&page.abi_version, &page.struct_size, sizeof(page));
    (void)memset(&item, 0, sizeof(item));
    set_header(&item.abi_version, &item.struct_size, sizeof(item));
    page.items = &item;
    page.item_capacity = 1u;
    REQUIRE(ninlil_transaction_list(runtime, &query, &page) == NINLIL_OK);
    REQUIRE(page.item_count == 1u);
    REQUIRE(memcmp(
                item.transaction_id.bytes,
                transaction_id->bytes,
                sizeof(item.transaction_id.bytes))
        == 0);
    REQUIRE(item.state == expected_state);
    REQUIRE(item.reason == NINLIL_REASON_NONE);
    return 0;
}

static int run_possible_send_closure_case(
    ninlil_bearer_status_t scripted_status,
    const ninlil_bearer_send_result_t *scripted_result,
    ninlil_status_t expected_first_step_status,
    int verify_inv005_identity_retry)
{
    delivery_env_t env;
    ninlil_runtime_t *endpoint_runtime = NULL;
    ninlil_service_t *endpoint_service = NULL;
    ninlil_runtime_config_t endpoint_config;
    ninlil_service_descriptor_t controller_descriptor;
    ninlil_service_descriptor_t endpoint_descriptor;
    ninlil_service_callbacks_t controller_callbacks;
    ninlil_service_callbacks_t endpoint_callbacks;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_status_t step_status;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t original_transaction_id;
    ninlil_id128_t first_attempt_id;
    uint64_t send_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    endpoint_config = config_endpoint(4u);
    endpoint_config.storage_namespace.data = TEST_ENDPOINT_NAMESPACE;
    endpoint_config.storage_namespace.length =
        sizeof(TEST_ENDPOINT_NAMESPACE) - 1u;
    REQUIRE(ninlil_runtime_create(
                &endpoint_config, &env.platform, &endpoint_runtime)
        == NINLIL_OK);

    controller_descriptor = desired_descriptor(0x70u);
    endpoint_descriptor = desired_descriptor(0x81u);
    (void)memset(
        &controller_callbacks, 0, sizeof(controller_callbacks));
    set_header(
        &controller_callbacks.abi_version,
        &controller_callbacks.struct_size,
        sizeof(controller_callbacks));
    (void)memset(&endpoint_callbacks, 0, sizeof(endpoint_callbacks));
    set_header(
        &endpoint_callbacks.abi_version,
        &endpoint_callbacks.struct_size,
        sizeof(endpoint_callbacks));
    endpoint_callbacks.on_delivery = delivery_complete_cb;
    endpoint_callbacks.on_reconcile = reconcile_noop_cb;
    REQUIRE(env_register(
        &env, &controller_descriptor, &controller_callbacks));
    REQUIRE(ninlil_service_register(
                endpoint_runtime,
                &endpoint_descriptor,
                &endpoint_callbacks,
                &endpoint_service)
        == NINLIL_OK);

    fill_desired_submission(&env, &submission, 0x66u);
    set_id(&env.target.target_runtime_id, 0x11u);
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    fill_step_budget(&budget);
    send_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    budget.max_bearer_sends = 0u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls);
    REQUIRE(step_result.state_transitions >= 1u);
    REQUIRE(step_result.more_work == 1u);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_prepared == 1u);
    REQUIRE(public_attempt_state_is(
        env.runtime,
        &submit_result.transaction_id,
        NINLIL_TXN_DISPATCHING) == 0);
    original_transaction_id = transaction->transaction_id;
    first_attempt_id = transaction->attempt_id;
    if (verify_inv005_identity_retry != 0) {
        /* TRACE-INV005-TXID-STABLE */
        REQUIRE(memcmp(
                    &original_transaction_id,
                    &submit_result.transaction_id,
                    sizeof(original_transaction_id))
            == 0);
        REQUIRE(transaction->attempt_prepared == 1u);
        REQUIRE(transaction->attempt_count == 1u);
        REQUIRE(memcmp(
                    &first_attempt_id,
                    &(ninlil_id128_t){{0}},
                    sizeof(first_attempt_id))
            != 0);
    }
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(
        env.bearer_fixture,
        scripted_status,
        scripted_result,
        1u));

    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    step_status = ninlil_runtime_step(env.runtime, &budget, &step_result);
    REQUIRE(step_status == expected_first_step_status);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls + 1u);
    REQUIRE(public_attempt_state_is(
        env.runtime,
        &submit_result.transaction_id,
        NINLIL_TXN_AWAITING_EVIDENCE) == 0);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(memcmp(
                &transaction->transaction_id,
                &original_transaction_id,
                sizeof(original_transaction_id))
        == 0);

    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    (void)ninlil_runtime_step(env.runtime, &budget, &step_result);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls + 1u);
    if (verify_inv005_identity_retry != 0) {
        /*
         * TRACE-INV005-LOGICAL-RETRY-FRESH-ATTEMPT
         * A closed LOST_UNKNOWN observation schedules a logical retry.  The
         * transaction identity is stable, while the next durable attempt ID
         * is fresh and the first ID remains in durable attempt history.
         */
        REQUIRE(ninlil_test_clock_advance(env.clock, 1200u));
        REQUIRE(ninlil_test_bearer_raw_send_enqueue(
            env.bearer_fixture,
            scripted_status,
            scripted_result,
            1u));
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &submit_result.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->attempt_count == 2u);
        REQUIRE(memcmp(
                    &transaction->attempt_ids[0],
                    &first_attempt_id,
                    sizeof(first_attempt_id))
            == 0);
        REQUIRE(memcmp(
                    &transaction->attempt_ids[1],
                    &first_attempt_id,
                    sizeof(first_attempt_id))
            != 0);
        REQUIRE(memcmp(
                    &transaction->transaction_id,
                    &original_transaction_id,
                    sizeof(original_transaction_id))
            == 0);
    }

    REQUIRE(ninlil_runtime_destroy(endpoint_runtime) == NINLIL_OK);
    endpoint_runtime = NULL;
    endpoint_service = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_lost_unknown_and_invalid_send_close_retransmit(void)
{
    ninlil_bearer_send_result_t send_result;

    (void)memset(&send_result, 0, sizeof(send_result));
    set_header(
        &send_result.abi_version,
        &send_result.struct_size,
        sizeof(send_result));
    /* Binding the second endpoint advances both direction epochs once. */
    send_result.availability_epoch = 2u;
    REQUIRE(run_possible_send_closure_case(
        NINLIL_BEARER_LOST_UNKNOWN,
        &send_result,
        NINLIL_OK,
        1) == 0);

    send_result.kind = (ninlil_bearer_send_kind_t)99u;
    REQUIRE(run_possible_send_closure_case(
        NINLIL_BEARER_OK,
        &send_result,
        NINLIL_E_DEGRADED,
        0) == 0);

    /*
     * Closed status set is OK..CORRUPT (0..6). Values above CORRUPT must
     * contract-fault (DEGRADED), not be accepted as open-ended upper range.
     * Exercises bearer_status_is_known without unsigned >=0 type-limits.
     */
    (void)memset(&send_result, 0, sizeof(send_result));
    set_header(
        &send_result.abi_version,
        &send_result.struct_size,
        sizeof(send_result));
    send_result.availability_epoch = 2u;
    REQUIRE(run_possible_send_closure_case(
        (ninlil_bearer_status_t)(NINLIL_BEARER_CORRUPT + 1u),
        &send_result,
        NINLIL_E_DEGRADED,
        0) == 0);
    REQUIRE(run_possible_send_closure_case(
        (ninlil_bearer_status_t)99u,
        &send_result,
        NINLIL_E_DEGRADED,
        0) == 0);
    REQUIRE(run_possible_send_closure_case(
        (ninlil_bearer_status_t)0xffffffffu,
        &send_result,
        NINLIL_E_DEGRADED,
        0) == 0);
    return 0;
}

static int run_attempt_prepare_commit_unknown_case(int committed_truth)
{
    delivery_env_t env;
    ninlil_runtime_t *endpoint_runtime = NULL;
    ninlil_runtime_config_t endpoint_config;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_metrics_snapshot_t metrics;
    ninlil_cancel_result_t cancel_result;
    ninlil_submission_result_t fenced_submit_result;
    ninlil_submission_result_t offer_result;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_delivery_token_t delivery_token;
    ninlil_application_result_t application_result;
    ninlil_service_t *fenced_service = NULL;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_v1_durable_recovery_publication_result_t publication;
    uint64_t storage_calls[NINLIL_TEST_STORAGE_OP_COUNT];
    uint64_t bearer_calls[NINLIL_TEST_BEARER_OP_COUNT];
    uint64_t clock_calls;
    uint64_t entropy_calls;
    uint32_t delivery_calls;
    uint32_t operation;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    endpoint_config = config_endpoint(4u);
    endpoint_config.storage_namespace.data = TEST_ENDPOINT_NAMESPACE;
    endpoint_config.storage_namespace.length =
        sizeof(TEST_ENDPOINT_NAMESPACE) - 1u;
    REQUIRE(ninlil_runtime_create(
                &endpoint_config, &env.platform, &endpoint_runtime)
        == NINLIL_OK);

    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);

    descriptor = desired_descriptor(0x70u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));
    fill_desired_submission(&env, &submission, 0x68u);
    set_id(&env.target.target_runtime_id, 0x11u);
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result)
        == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        committed_truth));

    fill_step_budget(&budget);
    budget.max_bearer_sends = 0u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(step_result.state_transitions == 0u);
    REQUIRE(step_result.bearer_sends == 0u);
    REQUIRE(step_result.transactions_terminalized == 0u);
    REQUIRE(step_result.events_parked == 0u);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_prepared == 0u);
    REQUIRE(transaction->attempt_count == 0u);

    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.storage_failures == 1u);
    REQUIRE(metrics.transactions_satisfied == 0u);
    REQUIRE(metrics.transactions_expired == 0u);
    REQUIRE(metrics.transactions_failed_definitive == 0u);
    REQUIRE(metrics.transactions_outcome_unknown == 0u);

    /*
     * COMMIT_UNKNOWN is a live-instance mutation fence, not a one-call error.
     * Every mutation entry must fail before touching Storage, Bearer, Clock,
     * Entropy, callbacks, attempt state, metrics, or work budgets.
     */
    for (operation = 0u;
         operation < (uint32_t)NINLIL_TEST_STORAGE_OP_COUNT;
         ++operation) {
        storage_calls[operation] = ninlil_test_storage_call_count(
            env.storage_fixture,
            (ninlil_test_storage_operation_t)operation);
    }
    for (operation = 0u;
         operation < (uint32_t)NINLIL_TEST_BEARER_OP_COUNT;
         ++operation) {
        bearer_calls[operation] = ninlil_test_bearer_call_count(
            env.bearer_fixture,
            (ninlil_test_bearer_operation_t)operation);
    }
    clock_calls = ninlil_test_clock_call_count(env.clock);
    entropy_calls = ninlil_test_entropy_call_count(env.entropy);
    delivery_calls = g_delivery_calls;

    (void)memset(&step_result, 0xa5, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(step_result.ingress_processed == 0u);
    REQUIRE(step_result.callbacks_invoked == 0u);
    REQUIRE(step_result.state_transitions == 0u);
    REQUIRE(step_result.bearer_sends == 0u);
    REQUIRE(step_result.transactions_terminalized == 0u);
    REQUIRE(step_result.events_parked == 0u);

    (void)memset(&fenced_submit_result, 0, sizeof(fenced_submit_result));
    set_header(
        &fenced_submit_result.abi_version,
        &fenced_submit_result.struct_size,
        sizeof(fenced_submit_result));
    REQUIRE(ninlil_submit(
                env.service, &submission, &fenced_submit_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);

    (void)memset(&cancel_result, 0, sizeof(cancel_result));
    set_header(
        &cancel_result.abi_version,
        &cancel_result.struct_size,
        sizeof(cancel_result));
    REQUIRE(ninlil_cancel_request(
                env.runtime,
                &submit_result.transaction_id,
                &cancel_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);

    (void)memset(&offer_result, 0, sizeof(offer_result));
    set_header(
        &offer_result.abi_version,
        &offer_result.struct_size,
        sizeof(offer_result));
    REQUIRE(ninlil_offer_accept(
                env.runtime, &submit_result.transaction_id, &offer_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);

    (void)memset(&resume_request, 0, sizeof(resume_request));
    set_header(
        &resume_request.abi_version,
        &resume_request.struct_size,
        sizeof(resume_request));
    set_id(&resume_request.operation_id, 0xc1u);
    (void)memset(&resume_result, 0, sizeof(resume_result));
    set_header(
        &resume_result.abi_version,
        &resume_result.struct_size,
        sizeof(resume_result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &submit_result.transaction_id,
                &resume_request,
                &resume_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);

    (void)memset(&discard_request, 0, sizeof(discard_request));
    set_header(
        &discard_request.abi_version,
        &discard_request.struct_size,
        sizeof(discard_request));
    set_id(&discard_request.operation_id, 0xc2u);
    (void)memset(&discard_result, 0, sizeof(discard_result));
    set_header(
        &discard_result.abi_version,
        &discard_result.struct_size,
        sizeof(discard_result));
    REQUIRE(ninlil_event_discard(
                env.runtime,
                &submit_result.transaction_id,
                &discard_request,
                &discard_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);

    (void)memset(&delivery_token, 0, sizeof(delivery_token));
    set_header(
        &delivery_token.abi_version,
        &delivery_token.struct_size,
        sizeof(delivery_token));
    set_id(&delivery_token.context_id, 0xc3u);
    delivery_token.generation = 1u;
    set_id(&delivery_token.clock_epoch_id, 0xc4u);
    delivery_token.expires_at_ms = 1u;
    (void)memset(&application_result, 0, sizeof(application_result));
    set_header(
        &application_result.abi_version,
        &application_result.struct_size,
        sizeof(application_result));
    REQUIRE(ninlil_delivery_complete(
                env.runtime, &delivery_token, &application_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);

    REQUIRE(ninlil_service_register(
                env.runtime,
                &descriptor,
                &callbacks,
                &fenced_service)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(fenced_service == NULL);

    for (operation = 0u;
         operation < (uint32_t)NINLIL_TEST_STORAGE_OP_COUNT;
         ++operation) {
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture,
                    (ninlil_test_storage_operation_t)operation)
            == storage_calls[operation]);
    }
    for (operation = 0u;
         operation < (uint32_t)NINLIL_TEST_BEARER_OP_COUNT;
         ++operation) {
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture,
                    (ninlil_test_bearer_operation_t)operation)
            == bearer_calls[operation]);
    }
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy) == entropy_calls);
    REQUIRE(g_delivery_calls == delivery_calls);
    REQUIRE(transaction->attempt_prepared == 0u);
    REQUIRE(transaction->attempt_count == 0u);
    REQUIRE(transaction->retry_budget
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);

    if (committed_truth != 0) {
        (void)memset(&publication, 0, sizeof(publication));
        REQUIRE(ninlil_v1_durable_recovery_publication_gate_storage(
                    env.platform.storage,
                    env.runtime->storage,
                    0u,
                    &publication)
            == NINLIL_OK);
    }

    REQUIRE(ninlil_runtime_destroy(endpoint_runtime) == NINLIL_OK);
    endpoint_runtime = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    env.config = config_controller(4u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(memcmp(
                &transaction->transaction_id,
                &submit_result.transaction_id,
                sizeof(transaction->transaction_id))
        == 0);
    REQUIRE(transaction->attempt_prepared
        == (committed_truth != 0 ? 1u : 0u));
    REQUIRE(transaction->attempt_count
        == (committed_truth != 0 ? 1u : 0u));
    REQUIRE(transaction->retry_budget
        == (committed_truth != 0
                ? NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - 1u
                : NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE));
    if (committed_truth != 0) {
        /*
         * TRACE-INV005-CRASH-REPLAY-SAME-ATTEMPT
         * Recovery publishes the exact committed attempt without consuming
         * entropy for a replacement ID.  The durable attempt-history entry
         * and active attempt are byte-identical.
         */
        REQUIRE(memcmp(
                    &transaction->attempt_id,
                    &transaction->attempt_ids[0],
                    sizeof(transaction->attempt_id))
            == 0);
        REQUIRE(memcmp(
                    &transaction->attempt_id,
                    &(ninlil_id128_t){{0}},
                    sizeof(transaction->attempt_id))
            != 0);
        REQUIRE(public_attempt_state_is(
            env.runtime,
            &submit_result.transaction_id,
            NINLIL_TXN_DISPATCHING) == 0);
    }

    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.storage_failures == 0u);
    REQUIRE(metrics.transactions_satisfied == 0u);
    REQUIRE(metrics.transactions_expired == 0u);
    REQUIRE(metrics.transactions_failed_definitive == 0u);
    REQUIRE(metrics.transactions_outcome_unknown == 0u);

    platform_teardown(&env);
    return 0;
}

static int test_attempt_prepare_commit_unknown_hidden_truth(void)
{
    REQUIRE(run_attempt_prepare_commit_unknown_case(0) == 0);
    REQUIRE(run_attempt_prepare_commit_unknown_case(1) == 0);
    return 0;
}

static int setup_origin_event_for_ordered_input(
    delivery_env_t *env,
    ninlil_submission_result_t *out_submit_result)
{
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_t submission;

    if (!platform_init(env)
        || !env_create(env, NINLIL_ROLE_ENDPOINT)) {
        return 0;
    }
    descriptor = event_fact_descriptor(0x78u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    if (!env_register(env, &descriptor, &callbacks)) {
        return 0;
    }
    fill_event_submission(
        env,
        &submission,
        0x79u,
        0x7au,
        TEST_IDEM_EVENT_A,
        sizeof(TEST_IDEM_EVENT_A) - 1u);
    (void)memset(out_submit_result, 0, sizeof(*out_submit_result));
    set_header(
        &out_submit_result->abi_version,
        &out_submit_result->struct_size,
        sizeof(*out_submit_result));
    return ninlil_submit(env->service, &submission, out_submit_result)
            == NINLIL_OK
        && out_submit_result->kind == NINLIL_SUBMISSION_ADMITTED_READY;
}

static int run_ordered_input_commit_unknown_case(int committed_truth)
{
    delivery_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    uint64_t original_revision;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(setup_origin_event_for_ordered_input(&env, &submit_result));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->ordered_input_sequence == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 0u);
    original_revision = transaction->record_revision;
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->ordered_input_sequence = 1u;
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        committed_truth));
    REQUIRE(ninlil_rt_v1_commit_ordered_input_snapshot(
                env.runtime,
                transaction,
                candidate,
                0x4453u,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(transaction->record_revision == original_revision);
    REQUIRE(transaction->ordered_input_sequence == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 0u);

    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(env_create(&env, NINLIL_ROLE_ENDPOINT));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->record_revision
        == original_revision + (committed_truth != 0 ? 1u : 0u));
    REQUIRE(transaction->ordered_input_sequence
        == (committed_truth != 0 ? 1u : 0u));
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == (committed_truth != 0 ? 1u : 0u));
    platform_teardown(&env);
    return 0;
}

static int test_ordered_input_commit_unknown_hidden_truth(void)
{
    REQUIRE(run_ordered_input_commit_unknown_case(0) == 0);
    REQUIRE(run_ordered_input_commit_unknown_case(1) == 0);
    return 0;
}

static int test_ordered_input_counter_exhaustion_is_durable(void)
{
    delivery_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    uint64_t put_calls;
    uint64_t commit_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(setup_origin_event_for_ordered_input(&env, &submit_result));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    env.runtime->last_assigned_ordered_input_sequence = UINT64_MAX - 1u;
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->ordered_input_sequence = UINT64_MAX;
    REQUIRE(ninlil_rt_v1_commit_ordered_input_snapshot(
                env.runtime,
                transaction,
                candidate,
                0x4453u,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_OK);
    REQUIRE(transaction->ordered_input_sequence == UINT64_MAX);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == UINT64_MAX);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason
        == NINLIL_REASON_COUNTER_EXHAUSTED);

    put_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    REQUIRE(ninlil_rt_v1_commit_ordered_input_snapshot(
                env.runtime,
                transaction,
                candidate,
                0x4453u,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_E_DEGRADED);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    REQUIRE(env_create(&env, NINLIL_ROLE_ENDPOINT));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submit_result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->ordered_input_sequence == UINT64_MAX);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == UINT64_MAX);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason
        == NINLIL_REASON_COUNTER_EXHAUSTED);
    platform_teardown(&env);
    return 0;
}

static int test_scheduler_collects_work_beyond_legacy_64_boundary(void)
{
    static ninlil_runtime_t runtime;
    static ninlil_rt_transaction_slot_t transactions[65];
    ninlil_time_sample_t clock_sample;
    uint32_t order[65];
    uint32_t seen[65];
    uint32_t count;
    uint32_t index;

    (void)memset(&runtime, 0, sizeof(runtime));
    (void)memset(transactions, 0, sizeof(transactions));
    (void)memset(&clock_sample, 0, sizeof(clock_sample));
    (void)memset(order, 0, sizeof(order));
    (void)memset(seen, 0, sizeof(seen));
    runtime.transactions = transactions;
    runtime.transaction_capacity =
        (uint32_t)(sizeof(transactions) / sizeof(transactions[0]));
    for (index = 0u; index < runtime.transaction_capacity; ++index) {
        transactions[index].in_use = 1u;
        transactions[index].pending_dispatch = 1u;
        transactions[index].semantic_priority = 1u;
        transactions[index].transaction_sequence = (uint64_t)index + 1u;
    }
    /* The 65th row must participate in ordering, not merely be counted. */
    transactions[64].semantic_priority = 8u;

    count = ninlil_rt_v1_delivery_collect_work_order(
        &runtime,
        &clock_sample,
        order,
        (uint32_t)(sizeof(order) / sizeof(order[0])));
    REQUIRE(count == 65u);
    REQUIRE(order[0] == 64u);
    for (index = 0u; index < count; ++index) {
        REQUIRE(order[index] < count);
        REQUIRE(seen[order[index]] == 0u);
        seen[order[index]] = 1u;
    }
    for (index = 0u; index < count; ++index) {
        REQUIRE(seen[index] == 1u);
    }
    return 0;
}

int main(void)
{
    int rc = 0;

    if (test_desired_state_unavailable_never_satisfies() != 0) {
        rc = 1;
    }
    if (test_transaction_capacity_retains_terminal_rows_at_boundary() != 0) {
        rc = 1;
    }
    if (test_service_inflight_quota_reconstructed_after_restart() != 0) {
        rc = 1;
    }
    if (test_terminal_quota_decrement_matches_exact_service() != 0) {
        rc = 1;
    }
    if (test_origin_terminal_quota_before_reattach_after_restart() != 0) {
        rc = 1;
    }
    if (test_origin_terminal_zero_inflight_is_corrupt() != 0) {
        rc = 1;
    }
    if (test_origin_terminal_missing_service_row_is_corrupt() != 0) {
        rc = 1;
    }
    if (test_origin_terminal_duplicate_service_row_is_corrupt() != 0) {
        rc = 1;
    }
    if (test_origin_terminal_commit_unknown_no_ram_quota_publish() != 0) {
        rc = 1;
    }
    if (test_callback_failure_no_false_success() != 0) {
        rc = 1;
    }
    if (test_deferred_delivery_complete_and_restart_fence() != 0) {
        rc = 1;
    }
    if (test_sync_completion_expiring_inside_callback_never_commits_success()
        != 0) {
        rc = 1;
    }
    if (test_all_callback_paths_fresh_clock_and_restart_fences() != 0) {
        rc = 1;
    }
    if (test_all_callback_paths_safe_completion_deep_copy() != 0) {
        rc = 1;
    }
    if (test_delivery_complete_validation_order_and_clock_fences() != 0) {
        rc = 1;
    }
    if (test_callback_capacity_is_acquired_before_callback() != 0) {
        rc = 1;
    }
    if (test_callback_start_fault_matrix_has_no_false_callback() != 0) {
        rc = 1;
    }
    if (test_clock_sample_shapes_fail_closed_before_active_token() != 0) {
        rc = 1;
    }
    if (test_create_recovers_active_token_before_bearer_open_failure()
        != 0) {
        rc = 1;
    }
    if (test_second_inbound_admission_is_rejected_before_durable_commit()
        != 0) {
        rc = 1;
    }
    if (test_restart_rejects_noncanonical_nts3_token_tuple() != 0) {
        rc = 1;
    }
    if (test_destroy_without_active_tokens_has_no_storage_mutation() != 0) {
        rc = 1;
    }
    if (test_destroy_order_uses_generation_as_secondary_key() != 0) {
        rc = 1;
    }
    if (test_destroy_recovery_group_is_atomic_and_ordered() != 0) {
        rc = 1;
    }
    if (test_destroy_recovery_group_fault_matrix() != 0) {
        rc = 1;
    }
    if (test_event_resume_wrong_role() != 0) {
        rc = 1;
    }
    if (test_event_discard_invalid_ack() != 0) {
        rc = 1;
    }
    if (test_endpoint_event_availability_resume_once_and_restart() != 0) {
        rc = 1;
    }
    if (test_bearer_state_once_budget_and_restart() != 0) {
        rc = 1;
    }
    if (test_lost_unknown_and_invalid_send_close_retransmit() != 0) {
        rc = 1;
    }
    if (test_attempt_prepare_commit_unknown_hidden_truth() != 0) {
        rc = 1;
    }
    if (test_ordered_input_commit_unknown_hidden_truth() != 0) {
        rc = 1;
    }
    if (test_ordered_input_counter_exhaustion_is_durable() != 0) {
        rc = 1;
    }
    if (test_legacy_transaction_restart_rejects_fail_closed() != 0) {
        rc = 1;
    }
    if (test_scheduler_collects_work_beyond_legacy_64_boundary() != 0) {
        rc = 1;
    }

    if (rc != 0) {
        (void)fprintf(stderr, "v1_runtime_delivery_test failed\n");
    }
    return rc;
}
