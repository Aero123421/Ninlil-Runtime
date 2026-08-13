/* SPDX-License-Identifier: Apache-2.0 */
/*
 * V1-LAB unit 2a: public Runtime lifecycle spine (B1-a/b/c admission slice).
 * Covers runtime_create/destroy, service_register, submit admission, cancel
 * admission, runtime_step bounded work budget. Delivery/durable deep path is 2b.
 */

#include "deterministic_entropy.h"
#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_d3s1.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_internal.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_spine_durable.h"
#include "typed_simulated_bearer.h"
#include "v1_durable_allowlist.h"

#include <ninlil/runtime.h>
#include <stdio.h>
#include <string.h>

#define RETRY_STATE_PREFIX ((uint16_t)0x5254u)
#define DELIVERY_STARTED_PREFIX ((uint16_t)0x4453u)

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "v1-runtime-spine-test";
static const char NS_TEXT[] = "org.ninlil.examples";
static const char SVC_TEXT[] = "absolute-state";
static const char SCHEMA_TEXT[] = "absolute-state";

typedef struct spine_env {
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
} spine_env_t;

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static int set_payload_content_digest(
    ninlil_digest256_t *digest,
    const uint8_t *payload,
    uint32_t length)
{
    ninlil_model_domain_digest_t actual;

    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    if (ninlil_model_domain_sha256(payload, length, &actual) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(digest->bytes, actual.bytes, sizeof(digest->bytes));
    return 1;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static ninlil_origin_auth_status_t origin_stub(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)request;
    (void)decision;
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static ninlil_runtime_config_t config_fixture_role(
    ninlil_role_t role,
    uint32_t max_services)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
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
    if (role == NINLIL_ROLE_ENDPOINT) {
        config.limits.max_services = max_services > 8u ? 8u : max_services;
        config.limits.max_nonterminal_transactions = 32u;
        config.limits.max_durable_outbox_payload_bytes = 0u;
        config.limits.max_nonterminal_deliveries = 32u;
        config.limits.max_event_spool_count = 32u;
        config.limits.max_event_spool_bytes = 32768u;
    }
    return config;
}

static ninlil_runtime_config_t config_fixture(uint32_t max_services)
{
    return config_fixture_role(NINLIL_ROLE_CONTROLLER, max_services);
}

static int platform_init(spine_env_t *env)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_bearer_config_t bearer_config;

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 2u;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = 1048576u;

    env->allocator = ninlil_test_allocator_create();
    env->execution = ninlil_test_execution_create(1u);
    env->clock = ninlil_test_clock_create();
    env->entropy = ninlil_test_entropy_create(0x2a2a2a2au, 1u);
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
    env->origin.evaluate = origin_stub;

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

static void platform_teardown(spine_env_t *env)
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
    descriptor.service_id.data = (const uint8_t *)SVC_TEXT;
    descriptor.service_id.length = sizeof(SVC_TEXT) - 1u;
    descriptor.schema_id.data = (const uint8_t *)SCHEMA_TEXT;
    descriptor.schema_id.length = sizeof(SCHEMA_TEXT) - 1u;
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

static int env_create_runtime(spine_env_t *env, uint32_t max_services)
{
    ninlil_status_t status;

    env->config = config_fixture(max_services);
    status = ninlil_runtime_create(
        &env->config, &env->platform, &env->runtime);
    if (status != NINLIL_OK) {
        return 0;
    }
    REQUIRE(env->runtime != NULL);
    return 1;
}

static ninlil_service_descriptor_t desired_descriptor_with_service(
    uint8_t app_tag,
    const char *service_id)
{
    ninlil_service_descriptor_t descriptor = desired_descriptor(app_tag);

    descriptor.service_id.data = (const uint8_t *)service_id;
    descriptor.service_id.length = strlen(service_id);
    return descriptor;
}

static int env_register_service(spine_env_t *env, uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor = desired_descriptor(app_tag);
    ninlil_service_callbacks_t callbacks;
    ninlil_status_t status;

    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    status = ninlil_service_register(
        env->runtime, &descriptor, &callbacks, &env->service);
    if (status != NINLIL_OK) {
        return 0;
    }
    REQUIRE(env->service != NULL);
    return 1;
}

static int service_capacity_equals(
    ninlil_runtime_t *runtime,
    uint64_t expected_used,
    uint64_t expected_reserved,
    uint64_t expected_high_water)
{
    ninlil_capacity_entry_t entries[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    ninlil_capacity_snapshot_t snapshot;
    uint32_t index;

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
        || entries[0].kind != NINLIL_RESOURCE_SERVICE
        || entries[0].used != expected_used
        || entries[0].reserved != expected_reserved
        || entries[0].high_water != expected_high_water) {
        return 0;
    }
    return 1;
}

static int env_make_submission(spine_env_t *env, ninlil_submission_t *submission)
{
    static const uint8_t idem_key[] = "key";

    (void)memset(submission, 0, sizeof(*submission));
    set_header(
        &submission->abi_version, &submission->struct_size, sizeof(*submission));
    submission->schema_major = 1u;
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
    env->payload[0] = 0xABu;
    if (!set_payload_content_digest(
            &submission->content_digest, env->payload, sizeof(env->payload))) {
        return 0;
    }
    return 1;
}

static void env_initialize_target(spine_env_t *env)
{
    (void)memset(&env->target, 0, sizeof(env->target));
    set_header(
        &env->target.abi_version,
        &env->target.struct_size,
        sizeof(env->target));
    set_id(&env->target.target_runtime_id, 0x80u);
    set_id(&env->target.target_application_instance_id, 0x81u);
    set_id(&env->target.device_id, 0x82u);
    set_id(&env->target.site_domain_id, 0x83u);
    env->target.binding_epoch = 1u;
    env->target.membership_epoch = 1u;
    env->target.flags =
        NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;
}

static int test_create_destroy_happy(void)
{
    spine_env_t env;
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_create_null_invalid(void)
{
    spine_env_t env;
    ninlil_runtime_t *runtime = (ninlil_runtime_t *)0x1u;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_fixture(4u);
    REQUIRE(ninlil_runtime_create(NULL, &env.platform, &runtime)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(runtime == NULL);
    REQUIRE(ninlil_runtime_create(&env.config, NULL, &runtime)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(runtime == NULL);
    REQUIRE(ninlil_runtime_create(&env.config, &env.platform, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

static int test_destroy_null_invalid(void)
{
    REQUIRE(ninlil_runtime_destroy(NULL) == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_register_submit_cancel_step_happy(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_cancel_result_t cancel_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x70u));

    set_header(&env.target.abi_version, &env.target.struct_size, sizeof(env.target));
    set_id(&env.target.target_runtime_id, 0x80u);
    set_id(&env.target.target_application_instance_id, 0x81u);
    set_id(&env.target.device_id, 0x82u);
    set_id(&env.target.site_domain_id, 0x83u);
    env.target.binding_epoch = 1u;
    env.target.membership_epoch = 1u;
    env.target.flags =
        NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;

    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    set_header(
        &submit_result.abi_version,
        &submit_result.struct_size,
        sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result) == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(submit_result.reason == NINLIL_REASON_NONE);

    (void)memset(&cancel_result, 0, sizeof(cancel_result));
    set_header(
        &cancel_result.abi_version,
        &cancel_result.struct_size,
        sizeof(cancel_result));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    REQUIRE(ninlil_test_clock_script(
                env.clock, NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u)
        == 1);
    REQUIRE(ninlil_cancel_request(
                env.runtime, &submit_result.transaction_id, &cancel_result)
        == NINLIL_E_CLOCK_UNCERTAIN);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(cancel_result.kind == 0u);
    REQUIRE(cancel_result.reason == 0u);
    REQUIRE(cancel_result.current_outcome == 0u);

    (void)memset(&cancel_result, 0, sizeof(cancel_result));
    set_header(
        &cancel_result.abi_version,
        &cancel_result.struct_size,
        sizeof(cancel_result));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    REQUIRE(ninlil_cancel_request(
                env.runtime, &submit_result.transaction_id, &cancel_result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(cancel_result.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&cancel_result, 0, sizeof(cancel_result));
    set_header(
        &cancel_result.abi_version,
        &cancel_result.struct_size,
        sizeof(cancel_result));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    REQUIRE(ninlil_cancel_request(
                env.runtime, &submit_result.transaction_id, &cancel_result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    REQUIRE(cancel_result.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);
    REQUIRE(
        cancel_result.current_outcome
        == NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 1u;
    budget.max_callbacks = 1u;
    budget.max_state_transitions = 1u;
    budget.max_bearer_sends = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(step_result.health == NINLIL_HEALTH_OK);

    platform_teardown(&env);
    return 0;
}

static int test_register_exact_reattach(void)
{
    spine_env_t env;
    ninlil_service_t *second = NULL;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x71u));
    descriptor = desired_descriptor(0x71u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &second)
        == NINLIL_OK);
    REQUIRE(second == env.service);
    platform_teardown(&env);
    return 0;
}

static int test_register_null_invalid(void)
{
    spine_env_t env;
    ninlil_service_descriptor_t descriptor = desired_descriptor(0x72u);
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service = NULL;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(NULL, &descriptor, &callbacks, &service)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_service_register(env.runtime, NULL, &callbacks, &service)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_service_register(env.runtime, &descriptor, NULL, &service)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_service_register(env.runtime, &descriptor, &callbacks, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

static int test_register_capacity_exhausted(void)
{
    spine_env_t env;
    static const char *const service_ids[5] = {
        "capacity-a", "capacity-b", "capacity-c", "capacity-d", "capacity-e"
    };
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *handles[4];
    ninlil_service_t *fifth = (ninlil_service_t *)0x1u;
    uint64_t puts_before;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));

    for (index = 0u; index < 4u; ++index) {
        ninlil_service_descriptor_t descriptor =
            desired_descriptor_with_service(
                (uint8_t)(0x73u + index), service_ids[index]);
        handles[index] = NULL;
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &handles[index])
            == NINLIL_OK);
        REQUIRE(handles[index] != NULL);
        REQUIRE(service_capacity_equals(
            env.runtime, index + 1u, 0u, index + 1u));

        /* Exact same-lifetime registration is attach-idempotent. */
        {
            ninlil_service_t *again = NULL;
            REQUIRE(ninlil_service_register(
                        env.runtime, &descriptor, &callbacks, &again)
                == NINLIL_OK);
            REQUIRE(again == handles[index]);
            REQUIRE(service_capacity_equals(
                env.runtime, index + 1u, 0u, index + 1u));
        }
    }
    puts_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    {
        ninlil_service_descriptor_t descriptor =
            desired_descriptor_with_service(0x77u, service_ids[4]);
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &fifth)
            == NINLIL_E_CAPACITY_EXHAUSTED);
    }
    REQUIRE(fifth == NULL);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == puts_before + 1u);
    REQUIRE(service_capacity_equals(env.runtime, 4u, 0u, 4u));
    REQUIRE(env.runtime->resource_ledger.entries[0].blocked == 1u);

    /* Once durably blocked, another refusal does not rewrite storage. */
    puts_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    fifth = (ninlil_service_t *)0x1u;
    {
        ninlil_service_descriptor_t descriptor =
            desired_descriptor_with_service(0x77u, service_ids[4]);
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &fifth)
            == NINLIL_E_CAPACITY_EXHAUSTED);
    }
    REQUIRE(fifth == NULL);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == puts_before);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env.runtime->service_count == 4u);
    REQUIRE(service_capacity_equals(env.runtime, 4u, 0u, 4u));
    REQUIRE(env.runtime->resource_ledger.entries[0].blocked == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_service_register_atomic_faults_and_restart(void)
{
    static const struct {
        ninlil_test_storage_operation_t operation;
        ninlil_storage_status_t raw_status;
        int has_commit_unknown_truth;
        int commit_unknown_committed;
        ninlil_status_t expected_status;
        uint64_t expected_after_restart;
    } cases[] = {
        {NINLIL_TEST_STORAGE_OP_PUT, NINLIL_STORAGE_IO_ERROR,
            0, 0, NINLIL_E_STORAGE, 0u},
        {NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_IO_ERROR,
            0, 0, NINLIL_E_STORAGE, 0u},
        {NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
            1, 0, NINLIL_E_STORAGE_COMMIT_UNKNOWN, 0u},
        {NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
            1, 1, NINLIL_E_STORAGE_COMMIT_UNKNOWN, 1u}
    };
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        spine_env_t env;
        ninlil_service_descriptor_t descriptor =
            desired_descriptor_with_service(
                (uint8_t)(0x90u + case_index), "atomic-service");
        ninlil_service_callbacks_t callbacks;
        ninlil_service_t *service = (ninlil_service_t *)0x1u;

        (void)memset(&env, 0, sizeof(env));
        REQUIRE(platform_init(&env));
        REQUIRE(env_create_runtime(&env, 4u));
        REQUIRE(service_capacity_equals(env.runtime, 0u, 0u, 0u));
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
        REQUIRE(ninlil_test_storage_fault_enqueue(
            env.storage_fixture,
            cases[case_index].operation,
            cases[case_index].raw_status,
            1u,
            cases[case_index].has_commit_unknown_truth,
            cases[case_index].commit_unknown_committed));
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &service)
            == cases[case_index].expected_status);
        REQUIRE(service == NULL);
        REQUIRE(env.runtime->service_count == 0u);
        REQUIRE(service_capacity_equals(env.runtime, 0u, 0u, 0u));
        if (cases[case_index].expected_status
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
            REQUIRE(env.runtime->commit_unknown_fence != 0u);
        }

        REQUIRE(ninlil_runtime_destroy(env.runtime)
            == (cases[case_index].expected_status
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN
                ? NINLIL_E_STORAGE_COMMIT_UNKNOWN
                : NINLIL_OK));
        env.runtime = NULL;
        REQUIRE(env_create_runtime(&env, 4u));
        REQUIRE(env.runtime->service_count
            == cases[case_index].expected_after_restart);
        REQUIRE(service_capacity_equals(
            env.runtime,
            cases[case_index].expected_after_restart,
            0u,
            cases[case_index].expected_after_restart));
        if (cases[case_index].expected_after_restart == 1u) {
            ninlil_service_t *reattached = NULL;
            REQUIRE(ninlil_service_register(
                        env.runtime,
                        &descriptor,
                        &callbacks,
                        &reattached)
                == NINLIL_OK);
            REQUIRE(reattached != NULL);
            REQUIRE(service_capacity_equals(env.runtime, 1u, 0u, 1u));
        }
        platform_teardown(&env);
    }
    return 0;
}

static int test_service_capacity_block_atomic_faults_and_restart(void)
{
    static const struct {
        ninlil_test_storage_operation_t operation;
        ninlil_storage_status_t raw_status;
        int has_commit_unknown_truth;
        int commit_unknown_committed;
        ninlil_status_t expected_status;
        uint32_t expected_blocked_after_restart;
    } cases[] = {
        {NINLIL_TEST_STORAGE_OP_PUT, NINLIL_STORAGE_IO_ERROR,
            0, 0, NINLIL_E_STORAGE, 0u},
        {NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_IO_ERROR,
            0, 0, NINLIL_E_STORAGE, 0u},
        {NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
            1, 0, NINLIL_E_STORAGE_COMMIT_UNKNOWN, 0u},
        {NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
            1, 1, NINLIL_E_STORAGE_COMMIT_UNKNOWN, 1u}
    };
    static const char *const service_ids[5] = {
        "block-a", "block-b", "block-c", "block-d", "block-e"
    };
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        spine_env_t env;
        ninlil_model_capacity_entry_t other_before[
            NINLIL_MODEL_RESOURCE_KIND_COUNT - 1u];
        ninlil_service_callbacks_t callbacks;
        ninlil_service_t *service = (ninlil_service_t *)0x1u;
        uint32_t index;

        (void)memset(&env, 0, sizeof(env));
        REQUIRE(platform_init(&env));
        REQUIRE(env_create_runtime(&env, 4u));
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
        for (index = 0u; index < 4u; ++index) {
            ninlil_service_descriptor_t descriptor =
                desired_descriptor_with_service(
                    (uint8_t)(0xA0u + index), service_ids[index]);
            service = NULL;
            REQUIRE(ninlil_service_register(
                        env.runtime, &descriptor, &callbacks, &service)
                == NINLIL_OK);
            REQUIRE(service != NULL);
        }
        REQUIRE(service_capacity_equals(env.runtime, 4u, 0u, 4u));
        REQUIRE(env.runtime->resource_ledger.entries[0].blocked == 0u);
        (void)memcpy(
            other_before,
            &env.runtime->resource_ledger.entries[1],
            sizeof(other_before));

        REQUIRE(ninlil_test_storage_fault_enqueue(
            env.storage_fixture,
            cases[case_index].operation,
            cases[case_index].raw_status,
            1u,
            cases[case_index].has_commit_unknown_truth,
            cases[case_index].commit_unknown_committed));
        {
            ninlil_service_descriptor_t descriptor =
                desired_descriptor_with_service(0xA4u, service_ids[4]);
            service = (ninlil_service_t *)0x1u;
            REQUIRE(ninlil_service_register(
                        env.runtime, &descriptor, &callbacks, &service)
                == cases[case_index].expected_status);
        }
        REQUIRE(service == NULL);
        REQUIRE(env.runtime->service_count == 4u);
        REQUIRE(service_capacity_equals(env.runtime, 4u, 0u, 4u));
        REQUIRE(env.runtime->resource_ledger.entries[0].blocked == 0u);
        REQUIRE(memcmp(
                    other_before,
                    &env.runtime->resource_ledger.entries[1],
                    sizeof(other_before))
            == 0);
        if (cases[case_index].expected_status
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
            REQUIRE(env.runtime->commit_unknown_fence != 0u);
        }

        REQUIRE(ninlil_runtime_destroy(env.runtime)
            == (cases[case_index].expected_status
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN
                ? NINLIL_E_STORAGE_COMMIT_UNKNOWN
                : NINLIL_OK));
        env.runtime = NULL;
        REQUIRE(env_create_runtime(&env, 4u));
        REQUIRE(env.runtime->service_count == 4u);
        REQUIRE(service_capacity_equals(env.runtime, 4u, 0u, 4u));
        REQUIRE(env.runtime->resource_ledger.entries[0].blocked
            == cases[case_index].expected_blocked_after_restart);
        REQUIRE(memcmp(
                    other_before,
                    &env.runtime->resource_ledger.entries[1],
                    sizeof(other_before))
            == 0);
        platform_teardown(&env);
    }
    return 0;
}

static int test_submit_null_invalid(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x75u));
    REQUIRE(env_make_submission(&env, &submission));
    REQUIRE(ninlil_submit(NULL, &submission, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_submit(env.service, NULL, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_submit(env.service, &submission, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

static int test_cancel_not_found(void)
{
    spine_env_t env;
    ninlil_id128_t missing;
    ninlil_cancel_result_t result;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    set_id(&missing, 0x99u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    REQUIRE(ninlil_cancel_request(env.runtime, &missing, &result)
        == NINLIL_E_NOT_FOUND);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    platform_teardown(&env);
    return 0;
}

static int test_cancel_targeted_deadline_priority(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t admitted;
    ninlil_cancel_result_t cancelled;
    uint64_t clock_calls;
    uint64_t ordered_before;

    /* At the exact deadline, management priority wins over the deadline. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x78u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(&admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_clock_advance(env.clock, 5000u));
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);
    REQUIRE(cancelled.current_outcome
        == NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before + 1u);

    /* An idempotent replay samples no clock and consumes no sequence. */
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before);
    platform_teardown(&env);

    /* Strictly older deadline work closes before the management mutation. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x79u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(&admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_ALREADY_TERMINAL);
    REQUIRE(cancelled.current_outcome == NINLIL_OUTCOME_EXPIRED);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before);
    platform_teardown(&env);
    return 0;
}

static int test_cancel_targeted_clock_and_counter_fences(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t admitted;
    ninlil_cancel_result_t cancelled;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_time_sample_t regressed;
    ninlil_time_sample_t trusted;
    ninlil_id128_t fresh_epoch;
    uint64_t clock_calls;
    uint64_t commit_calls;
    uint64_t ordered_before;

    /* A sample older than admission is a regression even if newer than start. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x7Au));
    env_initialize_target(&env);
    REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(&admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    regressed = env.runtime->started_sample;
    regressed.now_ms = 150u;
    regressed.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &regressed, 1u));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_E_DEGRADED);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(cancelled.kind == 0u);
    REQUIRE(cancelled.reason == 0u);
    REQUIRE(cancelled.current_outcome == 0u);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    platform_teardown(&env);

    /*
     * Old-epoch correctness timers may not be numerically skipped by a
     * new-epoch management input.  Until durable Recovery Fence convergence
     * exists, cancel fails closed before transaction/ordered mutation.
     */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x7Du));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(&admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    commit_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    set_id(&fresh_epoch, 0xedu);
    REQUIRE(ninlil_test_clock_rollback(env.clock, &fresh_epoch));
    (void)memset(&trusted, 0, sizeof(trusted));
    set_header(
        &trusted.abi_version, &trusted.struct_size, sizeof(trusted));
    trusted.clock_epoch_id = fresh_epoch;
    trusted.now_ms = 100u;
    trusted.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_recover(env.clock, &trusted));
    (void)memset(&cancelled, 0xa5, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_E_CLOCK_UNCERTAIN);
    REQUIRE(cancelled.kind == 0u);
    REQUIRE(cancelled.reason == 0u);
    REQUIRE(cancelled.current_outcome == 0u);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    platform_teardown(&env);

    /* Ordered-input exhaustion fails before clock sampling or transaction mutation. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x7Bu));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(&admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    env.runtime->last_assigned_ordered_input_sequence = UINT64_MAX;
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_E_DEGRADED);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    REQUIRE(cancelled.kind == 0u);
    REQUIRE(cancelled.reason == 0u);
    REQUIRE(cancelled.current_outcome == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == UINT64_MAX);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    platform_teardown(&env);
    return 0;
}

static int test_cancel_runtime_global_clock_fence(void)
{
    static const uint8_t key_a[] = "global-a";
    static const uint8_t key_b[] = "global-b";
    spine_env_t env;
    ninlil_submission_t submission_a;
    ninlil_submission_t submission_b;
    ninlil_submission_result_t admitted_a;
    ninlil_submission_result_t admitted_b;
    ninlil_cancel_result_t cancelled;
    ninlil_rt_transaction_slot_t before_b;
    ninlil_rt_transaction_slot_t *transaction_b;
    ninlil_time_sample_t regressed;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x7Cu));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission_a));
    submission_a.idempotency_key.data = key_a;
    submission_a.idempotency_key.length = sizeof(key_a) - 1u;
    submission_b = submission_a;
    submission_b.idempotency_key.data = key_b;
    submission_b.idempotency_key.length = sizeof(key_b) - 1u;
    submission_b.generation = 2u;
    (void)memset(&admitted_a, 0, sizeof(admitted_a));
    set_header(
        &admitted_a.abi_version,
        &admitted_a.struct_size,
        sizeof(admitted_a));
    (void)memset(&admitted_b, 0, sizeof(admitted_b));
    set_header(
        &admitted_b.abi_version,
        &admitted_b.struct_size,
        sizeof(admitted_b));
    REQUIRE(ninlil_submit(env.service, &submission_a, &admitted_a)
        == NINLIL_OK);
    REQUIRE(ninlil_submit(env.service, &submission_b, &admitted_b)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version,
        &cancelled.struct_size,
        sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted_a.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);

    transaction_b = ninlil_rt_find_transaction(
        env.runtime, &admitted_b.transaction_id);
    REQUIRE(transaction_b != NULL);
    before_b = *transaction_b;
    regressed = env.runtime->started_sample;
    regressed.now_ms = 500u;
    regressed.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
                env.clock, NINLIL_PORT_OK, &regressed, 1u)
        == 1);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version,
        &cancelled.struct_size,
        sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted_b.transaction_id, &cancelled)
        == NINLIL_E_DEGRADED);
    REQUIRE(cancelled.kind == 0u);
    REQUIRE(cancelled.reason == 0u);
    REQUIRE(cancelled.current_outcome == 0u);
    REQUIRE(memcmp(transaction_b, &before_b, sizeof(*transaction_b)) == 0);
    platform_teardown(&env);
    return 0;
}

typedef enum cancel_retry_clock_case {
    CANCEL_RETRY_CLOCK_REGRESSED = 0,
    CANCEL_RETRY_CLOCK_EXACT = 1,
    CANCEL_RETRY_CLOCK_UNDERFLOW = 2
} cancel_retry_clock_case_t;

static int run_cancel_retry_cold_restart_case(
    cancel_retry_clock_case_t case_kind)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t admitted;
    ninlil_cancel_result_t cancelled;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_model_resource_ledger_t ledger_before;
    ninlil_time_sample_t owner_sample;
    ninlil_time_sample_t management_sample;
    uint64_t scheduled_at_ms;
    uint64_t ordered_before;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint32_t target_index;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x7eu));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(
        &admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->retry_backoff_ms != 0u);
    (void)memset(&owner_sample, 0, sizeof(owner_sample));
    REQUIRE(env.platform.clock->now(
                env.platform.clock->user, &owner_sample)
        == NINLIL_PORT_OK);
    REQUIRE(ninlil_rt_accept_trusted_clock_sample(
                env.runtime, &owner_sample)
        == NINLIL_OK);
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    scheduled_at_ms = owner_sample.now_ms;
    if (case_kind == CANCEL_RETRY_CLOCK_UNDERFLOW) {
        candidate->next_retry_ms = candidate->retry_backoff_ms - 1u;
    } else {
        REQUIRE(owner_sample.now_ms
            <= UINT64_MAX - candidate->retry_backoff_ms);
        candidate->next_retry_ms =
            owner_sample.now_ms + candidate->retry_backoff_ms;
    }
    candidate->next_retry_clock_epoch_id = owner_sample.clock_epoch_id;
    for (target_index = 0u;
         target_index < candidate->bound_target_count;
         ++target_index) {
        ninlil_rt_target_slot_t *target =
            &candidate->bound_targets[target_index];

        if (target->in_use != 0u && target->terminal == 0u) {
            target->next_retry_ms = candidate->next_retry_ms;
            target->next_retry_clock_epoch_id =
                candidate->next_retry_clock_epoch_id;
        }
    }
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env.runtime,
                transaction,
                candidate,
                RETRY_STATE_PREFIX,
                NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT)
        == NINLIL_OK);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    management_sample = owner_sample;
    if (case_kind == CANCEL_RETRY_CLOCK_REGRESSED) {
        REQUIRE(scheduled_at_ms != 0u);
        management_sample.now_ms = scheduled_at_ms - 1u;
    }
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &management_sample, 2u));
    REQUIRE(env_create_runtime(&env, 4u));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ledger_before = env.runtime->resource_ledger;
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    (void)memset(&cancelled, 0xa5, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    status = ninlil_cancel_request(
        env.runtime, &admitted.transaction_id, &cancelled);
    if (case_kind == CANCEL_RETRY_CLOCK_EXACT) {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(cancelled.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);
        REQUIRE(cancelled.current_outcome
            == NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_before + 1u);
    } else {
        REQUIRE(status == NINLIL_E_DEGRADED);
        REQUIRE(cancelled.kind == 0u);
        REQUIRE(cancelled.reason == 0u);
        REQUIRE(cancelled.current_outcome == 0u);
        REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
        REQUIRE(env.runtime->degraded_reason
            == NINLIL_REASON_CLOCK_UNCERTAIN);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_before);
        REQUIRE(memcmp(
                    transaction, &transaction_before, sizeof(*transaction))
            == 0);
        REQUIRE(memcmp(
                    &env.runtime->resource_ledger,
                    &ledger_before,
                    sizeof(ledger_before))
            == 0);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
            == put_calls);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls);
    }
    platform_teardown(&env);
    return 0;
}

static int test_cancel_retry_cold_restart_owner_chronology(void)
{
    REQUIRE(run_cancel_retry_cold_restart_case(
                CANCEL_RETRY_CLOCK_REGRESSED)
        == 0);
    REQUIRE(run_cancel_retry_cold_restart_case(CANCEL_RETRY_CLOCK_EXACT)
        == 0);
    REQUIRE(run_cancel_retry_cold_restart_case(
                CANCEL_RETRY_CLOCK_UNDERFLOW)
        == 0);
    return 0;
}

static int setup_sent_command(
    spine_env_t *env,
    const uint8_t *endpoint_namespace,
    uint32_t endpoint_namespace_length,
    uint8_t service_seed,
    ninlil_runtime_t **out_endpoint_runtime,
    ninlil_submission_result_t *out_admitted);

static int run_cancel_receipt_boundary_case(
    int target_only,
    int exact_max)
{
    static const uint8_t endpoint_namespace[] =
        "cancel-receipt-boundary-endpoint";
    spine_env_t env;
    ninlil_runtime_t *endpoint_runtime = NULL;
    ninlil_submission_result_t admitted;
    ninlil_cancel_result_t cancelled;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_rt_target_slot_t *target;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_model_resource_ledger_t ledger_before;
    ninlil_time_sample_t management_sample;
    ninlil_id128_t owner_epoch;
    uint64_t ordered_before;
    uint64_t put_calls;
    uint64_t commit_calls;
    ninlil_status_t status;

    REQUIRE(setup_sent_command(
                &env,
                endpoint_namespace,
                (uint32_t)sizeof(endpoint_namespace) - 1u,
                target_only != 0 ? 0x7cu : 0x7bu,
                &endpoint_runtime,
                &admitted)
        == 0);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_receipt_timeout_ms > 1u);
    REQUIRE(transaction->active_target_index
        < transaction->bound_target_count);
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    target = &candidate->bound_targets[candidate->active_target_index];
    owner_epoch = target->send_observed_clock_epoch_id;
    target->send_observed_at_ms = UINT64_MAX
        - candidate->attempt_receipt_timeout_ms
        + (exact_max != 0 ? 0u : 1u);
    if (target_only != 0) {
        candidate->active_target_index = NINLIL_RT_V1_NO_ACTIVE_TARGET;
        candidate->attempt_prepared = 0u;
        (void)memset(
            &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
        candidate->send_observation_closed = 0u;
        candidate->send_observed_at_ms = 0u;
        (void)memset(
            &candidate->send_observed_clock_epoch_id,
            0,
            sizeof(candidate->send_observed_clock_epoch_id));
    } else {
        candidate->send_observed_at_ms = target->send_observed_at_ms;
        candidate->send_observed_clock_epoch_id = owner_epoch;
    }
    REQUIRE(candidate->evidence_grace_ms != 0u);
    candidate->effect_deadline_ms =
        UINT64_MAX - candidate->evidence_grace_ms;
    candidate->deadline_clock_epoch_id = owner_epoch;
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env.runtime,
                transaction,
                candidate,
                DELIVERY_STARTED_PREFIX,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_OK);

    REQUIRE(ninlil_runtime_destroy(endpoint_runtime) == NINLIL_OK);
    endpoint_runtime = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage_fixture);
    (void)memset(&management_sample, 0, sizeof(management_sample));
    set_header(
        &management_sample.abi_version,
        &management_sample.struct_size,
        sizeof(management_sample));
    management_sample.clock_epoch_id = owner_epoch;
    management_sample.now_ms = UINT64_MAX;
    management_sample.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &management_sample, 2u));
    REQUIRE(env_create_runtime(&env, 4u));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ledger_before = env.runtime->resource_ledger;
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    (void)memset(&cancelled, 0xa5, sizeof(cancelled));
    set_header(
        &cancelled.abi_version, &cancelled.struct_size, sizeof(cancelled));
    status = ninlil_cancel_request(
        env.runtime, &admitted.transaction_id, &cancelled);
    if (exact_max != 0) {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(cancelled.kind == NINLIL_CANCEL_PENDING_REMOTE_FENCE);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_before + 1u);
    } else {
        REQUIRE(status == NINLIL_E_DEGRADED);
        REQUIRE(cancelled.kind == 0u);
        REQUIRE(cancelled.reason == 0u);
        REQUIRE(cancelled.current_outcome == 0u);
        REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
        REQUIRE(env.runtime->degraded_reason
            == NINLIL_REASON_CLOCK_UNCERTAIN);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_before);
        REQUIRE(memcmp(
                    transaction,
                    &transaction_before,
                    sizeof(*transaction))
            == 0);
        REQUIRE(memcmp(
                    &env.runtime->resource_ledger,
                    &ledger_before,
                    sizeof(ledger_before))
            == 0);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
            == put_calls);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls);
    }
    platform_teardown(&env);
    return 0;
}

static int test_cancel_receipt_deadline_boundary(void)
{
    REQUIRE(run_cancel_receipt_boundary_case(0, 0) == 0);
    REQUIRE(run_cancel_receipt_boundary_case(0, 1) == 0);
    REQUIRE(run_cancel_receipt_boundary_case(1, 0) == 0);
    REQUIRE(run_cancel_receipt_boundary_case(1, 1) == 0);
    return 0;
}

static int setup_sent_command(
    spine_env_t *env,
    const uint8_t *endpoint_namespace,
    uint32_t endpoint_namespace_length,
    uint8_t service_seed,
    ninlil_runtime_t **out_endpoint_runtime,
    ninlil_submission_result_t *out_admitted)
{
    ninlil_runtime_config_t endpoint_config;
    ninlil_submission_t submission;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_rt_transaction_slot_t *transaction;
    uint32_t step;

    (void)memset(env, 0, sizeof(*env));
    *out_endpoint_runtime = NULL;
    REQUIRE(platform_init(env));
    REQUIRE(env_create_runtime(env, 4u));
    endpoint_config = config_fixture_role(NINLIL_ROLE_ENDPOINT, 4u);
    set_id(&endpoint_config.runtime_id, 0x11u);
    endpoint_config.storage_namespace.data = endpoint_namespace;
    endpoint_config.storage_namespace.length = endpoint_namespace_length;
    REQUIRE(ninlil_runtime_create(
                &endpoint_config,
                &env->platform,
                out_endpoint_runtime)
        == NINLIL_OK);
    REQUIRE(env_register_service(env, service_seed));
    env_initialize_target(env);
    env->target.target_runtime_id = endpoint_config.runtime_id;
    REQUIRE(env_make_submission(env, &submission));
    (void)memset(out_admitted, 0, sizeof(*out_admitted));
    set_header(
        &out_admitted->abi_version,
        &out_admitted->struct_size,
        sizeof(*out_admitted));
    REQUIRE(ninlil_submit(env->service, &submission, out_admitted)
        == NINLIL_OK);
    REQUIRE(out_admitted->kind == NINLIL_SUBMISSION_ADMITTED_READY);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 4u;
    budget.max_callbacks = 4u;
    budget.max_state_transitions = 8u;
    budget.max_bearer_sends = 4u;
    transaction = ninlil_rt_find_transaction(
        env->runtime, &out_admitted->transaction_id);
    REQUIRE(transaction != NULL);
    for (step = 0u;
         step < 8u && transaction->send_observation_closed == 0u;
         ++step) {
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(env->runtime, &budget, &step_result)
            == NINLIL_OK);
    }
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_STARTED);
    REQUIRE(transaction->send_observation_closed != 0u);
    return 0;
}

typedef struct cancel_timer_hook_counts {
    uint32_t timeout_before;
    uint32_t timeout_after;
    uint32_t close_before;
    uint32_t close_after;
} cancel_timer_hook_counts_t;

static void cancel_timer_hook(void *user, const char *name)
{
    cancel_timer_hook_counts_t *counts =
        (cancel_timer_hook_counts_t *)user;

    if (counts == NULL || name == NULL) {
        return;
    }
    if (strcmp(
            name,
            "controller.before_command_attempt_timeout_commit") == 0) {
        counts->timeout_before += 1u;
    } else if (strcmp(
            name,
            "controller.after_command_attempt_timeout_commit") == 0) {
        counts->timeout_after += 1u;
    } else if (strcmp(
            name, "controller.before_evidence_close_commit") == 0) {
        counts->close_before += 1u;
    } else if (strcmp(
            name, "controller.after_evidence_close_commit") == 0) {
        counts->close_after += 1u;
    }
}

static int test_cancel_command_timer_order_and_evidence_close(void)
{
    static const uint8_t endpoint_namespace[] =
        "cancel-order-endpoint";
    spine_env_t env;
    ninlil_runtime_t *endpoint_runtime = NULL;
    ninlil_submission_result_t admitted;
    ninlil_cancel_result_t cancelled;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_rt_transaction_slot_t *transaction;
    cancel_timer_hook_counts_t hooks;
    uint64_t clock_calls;
    uint64_t revision_before;

    REQUIRE(setup_sent_command(
                &env,
                endpoint_namespace,
                (uint32_t)sizeof(endpoint_namespace) - 1u,
                0x7Du,
                &endpoint_runtime,
                &admitted)
        == 0);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->send_observed_at_ms == 0u);
    REQUIRE(transaction->attempt_receipt_timeout_ms == 1000u);
    REQUIRE(transaction->effect_deadline_ms == 5000u);
    REQUIRE(transaction->evidence_grace_ms == 1000u);
    revision_before = transaction->record_revision;
    (void)memset(&hooks, 0, sizeof(hooks));
    env.runtime->private_transition_hook = cancel_timer_hook;
    env.runtime->private_transition_hook_user = &hooks;

    /* 1000 timeout -> 5000 deadline -> same-time cancel before 6000 close. */
    REQUIRE(ninlil_test_clock_advance(env.clock, 6000u));
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version,
        &cancelled.struct_size,
        sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(cancelled.reason == NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(cancelled.current_outcome == NINLIL_OUTCOME_NONE);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->deadline_verdict
        == NINLIL_DEADLINE_INDETERMINATE);
    REQUIRE(transaction->record_revision == revision_before + 3u);
    REQUIRE(hooks.timeout_before == 1u);
    REQUIRE(hooks.timeout_after == 1u);
    REQUIRE(hooks.close_before == 0u);
    REQUIRE(hooks.close_after == 0u);

    /* Persisted management replay does not sample clock or run catch-up. */
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version,
        &cancelled.struct_size,
        sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(cancelled.reason == NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    /* The effect/deadline/cancel truth survives a Runtime restart. */
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(env_create_runtime(&env, 4u));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->cancel_kind
        == NINLIL_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(transaction->deadline_verdict
        == NINLIL_DEADLINE_INDETERMINATE);
    env.runtime->private_transition_hook = cancel_timer_hook;
    env.runtime->private_transition_hook_user = &hooks;

    /* Strictly after evidence-close, Runtime step terminalizes UNKNOWN. */
    REQUIRE(ninlil_test_clock_advance(env.clock, 1u));
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 4u;
    budget.max_callbacks = 4u;
    budget.max_state_transitions = 8u;
    budget.max_bearer_sends = 4u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction->terminal != 0u);
    REQUIRE(transaction->reservation_active == 0u);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_UNKNOWN);
    REQUIRE(transaction->reason
        == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING);
    REQUIRE(hooks.close_before == 1u);
    REQUIRE(hooks.close_after == 1u);

    /* Cancel ledger identity remains stable; only current outcome changes. */
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&cancelled, 0, sizeof(cancelled));
    set_header(
        &cancelled.abi_version,
        &cancelled.struct_size,
        sizeof(cancelled));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &admitted.transaction_id, &cancelled)
        == NINLIL_OK);
    REQUIRE(cancelled.kind == NINLIL_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(cancelled.reason == NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE);
    REQUIRE(cancelled.current_outcome == NINLIL_OUTCOME_UNKNOWN);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(endpoint_runtime) == NINLIL_OK);
    endpoint_runtime = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_prepared_command_deadline_and_evidence_close(void)
{
    static const uint8_t endpoint_namespace[] =
        "prepared-deadline-endpoint";
    spine_env_t env;
    ninlil_runtime_t *endpoint_runtime = NULL;
    ninlil_runtime_config_t endpoint_config;
    ninlil_submission_t submission;
    ninlil_submission_result_t admitted;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_rt_transaction_slot_t *transaction;
    cancel_timer_hook_counts_t hooks;
    uint64_t revision_before;
    uint32_t step;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    endpoint_config = config_fixture_role(NINLIL_ROLE_ENDPOINT, 4u);
    set_id(&endpoint_config.runtime_id, 0x11u);
    endpoint_config.storage_namespace.data = endpoint_namespace;
    endpoint_config.storage_namespace.length =
        (uint32_t)sizeof(endpoint_namespace) - 1u;
    REQUIRE(ninlil_runtime_create(
                &endpoint_config, &env.platform, &endpoint_runtime)
        == NINLIL_OK);
    REQUIRE(env_register_service(&env, 0x7Eu));
    env_initialize_target(&env);
    env.target.target_runtime_id = endpoint_config.runtime_id;
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&admitted, 0, sizeof(admitted));
    set_header(&admitted.abi_version, &admitted.struct_size, sizeof(admitted));
    REQUIRE(ninlil_submit(env.service, &submission, &admitted) == NINLIL_OK);
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 4u;
    budget.max_callbacks = 4u;
    budget.max_state_transitions = 8u;
    budget.max_bearer_sends = 0u;
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    for (step = 0u;
         step < 8u && transaction->attempt_prepared == 0u;
         ++step) {
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
            == NINLIL_OK);
    }
    REQUIRE(transaction->attempt_prepared != 0u);
    REQUIRE(transaction->send_observation_closed == 0u);
    revision_before = transaction->record_revision;

    /* A durable ATTEMPT_PREPARED gate is effect-possible at the deadline. */
    (void)memset(&hooks, 0, sizeof(hooks));
    env.runtime->private_transition_hook = cancel_timer_hook;
    env.runtime->private_transition_hook_user = &hooks;
    REQUIRE(ninlil_test_clock_advance(env.clock, 5000u));
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->deadline_verdict
        == NINLIL_DEADLINE_INDETERMINATE);
    REQUIRE(transaction->reason
        == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING);
    REQUIRE(transaction->pending_dispatch == 0u);
    REQUIRE(transaction->record_revision == revision_before + 1u);
    REQUIRE(hooks.close_before == 0u);
    REQUIRE(hooks.close_after == 0u);

    /* Exact evidence-close then closes the possible attempt as UNKNOWN. */
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);
    REQUIRE(transaction->terminal != 0u);
    REQUIRE(transaction->reservation_active == 0u);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_UNKNOWN);
    REQUIRE(transaction->reason
        == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING);
    REQUIRE(hooks.close_before == 1u);
    REQUIRE(hooks.close_after == 1u);

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(endpoint_runtime) == NINLIL_OK);
    endpoint_runtime = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_cancel_wrong_role(void)
{
    spine_env_t env;
    ninlil_id128_t txn_id;
    ninlil_cancel_result_t result;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    set_id(&txn_id, 0x88u);
    REQUIRE(platform_init(&env));
    env.config = config_fixture_role(NINLIL_ROLE_ENDPOINT, 4u);
    REQUIRE(ninlil_runtime_create(&env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    REQUIRE(ninlil_cancel_request(env.runtime, &txn_id, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    platform_teardown(&env);
    return 0;
}

static int test_wrong_thread(void)
{
    spine_env_t env;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    ninlil_test_execution_set_context_id(env.execution, 2u);
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_WRONG_THREAD);
    platform_teardown(&env);
    return 0;
}

static int test_cancel_zero_txn_invalid(void)
{
    spine_env_t env;
    ninlil_id128_t zero_id;
    ninlil_cancel_result_t result;

    (void)memset(&env, 0, sizeof(env));
    (void)memset(&zero_id, 0, sizeof(zero_id));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_cancel_request(env.runtime, &zero_id, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

static int test_offer_accept_unsupported(void)
{
    spine_env_t env;
    ninlil_id128_t offer_id;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    set_id(&offer_id, 0x55u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_offer_accept(env.runtime, &offer_id, &result)
        == NINLIL_E_UNSUPPORTED);
    platform_teardown(&env);
    return 0;
}

static int test_capacity_snapshot_contract(void)
{
    spine_env_t env;
    ninlil_capacity_entry_t entries[12];
    ninlil_capacity_entry_t before[12];
    ninlil_capacity_snapshot_t snapshot;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(entries, 0x5a, sizeof(entries));
    for (index = 0u; index < 12u; ++index) {
        set_header(
            &entries[index].abi_version,
            &entries[index].struct_size,
            sizeof(entries[index]));
    }
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.entries = entries;
    snapshot.entry_capacity = 12u;

    REQUIRE(ninlil_capacity_snapshot(env.runtime, &snapshot) == NINLIL_OK);
    REQUIRE(snapshot.entries == entries);
    REQUIRE(snapshot.entry_capacity == 12u);
    REQUIRE(snapshot.entry_count == 11u);
    for (index = 0u; index < 11u; ++index) {
        REQUIRE(entries[index].kind == (ninlil_resource_kind_t)(index + 1u));
        REQUIRE(entries[index].used + entries[index].reserved
            <= entries[index].limit);
        REQUIRE(entries[index].high_water
            >= entries[index].used + entries[index].reserved);
        REQUIRE(entries[index].capacity_epoch == 1u);
    }
    REQUIRE(entries[0].limit == 4u);
    REQUIRE(entries[1].limit == 57u);
    REQUIRE(entries[11].kind == (ninlil_resource_kind_t)0x5a5a5a5au);

    (void)memcpy(before, entries, sizeof(entries));
    snapshot.entry_capacity = 10u;
    snapshot.entry_count = 99u;
    REQUIRE(ninlil_capacity_snapshot(env.runtime, &snapshot)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(snapshot.entries == entries);
    REQUIRE(snapshot.entry_capacity == 10u);
    REQUIRE(snapshot.entry_count == 11u);
    REQUIRE(memcmp(entries, before, sizeof(entries)) == 0);

    snapshot.entry_capacity = 11u;
    snapshot.entry_count = 99u;
    entries[7].struct_size = 1u;
    (void)memcpy(before, entries, sizeof(entries));
    REQUIRE(ninlil_capacity_snapshot(env.runtime, &snapshot)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(snapshot.entries == entries);
    REQUIRE(snapshot.entry_capacity == 11u);
    REQUIRE(snapshot.entry_count == 0u);
    REQUIRE(memcmp(entries, before, sizeof(entries)) == 0);

    platform_teardown(&env);
    return 0;
}

static int test_metrics_snapshot_extensible_output(void)
{
    typedef struct future_metrics {
        ninlil_metrics_snapshot_t known;
        uint8_t future_tail[16];
    } future_metrics_t;
    spine_env_t env;
    future_metrics_t output;
    uint32_t index;
    int metrics_epoch_nonzero = 0;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&output, 0xa5, sizeof(output));
    set_header(
        &output.known.abi_version,
        &output.known.struct_size,
        sizeof(output));

    REQUIRE(ninlil_metrics_snapshot(env.runtime, &output.known) == NINLIL_OK);
    REQUIRE(output.known.struct_size == (uint16_t)sizeof(output));
    for (index = 0u;
         index < (uint32_t)sizeof(output.known.metrics_epoch_id.bytes);
         ++index) {
        if (output.known.metrics_epoch_id.bytes[index] != 0u) {
            metrics_epoch_nonzero = 1;
        }
    }
    REQUIRE(metrics_epoch_nonzero);
    REQUIRE(output.known.started_clock_epoch_id.bytes[0] == 0xa0u);
    REQUIRE(output.known.started_clock_epoch_id.bytes[15] == 0x01u);
    REQUIRE(output.known.started_at_ms == 0u);
    REQUIRE(output.known.submission_calls == 0u);
    for (index = 0u; index < sizeof(output.future_tail); ++index) {
        REQUIRE(output.future_tail[index] == 0xa5u);
    }

    output.known.abi_version = (uint16_t)(NINLIL_ABI_VERSION + 1u);
    output.known.started_at_ms = 0x5a5a5a5a5a5a5a5aull;
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &output.known)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(output.known.started_at_ms == 0x5a5a5a5a5a5a5a5aull);

    platform_teardown(&env);
    return 0;
}

static int test_runtime_step_budget_and_extensible_result(void)
{
    typedef struct future_step_budget {
        ninlil_step_budget_t known;
        uint8_t future_tail[8];
    } future_step_budget_t;
    typedef struct future_step_result {
        ninlil_step_result_t known;
        uint8_t future_tail[8];
    } future_step_result_t;
    spine_env_t env;
    future_step_budget_t budget;
    future_step_result_t result;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));

    (void)memset(&budget, 0, sizeof(budget));
    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &budget.known.abi_version,
        &budget.known.struct_size,
        sizeof(budget));
    set_header(
        &result.known.abi_version,
        &result.known.struct_size,
        sizeof(result));
    budget.known.max_ingress_messages =
        env.config.limits.max_ingress_per_step + 1u;
    REQUIRE(ninlil_runtime_step(
                env.runtime, &budget.known, &result.known)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result.known.ingress_processed == 0u);
    REQUIRE(result.known.callbacks_invoked == 0u);
    REQUIRE(result.known.state_transitions == 0u);
    REQUIRE(result.known.bearer_sends == 0u);
    REQUIRE(result.known.health == NINLIL_HEALTH_OK);
    for (index = 0u; index < sizeof(result.future_tail); ++index) {
        REQUIRE(result.future_tail[index] == 0xa5u);
    }

    budget.known.max_ingress_messages = 0u;
    REQUIRE(ninlil_runtime_step(
                env.runtime, &budget.known, &result.known)
        == NINLIL_OK);
    REQUIRE(result.known.ingress_processed == 0u);
    REQUIRE(result.known.callbacks_invoked == 0u);
    REQUIRE(result.known.state_transitions == 0u);
    REQUIRE(result.known.bearer_sends == 0u);
    for (index = 0u; index < sizeof(result.future_tail); ++index) {
        REQUIRE(result.future_tail[index] == 0xa5u);
    }

    platform_teardown(&env);
    return 0;
}

static int test_transaction_query_and_list_contract(void)
{
    typedef struct future_query {
        ninlil_query_t known;
        uint8_t future_tail[8];
    } future_query_t;
    typedef struct future_page {
        ninlil_transaction_page_t known;
        uint8_t future_tail[8];
    } future_page_t;
    static const uint8_t second_key[] = "key-2";
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t first;
    ninlil_submission_result_t second;
    ninlil_target_snapshot_t targets[2];
    ninlil_transaction_snapshot_t snapshot;
    ninlil_transaction_summary_t items[2];
    future_query_t query;
    future_page_t page;
    ninlil_id128_t missing;
    uint8_t untouched_target[sizeof(targets[1])];
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0x70u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&first, 0, sizeof(first));
    set_header(&first.abi_version, &first.struct_size, sizeof(first));
    REQUIRE(ninlil_submit(env.service, &submission, &first) == NINLIL_OK);
    REQUIRE(first.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    submission.idempotency_key.data = second_key;
    submission.idempotency_key.length = sizeof(second_key) - 1u;
    submission.generation = 2u;
    (void)memset(&second, 0, sizeof(second));
    set_header(&second.abi_version, &second.struct_size, sizeof(second));
    REQUIRE(ninlil_submit(env.service, &submission, &second) == NINLIL_OK);
    REQUIRE(second.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    (void)memset(targets, 0x5a, sizeof(targets));
    for (index = 0u; index < 2u; ++index) {
        set_header(
            &targets[index].abi_version,
            &targets[index].struct_size,
            sizeof(targets[index]));
    }
    (void)memcpy(untouched_target, &targets[1], sizeof(targets[1]));
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = targets;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &first.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.targets == targets);
    REQUIRE(snapshot.target_capacity == 2u);
    REQUIRE(snapshot.target_count == 1u);
    REQUIRE(snapshot.family == NINLIL_FAMILY_DESIRED_STATE);
    REQUIRE(snapshot.state == NINLIL_TXN_READY);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_NONE);
    REQUIRE(snapshot.required_evidence == NINLIL_EVIDENCE_APPLIED);
    REQUIRE(snapshot.latest_evidence == NINLIL_EVIDENCE_NONE);
    REQUIRE(snapshot.transaction_sequence == 1u);
    REQUIRE(snapshot.record_revision == 1u);
    REQUIRE(snapshot.absolute_effect_deadline_ms == 5000u);
    REQUIRE(snapshot.assurance.assurance_profile
        == NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL);
    REQUIRE(memcmp(
                &targets[0].target,
                &env.target,
                sizeof(env.target))
        == 0);
    REQUIRE(memcmp(
                &targets[1],
                untouched_target,
                sizeof(targets[1]))
        == 0);

    snapshot.targets = NULL;
    snapshot.target_capacity = 0u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &first.transaction_id, &snapshot)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(snapshot.targets == NULL);
    REQUIRE(snapshot.target_capacity == 0u);
    REQUIRE(snapshot.target_count == 1u);

    set_id(&missing, 0xe0u);
    snapshot.targets = targets;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(env.runtime, &missing, &snapshot)
        == NINLIL_E_NOT_FOUND);
    REQUIRE(snapshot.targets == targets);
    REQUIRE(snapshot.target_capacity == 2u);
    REQUIRE(snapshot.target_count == 0u);

    (void)memset(&query, 0, sizeof(query));
    set_header(
        &query.known.abi_version,
        &query.known.struct_size,
        sizeof(query));
    query.known.include_terminal = 1u;
    query.known.include_nonterminal = 1u;
    (void)memset(&page, 0xa5, sizeof(page));
    set_header(
        &page.known.abi_version,
        &page.known.struct_size,
        sizeof(page));
    (void)memset(items, 0x5a, sizeof(items));
    for (index = 0u; index < 2u; ++index) {
        set_header(
            &items[index].abi_version,
            &items[index].struct_size,
            sizeof(items[index]));
    }
    page.known.items = items;
    page.known.item_capacity = 1u;
    REQUIRE(ninlil_transaction_list(
                env.runtime, &query.known, &page.known)
        == NINLIL_OK);
    REQUIRE(page.known.struct_size == (uint16_t)sizeof(page));
    REQUIRE(page.known.items == items);
    REQUIRE(page.known.item_capacity == 1u);
    REQUIRE(page.known.item_count == 1u);
    REQUIRE(page.known.next_after_transaction_sequence == 1u);
    REQUIRE(page.known.has_more == 1u);
    REQUIRE(items[0].transaction_sequence == 1u);
    REQUIRE(items[0].state == NINLIL_TXN_READY);
    for (index = 0u; index < sizeof(page.future_tail); ++index) {
        REQUIRE(page.future_tail[index] == 0xa5u);
    }

    query.known.after_transaction_sequence =
        page.known.next_after_transaction_sequence;
    REQUIRE(ninlil_transaction_list(
                env.runtime, &query.known, &page.known)
        == NINLIL_OK);
    REQUIRE(page.known.item_count == 1u);
    REQUIRE(page.known.next_after_transaction_sequence == 2u);
    REQUIRE(page.known.has_more == 0u);
    REQUIRE(items[0].transaction_sequence == 2u);

    query.known.after_transaction_sequence = 0u;
    page.known.items = NULL;
    page.known.item_capacity = 0u;
    REQUIRE(ninlil_transaction_list(
                env.runtime, &query.known, &page.known)
        == NINLIL_OK);
    REQUIRE(page.known.item_count == 0u);
    REQUIRE(page.known.next_after_transaction_sequence == 0u);
    REQUIRE(page.known.has_more == 1u);

    query.known.family_mask = NINLIL_FAMILY_MASK_EVENT_FACT;
    REQUIRE(ninlil_transaction_list(
                env.runtime, &query.known, &page.known)
        == NINLIL_OK);
    REQUIRE(page.known.item_count == 0u);
    REQUIRE(page.known.has_more == 0u);

    query.known.family_mask = 0u;
    query.known.include_terminal = 0u;
    query.known.include_nonterminal = 0u;
    REQUIRE(ninlil_transaction_list(
                env.runtime, &query.known, &page.known)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(page.known.items == NULL);
    REQUIRE(page.known.item_capacity == 0u);
    REQUIRE(page.known.item_count == 0u);

    platform_teardown(&env);
    return 0;
}

static int test_reserved_family_register_unsupported(void)
{
    spine_env_t env;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service = NULL;
    static const ninlil_family_t reserved[] = {
        NINLIL_FAMILY_LATEST_STATE_RESERVED,
        NINLIL_FAMILY_MEASUREMENT_RESERVED,
        NINLIL_FAMILY_TRANSFER_RESERVED,
        NINLIL_FAMILY_CONFIG_RESERVED,
        NINLIL_FAMILY_NETWORK_CONTROL_RESERVED
    };
    size_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    for (index = 0u; index < sizeof(reserved) / sizeof(reserved[0]); ++index) {
        descriptor = desired_descriptor(0x90u);
        descriptor.family = reserved[index];
        if (reserved[index] == NINLIL_FAMILY_LATEST_STATE_RESERVED
            || reserved[index] == NINLIL_FAMILY_MEASUREMENT_RESERVED
            || reserved[index] == NINLIL_FAMILY_NETWORK_CONTROL_RESERVED) {
            descriptor.direction = NINLIL_DIRECTION_UPLINK;
            descriptor.admission_authority = NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
            descriptor.minimum_deadline_ms = NINLIL_NO_DEADLINE;
            descriptor.maximum_deadline_ms = NINLIL_NO_DEADLINE;
            descriptor.maximum_evidence_grace_ms = 0u;
        }
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
        service = (ninlil_service_t *)0x1u;
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &service)
            == NINLIL_E_UNSUPPORTED);
        REQUIRE(service == NULL);
    }
    platform_teardown(&env);
    return 0;
}

static int test_output_abi_mismatch_preserves_buffer(void)
{
    spine_env_t env;
    ninlil_id128_t id;
    ninlil_cancel_result_t cancel;
    ninlil_submission_result_t offer;
    ninlil_step_result_t step;
    ninlil_step_budget_t budget;
    ninlil_metrics_snapshot_t metrics;
    uint8_t poison = 0xA5u;

    (void)memset(&env, 0, sizeof(env));
    set_id(&id, 0xAAu);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));

    (void)memset(&cancel, poison, sizeof(cancel));
    cancel.abi_version = 0u;
    cancel.struct_size = (uint16_t)sizeof(cancel);
    REQUIRE(ninlil_cancel_request(env.runtime, &id, &cancel)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&cancel)[4] == poison);

    (void)memset(&offer, poison, sizeof(offer));
    offer.abi_version = NINLIL_ABI_VERSION;
    offer.struct_size = 2u;
    REQUIRE(ninlil_offer_accept(env.runtime, &id, &offer)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&offer)[4] == poison);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    (void)memset(&step, poison, sizeof(step));
    step.abi_version = 0xFFFFu;
    step.struct_size = (uint16_t)sizeof(step);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&step)[4] == poison);

    (void)memset(&metrics, poison, sizeof(metrics));
    metrics.abi_version = NINLIL_ABI_VERSION;
    metrics.struct_size = 0u;
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&metrics)[4] == poison);

    platform_teardown(&env);
    return 0;
}

static int test_service_registry_restart_reattach_and_quota_window(void)
{
    spine_env_t env;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *reattached = NULL;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_rt_service_slot_t *slot;
    uint64_t first_window_start;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0xA1u));
    slot = &env.runtime->services[env.service->slot_index];
    REQUIRE(slot->in_use != 0u);
    REQUIRE(slot->attached != 0u);
    REQUIRE(slot->quota_admissions == 0u);

    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(slot->quota_admissions == 1u);
    REQUIRE(slot->quota_payload_bytes == sizeof(env.payload));
    first_window_start = slot->quota_window_start_ms;
    REQUIRE(first_window_start == 0u
        || (first_window_start % slot->descriptor.admission_window_ms) == 0u);

    /* Same-window second admission increments durable counters. */
    {
        static const uint8_t idem_b[] = "key-b";
        submission.idempotency_key.data = idem_b;
        submission.idempotency_key.length = sizeof(idem_b) - 1u;
        env.payload[1] = 0x11u;
        REQUIRE(set_payload_content_digest(
            &submission.content_digest, env.payload, sizeof(env.payload)));
        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        REQUIRE(slot->quota_admissions == 2u);
    }

    /* Advance clock past fixed window; next admit must rollover to 1. */
    REQUIRE(ninlil_test_clock_advance(
        env.clock, slot->descriptor.admission_window_ms));
    {
        static const uint8_t idem_c[] = "key-c";
        submission.idempotency_key.data = idem_c;
        submission.idempotency_key.length = sizeof(idem_c) - 1u;
        env.payload[1] = 0x22u;
        REQUIRE(set_payload_content_digest(
            &submission.content_digest, env.payload, sizeof(env.payload)));
        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        REQUIRE(slot->quota_admissions == 1u);
        REQUIRE(slot->quota_window_start_ms
            == first_window_start + slot->descriptor.admission_window_ms);
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;

    /* Restart restores durable SERVICE registry unattached. */
    REQUIRE(env_create_runtime(&env, 4u));
    {
        uint32_t restored = 0u;
        for (index = 0u; index < env.runtime->service_capacity; ++index) {
            if (env.runtime->services[index].in_use != 0u) {
                restored += 1u;
                REQUIRE(env.runtime->services[index].attached == 0u);
                REQUIRE(env.runtime->services[index].callbacks.on_delivery
                    == NULL);
                REQUIRE(env.runtime->services[index].quota_admissions == 1u);
            }
        }
        REQUIRE(restored == 1u);
    }

    descriptor = desired_descriptor(0xA1u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &reattached)
        == NINLIL_OK);
    REQUIRE(reattached != NULL);
    REQUIRE(reattached->slot_index < env.runtime->service_capacity);
    slot = &env.runtime->services[reattached->slot_index];
    REQUIRE(slot->attached != 0u);
    REQUIRE(slot->quota_admissions == 1u);
    /* Exact same-lifetime reattach is idempotent (same handle). */
    {
        ninlil_service_t *second = NULL;
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &second)
            == NINLIL_OK);
        REQUIRE(second == reattached);
    }
    /* Conflict on same key different digest. */
    {
        ninlil_service_t *conflict = (ninlil_service_t *)0x1u;
        descriptor.descriptor_digest.bytes[0] ^= 0xFFu;
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &conflict)
            == NINLIL_E_CONFLICT);
        REQUIRE(conflict == NULL);
    }

    platform_teardown(&env);
    return 0;
}

/* T2: payload content_digest mismatch has zero durable/quota side effects. */
static int test_t2_content_digest_mismatch_zero_effects(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_rt_service_slot_t *slot;
    uint64_t admissions_before;
    uint32_t txn_count_before;
    uint64_t metrics_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0xB1u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    /* Corrupt content_digest after correct computation. */
    submission.content_digest.bytes[0] ^= 0xFFu;
    slot = &env.runtime->services[env.service->slot_index];
    admissions_before = slot->quota_admissions;
    txn_count_before = env.runtime->transaction_count;
    metrics_before = env.runtime->metrics.admitted_ready;

    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env.service, &submission, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(slot->quota_admissions == admissions_before);
    REQUIRE(env.runtime->transaction_count == txn_count_before);
    REQUIRE(env.runtime->metrics.admitted_ready == metrics_before);
    REQUIRE(env.runtime->nonterminal_transaction_count == 0u);

    platform_teardown(&env);
    return 0;
}

/* T3: same key/same digest live+restart ALREADY; different digest CONFLICT. */
static int test_t3_idempotency_live_and_restart(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t first;
    ninlil_submission_result_t second;
    ninlil_id128_t first_txn;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *reattached = NULL;
    static const uint8_t key[] = "idem-t3";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0xB2u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    submission.idempotency_key.data = key;
    submission.idempotency_key.length = sizeof(key) - 1u;

    (void)memset(&first, 0, sizeof(first));
    set_header(&first.abi_version, &first.struct_size, sizeof(first));
    REQUIRE(ninlil_submit(env.service, &submission, &first) == NINLIL_OK);
    REQUIRE(first.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    first_txn = first.transaction_id;

    (void)memset(&second, 0, sizeof(second));
    set_header(&second.abi_version, &second.struct_size, sizeof(second));
    REQUIRE(ninlil_submit(env.service, &submission, &second) == NINLIL_OK);
    REQUIRE(second.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
    REQUIRE(memcmp(
                second.transaction_id.bytes,
                first_txn.bytes,
                sizeof(first_txn.bytes))
        == 0);

    /* Different digest, same key → IDEMPOTENCY_CONFLICT (live). */
    {
        ninlil_submission_result_t conflict;
        env.payload[2] = 0x55u;
        REQUIRE(set_payload_content_digest(
            &submission.content_digest, env.payload, sizeof(env.payload)));
        (void)memset(&conflict, 0, sizeof(conflict));
        set_header(&conflict.abi_version, &conflict.struct_size, sizeof(conflict));
        REQUIRE(ninlil_submit(env.service, &submission, &conflict) == NINLIL_OK);
        REQUIRE(conflict.kind == NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT);
        REQUIRE(memcmp(
                    conflict.transaction_id.bytes,
                    first_txn.bytes,
                    sizeof(first_txn.bytes))
            == 0);
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(env_create_runtime(&env, 4u));
    descriptor = desired_descriptor(0xB2u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &reattached)
        == NINLIL_OK);

    /* Restart: same key/same digest ALREADY (restore original payload/digest). */
    (void)memset(env.payload, 0, sizeof(env.payload));
    REQUIRE(env_make_submission(&env, &submission));
    submission.idempotency_key.data = key;
    submission.idempotency_key.length = sizeof(key) - 1u;
    (void)memset(&second, 0, sizeof(second));
    set_header(&second.abi_version, &second.struct_size, sizeof(second));
    REQUIRE(ninlil_submit(reattached, &submission, &second) == NINLIL_OK);
    REQUIRE(second.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
    REQUIRE(memcmp(
                second.transaction_id.bytes,
                first_txn.bytes,
                sizeof(first_txn.bytes))
        == 0);

    /* Restart: different digest CONFLICT. */
    {
        ninlil_submission_result_t conflict;
        env.payload[2] = 0x66u;
        REQUIRE(set_payload_content_digest(
            &submission.content_digest, env.payload, sizeof(env.payload)));
        (void)memset(&conflict, 0, sizeof(conflict));
        set_header(&conflict.abi_version, &conflict.struct_size, sizeof(conflict));
        REQUIRE(ninlil_submit(reattached, &submission, &conflict) == NINLIL_OK);
        REQUIRE(conflict.kind == NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT);
    }

    platform_teardown(&env);
    return 0;
}

static ninlil_service_descriptor_t event_descriptor(uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor = desired_descriptor(app_tag);

    descriptor.service_id.data = (const uint8_t *)"event-fact";
    descriptor.service_id.length = sizeof("event-fact") - 1u;
    descriptor.schema_id.data = (const uint8_t *)"event-fact";
    descriptor.schema_id.length = sizeof("event-fact") - 1u;
    descriptor.family = NINLIL_FAMILY_EVENT_FACT;
    descriptor.direction = NINLIL_DIRECTION_UPLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
    descriptor.minimum_deadline_ms = NINLIL_NO_DEADLINE;
    descriptor.maximum_deadline_ms = NINLIL_NO_DEADLINE;
    descriptor.maximum_evidence_grace_ms = 0u;
    return descriptor;
}

static ninlil_origin_auth_status_t origin_allow_stub(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)memset(decision, 0, sizeof(*decision));
    set_header(&decision->abi_version, &decision->struct_size, sizeof(*decision));
    decision->allowed = 1u;
    decision->max_payload_bytes = 65536u;
    decision->max_active_spool_count = 32u;
    decision->max_active_spool_bytes = 65536u;
    decision->rate_window_ms = 10000u;
    decision->max_admissions_per_window = 20u;
    decision->max_attempts_per_retry_cycle = 8u;
    (void)request;
    decision->provider_revision = 1u;
    decision->grant_revision = 1u;
    decision->evaluated_at_ms = request->now.now_ms;
    decision->valid_from_ms = 0u;
    decision->expires_at_ms = UINT64_MAX;
    decision->clock_epoch_id = request->now.clock_epoch_id;
    set_digest(&decision->decision_digest, 0xD1u);
    set_id(&decision->provider_id, 0xD2u);
    set_id(&decision->grant_id, 0xD3u);
    return NINLIL_ORIGIN_AUTH_OK;
}

/* EventFact triple: same event/key/digest ALREADY; key conflict CONFLICT. */
static int test_t3_eventfact_triple_live_and_restart(void)
{
    spine_env_t env;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_t submission;
    ninlil_submission_result_t first;
    ninlil_submission_result_t second;
    ninlil_id128_t first_txn;
    ninlil_service_t *service = NULL;
    static const uint8_t key[] = "ef-triple";
    static const uint8_t key_alt[] = "ef-triple-b";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.origin.evaluate = origin_allow_stub;
    env.config = config_fixture_role(NINLIL_ROLE_ENDPOINT, 4u);
    REQUIRE(ninlil_runtime_create(&env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = event_descriptor(0xB4u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &service)
        == NINLIL_OK);

    (void)memset(&submission, 0, sizeof(submission));
    set_header(&submission.abi_version, &submission.struct_size, sizeof(submission));
    submission.schema_major = 1u;
    env_initialize_target(&env);
    submission.targets = &env.target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
    submission.evidence_grace_ms = 0u;
    submission.generation = 0u;
    set_id(&submission.event_id, 0xE1u);
    submission.idempotency_key.data = key;
    submission.idempotency_key.length = sizeof(key) - 1u;
    submission.payload.data = env.payload;
    submission.payload.length = sizeof(env.payload);
    env.payload[0] = 0xEFu;
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, env.payload, sizeof(env.payload)));

    (void)memset(&first, 0, sizeof(first));
    set_header(&first.abi_version, &first.struct_size, sizeof(first));
    REQUIRE(ninlil_submit(service, &submission, &first) == NINLIL_OK);
    REQUIRE(first.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    first_txn = first.transaction_id;

    (void)memset(&second, 0, sizeof(second));
    set_header(&second.abi_version, &second.struct_size, sizeof(second));
    REQUIRE(ninlil_submit(service, &submission, &second) == NINLIL_OK);
    REQUIRE(second.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);

    /* Same event ID, different idempotency key → CONFLICT. */
    {
        ninlil_submission_result_t conflict;
        submission.idempotency_key.data = key_alt;
        submission.idempotency_key.length = sizeof(key_alt) - 1u;
        (void)memset(&conflict, 0, sizeof(conflict));
        set_header(&conflict.abi_version, &conflict.struct_size, sizeof(conflict));
        REQUIRE(ninlil_submit(service, &submission, &conflict) == NINLIL_OK);
        REQUIRE(conflict.kind == NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT);
        REQUIRE(memcmp(
                    conflict.transaction_id.bytes,
                    first_txn.bytes,
                    sizeof(first_txn.bytes))
            == 0);
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(ninlil_runtime_create(&env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &service)
        == NINLIL_OK);
    submission.idempotency_key.data = key;
    submission.idempotency_key.length = sizeof(key) - 1u;
    (void)memset(&second, 0, sizeof(second));
    set_header(&second.abi_version, &second.struct_size, sizeof(second));
    REQUIRE(ninlil_submit(service, &submission, &second) == NINLIL_OK);
    REQUIRE(second.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
    REQUIRE(memcmp(
                second.transaction_id.bytes,
                first_txn.bytes,
                sizeof(first_txn.bytes))
        == 0);

    platform_teardown(&env);
    return 0;
}

static int test_submission_reserved_zero_rejected(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0xB3u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    submission.reserved_zero = 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env.service, &submission, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

/*
 * Full dual-map truth table: ABSENT / BOTH / OLD / PROPOSED / MIXED / THIRD,
 * independent durable map row survival across restart, and CU dual-truth.
 */
static int test_independent_map_rows_and_cu_classify(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_rt_v1_map_truth_class_t cls = NINLIL_RT_V1_MAP_TRUTH_CORRUPT;
    ninlil_id128_t proposed;
    ninlil_id128_t admitted_id;
    ninlil_digest256_t admitted_digest;
    ninlil_rt_service_slot_t *slot;
    ninlil_rt_transaction_slot_t *txn;
    static const uint8_t key[] = "map-row-key";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0xC1u));
    slot = &env.runtime->services[env.service->slot_index];
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    submission.idempotency_key.data = key;
    submission.idempotency_key.length = sizeof(key) - 1u;

    /* ABSENT */
    (void)memset(&proposed, 0, sizeof(proposed));
    proposed.bytes[0] = 0x99u;
    REQUIRE(ninlil_rt_v1_map_read_classify(
                env.runtime, slot, &submission, &submission.content_digest,
                &proposed, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_RT_V1_MAP_TRUTH_ABSENT);

    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    admitted_id = result.transaction_id;
    admitted_digest = result.canonical_submission_digest;

    /* BOTH after successful FULL admit */
    REQUIRE(ninlil_rt_v1_map_read_classify(
                env.runtime, slot, &submission, &admitted_digest,
                &admitted_id, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_RT_V1_MAP_TRUTH_BOTH);

    /* OLD: map exists for this key but proposed id differs and is absent */
    proposed = admitted_id;
    proposed.bytes[0] ^= 0xFFu;
    REQUIRE(ninlil_rt_v1_map_read_classify(
                env.runtime, slot, &submission, &admitted_digest,
                &proposed, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_RT_V1_MAP_TRUTH_OLD);

    /* MIXED: map for key points at admitted, proposed is a different live TX */
    {
        ninlil_submission_t sub_b;
        ninlil_submission_result_t res_b;
        static const uint8_t key_b[] = "map-row-key-b";
        REQUIRE(env_make_submission(&env, &sub_b));
        sub_b.idempotency_key.data = key_b;
        sub_b.idempotency_key.length = sizeof(key_b) - 1u;
        env.payload[3] = 0x77u;
        REQUIRE(set_payload_content_digest(
            &sub_b.content_digest, env.payload, sizeof(env.payload)));
        (void)memset(&res_b, 0, sizeof(res_b));
        set_header(&res_b.abi_version, &res_b.struct_size, sizeof(res_b));
        REQUIRE(ninlil_submit(env.service, &sub_b, &res_b) == NINLIL_OK);
        REQUIRE(res_b.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        /* Classify original key against B's txn id → map OLD + tx present = MIXED */
        REQUIRE(ninlil_rt_v1_map_read_classify(
                    env.runtime, slot, &submission, &admitted_digest,
                    &res_b.transaction_id, &cls)
            == NINLIL_OK);
        REQUIRE(cls == NINLIL_RT_V1_MAP_TRUTH_MIXED);
    }

    /* PROPOSED: durable map present, RAM TX slot cleared */
    txn = ninlil_rt_find_transaction(env.runtime, &admitted_id);
    REQUIRE(txn != NULL);
    (void)memset(txn, 0, sizeof(*txn));
    REQUIRE(ninlil_rt_v1_map_read_classify(
                env.runtime, slot, &submission, &admitted_digest,
                &admitted_id, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_RT_V1_MAP_TRUTH_PROPOSED);

    /* THIRD: restore TX with wrong canonical digest vs durable map */
    txn = ninlil_rt_alloc_transaction(env.runtime);
    REQUIRE(txn != NULL);
    txn->in_use = 1u;
    txn->origin_admission = 1u;
    txn->transaction_id = admitted_id;
    txn->canonical_submission_digest = admitted_digest;
    txn->canonical_submission_digest.bytes[0] ^= 0xAAu;
    txn->idempotency_key_length = (uint8_t)sizeof(key) - 1u;
    (void)memcpy(txn->idempotency_key, key, sizeof(key) - 1u);
    txn->service_app_id = slot->descriptor.local_application_instance_id;
    REQUIRE(ninlil_rt_v1_map_read_classify(
                env.runtime, slot, &submission, &admitted_digest,
                &admitted_id, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_RT_V1_MAP_TRUTH_THIRD);

    /* Restart: independent map row drives ALREADY_ADMITTED */
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(env_create_runtime(&env, 4u));
    {
        ninlil_service_descriptor_t descriptor = desired_descriptor(0xC1u);
        ninlil_service_callbacks_t callbacks;
        ninlil_service_t *svc = NULL;
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
        REQUIRE(ninlil_service_register(
                    env.runtime, &descriptor, &callbacks, &svc)
            == NINLIL_OK);
        (void)memset(env.payload, 0, sizeof(env.payload));
        REQUIRE(env_make_submission(&env, &submission));
        submission.idempotency_key.data = key;
        submission.idempotency_key.length = sizeof(key) - 1u;
        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(svc, &submission, &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
        REQUIRE(memcmp(
                    result.transaction_id.bytes,
                    admitted_id.bytes,
                    sizeof(admitted_id.bytes))
            == 0);
    }
    platform_teardown(&env);
    return 0;
}

typedef struct writepoint_hook_ctx {
    ninlil_test_storage_t *storage;
    const char *fault_hook;
    ninlil_storage_status_t fault_status;
    int armed;
    uint32_t seen_txn_put;
    uint32_t seen_map_put;
    uint32_t seen_commit;
} writepoint_hook_ctx_t;

static void writepoint_fault_hook(void *user, const char *name)
{
    writepoint_hook_ctx_t *ctx = (writepoint_hook_ctx_t *)user;

    if (ctx == NULL || name == NULL) {
        return;
    }
    if (strcmp(name, "admission.after_txn_put") == 0) {
        ctx->seen_txn_put += 1u;
    }
    if (strcmp(name, "admission.after_idempotency_map_put") == 0) {
        ctx->seen_map_put += 1u;
    }
    if (strcmp(name, "admission.after_full_commit") == 0) {
        ctx->seen_commit += 1u;
    }
    if (ctx->armed != 0 && ctx->fault_hook != NULL
        && strcmp(name, ctx->fault_hook) == 0) {
        if (ctx->fault_status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            (void)ninlil_test_storage_fault_enqueue(
                ctx->storage,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                0);
        } else {
            (void)ninlil_test_storage_fault_enqueue(
                ctx->storage,
                NINLIL_TEST_STORAGE_OP_PUT,
                ctx->fault_status,
                1u,
                0,
                0);
        }
        ctx->armed = 0;
    }
}

/*
 * Production durable map FULL: exact key/value, head_witness = real
 * witness_digest, ACTIVE WITNESS_HEADER + MANIFEST_CHUNK membership, and
 * writer-gate SUBMIT (not SERVICE_REGISTER) for admission quota rewrite.
 */
static int test_map_witness_membership_and_writer_gate_separation(void)
{
    spine_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_rt_service_slot_t *slot;
    ninlil_id128_t admitted_id;
    static const uint8_t key[] = "witness-map-key";
    uint8_t scope[255];
    uint16_t scope_len = 0u;
    uint8_t map_key[64];
    uint8_t map_key_len = 0u;
    uint8_t value[4096];
    uint32_t value_len = 0u;
    int present = 0;
    ninlil_model_domain_typed_record_t typed;
    ninlil_model_domain_digest_t witness_id;
    ninlil_model_domain_digest_t value_dig;
    ninlil_model_domain_key_t header_key;
    ninlil_model_domain_key_t chunk_key;
    ninlil_bytes_view_t op_identity;
    ninlil_model_domain_witness_header_t wh;
    ninlil_model_domain_witness_chunk_t chunk;
    ninlil_model_domain_envelope_t env_hdr;
    ninlil_model_domain_envelope_t env_chunk;
    uint8_t chunk_components[34];
    ninlil_model_domain_digest_t chunk_identity;
    ninlil_v1_durable_record_kind_t kind;
    uint32_t i;
    int member_found = 0;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    REQUIRE(env_register_service(&env, 0xD1u));
    slot = &env.runtime->services[env.service->slot_index];
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    submission.idempotency_key.data = key;
    submission.idempotency_key.length = sizeof(key) - 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    admitted_id = result.transaction_id;

    /* Rebuild IDEMPOTENCY_MAP key and exact-get durable row. */
    {
        uint32_t o = 0u;
        uint8_t ns_len = (uint8_t)slot->descriptor.namespace_id.length;
        uint8_t svc_len = (uint8_t)slot->descriptor.service_id.length;
        (void)memcpy(
            &scope[o],
            slot->descriptor.local_application_instance_id.bytes,
            16u);
        o += 16u;
        scope[o++] = ns_len;
        (void)memcpy(
            &scope[o], slot->descriptor.namespace_id.data, ns_len);
        o += ns_len;
        scope[o++] = svc_len;
        (void)memcpy(
            &scope[o], slot->descriptor.service_id.data, svc_len);
        o += svc_len;
        scope_len = (uint16_t)o;
    }
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
                scope,
                scope_len,
                key,
                (uint16_t)(sizeof(key) - 1u),
                map_key,
                &map_key_len)
        == NINLIL_OK);

    {
        const ninlil_storage_ops_t *storage = env.runtime->platform->storage;
        ninlil_storage_txn_t txn = NULL;
        ninlil_mut_bytes_t mv;
        ninlil_storage_status_t st;
        REQUIRE(storage->begin(
                    storage->user,
                    env.runtime->storage,
                    NINLIL_STORAGE_READ_ONLY,
                    &txn)
            == NINLIL_STORAGE_OK);
        mv.data = value;
        mv.capacity = sizeof(value);
        mv.length = 0u;
        st = storage->get(
            storage->user,
            txn,
            (ninlil_bytes_view_t){map_key, map_key_len},
            &mv);
        (void)storage->rollback(storage->user, txn);
        REQUIRE(st == NINLIL_STORAGE_OK);
        present = 1;
        value_len = mv.length;
    }
    REQUIRE(present != 0);
    REQUIRE(ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){map_key, map_key_len},
                (ninlil_bytes_view_t){value, value_len},
                &typed)
        == NINLIL_OK);
    REQUIRE(typed.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP);

    op_identity.data = admitted_id.bytes;
    op_identity.length = 16u;
    REQUIRE(ninlil_model_domain_witness_identity_digest(
                2u, op_identity, &witness_id)
        == NINLIL_OK);
    REQUIRE(memcmp(
                typed.envelope.header.head_witness_digest,
                witness_id.bytes,
                32u)
        == 0);
    /* Reject synthetic V1-LAB tag preimage residual. */
    {
        uint8_t synth[50];
        ninlil_model_domain_digest_t synth_dig;
        (void)memcpy(synth, "IM", 2u);
        (void)memcpy(&synth[2], admitted_id.bytes, 16u);
        (void)memcpy(
            &synth[18],
            result.canonical_submission_digest.bytes,
            32u);
        REQUIRE(ninlil_model_domain_sha256(synth, 50u, &synth_dig) == NINLIL_OK);
        REQUIRE(memcmp(synth_dig.bytes, witness_id.bytes, 32u) != 0);
    }

    REQUIRE(ninlil_model_domain_value_digest(
                (ninlil_bytes_view_t){value, value_len}, &value_dig)
        == NINLIL_OK);

    /* WITNESS_HEADER exact key/value + ACTIVE membership. */
    REQUIRE(ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER,
                NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
                (ninlil_bytes_view_t){witness_id.bytes, 32u},
                &header_key)
        == NINLIL_OK);
    {
        const ninlil_storage_ops_t *storage = env.runtime->platform->storage;
        ninlil_storage_txn_t txn = NULL;
        ninlil_mut_bytes_t mv;
        REQUIRE(storage->begin(
                    storage->user,
                    env.runtime->storage,
                    NINLIL_STORAGE_READ_ONLY,
                    &txn)
            == NINLIL_STORAGE_OK);
        mv.data = value;
        mv.capacity = sizeof(value);
        mv.length = 0u;
        REQUIRE(storage->get(
                    storage->user,
                    txn,
                    (ninlil_bytes_view_t){header_key.bytes, header_key.length},
                    &mv)
            == NINLIL_STORAGE_OK);
        (void)storage->rollback(storage->user, txn);
        value_len = mv.length;
    }
    REQUIRE(ninlil_v1_durable_classify_row(
                (ninlil_bytes_view_t){header_key.bytes, header_key.length},
                (ninlil_bytes_view_t){value, value_len},
                &kind)
        == NINLIL_OK);
    REQUIRE(kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEADER);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
                (ninlil_bytes_view_t){header_key.bytes, header_key.length},
                (ninlil_bytes_view_t){value, value_len})
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT,
                (ninlil_bytes_view_t){header_key.bytes, header_key.length},
                (ninlil_bytes_view_t){value, value_len})
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(ninlil_model_domain_decode_envelope(
                (ninlil_bytes_view_t){value, value_len}, &env_hdr)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_decode_witness_header(env_hdr.body, &wh)
        == NINLIL_OK);
    REQUIRE(wh.operation_kind == 2u);
    REQUIRE(wh.witness_state == NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE);
    REQUIRE(wh.member_count == 1u);
    REQUIRE(wh.chunk_count == 1u);

    (void)memcpy(chunk_components, witness_id.bytes, 32u);
    chunk_components[32] = 0u;
    chunk_components[33] = 0u;
    REQUIRE(ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
                (ninlil_bytes_view_t){chunk_components, 34u},
                &chunk_identity)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
                NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
                (ninlil_bytes_view_t){chunk_identity.bytes, 32u},
                &chunk_key)
        == NINLIL_OK);
    {
        const ninlil_storage_ops_t *storage = env.runtime->platform->storage;
        ninlil_storage_txn_t txn = NULL;
        ninlil_mut_bytes_t mv;
        REQUIRE(storage->begin(
                    storage->user,
                    env.runtime->storage,
                    NINLIL_STORAGE_READ_ONLY,
                    &txn)
            == NINLIL_STORAGE_OK);
        mv.data = value;
        mv.capacity = sizeof(value);
        mv.length = 0u;
        REQUIRE(storage->get(
                    storage->user,
                    txn,
                    (ninlil_bytes_view_t){chunk_key.bytes, chunk_key.length},
                    &mv)
            == NINLIL_STORAGE_OK);
        (void)storage->rollback(storage->user, txn);
        value_len = mv.length;
    }
    REQUIRE(ninlil_v1_durable_classify_row(
                (ninlil_bytes_view_t){chunk_key.bytes, chunk_key.length},
                (ninlil_bytes_view_t){value, value_len},
                &kind)
        == NINLIL_OK);
    REQUIRE(kind == NINLIL_V1_DURABLE_KIND_DOM_WITNESS_MANIFEST_CHUNK);
    REQUIRE(ninlil_model_domain_decode_envelope(
                (ninlil_bytes_view_t){value, value_len}, &env_chunk)
        == NINLIL_OK);
    REQUIRE(ninlil_model_domain_decode_witness_chunk(env_chunk.body, &chunk)
        == NINLIL_OK);
    REQUIRE(chunk.entry_count == 1u);
    for (i = 0u; i < chunk.entry_count; ++i) {
        if (chunk.entries[i].key_length == map_key_len
            && memcmp(chunk.entries[i].key_bytes, map_key, map_key_len) == 0) {
            REQUIRE(chunk.entries[i].action
                == NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE);
            REQUIRE(chunk.entries[i].old_present == 0u);
            REQUIRE(chunk.entries[i].new_present == 1u);
            REQUIRE(memcmp(
                        chunk.entries[i].new_value_digest,
                        value_dig.bytes,
                        32u)
                == 0);
            member_found = 1;
        }
    }
    REQUIRE(member_found != 0);

    /* SERVICE ledger rewrite during admission is SUBMIT-gated. */
    {
        uint8_t svc_key[NINLIL_RT_V1_SERVICE_LEDGER_KEY_MAX_BYTES];
        uint32_t svc_key_len = 0u;
        uint8_t svc_value[NINLIL_RT_V1_SERVICE_LEDGER_VALUE_MAX_BYTES];
        uint32_t svc_value_len = 0u;
        REQUIRE(ninlil_rt_v1_spine_service_ledger_key(
                    &slot->descriptor, svc_key, sizeof(svc_key), &svc_key_len)
            == NINLIL_OK);
        {
            const ninlil_storage_ops_t *storage =
                env.runtime->platform->storage;
            ninlil_storage_txn_t txn = NULL;
            ninlil_mut_bytes_t mv;
            REQUIRE(storage->begin(
                        storage->user,
                        env.runtime->storage,
                        NINLIL_STORAGE_READ_ONLY,
                        &txn)
                == NINLIL_STORAGE_OK);
            mv.data = svc_value;
            mv.capacity = sizeof(svc_value);
            mv.length = 0u;
            REQUIRE(storage->get(
                        storage->user,
                        txn,
                        (ninlil_bytes_view_t){svc_key, svc_key_len},
                        &mv)
                == NINLIL_STORAGE_OK);
            (void)storage->rollback(storage->user, txn);
            svc_value_len = mv.length;
        }
        REQUIRE(ninlil_v1_durable_writer_gate_check(
                    NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
                    (ninlil_bytes_view_t){svc_key, svc_key_len},
                    (ninlil_bytes_view_t){svc_value, svc_value_len})
            == NINLIL_OK);
        REQUIRE(ninlil_v1_durable_writer_gate_check(
                    NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT,
                    (ninlil_bytes_view_t){svc_key, svc_key_len},
                    (ninlil_bytes_view_t){svc_value, svc_value_len})
            == NINLIL_OK);
    }

    platform_teardown(&env);
    return 0;
}

/* Every admission writepoint: PUT fail or CU → no publish; restart clean. */
static int test_admission_writepoint_commit_unknown_fail_closed(void)
{
    static const struct {
        const char *hook;
        ninlil_storage_status_t status;
        ninlil_status_t expect;
    } cases[] = {
        { "admission.before_txn_put", NINLIL_STORAGE_IO_ERROR,
            NINLIL_E_STORAGE },
        { "admission.before_idempotency_map_put", NINLIL_STORAGE_IO_ERROR,
            NINLIL_E_STORAGE },
        { "admission.before_witness_chunk_put", NINLIL_STORAGE_IO_ERROR,
            NINLIL_E_STORAGE },
        { "admission.before_witness_header_put", NINLIL_STORAGE_IO_ERROR,
            NINLIL_E_STORAGE },
        { "admission.before_full_commit", NINLIL_STORAGE_COMMIT_UNKNOWN,
            NINLIL_E_STORAGE_COMMIT_UNKNOWN },
        { "admission.before_idempotency_map_put",
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            NINLIL_E_STORAGE_COMMIT_UNKNOWN },
    };
    size_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        spine_env_t env;
        ninlil_submission_t submission;
        ninlil_submission_result_t result;
        writepoint_hook_ctx_t hook;
        uint32_t txn_before;
        static const uint8_t key[] = "cu-admit-key";
        uint8_t key_bytes[16];

        (void)memset(&env, 0, sizeof(env));
        (void)memset(&hook, 0, sizeof(hook));
        REQUIRE(platform_init(&env));
        REQUIRE(env_create_runtime(&env, 4u));
        REQUIRE(env_register_service(&env, (uint8_t)(0xC2u + case_index)));
        env_initialize_target(&env);
        REQUIRE(env_make_submission(&env, &submission));
        (void)memcpy(key_bytes, key, sizeof(key) - 1u);
        key_bytes[0] = (uint8_t)(0x40u + case_index);
        submission.idempotency_key.data = key_bytes;
        submission.idempotency_key.length = sizeof(key) - 1u;
        txn_before = env.runtime->transaction_count;

        hook.storage = env.storage_fixture;
        hook.fault_hook = cases[case_index].hook;
        hook.fault_status = cases[case_index].status;
        hook.armed = 1;
        env.runtime->private_transition_hook = writepoint_fault_hook;
        env.runtime->private_transition_hook_user = &hook;

        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(env.service, &submission, &result)
            == cases[case_index].expect);
        REQUIRE(env.runtime->transaction_count == txn_before);

        if (cases[case_index].status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            REQUIRE(env.runtime->commit_unknown_fence != 0u);
            REQUIRE(ninlil_rt_validate_mutation_allowed(env.runtime)
                == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        }

        /*
         * Destroy after CU returns COMMIT_UNKNOWN by design (docs cleanup path)
         * but still releases the instance for recreate recovery.
         */
        {
            ninlil_status_t destroy_st = ninlil_runtime_destroy(env.runtime);
            REQUIRE(destroy_st == NINLIL_OK
                || destroy_st == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        }
        env.runtime = NULL;
        env.service = NULL;
        REQUIRE(env_create_runtime(&env, 4u));
        {
            ninlil_service_descriptor_t descriptor =
                desired_descriptor((uint8_t)(0xC2u + case_index));
            ninlil_service_callbacks_t callbacks;
            ninlil_service_t *svc = NULL;
            (void)memset(&callbacks, 0, sizeof(callbacks));
            set_header(
                &callbacks.abi_version,
                &callbacks.struct_size,
                sizeof(callbacks));
            REQUIRE(ninlil_service_register(
                        env.runtime, &descriptor, &callbacks, &svc)
                == NINLIL_OK);
            REQUIRE(env_make_submission(&env, &submission));
            submission.idempotency_key.data = key_bytes;
            submission.idempotency_key.length = sizeof(key) - 1u;
            (void)memset(&result, 0, sizeof(result));
            set_header(
                &result.abi_version, &result.struct_size, sizeof(result));
            REQUIRE(ninlil_submit(svc, &submission, &result) == NINLIL_OK);
            /* Fail-closed not-committed path must admit cleanly as new. */
            REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        }
        platform_teardown(&env);
    }

    /* Successful path + power-cut simulate_crash → durable BOTH + ALREADY */
    {
        spine_env_t env;
        ninlil_submission_t submission;
        ninlil_submission_result_t result;
        ninlil_id128_t admitted_id;
        static const uint8_t key[] = "crash-ok-key";

        (void)memset(&env, 0, sizeof(env));
        REQUIRE(platform_init(&env));
        REQUIRE(env_create_runtime(&env, 4u));
        REQUIRE(env_register_service(&env, 0xCAu));
        env_initialize_target(&env);
        REQUIRE(env_make_submission(&env, &submission));
        submission.idempotency_key.data = key;
        submission.idempotency_key.length = sizeof(key) - 1u;
        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        admitted_id = result.transaction_id;

        ninlil_test_storage_simulate_crash(env.storage_fixture);
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
        env.runtime = NULL;
        env.service = NULL;
        REQUIRE(env_create_runtime(&env, 4u));
        {
            ninlil_service_descriptor_t descriptor = desired_descriptor(0xCAu);
            ninlil_service_callbacks_t callbacks;
            ninlil_service_t *svc = NULL;
            (void)memset(&callbacks, 0, sizeof(callbacks));
            set_header(
                &callbacks.abi_version,
                &callbacks.struct_size,
                sizeof(callbacks));
            REQUIRE(ninlil_service_register(
                        env.runtime, &descriptor, &callbacks, &svc)
                == NINLIL_OK);
            (void)memset(env.payload, 0, sizeof(env.payload));
            REQUIRE(env_make_submission(&env, &submission));
            submission.idempotency_key.data = key;
            submission.idempotency_key.length = sizeof(key) - 1u;
            (void)memset(&result, 0, sizeof(result));
            set_header(
                &result.abi_version, &result.struct_size, sizeof(result));
            REQUIRE(ninlil_submit(svc, &submission, &result) == NINLIL_OK);
            REQUIRE(result.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
            REQUIRE(memcmp(
                        result.transaction_id.bytes,
                        admitted_id.bytes,
                        sizeof(admitted_id.bytes))
                == 0);
        }
        platform_teardown(&env);
    }
    return 0;
}

/* Quota window boundary + future/uncertain clock fail-closed. */
static int test_quota_boundary_and_clock_fail_closed(void)
{
    spine_env_t env;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service = NULL;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_metrics_snapshot_t metrics;
    static const uint8_t key_a[] = "quota-a";
    static const uint8_t key_b[] = "quota-b";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    descriptor = desired_descriptor(0xD0u);
    descriptor.max_admissions_per_window = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &service)
        == NINLIL_OK);
    env_initialize_target(&env);

    REQUIRE(env_make_submission(&env, &submission));
    submission.idempotency_key.data = key_a;
    submission.idempotency_key.length = sizeof(key_a) - 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    /* Same window second distinct admission → RATE_EXHAUSTED (boundary). */
    env.payload[1] = 0x91u;
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, env.payload, sizeof(env.payload)));
    submission.idempotency_key.data = key_b;
    submission.idempotency_key.length = sizeof(key_b) - 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_RATE_EXHAUSTED);
    /*
     * NIN-INV-011: a rejected, otherwise-valid submission remains visible in
     * the submission denominator instead of disappearing from delivery-rate
     * accounting.
     */
    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(&metrics.abi_version, &metrics.struct_size, sizeof(metrics));
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics) == NINLIL_OK);
    REQUIRE(metrics.submission_calls == 2u);
    REQUIRE(metrics.admitted_ready == 1u);
    REQUIRE(metrics.rejected == 1u);

    /* Uncertain clock fail-closed before quota mutation. */
    REQUIRE(ninlil_test_clock_script(
                env.clock, NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u)
        == 1);
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(service, &submission, &result)
        == NINLIL_E_CLOCK_UNCERTAIN);

    /* Advance past fixed window → counters rollover, admit allowed again. */
    REQUIRE(ninlil_test_clock_advance(
                env.clock, descriptor.admission_window_ms)
        == 1);
    env.payload[1] = 0x92u;
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, env.payload, sizeof(env.payload)));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    /* Epoch change (trusted recover onto new epoch) → fail-closed then rollover. */
    {
        ninlil_id128_t fresh;
        ninlil_time_sample_t trusted;
        static const uint8_t key_c[] = "quota-c";
        set_id(&fresh, 0xEEu);
        REQUIRE(ninlil_test_clock_rollback(env.clock, &fresh) == 1);
        /*
         * While UNCERTAIN after rollback, a *new* idempotency key must fail
         * closed on the trusted-clock sample. Same-key ALREADY terminates
         * before clock (docs/12 exact admission order) and is not a clock
         * observation.
         */
        {
            static const uint8_t key_uncertain[] = "quota-uncertain";
            submission.idempotency_key.data = key_uncertain;
            submission.idempotency_key.length = sizeof(key_uncertain) - 1u;
            env.payload[1] = 0x94u;
            REQUIRE(set_payload_content_digest(
                &submission.content_digest, env.payload, sizeof(env.payload)));
        }
        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        {
            ninlil_status_t clock_st =
                ninlil_submit(service, &submission, &result);
            REQUIRE(clock_st == NINLIL_E_CLOCK_UNCERTAIN
                || clock_st == NINLIL_E_DEGRADED);
        }
        (void)memset(&trusted, 0, sizeof(trusted));
        set_header(
            &trusted.abi_version, &trusted.struct_size, sizeof(trusted));
        trusted.clock_epoch_id = fresh;
        trusted.now_ms = descriptor.admission_window_ms * 3u;
        trusted.trust = NINLIL_CLOCK_TRUSTED;
        REQUIRE(ninlil_test_clock_recover(env.clock, &trusted) == 1);
        env.payload[1] = 0x93u;
        REQUIRE(set_payload_content_digest(
            &submission.content_digest, env.payload, sizeof(env.payload)));
        submission.idempotency_key.data = key_c;
        submission.idempotency_key.length = sizeof(key_c) - 1u;
        (void)memset(&result, 0, sizeof(result));
        set_header(&result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(service, &submission, &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    }

    platform_teardown(&env);
    return 0;
}

/*
 * Exhaustive ABI precedence for all 14 public output APIs: bad version,
 * undersize struct_size, and unchanged poison buffer on ABI_MISMATCH.
 */
static int test_all_14_public_api_abi_precedence(void)
{
    spine_env_t env;
    ninlil_id128_t id;
    uint8_t poison = 0xA5u;
    ninlil_cancel_result_t cancel;
    ninlil_submission_result_t offer;
    ninlil_submission_result_t submit_out;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step;
    ninlil_event_resume_request_t resume_req;
    ninlil_event_resume_result_t resume_out;
    ninlil_event_discard_request_t discard_req;
    ninlil_event_discard_result_t discard_out;
    ninlil_transaction_snapshot_t query;
    ninlil_query_t list_query;
    ninlil_transaction_page_t page;
    ninlil_capacity_snapshot_t capacity;
    ninlil_metrics_snapshot_t metrics;
    ninlil_delivery_token_t token;
    ninlil_application_result_t app_result;
    ninlil_submission_t submission;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *svc = NULL;

    (void)memset(&env, 0, sizeof(env));
    set_id(&id, 0xABu);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));

    /* 1 cancel_request */
    (void)memset(&cancel, poison, sizeof(cancel));
    cancel.abi_version = 0u;
    cancel.struct_size = (uint16_t)sizeof(cancel);
    REQUIRE(ninlil_cancel_request(env.runtime, &id, &cancel)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&cancel)[4] == poison);

    /* 2 offer_accept */
    (void)memset(&offer, poison, sizeof(offer));
    offer.abi_version = NINLIL_ABI_VERSION;
    offer.struct_size = 2u;
    REQUIRE(ninlil_offer_accept(env.runtime, &id, &offer)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&offer)[4] == poison);

    /* 3 runtime_step */
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    (void)memset(&step, poison, sizeof(step));
    step.abi_version = 0xFFFFu;
    step.struct_size = (uint16_t)sizeof(step);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&step)[4] == poison);

    /* 4 event_resume */
    (void)memset(&resume_req, 0, sizeof(resume_req));
    set_header(
        &resume_req.abi_version, &resume_req.struct_size, sizeof(resume_req));
    (void)memset(&resume_out, poison, sizeof(resume_out));
    resume_out.abi_version = 0u;
    resume_out.struct_size = (uint16_t)sizeof(resume_out);
    REQUIRE(ninlil_event_resume(env.runtime, &id, &resume_req, &resume_out)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&resume_out)[4] == poison);

    /* 5 event_discard */
    (void)memset(&discard_req, 0, sizeof(discard_req));
    set_header(
        &discard_req.abi_version,
        &discard_req.struct_size,
        sizeof(discard_req));
    (void)memset(&discard_out, poison, sizeof(discard_out));
    discard_out.abi_version = NINLIL_ABI_VERSION;
    discard_out.struct_size = 4u;
    REQUIRE(ninlil_event_discard(env.runtime, &id, &discard_req, &discard_out)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&discard_out)[4] == poison);

    /* 6 transaction_query */
    (void)memset(&query, poison, sizeof(query));
    query.abi_version = 0u;
    query.struct_size = (uint16_t)sizeof(query);
    REQUIRE(ninlil_transaction_query(env.runtime, &id, &query)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&query)[4] == poison);

    /* 7 transaction_list */
    (void)memset(&list_query, 0, sizeof(list_query));
    set_header(
        &list_query.abi_version, &list_query.struct_size, sizeof(list_query));
    list_query.include_terminal = 1u;
    list_query.include_nonterminal = 1u;
    (void)memset(&page, poison, sizeof(page));
    page.abi_version = NINLIL_ABI_VERSION;
    page.struct_size = 2u;
    REQUIRE(ninlil_transaction_list(env.runtime, &list_query, &page)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&page)[4] == poison);

    /* 8 capacity_snapshot */
    (void)memset(&capacity, poison, sizeof(capacity));
    capacity.abi_version = 0u;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    REQUIRE(ninlil_capacity_snapshot(env.runtime, &capacity)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&capacity)[4] == poison);

    /* 9 metrics_snapshot */
    (void)memset(&metrics, poison, sizeof(metrics));
    metrics.abi_version = NINLIL_ABI_VERSION;
    metrics.struct_size = 0u;
    REQUIRE(ninlil_metrics_snapshot(env.runtime, &metrics)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&metrics)[4] == poison);

    /* 10 submit (out_result ABI) */
    REQUIRE(env_register_service(&env, 0xD1u));
    env_initialize_target(&env);
    REQUIRE(env_make_submission(&env, &submission));
    (void)memset(&submit_out, poison, sizeof(submit_out));
    submit_out.abi_version = 0u;
    submit_out.struct_size = (uint16_t)sizeof(submit_out);
    REQUIRE(ninlil_submit(env.service, &submission, &submit_out)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(((const uint8_t *)&submit_out)[4] == poison);

    /* 11 delivery_complete (token/result ABI) */
    (void)memset(&token, poison, sizeof(token));
    token.abi_version = 0u;
    token.struct_size = (uint16_t)sizeof(token);
    (void)memset(&app_result, 0, sizeof(app_result));
    set_header(
        &app_result.abi_version, &app_result.struct_size, sizeof(app_result));
    REQUIRE(ninlil_delivery_complete(env.runtime, &token, &app_result)
        == NINLIL_E_ABI_MISMATCH);

    /* 12 service_register descriptor ABI */
    descriptor = desired_descriptor(0xD2u);
    descriptor.abi_version = 0u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    svc = (ninlil_service_t *)0x1u;
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &svc)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(svc == NULL);

    /* 13 runtime_create config ABI */
    {
        ninlil_runtime_t *rt = (ninlil_runtime_t *)0x1u;
        ninlil_runtime_config_t cfg = env.config;
        cfg.abi_version = 0u;
        REQUIRE(ninlil_runtime_create(&cfg, &env.platform, &rt)
            == NINLIL_E_ABI_MISMATCH);
        REQUIRE(rt == NULL);
    }

    /* 14 destroy: null is INVALID_ARGUMENT (no output buffer). */
    REQUIRE(ninlil_runtime_destroy(NULL) == NINLIL_E_INVALID_ARGUMENT);

    /* Exact struct_size OK for cancel; oversize still OK (extensible write). */
    {
        typedef struct cancel_oversize {
            ninlil_cancel_result_t known;
            uint8_t tail[8];
        } cancel_oversize_t;
        cancel_oversize_t big;
        (void)memset(&big, poison, sizeof(big));
        big.known.abi_version = NINLIL_ABI_VERSION;
        big.known.struct_size = (uint16_t)sizeof(big);
        REQUIRE(ninlil_cancel_request(env.runtime, &id, &big.known)
            == NINLIL_E_NOT_FOUND
            || ninlil_cancel_request(env.runtime, &id, &big.known)
                == NINLIL_OK
            || ninlil_cancel_request(env.runtime, &id, &big.known)
                == NINLIL_E_UNSUPPORTED);
        /* Library must not write past known cancel fields into tail. */
        {
            size_t ti;
            for (ti = 0u; ti < sizeof(big.tail); ++ti) {
                REQUIRE(big.tail[ti] == poison);
            }
        }
    }

    /* Wrong-thread precedence after valid headers (owner check). */
    ninlil_test_execution_set_context_id(env.execution, 2u);
    (void)memset(&cancel, 0, sizeof(cancel));
    set_header(&cancel.abi_version, &cancel.struct_size, sizeof(cancel));
    REQUIRE(ninlil_cancel_request(env.runtime, &id, &cancel)
        == NINLIL_E_WRONG_THREAD);

    platform_teardown(&env);
    return 0;
}

int main(void)
{
    int rc = 0;

    if (test_create_destroy_happy() != 0) {
        rc = 1;
    }
    if (test_create_null_invalid() != 0) {
        rc = 1;
    }
    if (test_destroy_null_invalid() != 0) {
        rc = 1;
    }
    if (test_register_submit_cancel_step_happy() != 0) {
        rc = 1;
    }
    if (test_register_exact_reattach() != 0) {
        rc = 1;
    }
    if (test_register_null_invalid() != 0) {
        rc = 1;
    }
    if (test_register_capacity_exhausted() != 0) {
        rc = 1;
    }
    if (test_service_register_atomic_faults_and_restart() != 0) {
        rc = 1;
    }
    if (test_service_capacity_block_atomic_faults_and_restart() != 0) {
        rc = 1;
    }
    if (test_submit_null_invalid() != 0) {
        rc = 1;
    }
    if (test_cancel_not_found() != 0) {
        rc = 1;
    }
    if (test_cancel_targeted_deadline_priority() != 0) {
        rc = 1;
    }
    if (test_cancel_targeted_clock_and_counter_fences() != 0) {
        rc = 1;
    }
    if (test_cancel_runtime_global_clock_fence() != 0) {
        rc = 1;
    }
    if (test_cancel_retry_cold_restart_owner_chronology() != 0) {
        rc = 1;
    }
    if (test_cancel_receipt_deadline_boundary() != 0) {
        rc = 1;
    }
    if (test_cancel_command_timer_order_and_evidence_close() != 0) {
        rc = 1;
    }
    if (test_prepared_command_deadline_and_evidence_close() != 0) {
        rc = 1;
    }
    if (test_cancel_wrong_role() != 0) {
        rc = 1;
    }
    if (test_wrong_thread() != 0) {
        rc = 1;
    }
    if (test_cancel_zero_txn_invalid() != 0) {
        rc = 1;
    }
    if (test_offer_accept_unsupported() != 0) {
        rc = 1;
    }
    if (test_capacity_snapshot_contract() != 0) {
        rc = 1;
    }
    if (test_metrics_snapshot_extensible_output() != 0) {
        rc = 1;
    }
    if (test_runtime_step_budget_and_extensible_result() != 0) {
        rc = 1;
    }
    if (test_transaction_query_and_list_contract() != 0) {
        rc = 1;
    }
    if (test_reserved_family_register_unsupported() != 0) {
        rc = 1;
    }
    if (test_output_abi_mismatch_preserves_buffer() != 0) {
        rc = 1;
    }
    if (test_service_registry_restart_reattach_and_quota_window() != 0) {
        rc = 1;
    }
    if (test_t2_content_digest_mismatch_zero_effects() != 0) {
        rc = 1;
    }
    if (test_t3_idempotency_live_and_restart() != 0) {
        rc = 1;
    }
    if (test_t3_eventfact_triple_live_and_restart() != 0) {
        rc = 1;
    }
    if (test_submission_reserved_zero_rejected() != 0) {
        rc = 1;
    }
    if (test_independent_map_rows_and_cu_classify() != 0) {
        rc = 1;
    }
    if (test_map_witness_membership_and_writer_gate_separation() != 0) {
        rc = 1;
    }
    if (test_admission_writepoint_commit_unknown_fail_closed() != 0) {
        rc = 1;
    }
    if (test_quota_boundary_and_clock_fail_closed() != 0) {
        rc = 1;
    }
    if (test_all_14_public_api_abi_precedence() != 0) {
        rc = 1;
    }

    if (rc != 0) {
        (void)fprintf(stderr, "v1_runtime_spine_test failed\n");
    }
    return rc;
}
