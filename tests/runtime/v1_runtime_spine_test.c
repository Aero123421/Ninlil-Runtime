/*
 * V1-LAB unit 2a: public Runtime lifecycle spine (B1-a/b/c admission slice).
 * Covers runtime_create/destroy, service_register, submit admission, cancel
 * admission, runtime_step bounded work budget. Delivery/durable deep path is 2b.
 */

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
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

static int env_register_service_descriptor(
    spine_env_t *env,
    const ninlil_service_descriptor_t *descriptor)
{
    ninlil_service_callbacks_t callbacks;
    ninlil_status_t status;

    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    status = ninlil_service_register(
        env->runtime, descriptor, &callbacks, &env->service);
    if (status != NINLIL_OK) {
        return (int)status;
    }
    REQUIRE(env->service != NULL);
    return (int)NINLIL_OK;
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
    set_digest(&submission->content_digest, 0x22u);
    env->payload[0] = 0xABu;
    return 1;
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
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result) == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(submit_result.reason == NINLIL_REASON_NONE);

    (void)memset(&cancel_result, 0, sizeof(cancel_result));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &submit_result.transaction_id, &cancel_result)
        == NINLIL_OK);
    REQUIRE(cancel_result.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 1u;
    budget.max_callbacks = 1u;
    budget.max_state_transitions = 1u;
    budget.max_bearer_sends = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
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
    ninlil_service_descriptor_t second =
        desired_descriptor_with_service(0x74u, "absolute-state-b");

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 1u));
    REQUIRE(env_register_service(&env, 0x73u));
    REQUIRE(env_register_service_descriptor(&env, &second)
        == (int)NINLIL_E_CAPACITY_EXHAUSTED);
    platform_teardown(&env);
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

    (void)memset(&env, 0, sizeof(env));
    set_id(&missing, 0x99u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create_runtime(&env, 4u));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_cancel_request(env.runtime, &missing, &result)
        == NINLIL_E_NOT_FOUND);
    platform_teardown(&env);
    return 0;
}

static int test_cancel_wrong_role(void)
{
    spine_env_t env;
    ninlil_id128_t txn_id;
    ninlil_cancel_result_t result;

    (void)memset(&env, 0, sizeof(env));
    set_id(&txn_id, 0x88u);
    REQUIRE(platform_init(&env));
    env.config = config_fixture_role(NINLIL_ROLE_ENDPOINT, 4u);
    REQUIRE(ninlil_runtime_create(&env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_cancel_request(env.runtime, &txn_id, &result)
        == NINLIL_E_UNSUPPORTED);
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
    REQUIRE(ninlil_offer_accept(env.runtime, &offer_id, &result)
        == NINLIL_E_UNSUPPORTED);
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
    if (test_submit_null_invalid() != 0) {
        rc = 1;
    }
    if (test_cancel_not_found() != 0) {
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

    if (rc != 0) {
        (void)fprintf(stderr, "v1_runtime_spine_test failed\n");
    }
    return rc;
}
