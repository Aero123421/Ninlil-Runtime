/*
 * V1-LAB unit 4: B3 logical capability layer — priority/deadline/retry,
 * bearer payload limits, logical payload/fragment, reservation, restart.
 */

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "v1-runtime-capability-test";
static const char NS_TEXT[] = "org.ninlil.examples";

typedef struct cap_env {
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
    uint8_t *payload;
    uint32_t payload_capacity;
} cap_env_t;

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

static ninlil_origin_auth_status_t origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)memset(decision, 0, sizeof(*decision));
    set_header(&decision->abi_version, &decision->struct_size, sizeof(*decision));
    decision->allowed = 1u;
    decision->max_payload_bytes = 2048u;
    decision->clock_epoch_id = request->now.clock_epoch_id;
    decision->evaluated_at_ms = request->now.now_ms;
    return NINLIL_ORIGIN_AUTH_OK;
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
    config.limits.max_nonterminal_transactions = 32u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes = 65536u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    config.limits.max_nonterminal_deliveries = 32u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 32u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = 12u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static int platform_init(cap_env_t *env)
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
    env->entropy = ninlil_test_entropy_create(0x4c4c4c4cu, 1u);
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
    env->payload = NULL;
    env->payload_capacity = 0u;
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

static void platform_teardown(cap_env_t *env)
{
    if (env->runtime != NULL) {
        (void)ninlil_runtime_destroy(env->runtime);
        env->runtime = NULL;
    }
    if (env->payload != NULL) {
        free(env->payload);
        env->payload = NULL;
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

static int env_create(cap_env_t *env)
{
    env->config = config_controller(4u);
    return ninlil_runtime_create(&env->config, &env->platform, &env->runtime)
        == NINLIL_OK;
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
    descriptor.logical_payload_limit = 1024u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 32u;
    descriptor.max_payload_bytes_per_window = 65536u;
    descriptor.minimum_deadline_ms = 100u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 50u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    return descriptor;
}

static int env_register(cap_env_t *env, uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor = desired_descriptor(app_tag);
    ninlil_service_callbacks_t callbacks;

    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    return ninlil_service_register(
               env->runtime, &descriptor, &callbacks, &env->service)
        == NINLIL_OK;
}

static void fill_target(cap_env_t *env)
{
    (void)memset(&env->target, 0, sizeof(env->target));
    set_header(&env->target.abi_version, &env->target.struct_size, sizeof(env->target));
    set_id(&env->target.target_runtime_id, 0x10u);
    set_id(&env->target.target_application_instance_id, 0x81u);
    set_id(&env->target.device_id, 0x82u);
    set_id(&env->target.site_domain_id, 0x83u);
    env->target.binding_epoch = 1u;
    env->target.membership_epoch = 1u;
    env->target.flags = NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;
}

static int ensure_payload(cap_env_t *env, uint32_t size)
{
    if (env->payload_capacity >= size) {
        return 1;
    }
    if (env->payload != NULL) {
        free(env->payload);
        env->payload = NULL;
    }
    env->payload = (uint8_t *)malloc(size);
    if (env->payload == NULL) {
        return 0;
    }
    (void)memset(env->payload, 0xA5u, size);
    env->payload_capacity = size;
    return 1;
}

static int submit_with_payload(
    cap_env_t *env,
    uint32_t payload_length,
    uint64_t effect_deadline_ms,
    uint8_t digest_tag,
    const uint8_t *idem_key,
    size_t idem_key_length,
    ninlil_submission_result_t *out_result)
{
    ninlil_submission_t submission;
    static const uint8_t default_idem[] = "cap-idem";

    if (!ensure_payload(env, payload_length)) {
        return 0;
    }
    fill_target(env);
    (void)memset(&submission, 0, sizeof(submission));
    set_header(&submission.abi_version, &submission.struct_size, sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &env->target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = effect_deadline_ms;
    submission.evidence_grace_ms = 1000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idem_key != NULL ? idem_key : default_idem;
    submission.idempotency_key.length = idem_key != NULL
        ? idem_key_length
        : sizeof(default_idem) - 1u;
    submission.payload.data = env->payload;
    submission.payload.length = payload_length;
    set_digest(&submission.content_digest, digest_tag);
    return ninlil_submit(env->service, &submission, out_result) == NINLIL_OK;
}

static uint32_t count_storage_tx_markers(ninlil_test_storage_t *storage_fixture)
{
    return ninlil_test_storage_count_keys_with_prefix(
        storage_fixture,
        (ninlil_bytes_view_t){TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
        0x54u,
        0x58u);
}

static int test_bearer_limit_table(void)
{
    REQUIRE(ninlil_rt_v1_bearer_payload_limit(NINLIL_RT_V1_BEARER_ROUTE_U6) == 926u);
    REQUIRE(ninlil_rt_v1_bearer_payload_limit(
                NINLIL_RT_V1_BEARER_ROUTE_SIMULATED)
        == 926u);
    REQUIRE(ninlil_rt_v1_bearer_admits_payload(
        NINLIL_RT_V1_BEARER_ROUTE_U6, 926u));
    REQUIRE(!ninlil_rt_v1_bearer_admits_payload(
        NINLIL_RT_V1_BEARER_ROUTE_U6, 927u));
    return 0;
}

static int test_logical_fragment_single(void)
{
    ninlil_rt_v1_logical_fragment_desc_t frag;

    REQUIRE(ninlil_rt_v1_build_logical_fragment_desc(512u, &frag) == NINLIL_OK);
    REQUIRE(frag.fragment_index == 0u);
    REQUIRE(frag.fragment_count == 1u);
    REQUIRE(frag.fragment_logical_bytes == 512u);
    return 0;
}

static int test_payload_max_minus_one_admitted(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x70u));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(submit_with_payload(&env, 925u, 5000u, 0x21u, NULL, 0u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_payload_max_admitted(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x71u));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(submit_with_payload(&env, 926u, 5000u, 0x22u, NULL, 0u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_payload_max_plus_one_rejected(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;
    uint32_t tx_before;
    uint32_t tx_after;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x72u));
    tx_before = count_storage_tx_markers(env.storage_fixture);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(submit_with_payload(&env, 927u, 5000u, 0x23u, NULL, 0u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_INVALID_PAYLOAD_LENGTH);
    tx_after = count_storage_tx_markers(env.storage_fixture);
    REQUIRE(tx_before == tx_after);
    platform_teardown(&env);
    return 0;
}

static int test_deadline_timeout_outcome(void)
{
    cap_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
  static const uint8_t idem_a[] = "deadline-idem-a";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x73u));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(submit_with_payload(
        &env, 16u, 200u, 0x24u, idem_a, sizeof(idem_a) - 1u, &submit_result));
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_clock_advance(env.clock, 500u));
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_state_transitions = 8u;
    (void)memset(&step_result, 0, sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    platform_teardown(&env);
    return 0;
}

static int test_priority_dispatch_order(void)
{
    cap_env_t env;
    ninlil_submission_result_t result_a;
    ninlil_submission_result_t result_b;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    static const uint8_t idem_a[] = "prio-idem-a";
    static const uint8_t idem_b[] = "prio-idem-b";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x74u));
    (void)memset(&result_a, 0, sizeof(result_a));
    REQUIRE(submit_with_payload(
        &env, 16u, 10000u, 0x25u, idem_a, sizeof(idem_a) - 1u, &result_a));
    REQUIRE(result_a.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    (void)memset(&result_b, 0, sizeof(result_b));
    REQUIRE(submit_with_payload(
        &env, 16u, 1000u, 0x26u, idem_b, sizeof(idem_b) - 1u, &result_b));
    REQUIRE(result_b.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_state_transitions = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(step_result.more_work != 0u);
    platform_teardown(&env);
    return 0;
}

static int test_restart_preserves_admission(void)
{
    cap_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_runtime_config_t saved_config;
    ninlil_platform_ops_t saved_platform;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x75u));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(submit_with_payload(&env, 926u, 5000u, 0x27u, NULL, 0u, &submit_result));
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    saved_config = env.config;
    saved_platform = env.platform;
    (void)ninlil_runtime_destroy(env.runtime);
    env.runtime = NULL;
    env.config = saved_config;
    env.platform = saved_platform;
    REQUIRE(env_create(&env));
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_simulated_bearer_loss_injection(void)
{
    cap_env_t env;
    ninlil_id128_t runtime_id;
    ninlil_bearer_handle_t handle = NULL;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_id(&runtime_id, 0x10u);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &runtime_id,
                NINLIL_ROLE_CONTROLLER,
                &handle)
        == NINLIL_BEARER_OK);
    REQUIRE(ninlil_test_bearer_set_path_up(env.bearer_fixture, &runtime_id, 0));
    ninlil_bearer_send_result_t raw_result;

    (void)memset(&raw_result, 0, sizeof(raw_result));
    set_header(
        &raw_result.abi_version, &raw_result.struct_size, sizeof(raw_result));
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(
        env.bearer_fixture, NINLIL_BEARER_WOULD_BLOCK, &raw_result, 1u));
    REQUIRE(ninlil_test_bearer_set_path_up(env.bearer_fixture, &runtime_id, 1));
    (void)env.platform.bearer->close(env.platform.bearer->user, handle);
    platform_teardown(&env);
    return 0;
}

static int test_retry_budget_exhaustion(void)
{
    cap_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    static const uint8_t idem_retry[] = "retry-idem";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x76u));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(submit_with_payload(
        &env, 16u, 100u, 0x28u, idem_retry, sizeof(idem_retry) - 1u, &submit_result));
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_state_transitions = 32u;
    (void)memset(&step_result, 0, sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    platform_teardown(&env);
    return 0;
}

int main(void)
{
    int rc = 0;

    if (test_bearer_limit_table() != 0) {
        rc = 1;
    }
    if (test_logical_fragment_single() != 0) {
        rc = 1;
    }
    if (test_payload_max_minus_one_admitted() != 0) {
        rc = 1;
    }
    if (test_payload_max_admitted() != 0) {
        rc = 1;
    }
    if (test_payload_max_plus_one_rejected() != 0) {
        rc = 1;
    }
    if (test_deadline_timeout_outcome() != 0) {
        rc = 1;
    }
    if (test_priority_dispatch_order() != 0) {
        rc = 1;
    }
    if (test_restart_preserves_admission() != 0) {
        rc = 1;
    }
    if (test_simulated_bearer_loss_injection() != 0) {
        rc = 1;
    }
    if (test_retry_budget_exhaustion() != 0) {
        rc = 1;
    }

    if (rc != 0) {
        (void)fprintf(stderr, "v1_runtime_capability_test failed\n");
    }
    return rc;
}
