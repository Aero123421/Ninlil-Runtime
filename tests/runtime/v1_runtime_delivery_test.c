/*
 * V1-LAB unit 2b: durable delivery path, event_resume/discard, restart.
 */

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_v1_delivery_durable.h"
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
static const uint8_t TEST_IDEM_EVENT_A[] = "event-idem-a";
static const char NS_TEXT[] = "org.ninlil.examples";
static const char EVT_TEXT[] = "event-fact";

static uint32_t g_delivery_calls;
static uint32_t g_fail_delivery;

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
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
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

static void fill_desired_submission(
    delivery_env_t *env,
    ninlil_submission_t *submission,
    uint8_t digest_tag)
{
    static const uint8_t idem_key[] = "delivery-idem";

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
    set_digest(&submission->content_digest, digest_tag);
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
    set_digest(&submission->content_digest, digest_tag);
}

static void encode_event_spool_value(
    uint8_t *value,
    uint32_t state,
    uint64_t spool_revision,
    uint32_t park_cause)
{
    (void)memset(value, 0, 32u);
    value[0] = (uint8_t)state;
    (void)memcpy(&value[4], &spool_revision, sizeof(spool_revision));
    value[12] = (uint8_t)(park_cause & 0xffu);
    value[13] = (uint8_t)((park_cause >> 8) & 0xffu);
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
    uint8_t tx_key[16];
    uint8_t tx_value[NINLIL_RT_V1_TX_ADMISSION_MARKER_VALUE_BYTES];
    uint8_t es_key[16];
    uint8_t es_value[32];

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

    tx_key[0] = 0x54u;
    tx_key[1] = 0x58u;
    (void)memcpy(&tx_key[2], txn_id->bytes, 14u);
    set_id(&app_id, app_tag);
    ninlil_rt_v1_encode_tx_admission_marker(
        tx_value,
        NINLIL_FAMILY_EVENT_FACT,
        &app_id,
        NINLIL_NO_DEADLINE,
        0u);
    if (storage->put(
            storage->user,
            txn,
            (ninlil_bytes_view_t){tx_key, sizeof(tx_key)},
            (ninlil_bytes_view_t){tx_value, sizeof(tx_value)})
        != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        (void)storage->close(storage->user, handle);
        return 0;
    }

    es_key[0] = 0x45u;
    es_key[1] = 0x53u;
    (void)memcpy(&es_key[2], txn_id->bytes, 14u);
    encode_event_spool_value(
        es_value,
        2u,
        spool_revision,
        NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE);
    if (storage->put(
            storage->user,
            txn,
            (ninlil_bytes_view_t){es_key, sizeof(es_key)},
            (ninlil_bytes_view_t){es_value, sizeof(es_value)})
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

static int controller_register_event_receiver(
    delivery_env_t *env,
    uint8_t app_tag,
    const ninlil_service_callbacks_t *callbacks)
{
    ninlil_service_descriptor_t descriptor = event_fact_descriptor(app_tag);
    return env_register(env, &descriptor, callbacks);
}

static int test_desired_state_delivery_happy(void)
{
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    descriptor = desired_descriptor(0x70u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(env_register(&env, &descriptor, &callbacks));

    fill_desired_submission(&env, &submission, 0x22u);

    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(ninlil_submit(env.service, &submission, &submit_result) == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(step_result.more_work == 0u);

    platform_teardown(&env);
    return 0;
}

static int test_callback_failure_no_false_success(void)
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

    (void)memset(&resume_request, 0, sizeof(resume_request));
    set_header(
        &resume_request.abi_version,
        &resume_request.struct_size,
        sizeof(resume_request));
    set_id(&op_id, 0xb1u);
    resume_request.operation_id = op_id;
    resume_request.expected_spool_revision = 2u;
    resume_request.resume_reason = NINLIL_RESUME_TEST;
    REQUIRE(ninlil_event_resume(
                env.runtime, &txn_id, &resume_request, &resume_result)
        == NINLIL_OK);
    REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_RESUMED);

    fill_step_budget(&budget);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);

    g_fail_delivery = 0u;
    platform_teardown(&env);
    return 0;
}

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

    fill_step_budget(&budget);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);

    fill_step_budget(&budget);
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
    REQUIRE(controller_register_event_receiver(&env, 0x72u, &callbacks));
    fill_step_budget(&budget);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(g_delivery_calls == 1u);

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

static int test_endpoint_submit_parks(void)
{
    delivery_env_t env;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
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

    REQUIRE(ninlil_submit(env.service, &submission, &submit_result) == NINLIL_OK);
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    fill_step_budget(&budget);
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);

    platform_teardown(&env);
    return 0;
}

static int test_event_resume_wrong_role(void)
{
    delivery_env_t env;
    ninlil_id128_t txn_id;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;

    (void)memset(&env, 0, sizeof(env));
    set_id(&txn_id, 0x99u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_ENDPOINT));
    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    set_id(&request.operation_id, 0xa9u);
    (void)memset(&result, 0, sizeof(result));
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

    (void)memset(&env, 0, sizeof(env));
    set_id(&txn_id, 0x98u);
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env, NINLIL_ROLE_CONTROLLER));
    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    request.acknowledge_required_receipt_absent = 0u;
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_event_discard(env.runtime, &txn_id, &request, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    platform_teardown(&env);
    return 0;
}

int main(void)
{
    int rc = 0;

    if (test_desired_state_delivery_happy() != 0) {
        rc = 1;
    }
    if (test_callback_failure_no_false_success() != 0) {
        rc = 1;
    }
    if (test_event_resume_discard_flow() != 0) {
        rc = 1;
    }
    if (test_event_resume_wrong_role() != 0) {
        rc = 1;
    }
    if (test_event_discard_invalid_ack() != 0) {
        rc = 1;
    }
    if (test_event_discard_stale_revision() != 0) {
        rc = 1;
    }
    if (test_endpoint_submit_parks() != 0) {
        rc = 1;
    }

    if (rc != 0) {
        (void)fprintf(stderr, "v1_runtime_delivery_test failed\n");
    }
    return rc;
}
