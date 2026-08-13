/* SPDX-License-Identifier: Apache-2.0 */
#include "deterministic_entropy.h"
#include "domain_store_codec.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_store_codec.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_event_ledger_codec.h"
#include "runtime_v1_transaction_codec.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define EVENT_SPOOL_PREFIX ((uint16_t)0x4553u)
#define DELIVERY_STARTED_PREFIX ((uint16_t)0x4453u)
#define RETRY_STATE_PREFIX ((uint16_t)0x5254u)
#define TRANSACTION_ADMISSION_PREFIX ((uint16_t)0x5458u)

static const uint8_t TEST_NAMESPACE[] = "v1-event-mgmt-ledger-test";
static const uint8_t IDEMPOTENCY_KEY[] = "event-ledger-idem";
static const uint8_t PAYLOAD[] = {0x10u, 0x20u, 0x30u, 0x40u};
static const uint8_t RESUME_METADATA[] = "resume-audit";
static const uint8_t DISCARD_METADATA[] = "discard-audit";

typedef struct event_env {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage;
    ninlil_test_bearer_t *bearer;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    ninlil_id128_t transaction_id;
} event_env_t;

typedef enum storage_shape_fault {
    STORAGE_SHAPE_NONE = 0,
    STORAGE_SHAPE_BEGIN_OK_NULL = 1,
    STORAGE_SHAPE_BEGIN_ERROR_NONNULL = 2,
    STORAGE_SHAPE_ITER_OK_NULL = 3,
    STORAGE_SHAPE_ITER_ERROR_NONNULL = 4,
    STORAGE_SHAPE_ITER_END_REWRITE = 5
} storage_shape_fault_t;

static const ninlil_storage_ops_t *g_shape_delegate;
static ninlil_storage_ops_t g_shape_original;
static storage_shape_fault_t g_shape_fault;

static ninlil_storage_status_t shape_fault_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    ninlil_storage_status_t status;

    if (g_shape_fault == STORAGE_SHAPE_BEGIN_OK_NULL) {
        *out_transaction = NULL;
        return NINLIL_STORAGE_OK;
    }
    status = g_shape_delegate->begin(
        user, handle, mode, out_transaction);
    if (g_shape_fault == STORAGE_SHAPE_BEGIN_ERROR_NONNULL
        && status == NINLIL_STORAGE_OK
        && *out_transaction != NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    return status;
}

static ninlil_storage_status_t shape_fault_iter_open(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    ninlil_storage_status_t status;

    if (g_shape_fault == STORAGE_SHAPE_ITER_OK_NULL) {
        *out_iterator = NULL;
        return NINLIL_STORAGE_OK;
    }
    status = g_shape_delegate->iter_open(
        user, transaction, prefix, out_iterator);
    if (g_shape_fault == STORAGE_SHAPE_ITER_ERROR_NONNULL
        && status == NINLIL_STORAGE_OK
        && *out_iterator != NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    return status;
}

static ninlil_storage_status_t shape_fault_iter_next(
    void *user,
    ninlil_storage_iter_t iterator,
    ninlil_mut_bytes_t *out_key,
    ninlil_mut_bytes_t *out_value)
{
    ninlil_storage_status_t status = g_shape_delegate->iter_next(
        user, iterator, out_key, out_value);

    if (g_shape_fault == STORAGE_SHAPE_ITER_END_REWRITE
        && status == NINLIL_STORAGE_NOT_FOUND) {
        out_key->data = NULL;
        out_key->capacity = 0u;
        out_value->data = NULL;
        out_value->capacity = 0u;
    }
    return status;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void store_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24u);
    out[1] = (uint8_t)(value >> 16u);
    out[2] = (uint8_t)(value >> 8u);
    out[3] = (uint8_t)value;
}

static void refresh_event_ledger_crc(uint8_t *value, uint32_t length)
{
    uint32_t crc = ninlil_model_domain_crc32c(value, length - 4u);

    store_u32_be(&value[length - 4u], crc);
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static int id_is_zero(const ninlil_id128_t *id)
{
    ninlil_id128_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(id, &zero, sizeof(zero)) == 0;
}

static void set_digest(ninlil_digest256_t *digest, uint8_t tag)
{
    uint32_t index;

    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    for (index = 0u; index < sizeof(digest->bytes); ++index) {
        digest->bytes[index] = (uint8_t)(tag + index);
    }
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

static ninlil_origin_auth_status_t origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)memset(decision, 0, sizeof(*decision));
    set_header(
        &decision->abi_version,
        &decision->struct_size,
        sizeof(*decision));
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

static ninlil_runtime_config_t endpoint_config(void)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_ENDPOINT;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x11u);
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
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = 32u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 0u;
    config.limits.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 32u;
    config.limits.max_nonterminal_deliveries = 32u;
    config.limits.max_event_spool_count = 32u;
    config.limits.max_event_spool_bytes = 32768u;
    config.limits.max_result_cache_entries = 16u;
    config.limits.max_retained_dispositions = 16u;
    config.limits.max_ingress_per_step = 16u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 16u;
    config.limits.max_deferred_tokens = 16u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static ninlil_service_descriptor_t event_descriptor(void)
{
    static const uint8_t namespace_id[] = "org.ninlil.test";
    static const uint8_t service_id[] = "event-fact";
    static const uint8_t schema_id[] = "event-v1";
    ninlil_service_descriptor_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version,
        &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data = namespace_id;
    descriptor.namespace_id.length = sizeof(namespace_id) - 1u;
    descriptor.service_id.data = service_id;
    descriptor.service_id.length = sizeof(service_id) - 1u;
    descriptor.schema_id.data = schema_id;
    descriptor.schema_id.length = sizeof(schema_id) - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x33u);
    set_id(&descriptor.local_application_instance_id, 0x74u);
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

static int platform_init(event_env_t *env)
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
    env->storage = ninlil_test_storage_create(&storage_config);
    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 32u;
    bearer_config.max_bytes_per_direction = 65536u;
    bearer_config.max_permits = 32u;
    set_id(&bearer_config.permit_issuer_id, 0x80u);
    set_id(&bearer_config.initial_clock_epoch_id, 0xa0u);
    env->bearer = ninlil_test_bearer_create(&bearer_config);
    if (env->allocator == NULL || env->execution == NULL
        || env->clock == NULL || env->entropy == NULL
        || env->storage == NULL || env->bearer == NULL) {
        return 0;
    }
    (void)memset(&env->origin, 0, sizeof(env->origin));
    set_header(
        &env->origin.abi_version,
        &env->origin.struct_size,
        sizeof(env->origin));
    env->origin.evaluate = origin_allow;
    (void)memset(&env->platform, 0, sizeof(env->platform));
    set_header(
        &env->platform.abi_version,
        &env->platform.struct_size,
        sizeof(env->platform));
    env->platform.allocator = ninlil_test_allocator_ops(env->allocator);
    env->platform.execution = ninlil_test_execution_ops(env->execution);
    env->platform.clock = ninlil_test_clock_ops(env->clock);
    env->platform.entropy = ninlil_test_entropy_ops(env->entropy);
    env->platform.storage = ninlil_test_storage_ops(env->storage);
    env->platform.bearer = ninlil_test_bearer_ops(env->bearer);
    env->platform.tx_gate = ninlil_test_bearer_tx_gate_ops(env->bearer);
    env->platform.origin_authorization = &env->origin;
    env->config = endpoint_config();
    return 1;
}

static void env_teardown(event_env_t *env)
{
    if (env->runtime != NULL) {
        (void)ninlil_runtime_destroy(env->runtime);
        env->runtime = NULL;
    }
    if (env->bearer != NULL) {
        ninlil_test_bearer_destroy(env->bearer);
    }
    if (env->storage != NULL) {
        ninlil_test_storage_destroy(env->storage);
    }
    if (env->entropy != NULL) {
        ninlil_test_entropy_destroy(env->entropy);
    }
    if (env->clock != NULL) {
        ninlil_test_clock_destroy(env->clock);
    }
    if (env->execution != NULL) {
        ninlil_test_execution_destroy(env->execution);
    }
    if (env->allocator != NULL) {
        (void)ninlil_test_allocator_destroy(env->allocator);
    }
    (void)memset(env, 0, sizeof(*env));
}

static int env_open(event_env_t *env)
{
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;

    REQUIRE(ninlil_runtime_create(
                &env->config, &env->platform, &env->runtime)
        == NINLIL_OK);
    descriptor = event_descriptor();
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env->runtime, &descriptor, &callbacks, &env->service)
        == NINLIL_OK);
    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    set_id(&target.target_runtime_id, 0x10u);
    set_id(&target.target_application_instance_id, 0x81u);
    set_id(&target.device_id, 0x82u);
    set_id(&target.site_domain_id, 0x83u);
    target.binding_epoch = 1u;
    target.membership_epoch = 1u;
    target.flags = NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;

    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
    set_id(&submission.event_id, 0x93u);
    submission.idempotency_key.data = IDEMPOTENCY_KEY;
    submission.idempotency_key.length = sizeof(IDEMPOTENCY_KEY) - 1u;
    submission.payload.data = PAYLOAD;
    submission.payload.length = sizeof(PAYLOAD);
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, PAYLOAD, (uint32_t)sizeof(PAYLOAD)));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env->service, &submission, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    env->transaction_id = result.transaction_id;
    return 0;
}

static int submit_second_event(
    event_env_t *env,
    ninlil_id128_t *out_transaction_id)
{
    static const uint8_t second_idempotency_key[] =
        "event-ledger-idem-second";
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;

    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    set_id(&target.target_runtime_id, 0x10u);
    set_id(&target.target_application_instance_id, 0x81u);
    set_id(&target.device_id, 0x82u);
    set_id(&target.site_domain_id, 0x83u);
    target.binding_epoch = 1u;
    target.membership_epoch = 1u;
    target.flags = NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;

    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
    set_id(&submission.event_id, 0x95u);
    submission.idempotency_key.data = second_idempotency_key;
    submission.idempotency_key.length =
        sizeof(second_idempotency_key) - 1u;
    submission.payload.data = PAYLOAD;
    submission.payload.length = sizeof(PAYLOAD);
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, PAYLOAD, (uint32_t)sizeof(PAYLOAD)));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env->service, &submission, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    *out_transaction_id = result.transaction_id;
    return 0;
}

static int env_restart(event_env_t *env)
{
    ninlil_status_t create_status;

    REQUIRE(ninlil_runtime_destroy(env->runtime) == NINLIL_OK);
    env->runtime = NULL;
    env->service = NULL;
    ninlil_test_storage_simulate_crash(env->storage);
    create_status = ninlil_runtime_create(
        &env->config, &env->platform, &env->runtime);
    if (create_status != NINLIL_OK) {
        (void)fprintf(stderr, "restart create status=%d\n", create_status);
    }
    REQUIRE(create_status == NINLIL_OK);
    return 0;
}

static int env_restart_after_commit_unknown(event_env_t *env)
{
    ninlil_status_t create_status;

    REQUIRE(ninlil_runtime_destroy(env->runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env->runtime = NULL;
    env->service = NULL;
    ninlil_test_storage_simulate_crash(env->storage);
    create_status = ninlil_runtime_create(
        &env->config, &env->platform, &env->runtime);
    REQUIRE(create_status == NINLIL_OK);
    return 0;
}

static int raw_storage_mutate(
    event_env_t *env,
    ninlil_bytes_view_t key,
    const ninlil_bytes_view_t *value)
{
    const ninlil_storage_ops_t *storage =
        ninlil_test_storage_ops(env->storage);
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t status;

    if (storage->open(
            storage->user,
            env->config.storage_namespace,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle)
        != NINLIL_STORAGE_OK) {
        return 0;
    }
    if (storage->begin(
            storage->user,
            handle,
            NINLIL_STORAGE_READ_WRITE,
            &transaction)
        != NINLIL_STORAGE_OK) {
        storage->close(storage->user, handle);
        return 0;
    }
    status = value == NULL
        ? storage->erase(storage->user, transaction, key)
        : storage->put(storage->user, transaction, key, *value);
    if (status != NINLIL_STORAGE_OK
        || storage->commit(
                storage->user,
                transaction,
                NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        if (status == NINLIL_STORAGE_OK) {
            (void)storage->rollback(storage->user, transaction);
        }
        storage->close(storage->user, handle);
        return 0;
    }
    storage->close(storage->user, handle);
    return 1;
}

static int raw_storage_read(
    event_env_t *env,
    ninlil_bytes_view_t key,
    uint8_t *out_value,
    uint32_t capacity,
    uint32_t *out_length)
{
    const ninlil_storage_ops_t *storage =
        ninlil_test_storage_ops(env->storage);
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t status;
    uint32_t owns_handle = 0u;

    *out_length = 0u;
    if (env->runtime != NULL) {
        handle = env->runtime->storage;
    } else if (storage->open(
            storage->user,
            env->config.storage_namespace,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle)
        != NINLIL_STORAGE_OK) {
        return 0;
    } else {
        owns_handle = 1u;
    }
    if (storage->begin(
            storage->user,
            handle,
            NINLIL_STORAGE_READ_ONLY,
            &transaction)
        != NINLIL_STORAGE_OK) {
        if (owns_handle != 0u) {
            storage->close(storage->user, handle);
        }
        return 0;
    }
    value.data = out_value;
    value.capacity = capacity;
    value.length = 0u;
    status = storage->get(storage->user, transaction, key, &value);
    if (storage->rollback(storage->user, transaction)
            != NINLIL_STORAGE_OK
        || status != NINLIL_STORAGE_OK
        || value.data != out_value
        || value.capacity != capacity
        || value.length == 0u
        || value.length > capacity) {
        if (owns_handle != 0u) {
            storage->close(storage->user, handle);
        }
        return 0;
    }
    if (owns_handle != 0u) {
        storage->close(storage->user, handle);
    }
    *out_length = value.length;
    return 1;
}

static int read_ordered_input_counter(
    event_env_t *env,
    ninlil_model_runtime_store_counter_t *out_counter)
{
    ninlil_model_runtime_store_key_t key;
    uint8_t value[NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES];
    uint32_t value_length;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
                &key)
        == NINLIL_OK);
    REQUIRE(raw_storage_read(
        env,
        (ninlil_bytes_view_t){key.bytes, key.length},
        value,
        (uint32_t)sizeof(value),
        &value_length));
    REQUIRE(ninlil_model_runtime_store_decode_counter(
                NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
                (ninlil_bytes_view_t){value, value_length},
                out_counter)
        == NINLIL_OK);
    return 0;
}

static int write_ordered_input_counter(
    event_env_t *env,
    uint64_t counter_value,
    uint32_t exhausted_marker)
{
    ninlil_model_runtime_store_key_t key;
    ninlil_model_runtime_store_counter_t counter;
    uint8_t value_bytes[NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES];
    uint32_t value_length = 0u;
    ninlil_bytes_view_t value;

    (void)memset(&counter, 0, sizeof(counter));
    counter.kind = NINLIL_MODEL_RUNTIME_STORE_COUNTER_ORDERED_INPUT;
    counter.value = counter_value;
    counter.exhausted_marker = exhausted_marker;
    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
                &key)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_encode_counter(
                NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
                &counter,
                value_bytes,
                (uint32_t)sizeof(value_bytes),
                &value_length)
        == NINLIL_OK);
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(raw_storage_mutate(
        env,
        (ninlil_bytes_view_t){key.bytes, key.length},
        &value));
    return 0;
}

static int read_event_ledger(
    event_env_t *env,
    uint16_t prefix,
    const ninlil_id128_t *operation_id,
    ninlil_rt_v1_event_ledger_record_t *out_record)
{
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint32_t value_length;

    ninlil_rt_v1_event_ledger_key(
        prefix, &env->transaction_id, operation_id, key);
    REQUIRE(raw_storage_read(
        env,
        (ninlil_bytes_view_t){key, sizeof(key)},
        value,
        (uint32_t)sizeof(value),
        &value_length));
    REQUIRE(ninlil_rt_v1_event_ledger_decode(
                (ninlil_bytes_view_t){value, value_length},
                out_record)
        == NINLIL_OK);
    return 0;
}

static int stop_runtime(event_env_t *env)
{
    REQUIRE(ninlil_runtime_destroy(env->runtime) == NINLIL_OK);
    env->runtime = NULL;
    env->service = NULL;
    return 0;
}

static int restart_is_storage_corrupt(event_env_t *env)
{
    ninlil_status_t status = ninlil_runtime_create(
        &env->config, &env->platform, &env->runtime);

    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env->runtime == NULL);
    return 0;
}

static int park_event(event_env_t *env)
{
    ninlil_rt_transaction_slot_t *transaction =
        ninlil_rt_find_transaction(env->runtime, &env->transaction_id);
    ninlil_rt_transaction_slot_t *candidate;
    uint32_t index;

    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->spool_revision != UINT64_MAX);
    candidate = &env->runtime->transaction_scratch;
    *candidate = *transaction;
    candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
    candidate->pending_dispatch = 0u;
    candidate->event_park_cause =
        NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE;
    candidate->spool_revision += 1u;
    for (index = 0u; index < candidate->bound_target_count; ++index) {
        candidate->bound_targets[index].pending_dispatch = 0u;
    }
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env->runtime,
                transaction,
                candidate,
                EVENT_SPOOL_PREFIX,
                NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT)
        == NINLIL_OK);
    return 0;
}

static void set_event_attempt_history(
    ninlil_rt_transaction_slot_t *candidate,
    uint32_t attempt_count)
{
    uint32_t index;

    candidate->attempt_count = attempt_count;
    candidate->attempt_in_cycle = attempt_count;
    candidate->cumulative_attempts = attempt_count;
    candidate->retry_budget =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - attempt_count;
    candidate->attempt_prepared = attempt_count != 0u ? 1u : 0u;
    (void)memset(
        &candidate->attempt_id, 0, sizeof(candidate->attempt_id));
    (void)memset(
        candidate->attempt_ids, 0, sizeof(candidate->attempt_ids));
    for (index = 0u; index < attempt_count; ++index) {
        set_id(
            &candidate->attempt_ids[index],
            (uint8_t)(0x21u + index * 0x10u));
    }
    if (attempt_count != 0u) {
        candidate->attempt_id =
            candidate->attempt_ids[attempt_count - 1u];
    }
}

static int persist_required_receipt_pending(event_env_t *env)
{
    ninlil_rt_transaction_slot_t *transaction =
        ninlil_rt_find_transaction(env->runtime, &env->transaction_id);
    ninlil_rt_transaction_slot_t *candidate;

    REQUIRE(transaction != NULL);
    REQUIRE(transaction->family == NINLIL_FAMILY_EVENT_FACT);
    REQUIRE(transaction->spool_revision != UINT64_MAX);
    REQUIRE(env->runtime->last_assigned_ordered_input_sequence
        != UINT64_MAX);
    candidate = &env->runtime->transaction_scratch;
    *candidate = *transaction;
    set_event_attempt_history(candidate, 1u);
    candidate->receipt_pending = 1u;
    candidate->latest_evidence = candidate->required_evidence;
    candidate->spool_revision += 1u;
    candidate->ordered_input_sequence =
        env->runtime->last_assigned_ordered_input_sequence + 1u;
    REQUIRE(ninlil_rt_v1_commit_ordered_input_snapshot(
                env->runtime,
                transaction,
                candidate,
                DELIVERY_STARTED_PREFIX,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_OK);
    return 0;
}

static int persist_due_event_attempt(
    event_env_t *env,
    uint32_t attempt_count)
{
    ninlil_rt_transaction_slot_t *transaction =
        ninlil_rt_find_transaction(env->runtime, &env->transaction_id);
    ninlil_rt_transaction_slot_t *candidate;

    REQUIRE(transaction != NULL);
    REQUIRE(transaction->family == NINLIL_FAMILY_EVENT_FACT);
    REQUIRE(transaction->spool_revision != UINT64_MAX);
    REQUIRE(attempt_count != 0u);
    REQUIRE(attempt_count <= NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    candidate = &env->runtime->transaction_scratch;
    *candidate = *transaction;
    set_event_attempt_history(candidate, attempt_count);
    candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    candidate->pending_dispatch = 0u;
    candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    candidate->send_observation_closed = 1u;
    candidate->send_observed_clock_epoch_id =
        env->runtime->started_sample.clock_epoch_id;
    candidate->send_observed_at_ms =
        env->runtime->started_sample.now_ms;
    candidate->spool_revision += 1u;
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env->runtime,
                transaction,
                candidate,
                DELIVERY_STARTED_PREFIX,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_advance(
        env->clock, candidate->attempt_receipt_timeout_ms));
    return 0;
}

static void fill_step_budget(ninlil_step_budget_t *budget)
{
    (void)memset(budget, 0, sizeof(*budget));
    set_header(
        &budget->abi_version, &budget->struct_size, sizeof(*budget));
    budget->max_ingress_messages = 0u;
    budget->max_callbacks = 0u;
    budget->max_state_transitions = 16u;
    budget->max_bearer_sends = 0u;
}

static int event_spool_bytes(
    event_env_t *env,
    uint64_t *out_used,
    uint64_t *out_reserved)
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
    REQUIRE(ninlil_capacity_snapshot(env->runtime, &snapshot) == NINLIL_OK);
    REQUIRE(snapshot.entry_count == NINLIL_MODEL_RESOURCE_KIND_COUNT);
    REQUIRE(entries[NINLIL_RESOURCE_EVENT_SPOOL_BYTES - 1u].kind
        == NINLIL_RESOURCE_EVENT_SPOOL_BYTES);
    *out_used = entries[NINLIL_RESOURCE_EVENT_SPOOL_BYTES - 1u].used;
    *out_reserved =
        entries[NINLIL_RESOURCE_EVENT_SPOOL_BYTES - 1u].reserved;
    return 0;
}

static void fill_resume_request(
    ninlil_event_resume_request_t *request,
    const ninlil_rt_transaction_slot_t *transaction,
    uint8_t operation_tag,
    const uint8_t *metadata,
    uint32_t metadata_length)
{
    (void)memset(request, 0, sizeof(*request));
    set_header(
        &request->abi_version, &request->struct_size, sizeof(*request));
    set_id(&request->operation_id, operation_tag);
    set_id(&request->actor_id, 0xc0u);
    request->expected_spool_revision = transaction->spool_revision;
    request->resume_reason = NINLIL_RESUME_TEST;
    request->audit_metadata.data = metadata;
    request->audit_metadata.length = metadata_length;
}

static void fill_discard_request(
    ninlil_event_discard_request_t *request,
    const ninlil_rt_transaction_slot_t *transaction,
    uint8_t operation_tag,
    const uint8_t *metadata,
    uint32_t metadata_length)
{
    (void)memset(request, 0, sizeof(*request));
    set_header(
        &request->abi_version, &request->struct_size, sizeof(*request));
    set_id(&request->operation_id, operation_tag);
    set_id(&request->actor_id, 0xd0u);
    request->expected_event_id = transaction->event_id;
    request->expected_content_digest = transaction->content_digest;
    request->expected_spool_revision = transaction->spool_revision;
    request->discard_reason = NINLIL_DISCARD_TEST_CLEANUP;
    request->acknowledge_required_receipt_absent = 1u;
    request->audit_metadata.data = metadata;
    request->audit_metadata.length = metadata_length;
}

static int encode_resume_ledger_record(
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_event_resume_request_t *request,
    const ninlil_event_resume_result_t *result,
    const ninlil_id128_t *ledger_transaction_id,
    const ninlil_id128_t *ledger_event_id,
    uint8_t out_value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES],
    uint32_t *out_length)
{
    ninlil_rt_v1_event_ledger_record_t record;

    (void)memset(&record, 0, sizeof(record));
    record.operation_kind = NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME;
    record.record_revision = 1u;
    record.ordered_sequence = transaction->transaction_sequence;
    record.transaction_id = *ledger_transaction_id;
    record.event_id = *ledger_event_id;
    record.operation_id = request->operation_id;
    record.actor_id = request->actor_id;
    REQUIRE(ninlil_rt_v1_event_resume_request_digest(
                ledger_transaction_id,
                request,
                record.canonical_request_digest)
        == NINLIL_OK);
    record.expected_spool_revision = request->expected_spool_revision;
    record.request_reason = request->resume_reason;
    record.metadata_length = request->audit_metadata.length;
    (void)memcpy(
        record.metadata,
        request->audit_metadata.data,
        request->audit_metadata.length);
    record.audit_clock_epoch_id = transaction->admission_clock_epoch_id;
    record.audit_committed_at_ms = transaction->admitted_at_ms;
    record.replay_result_kind = NINLIL_EVENT_RESUME_ALREADY_RESUMED;
    record.replay_result_reason = NINLIL_REASON_NONE;
    record.replay_retry_cycle_id = result->retry_cycle_id;
    record.replay_spool_revision = result->spool_revision;
    REQUIRE(ninlil_rt_v1_event_ledger_encode(
                &record,
                out_value,
                NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES,
                out_length)
        == NINLIL_OK);
    return 0;
}

static int encode_discard_ledger_record(
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_event_discard_request_t *request,
    const ninlil_event_discard_result_t *result,
    const ninlil_digest256_t *expected_content_digest,
    uint8_t out_value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES],
    uint32_t *out_length)
{
    ninlil_event_discard_request_t digest_request = *request;
    ninlil_rt_v1_event_ledger_record_t record;

    digest_request.expected_content_digest = *expected_content_digest;
    (void)memset(&record, 0, sizeof(record));
    record.operation_kind = NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD;
    record.record_revision = 1u;
    record.ordered_sequence = transaction->transaction_sequence;
    record.transaction_id = transaction->transaction_id;
    record.event_id = transaction->event_id;
    record.operation_id = request->operation_id;
    record.actor_id = request->actor_id;
    REQUIRE(ninlil_rt_v1_event_discard_request_digest(
                &transaction->transaction_id,
                &digest_request,
                record.canonical_request_digest)
        == NINLIL_OK);
    record.expected_spool_revision = request->expected_spool_revision;
    record.expected_event_id = request->expected_event_id;
    record.expected_content_digest_algorithm =
        expected_content_digest->algorithm;
    (void)memcpy(
        record.expected_content_digest,
        expected_content_digest->bytes,
        sizeof(record.expected_content_digest));
    record.request_reason = request->discard_reason;
    record.acknowledge_flag =
        request->acknowledge_required_receipt_absent;
    record.metadata_length = request->audit_metadata.length;
    (void)memcpy(
        record.metadata,
        request->audit_metadata.data,
        request->audit_metadata.length);
    record.audit_clock_epoch_id = result->audit_clock_epoch_id;
    record.audit_committed_at_ms = result->audit_committed_at_ms;
    record.replay_result_kind = NINLIL_EVENT_DISCARD_ALREADY_DISCARDED;
    record.replay_result_reason =
        NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    record.replay_spool_revision = result->spool_revision;
    record.replay_spool_released = 1u;
    REQUIRE(ninlil_rt_v1_event_ledger_encode(
                &record,
                out_value,
                NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES,
                out_length)
        == NINLIL_OK);
    return 0;
}

static int resume_result_is_api_zero(
    const ninlil_event_resume_result_t *result)
{
    return result->abi_version == NINLIL_ABI_VERSION
        && result->struct_size == sizeof(*result)
        && result->kind == NINLIL_EVENT_RESUME_INVALID
        && result->reason == NINLIL_REASON_NONE
        && id_is_zero(&result->operation_id)
        && result->retry_cycle_id == 0u
        && result->spool_revision == 0u;
}

static int discard_result_is_api_zero(
    const ninlil_event_discard_result_t *result)
{
    return result->abi_version == NINLIL_ABI_VERSION
        && result->struct_size == sizeof(*result)
        && result->kind == NINLIL_EVENT_DISCARD_INVALID
        && result->reason == NINLIL_REASON_NONE
        && id_is_zero(&result->operation_id)
        && id_is_zero(&result->audit_clock_epoch_id)
        && result->audit_committed_at_ms == 0u
        && result->spool_revision == 0u
        && result->spool_released == 0u;
}

typedef enum targeted_clock_fault {
    TARGETED_CLOCK_TEMPORARY = 0,
    TARGETED_CLOCK_UNCERTAIN = 1,
    TARGETED_CLOCK_INVALID = 2,
    TARGETED_CLOCK_PERMANENT = 3,
    TARGETED_CLOCK_REGRESSION = 4
} targeted_clock_fault_t;

static int run_targeted_clock_health_case(
    int use_discard,
    targeted_clock_fault_t fault)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_time_sample_t sample;
    ninlil_id128_t second_transaction_id;
    ninlil_status_t expected_status;
    ninlil_status_t status;
    uint64_t clock_calls;
    uint64_t ordered_sequence;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    if (fault == TARGETED_CLOCK_REGRESSION) {
        /* Establish a Runtime-wide high-water independent of this owner. */
        REQUIRE(ninlil_test_clock_advance(env.clock, 100u));
        REQUIRE(submit_second_event(&env, &second_transaction_id) == 0);
    }
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ordered_sequence = env.runtime->last_assigned_ordered_input_sequence;
    sample = env.runtime->last_accepted_trusted_sample;
    expected_status = NINLIL_E_DEGRADED;
    switch (fault) {
    case TARGETED_CLOCK_TEMPORARY:
        expected_status = NINLIL_E_CLOCK_UNCERTAIN;
        REQUIRE(ninlil_test_clock_script(
            env.clock, NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u));
        break;
    case TARGETED_CLOCK_UNCERTAIN:
        sample.trust = NINLIL_CLOCK_UNCERTAIN;
        expected_status = NINLIL_E_CLOCK_UNCERTAIN;
        REQUIRE(ninlil_test_clock_script(
            env.clock, NINLIL_PORT_OK, &sample, 1u));
        break;
    case TARGETED_CLOCK_INVALID:
        sample.struct_size = (uint16_t)(sizeof(sample) - 1u);
        REQUIRE(ninlil_test_clock_script_raw(
            env.clock, NINLIL_PORT_OK, &sample, 1u));
        break;
    case TARGETED_CLOCK_PERMANENT:
        REQUIRE(ninlil_test_clock_script(
            env.clock, NINLIL_PORT_PERMANENT_FAILURE, NULL, 1u));
        break;
    case TARGETED_CLOCK_REGRESSION:
        REQUIRE(sample.now_ms > 0u);
        sample.now_ms -= 1u;
        REQUIRE(ninlil_test_clock_script_raw(
            env.clock, NINLIL_PORT_OK, &sample, 1u));
        break;
    default:
        REQUIRE(0);
    }

    clock_calls = ninlil_test_clock_call_count(env.clock);
    if (use_discard != 0) {
        fill_discard_request(
            &discard_request,
            transaction,
            (uint8_t)(0x80u + (uint8_t)fault),
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
        (void)memset(&discard_result, 0xa5, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        status = ninlil_event_discard(
            env.runtime,
            &env.transaction_id,
            &discard_request,
            &discard_result);
        REQUIRE(discard_result_is_api_zero(&discard_result));
    } else {
        fill_resume_request(
            &resume_request,
            transaction,
            (uint8_t)(0x70u + (uint8_t)fault),
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
        (void)memset(&resume_result, 0xa5, sizeof(resume_result));
        set_header(
            &resume_result.abi_version,
            &resume_result.struct_size,
            sizeof(resume_result));
        status = ninlil_event_resume(
            env.runtime,
            &env.transaction_id,
            &resume_request,
            &resume_result);
        REQUIRE(resume_result_is_api_zero(&resume_result));
    }
    REQUIRE(status == expected_status);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_sequence);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                use_discard != 0 ? 0x44u : 0x52u)
        == 0u);
    env_teardown(&env);
    return 0;
}

static int test_targeted_clock_failures_add_health_without_mutation(void)
{
    targeted_clock_fault_t fault;

    for (fault = TARGETED_CLOCK_TEMPORARY;
         fault <= TARGETED_CLOCK_REGRESSION;
         fault = (targeted_clock_fault_t)((uint32_t)fault + 1u)) {
        REQUIRE(run_targeted_clock_health_case(0, fault) == 0);
        REQUIRE(run_targeted_clock_health_case(1, fault) == 0);
    }
    return 0;
}

static int run_cross_epoch_management_fence_case(
    int use_discard,
    int parked_cycle)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_time_sample_t trusted;
    ninlil_id128_t fresh_epoch;
    ninlil_status_t status;
    uint64_t commit_calls;
    uint64_t ordered_sequence;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(persist_due_event_attempt(
                &env,
                parked_cycle != 0
                    ? NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE : 1u)
        == 0);
    if (parked_cycle != 0) {
        ninlil_step_budget_t budget;
        ninlil_step_result_t step_result;

        fill_step_budget(&budget);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
    }
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    if (parked_cycle != 0) {
        REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
        REQUIRE(transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT);
        REQUIRE(transaction->send_observation_closed == 1u);
    }
    transaction_before = *transaction;
    ordered_sequence = env.runtime->last_assigned_ordered_input_sequence;
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);

    if (use_discard != 0) {
        fill_discard_request(
            &discard_request,
            transaction,
            0x92u,
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
    } else {
        fill_resume_request(
            &resume_request,
            transaction,
            0x91u,
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
    }

    set_id(&fresh_epoch, use_discard != 0 ? 0xf2u : 0xf1u);
    REQUIRE(ninlil_test_clock_rollback(env.clock, &fresh_epoch));
    (void)memset(&trusted, 0, sizeof(trusted));
    set_header(
        &trusted.abi_version, &trusted.struct_size, sizeof(trusted));
    trusted.clock_epoch_id = fresh_epoch;
    trusted.now_ms = 2000u;
    trusted.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_recover(env.clock, &trusted));

    if (use_discard != 0) {
        (void)memset(&discard_result, 0xa5, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        status = ninlil_event_discard(
            env.runtime,
            &env.transaction_id,
            &discard_request,
            &discard_result);
        REQUIRE(discard_result_is_api_zero(&discard_result));
    } else {
        (void)memset(&resume_result, 0xa5, sizeof(resume_result));
        set_header(
            &resume_result.abi_version,
            &resume_result.struct_size,
            sizeof(resume_result));
        status = ninlil_event_resume(
            env.runtime,
            &env.transaction_id,
            &resume_request,
            &resume_result);
        REQUIRE(resume_result_is_api_zero(&resume_result));
    }
    REQUIRE(status == NINLIL_E_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_sequence);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                use_discard != 0 ? 0x44u : 0x52u)
        == 0u);
    env_teardown(&env);
    return 0;
}

static int test_cross_epoch_management_fails_closed_without_mutation(void)
{
    REQUIRE(run_cross_epoch_management_fence_case(0, 0) == 0);
    REQUIRE(run_cross_epoch_management_fence_case(1, 0) == 0);
    REQUIRE(run_cross_epoch_management_fence_case(0, 1) == 0);
    REQUIRE(run_cross_epoch_management_fence_case(1, 1) == 0);
    return 0;
}

typedef enum event_owner_clock_baseline {
    EVENT_OWNER_CLOCK_ADMISSION = 0,
    EVENT_OWNER_CLOCK_SEND_OBSERVATION = 1,
    EVENT_OWNER_CLOCK_RETRY_SCHEDULED = 2,
    EVENT_OWNER_CLOCK_RECENT_RETRY_HISTORY = 3,
    EVENT_OWNER_CLOCK_OLDER_RETRY_HISTORY = 4,
    EVENT_OWNER_CLOCK_PARKED_CYCLE_SEND_HISTORY = 5
} event_owner_clock_baseline_t;

static int run_cold_restart_owner_clock_regression_case(
    int use_discard,
    event_owner_clock_baseline_t baseline_kind,
    int exact_boundary)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_id128_t owner_epoch;
    ninlil_time_sample_t owner_sample;
    ninlil_time_sample_t regressed_sample;
    uint64_t owner_baseline_ms;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint64_t ordered_sequence;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    owner_epoch = transaction->admission_clock_epoch_id;
    owner_baseline_ms = transaction->admitted_at_ms;

    if (baseline_kind != EVENT_OWNER_CLOCK_ADMISSION) {
        REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
        (void)memset(&owner_sample, 0, sizeof(owner_sample));
        REQUIRE(env.platform.clock->now(
                    env.platform.clock->user, &owner_sample)
            == NINLIL_PORT_OK);
        REQUIRE(ninlil_rt_accept_trusted_clock_sample(
                    env.runtime, &owner_sample)
            == NINLIL_OK);
        candidate = &env.runtime->transaction_scratch;
        *candidate = *transaction;
        if (baseline_kind == EVENT_OWNER_CLOCK_SEND_OBSERVATION) {
            set_event_attempt_history(candidate, 1u);
            candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
            candidate->pending_dispatch = 0u;
            candidate->send_observation_closed = 1u;
            candidate->send_observed_clock_epoch_id =
                owner_sample.clock_epoch_id;
            candidate->send_observed_at_ms = owner_sample.now_ms;
            candidate->spool_revision += 1u;
            REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                        env.runtime,
                        transaction,
                        candidate,
                        DELIVERY_STARTED_PREFIX,
                        NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
                == NINLIL_OK);
            owner_baseline_ms = owner_sample.now_ms;
        } else if (baseline_kind == EVENT_OWNER_CLOCK_RETRY_SCHEDULED) {
            REQUIRE(candidate->retry_backoff_ms != 0u);
            REQUIRE(owner_sample.now_ms
                <= UINT64_MAX - candidate->retry_backoff_ms);
            candidate->next_retry_ms =
                owner_sample.now_ms + candidate->retry_backoff_ms;
            candidate->next_retry_clock_epoch_id =
                owner_sample.clock_epoch_id;
            REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                        env.runtime,
                        transaction,
                        candidate,
                        RETRY_STATE_PREFIX,
                        NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT)
                == NINLIL_OK);
            owner_baseline_ms = owner_sample.now_ms;
        } else if (baseline_kind
                == EVENT_OWNER_CLOCK_RECENT_RETRY_HISTORY) {
            candidate->retry_cycle_id = 3u;
            candidate->retry_summary_count = 2u;
            candidate->retry_summaries[0].retry_cycle_id = 1u;
            candidate->retry_summaries[0]
                    .last_observed_clock_epoch_id =
                owner_sample.clock_epoch_id;
            candidate->retry_summaries[0].last_observed_at_ms =
                owner_sample.now_ms;
            candidate->retry_summaries[1].retry_cycle_id = 2u;
            REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                        env.runtime,
                        transaction,
                        candidate,
                        RETRY_STATE_PREFIX,
                        NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT)
                == NINLIL_OK);
            owner_baseline_ms = owner_sample.now_ms;
        } else if (baseline_kind
                == EVENT_OWNER_CLOCK_OLDER_RETRY_HISTORY) {
            candidate->retry_cycle_id = 2u;
            candidate->older_retry_cycle_count = 1u;
            candidate->older_retry_last_observed_clock_epoch_id =
                owner_sample.clock_epoch_id;
            candidate->older_retry_last_observed_at_ms =
                owner_sample.now_ms;
            REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                        env.runtime,
                        transaction,
                        candidate,
                        RETRY_STATE_PREFIX,
                        NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT)
                == NINLIL_OK);
            owner_baseline_ms = owner_sample.now_ms;
        } else {
            set_event_attempt_history(
                candidate, NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
            candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
            candidate->pending_dispatch = 0u;
            candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
            candidate->send_observation_closed = 1u;
            candidate->send_observed_clock_epoch_id =
                owner_sample.clock_epoch_id;
            candidate->send_observed_at_ms = owner_sample.now_ms;
            candidate->spool_revision += 1u;
            REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                        env.runtime,
                        transaction,
                        candidate,
                        DELIVERY_STARTED_PREFIX,
                        NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
                == NINLIL_OK);
            REQUIRE(candidate->attempt_receipt_timeout_ms
                <= UINT64_MAX - 100u);
            REQUIRE(ninlil_test_clock_advance(
                env.clock,
                candidate->attempt_receipt_timeout_ms + 100u));
            fill_step_budget(&budget);
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            REQUIRE(ninlil_runtime_step(
                        env.runtime, &budget, &step_result)
                == NINLIL_OK);
            transaction = ninlil_rt_find_transaction(
                env.runtime, &env.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(transaction->delivery_phase
                == NINLIL_RT_DELIVERY_PARKED);
            REQUIRE(transaction->event_park_cause
                == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT);
            REQUIRE(transaction->send_observation_closed == 1u);
            REQUIRE(memcmp(
                        &transaction->send_observed_clock_epoch_id,
                        &owner_sample.clock_epoch_id,
                        sizeof(transaction->send_observed_clock_epoch_id))
                == 0);
            REQUIRE(transaction->send_observed_at_ms
                == owner_sample.now_ms);
            REQUIRE(owner_sample.now_ms
                <= UINT64_MAX - transaction->attempt_receipt_timeout_ms);
            owner_baseline_ms = owner_sample.now_ms
                + transaction->attempt_receipt_timeout_ms;
        }
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
    }

    if (use_discard != 0) {
        fill_discard_request(
            &discard_request,
            transaction,
            (uint8_t)(0xb0u + (uint8_t)baseline_kind),
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
    } else {
        fill_resume_request(
            &resume_request,
            transaction,
            (uint8_t)(0xa0u + (uint8_t)baseline_kind),
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
    }

    REQUIRE(owner_baseline_ms != 0u);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage);
    (void)memset(&regressed_sample, 0, sizeof(regressed_sample));
    set_header(
        &regressed_sample.abi_version,
        &regressed_sample.struct_size,
        sizeof(regressed_sample));
    regressed_sample.clock_epoch_id = owner_epoch;
    regressed_sample.now_ms = exact_boundary != 0
        ? owner_baseline_ms
        : owner_baseline_ms - 1u;
    regressed_sample.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &regressed_sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ordered_sequence = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);

    if (use_discard != 0) {
        (void)memset(&discard_result, 0xa5, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        status = ninlil_event_discard(
            env.runtime,
            &env.transaction_id,
            &discard_request,
            &discard_result);
        if (exact_boundary == 0) {
            REQUIRE(discard_result_is_api_zero(&discard_result));
        }
    } else {
        (void)memset(&resume_result, 0xa5, sizeof(resume_result));
        set_header(
            &resume_result.abi_version,
            &resume_result.struct_size,
            sizeof(resume_result));
        status = ninlil_event_resume(
            env.runtime,
            &env.transaction_id,
            &resume_request,
            &resume_result);
        if (exact_boundary == 0) {
            REQUIRE(resume_result_is_api_zero(&resume_result));
        }
    }
    if (exact_boundary != 0) {
        REQUIRE(status == NINLIL_OK);
        if (use_discard != 0) {
            REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
            REQUIRE(env.runtime->last_assigned_ordered_input_sequence
                == ordered_sequence + 1u);
        } else if (baseline_kind
                == EVENT_OWNER_CLOCK_PARKED_CYCLE_SEND_HISTORY) {
            REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_RESUMED);
            REQUIRE(env.runtime->last_assigned_ordered_input_sequence
                == ordered_sequence + 1u);
            transaction = ninlil_rt_find_transaction(
                env.runtime, &env.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(transaction->retry_summary_count == 1u);
            REQUIRE(memcmp(
                        &transaction->retry_summaries[0]
                            .last_observed_clock_epoch_id,
                        &owner_epoch,
                        sizeof(owner_epoch))
                == 0);
            REQUIRE(transaction->retry_summaries[0]
                    .last_observed_at_ms
                == owner_baseline_ms);
            REQUIRE(transaction->send_observation_closed == 0u);
            REQUIRE(transaction->send_observed_at_ms == 0u);
            REQUIRE(id_is_zero(
                &transaction->send_observed_clock_epoch_id));
        } else {
            REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_NOT_PARKED);
            REQUIRE(env.runtime->last_assigned_ordered_input_sequence
                == ordered_sequence);
        }
    } else {
        REQUIRE(status == NINLIL_E_DEGRADED);
        REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
        REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_sequence);
        REQUIRE(memcmp(
                    transaction, &transaction_before, sizeof(*transaction))
            == 0);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_PUT)
            == put_calls);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls);
        REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                    env.storage,
                    (ninlil_bytes_view_t){
                        TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                    0x45u,
                    use_discard != 0 ? 0x44u : 0x52u)
            == 0u);
    }
    env_teardown(&env);
    return 0;
}

static int test_cold_restart_event_owner_clock_regression_fails_closed(void)
{
    event_owner_clock_baseline_t baseline_kind;

    for (baseline_kind = EVENT_OWNER_CLOCK_ADMISSION;
         baseline_kind <= EVENT_OWNER_CLOCK_OLDER_RETRY_HISTORY;
         baseline_kind = (event_owner_clock_baseline_t)(
             (uint32_t)baseline_kind + 1u)) {
        REQUIRE(run_cold_restart_owner_clock_regression_case(
                    0, baseline_kind, 0)
            == 0);
        REQUIRE(run_cold_restart_owner_clock_regression_case(
                    1, baseline_kind, 0)
            == 0);
    }
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                0, EVENT_OWNER_CLOCK_RECENT_RETRY_HISTORY, 1)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                1, EVENT_OWNER_CLOCK_RECENT_RETRY_HISTORY, 1)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                0, EVENT_OWNER_CLOCK_OLDER_RETRY_HISTORY, 1)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                1, EVENT_OWNER_CLOCK_OLDER_RETRY_HISTORY, 1)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                0, EVENT_OWNER_CLOCK_PARKED_CYCLE_SEND_HISTORY, 0)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                1, EVENT_OWNER_CLOCK_PARKED_CYCLE_SEND_HISTORY, 0)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                0, EVENT_OWNER_CLOCK_PARKED_CYCLE_SEND_HISTORY, 1)
        == 0);
    REQUIRE(run_cold_restart_owner_clock_regression_case(
                1, EVENT_OWNER_CLOCK_PARKED_CYCLE_SEND_HISTORY, 1)
        == 0);
    return 0;
}

static int run_parked_cycle_deadline_overflow_case(int use_discard)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_id128_t owner_epoch;
    ninlil_time_sample_t sample;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint64_t ordered_sequence;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_receipt_timeout_ms > 1u);
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    set_event_attempt_history(
        candidate, NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
    candidate->pending_dispatch = 0u;
    candidate->event_park_cause =
        NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT;
    candidate->send_observation_closed = 1u;
    candidate->send_observed_clock_epoch_id =
        transaction->admission_clock_epoch_id;
    owner_epoch = candidate->send_observed_clock_epoch_id;
    candidate->send_observed_at_ms = UINT64_MAX
        - candidate->attempt_receipt_timeout_ms + 1u;
    candidate->spool_revision += 1u;
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env.runtime,
                transaction,
                candidate,
                EVENT_SPOOL_PREFIX,
                NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    if (use_discard != 0) {
        fill_discard_request(
            &discard_request,
            transaction,
            0xd2u,
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
    } else {
        fill_resume_request(
            &resume_request,
            transaction,
            0xd1u,
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage);
    (void)memset(&sample, 0, sizeof(sample));
    set_header(&sample.abi_version, &sample.struct_size, sizeof(sample));
    sample.clock_epoch_id = owner_epoch;
    sample.now_ms = UINT64_MAX;
    sample.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ordered_sequence = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);

    if (use_discard != 0) {
        (void)memset(&discard_result, 0xa5, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        status = ninlil_event_discard(
            env.runtime,
            &env.transaction_id,
            &discard_request,
            &discard_result);
        REQUIRE(discard_result_is_api_zero(&discard_result));
    } else {
        (void)memset(&resume_result, 0xa5, sizeof(resume_result));
        set_header(
            &resume_result.abi_version,
            &resume_result.struct_size,
            sizeof(resume_result));
        status = ninlil_event_resume(
            env.runtime,
            &env.transaction_id,
            &resume_request,
            &resume_result);
        REQUIRE(resume_result_is_api_zero(&resume_result));
    }
    REQUIRE(status == NINLIL_E_DEGRADED);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_sequence);
    REQUIRE(memcmp(
                transaction, &transaction_before, sizeof(*transaction))
        == 0);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    env_teardown(&env);
    return 0;
}

static int test_parked_cycle_deadline_overflow_fails_closed(void)
{
    REQUIRE(run_parked_cycle_deadline_overflow_case(0) == 0);
    REQUIRE(run_parked_cycle_deadline_overflow_case(1) == 0);
    return 0;
}

typedef enum started_receipt_boundary_case {
    STARTED_RECEIPT_STEP_OVERFLOW = 0,
    STARTED_RECEIPT_STEP_MISSING_TIMEOUT = 1,
    STARTED_RECEIPT_DISCARD_OVERFLOW = 2,
    STARTED_RECEIPT_DISCARD_EXACT_MAX = 3
} started_receipt_boundary_case_t;

static int run_started_receipt_boundary_case(
    started_receipt_boundary_case_t case_kind)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_time_sample_t sample;
    ninlil_id128_t owner_epoch;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint64_t ordered_sequence;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_receipt_timeout_ms > 1u);
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    set_event_attempt_history(candidate, 1u);
    candidate->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    candidate->pending_dispatch = 0u;
    candidate->event_park_cause = NINLIL_EVENT_PARK_CAUSE_NONE;
    candidate->send_observation_closed = 1u;
    candidate->send_observed_clock_epoch_id =
        transaction->admission_clock_epoch_id;
    owner_epoch = candidate->send_observed_clock_epoch_id;
    if (case_kind == STARTED_RECEIPT_STEP_MISSING_TIMEOUT) {
        candidate->attempt_receipt_timeout_ms = 0u;
        candidate->send_observed_at_ms = 1000u;
    } else {
        candidate->send_observed_at_ms = UINT64_MAX
            - candidate->attempt_receipt_timeout_ms
            + (case_kind == STARTED_RECEIPT_DISCARD_EXACT_MAX ? 0u : 1u);
    }
    candidate->spool_revision += 1u;
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env.runtime,
                transaction,
                candidate,
                DELIVERY_STARTED_PREFIX,
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    if (case_kind != STARTED_RECEIPT_STEP_OVERFLOW) {
        fill_discard_request(
            &discard_request,
            transaction,
            case_kind == STARTED_RECEIPT_DISCARD_EXACT_MAX
                ? 0xd4u : 0xd3u,
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage);
    (void)memset(&sample, 0, sizeof(sample));
    set_header(&sample.abi_version, &sample.struct_size, sizeof(sample));
    sample.clock_epoch_id = owner_epoch;
    sample.now_ms = UINT64_MAX;
    sample.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    ordered_sequence = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);

    if (case_kind == STARTED_RECEIPT_STEP_OVERFLOW
        || case_kind == STARTED_RECEIPT_STEP_MISSING_TIMEOUT) {
        fill_step_budget(&budget);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        status = ninlil_runtime_step(env.runtime, &budget, &step_result);
        REQUIRE(step_result.has_next_wake == 0u);
        REQUIRE(step_result.next_wake_at_ms == 0u);
    } else {
        (void)memset(&discard_result, 0xa5, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        status = ninlil_event_discard(
            env.runtime,
            &env.transaction_id,
            &discard_request,
            &discard_result);
    }
    if (case_kind == STARTED_RECEIPT_DISCARD_EXACT_MAX) {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_sequence + 1u);
    } else {
        REQUIRE(status == NINLIL_E_DEGRADED);
        if (case_kind == STARTED_RECEIPT_DISCARD_OVERFLOW) {
            REQUIRE(discard_result_is_api_zero(&discard_result));
        }
        REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
        REQUIRE(env.runtime->degraded_reason
            == NINLIL_REASON_CLOCK_UNCERTAIN);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_sequence);
        REQUIRE(memcmp(
                    transaction,
                    &transaction_before,
                    sizeof(*transaction))
            == 0);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_PUT)
            == put_calls);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls);
    }
    env_teardown(&env);
    return 0;
}

static int test_started_receipt_deadline_boundary(void)
{
    REQUIRE(run_started_receipt_boundary_case(
                STARTED_RECEIPT_STEP_OVERFLOW)
        == 0);
    REQUIRE(run_started_receipt_boundary_case(
                STARTED_RECEIPT_STEP_MISSING_TIMEOUT)
        == 0);
    REQUIRE(run_started_receipt_boundary_case(
                STARTED_RECEIPT_DISCARD_OVERFLOW)
        == 0);
    REQUIRE(run_started_receipt_boundary_case(
                STARTED_RECEIPT_DISCARD_EXACT_MAX)
        == 0);
    return 0;
}

typedef enum automatic_resume_clock_baseline {
    AUTOMATIC_RESUME_CLOCK_CYCLE_END = 0,
    AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION = 1,
    AUTOMATIC_RESUME_CLOCK_CROSS_EPOCH = 2
} automatic_resume_clock_baseline_t;

static int run_cold_restart_automatic_resume_clock_case(
    automatic_resume_clock_baseline_t baseline_kind,
    int exact_boundary)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_bearer_state_t available_state;
    ninlil_bearer_state_t resume_state;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_time_sample_t restart_sample;
    ninlil_id128_t owner_epoch;
    uint64_t bearer_observed_at_ms = 0u;
    uint64_t cycle_ended_at_ms;
    uint64_t restart_baseline_ms;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint64_t retry_cycle_id;
    uint64_t spool_revision;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    (void)memset(&available_state, 0, sizeof(available_state));
    set_header(
        &available_state.abi_version,
        &available_state.struct_size,
        sizeof(available_state));
    available_state.availability_epoch = 2u;
    available_state.available = 1u;
    resume_state = available_state;
    resume_state.availability_epoch = 3u;

    if (baseline_kind != AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION) {
        /* Persist A before the accepted send so V is the later boundary. */
        REQUIRE(ninlil_test_bearer_raw_state_enqueue(
            env.bearer, NINLIL_BEARER_OK, &available_state, 1u));
        fill_step_budget(&budget);
        budget.max_state_transitions = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
        REQUIRE(env.runtime->bearer_state_present == 1u);
        REQUIRE(env.runtime->bearer_availability_epoch
            == available_state.availability_epoch);
        bearer_observed_at_ms = env.runtime->bearer_observed_at_ms;
    }

    REQUIRE(persist_due_event_attempt(
                &env, NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE)
        == 0);
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(
                env.runtime, &budget, &step_result)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    REQUIRE(transaction->event_park_cause
        == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT);
    REQUIRE(transaction->send_observation_closed == 1u);
    if (baseline_kind != AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION) {
        /* The new park writer snapshots the latest namespace epoch. */
        REQUIRE(transaction->last_bearer_availability_epoch
            == available_state.availability_epoch);
        REQUIRE(transaction->last_consumed_bearer_availability_epoch
            == available_state.availability_epoch);
        /* Simulate a legacy parked owner written before that fix. */
        candidate = &env.runtime->transaction_scratch;
        *candidate = *transaction;
        candidate->last_bearer_availability_epoch = 1u;
        candidate->last_consumed_bearer_availability_epoch = 1u;
        REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                    env.runtime,
                    transaction,
                    candidate,
                    EVENT_SPOOL_PREFIX,
                    NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
    }
    REQUIRE(transaction->send_observed_at_ms
        <= UINT64_MAX - transaction->attempt_receipt_timeout_ms);
    owner_epoch = transaction->send_observed_clock_epoch_id;
    cycle_ended_at_ms = transaction->send_observed_at_ms
        + transaction->attempt_receipt_timeout_ms;

    if (baseline_kind == AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION) {
        /* Persist fresh B with observation A strictly after V. */
        REQUIRE(ninlil_test_clock_advance(env.clock, 500u));
        REQUIRE(ninlil_test_bearer_raw_state_enqueue(
            env.bearer, NINLIL_BEARER_OK, &resume_state, 1u));
        fill_step_budget(&budget);
        budget.max_state_transitions = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_PARKED);
        bearer_observed_at_ms = env.runtime->bearer_observed_at_ms;
        REQUIRE(bearer_observed_at_ms > cycle_ended_at_ms);
        /* Keep B fresh for the automatic consume after restart. */
        candidate = &env.runtime->transaction_scratch;
        *candidate = *transaction;
        candidate->last_bearer_availability_epoch = 1u;
        candidate->last_consumed_bearer_availability_epoch = 1u;
        REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                    env.runtime,
                    transaction,
                    candidate,
                    EVENT_SPOOL_PREFIX,
                    NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
    } else {
        REQUIRE(bearer_observed_at_ms < cycle_ended_at_ms);
    }
    REQUIRE(env.runtime->bearer_available == 1u);
    if (baseline_kind == AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION) {
        REQUIRE(env.runtime->bearer_availability_epoch
            == resume_state.availability_epoch);
    } else {
        REQUIRE(env.runtime->bearer_availability_epoch
            == available_state.availability_epoch);
    }
    REQUIRE(memcmp(
                &env.runtime->bearer_observed_clock_epoch_id,
                &owner_epoch,
                sizeof(owner_epoch))
        == 0);
    REQUIRE(transaction->last_bearer_availability_epoch
        < resume_state.availability_epoch);
    REQUIRE(transaction->last_consumed_bearer_availability_epoch
        < resume_state.availability_epoch);
    retry_cycle_id = transaction->retry_cycle_id;
    spool_revision = transaction->spool_revision;

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage);
    (void)memset(&restart_sample, 0, sizeof(restart_sample));
    set_header(
        &restart_sample.abi_version,
        &restart_sample.struct_size,
        sizeof(restart_sample));
    restart_baseline_ms = baseline_kind
            == AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION
        ? bearer_observed_at_ms : cycle_ended_at_ms;
    restart_sample.clock_epoch_id = owner_epoch;
    restart_sample.now_ms = exact_boundary != 0
        ? restart_baseline_ms : restart_baseline_ms - 1u;
    restart_sample.trust = NINLIL_CLOCK_TRUSTED;
    if (baseline_kind == AUTOMATIC_RESUME_CLOCK_CROSS_EPOCH) {
        set_id(&restart_sample.clock_epoch_id, 0xe0u);
        restart_sample.now_ms = restart_baseline_ms;
    }
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &restart_sample, 3u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_test_bearer_raw_state_enqueue(
        env.bearer, NINLIL_BEARER_OK, &resume_state, 2u));
    fill_step_budget(&budget);
    budget.max_state_transitions = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    status = ninlil_runtime_step(env.runtime, &budget, &step_result);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    if (baseline_kind == AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION
        && exact_boundary == 0) {
        REQUIRE(status == NINLIL_E_DEGRADED);
        REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
        REQUIRE(env.runtime->degraded_reason
            == NINLIL_REASON_CLOCK_UNCERTAIN);
        REQUIRE(step_result.state_transitions == 0u);
    } else if (baseline_kind == AUTOMATIC_RESUME_CLOCK_CROSS_EPOCH) {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(step_result.state_transitions == 1u);
        REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    } else if (baseline_kind == AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION) {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(step_result.state_transitions == 1u);
        REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_QUEUED);
    } else {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(step_result.state_transitions == 1u);
        REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    }
    if (status == NINLIL_OK
        && transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED) {
        transaction_before = *transaction;
        put_calls = ninlil_test_storage_call_count(
            env.storage, NINLIL_TEST_STORAGE_OP_PUT);
        commit_calls = ninlil_test_storage_call_count(
            env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        status = ninlil_runtime_step(env.runtime, &budget, &step_result);
    }

    if (exact_boundary == 0
        || baseline_kind == AUTOMATIC_RESUME_CLOCK_CROSS_EPOCH) {
        REQUIRE(status == (baseline_kind
                    == AUTOMATIC_RESUME_CLOCK_CROSS_EPOCH
                ? NINLIL_E_CLOCK_UNCERTAIN : NINLIL_E_DEGRADED));
        REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
        REQUIRE(env.runtime->degraded_reason
            == NINLIL_REASON_CLOCK_UNCERTAIN);
        REQUIRE(step_result.state_transitions == 0u);
        REQUIRE(memcmp(
                    transaction,
                    &transaction_before,
                    sizeof(*transaction))
            == 0);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_PUT)
            == put_calls);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls);
    } else {
        REQUIRE(status == NINLIL_OK);
        REQUIRE(step_result.state_transitions == 1u);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->retry_cycle_id == retry_cycle_id + 1u);
        REQUIRE(transaction->spool_revision == spool_revision + 1u);
        REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_QUEUED);
        REQUIRE(transaction->retry_summary_count == 1u);
        REQUIRE(memcmp(
                    &transaction->retry_summaries[0]
                        .last_observed_clock_epoch_id,
                    &owner_epoch,
                    sizeof(owner_epoch))
            == 0);
        REQUIRE(transaction->retry_summaries[0].last_observed_at_ms
            == cycle_ended_at_ms);
        REQUIRE(transaction->send_observation_closed == 0u);
        REQUIRE(transaction->send_observed_at_ms == 0u);
        REQUIRE(id_is_zero(
            &transaction->send_observed_clock_epoch_id));
        REQUIRE(transaction->last_bearer_availability_epoch
            == resume_state.availability_epoch);
        REQUIRE(transaction->last_consumed_bearer_availability_epoch
            == resume_state.availability_epoch);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls + 1u);
    }
    env_teardown(&env);
    return 0;
}

static int test_cold_restart_automatic_resume_clock_guard(void)
{
    REQUIRE(run_cold_restart_automatic_resume_clock_case(
                AUTOMATIC_RESUME_CLOCK_CYCLE_END, 0)
        == 0);
    REQUIRE(run_cold_restart_automatic_resume_clock_case(
                AUTOMATIC_RESUME_CLOCK_CYCLE_END, 1)
        == 0);
    REQUIRE(run_cold_restart_automatic_resume_clock_case(
                AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION, 0)
        == 0);
    REQUIRE(run_cold_restart_automatic_resume_clock_case(
                AUTOMATIC_RESUME_CLOCK_BEARER_OBSERVATION, 1)
        == 0);
    REQUIRE(run_cold_restart_automatic_resume_clock_case(
                AUTOMATIC_RESUME_CLOCK_CROSS_EPOCH, 0)
        == 0);
    return 0;
}

static int test_cold_restart_automatic_resume_overflow_fails_closed(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t *candidate;
    ninlil_bearer_state_t available_state;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_time_sample_t restart_sample;
    ninlil_id128_t owner_epoch;
    uint64_t put_calls;
    uint64_t commit_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    (void)memset(&available_state, 0, sizeof(available_state));
    set_header(
        &available_state.abi_version,
        &available_state.struct_size,
        sizeof(available_state));
    available_state.availability_epoch = 2u;
    available_state.available = 1u;
    REQUIRE(ninlil_test_bearer_raw_state_enqueue(
        env.bearer, NINLIL_BEARER_OK, &available_state, 1u));
    fill_step_budget(&budget);
    budget.max_state_transitions = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_OK);

    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_receipt_timeout_ms > 1u);
    candidate = &env.runtime->transaction_scratch;
    *candidate = *transaction;
    set_event_attempt_history(
        candidate, NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    candidate->delivery_phase = NINLIL_RT_DELIVERY_PARKED;
    candidate->pending_dispatch = 0u;
    candidate->event_park_cause =
        NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT;
    candidate->send_observation_closed = 1u;
    candidate->send_observed_clock_epoch_id =
        transaction->admission_clock_epoch_id;
    owner_epoch = candidate->send_observed_clock_epoch_id;
    candidate->send_observed_at_ms = UINT64_MAX
        - candidate->attempt_receipt_timeout_ms + 1u;
    candidate->spool_revision += 1u;
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env.runtime,
                transaction,
                candidate,
                EVENT_SPOOL_PREFIX,
                NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    ninlil_test_storage_simulate_crash(env.storage);
    (void)memset(&restart_sample, 0, sizeof(restart_sample));
    set_header(
        &restart_sample.abi_version,
        &restart_sample.struct_size,
        sizeof(restart_sample));
    restart_sample.clock_epoch_id = owner_epoch;
    restart_sample.now_ms = UINT64_MAX;
    restart_sample.trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &restart_sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_before = *transaction;
    REQUIRE(ninlil_test_bearer_raw_state_enqueue(
        env.bearer, NINLIL_BEARER_OK, &available_state, 1u));
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
    fill_step_budget(&budget);
    budget.max_state_transitions = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result)
        == NINLIL_E_DEGRADED);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(step_result.state_transitions == 0u);
    REQUIRE(memcmp(
                transaction, &transaction_before, sizeof(*transaction))
        == 0);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    env_teardown(&env);
    return 0;
}

static int resume_once_at_owner_sample(
    event_env_t *env,
    ninlil_event_resume_request_t *out_request,
    ninlil_time_sample_t *out_sample)
{
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_result_t result;
    ninlil_rt_v1_event_ledger_record_t record;

    REQUIRE(park_event(env) == 0);
    transaction = ninlil_rt_find_transaction(
        env->runtime, &env->transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(env->platform.clock->now(
                env->platform.clock->user, out_sample)
        == NINLIL_PORT_OK);
    fill_resume_request(
        out_request,
        transaction,
        0xedu,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env->runtime,
                &env->transaction_id,
                out_request,
                &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
    REQUIRE(read_event_ledger(
                env,
                NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
                &out_request->operation_id,
                &record)
        == 0);
    REQUIRE(memcmp(
                record.audit_clock_epoch_id.bytes,
                out_sample->clock_epoch_id.bytes,
                sizeof(record.audit_clock_epoch_id.bytes))
        == 0);
    REQUIRE(record.audit_committed_at_ms == out_sample->now_ms);
    return 0;
}

static int test_resume_ledger_audit_chronology_and_legacy_fence(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_event_resume_request_t original_request;
    ninlil_event_resume_request_t unseen_resume;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t unseen_discard;
    ninlil_event_discard_result_t discard_result;
    ninlil_time_sample_t owner_sample;
    ninlil_time_sample_t restart_sample;
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint32_t value_length;
    uint64_t ordered_before;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint64_t clock_calls;

    /* Canonical resume audit is a cold-restart baseline; replay stays clock0. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
    REQUIRE(resume_once_at_owner_sample(
                &env, &original_request, &owner_sample)
        == 0);
    REQUIRE(owner_sample.now_ms != 0u);
    REQUIRE(stop_runtime(&env) == 0);
    ninlil_test_storage_simulate_crash(env.storage);
    restart_sample = owner_sample;
    restart_sample.now_ms -= 1u;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &restart_sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&resume_result, 0, sizeof(resume_result));
    set_header(
        &resume_result.abi_version,
        &resume_result.struct_size,
        sizeof(resume_result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &original_request,
                &resume_result)
        == NINLIL_OK);
    REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &unseen_resume,
        transaction,
        0xeeu,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    transaction_before = *transaction;
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
    (void)memset(&resume_result, 0xa5, sizeof(resume_result));
    set_header(
        &resume_result.abi_version,
        &resume_result.struct_size,
        sizeof(resume_result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &unseen_resume,
                &resume_result)
        == NINLIL_E_DEGRADED);
    REQUIRE(resume_result_is_api_zero(&resume_result));
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    env_teardown(&env);

    /* Equality is accepted and reaches the ordinary current-state semantic. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
    REQUIRE(resume_once_at_owner_sample(
                &env, &original_request, &owner_sample)
        == 0);
    REQUIRE(stop_runtime(&env) == 0);
    ninlil_test_storage_simulate_crash(env.storage);
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &owner_sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &unseen_resume,
        transaction,
        0xeeu,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    (void)memset(&resume_result, 0, sizeof(resume_result));
    set_header(
        &resume_result.abi_version,
        &resume_result.struct_size,
        sizeof(resume_result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &unseen_resume,
                &resume_result)
        == NINLIL_OK);
    REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_NOT_PARKED);
    env_teardown(&env);

    /* Legacy zero/zero remains replayable, but any ledger miss fails closed. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
    REQUIRE(resume_once_at_owner_sample(
                &env, &original_request, &owner_sample)
        == 0);
    REQUIRE(stop_runtime(&env) == 0);
    ninlil_rt_v1_event_ledger_key(
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        &env.transaction_id,
        &original_request.operation_id,
        key);
    REQUIRE(raw_storage_read(
        &env,
        (ninlil_bytes_view_t){key, sizeof(key)},
        value,
        (uint32_t)sizeof(value),
        &value_length));
    REQUIRE(value_length >= 228u);
    (void)memset(&value[200], 0, 24u);
    refresh_event_ledger_crc(value, value_length);
    {
        ninlil_bytes_view_t legacy_value = {value, value_length};

        REQUIRE(raw_storage_mutate(
            &env,
            (ninlil_bytes_view_t){key, sizeof(key)},
            &legacy_value));
    }
    ninlil_test_storage_simulate_crash(env.storage);
    restart_sample = owner_sample;
    restart_sample.now_ms += 1u;
    REQUIRE(ninlil_test_clock_script_raw(
        env.clock, NINLIL_PORT_OK, &restart_sample, 2u));
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&resume_result, 0, sizeof(resume_result));
    set_header(
        &resume_result.abi_version,
        &resume_result.struct_size,
        sizeof(resume_result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &original_request,
                &resume_result)
        == NINLIL_OK);
    REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_discard_request(
        &unseen_discard,
        transaction,
        0xefu,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    transaction_before = *transaction;
    ordered_before = env.runtime->last_assigned_ordered_input_sequence;
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&discard_result, 0xa5, sizeof(discard_result));
    set_header(
        &discard_result.abi_version,
        &discard_result.struct_size,
        sizeof(discard_result));
    REQUIRE(ninlil_event_discard(
                env.runtime,
                &env.transaction_id,
                &unseen_discard,
                &discard_result)
        == NINLIL_E_CLOCK_UNCERTAIN);
    REQUIRE(discard_result_is_api_zero(&discard_result));
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_CLOCK_UNCERTAIN);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == ordered_before);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    env_teardown(&env);
    return 0;
}

static int test_discard_ledger_audit_chronology(void)
{
    uint32_t exact_boundary;

    for (exact_boundary = 0u; exact_boundary <= 1u; ++exact_boundary) {
        event_env_t env;
        ninlil_rt_transaction_slot_t *transaction;
        ninlil_rt_transaction_slot_t transaction_before;
        ninlil_event_discard_request_t discard_request;
        ninlil_event_discard_result_t discard_result;
        ninlil_event_resume_request_t unseen_resume;
        ninlil_event_resume_result_t resume_result;
        ninlil_rt_v1_event_ledger_record_t record;
        ninlil_time_sample_t owner_sample;
        ninlil_time_sample_t restart_sample;
        uint64_t ordered_before;
        uint64_t put_calls;
        uint64_t commit_calls;

        (void)memset(&env, 0, sizeof(env));
        REQUIRE(platform_init(&env));
        REQUIRE(ninlil_test_clock_advance(env.clock, 1000u));
        REQUIRE(env_open(&env) == 0);
        REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        fill_discard_request(
            &discard_request,
            transaction,
            (uint8_t)(0xd8u + exact_boundary),
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
        REQUIRE(env.platform.clock->now(
                    env.platform.clock->user, &owner_sample)
            == NINLIL_PORT_OK);
        (void)memset(&discard_result, 0, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        REQUIRE(ninlil_event_discard(
                    env.runtime,
                    &env.transaction_id,
                    &discard_request,
                    &discard_result)
            == NINLIL_OK);
        REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
        REQUIRE(memcmp(
                    discard_result.audit_clock_epoch_id.bytes,
                    owner_sample.clock_epoch_id.bytes,
                    sizeof(discard_result.audit_clock_epoch_id.bytes))
            == 0);
        REQUIRE(discard_result.audit_committed_at_ms == owner_sample.now_ms);
        REQUIRE(read_event_ledger(
                    &env,
                    NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
                    &discard_request.operation_id,
                    &record)
            == 0);
        REQUIRE(memcmp(
                    record.audit_clock_epoch_id.bytes,
                    owner_sample.clock_epoch_id.bytes,
                    sizeof(record.audit_clock_epoch_id.bytes))
            == 0);
        REQUIRE(record.audit_committed_at_ms == owner_sample.now_ms);
        REQUIRE(stop_runtime(&env) == 0);
        ninlil_test_storage_simulate_crash(env.storage);
        restart_sample = owner_sample;
        if (exact_boundary == 0u) {
            restart_sample.now_ms -= 1u;
        }
        REQUIRE(ninlil_test_clock_script_raw(
            env.clock, NINLIL_PORT_OK, &restart_sample, 2u));
        REQUIRE(ninlil_runtime_create(
                    &env.config, &env.platform, &env.runtime)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        fill_resume_request(
            &unseen_resume,
            transaction,
            (uint8_t)(0xe8u + exact_boundary),
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
        transaction_before = *transaction;
        ordered_before = env.runtime->last_assigned_ordered_input_sequence;
        put_calls = ninlil_test_storage_call_count(
            env.storage, NINLIL_TEST_STORAGE_OP_PUT);
        commit_calls = ninlil_test_storage_call_count(
            env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
        (void)memset(&resume_result, 0xa5, sizeof(resume_result));
        set_header(
            &resume_result.abi_version,
            &resume_result.struct_size,
            sizeof(resume_result));
        if (exact_boundary == 0u) {
            REQUIRE(ninlil_event_resume(
                        env.runtime,
                        &env.transaction_id,
                        &unseen_resume,
                        &resume_result)
                == NINLIL_E_DEGRADED);
            REQUIRE(resume_result_is_api_zero(&resume_result));
            REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
            REQUIRE(env.runtime->degraded_reason
                == NINLIL_REASON_CLOCK_UNCERTAIN);
        } else {
            REQUIRE(ninlil_event_resume(
                        env.runtime,
                        &env.transaction_id,
                        &unseen_resume,
                        &resume_result)
                == NINLIL_OK);
            REQUIRE(resume_result.kind
                == NINLIL_EVENT_RESUME_ALREADY_DISCARDED);
        }
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ordered_before);
        REQUIRE(memcmp(
                    transaction, &transaction_before, sizeof(*transaction))
            == 0);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_PUT)
            == put_calls);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commit_calls);
        env_teardown(&env);
    }
    return 0;
}

static int test_syntax_role_replay_conflict_and_restart(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_request_t changed;
    ninlil_event_resume_result_t result;
    ninlil_event_resume_result_t initial;
    ninlil_event_discard_request_t cross_kind;
    ninlil_event_discard_result_t discard_result;
    uint8_t changed_metadata[] = "resume-audiX";
    uint64_t get_calls;
    uint64_t clock_calls;
    uint64_t capacity_used;
    uint64_t capacity_reserved;
    ninlil_role_t saved_role;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(event_spool_bytes(
                &env, &capacity_used, &capacity_reserved)
        == 0);
    REQUIRE(capacity_used == sizeof(PAYLOAD));
    REQUIRE(capacity_reserved
        == NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0xa0u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);

    changed = request;
    changed.audit_metadata.data = NULL;
    changed.audit_metadata.length = 0u;
    get_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_GET);
    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &changed, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(resume_result_is_api_zero(&result));
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_GET)
        == get_calls);

    saved_role = env.runtime->config.role;
    env.runtime->config.role = NINLIL_ROLE_CONTROLLER;
    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(resume_result_is_api_zero(&result));
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_GET)
        == get_calls);
    env.runtime->config.role = saved_role;

    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
    REQUIRE(result.reason == NINLIL_REASON_NONE);
    initial = result;
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->resume_op_count == 1u);
    REQUIRE(event_spool_bytes(
                &env, &capacity_used, &capacity_reserved)
        == 0);
    REQUIRE(capacity_used == sizeof(PAYLOAD) + 256u);
    REQUIRE(capacity_reserved
        == NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES - 256u);

    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED);
    REQUIRE(result.retry_cycle_id == initial.retry_cycle_id);
    REQUIRE(result.spool_revision == initial.spool_revision);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    changed = request;
    changed.audit_metadata.data = changed_metadata;
    changed.audit_metadata.length = sizeof(changed_metadata) - 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &changed, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_CONFLICT);
    REQUIRE(result.reason == NINLIL_REASON_RESUME_CONFLICT);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    fill_discard_request(
        &cross_kind,
        transaction,
        0xa0u,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    (void)memset(&discard_result, 0, sizeof(discard_result));
    set_header(
        &discard_result.abi_version,
        &discard_result.struct_size,
        sizeof(discard_result));
    REQUIRE(ninlil_event_discard(
                env.runtime,
                &env.transaction_id,
                &cross_kind,
                &discard_result)
        == NINLIL_OK);
    REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_CONFLICT);
    REQUIRE(discard_result.reason == NINLIL_REASON_DISCARD_CONFLICT);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    REQUIRE(env_restart(&env) == 0);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED);
    REQUIRE(result.retry_cycle_id == initial.retry_cycle_id);
    REQUIRE(result.spool_revision == initial.spool_revision);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    env_teardown(&env);
    return 0;
}

static int test_eight_resume_limit_and_old_replay(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_request_t first_request = {0};
    ninlil_event_resume_result_t result;
    ninlil_event_resume_result_t first_result = {0};
    ninlil_rt_v1_event_ledger_record_t ledger_record;
    ninlil_model_runtime_store_counter_t ordered_counter;
    uint32_t index;
    uint64_t before_revision;
    uint64_t capacity_used;
    uint64_t capacity_reserved;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    for (index = 0u;
         index < NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS;
         ++index) {
        REQUIRE(park_event(&env) == 0);
        transaction =
            ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        fill_resume_request(
            &request,
            transaction,
            (uint8_t)(0x30u + index * 0x10u),
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
        (void)memset(&result, 0, sizeof(result));
        set_header(
            &result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_event_resume(
                    env.runtime,
                    &env.transaction_id,
                    &request,
                    &result)
            == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
        REQUIRE(result.retry_cycle_id == (uint64_t)index + 2u);
        REQUIRE(read_event_ledger(
                    &env,
                    NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
                    &request.operation_id,
                    &ledger_record)
            == 0);
        REQUIRE(ledger_record.ordered_sequence == (uint64_t)index + 1u);
        transaction =
            ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->ordered_input_sequence
            == ledger_record.ordered_sequence);
        REQUIRE(env.runtime->last_assigned_ordered_input_sequence
            == ledger_record.ordered_sequence);
        REQUIRE(read_ordered_input_counter(&env, &ordered_counter) == 0);
        REQUIRE(ordered_counter.value == ledger_record.ordered_sequence);
        REQUIRE(ordered_counter.exhausted_marker == 0u);
        if (index == 0u) {
            first_request = request;
            first_result = result;
        }
    }
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                0x52u)
        == NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->retry_cycle_id == 9u);
    REQUIRE(transaction->attempt_in_cycle == 0u);
    REQUIRE(transaction->cumulative_attempts == 0u);
    REQUIRE(transaction->retry_summary_count
        == NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS);
    REQUIRE(transaction->older_retry_cycle_count == 4u);
    REQUIRE(event_spool_bytes(
                &env, &capacity_used, &capacity_reserved)
        == 0);
    REQUIRE(capacity_used
        == sizeof(PAYLOAD)
            + NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS * 256u);
    REQUIRE(capacity_reserved == 512u);
    for (index = 0u;
         index < NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS;
         ++index) {
        REQUIRE(transaction->retry_summaries[index].retry_cycle_id
            == (uint64_t)index + 5u);
        REQUIRE(transaction->retry_summaries[index].attempt_count == 0u);
    }
    REQUIRE(env_restart(&env) == 0);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS);
    REQUIRE(read_ordered_input_counter(&env, &ordered_counter) == 0);
    REQUIRE(ordered_counter.value
        == NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->retry_cycle_id == 9u);
    REQUIRE(transaction->retry_summary_count
        == NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS);
    REQUIRE(transaction->older_retry_cycle_count == 4u);
    REQUIRE(transaction->cumulative_attempts == 0u);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0xe0u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    before_revision = transaction->spool_revision;
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_LIMIT_EXHAUSTED);
    REQUIRE(result.reason == NINLIL_REASON_CAPACITY_EXHAUSTED);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction->spool_revision == before_revision);
    REQUIRE(transaction->resume_op_count
        == NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS);

    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &first_request,
                &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED);
    REQUIRE(result.retry_cycle_id == first_result.retry_cycle_id);
    REQUIRE(result.spool_revision == first_result.spool_revision);
    env_teardown(&env);
    return 0;
}

static int test_discard_replay_conflict_and_restart(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_discard_request_t request;
    ninlil_event_discard_request_t changed;
    ninlil_event_discard_result_t result;
    ninlil_event_discard_result_t initial;
    uint8_t changed_metadata[] = "discard-audiX";
    uint64_t clock_calls;
    uint64_t capacity_used;
    uint64_t capacity_reserved;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_discard_request(
        &request,
        transaction,
        0xb0u,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
    REQUIRE(result.reason
        == NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT);
    REQUIRE(result.spool_released == 1u);
    REQUIRE(!id_is_zero(&result.audit_clock_epoch_id));
    initial = result;
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->event_discarded == 1u);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(transaction->reservation_active == 0u);
    REQUIRE(transaction->payload_length == 0u);
    REQUIRE(event_spool_bytes(
                &env, &capacity_used, &capacity_reserved)
        == 0);
    REQUIRE(capacity_used == 512u);
    REQUIRE(capacity_reserved == 0u);

    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_ALREADY_DISCARDED);
    REQUIRE(result.spool_revision == initial.spool_revision);
    REQUIRE(result.audit_committed_at_ms
        == initial.audit_committed_at_ms);
    REQUIRE(result.spool_released == 1u);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    changed = request;
    changed.audit_metadata.data = changed_metadata;
    changed.audit_metadata.length = sizeof(changed_metadata) - 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &changed, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_CONFLICT);
    REQUIRE(result.spool_released == 0u);
    REQUIRE(id_is_zero(&result.audit_clock_epoch_id));
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);

    REQUIRE(env_restart(&env) == 0);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_ALREADY_DISCARDED);
    REQUIRE(result.spool_revision == initial.spool_revision);
    REQUIRE(result.audit_committed_at_ms
        == initial.audit_committed_at_ms);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    env_teardown(&env);
    return 0;
}

static int run_commit_unknown_case(int committed_truth)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    ninlil_model_runtime_store_counter_t ordered_counter;
    uint64_t parked_revision;
    uint64_t get_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    parked_revision = transaction->spool_revision;
    fill_resume_request(
        &request,
        transaction,
        0xf0u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        committed_truth));
    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(resume_result_is_api_zero(&result));
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    REQUIRE(transaction->spool_revision == parked_revision);
    REQUIRE(transaction->resume_op_count == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 0u);
    REQUIRE(read_ordered_input_counter(&env, &ordered_counter) == 0);
    REQUIRE(ordered_counter.value
        == (committed_truth != 0 ? 1u : 0u));

    get_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_GET);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(resume_result_is_api_zero(&result));
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_GET)
        == get_calls);

    REQUIRE(env_restart_after_commit_unknown(&env) == 0);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == (committed_truth != 0 ? 1u : 0u));
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == (committed_truth != 0
            ? NINLIL_EVENT_RESUME_ALREADY_RESUMED
            : NINLIL_EVENT_RESUME_RESUMED));
    REQUIRE(result.spool_revision == parked_revision + 1u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->resume_op_count == 1u);
    REQUIRE(transaction->spool_revision == parked_revision + 1u);
    REQUIRE(transaction->ordered_input_sequence == 1u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 1u);
    REQUIRE(read_ordered_input_counter(&env, &ordered_counter) == 0);
    REQUIRE(ordered_counter.value == 1u);
    env_teardown(&env);
    return 0;
}

static int test_commit_unknown_hidden_truths(void)
{
    REQUIRE(run_commit_unknown_case(0) == 0);
    REQUIRE(run_commit_unknown_case(1) == 0);
    return 0;
}

static int trace_has_exact_full_event_group(
    const event_env_t *env,
    size_t trace_start,
    uint32_t expected_erase_count)
{
    size_t trace_index;
    uint32_t put_count = 0u;
    uint32_t erase_count = 0u;
    uint32_t commit_count = 0u;

    for (trace_index = trace_start;
         trace_index < ninlil_test_storage_trace_count(env->storage);
         ++trace_index) {
        const ninlil_test_storage_trace_record_t *record =
            ninlil_test_storage_trace_at(env->storage, trace_index);

        REQUIRE(record != NULL);
        if (record->operation == NINLIL_TEST_STORAGE_OP_PUT) {
            REQUIRE(record->status == NINLIL_STORAGE_OK);
            put_count += 1u;
        } else if (record->operation == NINLIL_TEST_STORAGE_OP_ERASE) {
            REQUIRE(record->status == NINLIL_STORAGE_OK);
            erase_count += 1u;
        } else if (record->operation == NINLIL_TEST_STORAGE_OP_COMMIT) {
            REQUIRE(record->status == NINLIL_STORAGE_OK);
            REQUIRE(record->durability == NINLIL_DURABILITY_FULL);
            commit_count += 1u;
        }
    }
    REQUIRE(put_count == 14u);
    REQUIRE(erase_count == expected_erase_count);
    REQUIRE(commit_count == 1u);
    return 0;
}

static int test_event_mutations_use_one_full_counter_group(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    size_t trace_start;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &resume_request,
        transaction,
        0x42u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    trace_start = ninlil_test_storage_trace_count(env.storage);
    (void)memset(&resume_result, 0, sizeof(resume_result));
    set_header(
        &resume_result.abi_version,
        &resume_result.struct_size,
        sizeof(resume_result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &resume_request,
                &resume_result)
        == NINLIL_OK);
    REQUIRE(resume_result.kind == NINLIL_EVENT_RESUME_RESUMED);
    REQUIRE(trace_has_exact_full_event_group(&env, trace_start, 0u) == 0);

    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_discard_request(
        &discard_request,
        transaction,
        0x62u,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    trace_start = ninlil_test_storage_trace_count(env.storage);
    (void)memset(&discard_result, 0, sizeof(discard_result));
    set_header(
        &discard_result.abi_version,
        &discard_result.struct_size,
        sizeof(discard_result));
    REQUIRE(ninlil_event_discard(
                env.runtime,
                &env.transaction_id,
                &discard_request,
                &discard_result)
        == NINLIL_OK);
    REQUIRE(discard_result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
    REQUIRE(trace_has_exact_full_event_group(&env, trace_start, 1u) == 0);
    env_teardown(&env);
    return 0;
}

static int test_ordered_counter_last_value_and_exhaustion(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_request_t blocked_request;
    ninlil_event_resume_result_t result;
    ninlil_model_runtime_store_counter_t ordered_counter;
    ninlil_rt_v1_event_ledger_record_t ledger_record;
    uint64_t put_calls;
    uint64_t commit_calls;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0x43u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    REQUIRE(stop_runtime(&env) == 0);
    REQUIRE(write_ordered_input_counter(&env, UINT64_MAX - 1u, 0u) == 0);
    ninlil_test_storage_simulate_crash(env.storage);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence
        == UINT64_MAX - 1u);

    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
    REQUIRE(read_event_ledger(
                &env,
                NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
                &request.operation_id,
                &ledger_record)
        == 0);
    REQUIRE(ledger_record.ordered_sequence == UINT64_MAX);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == UINT64_MAX);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason == NINLIL_REASON_COUNTER_EXHAUSTED);
    REQUIRE(read_ordered_input_counter(&env, &ordered_counter) == 0);
    REQUIRE(ordered_counter.value == UINT64_MAX);
    REQUIRE(ordered_counter.exhausted_marker == 1u);

    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &blocked_request,
        transaction,
        0x63u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);
    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime,
                &env.transaction_id,
                &blocked_request,
                &result)
        == NINLIL_E_DEGRADED);
    REQUIRE(resume_result_is_api_zero(&result));
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);

    REQUIRE(env_restart(&env) == 0);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == UINT64_MAX);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls);
    env_teardown(&env);
    return 0;
}

static int run_storage_shape_fault(storage_shape_fault_t fault)
{
    event_env_t env;
    ninlil_storage_ops_t fault_ops;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    uint64_t put_calls;
    uint64_t commit_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        (uint8_t)(0x70u + (uint8_t)fault),
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    put_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_PUT);
    commit_calls = ninlil_test_storage_call_count(
        env.storage, NINLIL_TEST_STORAGE_OP_COMMIT);

    /*
     * Runtime deep-copies storage ops at create into owned storage. Inject
     * shape faults into the live owned vtable; keep an original snapshot so
     * fault wrappers call through without recursion.
     */
    g_shape_original = *env.runtime->platform->storage;
    g_shape_delegate = &g_shape_original;
    g_shape_fault = fault;
    fault_ops = g_shape_original;
    fault_ops.begin = shape_fault_begin;
    fault_ops.iter_open = shape_fault_iter_open;
    fault_ops.iter_next = shape_fault_iter_next;
    {
        ninlil_storage_ops_t *live =
            (ninlil_storage_ops_t *)(void *)env.runtime->platform->storage;
        *live = fault_ops;
    }

    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(resume_result_is_api_zero(&result));
    REQUIRE(env.runtime->commit_unknown_fence == 1u);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls);
    REQUIRE(ninlil_test_storage_live_transactions(env.storage) == 0u);
    REQUIRE(ninlil_test_storage_live_iterators(env.storage) == 0u);

    {
        ninlil_storage_ops_t *live =
            (ninlil_storage_ops_t *)(void *)env.runtime->platform->storage;
        *live = g_shape_original;
    }
    g_shape_delegate = NULL;
    g_shape_fault = STORAGE_SHAPE_NONE;
    env_teardown(&env);
    return 0;
}

static int test_storage_shape_faults_fail_closed(void)
{
    REQUIRE(run_storage_shape_fault(STORAGE_SHAPE_BEGIN_OK_NULL) == 0);
    REQUIRE(run_storage_shape_fault(STORAGE_SHAPE_BEGIN_ERROR_NONNULL) == 0);
    REQUIRE(run_storage_shape_fault(STORAGE_SHAPE_ITER_OK_NULL) == 0);
    REQUIRE(run_storage_shape_fault(STORAGE_SHAPE_ITER_ERROR_NONNULL) == 0);
    REQUIRE(run_storage_shape_fault(STORAGE_SHAPE_ITER_END_REWRITE) == 0);
    return 0;
}

static int run_required_receipt_precedence_case(int use_discard)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t resume_request;
    ninlil_event_resume_result_t resume_result;
    ninlil_event_discard_request_t discard_request;
    ninlil_event_discard_result_t discard_result;
    ninlil_model_runtime_store_counter_t ordered_counter;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    REQUIRE(persist_required_receipt_pending(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->receipt_pending == 1u);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    if (use_discard != 0) {
        fill_discard_request(
            &discard_request,
            transaction,
            0x7au,
            DISCARD_METADATA,
            sizeof(DISCARD_METADATA) - 1u);
    } else {
        fill_resume_request(
            &resume_request,
            transaction,
            0x6au,
            RESUME_METADATA,
            sizeof(RESUME_METADATA) - 1u);
    }
    clock_calls = ninlil_test_clock_call_count(env.clock);
    if (use_discard != 0) {
        (void)memset(&discard_result, 0, sizeof(discard_result));
        set_header(
            &discard_result.abi_version,
            &discard_result.struct_size,
            sizeof(discard_result));
        REQUIRE(ninlil_event_discard(
                    env.runtime,
                    &env.transaction_id,
                    &discard_request,
                    &discard_result)
            == NINLIL_OK);
        REQUIRE(discard_result.kind
            == NINLIL_EVENT_DISCARD_ALREADY_RELEASED);
        REQUIRE(discard_result.reason
            == NINLIL_REASON_REQUIRED_EVIDENCE_MET);
        REQUIRE(discard_result.spool_released == 0u);
        REQUIRE(id_is_zero(&discard_result.audit_clock_epoch_id));
    } else {
        (void)memset(&resume_result, 0, sizeof(resume_result));
        set_header(
            &resume_result.abi_version,
            &resume_result.struct_size,
            sizeof(resume_result));
        REQUIRE(ninlil_event_resume(
                    env.runtime,
                    &env.transaction_id,
                    &resume_request,
                    &resume_result)
            == NINLIL_OK);
        REQUIRE(resume_result.kind
            == NINLIL_EVENT_RESUME_ALREADY_RELEASED);
        REQUIRE(resume_result.reason
            == NINLIL_REASON_REQUIRED_EVIDENCE_MET);
    }
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->receipt_pending == 0u);
    REQUIRE(transaction->evidence_recorded == 1u);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(transaction->reservation_active == 0u);
    REQUIRE(transaction->event_discarded == 0u);
    REQUIRE(transaction->resume_op_count == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 1u);
    REQUIRE(read_ordered_input_counter(&env, &ordered_counter) == 0);
    REQUIRE(ordered_counter.value == 1u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                0x52u)
        == 0u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                0x44u)
        == 0u);
    env_teardown(&env);
    return 0;
}

static int test_catch_up_required_receipt_precedence(void)
{
    REQUIRE(run_required_receipt_precedence_case(0) == 0);
    REQUIRE(run_required_receipt_precedence_case(1) == 0);
    return 0;
}

static int test_catch_up_same_time_event_timeout_precedes_resume(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(persist_due_event_attempt(
                &env, NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE)
        == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_STARTED);
    REQUIRE(transaction->retry_budget == 0u);
    fill_resume_request(
        &request,
        transaction,
        0x6bu,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_STALE_SPOOL_REVISION);
    REQUIRE(result.reason == NINLIL_REASON_STALE_SPOOL_REVISION);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_PARKED);
    REQUIRE(transaction->event_park_cause
        == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT);
    REQUIRE(transaction->spool_revision
        == request.expected_spool_revision + 1u);
    REQUIRE(result.spool_revision == transaction->spool_revision);
    REQUIRE(transaction->resume_op_count == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 0u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                0x52u)
        == 0u);
    env_teardown(&env);
    return 0;
}

static int run_delivery_step_event_timeout_case(uint32_t attempt_count)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_bearer_state_t available_state;
    ninlil_id128_t zero_id;
    uint64_t spool_revision;
    uint64_t send_observed_at_ms;
    uint64_t cycle_ended_at_ms;
    ninlil_id128_t send_observed_clock_epoch_id;
    int parks_cycle =
        attempt_count == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;

    (void)memset(&env, 0, sizeof(env));
    (void)memset(&zero_id, 0, sizeof(zero_id));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(persist_due_event_attempt(&env, attempt_count) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    spool_revision = transaction->spool_revision;
    send_observed_at_ms = transaction->send_observed_at_ms;
    send_observed_clock_epoch_id =
        transaction->send_observed_clock_epoch_id;
    REQUIRE(send_observed_at_ms
        <= UINT64_MAX - transaction->attempt_receipt_timeout_ms);
    cycle_ended_at_ms = send_observed_at_ms
        + transaction->attempt_receipt_timeout_ms;
    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(
                env.runtime, &budget, &step_result)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_prepared == 0u);
    REQUIRE(memcmp(
                &transaction->attempt_id,
                &zero_id,
                sizeof(zero_id))
        == 0);
    REQUIRE(transaction->retry_budget
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - attempt_count);
    REQUIRE(step_result.state_transitions >= 1u);
    if (parks_cycle) {
        REQUIRE(transaction->send_observation_closed == 1u);
        REQUIRE(transaction->send_observed_at_ms
            == send_observed_at_ms);
        REQUIRE(memcmp(
                    &transaction->send_observed_clock_epoch_id,
                    &send_observed_clock_epoch_id,
                    sizeof(send_observed_clock_epoch_id))
            == 0);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_PARKED);
        REQUIRE(transaction->pending_dispatch == 0u);
        REQUIRE(transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT);
        REQUIRE(transaction->spool_revision == spool_revision + 1u);
        REQUIRE(step_result.events_parked == 1u);

        /* Automatic availability resume must preserve the fixed deadline V. */
        (void)memset(&available_state, 0, sizeof(available_state));
        set_header(
            &available_state.abi_version,
            &available_state.struct_size,
            sizeof(available_state));
        REQUIRE(env.runtime->bearer_availability_epoch != UINT64_MAX);
        available_state.availability_epoch =
            env.runtime->bearer_availability_epoch + 1u;
        available_state.available = 1u;
        REQUIRE(ninlil_test_bearer_raw_state_enqueue(
            env.bearer, NINLIL_BEARER_OK, &available_state, 2u));
        budget.max_state_transitions = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_PARKED);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &env.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->retry_summary_count == 1u);
        REQUIRE(memcmp(
                    &transaction->retry_summaries[0]
                        .last_observed_clock_epoch_id,
                    &send_observed_clock_epoch_id,
                    sizeof(send_observed_clock_epoch_id))
            == 0);
        REQUIRE(transaction->retry_summaries[0].last_observed_at_ms
            == cycle_ended_at_ms);
        REQUIRE(transaction->send_observation_closed == 0u);
        REQUIRE(transaction->send_observed_at_ms == 0u);
        REQUIRE(id_is_zero(
            &transaction->send_observed_clock_epoch_id));
    } else {
        REQUIRE(transaction->send_observation_closed == 0u);
        REQUIRE(transaction->send_observed_at_ms == 0u);
        REQUIRE(id_is_zero(
            &transaction->send_observed_clock_epoch_id));
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_QUEUED);
        REQUIRE(transaction->pending_dispatch == 1u);
        REQUIRE(transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_NONE);
        REQUIRE(memcmp(
                    &transaction->next_retry_clock_epoch_id,
                    &env.runtime->last_accepted_trusted_sample
                        .clock_epoch_id,
                    sizeof(transaction->next_retry_clock_epoch_id))
            == 0);
        REQUIRE(transaction->next_retry_ms
            == env.runtime->last_accepted_trusted_sample.now_ms
                + transaction->retry_backoff_ms);
        REQUIRE(env.runtime->last_accepted_trusted_sample.now_ms
            < transaction->next_retry_ms);
        REQUIRE(transaction->spool_revision == spool_revision);
        REQUIRE(step_result.events_parked == 0u);

        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    env.runtime, &budget, &step_result)
            == NINLIL_OK);
        REQUIRE(transaction->attempt_count == attempt_count);
        REQUIRE(transaction->attempt_prepared == 0u);
    }
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 0u);
    env_teardown(&env);
    return 0;
}

static int test_delivery_step_event_attempt_timeout(void)
{
    REQUIRE(run_delivery_step_event_timeout_case(1u) == 0);
    REQUIRE(run_delivery_step_event_timeout_case(
                NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE)
        == 0);
    return 0;
}

static int test_event_receipt_backoff_overflow_fails_before_mutation(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t transaction_before;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(persist_due_event_attempt(&env, 1u) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->retry_backoff_ms > 50u);
    transaction_before = *transaction;
    REQUIRE(ninlil_test_clock_advance(
        env.clock,
        UINT64_MAX - transaction->attempt_receipt_timeout_ms - 50u));

    fill_step_budget(&budget);
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(
                env.runtime, &budget, &step_result)
        == NINLIL_E_DEGRADED);
    REQUIRE(env.runtime->health == NINLIL_HEALTH_DEGRADED);
    REQUIRE(env.runtime->degraded_reason
        == NINLIL_REASON_COUNTER_EXHAUSTED);
    REQUIRE(memcmp(transaction, &transaction_before, sizeof(*transaction)) == 0);
    env_teardown(&env);
    return 0;
}

static int test_catch_up_required_receipt_after_restart(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    REQUIRE(persist_required_receipt_pending(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0x6cu,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    REQUIRE(env_restart(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->receipt_pending == 1u);
    REQUIRE(transaction->ordered_input_sequence == 1u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_ALREADY_RELEASED);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->receipt_pending == 0u);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(transaction->outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(transaction->reservation_active == 0u);
    env_teardown(&env);
    return 0;
}

static int run_catch_up_commit_unknown_case(int committed_truth)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_discard_request_t request;
    ninlil_event_discard_result_t result;
    uint64_t clock_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    REQUIRE(persist_required_receipt_pending(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_discard_request(
        &request,
        transaction,
        0x7bu,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    REQUIRE(ninlil_test_storage_fault_enqueue(
        env.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        committed_truth));
    clock_calls = ninlil_test_clock_call_count(env.clock);
    (void)memset(&result, 0xa5, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(discard_result_is_api_zero(&result));
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_calls + 1u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->receipt_pending == 1u);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->event_discarded == 0u);
    REQUIRE(env.runtime->commit_unknown_fence == 1u);

    REQUIRE(env_restart_after_commit_unknown(&env) == 0);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_ALREADY_RELEASED);
    REQUIRE(result.reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET);
    REQUIRE(result.spool_released == 0u);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->receipt_pending == 0u);
    REQUIRE(transaction->terminal == 1u);
    REQUIRE(transaction->event_discarded == 0u);
    REQUIRE(transaction->reservation_active == 0u);
    REQUIRE(env.runtime->last_assigned_ordered_input_sequence == 1u);
    REQUIRE(ninlil_test_storage_count_keys_with_prefix(
                env.storage,
                (ninlil_bytes_view_t){
                    TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
                0x45u,
                0x44u)
        == 0u);
    env_teardown(&env);
    return 0;
}

static int test_catch_up_commit_unknown_hidden_truths(void)
{
    REQUIRE(run_catch_up_commit_unknown_case(0) == 0);
    REQUIRE(run_catch_up_commit_unknown_case(1) == 0);
    return 0;
}

static int test_retry_cycle_helper_preserves_cumulative_attempts(void)
{
    ninlil_rt_transaction_slot_t current;
    ninlil_rt_transaction_slot_t before;
    ninlil_rt_transaction_slot_t candidate;

    (void)memset(&current, 0, sizeof(current));
    current.family = NINLIL_FAMILY_EVENT_FACT;
    current.retry_cycle_id = 1u;
    current.attempt_in_cycle = 2u;
    current.attempt_count = 2u;
    current.cumulative_attempts = 2u;
    current.retry_budget =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - 2u;
    current.delivery_count = 2u;
    set_id(&current.attempt_ids[0], 0x31u);
    set_id(&current.attempt_ids[1], 0x51u);
    before = current;
    (void)memset(&candidate, 0xa5, sizeof(candidate));
    REQUIRE(ninlil_rt_v1_begin_event_retry_cycle(
                &current, &candidate)
        == NINLIL_OK);
    REQUIRE(memcmp(&current, &before, sizeof(current)) == 0);
    REQUIRE(candidate.retry_cycle_id == 2u);
    REQUIRE(candidate.attempt_in_cycle == 0u);
    REQUIRE(candidate.attempt_count == 0u);
    REQUIRE(candidate.cumulative_attempts == 2u);
    REQUIRE(candidate.delivery_count == 0u);
    REQUIRE(candidate.retry_budget
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    REQUIRE(candidate.retry_summary_count == 1u);
    REQUIRE(candidate.retry_summaries[0].retry_cycle_id == 1u);
    REQUIRE(candidate.retry_summaries[0].attempt_count == 2u);
    REQUIRE(id_is_zero(&candidate.attempt_ids[0]));
    REQUIRE(id_is_zero(&candidate.attempt_ids[1]));

    current.retry_cycle_id = UINT64_MAX;
    REQUIRE(ninlil_rt_v1_begin_event_retry_cycle(
                &current, &candidate)
        == NINLIL_E_INVALID_STATE);
    return 0;
}

typedef enum resume_boot_corruption {
    RESUME_BOOT_MISSING_LEDGER = 1,
    RESUME_BOOT_WRONG_EVENT = 2,
    RESUME_BOOT_ORPHAN_LEDGER = 3
} resume_boot_corruption_t;

static int run_resume_boot_corruption(resume_boot_corruption_t corruption)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t transaction_copy;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    ninlil_id128_t ledger_transaction_id;
    ninlil_id128_t ledger_event_id;
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t value_bytes[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint32_t value_length = 0u;
    ninlil_bytes_view_t value;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0xe0u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_copy = *transaction;
    ledger_transaction_id = env.transaction_id;
    ledger_event_id = transaction->event_id;

    if (corruption == RESUME_BOOT_WRONG_EVENT) {
        set_id(&ledger_event_id, 0x55u);
    } else if (corruption == RESUME_BOOT_ORPHAN_LEDGER) {
        set_id(&ledger_transaction_id, 0x66u);
    }
    ninlil_rt_v1_event_ledger_key(
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        &ledger_transaction_id,
        &request.operation_id,
        key);
    if (corruption != RESUME_BOOT_MISSING_LEDGER) {
        REQUIRE(encode_resume_ledger_record(
                    &transaction_copy,
                    &request,
                    &result,
                    &ledger_transaction_id,
                    &ledger_event_id,
                    value_bytes,
                    &value_length)
            == 0);
        value.data = value_bytes;
        value.length = value_length;
    }
    REQUIRE(stop_runtime(&env) == 0);
    REQUIRE(raw_storage_mutate(
        &env,
        (ninlil_bytes_view_t){key, sizeof(key)},
        corruption == RESUME_BOOT_MISSING_LEDGER ? NULL : &value));
    REQUIRE(restart_is_storage_corrupt(&env) == 0);
    env_teardown(&env);
    return 0;
}

static int test_restart_rejects_resume_cross_record_corruption(void)
{
    REQUIRE(run_resume_boot_corruption(RESUME_BOOT_MISSING_LEDGER) == 0);
    REQUIRE(run_resume_boot_corruption(RESUME_BOOT_WRONG_EVENT) == 0);
    REQUIRE(run_resume_boot_corruption(RESUME_BOOT_ORPHAN_LEDGER) == 0);
    return 0;
}

static int test_restart_rejects_discard_flag_ledger_mismatch(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_event_discard_request_t request;
    ninlil_event_discard_result_t result;
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_discard_request(
        &request,
        transaction,
        0xd8u,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
    ninlil_rt_v1_event_ledger_key(
        NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
        &env.transaction_id,
        &request.operation_id,
        key);
    REQUIRE(stop_runtime(&env) == 0);
    REQUIRE(raw_storage_mutate(
        &env, (ninlil_bytes_view_t){key, sizeof(key)}, NULL));
    REQUIRE(restart_is_storage_corrupt(&env) == 0);
    env_teardown(&env);
    return 0;
}

static int test_restart_rejects_discard_content_mismatch(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t transaction_copy;
    ninlil_event_discard_request_t request;
    ninlil_event_discard_result_t result;
    ninlil_digest256_t wrong_digest;
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t value_bytes[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint32_t value_length = 0u;
    ninlil_bytes_view_t value;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_discard_request(
        &request,
        transaction,
        0xd9u,
        DISCARD_METADATA,
        sizeof(DISCARD_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_discard(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_DISCARD_DISCARDED);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    transaction_copy = *transaction;
    set_digest(&wrong_digest, 0x12u);
    REQUIRE(encode_discard_ledger_record(
                &transaction_copy,
                &request,
                &result,
                &wrong_digest,
                value_bytes,
                &value_length)
        == 0);
    ninlil_rt_v1_event_ledger_key(
        NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX,
        &env.transaction_id,
        &request.operation_id,
        key);
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(stop_runtime(&env) == 0);
    REQUIRE(raw_storage_mutate(
        &env, (ninlil_bytes_view_t){key, sizeof(key)}, &value));
    REQUIRE(restart_is_storage_corrupt(&env) == 0);
    env_teardown(&env);
    return 0;
}

static int test_restart_rejects_same_revision_snapshot_conflict(void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t conflicting;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    uint8_t key[18];
    uint8_t value_bytes[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t value_length = 0u;
    ninlil_bytes_view_t value;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0x49u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    conflicting = *transaction;
    REQUIRE(conflicting.admitted_at_ms != UINT64_MAX);
    conflicting.admitted_at_ms += 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &conflicting,
                value_bytes,
                (uint32_t)sizeof(value_bytes),
                &value_length)
        == NINLIL_OK);
    key[0] = (uint8_t)(RETRY_STATE_PREFIX >> 8);
    key[1] = (uint8_t)RETRY_STATE_PREFIX;
    (void)memcpy(
        &key[2],
        env.transaction_id.bytes,
        sizeof(env.transaction_id.bytes));
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(stop_runtime(&env) == 0);
    REQUIRE(raw_storage_mutate(
        &env, (ninlil_bytes_view_t){key, sizeof(key)}, &value));
    REQUIRE(restart_is_storage_corrupt(&env) == 0);
    env_teardown(&env);
    return 0;
}

static int test_restart_rejects_cross_transaction_ordered_sequence_duplicate(
    void)
{
    event_env_t env;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t first_snapshot;
    ninlil_rt_transaction_slot_t second_snapshot;
    ninlil_event_resume_request_t request;
    ninlil_event_resume_result_t result;
    ninlil_id128_t second_transaction_id;
    uint8_t key[18];
    uint8_t value_bytes[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t value_length;
    ninlil_bytes_view_t value;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_open(&env) == 0);
    REQUIRE(park_event(&env) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    fill_resume_request(
        &request,
        transaction,
        0x59u,
        RESUME_METADATA,
        sizeof(RESUME_METADATA) - 1u);
    (void)memset(&result, 0, sizeof(result));
    set_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_event_resume(
                env.runtime, &env.transaction_id, &request, &result)
        == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_EVENT_RESUME_RESUMED);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &env.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->ordered_input_sequence == 1u);
    first_snapshot = *transaction;
    first_snapshot.ordered_input_sequence = 2u;

    REQUIRE(submit_second_event(&env, &second_transaction_id) == 0);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &second_transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->ordered_input_sequence == 0u);
    second_snapshot = *transaction;
    second_snapshot.ordered_input_sequence = 1u;
    REQUIRE(stop_runtime(&env) == 0);

    value_length = 0u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &first_snapshot,
                value_bytes,
                (uint32_t)sizeof(value_bytes),
                &value_length)
        == NINLIL_OK);
    key[0] = (uint8_t)(EVENT_SPOOL_PREFIX >> 8);
    key[1] = (uint8_t)EVENT_SPOOL_PREFIX;
    (void)memcpy(
        &key[2],
        env.transaction_id.bytes,
        sizeof(env.transaction_id.bytes));
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(raw_storage_mutate(
        &env, (ninlil_bytes_view_t){key, sizeof(key)}, &value));

    value_length = 0u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &second_snapshot,
                value_bytes,
                (uint32_t)sizeof(value_bytes),
                &value_length)
        == NINLIL_OK);
    key[0] = (uint8_t)(TRANSACTION_ADMISSION_PREFIX >> 8);
    key[1] = (uint8_t)TRANSACTION_ADMISSION_PREFIX;
    (void)memcpy(
        &key[2],
        second_transaction_id.bytes,
        sizeof(second_transaction_id.bytes));
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(raw_storage_mutate(
        &env, (ninlil_bytes_view_t){key, sizeof(key)}, &value));
    REQUIRE(write_ordered_input_counter(&env, 2u, 0u) == 0);

    /*
     * Transaction sequences are distinct (2 and 1).  The duplicate is
     * specifically between transaction 2 and transaction 1's Resume ledger.
     */
    REQUIRE(restart_is_storage_corrupt(&env) == 0);
    env_teardown(&env);
    return 0;
}

int main(void)
{
    REQUIRE(test_targeted_clock_failures_add_health_without_mutation() == 0);
    REQUIRE(test_cross_epoch_management_fails_closed_without_mutation() == 0);
    REQUIRE(
        test_cold_restart_event_owner_clock_regression_fails_closed() == 0);
    REQUIRE(test_parked_cycle_deadline_overflow_fails_closed() == 0);
    REQUIRE(test_started_receipt_deadline_boundary() == 0);
    REQUIRE(test_cold_restart_automatic_resume_clock_guard() == 0);
    REQUIRE(
        test_cold_restart_automatic_resume_overflow_fails_closed() == 0);
    REQUIRE(test_resume_ledger_audit_chronology_and_legacy_fence() == 0);
    REQUIRE(test_discard_ledger_audit_chronology() == 0);
    REQUIRE(test_syntax_role_replay_conflict_and_restart() == 0);
    REQUIRE(test_eight_resume_limit_and_old_replay() == 0);
    REQUIRE(test_discard_replay_conflict_and_restart() == 0);
    REQUIRE(test_commit_unknown_hidden_truths() == 0);
    REQUIRE(test_event_mutations_use_one_full_counter_group() == 0);
    REQUIRE(test_ordered_counter_last_value_and_exhaustion() == 0);
    REQUIRE(test_storage_shape_faults_fail_closed() == 0);
    REQUIRE(test_catch_up_required_receipt_precedence() == 0);
    REQUIRE(test_catch_up_same_time_event_timeout_precedes_resume() == 0);
    REQUIRE(test_delivery_step_event_attempt_timeout() == 0);
    REQUIRE(
        test_event_receipt_backoff_overflow_fails_before_mutation() == 0);
    REQUIRE(test_catch_up_required_receipt_after_restart() == 0);
    REQUIRE(test_catch_up_commit_unknown_hidden_truths() == 0);
    REQUIRE(test_retry_cycle_helper_preserves_cumulative_attempts() == 0);
    REQUIRE(test_restart_rejects_resume_cross_record_corruption() == 0);
    REQUIRE(test_restart_rejects_discard_flag_ledger_mismatch() == 0);
    REQUIRE(test_restart_rejects_discard_content_mismatch() == 0);
    REQUIRE(test_restart_rejects_same_revision_snapshot_conflict() == 0);
    REQUIRE(
        test_restart_rejects_cross_transaction_ordered_sequence_duplicate()
        == 0);
    (void)fprintf(stderr, "v1_event_mgmt_ledger_test ok\n");
    return 0;
}
