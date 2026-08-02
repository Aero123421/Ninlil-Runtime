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
    ninlil_event_resume_request_t first_request;
    ninlil_event_resume_result_t result;
    ninlil_event_resume_result_t first_result;
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
    ninlil_id128_t zero_id;
    uint64_t spool_revision;
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
    REQUIRE(transaction->send_observation_closed == 0u);
    REQUIRE(transaction->send_observed_at_ms == 0u);
    REQUIRE(id_is_zero(&transaction->send_observed_clock_epoch_id));
    REQUIRE(transaction->retry_budget
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - attempt_count);
    if (parks_cycle) {
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_PARKED);
        REQUIRE(transaction->pending_dispatch == 0u);
        REQUIRE(transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT);
        REQUIRE(transaction->spool_revision == spool_revision + 1u);
        REQUIRE(step_result.events_parked == 1u);
    } else {
        REQUIRE(transaction->delivery_phase
            == NINLIL_RT_DELIVERY_QUEUED);
        REQUIRE(transaction->pending_dispatch == 1u);
        REQUIRE(transaction->event_park_cause
            == NINLIL_EVENT_PARK_CAUSE_NONE);
        REQUIRE(transaction->spool_revision == spool_revision);
        REQUIRE(step_result.events_parked == 0u);
    }
    REQUIRE(step_result.state_transitions >= 1u);
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
