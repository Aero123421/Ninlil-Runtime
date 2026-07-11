#include "runtime_lifecycle_model.h"

#include <stdint.h>
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

typedef struct platform_fixture {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_storage_ops_t storage;
    ninlil_bearer_ops_t bearer;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
} platform_fixture_t;

static void set_header(uint16_t *version, uint16_t *size, size_t value_size)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value_size;
}

static void *stub_allocate(void *user, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)size;
    (void)alignment;
    return NULL;
}

static void stub_deallocate(
    void *user, void *ptr, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)ptr;
    (void)size;
    (void)alignment;
}

static uint64_t stub_context(void *user)
{
    (void)user;
    return 1u;
}

static ninlil_port_status_t stub_clock(
    void *user, ninlil_time_sample_t *out_sample)
{
    (void)user;
    (void)out_sample;
    return NINLIL_PORT_PERMANENT_FAILURE;
}

static ninlil_port_status_t stub_entropy(
    void *user, uint8_t *out, uint32_t length)
{
    (void)user;
    (void)out;
    (void)length;
    return NINLIL_PORT_PERMANENT_FAILURE;
}

static ninlil_storage_status_t stub_storage_open(
    void *user, ninlil_bytes_view_t storage_namespace, uint32_t schema,
    ninlil_storage_handle_t *out_handle)
{
    (void)user;
    (void)storage_namespace;
    (void)schema;
    (void)out_handle;
    return NINLIL_STORAGE_IO_ERROR;
}

static void stub_storage_close(void *user, ninlil_storage_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_storage_status_t stub_storage_begin(
    void *user, ninlil_storage_handle_t handle, ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    (void)user;
    (void)handle;
    (void)mode;
    (void)out_txn;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_get(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *value)
{
    (void)user;
    (void)txn;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_put(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    (void)user;
    (void)txn;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    (void)user;
    (void)txn;
    (void)key;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_iter_open(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    (void)user;
    (void)txn;
    (void)prefix;
    (void)out_iter;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_iter_next(
    void *user, ninlil_storage_iter_t iter, ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    (void)user;
    (void)iter;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static void stub_storage_iter_close(void *user, ninlil_storage_iter_t iter)
{
    (void)user;
    (void)iter;
}

static ninlil_storage_status_t stub_storage_capacity(
    void *user, ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *capacity)
{
    (void)user;
    (void)handle;
    (void)capacity;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    (void)user;
    (void)txn;
    (void)durability;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t stub_storage_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    (void)txn;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_bearer_status_t stub_bearer_open(
    void *user, const ninlil_id128_t *runtime_id, ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    (void)user;
    (void)runtime_id;
    (void)role;
    (void)out_handle;
    return NINLIL_BEARER_UNAVAILABLE;
}

static void stub_bearer_close(void *user, ninlil_bearer_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_bearer_status_t stub_bearer_send(
    void *user, ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    (void)user;
    (void)handle;
    (void)permit;
    (void)message;
    (void)out_result;
    return NINLIL_BEARER_UNAVAILABLE;
}

static ninlil_bearer_status_t stub_bearer_receive(
    void *user, ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    (void)user;
    (void)handle;
    (void)out_message;
    return NINLIL_BEARER_EMPTY;
}

static void stub_bearer_release(
    void *user, ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    (void)user;
    (void)handle;
    (void)message;
}

static ninlil_bearer_status_t stub_bearer_state(
    void *user, ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    (void)user;
    (void)handle;
    (void)out_state;
    return NINLIL_BEARER_UNAVAILABLE;
}

static ninlil_tx_gate_status_t stub_tx_acquire(
    void *user, const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now, ninlil_tx_permit_t *out_permit)
{
    (void)user;
    (void)request;
    (void)now;
    (void)out_permit;
    return NINLIL_TX_GATE_TEMPORARY;
}

static void stub_tx_release(void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t stub_origin(
    void *user, const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)request;
    (void)decision;
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static platform_fixture_t make_platform(void)
{
    platform_fixture_t value;

    (void)memset(&value, 0, sizeof(value));
    set_header(&value.allocator.abi_version, &value.allocator.struct_size,
        sizeof(value.allocator));
    value.allocator.allocate = stub_allocate;
    value.allocator.deallocate = stub_deallocate;
    set_header(&value.execution.abi_version, &value.execution.struct_size,
        sizeof(value.execution));
    value.execution.current_context_id = stub_context;
    set_header(&value.clock.abi_version, &value.clock.struct_size,
        sizeof(value.clock));
    value.clock.now = stub_clock;
    set_header(&value.entropy.abi_version, &value.entropy.struct_size,
        sizeof(value.entropy));
    value.entropy.fill = stub_entropy;
    set_header(&value.storage.abi_version, &value.storage.struct_size,
        sizeof(value.storage));
    value.storage.open = stub_storage_open;
    value.storage.close = stub_storage_close;
    value.storage.begin = stub_storage_begin;
    value.storage.get = stub_storage_get;
    value.storage.put = stub_storage_put;
    value.storage.erase = stub_storage_erase;
    value.storage.iter_open = stub_storage_iter_open;
    value.storage.iter_next = stub_storage_iter_next;
    value.storage.iter_close = stub_storage_iter_close;
    value.storage.capacity = stub_storage_capacity;
    value.storage.commit = stub_storage_commit;
    value.storage.rollback = stub_storage_rollback;
    set_header(&value.bearer.abi_version, &value.bearer.struct_size,
        sizeof(value.bearer));
    value.bearer.open = stub_bearer_open;
    value.bearer.close = stub_bearer_close;
    value.bearer.send = stub_bearer_send;
    value.bearer.receive_next = stub_bearer_receive;
    value.bearer.release_received = stub_bearer_release;
    value.bearer.state = stub_bearer_state;
    set_header(&value.tx_gate.abi_version, &value.tx_gate.struct_size,
        sizeof(value.tx_gate));
    value.tx_gate.acquire = stub_tx_acquire;
    value.tx_gate.release_unused = stub_tx_release;
    set_header(&value.origin.abi_version, &value.origin.struct_size,
        sizeof(value.origin));
    value.origin.evaluate = stub_origin;
    set_header(&value.platform.abi_version, &value.platform.struct_size,
        sizeof(value.platform));
    return value;
}

static void bind_platform(platform_fixture_t *value)
{
    value->platform.allocator = &value->allocator;
    value->platform.execution = &value->execution;
    value->platform.clock = &value->clock;
    value->platform.entropy = &value->entropy;
    value->platform.storage = &value->storage;
    value->platform.bearer = &value->bearer;
    value->platform.tx_gate = &value->tx_gate;
    value->platform.origin_authorization = &value->origin;
}

static ninlil_runtime_config_t make_config(ninlil_role_t role)
{
    static const uint8_t NAMESPACE[] = {0x00u};
    ninlil_runtime_config_t config;
    ninlil_resource_limits_t *limits;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
    config.environment = NINLIL_ENV_TEST;
    config.runtime_id.bytes[15] = 1u;
    set_header(&config.local_identity.abi_version,
        &config.local_identity.struct_size, sizeof(config.local_identity));
    config.local_identity.device_id.bytes[15] = 1u;
    config.local_identity.site_domain_id.bytes[15] = 1u;
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    config.storage_namespace.data = NAMESPACE;
    config.storage_namespace.length = sizeof(NAMESPACE);
    limits = &config.limits;
    set_header(&limits->abi_version, &limits->struct_size, sizeof(*limits));
    limits->max_services = role == NINLIL_ROLE_CONTROLLER ? 16u : 8u;
    limits->max_nonterminal_transactions =
        role == NINLIL_ROLE_CONTROLLER ? 256u : 32u;
    limits->max_targets_per_transaction = 1u;
    limits->max_logical_payload_bytes = 1024u;
    limits->max_durable_outbox_payload_bytes =
        role == NINLIL_ROLE_CONTROLLER ? 262144u : 0u;
    limits->max_attempts_per_target_per_cycle = 8u;
    limits->max_cancel_attempts_per_transaction = 1u;
    limits->max_evidence_per_target = 8u;
    limits->max_retained_terminal_transactions =
        role == NINLIL_ROLE_CONTROLLER ? 2048u : 64u;
    limits->max_nonterminal_deliveries = 32u;
    limits->max_event_spool_count = role == NINLIL_ROLE_ENDPOINT ? 32u : 0u;
    limits->max_event_spool_bytes =
        role == NINLIL_ROLE_ENDPOINT ? 32768u : 0u;
    limits->max_result_cache_entries = 64u;
    limits->max_retained_dispositions = 64u;
    limits->max_ingress_per_step = 64u;
    limits->max_callbacks_per_step = 64u;
    limits->max_state_transitions_per_step = 64u;
    limits->max_bearer_sends_per_step = 64u;
    limits->max_deferred_tokens = 32u;
    config.terminal_retention_ms = 86400000u;
    config.result_cache_retention_ms = 86400000u;
    config.observation_retention_ms = 3600000u;
    return config;
}

static int test_capacity_derivation(void)
{
    static const uint64_t CONTROLLER_EXPECTED[11] = {
        16u, 2304u, 2304u, 262144u, 32u, 0u, 0u, 128u,
        20736u, 64u, 32u
    };
    static const uint64_t ENDPOINT_EXPECTED[11] = {
        8u, 96u, 96u, 0u, 32u, 32u, 32768u, 128u,
        864u, 64u, 32u
    };
    ninlil_resource_limits_t limits;
    ninlil_model_capacity_limits_t derived;
    ninlil_runtime_config_t endpoint;

    (void)memset(&limits, 0, sizeof(limits));
    limits.max_services = 16u;
    limits.max_nonterminal_transactions = 256u;
    limits.max_targets_per_transaction = 1u;
    limits.max_durable_outbox_payload_bytes = 262144u;
    limits.max_evidence_per_target = 8u;
    limits.max_retained_terminal_transactions = 2048u;
    limits.max_nonterminal_deliveries = 32u;
    limits.max_result_cache_entries = 64u;
    limits.max_retained_dispositions = 64u;
    limits.max_ingress_per_step = 64u;
    limits.max_deferred_tokens = 32u;
    REQUIRE(ninlil_model_runtime_derive_capacity_limits(&limits, &derived)
        == NINLIL_OK);
    REQUIRE(memcmp(derived.values, CONTROLLER_EXPECTED,
        sizeof(CONTROLLER_EXPECTED)) == 0);

    endpoint = make_config(NINLIL_ROLE_ENDPOINT);
    REQUIRE(ninlil_model_runtime_derive_capacity_limits(
        &endpoint.limits, &derived) == NINLIL_OK);
    REQUIRE(memcmp(derived.values, ENDPOINT_EXPECTED,
        sizeof(ENDPOINT_EXPECTED)) == 0);

    limits.max_nonterminal_transactions = UINT32_MAX;
    limits.max_retained_terminal_transactions = UINT32_MAX;
    limits.max_targets_per_transaction = UINT32_MAX;
    (void)memset(&derived, 0xa5, sizeof(derived));
    REQUIRE(ninlil_model_runtime_derive_capacity_limits(&limits, &derived)
        == NINLIL_E_INVALID_ARGUMENT);
    {
        ninlil_model_capacity_limits_t zero;
        (void)memset(&zero, 0, sizeof(zero));
        REQUIRE(memcmp(&derived, &zero, sizeof(derived)) == 0);
    }

    (void)memset(&limits, 0, sizeof(limits));
    limits.max_nonterminal_transactions = UINT32_MAX;
    limits.max_retained_terminal_transactions = UINT32_MAX;
    limits.max_targets_per_transaction = 1u;
    limits.max_evidence_per_target = UINT32_MAX;
    (void)memset(&derived, 0xa5, sizeof(derived));
    REQUIRE(ninlil_model_runtime_derive_capacity_limits(&limits, &derived)
        == NINLIL_E_INVALID_ARGUMENT);
    {
        ninlil_model_capacity_limits_t zero;
        (void)memset(&zero, 0, sizeof(zero));
        REQUIRE(memcmp(&derived, &zero, sizeof(derived)) == 0);
    }
    return 0;
}

static int expect_validation(
    ninlil_status_t status,
    ninlil_model_runtime_validation_failure_field_t field,
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform)
{
    ninlil_model_runtime_validation_result_t result;
    ninlil_model_capacity_limits_t zero_limits;

    (void)memset(&result, 0xa5, sizeof(result));
    (void)memset(&zero_limits, 0, sizeof(zero_limits));
    return ninlil_model_runtime_validate_and_derive(
               config, platform, &result) == status
        && result.status == status
        && result.failure_field == field
        && memcmp(&result.capacity_limits, &zero_limits,
            sizeof(zero_limits)) == 0;
}

static int test_validation_and_precedence(void)
{
    platform_fixture_t fixture = make_platform();
    ninlil_runtime_config_t config = make_config(NINLIL_ROLE_CONTROLLER);
    ninlil_model_runtime_validation_result_t result;

    bind_platform(&fixture);
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);
    REQUIRE(result.status == NINLIL_OK
        && result.failure_field == NINLIL_MODEL_RUNTIME_VALIDATION_NONE);
    REQUIRE(result.capacity_limits.values[
        NINLIL_RESOURCE_SERVICE - 1u] == 16u);
    REQUIRE(result.capacity_limits.values[
        NINLIL_RESOURCE_TRANSACTION - 1u] == 2304u);
    REQUIRE(result.capacity_limits.values[
        NINLIL_RESOURCE_EVIDENCE - 1u] == 20736u);

    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_POINTER,
        NULL, &fixture.platform));
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_POINTER,
        &config, NULL));

    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.abi_version = 0u;
    fixture.platform.abi_version = 0u;
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_HEADER,
        &config, &fixture.platform));

    fixture = make_platform();
    bind_platform(&fixture);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.abi_version = 0u;
    fixture.platform.allocator = NULL;
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));

    fixture = make_platform();
    bind_platform(&fixture);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    fixture.allocator.abi_version = 0u;
    config.storage_namespace.data = NULL;
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_HEADER,
        &config, &fixture.platform));

    fixture = make_platform();
    bind_platform(&fixture);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    fixture.storage.commit = NULL;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_REQUIRED_FUNCTION,
        &config, &fixture.platform));

    fixture = make_platform();
    bind_platform(&fixture);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.reserved_zero = 1u;
    config.role = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RESERVED,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.role = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ROLE,
        &config, &fixture.platform));
    config.role = NINLIL_ROLE_CELL_AGENT_RESERVED;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ROLE,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.environment = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ENVIRONMENT,
        &config, &fixture.platform));
    config.environment = NINLIL_ENV_LAB_RESERVED;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ENVIRONMENT,
        &config, &fixture.platform));
    config.environment = NINLIL_ENV_FIELD_RESERVED;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ENVIRONMENT,
        &config, &fixture.platform));
    config.environment = NINLIL_ENV_PRODUCTION_RESERVED;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ENVIRONMENT,
        &config, &fixture.platform));

    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.limits.max_services = 0u;
    config.limits.max_logical_payload_bytes = 1025u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_LOWER_OR_CONDITIONAL,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.limits.max_nonterminal_deliveries = 33u;
    config.limits.max_deferred_tokens = 34u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.terminal_retention_ms = 0u;
    config.limits.max_services = 17u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.limits.max_nonterminal_transactions = UINT32_MAX;
    config.limits.max_retained_terminal_transactions = UINT32_MAX;
    config.limits.max_targets_per_transaction = UINT32_MAX;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_CAPACITY_DERIVATION_OVERFLOW,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.limits.max_services = 17u;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_PROFILE_UPPER,
        &config, &fixture.platform));

    config = make_config(NINLIL_ROLE_ENDPOINT);
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 1u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_LOWER_OR_CONDITIONAL,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_ENDPOINT);
    config.limits.max_event_spool_count = 1u;
    config.limits.max_event_spool_bytes = 2560u;
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);
    return 0;
}

static void clear_required_function(platform_fixture_t *fixture, uint32_t index)
{
    switch (index) {
    case 0u: fixture->allocator.allocate = NULL; break;
    case 1u: fixture->allocator.deallocate = NULL; break;
    case 2u: fixture->execution.current_context_id = NULL; break;
    case 3u: fixture->clock.now = NULL; break;
    case 4u: fixture->entropy.fill = NULL; break;
    case 5u: fixture->storage.open = NULL; break;
    case 6u: fixture->storage.close = NULL; break;
    case 7u: fixture->storage.begin = NULL; break;
    case 8u: fixture->storage.get = NULL; break;
    case 9u: fixture->storage.put = NULL; break;
    case 10u: fixture->storage.erase = NULL; break;
    case 11u: fixture->storage.iter_open = NULL; break;
    case 12u: fixture->storage.iter_next = NULL; break;
    case 13u: fixture->storage.iter_close = NULL; break;
    case 14u: fixture->storage.capacity = NULL; break;
    case 15u: fixture->storage.commit = NULL; break;
    case 16u: fixture->storage.rollback = NULL; break;
    case 17u: fixture->bearer.open = NULL; break;
    case 18u: fixture->bearer.close = NULL; break;
    case 19u: fixture->bearer.send = NULL; break;
    case 20u: fixture->bearer.receive_next = NULL; break;
    case 21u: fixture->bearer.release_received = NULL; break;
    case 22u: fixture->bearer.state = NULL; break;
    case 23u: fixture->tx_gate.acquire = NULL; break;
    case 24u: fixture->tx_gate.release_unused = NULL; break;
    default: fixture->origin.evaluate = NULL; break;
    }
}

static int test_platform_validation_matrix(void)
{
    ninlil_runtime_config_t config = make_config(NINLIL_ROLE_CONTROLLER);
    platform_fixture_t fixture;
    ninlil_model_runtime_validation_result_t result;
    uint32_t index;

    for (index = 0u; index < 8u; ++index) {
        fixture = make_platform();
        bind_platform(&fixture);
        switch (index) {
        case 0u: fixture.platform.allocator = NULL; break;
        case 1u: fixture.platform.execution = NULL; break;
        case 2u: fixture.platform.clock = NULL; break;
        case 3u: fixture.platform.entropy = NULL; break;
        case 4u: fixture.platform.storage = NULL; break;
        case 5u: fixture.platform.bearer = NULL; break;
        case 6u: fixture.platform.tx_gate = NULL; break;
        default: fixture.platform.origin_authorization = NULL; break;
        }
        REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_POINTER,
            &config, &fixture.platform));
    }

    for (index = 0u; index < 26u; ++index) {
        fixture = make_platform();
        bind_platform(&fixture);
        clear_required_function(&fixture, index);
        REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_REQUIRED_FUNCTION,
            &config, &fixture.platform));
    }

    fixture = make_platform();
    bind_platform(&fixture);
    {
        uint16_t *versions[8] = {
            &fixture.allocator.abi_version,
            &fixture.execution.abi_version,
            &fixture.clock.abi_version,
            &fixture.entropy.abi_version,
            &fixture.storage.abi_version,
            &fixture.bearer.abi_version,
            &fixture.tx_gate.abi_version,
            &fixture.origin.abi_version
        };
        uint16_t *sizes[8] = {
            &fixture.allocator.struct_size,
            &fixture.execution.struct_size,
            &fixture.clock.struct_size,
            &fixture.entropy.struct_size,
            &fixture.storage.struct_size,
            &fixture.bearer.struct_size,
            &fixture.tx_gate.struct_size,
            &fixture.origin.struct_size
        };
        uint16_t original_sizes[8];
        for (index = 0u; index < 8u; ++index) {
            original_sizes[index] = *sizes[index];
            *versions[index] = 0u;
            REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
                NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_HEADER,
                &config, &fixture.platform));
            *versions[index] = NINLIL_ABI_VERSION;
            *sizes[index] = (uint16_t)(original_sizes[index] - 1u);
            REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
                NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_HEADER,
                &config, &fixture.platform));
            *sizes[index] = (uint16_t)(original_sizes[index] + 1u);
            REQUIRE(ninlil_model_runtime_validate_and_derive(
                &config, &fixture.platform, &result) == NINLIL_OK);
            *sizes[index] = original_sizes[index];
        }
    }

    fixture = make_platform();
    bind_platform(&fixture);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.struct_size = (uint16_t)(sizeof(config) + 1u);
    fixture.platform.struct_size =
        (uint16_t)(sizeof(fixture.platform) + 1u);
    config.local_identity.struct_size =
        (uint16_t)(sizeof(config.local_identity) + 1u);
    config.limits.struct_size = (uint16_t)(sizeof(config.limits) + 1u);
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);

    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.struct_size = (uint16_t)(sizeof(config) - 1u);
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    fixture.platform.struct_size = (uint16_t)(sizeof(fixture.platform) - 1u);
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_HEADER,
        &config, &fixture.platform));

    fixture = make_platform();
    bind_platform(&fixture);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.abi_version = 0u;
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.struct_size =
        (uint16_t)(sizeof(config.local_identity) - 1u);
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.limits.abi_version = 0u;
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.limits.struct_size = (uint16_t)(sizeof(config.limits) - 1u);
    REQUIRE(expect_validation(NINLIL_E_ABI_MISMATCH,
        NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER,
        &config, &fixture.platform));
    return 0;
}

static int test_namespace_reserved_and_identity(void)
{
    uint8_t binary_namespace[255];
    platform_fixture_t fixture = make_platform();
    ninlil_runtime_config_t config = make_config(NINLIL_ROLE_CONTROLLER);
    ninlil_model_runtime_validation_result_t result;
    uint32_t index;

    bind_platform(&fixture);
    for (index = 0u; index < sizeof(binary_namespace); ++index) {
        binary_namespace[index] = (uint8_t)index;
    }
    config.storage_namespace.data = binary_namespace;
    config.storage_namespace.length = 255u;
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);
    config.storage_namespace.length = 1u;
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);
    config.storage_namespace.length = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_NAMESPACE,
        &config, &fixture.platform));
    config.storage_namespace.length = 256u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_NAMESPACE,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.storage_namespace.data = NULL;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_NAMESPACE,
        &config, &fixture.platform));

    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.storage_namespace.data = NULL;
    config.reserved_zero = 1u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RESERVED,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.storage_namespace.data = NULL;
    config.role = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ROLE,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.storage_namespace.data = NULL;
    config.role = NINLIL_ROLE_CELL_AGENT_RESERVED;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ROLE,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.storage_namespace.data = NULL;
    config.environment = NINLIL_ENV_LAB_RESERVED;
    REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
        NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ENVIRONMENT,
        &config, &fixture.platform));

    for (index = 0u; index < 3u; ++index) {
        config = make_config(NINLIL_ROLE_CONTROLLER);
        if (index == 0u) {
            config.reserved_zero = 1u;
        } else if (index == 1u) {
            config.limits.reserved_zero = 1u;
        } else {
            config.local_identity.reserved_zero = 1u;
        }
        REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_RESERVED,
            &config, &fixture.platform));
    }
    config = make_config(NINLIL_ROLE_CONTROLLER);
    (void)memset(&config.runtime_id, 0, sizeof(config.runtime_id));
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RUNTIME_ID,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.binding_epoch = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.membership_epoch = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.flags |= 8u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RESERVED,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.flags &= ~NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    (void)memset(&config.local_identity.device_id, 0,
        sizeof(config.local_identity.device_id));
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.flags &= ~NINLIL_LOCAL_IDENTITY_HAS_SITE;
    (void)memset(&config.local_identity.site_domain_id, 0,
        sizeof(config.local_identity.site_domain_id));
    config.local_identity.membership_epoch = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY,
        &config, &fixture.platform));
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.flags |= NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    config.local_identity.installation_id.bytes[15] = 1u;
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);
    config = make_config(NINLIL_ROLE_CONTROLLER);
    config.local_identity.installation_id.bytes[15] = 1u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY,
        &config, &fixture.platform));
    return 0;
}

static void set_limit_field(
    ninlil_resource_limits_t *limits, uint32_t field, uint64_t value)
{
    switch (field) {
    case 0u: limits->max_services = (uint32_t)value; break;
    case 1u: limits->max_nonterminal_transactions = (uint32_t)value; break;
    case 2u: limits->max_targets_per_transaction = (uint32_t)value; break;
    case 3u: limits->max_logical_payload_bytes = (uint32_t)value; break;
    case 4u: limits->max_durable_outbox_payload_bytes = value; break;
    case 5u: limits->max_attempts_per_target_per_cycle = (uint32_t)value; break;
    case 6u: limits->max_cancel_attempts_per_transaction = (uint32_t)value; break;
    case 7u: limits->max_evidence_per_target = (uint32_t)value; break;
    case 8u:
        limits->max_retained_terminal_transactions = (uint32_t)value;
        break;
    case 9u: limits->max_nonterminal_deliveries = (uint32_t)value; break;
    case 10u: limits->max_event_spool_count = (uint32_t)value; break;
    case 11u: limits->max_event_spool_bytes = value; break;
    case 12u: limits->max_result_cache_entries = (uint32_t)value; break;
    case 13u: limits->max_retained_dispositions = (uint32_t)value; break;
    case 14u: limits->max_ingress_per_step = (uint32_t)value; break;
    case 15u: limits->max_callbacks_per_step = (uint32_t)value; break;
    case 16u: limits->max_state_transitions_per_step = (uint32_t)value; break;
    case 17u: limits->max_bearer_sends_per_step = (uint32_t)value; break;
    default: limits->max_deferred_tokens = (uint32_t)value; break;
    }
}

static ninlil_runtime_config_t make_min_config(ninlil_role_t role)
{
    static const uint64_t CONTROLLER_MIN[19] = {
        1u, 1u, 1u, 1u, 1u, 8u, 1u, 1u, 1u, 1u,
        0u, 0u, 1u, 1u, 1u, 1u, 2u, 1u, 1u
    };
    static const uint64_t ENDPOINT_MIN[19] = {
        1u, 1u, 1u, 1u, 0u, 8u, 1u, 1u, 1u, 1u,
        0u, 0u, 1u, 1u, 1u, 1u, 2u, 1u, 1u
    };
    const uint64_t *values = role == NINLIL_ROLE_CONTROLLER
        ? CONTROLLER_MIN : ENDPOINT_MIN;
    ninlil_runtime_config_t config = make_config(role);
    uint32_t field;

    for (field = 0u; field < 19u; ++field) {
        set_limit_field(&config.limits, field, values[field]);
    }
    config.terminal_retention_ms = 1u;
    config.result_cache_retention_ms = 1u;
    config.observation_retention_ms = 0u;
    return config;
}

static void preserve_cross_fields(
    ninlil_runtime_config_t *config, uint32_t field)
{
    ninlil_resource_limits_t *limits = &config->limits;

    if (config->role == NINLIL_ROLE_CONTROLLER && field == 3u
        && limits->max_durable_outbox_payload_bytes
            < limits->max_logical_payload_bytes) {
        limits->max_durable_outbox_payload_bytes =
            limits->max_logical_payload_bytes;
    }
    if (field == 9u
        && limits->max_nonterminal_transactions
            < limits->max_nonterminal_deliveries) {
        limits->max_nonterminal_transactions =
            limits->max_nonterminal_deliveries;
    }
    if (field == 10u) {
        if (limits->max_nonterminal_transactions
            < limits->max_event_spool_count) {
            limits->max_nonterminal_transactions =
                limits->max_event_spool_count;
        }
        if (config->role == NINLIL_ROLE_ENDPOINT
            && limits->max_event_spool_count > 0u) {
            limits->max_event_spool_bytes = 2560u;
        }
    }
    if (field == 11u && config->role == NINLIL_ROLE_ENDPOINT
        && limits->max_event_spool_bytes > 0u) {
        limits->max_event_spool_count = 1u;
    }
    if (field == 18u) {
        if (limits->max_nonterminal_deliveries
            < limits->max_deferred_tokens) {
            limits->max_nonterminal_deliveries = limits->max_deferred_tokens;
        }
        if (limits->max_nonterminal_transactions
            < limits->max_nonterminal_deliveries) {
            limits->max_nonterminal_transactions =
                limits->max_nonterminal_deliveries;
        }
    }
}

static int test_rl1_to_rl7_matrix(void)
{
    static const uint64_t CONTROLLER_MIN[19] = {
        1u, 1u, 1u, 1u, 1u, 8u, 1u, 1u, 1u, 1u,
        0u, 0u, 1u, 1u, 1u, 1u, 2u, 1u, 1u
    };
    static const uint64_t CONTROLLER_MAX[19] = {
        16u, 256u, 1u, 1024u, 262144u, 8u, 1u, 8u, 2048u, 32u,
        0u, 0u, 64u, 64u, 64u, 64u, 64u, 64u, 32u
    };
    static const uint64_t ENDPOINT_MIN[19] = {
        1u, 1u, 1u, 1u, 0u, 8u, 1u, 1u, 1u, 1u,
        0u, 0u, 1u, 1u, 1u, 1u, 2u, 1u, 1u
    };
    static const uint64_t ENDPOINT_MAX[19] = {
        8u, 32u, 1u, 1024u, 0u, 8u, 1u, 8u, 64u, 32u,
        32u, 32768u, 64u, 64u, 64u, 64u, 64u, 64u, 32u
    };
    platform_fixture_t fixture = make_platform();
    ninlil_model_runtime_validation_result_t result;
    uint32_t role_index;
    uint32_t field;

    bind_platform(&fixture);
    for (role_index = 0u; role_index < 2u; ++role_index) {
        ninlil_role_t role = role_index == 0u
            ? NINLIL_ROLE_CONTROLLER : NINLIL_ROLE_ENDPOINT;
        const uint64_t *minimum = role_index == 0u
            ? CONTROLLER_MIN : ENDPOINT_MIN;
        const uint64_t *maximum = role_index == 0u
            ? CONTROLLER_MAX : ENDPOINT_MAX;
        for (field = 0u; field < 19u; ++field) {
            ninlil_runtime_config_t config = make_min_config(role);
            set_limit_field(&config.limits, field, minimum[field]);
            preserve_cross_fields(&config, field);
            REQUIRE(ninlil_model_runtime_validate_and_derive(
                &config, &fixture.platform, &result) == NINLIL_OK);

            config = make_min_config(role);
            set_limit_field(&config.limits, field, maximum[field]);
            preserve_cross_fields(&config, field);
            REQUIRE(ninlil_model_runtime_validate_and_derive(
                &config, &fixture.platform, &result) == NINLIL_OK);

            if (minimum[field] > 0u) {
                config = make_min_config(role);
                set_limit_field(&config.limits, field, minimum[field] - 1u);
                preserve_cross_fields(&config, field);
                REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
                    NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_LOWER_OR_CONDITIONAL,
                    &config, &fixture.platform));
            }

            config = make_min_config(role);
            set_limit_field(&config.limits, field, maximum[field] + 1u);
            preserve_cross_fields(&config, field);
            REQUIRE(expect_validation(NINLIL_E_UNSUPPORTED,
                NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_PROFILE_UPPER,
                &config, &fixture.platform));
        }
    }

    {
        ninlil_runtime_config_t config = make_min_config(NINLIL_ROLE_ENDPOINT);
        config.limits.max_event_spool_count = 1u;
        config.limits.max_event_spool_bytes = 2559u;
        REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
            NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_LOWER_OR_CONDITIONAL,
            &config, &fixture.platform));
    }
    return 0;
}

static int test_cross_and_retention_matrix(void)
{
    platform_fixture_t fixture = make_platform();
    ninlil_runtime_config_t config;
    ninlil_model_runtime_validation_result_t result;

    bind_platform(&fixture);
    config = make_min_config(NINLIL_ROLE_ENDPOINT);
    config.limits.max_deferred_tokens = 2u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD,
        &config, &fixture.platform));
    config = make_min_config(NINLIL_ROLE_ENDPOINT);
    config.limits.max_nonterminal_deliveries = 2u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD,
        &config, &fixture.platform));
    config = make_min_config(NINLIL_ROLE_ENDPOINT);
    config.limits.max_event_spool_count = 2u;
    config.limits.max_event_spool_bytes = 2560u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD,
        &config, &fixture.platform));
    config = make_min_config(NINLIL_ROLE_CONTROLLER);
    config.limits.max_logical_payload_bytes = 2u;
    config.limits.max_durable_outbox_payload_bytes = 1u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD,
        &config, &fixture.platform));

    config = make_min_config(NINLIL_ROLE_CONTROLLER);
    config.terminal_retention_ms = NINLIL_M1A_MAX_RETENTION_MS;
    config.result_cache_retention_ms = NINLIL_M1A_MAX_RETENTION_MS;
    config.observation_retention_ms = NINLIL_M1A_MAX_RETENTION_MS;
    REQUIRE(ninlil_model_runtime_validate_and_derive(
        &config, &fixture.platform, &result) == NINLIL_OK);
    config.terminal_retention_ms = NINLIL_M1A_MAX_RETENTION_MS + 1u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION,
        &config, &fixture.platform));
    config = make_min_config(NINLIL_ROLE_CONTROLLER);
    config.result_cache_retention_ms = 2u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION,
        &config, &fixture.platform));
    config = make_min_config(NINLIL_ROLE_CONTROLLER);
    config.result_cache_retention_ms = 0u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION,
        &config, &fixture.platform));
    config = make_min_config(NINLIL_ROLE_CONTROLLER);
    config.observation_retention_ms = NINLIL_M1A_MAX_RETENTION_MS + 1u;
    REQUIRE(expect_validation(NINLIL_E_INVALID_ARGUMENT,
        NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION,
        &config, &fixture.platform));
    return 0;
}

static int gate_is(
    const ninlil_model_runtime_create_gate_t *gate,
    ninlil_status_t status,
    uint32_t continue_create,
    uint32_t close_handle)
{
    return gate->api_status == status
        && gate->continue_create == continue_create
        && gate->close_returned_handle == close_handle;
}

static int test_storage_and_bearer_mapping(void)
{
    static const struct {
        ninlil_storage_status_t port;
        ninlil_status_t api;
        uint32_t proceed;
    } STORAGE_CASES[] = {
        {NINLIL_STORAGE_OK, NINLIL_OK, 1u},
        {NINLIL_STORAGE_BUSY, NINLIL_E_WOULD_BLOCK, 0u},
        {NINLIL_STORAGE_NO_SPACE, NINLIL_E_CAPACITY_EXHAUSTED, 0u},
        {NINLIL_STORAGE_IO_ERROR, NINLIL_E_STORAGE, 0u},
        {NINLIL_STORAGE_CORRUPT, NINLIL_E_STORAGE_CORRUPT, 0u},
        {NINLIL_STORAGE_NOT_FOUND, NINLIL_E_STORAGE_CORRUPT, 0u},
        {NINLIL_STORAGE_BUFFER_TOO_SMALL, NINLIL_E_STORAGE_CORRUPT, 0u},
        {NINLIL_STORAGE_UNSUPPORTED_SCHEMA, NINLIL_E_UNSUPPORTED, 0u},
        {NINLIL_STORAGE_COMMIT_UNKNOWN,
            NINLIL_E_STORAGE_COMMIT_UNKNOWN, 0u}
    };
    static const struct {
        ninlil_bearer_status_t port;
        ninlil_status_t api;
        uint32_t proceed;
    } BEARER_CASES[] = {
        {NINLIL_BEARER_OK, NINLIL_OK, 1u},
        {NINLIL_BEARER_WOULD_BLOCK, NINLIL_E_WOULD_BLOCK, 0u},
        {NINLIL_BEARER_UNAVAILABLE, NINLIL_E_WOULD_BLOCK, 0u},
        {NINLIL_BEARER_DENIED, NINLIL_E_UNSUPPORTED, 0u},
        {NINLIL_BEARER_EMPTY, NINLIL_E_DEGRADED, 0u},
        {NINLIL_BEARER_LOST_UNKNOWN, NINLIL_E_DEGRADED, 0u},
        {NINLIL_BEARER_CORRUPT, NINLIL_E_DEGRADED, 0u}
    };
    ninlil_model_runtime_create_gate_t gate;
    size_t index;

    for (index = 0u;
         index < sizeof(STORAGE_CASES) / sizeof(STORAGE_CASES[0]);
         ++index) {
        uint32_t present = STORAGE_CASES[index].port == NINLIL_STORAGE_OK;
        REQUIRE(ninlil_model_runtime_map_storage_open(
            STORAGE_CASES[index].port, present, &gate) == NINLIL_OK);
        REQUIRE(gate_is(&gate, STORAGE_CASES[index].api,
            STORAGE_CASES[index].proceed, 0u));
        if (STORAGE_CASES[index].port != NINLIL_STORAGE_OK) {
            REQUIRE(ninlil_model_runtime_map_storage_open(
                STORAGE_CASES[index].port, 1u, &gate) == NINLIL_OK);
            REQUIRE(gate_is(&gate, NINLIL_E_STORAGE_CORRUPT, 0u, 1u));
        }
    }
    REQUIRE(ninlil_model_runtime_map_storage_open(99u, 0u, &gate)
        == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_STORAGE_CORRUPT, 0u, 0u));
    REQUIRE(ninlil_model_runtime_map_storage_open(99u, 1u, &gate)
        == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_STORAGE_CORRUPT, 0u, 1u));
    REQUIRE(ninlil_model_runtime_map_storage_open(
        NINLIL_STORAGE_OK, 0u, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_STORAGE_CORRUPT, 0u, 0u));
    REQUIRE(ninlil_model_runtime_map_storage_open(
        NINLIL_STORAGE_BUSY, 1u, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_STORAGE_CORRUPT, 0u, 1u));
    (void)memset(&gate, 0xa5, sizeof(gate));
    REQUIRE(ninlil_model_runtime_map_storage_open(
        NINLIL_STORAGE_OK, 2u, &gate) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(gate.api_status == 0 && gate.continue_create == 0u
        && gate.close_returned_handle == 0u);

    for (index = 0u;
         index < sizeof(BEARER_CASES) / sizeof(BEARER_CASES[0]);
         ++index) {
        uint32_t present = BEARER_CASES[index].port == NINLIL_BEARER_OK;
        REQUIRE(ninlil_model_runtime_map_bearer_open(
            BEARER_CASES[index].port, present, &gate) == NINLIL_OK);
        REQUIRE(gate_is(&gate, BEARER_CASES[index].api,
            BEARER_CASES[index].proceed, 0u));
        if (BEARER_CASES[index].port != NINLIL_BEARER_OK) {
            REQUIRE(ninlil_model_runtime_map_bearer_open(
                BEARER_CASES[index].port, 1u, &gate) == NINLIL_OK);
            REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 1u));
        }
    }
    REQUIRE(ninlil_model_runtime_map_bearer_open(99u, 0u, &gate)
        == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    REQUIRE(ninlil_model_runtime_map_bearer_open(99u, 1u, &gate)
        == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 1u));
    REQUIRE(ninlil_model_runtime_map_bearer_open(
        NINLIL_BEARER_OK, 0u, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    REQUIRE(ninlil_model_runtime_map_bearer_open(
        NINLIL_BEARER_DENIED, 1u, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 1u));
    (void)memset(&gate, 0xa5, sizeof(gate));
    REQUIRE(ninlil_model_runtime_map_bearer_open(
        NINLIL_BEARER_OK, 2u, &gate) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(gate.api_status == 0 && gate.continue_create == 0u
        && gate.close_returned_handle == 0u);
    return 0;
}

static ninlil_model_runtime_clock_input_t make_clock_input(uint64_t now_ms)
{
    ninlil_model_runtime_clock_input_t input;

    (void)memset(&input, 0, sizeof(input));
    input.port_status = NINLIL_PORT_OK;
    set_header(&input.sample.abi_version, &input.sample.struct_size,
        sizeof(input.sample));
    input.sample.clock_epoch_id.bytes[15] = 1u;
    input.sample.now_ms = now_ms;
    input.sample.trust = NINLIL_CLOCK_TRUSTED;
    return input;
}

static int test_clock_classification(void)
{
    ninlil_model_runtime_clock_input_t input = make_clock_input(0u);
    ninlil_model_runtime_create_gate_t gate;

    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_OK, 1u, 0u));
    input.sample.trust = NINLIL_CLOCK_UNCERTAIN;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_CLOCK_UNCERTAIN, 0u, 0u));

    input = make_clock_input(0u);
    (void)memset(&input.sample.clock_epoch_id, 0,
        sizeof(input.sample.clock_epoch_id));
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input = make_clock_input(0u);
    input.sample.trust = 99u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input = make_clock_input(0u);
    input.sample.abi_version = 0u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input = make_clock_input(0u);
    input.sample.struct_size = (uint16_t)(sizeof(input.sample) - 1u);
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input = make_clock_input(0u);
    input.sample.struct_size = (uint16_t)(sizeof(input.sample) + 1u);
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_OK, 1u, 0u));
    input = make_clock_input(0u);
    input.sample.reserved_zero = 1u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));

    (void)memset(&input, 0, sizeof(input));
    input.port_status = NINLIL_PORT_TEMPORARY_FAILURE;
    set_header(&input.sample.abi_version, &input.sample.struct_size,
        sizeof(input.sample));
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_CLOCK_UNCERTAIN, 0u, 0u));
    input.sample.struct_size = (uint16_t)(sizeof(input.sample) + 1u);
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input.port_status = NINLIL_PORT_PERMANENT_FAILURE;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input.port_status = 99u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));

    input = make_clock_input(99u);
    input.has_external_baseline = 1u;
    input.external_baseline_clock_epoch_id = input.sample.clock_epoch_id;
    input.external_baseline_now_ms = 100u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_E_DEGRADED, 0u, 0u));
    input.sample.now_ms = 100u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_OK, 1u, 0u));
    input.sample.now_ms = 1u;
    input.sample.clock_epoch_id.bytes[15] = 2u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_OK);
    REQUIRE(gate_is(&gate, NINLIL_OK, 1u, 0u));

    input = make_clock_input(0u);
    input.has_external_baseline = 2u;
    (void)memset(&gate, 0xa5, sizeof(gate));
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(gate.api_status == 0 && gate.continue_create == 0u);
    input = make_clock_input(0u);
    input.external_baseline_now_ms = 1u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_E_INVALID_ARGUMENT);
    input = make_clock_input(0u);
    input.has_external_baseline = 1u;
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &input, &gate) == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_entropy_mapping(void)
{
    ninlil_model_runtime_entropy_observation_t observations[4];
    ninlil_model_runtime_entropy_result_t result;
    uint32_t selected;

    (void)memset(observations, 0, sizeof(observations));
    observations[0].port_status = NINLIL_PORT_TEMPORARY_FAILURE;
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        observations, 1u, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_OK
        && result.action == NINLIL_MODEL_RUNTIME_ENTROPY_MORE_REQUIRED
        && result.calls_consumed == 1u);
    observations[0].port_status = NINLIL_PORT_OK;
    observations[0].candidate.bytes[15] = 1u;
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        observations, 1u, &result) == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED
        && result.calls_consumed == 1u
        && result.metrics_epoch_id.bytes[15] == 1u);
    observations[0].candidate.bytes[15] = 0u;
    observations[0].port_status = NINLIL_PORT_TEMPORARY_FAILURE;

    observations[1].port_status = NINLIL_PORT_OK;
    observations[2].port_status = NINLIL_PORT_PERMANENT_FAILURE;
    observations[2].candidate.bytes[0] = 0x55u;
    observations[3].port_status = NINLIL_PORT_OK;
    observations[3].candidate.bytes[15] = 4u;
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        observations, 4u, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_OK
        && result.action == NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED
        && result.calls_consumed == 4u
        && result.metrics_epoch_id.bytes[15] == 4u);

    observations[3].candidate.bytes[15] = 0u;
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        observations, 4u, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_ENTROPY
        && result.action == NINLIL_MODEL_RUNTIME_ENTROPY_EXHAUSTED
        && result.calls_consumed == 4u);
    (void)memset(&result, 0xa5, sizeof(result));
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        observations, 0u, &result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result.api_status == 0 && result.action == 0
        && result.calls_consumed == 0u);

    for (selected = 0u; selected < 4u; ++selected) {
        uint32_t index;
        (void)memset(observations, 0, sizeof(observations));
        for (index = 0u; index < 4u; ++index) {
            observations[index].port_status =
                index == selected ? NINLIL_PORT_OK
                                  : NINLIL_PORT_TEMPORARY_FAILURE;
        }
        observations[selected].candidate.bytes[15] =
            (uint8_t)(selected + 1u);
        REQUIRE(ninlil_model_runtime_map_metrics_entropy(
            observations, 4u, &result) == NINLIL_OK);
        REQUIRE(result.action == NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED
            && result.calls_consumed == selected + 1u
            && result.metrics_epoch_id.bytes[15] == selected + 1u);
    }
    (void)memset(observations, 0, sizeof(observations));
    observations[0].port_status = 99u;
    observations[0].candidate.bytes[15] = 7u;
    observations[1].port_status = NINLIL_PORT_OK;
    observations[1].candidate.bytes[15] = 7u;
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        observations, 2u, &result) == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED
        && result.calls_consumed == 2u
        && result.metrics_epoch_id.bytes[15] == 7u);
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        &observations[1], 1u, &result) == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED
        && result.metrics_epoch_id.bytes[15] == 7u);
    return 0;
}

static int test_health_projection(void)
{
    static const ninlil_reason_t REASONS[8] = {
        NINLIL_REASON_STORAGE_IO,
        NINLIL_REASON_STORAGE_COMMIT_UNKNOWN,
        NINLIL_REASON_CALLBACK_CONTRACT,
        NINLIL_REASON_APPLICATION_FAILED,
        NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE,
        NINLIL_REASON_CLOCK_UNCERTAIN,
        NINLIL_REASON_COUNTER_EXHAUSTED,
        NINLIL_REASON_OUTCOME_UNKNOWN
    };
    uint64_t counts[8];
    ninlil_model_runtime_health_projection_t projection;
    ninlil_model_runtime_stage9_health_input_t stage9;
    size_t index;
    size_t other;

    (void)memset(counts, 0, sizeof(counts));
    REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
        == NINLIL_OK);
    REQUIRE(projection.health == NINLIL_HEALTH_OK
        && projection.degraded_reason == NINLIL_REASON_NONE);
    for (index = 0u; index < 8u; ++index) {
        (void)memset(counts, 0, sizeof(counts));
        counts[index] = UINT64_MAX;
        REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
            == NINLIL_OK);
        REQUIRE(projection.health == NINLIL_HEALTH_DEGRADED
            && projection.degraded_reason == REASONS[index]);
    }
    counts[7] = 1u;
    counts[4] = 1u;
    counts[1] = 1u;
    REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
        == NINLIL_OK);
    REQUIRE(projection.degraded_reason == NINLIL_REASON_STORAGE_COMMIT_UNKNOWN);

    /* All priority pairs and fallthrough after clearing the higher cause. */
    for (index = 0u; index < 8u; ++index) {
        for (other = index + 1u; other < 8u; ++other) {
            (void)memset(counts, 0, sizeof(counts));
            counts[index] = 1u;
            counts[other] = 2u;
            REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
                == NINLIL_OK);
            REQUIRE(projection.degraded_reason == REASONS[index]);
            counts[index] = 0u;
            REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
                == NINLIL_OK);
            REQUIRE(projection.degraded_reason == REASONS[other]);
        }
    }
    (void)memset(counts, 0, sizeof(counts));
    counts[3] = 2u;
    REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
        == NINLIL_OK);
    counts[3] = 1u;
    REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
        == NINLIL_OK);
    REQUIRE(projection.degraded_reason == NINLIL_REASON_APPLICATION_FAILED);
    counts[3] = 0u;
    REQUIRE(ninlil_model_runtime_project_health(counts, &projection)
        == NINLIL_OK);
    REQUIRE(projection.health == NINLIL_HEALTH_OK);

    (void)memset(&stage9, 0, sizeof(stage9));
    (void)memset(&projection, 0xa5, sizeof(projection));
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, &projection)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(projection.health == 0u && projection.degraded_reason == 0u);
    stage9.storage_recovery_complete = 1u;
    stage9.durable_active_reference_count[0] = 1u;
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, &projection)
        == NINLIL_E_INVALID_STATE);
    stage9.durable_active_reference_count[0] = 0u;
    stage9.durable_active_reference_count[1] = 1u;
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, &projection)
        == NINLIL_E_INVALID_STATE);
    stage9.durable_active_reference_count[1] = 0u;
    stage9.durable_active_reference_count[2] = 1u;
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, &projection)
        == NINLIL_OK);
    REQUIRE(projection.health == NINLIL_HEALTH_DEGRADED
        && projection.degraded_reason == NINLIL_REASON_CALLBACK_CONTRACT);
    stage9.durable_active_reference_count[2] = 0u;
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, &projection)
        == NINLIL_OK);
    REQUIRE(projection.health == NINLIL_HEALTH_OK
        && projection.degraded_reason == NINLIL_REASON_NONE);
    stage9.storage_recovery_complete = 2u;
    (void)memset(&projection, 0xa5, sizeof(projection));
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, &projection)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(projection.health == 0u && projection.degraded_reason == 0u);
    return 0;
}

static int test_null_and_zero_outputs(void)
{
    ninlil_resource_limits_t limits;
    ninlil_model_capacity_limits_t capacity;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_model_runtime_create_gate_t gate;
    ninlil_model_runtime_clock_input_t clock = make_clock_input(0u);
    ninlil_model_runtime_health_projection_t health;
    ninlil_model_runtime_stage9_health_input_t stage9;
    ninlil_model_runtime_entropy_observation_t observation;
    ninlil_model_runtime_entropy_result_t entropy;
    uint64_t counts[8];

    (void)memset(&limits, 0, sizeof(limits));
    (void)memset(&capacity, 0xa5, sizeof(capacity));
    REQUIRE(ninlil_model_runtime_derive_capacity_limits(NULL, &capacity)
        == NINLIL_E_INVALID_ARGUMENT);
    {
        ninlil_model_capacity_limits_t zero;
        (void)memset(&zero, 0, sizeof(zero));
        REQUIRE(memcmp(&capacity, &zero, sizeof(zero)) == 0);
    }
    REQUIRE(ninlil_model_runtime_derive_capacity_limits(&limits, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_validate_and_derive(NULL, NULL, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)validation;
    REQUIRE(ninlil_model_runtime_map_storage_open(
        NINLIL_STORAGE_OK, 1u, NULL) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_map_bearer_open(
        NINLIL_BEARER_OK, 1u, NULL) == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&gate, 0xa5, sizeof(gate));
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        NULL, &gate) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(gate.api_status == 0 && gate.continue_create == 0u
        && gate.close_returned_handle == 0u);
    REQUIRE(ninlil_model_runtime_classify_clock_with_external_baseline(
        &clock, NULL) == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&health, 0xa5, sizeof(health));
    REQUIRE(ninlil_model_runtime_project_health(NULL, &health)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(health.health == 0u && health.degraded_reason == 0u);
    (void)memset(counts, 0, sizeof(counts));
    REQUIRE(ninlil_model_runtime_project_health(counts, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&stage9, 0, sizeof(stage9));
    (void)memset(&health, 0xa5, sizeof(health));
    REQUIRE(ninlil_model_runtime_project_stage9_health(NULL, &health)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(health.health == 0u && health.degraded_reason == 0u);
    REQUIRE(ninlil_model_runtime_project_stage9_health(&stage9, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&observation, 0, sizeof(observation));
    (void)memset(&entropy, 0xa5, sizeof(entropy));
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(NULL, 1u, &entropy)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(entropy.api_status == 0 && entropy.action == 0
        && entropy.calls_consumed == 0u);
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        &observation, 1u, NULL) == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&entropy, 0xa5, sizeof(entropy));
    REQUIRE(ninlil_model_runtime_map_metrics_entropy(
        &observation, 5u, &entropy) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(entropy.api_status == 0 && entropy.action == 0
        && entropy.calls_consumed == 0u);
    return 0;
}

int main(void)
{
    if (test_capacity_derivation() != 0
        || test_validation_and_precedence() != 0
        || test_platform_validation_matrix() != 0
        || test_namespace_reserved_and_identity() != 0
        || test_rl1_to_rl7_matrix() != 0
        || test_cross_and_retention_matrix() != 0
        || test_storage_and_bearer_mapping() != 0
        || test_clock_classification() != 0
        || test_entropy_mapping() != 0
        || test_health_projection() != 0
        || test_null_and_zero_outputs() != 0) {
        return 1;
    }
    return 0;
}
