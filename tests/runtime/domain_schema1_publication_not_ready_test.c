/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0022 public fail-closed acceptance.
 *
 * While the private Domain schema1 implementation is incomplete, a valid
 * public Runtime create must return NINLIL_E_UNSUPPORTED before every Port
 * call/allocation and without publishing a handle.
 */

#include "deterministic_entropy.h"
#include "domain_schema1_startup_owner.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_lifecycle_model.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                  \
    do {                                                                    \
        if (!(condition)) {                                                 \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "domain_schema1_not_ready FAIL %s:%d: %s\n",                \
                __FILE__,                                                   \
                __LINE__,                                                   \
                #condition);                                                \
            return 1;                                                       \
        }                                                                   \
    } while (0)

_Static_assert(
    NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY == 0u,
    "this acceptance test is valid only while public Domain Runtime is closed");

static const uint8_t k_namespace[] = "domain-schema1-not-ready";

typedef struct test_env {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage;
    ninlil_test_bearer_t *bearer;
    uint64_t origin_calls;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
} test_env_t;

static void set_header(uint16_t *version, uint16_t *size, size_t bytes)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)bytes;
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;

    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static ninlil_origin_auth_status_t origin_trap(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    uint64_t *calls = (uint64_t *)user;

    (void)request;
    (void)decision;
    if (calls != NULL && *calls != UINT64_MAX) {
        *calls += 1u;
    }
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static ninlil_runtime_config_t make_valid_config(void)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x44u);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x55u);
    set_id(&config.local_identity.installation_id, 0x66u);
    set_id(&config.local_identity.site_domain_id, 0x77u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = k_namespace;
    config.storage_namespace.length = sizeof(k_namespace) - 1u;
    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 16u;
    config.limits.max_nonterminal_transactions = 32u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 256u;
    config.limits.max_durable_outbox_payload_bytes = 8192u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 64u;
    config.limits.max_nonterminal_deliveries = 32u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 32u;
    config.limits.max_retained_dispositions = 64u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 16u;
    config.terminal_retention_ms = 2000u;
    config.result_cache_retention_ms = 1000u;
    config.observation_retention_ms = 3000u;
    return config;
}

static int env_init(test_env_t *env)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_bearer_config_t bearer_config;

    (void)memset(env, 0, sizeof(*env));
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 2u;
    storage_config.max_entries_per_namespace = 256u;
    storage_config.max_bytes_per_namespace = 1024u * 1024u;
    env->allocator = ninlil_test_allocator_create();
    env->execution = ninlil_test_execution_create(1u);
    env->clock = ninlil_test_clock_create();
    env->entropy = ninlil_test_entropy_create(0xD011u, 1u);
    env->storage = ninlil_test_storage_create(&storage_config);

    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 8u;
    bearer_config.max_bytes_per_direction = 65536u;
    bearer_config.max_permits = 8u;
    bearer_config.permit_issuer_id.bytes[0] = 0x80u;
    bearer_config.initial_clock_epoch_id.bytes[0] = 0xa0u;
    env->bearer = ninlil_test_bearer_create(&bearer_config);
    if (env->allocator == NULL || env->execution == NULL || env->clock == NULL
        || env->entropy == NULL || env->storage == NULL
        || env->bearer == NULL) {
        return 0;
    }

    set_header(
        &env->origin.abi_version,
        &env->origin.struct_size,
        sizeof(env->origin));
    env->origin.user = &env->origin_calls;
    env->origin.evaluate = origin_trap;

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
    env->config = make_valid_config();
    return 1;
}

static uint64_t env_fini(test_env_t *env)
{
    uint64_t leaks = 0u;

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
        leaks = ninlil_test_allocator_destroy(env->allocator);
    }
    (void)memset(env, 0, sizeof(*env));
    return leaks;
}

int main(void)
{
    test_env_t env;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_test_allocator_diagnostics_t allocator_before;
    ninlil_test_allocator_diagnostics_t allocator_after;
    uint64_t storage_before[NINLIL_TEST_STORAGE_OP_COUNT];
    uint64_t bearer_before[NINLIL_TEST_BEARER_OP_COUNT];
    uint64_t execution_before;
    uint64_t clock_before;
    uint64_t entropy_before;
    uint64_t origin_before;
    ninlil_runtime_t *runtime = (ninlil_runtime_t *)(uintptr_t)1u;
    ninlil_status_t status;
    uint32_t index;

    REQUIRE(env_init(&env));
    status = ninlil_model_runtime_validate_and_derive(
        &env.config, &env.platform, &validation);
    REQUIRE(status == NINLIL_OK);
    REQUIRE(validation.status == NINLIL_OK);

    allocator_before = ninlil_test_allocator_diagnostics(env.allocator);
    execution_before = ninlil_test_execution_call_count(env.execution);
    clock_before = ninlil_test_clock_call_count(env.clock);
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    origin_before = env.origin_calls;
    for (index = 0u; index < NINLIL_TEST_STORAGE_OP_COUNT; ++index) {
        storage_before[index] = ninlil_test_storage_call_count(
            env.storage, (ninlil_test_storage_operation_t)index);
    }
    for (index = 0u; index < NINLIL_TEST_BEARER_OP_COUNT; ++index) {
        bearer_before[index] = ninlil_test_bearer_call_count(
            env.bearer, (ninlil_test_bearer_operation_t)index);
    }

    status = ninlil_runtime_create(&env.config, &env.platform, &runtime);
    REQUIRE(status == NINLIL_E_UNSUPPORTED);
    REQUIRE(runtime == NULL);

    allocator_after = ninlil_test_allocator_diagnostics(env.allocator);
    REQUIRE(allocator_after.allocate_calls == allocator_before.allocate_calls);
    REQUIRE(
        allocator_after.deallocate_calls == allocator_before.deallocate_calls);
    REQUIRE(
        allocator_after.live_allocations
        == allocator_before.live_allocations);
    REQUIRE(allocator_after.live_bytes == allocator_before.live_bytes);
    REQUIRE(
        allocator_after.violation_count == allocator_before.violation_count);
    REQUIRE(
        ninlil_test_execution_call_count(env.execution) == execution_before);
    REQUIRE(ninlil_test_clock_call_count(env.clock) == clock_before);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy) == entropy_before);
    REQUIRE(env.origin_calls == origin_before);
    for (index = 0u; index < NINLIL_TEST_STORAGE_OP_COUNT; ++index) {
        REQUIRE(
            ninlil_test_storage_call_count(
                env.storage, (ninlil_test_storage_operation_t)index)
            == storage_before[index]);
    }
    for (index = 0u; index < NINLIL_TEST_BEARER_OP_COUNT; ++index) {
        REQUIRE(
            ninlil_test_bearer_call_count(
                env.bearer, (ninlil_test_bearer_operation_t)index)
            == bearer_before[index]);
    }

    REQUIRE(env_fini(&env) == 0u);
    (void)printf(
        "domain_schema1_publication_not_ready OK "
        "unsupported+null-handle+zero-port-calls\n");
    return 0;
}
