/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TESTS_RUNTIME_COMPOSITION_V1_TEST_FIXTURE_H
#define NINLIL_TESTS_RUNTIME_COMPOSITION_V1_TEST_FIXTURE_H

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"

#include <ninlil/composition_v1.h>

#include <stdint.h>
#include <string.h>

typedef struct composition_test_fixture {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage;
    uint32_t owns_storage;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin_authorization;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
    uint8_t storage_namespace[64];
    void *workspace;
    uint32_t workspace_bytes;
    uint32_t workspace_alignment;
} composition_test_fixture_t;

static void composition_test_set_id(ninlil_id128_t *id, uint8_t seed)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(seed + index);
    }
}

static ninlil_tx_gate_status_t composition_test_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    (void)user;
    (void)request;
    (void)now;
    (void)out_permit;
    return NINLIL_TX_GATE_DENIED;
}

static void composition_test_tx_release(
    void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t composition_test_origin_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    (void)user;
    (void)request;
    (void)out_decision;
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static int composition_test_fixture_init(
    composition_test_fixture_t *fixture,
    ninlil_test_storage_t *shared_storage,
    uint8_t runtime_seed,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length)
{
    ninlil_test_storage_config_t storage_config;
    const ninlil_allocator_ops_t *allocator_ops;

    if (fixture == NULL || storage_namespace == NULL
        || storage_namespace_length == 0u
        || storage_namespace_length > sizeof(fixture->storage_namespace)) {
        return 0;
    }
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->allocator = ninlil_test_allocator_create();
    fixture->execution = ninlil_test_execution_create(1u);
    fixture->clock = ninlil_test_clock_create();
    fixture->entropy = ninlil_test_entropy_create(7u, runtime_seed);
    if (shared_storage == NULL) {
        (void)memset(&storage_config, 0, sizeof(storage_config));
        storage_config.max_namespaces = 32u;
        storage_config.max_entries_per_namespace = 512u;
        storage_config.max_bytes_per_namespace = UINT64_C(1048576);
        fixture->storage = ninlil_test_storage_create(&storage_config);
        fixture->owns_storage = 1u;
    } else {
        fixture->storage = shared_storage;
    }
    if (fixture->allocator == NULL || fixture->execution == NULL
        || fixture->clock == NULL || fixture->entropy == NULL
        || fixture->storage == NULL) {
        return 0;
    }

    fixture->tx_gate.abi_version = NINLIL_ABI_VERSION;
    fixture->tx_gate.struct_size = (uint16_t)sizeof(fixture->tx_gate);
    fixture->tx_gate.acquire = composition_test_tx_acquire;
    fixture->tx_gate.release_unused = composition_test_tx_release;
    fixture->origin_authorization.abi_version = NINLIL_ABI_VERSION;
    fixture->origin_authorization.struct_size =
        (uint16_t)sizeof(fixture->origin_authorization);
    fixture->origin_authorization.evaluate = composition_test_origin_evaluate;

    fixture->platform.abi_version = NINLIL_ABI_VERSION;
    fixture->platform.struct_size = (uint16_t)sizeof(fixture->platform);
    fixture->platform.allocator =
        ninlil_test_allocator_ops(fixture->allocator);
    fixture->platform.execution =
        ninlil_test_execution_ops(fixture->execution);
    fixture->platform.clock = ninlil_test_clock_ops(fixture->clock);
    fixture->platform.entropy = ninlil_test_entropy_ops(fixture->entropy);
    fixture->platform.storage = ninlil_test_storage_ops(fixture->storage);
    fixture->platform.bearer = NULL;
    fixture->platform.tx_gate = &fixture->tx_gate;
    fixture->platform.origin_authorization =
        &fixture->origin_authorization;

    (void)memcpy(
        fixture->storage_namespace,
        storage_namespace,
        storage_namespace_length);
    fixture->config.abi_version = NINLIL_ABI_VERSION;
    fixture->config.struct_size = (uint16_t)sizeof(fixture->config);
    fixture->config.role = NINLIL_ROLE_CONTROLLER;
    fixture->config.environment = NINLIL_ENV_TEST;
    composition_test_set_id(&fixture->config.runtime_id, runtime_seed);
    fixture->config.local_identity.abi_version = NINLIL_ABI_VERSION;
    fixture->config.local_identity.struct_size =
        (uint16_t)sizeof(fixture->config.local_identity);
    fixture->config.local_identity.flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    composition_test_set_id(
        &fixture->config.local_identity.device_id,
        (uint8_t)(runtime_seed + 0x10u));
    composition_test_set_id(
        &fixture->config.local_identity.installation_id,
        (uint8_t)(runtime_seed + 0x20u));
    composition_test_set_id(
        &fixture->config.local_identity.site_domain_id,
        (uint8_t)(runtime_seed + 0x30u));
    fixture->config.local_identity.binding_epoch = 1u;
    fixture->config.local_identity.membership_epoch = 1u;
    fixture->config.storage_namespace.data = fixture->storage_namespace;
    fixture->config.storage_namespace.length = storage_namespace_length;
    fixture->config.limits.abi_version = NINLIL_ABI_VERSION;
    fixture->config.limits.struct_size =
        (uint16_t)sizeof(fixture->config.limits);
    fixture->config.limits.max_services = 2u;
    fixture->config.limits.max_nonterminal_transactions = 4u;
    fixture->config.limits.max_targets_per_transaction = 1u;
    fixture->config.limits.max_logical_payload_bytes = 1000u;
    fixture->config.limits.max_durable_outbox_payload_bytes = 4096u;
    fixture->config.limits.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    fixture->config.limits.max_cancel_attempts_per_transaction = 1u;
    fixture->config.limits.max_evidence_per_target = 2u;
    fixture->config.limits.max_retained_terminal_transactions = 4u;
    fixture->config.limits.max_nonterminal_deliveries = 4u;
    fixture->config.limits.max_result_cache_entries = 4u;
    fixture->config.limits.max_retained_dispositions = 4u;
    fixture->config.limits.max_ingress_per_step = 4u;
    fixture->config.limits.max_callbacks_per_step = 4u;
    fixture->config.limits.max_state_transitions_per_step = 4u;
    fixture->config.limits.max_bearer_sends_per_step = 4u;
    fixture->config.limits.max_deferred_tokens = 4u;
    fixture->config.terminal_retention_ms = 4000u;
    fixture->config.result_cache_retention_ms = 1000u;
    fixture->config.observation_retention_ms = 1000u;

    if (ninlil_composition_v1_workspace_required(
            NINLIL_COMPOSITION_PROFILE_1,
            &fixture->workspace_bytes,
            &fixture->workspace_alignment)
        != NINLIL_OK) {
        return 0;
    }
    allocator_ops = ninlil_test_allocator_ops(fixture->allocator);
    fixture->workspace = allocator_ops->allocate(
        allocator_ops->user,
        fixture->workspace_bytes,
        fixture->workspace_alignment);
    return fixture->workspace != NULL;
}

static inline int composition_test_fixture_release_composition(
    composition_test_fixture_t *fixture,
    ninlil_composition_v1_t *composition)
{
    uint32_t done = 0u;
    uint32_t spins;

    (void)fixture;
    if (composition == NULL) {
        return 1;
    }
    if (ninlil_composition_v1_close_begin(composition) != NINLIL_OK) {
        return 0;
    }
    for (spins = 0u; spins < 64u && done == 0u; ++spins) {
        if (ninlil_composition_v1_close_poll(composition, 64u, &done)
            != NINLIL_OK) {
            return 0;
        }
    }
    if (done == 0u || ninlil_composition_v1_destroy(composition) != NINLIL_OK) {
        return 0;
    }
    return 1;
}

static void composition_test_fixture_destroy(
    composition_test_fixture_t *fixture)
{
    const ninlil_allocator_ops_t *allocator_ops;

    if (fixture == NULL) {
        return;
    }
    if (fixture->allocator != NULL && fixture->workspace != NULL) {
        allocator_ops = ninlil_test_allocator_ops(fixture->allocator);
        allocator_ops->deallocate(
            allocator_ops->user,
            fixture->workspace,
            fixture->workspace_bytes,
            fixture->workspace_alignment);
        fixture->workspace = NULL;
    }
    if (fixture->entropy != NULL) {
        ninlil_test_entropy_destroy(fixture->entropy);
    }
    if (fixture->clock != NULL) {
        ninlil_test_clock_destroy(fixture->clock);
    }
    if (fixture->execution != NULL) {
        ninlil_test_execution_destroy(fixture->execution);
    }
    if (fixture->allocator != NULL) {
        (void)ninlil_test_allocator_destroy(fixture->allocator);
    }
    if (fixture->owns_storage != 0u && fixture->storage != NULL) {
        ninlil_test_storage_destroy(fixture->storage);
    }
    (void)memset(fixture, 0, sizeof(*fixture));
}

#endif
