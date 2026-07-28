/*
 * External installed-package consumer.
 *
 * This file deliberately includes only installed public headers and links only
 * installed CMake targets. It creates, steps, and destroys a real Runtime with
 * a minimal valid Host platform fixture. The default executable supplies a
 * consumer-owned bounded in-memory storage provider through the public ABI, so
 * it proves that Ninlil::runtime is usable without the optional SQLite port.
 * An optional second executable repeats the lifecycle with the installed
 * SQLite target.
 */

#include <ninlil/runtime.h>

#if defined(NINLIL_CONSUMER_WITH_SQLITE)
#include <ninlil_posix_sqlite_storage.h>
#else
#include "memory_storage.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct consumer_fixture {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_bearer_ops_t bearer;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    uint64_t entropy_counter;
    uint8_t bearer_token;
} consumer_fixture_t;

static const uint8_t STORAGE_NAMESPACE[] =
    "installed-host-runtime-consumer";

static void set_header(
    uint16_t *abi_version,
    uint16_t *struct_size,
    size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;

    for (index = 0u; index < NINLIL_ID_BYTES; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static int power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static void *fixture_allocate(
    void *user,
    uint64_t size,
    uint32_t alignment)
{
    (void)user;
    if (size == 0u || size > (uint64_t)SIZE_MAX
        || !power_of_two(alignment)
        || alignment > (uint32_t)_Alignof(max_align_t)) {
        return NULL;
    }
    return malloc((size_t)size);
}

static void fixture_deallocate(
    void *user,
    void *pointer,
    uint64_t size,
    uint32_t alignment)
{
    (void)user;
    (void)size;
    (void)alignment;
    free(pointer);
}

static uint64_t fixture_context_id(void *user)
{
    (void)user;
    return 1u;
}

static ninlil_port_status_t fixture_now(
    void *user,
    ninlil_time_sample_t *out_sample)
{
    (void)user;
    if (out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    (void)memset(out_sample, 0, sizeof(*out_sample));
    set_header(
        &out_sample->abi_version,
        &out_sample->struct_size,
        sizeof(*out_sample));
    set_id(&out_sample->clock_epoch_id, 0xa0u);
    out_sample->now_ms = 1000u;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static ninlil_port_status_t fixture_entropy_fill(
    void *user,
    uint8_t *out,
    uint32_t length)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;
    uint32_t index;

    if (fixture == NULL || out == NULL || length == 0u) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    fixture->entropy_counter += 1u;
    for (index = 0u; index < length; ++index) {
        out[index] = (uint8_t)(
            1u + ((fixture->entropy_counter * 37u + index * 17u) % 251u));
    }
    return NINLIL_PORT_OK;
}

static ninlil_bearer_status_t fixture_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;

    if (fixture == NULL || runtime_id == NULL || out_handle == NULL
        || (role != NINLIL_ROLE_CONTROLLER
            && role != NINLIL_ROLE_ENDPOINT)) {
        return NINLIL_BEARER_DENIED;
    }
    *out_handle = &fixture->bearer_token;
    return NINLIL_BEARER_OK;
}

static void fixture_bearer_close(
    void *user,
    ninlil_bearer_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_bearer_status_t fixture_bearer_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    (void)user;
    (void)handle;
    (void)permit;
    (void)message;
    (void)out_result;
    return NINLIL_BEARER_WOULD_BLOCK;
}

static ninlil_bearer_status_t fixture_bearer_receive_next(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    (void)user;
    (void)handle;
    (void)out_message;
    return NINLIL_BEARER_EMPTY;
}

static void fixture_bearer_release_received(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    (void)user;
    (void)handle;
    (void)message;
}

static ninlil_bearer_status_t fixture_bearer_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    (void)user;
    if (handle == NULL || out_state == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    set_header(
        &out_state->abi_version,
        &out_state->struct_size,
        sizeof(*out_state));
    out_state->availability_epoch = 1u;
    out_state->available = 1u;
    return NINLIL_BEARER_OK;
}

static ninlil_tx_gate_status_t fixture_tx_acquire(
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

static void fixture_tx_release_unused(
    void *user,
    const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t fixture_origin_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    (void)user;
    (void)request;
    (void)out_decision;
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static void fixture_init(
    consumer_fixture_t *fixture,
    const ninlil_storage_ops_t *storage)
{
    (void)memset(fixture, 0, sizeof(*fixture));

    set_header(
        &fixture->allocator.abi_version,
        &fixture->allocator.struct_size,
        sizeof(fixture->allocator));
    fixture->allocator.allocate = fixture_allocate;
    fixture->allocator.deallocate = fixture_deallocate;

    set_header(
        &fixture->execution.abi_version,
        &fixture->execution.struct_size,
        sizeof(fixture->execution));
    fixture->execution.current_context_id = fixture_context_id;

    set_header(
        &fixture->clock.abi_version,
        &fixture->clock.struct_size,
        sizeof(fixture->clock));
    fixture->clock.now = fixture_now;

    set_header(
        &fixture->entropy.abi_version,
        &fixture->entropy.struct_size,
        sizeof(fixture->entropy));
    fixture->entropy.user = fixture;
    fixture->entropy.fill = fixture_entropy_fill;

    set_header(
        &fixture->bearer.abi_version,
        &fixture->bearer.struct_size,
        sizeof(fixture->bearer));
    fixture->bearer.user = fixture;
    fixture->bearer.open = fixture_bearer_open;
    fixture->bearer.close = fixture_bearer_close;
    fixture->bearer.send = fixture_bearer_send;
    fixture->bearer.receive_next = fixture_bearer_receive_next;
    fixture->bearer.release_received = fixture_bearer_release_received;
    fixture->bearer.state = fixture_bearer_state;

    set_header(
        &fixture->tx_gate.abi_version,
        &fixture->tx_gate.struct_size,
        sizeof(fixture->tx_gate));
    fixture->tx_gate.acquire = fixture_tx_acquire;
    fixture->tx_gate.release_unused = fixture_tx_release_unused;

    set_header(
        &fixture->origin.abi_version,
        &fixture->origin.struct_size,
        sizeof(fixture->origin));
    fixture->origin.evaluate = fixture_origin_evaluate;

    set_header(
        &fixture->platform.abi_version,
        &fixture->platform.struct_size,
        sizeof(fixture->platform));
    fixture->platform.allocator = &fixture->allocator;
    fixture->platform.execution = &fixture->execution;
    fixture->platform.clock = &fixture->clock;
    fixture->platform.entropy = &fixture->entropy;
    fixture->platform.storage = storage;
    fixture->platform.bearer = &fixture->bearer;
    fixture->platform.tx_gate = &fixture->tx_gate;
    fixture->platform.origin_authorization = &fixture->origin;
}

static ninlil_runtime_config_t runtime_config(void)
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
    config.storage_namespace.data = STORAGE_NAMESPACE;
    config.storage_namespace.length = sizeof(STORAGE_NAMESPACE) - 1u;

    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = 8u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 8u;
    config.limits.max_nonterminal_deliveries = 8u;
    config.limits.max_result_cache_entries = 8u;
    config.limits.max_retained_dispositions = 8u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 8u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 900u;
    config.observation_retention_ms = 800u;
    return config;
}

#if defined(NINLIL_CONSUMER_WITH_SQLITE)
static void remove_database_artifacts(const char *path)
{
    char sidecar[1024];

    (void)remove(path);
    if (snprintf(sidecar, sizeof(sidecar), "%s-wal", path)
        > 0) {
        (void)remove(sidecar);
    }
    if (snprintf(sidecar, sizeof(sidecar), "%s-shm", path)
        > 0) {
        (void)remove(sidecar);
    }
}
#endif

static int exercise_runtime(const ninlil_storage_ops_t *storage)
{
    consumer_fixture_t fixture;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_status_t status;
    fixture_init(&fixture, storage);
    config = runtime_config();
    status = ninlil_runtime_create(&config, &fixture.platform, &runtime);
    if (status != NINLIL_OK || runtime == NULL) {
        (void)fprintf(stderr, "runtime create failed: %d\n", (int)status);
        return 1;
    }

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 1u;
    budget.max_callbacks = 1u;
    budget.max_state_transitions = 2u;
    budget.max_bearer_sends = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    status = ninlil_runtime_step(runtime, &budget, &step_result);
    if (status != NINLIL_OK) {
        (void)fprintf(stderr, "runtime step failed: %d\n", (int)status);
        (void)ninlil_runtime_destroy(runtime);
        return 1;
    }

    status = ninlil_runtime_destroy(runtime);
    if (status != NINLIL_OK) {
        (void)fprintf(stderr, "runtime destroy failed: %d\n", (int)status);
        return 1;
    }
    return 0;
}

#if defined(NINLIL_CONSUMER_WITH_SQLITE)
int main(int argc, char **argv)
{
    ninlil_posix_sqlite_storage_config_t storage_config;
    ninlil_posix_sqlite_storage_t *storage;
    const char *database_path;
    int result;

    if (argc != 2 || argv[1] == NULL || argv[1][0] == '\0') {
        (void)fprintf(stderr, "usage: consumer <sqlite-database-path>\n");
        return 2;
    }
    database_path = argv[1];
    remove_database_artifacts(database_path);

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.database_path = database_path;
    storage_config.busy_timeout_ms =
        NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = 1048576u;
    storage_config.max_handles = 8u;
    storage_config.max_transactions = 8u;
    storage_config.max_iterators = 8u;
    storage = ninlil_posix_sqlite_storage_create(&storage_config);
    if (storage == NULL) {
        (void)fprintf(stderr, "SQLite storage create failed\n");
        return 1;
    }
    result = exercise_runtime(ninlil_posix_sqlite_storage_ops(storage));
    if (result == 0
        && (ninlil_posix_sqlite_storage_live_handles(storage) != 0u
            || ninlil_posix_sqlite_storage_live_transactions(storage) != 0u
            || ninlil_posix_sqlite_storage_live_iterators(storage) != 0u)) {
        (void)fprintf(stderr, "SQLite port cleanup failed\n");
        result = 1;
    }

    ninlil_posix_sqlite_storage_destroy(storage);
    remove_database_artifacts(database_path);
    if (result == 0) {
        (void)printf("installed_host_runtime_sqlite_consumer ok\n");
    }
    return result;
}
#else
int main(void)
{
    consumer_memory_storage_t *storage =
        consumer_memory_storage_create();
    int result;

    if (storage == NULL) {
        (void)fprintf(stderr, "memory storage create failed\n");
        return 1;
    }
    result = exercise_runtime(consumer_memory_storage_ops(storage));
    if (result == 0
        && (consumer_memory_storage_live_handles(storage) != 0u
            || consumer_memory_storage_live_transactions(storage) != 0u
            || consumer_memory_storage_live_iterators(storage) != 0u)) {
        (void)fprintf(stderr, "memory storage cleanup failed\n");
        result = 1;
    }
    consumer_memory_storage_destroy(storage);
    if (result == 0) {
        (void)printf("installed_host_runtime_memory_consumer ok\n");
    }
    return result;
}
#endif
