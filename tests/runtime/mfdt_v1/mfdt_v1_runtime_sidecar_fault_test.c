/* SPDX-License-Identifier: Apache-2.0
 *
 * Runtime-owned MFDT sidecar fault acceptance.  This is a Host software
 * witness for the NMS1 bootstrap/reopen classifier and exact close order; it
 * is not physical power-cut or ESP HIL evidence.
 */
#include "mfdt_v1_runtime_owner.h"
#include "runtime_internal.h"

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROXY_HANDLE_MAX ((size_t)8u)
#define PROXY_TXN_MAX ((size_t)32u)

static const uint8_t k_base_namespace[] = "mfdt-runtime-sidecar-fault";
static const uint8_t k_namespace_domain[] =
    "NINLIL-MFDT-STORAGE-NAMESPACE-V1";
static const uint8_t k_binding_domain[] =
    "NINLIL-MFDT-BASE-NAMESPACE-V1";
static const uint8_t k_binding_key[20] = {'N', 'M', 'S', '1'};

typedef enum mutation_kind {
    MUTATION_NONE = 0,
    MUTATION_PARTIAL = 1,
    MUTATION_EXTRA = 2,
    MUTATION_THIRD = 3
} mutation_kind_t;

typedef struct close_trace {
    const ninlil_bearer_ops_t *raw_bearer;
    uint64_t sequence;
    uint64_t bearer_close_sequence;
    uint64_t sidecar_close_sequence;
    uint64_t foundation_close_sequence;
} close_trace_t;

typedef struct proxy_handle {
    ninlil_storage_handle_t handle;
    uint8_t sidecar;
} proxy_handle_t;

typedef struct proxy_txn {
    ninlil_storage_txn_t txn;
    ninlil_storage_handle_t handle;
    ninlil_storage_mode_t mode;
    uint8_t sidecar;
} proxy_txn_t;

typedef struct storage_proxy {
    const ninlil_storage_ops_t *raw;
    ninlil_storage_ops_t ops;
    close_trace_t *close_trace;
    mutation_kind_t mutation;
    uint32_t injected_count;
    uint8_t sidecar_namespace[36];
    uint8_t binding_value[307];
    uint32_t binding_value_length;
    proxy_handle_t handles[PROXY_HANDLE_MAX];
    proxy_txn_t transactions[PROXY_TXN_MAX];
} storage_proxy_t;

typedef struct test_env {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage;
    ninlil_test_bearer_t *bearer;
    ninlil_origin_authorization_ops_t origin;
    ninlil_bearer_ops_t tracked_bearer;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime;
    close_trace_t close_trace;
    storage_proxy_t proxy;
} test_env_t;

static close_trace_t *g_close_trace;

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void set_id(ninlil_id128_t *id, uint8_t tag)
{
    size_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(tag + (uint8_t)index);
    }
}

static void derive_sidecar_namespace(
    const uint8_t *base,
    uint32_t base_length,
    uint8_t out[36])
{
    uint8_t preimage[sizeof(k_namespace_domain) - 1u + 2u + 255u];
    uint8_t digest[32];
    uint32_t offset = 0u;

    (void)memcpy(
        preimage + offset,
        k_namespace_domain,
        sizeof(k_namespace_domain) - 1u);
    offset += (uint32_t)sizeof(k_namespace_domain) - 1u;
    ninlil_mfdt_v1_put_u16(preimage + offset, (uint16_t)base_length);
    offset += 2u;
    (void)memcpy(preimage + offset, base, base_length);
    offset += base_length;
    ninlil_mfdt_v1_sha256(preimage, offset, digest);
    (void)memcpy(out, "NMF1", 4u);
    (void)memcpy(out + 4u, digest, sizeof(digest));
}

static uint32_t build_binding_value(
    const uint8_t *base,
    uint32_t base_length,
    uint8_t out[307])
{
    uint8_t preimage[sizeof(k_binding_domain) - 1u + 2u + 255u];
    uint8_t digest[32];
    uint32_t preimage_length = 0u;
    uint32_t offset = 0u;
    uint32_t total_length = 52u + base_length;

    (void)memcpy(
        preimage + preimage_length,
        k_binding_domain,
        sizeof(k_binding_domain) - 1u);
    preimage_length += (uint32_t)sizeof(k_binding_domain) - 1u;
    ninlil_mfdt_v1_put_u16(
        preimage + preimage_length, (uint16_t)base_length);
    preimage_length += 2u;
    (void)memcpy(preimage + preimage_length, base, base_length);
    preimage_length += base_length;
    ninlil_mfdt_v1_sha256(preimage, preimage_length, digest);

    (void)memset(out, 0, 307u);
    (void)memcpy(out + offset, "NMS1", 4u);
    offset += 4u;
    ninlil_mfdt_v1_put_u16(out + offset, 1u);
    offset += 2u;
    ninlil_mfdt_v1_put_u16(out + offset, 48u);
    offset += 2u;
    ninlil_mfdt_v1_put_u32(out + offset, total_length);
    offset += 4u;
    ninlil_mfdt_v1_put_u16(out + offset, (uint16_t)base_length);
    offset += 2u;
    ninlil_mfdt_v1_put_u16(out + offset, 0u);
    offset += 2u;
    (void)memcpy(out + offset, digest, sizeof(digest));
    offset += (uint32_t)sizeof(digest);
    (void)memcpy(out + offset, base, base_length);
    offset += base_length;
    ninlil_mfdt_v1_put_u32(
        out + offset, ninlil_mfdt_v1_crc32c(out, offset));
    offset += 4u;
    return offset;
}

static proxy_handle_t *find_handle(
    storage_proxy_t *proxy,
    ninlil_storage_handle_t handle)
{
    size_t index;

    for (index = 0u; index < PROXY_HANDLE_MAX; ++index) {
        if (proxy->handles[index].handle == handle) {
            return &proxy->handles[index];
        }
    }
    return NULL;
}

static proxy_txn_t *find_transaction(
    storage_proxy_t *proxy,
    ninlil_storage_txn_t transaction)
{
    size_t index;

    for (index = 0u; index < PROXY_TXN_MAX; ++index) {
        if (proxy->transactions[index].txn == transaction) {
            return &proxy->transactions[index];
        }
    }
    return NULL;
}

static int remember_handle(
    storage_proxy_t *proxy,
    ninlil_storage_handle_t handle,
    int sidecar)
{
    size_t index;

    for (index = 0u; index < PROXY_HANDLE_MAX; ++index) {
        if (proxy->handles[index].handle == NULL) {
            proxy->handles[index].handle = handle;
            proxy->handles[index].sidecar = sidecar != 0;
            return 1;
        }
    }
    return 0;
}

static int remember_transaction(
    storage_proxy_t *proxy,
    ninlil_storage_txn_t transaction,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    int sidecar)
{
    size_t index;

    for (index = 0u; index < PROXY_TXN_MAX; ++index) {
        if (proxy->transactions[index].txn == NULL) {
            proxy->transactions[index].txn = transaction;
            proxy->transactions[index].handle = handle;
            proxy->transactions[index].mode = mode;
            proxy->transactions[index].sidecar = sidecar != 0;
            return 1;
        }
    }
    return 0;
}

static ninlil_storage_status_t proxy_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    ninlil_storage_status_t status;
    int sidecar;

    if (proxy == NULL || proxy->raw == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    status = proxy->raw->open(
        proxy->raw->user, storage_namespace, expected_schema, out_handle);
    if (status != NINLIL_STORAGE_OK || out_handle == NULL
        || *out_handle == NULL) {
        return status;
    }
    sidecar = storage_namespace.length == sizeof(proxy->sidecar_namespace)
        && memcmp(
               storage_namespace.data,
               proxy->sidecar_namespace,
               sizeof(proxy->sidecar_namespace)) == 0;
    if (!remember_handle(proxy, *out_handle, sidecar)) {
        proxy->raw->close(proxy->raw->user, *out_handle);
        *out_handle = NULL;
        return NINLIL_STORAGE_NO_SPACE;
    }
    return NINLIL_STORAGE_OK;
}

static void proxy_close(void *user, ninlil_storage_handle_t handle)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    proxy_handle_t *entry;

    if (proxy == NULL || proxy->raw == NULL) {
        return;
    }
    entry = find_handle(proxy, handle);
    if (entry != NULL && proxy->close_trace != NULL) {
        proxy->close_trace->sequence += 1u;
        if (entry->sidecar != 0u) {
            proxy->close_trace->sidecar_close_sequence =
                proxy->close_trace->sequence;
        } else {
            proxy->close_trace->foundation_close_sequence =
                proxy->close_trace->sequence;
        }
    }
    if (entry != NULL) {
        (void)memset(entry, 0, sizeof(*entry));
    }
    proxy->raw->close(proxy->raw->user, handle);
}

static ninlil_storage_status_t proxy_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    proxy_handle_t *handle_entry;
    ninlil_storage_status_t status;

    if (proxy == NULL || proxy->raw == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    handle_entry = find_handle(proxy, handle);
    if (handle_entry == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    status = proxy->raw->begin(
        proxy->raw->user, handle, mode, out_transaction);
    if (status != NINLIL_STORAGE_OK || out_transaction == NULL
        || *out_transaction == NULL) {
        return status;
    }
    if (!remember_transaction(
            proxy,
            *out_transaction,
            handle,
            mode,
            handle_entry->sidecar)) {
        (void)proxy->raw->rollback(proxy->raw->user, *out_transaction);
        *out_transaction = NULL;
        return NINLIL_STORAGE_NO_SPACE;
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t proxy_get(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *value)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    return proxy->raw->get(proxy->raw->user, transaction, key, value);
}

static ninlil_storage_status_t proxy_put(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    return proxy->raw->put(proxy->raw->user, transaction, key, value);
}

static ninlil_storage_status_t proxy_erase(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    return proxy->raw->erase(proxy->raw->user, transaction, key);
}

static ninlil_storage_status_t proxy_iter_open(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    return proxy->raw->iter_open(
        proxy->raw->user, transaction, prefix, out_iterator);
}

static ninlil_storage_status_t proxy_iter_next(
    void *user,
    ninlil_storage_iter_t iterator,
    ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    return proxy->raw->iter_next(
        proxy->raw->user, iterator, key, value);
}

static void proxy_iter_close(void *user, ninlil_storage_iter_t iterator)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    proxy->raw->iter_close(proxy->raw->user, iterator);
}

static ninlil_storage_status_t proxy_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *capacity)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    return proxy->raw->capacity(proxy->raw->user, handle, capacity);
}

static int mutate_committed_binding(
    storage_proxy_t *proxy,
    ninlil_storage_handle_t handle,
    mutation_kind_t mutation)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    uint8_t third[307];
    uint8_t extra_key[20] = {'N', 'M', '3', 'S'};
    uint8_t extra_value = 0u;
    ninlil_storage_status_t status;

    status = proxy->raw->begin(
        proxy->raw->user,
        handle,
        NINLIL_STORAGE_READ_WRITE,
        &transaction);
    if (status != NINLIL_STORAGE_OK || transaction == NULL) {
        return 0;
    }
    if (mutation == MUTATION_EXTRA) {
        extra_key[4] = 0x90u;
        extra_key[19] = 0x9fu;
        key.data = extra_key;
        key.length = sizeof(extra_key);
        value.data = &extra_value;
        value.length = 1u;
    } else {
        key.data = k_binding_key;
        key.length = sizeof(k_binding_key);
        if (mutation == MUTATION_PARTIAL) {
            value.data = proxy->binding_value;
            value.length = proxy->binding_value_length - 1u;
        } else if (mutation == MUTATION_THIRD) {
            (void)memcpy(
                third, proxy->binding_value, proxy->binding_value_length);
            third[8] ^= 0x01u;
            value.data = third;
            value.length = proxy->binding_value_length;
        } else {
            (void)proxy->raw->rollback(proxy->raw->user, transaction);
            return 0;
        }
    }
    status = proxy->raw->put(
        proxy->raw->user, transaction, key, value);
    if (status != NINLIL_STORAGE_OK) {
        (void)proxy->raw->rollback(proxy->raw->user, transaction);
        return 0;
    }
    status = proxy->raw->commit(
        proxy->raw->user, transaction, NINLIL_DURABILITY_FULL);
    return status == NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t proxy_commit(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_durability_t durability)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    proxy_txn_t *entry = find_transaction(proxy, transaction);
    proxy_txn_t snapshot;
    ninlil_storage_status_t status;
    mutation_kind_t mutation;

    if (entry == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    snapshot = *entry;
    (void)memset(entry, 0, sizeof(*entry));
    status = proxy->raw->commit(
        proxy->raw->user, transaction, durability);
    mutation = proxy->mutation;
    if (status == NINLIL_STORAGE_OK
        && snapshot.sidecar != 0u
        && snapshot.mode == NINLIL_STORAGE_READ_WRITE
        && mutation != MUTATION_NONE) {
        proxy->mutation = MUTATION_NONE;
        if (!mutate_committed_binding(proxy, snapshot.handle, mutation)) {
            return NINLIL_STORAGE_CORRUPT;
        }
        proxy->injected_count += 1u;
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    return status;
}

static ninlil_storage_status_t proxy_rollback(
    void *user,
    ninlil_storage_txn_t transaction)
{
    storage_proxy_t *proxy = (storage_proxy_t *)user;
    proxy_txn_t *entry = find_transaction(proxy, transaction);
    ninlil_storage_status_t status = proxy->raw->rollback(
        proxy->raw->user, transaction);

    if (entry != NULL) {
        (void)memset(entry, 0, sizeof(*entry));
    }
    return status;
}

static void proxy_init(
    storage_proxy_t *proxy,
    const ninlil_storage_ops_t *raw,
    close_trace_t *close_trace)
{
    (void)memset(proxy, 0, sizeof(*proxy));
    proxy->raw = raw;
    proxy->close_trace = close_trace;
    derive_sidecar_namespace(
        k_base_namespace,
        (uint32_t)(sizeof(k_base_namespace) - 1u),
        proxy->sidecar_namespace);
    proxy->binding_value_length = build_binding_value(
        k_base_namespace,
        (uint32_t)(sizeof(k_base_namespace) - 1u),
        proxy->binding_value);
    proxy->ops.abi_version = NINLIL_ABI_VERSION;
    proxy->ops.struct_size = (uint16_t)sizeof(proxy->ops);
    proxy->ops.user = proxy;
    proxy->ops.open = proxy_open;
    proxy->ops.close = proxy_close;
    proxy->ops.begin = proxy_begin;
    proxy->ops.get = proxy_get;
    proxy->ops.put = proxy_put;
    proxy->ops.erase = proxy_erase;
    proxy->ops.iter_open = proxy_iter_open;
    proxy->ops.iter_next = proxy_iter_next;
    proxy->ops.iter_close = proxy_iter_close;
    proxy->ops.capacity = proxy_capacity;
    proxy->ops.commit = proxy_commit;
    proxy->ops.rollback = proxy_rollback;
}

static void tracked_bearer_close(
    void *user,
    ninlil_bearer_handle_t handle)
{
    if (g_close_trace == NULL || g_close_trace->raw_bearer == NULL) {
        return;
    }
    g_close_trace->sequence += 1u;
    g_close_trace->bearer_close_sequence = g_close_trace->sequence;
    g_close_trace->raw_bearer->close(user, handle);
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
    config.local_identity.flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = k_base_namespace;
    config.storage_namespace.length = sizeof(k_base_namespace) - 1u;
    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes = 262144u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 32u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_result_cache_entries = 32u;
    config.limits.max_retained_dispositions = 32u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static int env_init(test_env_t *env)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_bearer_config_t bearer_config;
    const ninlil_bearer_ops_t *raw_bearer;

    (void)memset(env, 0, sizeof(*env));
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 4u;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = 2u * 1024u * 1024u;
    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 32u;
    bearer_config.max_bytes_per_direction = 65536u;
    bearer_config.max_permits = 32u;
    set_id(&bearer_config.permit_issuer_id, 0x80u);
    set_id(&bearer_config.initial_clock_epoch_id, 0xa0u);

    env->allocator = ninlil_test_allocator_create();
    env->execution = ninlil_test_execution_create(1u);
    env->clock = ninlil_test_clock_create();
    env->entropy = ninlil_test_entropy_create(0x44556677u, 1u);
    env->storage = ninlil_test_storage_create(&storage_config);
    env->bearer = ninlil_test_bearer_create(&bearer_config);
    if (env->allocator == NULL || env->execution == NULL
        || env->clock == NULL || env->entropy == NULL
        || env->storage == NULL || env->bearer == NULL) {
        return 0;
    }
    raw_bearer = ninlil_test_bearer_ops(env->bearer);
    env->close_trace.raw_bearer = raw_bearer;
    proxy_init(
        &env->proxy,
        ninlil_test_storage_ops(env->storage),
        &env->close_trace);
    env->tracked_bearer = *raw_bearer;
    env->tracked_bearer.close = tracked_bearer_close;
    g_close_trace = &env->close_trace;

    set_header(
        &env->origin.abi_version,
        &env->origin.struct_size,
        sizeof(env->origin));
    env->origin.evaluate = origin_stub;
    set_header(
        &env->platform.abi_version,
        &env->platform.struct_size,
        sizeof(env->platform));
    env->platform.allocator = ninlil_test_allocator_ops(env->allocator);
    env->platform.execution = ninlil_test_execution_ops(env->execution);
    env->platform.clock = ninlil_test_clock_ops(env->clock);
    env->platform.entropy = ninlil_test_entropy_ops(env->entropy);
    env->platform.storage = &env->proxy.ops;
    env->platform.bearer = &env->tracked_bearer;
    env->platform.tx_gate = ninlil_test_bearer_tx_gate_ops(env->bearer);
    env->platform.origin_authorization = &env->origin;
    env->config = runtime_config();
    return ninlil_runtime_create(
               &env->config, &env->platform, &env->runtime)
        == NINLIL_OK;
}

static int env_destroy(test_env_t *env)
{
    int ok = 1;
    uint64_t leaked_allocations;

    if (env->runtime != NULL) {
        ninlil_status_t status = ninlil_runtime_destroy(env->runtime);
        if (status != NINLIL_OK
            && status != NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
            ok = 0;
        }
        env->runtime = NULL;
    }
    if (ninlil_test_storage_live_handles(env->storage) != 0u
        || ninlil_test_storage_live_transactions(env->storage) != 0u
        || ninlil_test_storage_live_iterators(env->storage) != 0u
        || ninlil_test_bearer_live_handle_count(env->bearer) != 0u) {
        ok = 0;
    }
    if (g_close_trace == &env->close_trace) {
        g_close_trace = NULL;
    }
    ninlil_test_bearer_destroy(env->bearer);
    ninlil_test_storage_destroy(env->storage);
    ninlil_test_entropy_destroy(env->entropy);
    ninlil_test_clock_destroy(env->clock);
    ninlil_test_execution_destroy(env->execution);
    leaked_allocations = ninlil_test_allocator_destroy(env->allocator);
    if (leaked_allocations != 0u) {
        ok = 0;
    }
    (void)memset(env, 0, sizeof(*env));
    return ok;
}

static ninlil_status_t enable_owner(ninlil_runtime_t *runtime)
{
    ninlil_rt_mfdt_v1_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.struct_size = (uint32_t)sizeof(config);
    config.enabled = 1u;
    config.session_generation = 1u;
    config.session_cookie = UINT64_C(0x1122334455667788);
    return ninlil_rt_mfdt_v1_runtime_configure(runtime, &config);
}

static int owner_is_ready(ninlil_runtime_t *runtime)
{
    ninlil_rt_mfdt_v1_runtime_snapshot_t snapshot;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    snapshot.struct_size = (uint32_t)sizeof(snapshot);
    return ninlil_rt_mfdt_v1_runtime_snapshot(runtime, &snapshot)
            == NINLIL_OK
        && snapshot.enabled == 1u
        && snapshot.ready == 1u
        && snapshot.exact_slot_count == 4u
        && snapshot.active_count == 0u
        && snapshot.inventory_uncertain == 0u;
}

static int seed_foreign_row(test_env_t *env)
{
    const ninlil_storage_ops_t *raw = env->proxy.raw;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_bytes_view_t storage_namespace;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    uint8_t foreign_key[20] = {'X', 'X', 'X', 'X'};
    uint8_t foreign_value = 0x5au;

    storage_namespace.data = env->proxy.sidecar_namespace;
    storage_namespace.length = sizeof(env->proxy.sidecar_namespace);
    if (raw->open(
            raw->user,
            storage_namespace,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle) != NINLIL_STORAGE_OK
        || handle == NULL) {
        return 0;
    }
    if (raw->begin(
            raw->user,
            handle,
            NINLIL_STORAGE_READ_WRITE,
            &transaction) != NINLIL_STORAGE_OK
        || transaction == NULL) {
        raw->close(raw->user, handle);
        return 0;
    }
    key.data = foreign_key;
    key.length = sizeof(foreign_key);
    value.data = &foreign_value;
    value.length = 1u;
    if (raw->put(raw->user, transaction, key, value) != NINLIL_STORAGE_OK
        || raw->commit(
               raw->user, transaction, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        (void)raw->rollback(raw->user, transaction);
        raw->close(raw->user, handle);
        return 0;
    }
    raw->close(raw->user, handle);
    return 1;
}

static int run_committed_new(void)
{
    test_env_t env;
    int ok = 0;

#define EXPECT_NEW(condition)                                                  \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr, "committed-new:%d: %s\n", __LINE__, #condition);       \
            goto done;                                                         \
        }                                                                      \
    } while (0)

    EXPECT_NEW(env_init(&env));
    EXPECT_NEW(ninlil_test_storage_fault_enqueue(
        env.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        1));
    EXPECT_NEW(enable_owner(env.runtime) == NINLIL_OK);
    EXPECT_NEW(owner_is_ready(env.runtime));
    EXPECT_NEW(env.runtime->commit_unknown_fence == 0u);
    EXPECT_NEW(ninlil_test_storage_live_handles(env.storage) == 2u);
    EXPECT_NEW(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    EXPECT_NEW(env.close_trace.bearer_close_sequence != 0u);
    EXPECT_NEW(
        env.close_trace.bearer_close_sequence
        < env.close_trace.sidecar_close_sequence);
    EXPECT_NEW(
        env.close_trace.sidecar_close_sequence
        < env.close_trace.foundation_close_sequence);
    ok = 1;

done:
    if (!env_destroy(&env)) {
        ok = 0;
    }
#undef EXPECT_NEW
    return ok ? 0 : 1;
}

static int run_uncommitted_absent(uint32_t count)
{
    test_env_t env;
    ninlil_status_t expected =
        count == 1u ? NINLIL_OK : NINLIL_E_WOULD_BLOCK;
    int ok = 0;

#define EXPECT_ABSENT(condition)                                               \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr, "absent-%u:%d: %s\n",                                 \
                (unsigned)count, __LINE__, #condition);                        \
            goto done;                                                         \
        }                                                                      \
    } while (0)

    EXPECT_ABSENT(env_init(&env));
    EXPECT_ABSENT(ninlil_test_storage_fault_enqueue(
        env.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        count,
        1,
        0));
    EXPECT_ABSENT(enable_owner(env.runtime) == expected);
    EXPECT_ABSENT(env.runtime->commit_unknown_fence == 0u);
    if (count == 1u) {
        EXPECT_ABSENT(owner_is_ready(env.runtime));
    } else {
        EXPECT_ABSENT(env.runtime->mfdt_v1_owner == NULL);
        EXPECT_ABSENT(
            ninlil_test_storage_live_handles(env.storage) == 1u);
        EXPECT_ABSENT(enable_owner(env.runtime) == NINLIL_OK);
        EXPECT_ABSENT(owner_is_ready(env.runtime));
    }
    EXPECT_ABSENT(
        ninlil_test_storage_live_transactions(env.storage) == 0u);
    EXPECT_ABSENT(
        ninlil_test_storage_live_iterators(env.storage) == 0u);
    ok = 1;

done:
    if (!env_destroy(&env)) {
        ok = 0;
    }
#undef EXPECT_ABSENT
    return ok ? 0 : 1;
}

static int run_corrupt_mutation(mutation_kind_t mutation)
{
    test_env_t env;
    int ok = 0;

#define EXPECT_MUTATION(condition)                                             \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr, "mutation-%u:%d: %s\n",                               \
                (unsigned)mutation, __LINE__, #condition);                     \
            goto done;                                                         \
        }                                                                      \
    } while (0)

    EXPECT_MUTATION(env_init(&env));
    env.proxy.mutation = mutation;
    EXPECT_MUTATION(
        enable_owner(env.runtime) == NINLIL_E_STORAGE_CORRUPT);
    EXPECT_MUTATION(env.proxy.injected_count == 1u);
    EXPECT_MUTATION(env.runtime->commit_unknown_fence == 1u);
    EXPECT_MUTATION(env.runtime->mfdt_v1_owner == NULL);
    EXPECT_MUTATION(
        ninlil_test_storage_live_handles(env.storage) == 1u);
    EXPECT_MUTATION(
        ninlil_test_storage_live_transactions(env.storage) == 0u);
    EXPECT_MUTATION(
        ninlil_test_storage_live_iterators(env.storage) == 0u);
    EXPECT_MUTATION(
        enable_owner(env.runtime) == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    ok = 1;

done:
    if (!env_destroy(&env)) {
        ok = 0;
    }
#undef EXPECT_MUTATION
    return ok ? 0 : 1;
}

static int run_foreign_row(void)
{
    test_env_t env;
    int ok = 0;

#define EXPECT_FOREIGN(condition)                                              \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr, "foreign:%d: %s\n", __LINE__, #condition);             \
            goto done;                                                         \
        }                                                                      \
    } while (0)

    EXPECT_FOREIGN(env_init(&env));
    EXPECT_FOREIGN(seed_foreign_row(&env));
    EXPECT_FOREIGN(
        enable_owner(env.runtime) == NINLIL_E_STORAGE_CORRUPT);
    EXPECT_FOREIGN(env.runtime->commit_unknown_fence == 1u);
    EXPECT_FOREIGN(env.runtime->mfdt_v1_owner == NULL);
    EXPECT_FOREIGN(
        ninlil_test_storage_live_handles(env.storage) == 1u);
    EXPECT_FOREIGN(
        enable_owner(env.runtime) == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    ok = 1;

done:
    if (!env_destroy(&env)) {
        ok = 0;
    }
#undef EXPECT_FOREIGN
    return ok ? 0 : 1;
}

int main(void)
{
    if (run_committed_new() != 0
        || run_uncommitted_absent(1u) != 0
        || run_uncommitted_absent(2u) != 0
        || run_corrupt_mutation(MUTATION_PARTIAL) != 0
        || run_corrupt_mutation(MUTATION_EXTRA) != 0
        || run_corrupt_mutation(MUTATION_THIRD) != 0
        || run_foreign_row() != 0) {
        return 1;
    }
    (void)printf("mfdt_v1_runtime_sidecar_fault_test: PASS\n");
    return 0;
}
