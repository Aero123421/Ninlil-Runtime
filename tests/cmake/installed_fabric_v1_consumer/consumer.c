/* Clean installed-package proof: Composition -> Runtime/Fabric -> Receipt. */
#include <ninlil/composition_v1.h>
#include <ninlil/fabric_v1.h>
#include <ninlil/runtime.h>

#include <openssl/evp.h>

#include "direct_packet_link.h"
#include "memory_storage.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr, "%s:%d requirement failed: %s\n",                    \
                __FILE__, __LINE__, #condition);                              \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct consumer_fixture {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    uint64_t entropy_counter;
    uint64_t permit_sequence;
    uint64_t now_ms;
    uint8_t permit_tag;
} consumer_fixture_t;

typedef struct composition_storage_router {
    ninlil_storage_ops_t ops;
    const ninlil_storage_ops_t *runtime;
    const ninlil_storage_ops_t *fabric;
    ninlil_bytes_view_t runtime_namespace;
} composition_storage_router_t;

typedef struct runtime_side {
    consumer_memory_storage_t *runtime_storage;
    consumer_memory_storage_t *fabric_storage;
    composition_storage_router_t storage_router;
    consumer_fixture_t fixture;
    void *composition_workspace;
    uint32_t composition_workspace_bytes;
    ninlil_composition_v1_t *composition;
    ninlil_fabric_v1_t *fabric;
    ninlil_fabric_link_registration_v1_t *registration;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    installed_pair_link_t link;
} runtime_side_t;

static uint32_t g_delivery_calls;
static const uint8_t g_evidence[] = "installed-public-fabric-applied";

static void set_header(uint16_t *version, uint16_t *size, size_t value_size)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value_size;
}

static int views_equal(ninlil_bytes_view_t left, ninlil_bytes_view_t right)
{
    return left.length == right.length && left.data != NULL
        && right.data != NULL
        && memcmp(left.data, right.data, left.length) == 0;
}

static ninlil_storage_status_t router_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    const ninlil_storage_ops_t *target;
    if (router == NULL || router->runtime == NULL || router->fabric == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    target = views_equal(storage_namespace, router->runtime_namespace)
        ? router->runtime : router->fabric;
    return target->open(
        target->user, storage_namespace, expected_schema, out_handle);
}

static void router_close(void *user, ninlil_storage_handle_t handle)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return;
    }
    router->runtime->close(router->runtime->user, handle);
    router->fabric->close(router->fabric->user, handle);
}

#define ROUTER_TRY_BOTH(router_, member_, ...)                                \
    do {                                                                       \
        ninlil_storage_status_t router_status_ = (router_)->runtime->member_(  \
            (router_)->runtime->user, __VA_ARGS__);                            \
        if (router_status_ == NINLIL_STORAGE_CORRUPT) {                        \
            router_status_ = (router_)->fabric->member_(                       \
                (router_)->fabric->user, __VA_ARGS__);                         \
        }                                                                      \
        return router_status_;                                                 \
    } while (0)

static ninlil_storage_status_t router_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, begin, handle, mode, out_transaction);
}

static ninlil_storage_status_t router_get(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, get, transaction, key, inout_value);
}

static ninlil_storage_status_t router_put(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, put, transaction, key, value);
}

static ninlil_storage_status_t router_erase(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, erase, transaction, key);
}

static ninlil_storage_status_t router_iter_open(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, iter_open, transaction, prefix, out_iterator);
}

static ninlil_storage_status_t router_iter_next(
    void *user,
    ninlil_storage_iter_t iterator,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, iter_next, iterator, inout_key, inout_value);
}

static void router_iter_close(void *user, ninlil_storage_iter_t iterator)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return;
    }
    router->runtime->iter_close(router->runtime->user, iterator);
    router->fabric->iter_close(router->fabric->user, iterator);
}

static ninlil_storage_status_t router_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, capacity, handle, out_capacity);
}

static ninlil_storage_status_t router_commit(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_durability_t durability)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, commit, transaction, durability);
}

static ninlil_storage_status_t router_rollback(
    void *user, ninlil_storage_txn_t transaction)
{
    composition_storage_router_t *router =
        (composition_storage_router_t *)user;
    if (router == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ROUTER_TRY_BOTH(router, rollback, transaction);
}

#undef ROUTER_TRY_BOTH

static void storage_router_init(
    composition_storage_router_t *router,
    consumer_memory_storage_t *runtime_storage,
    consumer_memory_storage_t *fabric_storage,
    ninlil_bytes_view_t runtime_namespace)
{
    (void)memset(router, 0, sizeof(*router));
    router->runtime = consumer_memory_storage_ops(runtime_storage);
    router->fabric = consumer_memory_storage_ops(fabric_storage);
    router->runtime_namespace = runtime_namespace;
    set_header(&router->ops.abi_version, &router->ops.struct_size,
               sizeof(router->ops));
    router->ops.user = router;
    router->ops.open = router_open;
    router->ops.close = router_close;
    router->ops.begin = router_begin;
    router->ops.get = router_get;
    router->ops.put = router_put;
    router->ops.erase = router_erase;
    router->ops.iter_open = router_iter_open;
    router->ops.iter_next = router_iter_next;
    router->ops.iter_close = router_iter_close;
    router->ops.capacity = router_capacity;
    router->ops.commit = router_commit;
    router->ops.rollback = router_rollback;
}

static void set_id(ninlil_id128_t *id, uint8_t seed)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int id_zero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void set_digest_pattern(ninlil_digest256_t *digest, uint8_t seed)
{
    uint32_t index;
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    for (index = 0u; index < 32u; ++index) {
        digest->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static void fill_pattern(uint8_t *bytes, uint32_t length, uint8_t seed)
{
    uint32_t index;
    for (index = 0u; index < length; ++index) {
        bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static void put_u16_be(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void put_u64_be(uint8_t out[8], uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        out[7u - index] = (uint8_t)(value >> (index * 8u));
    }
}

static int sha256_parts(
    const uint8_t *first,
    size_t first_length,
    const uint8_t *second,
    size_t second_length,
    uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int output_length = 0u;
    int ok = 0;
    if (ctx != NULL && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(ctx, first, first_length) == 1
        && (second_length == 0u
            || EVP_DigestUpdate(ctx, second, second_length) == 1)
        && EVP_DigestFinal_ex(ctx, out, &output_length) == 1
        && output_length == 32u) {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int tagged_sha256(
    const char *tag, const uint8_t *value, size_t value_length, uint8_t out[32])
{
    return sha256_parts(
        (const uint8_t *)tag, strlen(tag), value, value_length, out);
}

static int service_identity_digest(
    const ninlil_service_descriptor_t *descriptor, uint8_t out[32])
{
    uint8_t canonical[256];
    size_t offset = 0u;
    const size_t namespace_length = descriptor->namespace_id.length;
    const size_t service_length = descriptor->service_id.length;
    const size_t schema_length = descriptor->schema_id.length;

    if (namespace_length == 0u || namespace_length > 63u
        || service_length == 0u || service_length > 63u
        || schema_length == 0u || schema_length > 63u) {
        return 0;
    }
    put_u16_be(canonical + offset, (uint16_t)namespace_length);
    offset += 2u;
    (void)memcpy(
        canonical + offset, descriptor->namespace_id.data, namespace_length);
    offset += namespace_length;
    put_u16_be(canonical + offset, (uint16_t)service_length);
    offset += 2u;
    (void)memcpy(
        canonical + offset, descriptor->service_id.data, service_length);
    offset += service_length;
    put_u16_be(canonical + offset, (uint16_t)schema_length);
    offset += 2u;
    (void)memcpy(
        canonical + offset, descriptor->schema_id.data, schema_length);
    offset += schema_length;
    put_u64_be(canonical + offset, descriptor->descriptor_revision);
    offset += 8u;
    put_u16_be(canonical + offset, NINLIL_DIGEST_SHA256);
    offset += 2u;
    (void)memcpy(
        canonical + offset, descriptor->descriptor_digest.bytes, 32u);
    offset += 32u;
    put_u16_be(canonical + offset, descriptor->schema_major);
    offset += 2u;
    put_u16_be(canonical + offset, descriptor->schema_minor_min);
    offset += 2u;
    put_u32_be(canonical + offset, descriptor->family);
    offset += 4u;
    return tagged_sha256(
        "NINLIL-FABRIC-SERVICE-IDENTITY-V1", canonical, offset, out);
}

static int power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static void *fixture_allocate(void *user, uint64_t size, uint32_t alignment)
{
    (void)user;
    if (size == 0u || size > (uint64_t)SIZE_MAX || !power_of_two(alignment)
        || alignment > (uint32_t)_Alignof(max_align_t)) {
        return NULL;
    }
    return malloc((size_t)size);
}

static void fixture_deallocate(
    void *user, void *pointer, uint64_t size, uint32_t alignment)
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
    void *user, ninlil_time_sample_t *out_sample)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;
    if (fixture == NULL || out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    (void)memset(out_sample, 0, sizeof(*out_sample));
    set_header(
        &out_sample->abi_version, &out_sample->struct_size, sizeof(*out_sample));
    set_id(&out_sample->clock_epoch_id, 0xA0u);
    out_sample->now_ms = fixture->now_ms;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static ninlil_port_status_t fixture_entropy(
    void *user, uint8_t *out, uint32_t length)
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

static ninlil_tx_gate_status_t fixture_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;
    uint32_t index;
    if (fixture == NULL || request == NULL || now == NULL
        || out_permit == NULL || id_zero(&request->attempt_id)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || id_zero(&now->clock_epoch_id)
        || fixture->permit_sequence == UINT64_MAX
        || UINT64_MAX - now->now_ms < 60000u) {
        return NINLIL_TX_GATE_DENIED;
    }
    fixture->permit_sequence += 1u;
    (void)memset(out_permit, 0, sizeof(*out_permit));
    set_header(
        &out_permit->abi_version,
        &out_permit->struct_size,
        sizeof(*out_permit));
    for (index = 0u; index < 8u; ++index) {
        out_permit->permit_id.bytes[index] =
            (uint8_t)(fixture->permit_tag + (uint8_t)index);
    }
    put_u64_be(
        out_permit->permit_id.bytes + 8u, fixture->permit_sequence);
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms = now->now_ms + 60000u;
    return NINLIL_TX_GATE_OK;
}

static void fixture_tx_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t fixture_origin(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    (void)user;
    if (request == NULL || out_decision == NULL
        || request->now.trust != NINLIL_CLOCK_TRUSTED
        || UINT64_MAX - request->now.now_ms < 600000u) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    (void)memset(out_decision, 0, sizeof(*out_decision));
    set_header(
        &out_decision->abi_version,
        &out_decision->struct_size,
        sizeof(*out_decision));
    out_decision->allowed = 1u;
    out_decision->reason = NINLIL_REASON_NONE;
    out_decision->retry_guidance = NINLIL_RETRY_NEVER;
    set_id(&out_decision->provider_id, 0xD0u);
    out_decision->provider_revision = 1u;
    set_digest_pattern(&out_decision->decision_digest, 0xD1u);
    set_id(&out_decision->grant_id, 0xE0u);
    out_decision->grant_revision = 1u;
    out_decision->clock_epoch_id = request->now.clock_epoch_id;
    out_decision->evaluated_at_ms = request->now.now_ms;
    out_decision->expires_at_ms = request->now.now_ms + 600000u;
    out_decision->max_payload_bytes = 1024u;
    out_decision->max_active_spool_count = 32u;
    out_decision->max_active_spool_bytes = 32768u;
    out_decision->rate_window_ms = 10000u;
    out_decision->max_admissions_per_window = 20u;
    out_decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static void fixture_init(
    consumer_fixture_t *fixture,
    const ninlil_storage_ops_t *storage,
    uint8_t permit_tag)
{
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->now_ms = 1000u;
    fixture->permit_tag = permit_tag;

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
    fixture->clock.user = fixture;
    fixture->clock.now = fixture_now;
    set_header(
        &fixture->entropy.abi_version,
        &fixture->entropy.struct_size,
        sizeof(fixture->entropy));
    fixture->entropy.user = fixture;
    fixture->entropy.fill = fixture_entropy;
    set_header(
        &fixture->tx_gate.abi_version,
        &fixture->tx_gate.struct_size,
        sizeof(fixture->tx_gate));
    fixture->tx_gate.user = fixture;
    fixture->tx_gate.acquire = fixture_tx_acquire;
    fixture->tx_gate.release_unused = fixture_tx_release_unused;
    set_header(
        &fixture->origin.abi_version,
        &fixture->origin.struct_size,
        sizeof(fixture->origin));
    fixture->origin.evaluate = fixture_origin;
    set_header(
        &fixture->platform.abi_version,
        &fixture->platform.struct_size,
        sizeof(fixture->platform));
    fixture->platform.allocator = &fixture->allocator;
    fixture->platform.execution = &fixture->execution;
    fixture->platform.clock = &fixture->clock;
    fixture->platform.entropy = &fixture->entropy;
    fixture->platform.storage = storage;
    fixture->platform.tx_gate = &fixture->tx_gate;
    fixture->platform.origin_authorization = &fixture->origin;
}

static ninlil_runtime_config_t runtime_config(
    ninlil_role_t role,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    uint8_t runtime_seed)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_seed);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_seed + 0x10u));
    set_id(
        &config.local_identity.installation_id,
        (uint8_t)(runtime_seed + 0x20u));
    set_id(
        &config.local_identity.site_domain_id,
        (uint8_t)(runtime_seed + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_namespace;
    config.storage_namespace.length = storage_namespace_length;
    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions =
        role == NINLIL_ROLE_ENDPOINT ? 32u : 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes =
        role == NINLIL_ROLE_CONTROLLER ? 32768u : 0u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 32u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_event_spool_count =
        role == NINLIL_ROLE_ENDPOINT ? 32u : 0u;
    config.limits.max_event_spool_bytes =
        role == NINLIL_ROLE_ENDPOINT ? 32768u : 0u;
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

static ninlil_service_descriptor_t service_descriptor(uint8_t app_seed)
{
    static const uint8_t namespace_id[] = "org.ninlil.fabric.installed";
    static const uint8_t service_id[] = "verified-state";
    static const uint8_t schema_id[] = "verified-state-v1";
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
    set_digest_pattern(&descriptor.descriptor_digest, 0x41u);
    set_id(&descriptor.local_application_instance_id, app_seed);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
    descriptor.logical_payload_limit = 1024u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = 8u;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 60000u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 5000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 60000u;
    return descriptor;
}

static void fill_link_descriptor(
    ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_id128_t *peer_runtime_id,
    const ninlil_time_sample_t *now)
{
    (void)memset(descriptor, 0, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    set_id(&descriptor->instance_id, 0x61u);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_LOOPBACK;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_CUSTODY | NINLIL_FABRIC_CAP_EVIDENCE;
    descriptor->descriptor_revision = 1u;
    fill_pattern(descriptor->descriptor_digest, 32u, 0x11u);
    set_id(&descriptor->security_profile_id, 0x30u);
    descriptor->security_capability_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    fill_pattern(descriptor->security_binding_digest, 32u, 0x21u);
    descriptor->attestation_epoch = 1u;
    descriptor->attestation_clock_epoch_id = now->clock_epoch_id;
    descriptor->attestation_expires_at_ms = now->now_ms + 600000u;
    fill_pattern(descriptor->attestation_digest, 32u, 0x31u);
    descriptor->authenticated_peer_runtime_id = *peer_runtime_id;
    set_id(&descriptor->attachment_authority_id, 0x50u);
    fill_pattern(descriptor->attachment_binding_digest, 32u, 0x41u);
    descriptor->maximum_packet_bytes = INSTALLED_PAIR_PACKET_MAX;
    descriptor->maximum_transfer_bytes = INSTALLED_PAIR_PACKET_MAX;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->reservation_capacity = 8u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    fill_pattern(descriptor->configuration_digest, 32u, 0x51u);
}

static int install_forward_policy(
    runtime_side_t *side,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *endpoint_runtime_id,
    const ninlil_id128_t *endpoint_application_id,
    const ninlil_time_sample_t *now)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t snapshot;
    ninlil_fabric_authority_binding_v1_t binding;
    uint8_t service_digest[32];

    if (!service_identity_digest(descriptor, service_digest)) {
        return 0;
    }
    (void)memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    set_id(&policy.policy_id, 0x71u);
    policy.revision = 1u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = descriptor->family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_CUSTODY
        | NINLIL_FABRIC_CAP_EVIDENCE;
    policy.required_security_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.maximum_latency_class = 10u;
    policy.maximum_cost_class = 10u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.candidate_count = 1u;
    set_id(&policy.candidates[0].instance_id, 0x61u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    if (ninlil_fabric_v1_policy_put(side->fabric, &policy)
        != NINLIL_FABRIC_OK) {
        return 0;
    }
    (void)memset(&snapshot, 0, sizeof(snapshot));
    if (ninlil_fabric_v1_policy_snapshot(
            side->fabric, &policy.policy_id, policy.revision, &snapshot)
        != NINLIL_FABRIC_OK) {
        return 0;
    }

    (void)memset(&binding, 0, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    set_id(&binding.binding_id, 0x81u);
    (void)memcpy(binding.service_identity_digest, service_digest, 32u);
    binding.family = descriptor->family;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    binding.endpoint_runtime_id = *endpoint_runtime_id;
    binding.target_runtime_id = *endpoint_runtime_id;
    binding.target_application_id = *endpoint_application_id;
    binding.policy_id = policy.policy_id;
    binding.policy_revision = policy.revision;
    (void)memcpy(
        binding.policy_digest,
        snapshot.canonical_digest_zero_on_input,
        32u);
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    set_id(&binding.authority_id, 0x91u);
    binding.authority_term = 1u;
    binding.assignment_epoch = 1u;
    set_id(&binding.owner_scope_id, 0xA1u);
    fill_pattern(binding.owner_tuple_canonical, 200u, 0xB1u);
    (void)memcpy(
        binding.owner_tuple_canonical, endpoint_runtime_id->bytes, 16u);
    (void)memcpy(
        binding.owner_tuple_canonical + 16u,
        endpoint_application_id->bytes,
        16u);
    if (!tagged_sha256(
            "NINLIL-FABRIC-OWNER-TUPLE-V1",
            binding.owner_tuple_canonical,
            200u,
            binding.owner_tuple_digest)) {
        return 0;
    }
    binding.authority_clock_epoch_id = now->clock_epoch_id;
    binding.lease_expires_at_ms = now->now_ms + 600000u;
    binding.assignment_revision = 1u;
    return ninlil_fabric_v1_authority_put(side->fabric, &binding)
        == NINLIL_FABRIC_OK;
}

static int side_init(
    runtime_side_t *side,
    const ninlil_runtime_config_t *runtime_config_value,
    const ninlil_id128_t *peer_runtime_id,
    uint8_t permit_tag)
{
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_time_sample_t now;
    uint32_t bytes = 0u;
    uint32_t alignment = 0u;

    (void)memset(side, 0, sizeof(*side));
    side->runtime_storage = consumer_memory_storage_create();
    side->fabric_storage = consumer_memory_storage_create();
    if (side->runtime_storage == NULL || side->fabric_storage == NULL
        || runtime_config_value == NULL) {
        return 0;
    }
    storage_router_init(
        &side->storage_router,
        side->runtime_storage,
        side->fabric_storage,
        runtime_config_value->storage_namespace);
    fixture_init(
        &side->fixture,
        &side->storage_router.ops,
        permit_tag);
    installed_pair_link_init(&side->link, &side->fixture.clock);

    if (ninlil_composition_v1_workspace_required(
            NINLIL_COMPOSITION_PROFILE_1, &bytes, &alignment)
            != NINLIL_OK
        || bytes == 0u || alignment == 0u
        || alignment > _Alignof(max_align_t)) {
        return 0;
    }
    side->composition_workspace = malloc(bytes);
    side->composition_workspace_bytes = bytes;
    if (side->composition_workspace == NULL
        || (uintptr_t)side->composition_workspace % alignment != 0u) {
        return 0;
    }
    if (ninlil_composition_v1_create(
            NINLIL_COMPOSITION_PROFILE_1,
            runtime_config_value,
            &side->fixture.platform,
            side->composition_workspace,
            side->composition_workspace_bytes,
            &side->composition)
            != NINLIL_OK
        || ninlil_composition_v1_runtime(side->composition, &side->runtime)
            != NINLIL_OK
        || ninlil_composition_v1_fabric(side->composition, &side->fabric)
            != NINLIL_OK) {
        return 0;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (side->fixture.clock.now(side->fixture.clock.user, &now)
        != NINLIL_PORT_OK) {
        return 0;
    }
    fill_link_descriptor(&descriptor, peer_runtime_id, &now);
    installed_pair_link_ops(&side->link, &link_ops);
    if (ninlil_fabric_v1_register_link(
            side->fabric, &descriptor, &link_ops, &side->registration)
        != NINLIL_FABRIC_OK) {
        return 0;
    }
    return 1;
}

static int side_close(runtime_side_t *side)
{
    uint32_t done = 0u;
    uint32_t work = 0u;
    uint32_t spins;
    int ok = 1;

    if (side->registration != NULL && side->fabric != NULL) {
        if (ninlil_fabric_v1_unregister_begin(
                side->fabric, side->registration)
            != NINLIL_FABRIC_OK) {
            ok = 0;
        }
        for (spins = 0u; spins < 128u && done == 0u; ++spins) {
            (void)ninlil_fabric_v1_step(side->fabric, 64u, &work);
            if (ninlil_fabric_v1_unregister_poll(
                    side->fabric, side->registration, &done)
                != NINLIL_FABRIC_OK) {
                ok = 0;
                break;
            }
        }
        if (done == 0u) {
            ok = 0;
        }
        side->registration = NULL;
    }
    done = 0u;
    if (side->composition != NULL) {
        if (ninlil_composition_v1_close_begin(side->composition) != NINLIL_OK) {
            ok = 0;
        }
        for (spins = 0u; spins < 128u && done == 0u; ++spins) {
            if (ninlil_composition_v1_close_poll(
                    side->composition, 64u, &done)
                != NINLIL_OK) {
                ok = 0;
                break;
            }
        }
        if (done == 0u
            || ninlil_composition_v1_destroy(side->composition) != NINLIL_OK) {
            ok = 0;
        }
        side->composition = NULL;
        side->runtime = NULL;
        side->fabric = NULL;
    }
    free(side->composition_workspace);
    side->composition_workspace = NULL;
    side->composition_workspace_bytes = 0u;
    if (side->runtime_storage != NULL) {
        if (consumer_memory_storage_live_handles(side->runtime_storage) != 0u
            || consumer_memory_storage_live_transactions(side->runtime_storage)
                != 0u
            || consumer_memory_storage_live_iterators(side->runtime_storage)
                != 0u) {
            ok = 0;
        }
        consumer_memory_storage_destroy(side->runtime_storage);
        side->runtime_storage = NULL;
    }
    if (side->fabric_storage != NULL) {
        if (consumer_memory_storage_live_handles(side->fabric_storage) != 0u
            || consumer_memory_storage_live_transactions(side->fabric_storage)
                != 0u
            || consumer_memory_storage_live_iterators(side->fabric_storage)
                != 0u) {
            ok = 0;
        }
        consumer_memory_storage_destroy(side->fabric_storage);
        side->fabric_storage = NULL;
    }
    return ok;
}

static ninlil_callback_action_t endpoint_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    (void)token;
    if (delivery == NULL || out_result == NULL || delivery->payload.data == NULL
        || delivery->payload.length != 16u) {
        return NINLIL_CALLBACK_DEFER;
    }
    g_delivery_calls += 1u;
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    out_result->evidence.data = g_evidence;
    out_result->evidence.length = sizeof(g_evidence) - 1u;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t endpoint_reconcile(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static int query_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *out_snapshot,
    ninlil_target_snapshot_t *out_target)
{
    (void)memset(out_target, 0, sizeof(*out_target));
    set_header(
        &out_target->abi_version, &out_target->struct_size, sizeof(*out_target));
    (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    set_header(
        &out_snapshot->abi_version,
        &out_snapshot->struct_size,
        sizeof(*out_snapshot));
    out_snapshot->targets = out_target;
    out_snapshot->target_capacity = 1u;
    return ninlil_transaction_query(runtime, transaction_id, out_snapshot)
        == NINLIL_OK;
}

static int run_installed_pair(void)
{
    static const uint8_t controller_namespace[] = "installed-fabric-controller";
    static const uint8_t endpoint_namespace[] = "installed-fabric-endpoint";
    static const uint8_t idempotency_key[] = "installed-fabric-idempotency";
    static const uint8_t payload[16] = {
        0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
        0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu
    };
    runtime_side_t controller;
    runtime_side_t endpoint;
    ninlil_id128_t controller_runtime_id;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_id128_t endpoint_app_id;
    ninlil_runtime_config_t controller_config;
    ninlil_runtime_config_t endpoint_config;
    ninlil_service_descriptor_t controller_descriptor;
    ninlil_service_descriptor_t endpoint_descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_time_sample_t controller_now;
    ninlil_time_sample_t endpoint_now;
    ninlil_submission_t submission;
    ninlil_submission_result_t submission_result;
    ninlil_concrete_target_t target;
    ninlil_step_budget_t budget;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target_snapshot;
    uint32_t step;
    int satisfied = 0;

    set_id(&controller_runtime_id, 0x10u);
    set_id(&endpoint_runtime_id, 0x21u);
    set_id(&endpoint_app_id, 0x81u);
    controller_config = runtime_config(
        NINLIL_ROLE_CONTROLLER,
        controller_namespace,
        sizeof(controller_namespace) - 1u,
        0x10u);
    endpoint_config = runtime_config(
        NINLIL_ROLE_ENDPOINT,
        endpoint_namespace,
        sizeof(endpoint_namespace) - 1u,
        0x21u);
    REQUIRE(side_init(
        &controller, &controller_config, &endpoint_runtime_id, 0x31u));
    REQUIRE(side_init(
        &endpoint, &endpoint_config, &controller_runtime_id, 0x51u));
    installed_pair_link_connect(&controller.link, &endpoint.link);

    (void)memset(&controller_now, 0, sizeof(controller_now));
    set_header(
        &controller_now.abi_version,
        &controller_now.struct_size,
        sizeof(controller_now));
    REQUIRE(controller.fixture.clock.now(
                controller.fixture.clock.user, &controller_now)
        == NINLIL_PORT_OK);
    (void)memset(&endpoint_now, 0, sizeof(endpoint_now));
    set_header(
        &endpoint_now.abi_version,
        &endpoint_now.struct_size,
        sizeof(endpoint_now));
    REQUIRE(endpoint.fixture.clock.now(endpoint.fixture.clock.user, &endpoint_now)
        == NINLIL_PORT_OK);

    controller_descriptor = service_descriptor(0x70u);
    endpoint_descriptor = service_descriptor(0x81u);
    REQUIRE(install_forward_policy(
        &controller,
        &controller_descriptor,
        &endpoint_runtime_id,
        &endpoint_app_id,
        &controller_now));
    REQUIRE(install_forward_policy(
        &endpoint,
        &endpoint_descriptor,
        &endpoint_runtime_id,
        &endpoint_app_id,
        &endpoint_now));

    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                controller.runtime,
                &controller_descriptor,
                &callbacks,
                &controller.service)
        == NINLIL_OK);
    callbacks.on_delivery = endpoint_delivery;
    callbacks.on_reconcile = endpoint_reconcile;
    REQUIRE(ninlil_service_register(
                endpoint.runtime,
                &endpoint_descriptor,
                &callbacks,
                &endpoint.service)
        == NINLIL_OK);

    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    target.target_runtime_id = endpoint_runtime_id;
    target.target_application_instance_id = endpoint_app_id;
    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version, &submission.struct_size, sizeof(submission));
    submission.targets = &target;
    submission.target_count = 1u;
    submission.schema_major = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    submission.effect_deadline_ms = 60000u;
    submission.evidence_grace_ms = 5000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = sizeof(idempotency_key) - 1u;
    submission.payload.data = payload;
    submission.payload.length = sizeof(payload);
    submission.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    REQUIRE(sha256_parts(payload, sizeof(payload), NULL, 0u,
                         submission.content_digest.bytes));
    (void)memset(&submission_result, 0, sizeof(submission_result));
    set_header(
        &submission_result.abi_version,
        &submission_result.struct_size,
        sizeof(submission_result));
    REQUIRE(ninlil_submit(controller.service, &submission, &submission_result)
        == NINLIL_OK);
    REQUIRE(submission_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 8u;
    budget.max_callbacks = 8u;
    budget.max_state_transitions = 16u;
    budget.max_bearer_sends = 8u;
    for (step = 0u; step < 512u; ++step) {
        ninlil_composition_step_budget_v1_t composition_budget;
        ninlil_composition_step_result_v1_t composition_result;
        (void)memset(&composition_budget, 0, sizeof(composition_budget));
        composition_budget.api_version = NINLIL_COMPOSITION_API_VERSION;
        composition_budget.struct_size =
            (uint16_t)sizeof(composition_budget);
        composition_budget.runtime = budget;
        composition_budget.fabric_work = 64u;
        (void)memset(&composition_result, 0, sizeof(composition_result));
        composition_result.api_version = NINLIL_COMPOSITION_API_VERSION;
        composition_result.struct_size =
            (uint16_t)sizeof(composition_result);
        REQUIRE(ninlil_composition_v1_step(
                    controller.composition,
                    &composition_budget,
                    &composition_result)
            == NINLIL_OK);
        (void)memset(&composition_result, 0, sizeof(composition_result));
        composition_result.api_version = NINLIL_COMPOSITION_API_VERSION;
        composition_result.struct_size =
            (uint16_t)sizeof(composition_result);
        REQUIRE(ninlil_composition_v1_step(
                    endpoint.composition,
                    &composition_budget,
                    &composition_result)
            == NINLIL_OK);
        REQUIRE(query_transaction(
            controller.runtime,
            &submission_result.transaction_id,
            &snapshot,
            &target_snapshot));
        if (snapshot.state == NINLIL_TXN_TERMINAL
            && snapshot.outcome == NINLIL_OUTCOME_SATISFIED
            && target_snapshot.latest_evidence >= NINLIL_EVIDENCE_VERIFIED) {
            satisfied = 1;
            break;
        }
    }
    REQUIRE(satisfied != 0);
    REQUIRE(g_delivery_calls == 1u);
    REQUIRE(controller.link.start_calls >= 1u);
    REQUIRE(endpoint.link.start_calls >= 1u);
    REQUIRE(controller.link.accepted_packets >= 1u);
    REQUIRE(endpoint.link.accepted_packets >= 1u);
    REQUIRE(side_close(&endpoint));
    REQUIRE(side_close(&controller));
    return 0;
}

int main(void)
{
    const int result = run_installed_pair();
    if (result == 0) {
        (void)printf("installed_fabric_v1_consumer: PASS\n");
    }
    return result;
}
