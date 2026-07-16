/*
 * D2-S6 private Stage 5 fail-closed seam integration matrix.
 * Claims: private fail-closed seam implemented; Stage 5 incomplete.
 * Does not claim D3/D4/identity/health/public runtime/Bearer/Stage9/ESP.
 *
 * Host tests may place stage5 workspaces on the test stack for convenience.
 * Production contract remains: Runtime arena allocation only (never task stack).
 * Seam production functions do not declare workspace automatic locals (gate).
 */

#include "runtime_store_stage5_seam.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_store_bootstrap.h"

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

static const uint8_t TEST_NAMESPACE[] = "runtime-store-stage5-seam";

/* Distinctive non-default limits so candidate binding bytes are non-trivial. */
static const uint32_t DISTINCT_MAX_SERVICES = 11u;
static const uint32_t DISTINCT_MAX_NONTERMINAL = 27u;
static const uint32_t DISTINCT_MAX_DEFERRED = 19u;
static const uint64_t DISTINCT_TERMINAL_RETENTION_MS = 4242u;

typedef struct hook_spy {
    uint32_t count;
    const char *names[4];
} hook_spy_t;

typedef struct test_context {
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_allocator_t *allocator_fixture;
    const ninlil_storage_ops_t *storage;
    ninlil_storage_handle_t handle;
    ninlil_model_runtime_validation_result_t validation;
    /*
     * Host stack placement for tests only. Production: Runtime arena.
     */
    ninlil_runtime_store_stage5_workspace_t workspace;
    ninlil_runtime_store_stage5_result_t result;
    hook_spy_t hook_spy;
    ninlil_runtime_store_hook_dispatcher_t hooks;
} test_context_t;

/* ---- test storage proxy (no production hooks) ---- */

typedef struct stage5_proxy {
    const ninlil_storage_ops_t *base;
    ninlil_storage_ops_t ops;
    uint32_t begin_ro_count;
    uint32_t get_count;
    uint32_t iter_next_count;
    uint32_t finalize_close_proxy; /* unused; reserved */
    /* Mutate under second READ_ONLY begin (L2b1→scanner race). */
    int mutate_on_second_ro_begin;
    ninlil_test_storage_t *fixture_for_mutate;
    const uint8_t *mutate_key;
    uint32_t mutate_key_len;
    const uint8_t *mutate_value;
    uint32_t mutate_value_len;
    /* Fault injection on N-th get/iter_next after arming (1-based). */
    uint32_t arm_get_fault_on;
    ninlil_storage_status_t get_fault_status;
    uint32_t arm_iter_next_fault_on;
    ninlil_storage_status_t iter_next_fault_status;
    uint32_t arm_rollback_fault_on;
    ninlil_storage_status_t rollback_fault_status;
    uint32_t rollback_count;
    /*
     * INVARIANT-ONLY test hook (test code only; not a production hook):
     * On the N-th rollback (1-based), after base rollback returns OK, set
     * session_for_reopen_mutate->reopen_required = 1 so scanner finalize can
     * return OK with adopted=0 without weakening production contracts.
     */
    uint32_t arm_reopen_mutate_on_rollback;
    ninlil_domain_scan_session_t *session_for_reopen_mutate;
} stage5_proxy_t;

static stage5_proxy_t g_proxy;

static ninlil_storage_status_t proxy_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    if (mode == NINLIL_STORAGE_READ_ONLY) {
        g_proxy.begin_ro_count += 1u;
        if (g_proxy.mutate_on_second_ro_begin != 0
            && g_proxy.begin_ro_count == 2u
            && g_proxy.fixture_for_mutate != NULL
            && g_proxy.mutate_key != NULL) {
            /*
             * Between L2b1 snapshot close and scanner second begin: inject
             * a domain/future/corrupt row into committed storage.
             */
            ninlil_storage_txn_t wtxn = NULL;
            ninlil_bytes_view_t key;
            ninlil_bytes_view_t value;
            const ninlil_storage_ops_t *base = g_proxy.base;
            if (base->begin(user, handle, NINLIL_STORAGE_READ_WRITE, &wtxn)
                    == NINLIL_STORAGE_OK) {
                key.data = g_proxy.mutate_key;
                key.length = g_proxy.mutate_key_len;
                value.data = g_proxy.mutate_value;
                value.length = g_proxy.mutate_value_len;
                (void)base->put(user, wtxn, key, value);
                (void)base->commit(user, wtxn, NINLIL_DURABILITY_FULL);
            }
        }
    }
    return g_proxy.base->begin(user, handle, mode, out_txn);
}

static ninlil_storage_status_t proxy_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    g_proxy.get_count += 1u;
    if (g_proxy.arm_get_fault_on != 0u
        && g_proxy.get_count == g_proxy.arm_get_fault_on) {
        if (inout_value != NULL) {
            inout_value->length = 0u;
        }
        return g_proxy.get_fault_status;
    }
    return g_proxy.base->get(user, txn, key, inout_value);
}

static ninlil_storage_status_t proxy_iter_next(
    void *user,
    ninlil_storage_iter_t iterator,
    ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    g_proxy.iter_next_count += 1u;
    if (g_proxy.arm_iter_next_fault_on != 0u
        && g_proxy.iter_next_count == g_proxy.arm_iter_next_fault_on) {
        if (key != NULL) {
            key->length = 0u;
        }
        if (value != NULL) {
            value->length = 0u;
        }
        return g_proxy.iter_next_fault_status;
    }
    return g_proxy.base->iter_next(user, iterator, key, value);
}

static ninlil_storage_status_t proxy_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    ninlil_storage_status_t status;

    g_proxy.rollback_count += 1u;
    if (g_proxy.arm_rollback_fault_on != 0u
        && g_proxy.rollback_count == g_proxy.arm_rollback_fault_on) {
        /* Still perform base rollback so resources free, then surface fault. */
        (void)g_proxy.base->rollback(user, txn);
        return g_proxy.rollback_fault_status;
    }
    status = g_proxy.base->rollback(user, txn);
    /*
     * INVARIANT-ONLY: after a successful base rollback on the armed count,
     * force session.reopen_required so finalize yields OK + adopted=0.
     * Production scanner contracts are unchanged; this is test-proxy only.
     */
    if (status == NINLIL_STORAGE_OK
        && g_proxy.arm_reopen_mutate_on_rollback != 0u
        && g_proxy.rollback_count == g_proxy.arm_reopen_mutate_on_rollback
        && g_proxy.session_for_reopen_mutate != NULL) {
        g_proxy.session_for_reopen_mutate->reopen_required = 1u;
    }
    return status;
}

static void proxy_reset(const ninlil_storage_ops_t *base)
{
    (void)memset(&g_proxy, 0, sizeof(g_proxy));
    g_proxy.base = base;
    g_proxy.ops = *base;
    g_proxy.ops.begin = proxy_begin;
    g_proxy.ops.get = proxy_get;
    g_proxy.ops.iter_next = proxy_iter_next;
    g_proxy.ops.rollback = proxy_rollback;
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static ninlil_runtime_config_t config_fixture(void)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
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
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = DISTINCT_MAX_SERVICES;
    config.limits.max_nonterminal_transactions = DISTINCT_MAX_NONTERMINAL;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    config.limits.max_nonterminal_deliveries = 12u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 17u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = DISTINCT_MAX_DEFERRED;
    config.terminal_retention_ms = DISTINCT_TERMINAL_RETENTION_MS;
    config.result_cache_retention_ms = 900u;
    config.observation_retention_ms = 800u;
    return config;
}

static ninlil_model_runtime_validation_result_t validation_fixture(
    const ninlil_runtime_config_t *config)
{
    ninlil_model_runtime_validation_result_t validation;
    (void)memset(&validation, 0, sizeof(validation));
    validation.status = NINLIL_OK;
    validation.failure_field = NINLIL_MODEL_RUNTIME_VALIDATION_NONE;
    (void)ninlil_model_runtime_derive_capacity_limits(
        &config->limits, &validation.capacity_limits);
    validation.accepted_config.role = config->role;
    validation.accepted_config.environment = config->environment;
    validation.accepted_config.runtime_id = config->runtime_id;
    validation.accepted_config.identity_flags = config->local_identity.flags;
    validation.accepted_config.device_id = config->local_identity.device_id;
    validation.accepted_config.installation_id =
        config->local_identity.installation_id;
    validation.accepted_config.site_domain_id =
        config->local_identity.site_domain_id;
    validation.accepted_config.binding_epoch =
        config->local_identity.binding_epoch;
    validation.accepted_config.membership_epoch =
        config->local_identity.membership_epoch;
#define COPY_LIMIT(field) \
    validation.accepted_config.limits.field = config->limits.field
    COPY_LIMIT(max_services);
    COPY_LIMIT(max_nonterminal_transactions);
    COPY_LIMIT(max_targets_per_transaction);
    COPY_LIMIT(max_logical_payload_bytes);
    COPY_LIMIT(max_durable_outbox_payload_bytes);
    COPY_LIMIT(max_attempts_per_target_per_cycle);
    COPY_LIMIT(max_cancel_attempts_per_transaction);
    COPY_LIMIT(max_evidence_per_target);
    COPY_LIMIT(max_retained_terminal_transactions);
    COPY_LIMIT(max_nonterminal_deliveries);
    COPY_LIMIT(max_event_spool_count);
    COPY_LIMIT(max_event_spool_bytes);
    COPY_LIMIT(max_result_cache_entries);
    COPY_LIMIT(max_retained_dispositions);
    COPY_LIMIT(max_ingress_per_step);
    COPY_LIMIT(max_callbacks_per_step);
    COPY_LIMIT(max_state_transitions_per_step);
    COPY_LIMIT(max_bearer_sends_per_step);
    COPY_LIMIT(max_deferred_tokens);
#undef COPY_LIMIT
    validation.accepted_config.terminal_retention_ms =
        config->terminal_retention_ms;
    validation.accepted_config.result_cache_retention_ms =
        config->result_cache_retention_ms;
    validation.accepted_config.observation_retention_ms =
        config->observation_retention_ms;
    return validation;
}

static void hook_dispatch(void *user, const char *name)
{
    hook_spy_t *spy = (hook_spy_t *)user;
    if (spy->count < 4u) {
        spy->names[spy->count] = name;
    }
    spy->count += 1u;
}

static int context_init(test_context_t *context)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_runtime_config_t config = config_fixture();
    ninlil_bytes_view_t storage_namespace;

    (void)memset(context, 0, sizeof(*context));
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 2u;
    storage_config.max_entries_per_namespace = 64u;
    storage_config.max_bytes_per_namespace = 200000u;
    context->storage_fixture = ninlil_test_storage_create(&storage_config);
    context->allocator_fixture = ninlil_test_allocator_create();
    if (context->storage_fixture == NULL
        || context->allocator_fixture == NULL) {
        return 0;
    }
    context->storage = ninlil_test_storage_ops(context->storage_fixture);
    context->validation = validation_fixture(&config);
    context->hooks.user = &context->hook_spy;
    context->hooks.dispatch = hook_dispatch;
    storage_namespace.data = TEST_NAMESPACE;
    storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    return context->storage->open(context->storage->user,
        storage_namespace, NINLIL_STORAGE_SCHEMA_M1A,
        &context->handle) == NINLIL_STORAGE_OK;
}

static int reopen(test_context_t *context)
{
    ninlil_bytes_view_t storage_namespace;
    storage_namespace.data = TEST_NAMESPACE;
    storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    context->handle = NULL;
    return context->storage->open(context->storage->user,
        storage_namespace, NINLIL_STORAGE_SCHEMA_M1A,
        &context->handle) == NINLIL_STORAGE_OK;
}

static int context_destroy(test_context_t *context)
{
    int clean;
    if (context->handle != NULL) {
        context->storage->close(context->storage->user, context->handle);
        context->handle = NULL;
    }
    clean = ninlil_test_storage_live_handles(context->storage_fixture) == 0u
        && ninlil_test_storage_live_transactions(context->storage_fixture)
            == 0u
        && ninlil_test_storage_live_iterators(context->storage_fixture) == 0u
        && ninlil_test_allocator_destroy(context->allocator_fixture) == 0u;
    ninlil_test_storage_destroy(context->storage_fixture);
    return clean;
}

static ninlil_status_t run(test_context_t *context)
{
    return ninlil_runtime_store_stage5_private_hookup(
        context->storage, &context->handle,
        &context->validation, &context->hooks, &context->workspace,
        &context->result);
}

static ninlil_status_t run_with_ops(
    test_context_t *context,
    const ninlil_storage_ops_t *ops)
{
    return ninlil_runtime_store_stage5_private_hookup(
        ops, &context->handle,
        &context->validation, &context->hooks, &context->workspace,
        &context->result);
}

static int raw_put(
    test_context_t *context,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_storage_txn_t transaction = NULL;
    return context->storage->begin(context->storage->user, context->handle,
            NINLIL_STORAGE_READ_WRITE, &transaction) == NINLIL_STORAGE_OK
        && context->storage->put(context->storage->user,
            transaction, key, value) == NINLIL_STORAGE_OK
        && context->storage->commit(context->storage->user,
            transaction, NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_OK;
}

static int seed_partial_bootstrap(test_context_t *context)
{
    ninlil_model_runtime_store_bootstrap_plan_t plan;
    ninlil_model_runtime_store_bootstrap_record_t record;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    (void)memset(&plan, 0, sizeof(plan));
    (void)memset(&record, 0, sizeof(record));
    if (ninlil_model_runtime_store_build_bootstrap_plan(
            &context->validation, &plan) != NINLIL_OK
        || ninlil_model_runtime_store_bootstrap_record_at(
            &plan, 0u, &record) != NINLIL_OK) {
        return 0;
    }
    key.data = record.key.bytes;
    key.length = record.key.length;
    value.data = record.value;
    value.length = record.value_length;
    return raw_put(context, key, value);
}

static int seed_bootstrap_without(
    test_context_t *context,
    uint32_t missing_index)
{
    ninlil_model_runtime_store_bootstrap_plan_t plan;
    ninlil_storage_txn_t transaction = NULL;
    uint32_t index;
    (void)memset(&plan, 0, sizeof(plan));
    if (ninlil_model_runtime_store_build_bootstrap_plan(
            &context->validation, &plan) != NINLIL_OK
        || context->storage->begin(context->storage->user, context->handle,
            NINLIL_STORAGE_READ_WRITE, &transaction) != NINLIL_STORAGE_OK) {
        return 0;
    }
    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_model_runtime_store_bootstrap_record_t record;
        ninlil_bytes_view_t key;
        ninlil_bytes_view_t value;
        if (index == missing_index) {
            continue;
        }
        (void)memset(&record, 0, sizeof(record));
        if (ninlil_model_runtime_store_bootstrap_record_at(
                &plan, index, &record) != NINLIL_OK) {
            (void)context->storage->rollback(
                context->storage->user, transaction);
            return 0;
        }
        key.data = record.key.bytes;
        key.length = record.key.length;
        value.data = record.value;
        value.length = record.value_length;
        if (context->storage->put(context->storage->user,
                transaction, key, value) != NINLIL_STORAGE_OK) {
            (void)context->storage->rollback(
                context->storage->user, transaction);
            return 0;
        }
    }
    return context->storage->commit(context->storage->user,
        transaction, NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_OK;
}

/*
 * Production-codec family5 INTERNAL_INVARIANT row (not a short fake key).
 * Reconstructs D1 DSB1_INV_TYPED_POSITIVE via encode_body + encode_envelope
 * + build_key + validate_typed_record.
 */
static int make_valid_family5_invariant_row(
    uint8_t *key_out,
    uint32_t *key_len,
    uint8_t *value_out,
    uint32_t value_cap,
    uint32_t *value_len)
{
    static const uint8_t SUBJECT_DIGEST[32] = {
        0xfau, 0x86u, 0xa0u, 0x67u, 0xe3u, 0x4cu, 0xe6u, 0x5fu,
        0xf3u, 0xfau, 0x15u, 0xa2u, 0x9du, 0x9cu, 0x04u, 0x46u,
        0xbau, 0x4au, 0xcfu, 0x0cu, 0x7eu, 0xd5u, 0x17u, 0x42u,
        0xdbu, 0x34u, 0xf3u, 0xa8u, 0x28u, 0x79u, 0xe9u, 0x85u
    };
    static const uint8_t DETAIL_DIGEST[32] = {
        0x9cu, 0x02u, 0x11u, 0xc5u, 0x1du, 0x04u, 0x57u, 0x4fu,
        0xdau, 0xeeu, 0x6du, 0x51u, 0xf5u, 0x3fu, 0x41u, 0x95u,
        0x25u, 0x70u, 0xb0u, 0xbfu, 0x68u, 0xa7u, 0x21u, 0x9au,
        0xaau, 0xe0u, 0x1cu, 0xe0u, 0x0fu, 0xa6u, 0xb8u, 0xddu
    };
    ninlil_model_domain_body_internal_invariant_t inv;
    ninlil_model_domain_common_header_t hdr;
    ninlil_model_domain_key_t key;
    ninlil_model_domain_typed_record_t typed;
    ninlil_bytes_view_t identity;
    ninlil_bytes_view_t body_view;
    uint8_t body[NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES];
    uint8_t marker[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint32_t body_len = 0u;
    uint32_t enc_len = 0u;

    (void)memset(&inv, 0, sizeof(inv));
    inv.reason = 129u; /* known public */
    inv.subject_kind = 0x0622u;
    inv.reserved = 0u;
    (void)memcpy(inv.subject_digest, SUBJECT_DIGEST, 32u);
    inv.first_clock_epoch[15] = 0x01u;
    inv.first_at_ms = 1000u;
    (void)memcpy(inv.detail_digest, DETAIL_DIGEST, 32u);

    if (ninlil_model_domain_encode_body_internal_invariant(
            &inv, body, sizeof(body), &body_len) != NINLIL_OK
        || body_len != NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES) {
        return 0;
    }
    if (ninlil_model_domain_invariant_marker_id(
            inv.reason, inv.subject_kind, inv.subject_digest, marker)
        != NINLIL_OK) {
        return 0;
    }
    identity.data = marker;
    identity.length = NINLIL_MODEL_DOMAIN_ID_BYTES;
    if (ninlil_model_domain_build_key(
            NINLIL_MODEL_DOMAIN_FAMILY_HEALTH,
            NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            identity,
            &key) != NINLIL_OK) {
        return 0;
    }
    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body_len;
    if (ninlil_model_domain_primary_id_from_identity(
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128, identity, hdr.primary_id)
        != NINLIL_OK) {
        return 0;
    }
    /* Health INTERNAL_INVARIANT: head and PVD must be zero (primary). */
    (void)memset(hdr.head_witness_digest, 0, 32u);
    (void)memset(hdr.primary_value_digest, 0, 32u);
    body_view.data = body;
    body_view.length = body_len;
    if (ninlil_model_domain_encode_envelope(
            NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH,
            &hdr,
            body_view,
            value_out,
            value_cap,
            &enc_len) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){key.bytes, key.length},
            (ninlil_bytes_view_t){value_out, enc_len},
            &typed) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(key_out, key.bytes, key.length);
    *key_len = key.length;
    *value_len = enc_len;
    return 1;
}

/* ---- workspace / source gates ---- */

static int test_workspace_ceiling_and_union(void)
{
    REQUIRE(sizeof(ninlil_runtime_store_stage5_workspace_t)
        <= NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES);
    REQUIRE(NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES == 8704u);
    REQUIRE(NINLIL_RUNTIME_STORE_STAGE5_SCAN_BUDGET == 64u);
    REQUIRE(NINLIL_RUNTIME_STORE_L2B1_SCAN_VALUE_CAPACITY == 4096u);
    REQUIRE(sizeof(ninlil_runtime_store_bootstrap_workspace_t)
        <= NINLIL_RUNTIME_STORE_L2B1_WORKSPACE_CEILING_BYTES);
    /* Phase union reuses memory: stage5 ws < l2b1 + scan sum. */
    REQUIRE(sizeof(ninlil_runtime_store_stage5_workspace_t)
        < sizeof(ninlil_runtime_store_bootstrap_workspace_t)
            + sizeof(ninlil_domain_scan_workspace_t)
            + sizeof(ninlil_domain_scan_session_t)
            + sizeof(ninlil_model_runtime_store_binding_t));
    /*
     * Production contract note (host may stack-allocate for tests):
     * sizeof(workspace) is the Runtime-arena reservation size.
     */
    REQUIRE(sizeof(ninlil_runtime_store_stage5_workspace_t) > 0u);
    return 0;
}

/* ---- new empty → bootstrap pending, scanner not invoked ---- */

static int test_new_empty_bootstrap_pending_no_scan(void)
{
    test_context_t context;
    uint64_t put_before;
    uint64_t get_before;
    ninlil_test_allocator_diagnostics_t diagnostics;

    REQUIRE(context_init(&context));
    put_before = ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT);
    get_before = ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_GET);
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);
    REQUIRE(context.result.bootstrap_outcome
        == NINLIL_RUNTIME_STORE_NEW_BOOTSTRAP_COMMITTED);
    REQUIRE(context.result.scan_ran == 0u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.result.reopen_required == 0u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT) == put_before + 17u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_GET) == get_before + 17u);
    REQUIRE(context.hook_spy.count == 2u);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

/* ---- exact existing 17 profile clean → scan adopted D3_PENDING ---- */

static int test_existing_exact_scan_adopted_d3_pending(void)
{
    test_context_t context;
    uint64_t put_after_bootstrap;
    uint64_t erase_after;
    uint64_t commit_after;

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);
    put_after_bootstrap = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    erase_after = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
    commit_after = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);

    context.hook_spy.count = 0u;
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING);
    REQUIRE(context.result.bootstrap_outcome
        == NINLIL_RUNTIME_STORE_EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 1u);
    REQUIRE(context.result.scan_status == NINLIL_OK);
    REQUIRE(context.result.profile_exact_active == 1u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.result.reopen_required == 0u);
    REQUIRE(context.result.current_domain_key_count == 0u);
    REQUIRE(context.result.ok_row_count == 17u);
    REQUIRE(context.hook_spy.count == 0u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT) == put_after_bootstrap);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ERASE) == erase_after);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT) == commit_after);
    REQUIRE(context_destroy(&context));
    return 0;
}

/*
 * Candidate handoff: distinctive non-default binding preserved outside phase
 * union after L2b1→scan reuse; second profile gate adopts.
 */
static int test_candidate_handoff_distinctive_binding(void)
{
    test_context_t context;
    ninlil_model_runtime_store_bootstrap_plan_t expected_plan;
    ninlil_model_runtime_store_binding_t expected_binding;
    uintptr_t candidate_addr;
    uintptr_t phase_addr;

    REQUIRE(context_init(&context));
    REQUIRE(context.validation.accepted_config.limits.max_services
        == DISTINCT_MAX_SERVICES);
    REQUIRE(context.validation.accepted_config.terminal_retention_ms
        == DISTINCT_TERMINAL_RETENTION_MS);

    (void)memset(&expected_plan, 0, sizeof(expected_plan));
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
            &context.validation, &expected_plan) == NINLIL_OK);
    expected_binding = expected_plan.binding;
    /* Distinctive fields must not be all-zero defaults. */
    REQUIRE(expected_binding.limits.max_services == DISTINCT_MAX_SERVICES);
    REQUIRE(expected_binding.limits.max_nonterminal_transactions
        == DISTINCT_MAX_NONTERMINAL);
    REQUIRE(expected_binding.limits.max_deferred_tokens
        == DISTINCT_MAX_DEFERRED);
    REQUIRE(expected_binding.terminal_retention_ms
        == DISTINCT_TERMINAL_RETENTION_MS);

    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);

    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING);
    REQUIRE(context.result.scan_adopted == 1u);
    REQUIRE(context.result.profile_exact_active == 1u);

    /* Workspace candidate must equal expected plan binding byte-for-byte. */
    REQUIRE(memcmp(&context.workspace.candidate_binding,
            &expected_binding,
            sizeof(expected_binding)) == 0);

    /*
     * Regression: candidate lives outside phase union. If copy occurred after
     * zeroing, or pointed into the union that was wiped, bytes would not match
     * and/or addresses would overlap.
     */
    candidate_addr = (uintptr_t)&context.workspace.candidate_binding;
    phase_addr = (uintptr_t)&context.workspace.phase;
    REQUIRE(candidate_addr + sizeof(context.workspace.candidate_binding)
        <= phase_addr
        || phase_addr + sizeof(context.workspace.phase) <= candidate_addr);
    /* Phase scan memory was reused; candidate must still be intact. */
    REQUIRE(context.workspace.candidate_binding.limits.max_services
        == DISTINCT_MAX_SERVICES);
    REQUIRE(context.workspace.candidate_binding.terminal_retention_ms
        == DISTINCT_TERMINAL_RETENTION_MS);

    REQUIRE(context_destroy(&context));
    return 0;
}

/* ---- structurally valid family5 domain row → D3_PENDING ---- */

static int test_structurally_valid_family5_domain_row_d3_pending(void)
{
    test_context_t context;
    uint8_t key_buf[64];
    uint8_t value_buf[512];
    uint32_t key_len = 0u;
    uint32_t value_len = 0u;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    uint64_t put_after_seed;
    uint64_t erase_after;
    uint64_t commit_after;

    REQUIRE(make_valid_family5_invariant_row(
        key_buf, &key_len, value_buf, sizeof(value_buf), &value_len));
    REQUIRE(key_len >= 13u);
    REQUIRE(value_len > 100u);

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);

    key.data = key_buf;
    key.length = key_len;
    value.data = value_buf;
    value.length = value_len;
    REQUIRE(raw_put(&context, key, value));

    put_after_seed = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    erase_after = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
    commit_after = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);

    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 1u);
    REQUIRE(context.result.scan_status == NINLIL_OK);
    REQUIRE(context.result.profile_exact_active == 1u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.result.current_domain_key_count == 1u);
    /* 17 family1-4 + 1 domain = 18 OK rows. */
    REQUIRE(context.result.ok_row_count == 18u);
    REQUIRE(context.result.family14_row_count == 17u);
    /* Scanner-phase mutation 0. */
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT) == put_after_seed);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ERASE) == erase_after);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT) == commit_after);
    REQUIRE(context_destroy(&context));
    return 0;
}

/* ---- recognizable future → UNSUPPORTED ---- */

static int test_recognizable_future_unsupported(void)
{
    static const uint8_t FUTURE_KEY[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x02u, 0x01u
    };
    static const uint8_t VALUE[] = {0x01u};
    test_context_t context;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;

    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = VALUE;
    value.length = sizeof(VALUE);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_UNSUPPORTED);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 0u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

/* ---- corrupt structural / BTS / lex ---- */

static int test_corrupt_bts_and_partial(void)
{
    static const uint8_t FUTURE_KEY[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x02u, 0x01u
    };
    static uint8_t value_4097[4097];
    test_context_t context;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    ninlil_test_allocator_diagnostics_t diagnostics;
    uint32_t missing;

    (void)memset(value_4097, 0x5a, sizeof(value_4097));

    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = value_4097;
    value.length = sizeof(value_4097);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 0u);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    REQUIRE(seed_partial_bootstrap(&context));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.result.scan_ran == 0u);
    REQUIRE(context_destroy(&context));

    for (missing = 0u;
         missing < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++missing) {
        REQUIRE(context_init(&context));
        REQUIRE(seed_bootstrap_without(&context, missing));
        REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(context.result.scan_ran == 0u);
        REQUIRE(context_destroy(&context));
    }
    return 0;
}

/* ---- profile mismatch → UNSUPPORTED ---- */

static int test_profile_mismatch_unsupported(void)
{
    test_context_t context;

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);
    context.validation.accepted_config.limits.max_services -= 1u;
    context.validation.capacity_limits.values[NINLIL_RESOURCE_SERVICE - 1u]
        -= 1u;
    REQUIRE(run(&context) == NINLIL_E_UNSUPPORTED);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

/* ---- L2b1 rollback fence (pre-scan) ---- */

static int test_l2b1_rollback_fence_reopen(void)
{
    test_context_t context;

    REQUIRE(context_init(&context));
    REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_IO_ERROR));
    REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ROLLBACK, NINLIL_STORAGE_BUSY));
    REQUIRE(run(&context) == NINLIL_E_STORAGE);
    REQUIRE(context.result.cleanup_status == NINLIL_STORAGE_BUSY);
    REQUIRE(context.result.reopen_required == 1u);
    REQUIRE(context.handle == NULL);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 0u);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 1));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(context.handle == NULL);
    REQUIRE(context.result.reopen_required == 1u);
    REQUIRE(reopen(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING);
    REQUIRE(context_destroy(&context));
    return 0;
}

/*
 * Strict poison retention: every INVALID_ARGUMENT prevalidation failure
 * leaves out_result and workspace poison unchanged.
 */
static int test_prevalidation_poison_retention(void)
{
    test_context_t context;
    ninlil_runtime_store_stage5_result_t poisoned_result;
    ninlil_runtime_store_stage5_workspace_t poisoned_workspace;
    ninlil_storage_ops_t missing_ops;
    ninlil_storage_handle_t null_handle;

    REQUIRE(context_init(&context));
    (void)memset(&poisoned_result, 0xa5, sizeof(poisoned_result));
    (void)memset(&poisoned_workspace, 0x3c, sizeof(poisoned_workspace));

    /* NULL out_result: no object to retain; still no side effects. */
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, &context.validation,
        &context.hooks, &context.workspace, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(context.handle != NULL);

    /* NULL storage — poison retained. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        NULL, &context.handle, &context.validation, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);
    REQUIRE(context.handle != NULL);

    /* NULL handle pointer. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, NULL, &context.validation, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* NULL *handle. */
    null_handle = NULL;
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &null_handle, &context.validation, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* NULL validation. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, NULL, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* NULL workspace. */
    context.result = poisoned_result;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, &context.validation, &context.hooks,
        NULL, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);

    /* Missing required storage op (begin NULL). */
    missing_ops = *context.storage;
    missing_ops.begin = NULL;
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        &missing_ops, &context.handle, &context.validation, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* out_result overlaps workspace. */
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, &context.validation,
        &context.hooks, &context.workspace,
        (ninlil_runtime_store_stage5_result_t *)&context.workspace)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);
    REQUIRE(context.handle != NULL);

    /* workspace overlaps handle. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage,
        (ninlil_storage_handle_t *)&context.workspace,
        &context.validation, &context.hooks, &context.workspace,
        &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);
    REQUIRE(context.handle != NULL);

    /* storage overlaps workspace. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        (const ninlil_storage_ops_t *)&context.workspace,
        &context.handle, &context.validation, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* hooks overlap out_result. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, &context.validation,
        (const ninlil_runtime_store_hook_dispatcher_t *)&context.result,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* validation overlaps workspace. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle,
        (const ninlil_model_runtime_validation_result_t *)&context.workspace,
        &context.hooks, &context.workspace, &context.result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* storage ↔ validation (const-const) overlap. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        (const ninlil_storage_ops_t *)&context.validation,
        &context.handle, &context.validation, &context.hooks,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* hooks ↔ storage (const-const) overlap. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, &context.validation,
        (const ninlil_runtime_store_hook_dispatcher_t *)context.storage,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    /* hooks ↔ validation (const-const) overlap. */
    context.result = poisoned_result;
    context.workspace = poisoned_workspace;
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
        context.storage, &context.handle, &context.validation,
        (const ninlil_runtime_store_hook_dispatcher_t *)&context.validation,
        &context.workspace, &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context.result, &poisoned_result, sizeof(poisoned_result))
        == 0);
    REQUIRE(memcmp(&context.workspace, &poisoned_workspace,
            sizeof(poisoned_workspace)) == 0);

    REQUIRE(context.handle != NULL);
    REQUIRE(context_destroy(&context));
    return 0;
}

/*
 * L2b1→scanner second-snapshot race: mutate storage immediately before the
 * scanner's second READ_ONLY begin. Future-root key (version >= 2) must be
 * paired with a valid NLR1-framed value so classify_row is deterministic
 * RECOGNIZABLE_FUTURE → finalize UNSUPPORTED (not MALFORMED/CORRUPT).
 */
static int test_second_snapshot_race_revalidates(void)
{
    static const uint8_t FUTURE_KEY[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x02u, 0x01u
    };
    uint8_t family5_key[64];
    uint8_t family5_value[512];
    uint32_t family5_key_len = 0u;
    uint32_t family5_value_len = 0u;
    test_context_t context;
    ninlil_status_t st;

    /* Reuse production-codec NLR1 envelope from make_valid_family5_invariant_row. */
    REQUIRE(make_valid_family5_invariant_row(
        family5_key, &family5_key_len, family5_value, sizeof(family5_value),
        &family5_value_len));
    REQUIRE(family5_value_len >= 16u);
    REQUIRE(FUTURE_KEY[7] >= 2u);

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);

    proxy_reset(context.storage);
    g_proxy.mutate_on_second_ro_begin = 1;
    g_proxy.fixture_for_mutate = context.storage_fixture;
    g_proxy.mutate_key = FUTURE_KEY;
    g_proxy.mutate_key_len = (uint32_t)sizeof(FUTURE_KEY);
    g_proxy.mutate_value = family5_value;
    g_proxy.mutate_value_len = family5_value_len;

    st = run_with_ops(&context, &g_proxy.ops);
    /* Exact closed mapping: recognizable future on second snapshot. */
    REQUIRE(st == NINLIL_E_UNSUPPORTED);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.scan_status == NINLIL_E_UNSUPPORTED);
    REQUIRE(context.result.recognizable_future_seen == 1u);
    REQUIRE(context.result.profile_exact_active == 1u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    /* Exactly two READ_ONLY begins: L2b1 then scanner (race injection point). */
    REQUIRE(g_proxy.begin_ro_count == 2u);
    REQUIRE(context_destroy(&context));
    return 0;
}

/*
 * Scanner-phase faults distinct from L2b1: inject on scanner's second-snapshot
 * get (after L2b1's 17 gets) or on iter_next/finalize rollback path.
 */
static int test_scanner_phase_fault_io_no_fence(void)
{
    test_context_t context;
    uint64_t close_before;

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);

    proxy_reset(context.storage);
    /*
     * Existing path: L2b1 = 17 gets; scanner begin starts at get #18.
     * Fault first scanner get with known IO (no fence).
     */
    g_proxy.arm_get_fault_on = 18u;
    g_proxy.get_fault_status = NINLIL_STORAGE_IO_ERROR;

    close_before = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);
    REQUIRE(run_with_ops(&context, &g_proxy.ops) == NINLIL_E_STORAGE);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.result.reopen_required == 0u);
    /* Known IO: no fence; original handle remains. */
    REQUIRE(context.handle != NULL);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_CLOSE) == close_before);
    /* Original close exactly once only if fenced — here zero extra closes. */
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_scanner_phase_fault_unknown_requires_fence(void)
{
    test_context_t context;
    uint64_t close_before;

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);

    proxy_reset(context.storage);
    g_proxy.arm_get_fault_on = 18u;
    g_proxy.get_fault_status = (ninlil_storage_status_t)99u;

    close_before = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_CLOSE);
    REQUIRE(run_with_ops(&context, &g_proxy.ops)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.result.reopen_required == 1u);
    /* Unknown status requires fence; original handle closed exactly once. */
    REQUIRE(context.handle == NULL);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_CLOSE) == close_before + 1u);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_scanner_phase_iter_next_bts_and_io(void)
{
    test_context_t context;

    /* BTS on first scanner iter_next → CORRUPT, no fence. */
    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    proxy_reset(context.storage);
    g_proxy.arm_iter_next_fault_on = 1u;
    g_proxy.iter_next_fault_status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
    REQUIRE(run_with_ops(&context, &g_proxy.ops)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.result.reopen_required == 0u);
    REQUIRE(context.handle != NULL);
    REQUIRE(g_proxy.iter_next_count == 1u);
    REQUIRE(context_destroy(&context));

    /* IO on first scanner iter_next → STORAGE, no fence. */
    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    proxy_reset(context.storage);
    g_proxy.arm_iter_next_fault_on = 1u;
    g_proxy.iter_next_fault_status = NINLIL_STORAGE_IO_ERROR;
    REQUIRE(run_with_ops(&context, &g_proxy.ops) == NINLIL_E_STORAGE);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(context.handle != NULL);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_no_allocator_on_seam_paths(void)
{
    test_context_t context;
    ninlil_test_allocator_diagnostics_t diagnostics;

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(run(&context) == NINLIL_OK);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

/*
 * Behavioral OK+unadopted closure (not enum/source-only).
 *
 * INVARIANT-ONLY: on the scanner finalize rollback (2nd rollback of the
 * existing-profile re-entry: L2b1 RO cleanup then scanner finalize cleanup),
 * the test storage proxy sets the known private session's reopen_required=1
 * while the underlying rollback still returns OK. Production finalize then
 * returns OK with adopted=0; Stage5 maps that to STORAGE_CORRUPT + NONE.
 * No production test hook; scanner contracts are not weakened.
 */
static int test_ok_unadopted_maps_storage_corrupt(void)
{
    test_context_t context;

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);

    proxy_reset(context.storage);
    /* Address is stable across workspace zeroing at hookup entry. */
    g_proxy.session_for_reopen_mutate = &context.workspace.session;
    g_proxy.arm_reopen_mutate_on_rollback = 2u;

    REQUIRE(run_with_ops(&context, &g_proxy.ops)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE);
    REQUIRE(context.result.scan_ran == 1u);
    REQUIRE(context.result.scan_adopted == 0u);
    REQUIRE(context.result.scan_status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.result.storage_recovery_complete == 0u);
    REQUIRE(g_proxy.rollback_count == 2u);
    REQUIRE(context_destroy(&context));
    return 0;
}

int main(void)
{
    if (test_workspace_ceiling_and_union() != 0
        || test_new_empty_bootstrap_pending_no_scan() != 0
        || test_existing_exact_scan_adopted_d3_pending() != 0
        || test_candidate_handoff_distinctive_binding() != 0
        || test_structurally_valid_family5_domain_row_d3_pending() != 0
        || test_recognizable_future_unsupported() != 0
        || test_corrupt_bts_and_partial() != 0
        || test_profile_mismatch_unsupported() != 0
        || test_l2b1_rollback_fence_reopen() != 0
        || test_prevalidation_poison_retention() != 0
        || test_second_snapshot_race_revalidates() != 0
        || test_scanner_phase_fault_io_no_fence() != 0
        || test_scanner_phase_fault_unknown_requires_fence() != 0
        || test_scanner_phase_iter_next_bts_and_io() != 0
        || test_no_allocator_on_seam_paths() != 0
        || test_ok_unadopted_maps_storage_corrupt() != 0) {
        return 1;
    }
    return 0;
}
