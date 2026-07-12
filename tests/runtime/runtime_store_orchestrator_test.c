#include "runtime_store_orchestrator.h"

#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"

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

static const uint8_t TEST_NAMESPACE[] = "runtime-store-orchestrator";

typedef struct hook_spy {
    uint32_t count;
    const char *names[4];
} hook_spy_t;

typedef struct test_context {
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_allocator_t *allocator_fixture;
    const ninlil_storage_ops_t *storage;
    const ninlil_allocator_ops_t *allocator;
    ninlil_storage_handle_t handle;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_runtime_store_bootstrap_workspace_t workspace;
    ninlil_runtime_store_bootstrap_result_t result;
    hook_spy_t hook_spy;
    ninlil_runtime_store_hook_dispatcher_t hooks;
} test_context_t;

typedef enum adversarial_mode {
    ADVERSARIAL_NONE = 0,
    ADVERSARIAL_ITER_DUPLICATE = 1,
    ADVERSARIAL_ITER_OUT_OF_ORDER = 2,
    ADVERSARIAL_ITER_RETRY_LENGTH_CHANGE = 3,
    ADVERSARIAL_ITER_RETRY_IO = 4,
    ADVERSARIAL_ITER_RETRY_UNKNOWN = 5,
    ADVERSARIAL_BEGIN_OK_NULL = 6,
    ADVERSARIAL_BEGIN_ERROR_WITH_TXN = 7,
    ADVERSARIAL_ITER_OPEN_OK_NULL = 8,
    ADVERSARIAL_ITER_OPEN_ERROR_WITH_ITER = 9,
    /* First iter_next reports key-required >255 BTS (S6a no-reread). */
    ADVERSARIAL_ITER_KEY_BTS_OVER_255 = 10
} adversarial_mode_t;

static adversarial_mode_t adversarial_mode;
static ninlil_storage_status_t (*base_begin)(
    void *, ninlil_storage_handle_t, ninlil_storage_mode_t,
    ninlil_storage_txn_t *);
static ninlil_storage_status_t (*base_iter_open)(
    void *, ninlil_storage_txn_t, ninlil_bytes_view_t,
    ninlil_storage_iter_t *);
static ninlil_storage_status_t (*base_iter_next)(
    void *, ninlil_storage_iter_t, ninlil_mut_bytes_t *,
    ninlil_mut_bytes_t *);
static uint32_t adversarial_iter_calls;
static uint8_t adversarial_first_key[255];
static uint32_t adversarial_first_key_length;

static ninlil_storage_status_t adversarial_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    if (adversarial_mode == ADVERSARIAL_BEGIN_OK_NULL) {
        return NINLIL_STORAGE_OK;
    }
    if (adversarial_mode == ADVERSARIAL_BEGIN_ERROR_WITH_TXN) {
        ninlil_storage_status_t status = base_begin(
            user, handle, mode, out_transaction);
        return status == NINLIL_STORAGE_OK
            ? NINLIL_STORAGE_IO_ERROR : status;
    }
    return base_begin(user, handle, mode, out_transaction);
}

static ninlil_storage_status_t adversarial_iter_open(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    if (adversarial_mode == ADVERSARIAL_ITER_OPEN_OK_NULL) {
        return NINLIL_STORAGE_OK;
    }
    if (adversarial_mode == ADVERSARIAL_ITER_OPEN_ERROR_WITH_ITER) {
        ninlil_storage_status_t status = base_iter_open(
            user, transaction, prefix, out_iterator);
        return status == NINLIL_STORAGE_OK
            ? NINLIL_STORAGE_IO_ERROR : status;
    }
    return base_iter_open(user, transaction, prefix, out_iterator);
}

static ninlil_storage_status_t adversarial_iter_next(
    void *user,
    ninlil_storage_iter_t iterator,
    ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    ninlil_storage_status_t status;
    adversarial_iter_calls += 1u;
    if (adversarial_mode == ADVERSARIAL_ITER_KEY_BTS_OVER_255
        && adversarial_iter_calls == 1u) {
        /*
         * ch12-valid BTS may report required key length > workspace (255).
         * L2b1 must not reread/allocate (S6a).
         */
        if (key != NULL) {
            key->length = 256u;
        }
        if (value != NULL) {
            value->length = 0u;
        }
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if ((adversarial_mode == ADVERSARIAL_ITER_RETRY_IO
            || adversarial_mode == ADVERSARIAL_ITER_RETRY_UNKNOWN)
        && adversarial_iter_calls == 2u) {
        key->length = 0u;
        value->length = 0u;
        return adversarial_mode == ADVERSARIAL_ITER_RETRY_IO
            ? NINLIL_STORAGE_IO_ERROR : (ninlil_storage_status_t)99u;
    }
    status = base_iter_next(user, iterator, key, value);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (adversarial_iter_calls == 1u) {
        adversarial_first_key_length = key->length;
        (void)memcpy(adversarial_first_key, key->data, key->length);
    } else if (adversarial_mode == ADVERSARIAL_ITER_DUPLICATE
        && adversarial_iter_calls == 2u) {
        (void)memcpy(key->data, adversarial_first_key,
            adversarial_first_key_length);
        key->length = adversarial_first_key_length;
    } else if (adversarial_mode == ADVERSARIAL_ITER_OUT_OF_ORDER
        && adversarial_iter_calls == 2u) {
        key->data[0] = 0x00u;
    } else if (adversarial_mode
            == ADVERSARIAL_ITER_RETRY_LENGTH_CHANGE
        && adversarial_iter_calls == 2u && value->length != 0u) {
        value->length -= 1u;
    }
    return status;
}

static ninlil_storage_ops_t adversarial_ops(
    const ninlil_storage_ops_t *original,
    adversarial_mode_t mode)
{
    ninlil_storage_ops_t ops = *original;
    adversarial_mode = mode;
    adversarial_iter_calls = 0u;
    adversarial_first_key_length = 0u;
    base_begin = original->begin;
    base_iter_open = original->iter_open;
    base_iter_next = original->iter_next;
    ops.begin = adversarial_begin;
    ops.iter_open = adversarial_iter_open;
    ops.iter_next = adversarial_iter_next;
    return ops;
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
    config.limits.max_services = 7u;
    config.limits.max_nonterminal_transactions = 20u;
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
    config.limits.max_deferred_tokens = 11u;
    config.terminal_retention_ms = 1000u;
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
    storage_config.max_bytes_per_namespace = 100000u;
    context->storage_fixture = ninlil_test_storage_create(&storage_config);
    context->allocator_fixture = ninlil_test_allocator_create();
    if (context->storage_fixture == NULL
        || context->allocator_fixture == NULL) {
        return 0;
    }
    context->storage = ninlil_test_storage_ops(context->storage_fixture);
    context->allocator =
        ninlil_test_allocator_ops(context->allocator_fixture);
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
    return ninlil_runtime_store_orchestrate_bootstrap(
        context->storage, &context->handle,
        &context->validation, &context->hooks, &context->workspace,
        &context->result);
}

static ninlil_status_t run_with_storage(
    test_context_t *context,
    const ninlil_storage_ops_t *storage)
{
    return ninlil_runtime_store_orchestrate_bootstrap(
        storage, &context->handle,
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

static int test_new_then_existing_exact(void)
{
    test_context_t context;
    uint64_t begin_before;
    size_t trace_count;
    const ninlil_test_storage_trace_record_t *last;
    REQUIRE(context_init(&context));
    begin_before = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_BEGIN);
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_NEW_BOOTSTRAP_COMMITTED);
    REQUIRE(context.result.reopen_required == 0u);
    REQUIRE(context.hook_spy.count == 2u);
    REQUIRE(strcmp(context.hook_spy.names[0],
        NINLIL_RUNTIME_STORE_HOOK_BEFORE_NAMESPACE_BINDING_COMMIT) == 0);
    REQUIRE(strcmp(context.hook_spy.names[1],
        NINLIL_RUNTIME_STORE_HOOK_AFTER_NAMESPACE_BINDING_COMMIT) == 0);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_BEGIN) == begin_before + 2u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_GET) == 17u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT) == 17u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_OPEN) == 1u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_NEXT) == 1u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_CLOSE) == 1u);
    trace_count = ninlil_test_storage_trace_count(context.storage_fixture);
    last = ninlil_test_storage_trace_at(context.storage_fixture,
        trace_count - 1u);
    REQUIRE(last != NULL);
    REQUIRE(last->operation == NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(last->durability == NINLIL_DURABILITY_FULL);

    context.hook_spy.count = 0u;
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED);
    REQUIRE(context.hook_spy.count == 0u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT) == 17u);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_partial_and_profile_mismatch(void)
{
    test_context_t context;
    uint32_t missing;
    REQUIRE(context_init(&context));
    REQUIRE(seed_partial_bootstrap(&context));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_OPEN) == 0u);
    REQUIRE(context.hook_spy.count == 0u);
    REQUIRE(context_destroy(&context));

    for (missing = 0u;
         missing < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++missing) {
        REQUIRE(context_init(&context));
        REQUIRE(seed_bootstrap_without(&context, missing));
        REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(context.result.outcome
            == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
        REQUIRE(context.hook_spy.count == 0u);
        REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_ITER_OPEN) == 0u);
        REQUIRE(context_destroy(&context));
    }

    REQUIRE(context_init(&context));
    REQUIRE(run(&context) == NINLIL_OK);
    context.hook_spy.count = 0u;
    context.validation.accepted_config.limits.max_services -= 1u;
    context.validation.capacity_limits.values[NINLIL_RESOURCE_SERVICE - 1u]
        -= 1u;
    REQUIRE(run(&context) == NINLIL_E_UNSUPPORTED);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
    REQUIRE(context.hook_spy.count == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_extra_rows_and_oversized_scan(void)
{
    static const uint8_t FUTURE_KEY[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x02u, 0x01u
    };
    static const uint8_t UNKNOWN_KEY[] = {0x01u};
    static const uint8_t FUTURE_KEY_2[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x02u, 0x02u
    };
    uint8_t midsize[300];
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    test_context_t context;
    ninlil_test_allocator_diagnostics_t diagnostics;

    (void)memset(midsize, 0x5au, sizeof(midsize));
    /* Value 300 fits private 4096 workspace: future classifies, no alloc. */
    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = midsize;
    value.length = sizeof(midsize);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_UNSUPPORTED);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(diagnostics.deallocate_calls == 0u);
    REQUIRE(diagnostics.live_allocations == 0u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_NEXT) == 2u);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    key.data = UNKNOWN_KEY;
    key.length = sizeof(UNKNOWN_KEY);
    value.data = midsize;
    value.length = 1u;
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = midsize;
    value.length = 1u;
    REQUIRE(raw_put(&context, key, value));
    key.data = FUTURE_KEY_2;
    key.length = sizeof(FUTURE_KEY_2);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_UNSUPPORTED);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_NEXT) == 3u);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    key.data = UNKNOWN_KEY;
    key.length = sizeof(UNKNOWN_KEY);
    value.length = 1u;
    REQUIRE(raw_put(&context, key, value));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_rollback_precedence(void)
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
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ROLLBACK, NINLIL_STORAGE_BUSY));
    REQUIRE(run(&context) == NINLIL_E_WOULD_BLOCK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
    REQUIRE(context.handle == NULL);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_PUT) == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

/*
 * S6a: private 4096 exact boundary OK (future classify, no alloc);
 * value 4097, Storage ABI 65536, and key length >255 BTS → CORRUPT,
 * allocate/deallocate 0, no reread (iter_next once per oversized row).
 * No temporary allocation API remains on the private L2b1 path.
 */
static int test_bts_no_reread_boundaries(void)
{
    static const uint8_t FUTURE_KEY[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x02u, 0x01u
    };
    static uint8_t key_over_255[256];
    static uint8_t value_4096[4096];
    static uint8_t value_4097[4097];
    static uint8_t value_65536[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
    static const uint8_t SMALL_VALUE[] = {0x01u};
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    ninlil_test_allocator_diagnostics_t diagnostics;
    test_context_t context;
    uint64_t iter_next_before;

    (void)memset(key_over_255, 0x7au, sizeof(key_over_255));
    (void)memset(value_4096, 0x6cu, sizeof(value_4096));
    (void)memset(value_4097, 0x6du, sizeof(value_4097));
    (void)memset(value_65536, 0x6eu, sizeof(value_65536));

    /* Exact private max 4096: accepted, classifies as future, no alloc. */
    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = value_4096;
    value.length = sizeof(value_4096);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_UNSUPPORTED);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(diagnostics.deallocate_calls == 0u);
    REQUIRE(diagnostics.live_allocations == 0u);
    REQUIRE(context_destroy(&context));

    /* 4097 → BTS → CORRUPT, no reread, no alloc. */
    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = value_4097;
    value.length = sizeof(value_4097);
    REQUIRE(raw_put(&context, key, value));
    iter_next_before = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_ITER_NEXT);
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(diagnostics.deallocate_calls == 0u);
    /* One BTS attempt only: no second reread iter_next. */
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_NEXT) == iter_next_before + 1u);
    REQUIRE(context_destroy(&context));

    /* Storage ABI max 65536 → BTS → CORRUPT, no reread, no alloc. */
    REQUIRE(context_init(&context));
    key.data = FUTURE_KEY;
    key.length = sizeof(FUTURE_KEY);
    value.data = value_65536;
    value.length = sizeof(value_65536);
    REQUIRE(raw_put(&context, key, value));
    iter_next_before = ninlil_test_storage_call_count(
        context.storage_fixture, NINLIL_TEST_STORAGE_OP_ITER_NEXT);
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    diagnostics = ninlil_test_allocator_diagnostics(
        context.allocator_fixture);
    REQUIRE(diagnostics.allocate_calls == 0u);
    REQUIRE(diagnostics.deallocate_calls == 0u);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_NEXT) == iter_next_before + 1u);
    REQUIRE(context_destroy(&context));

    /*
     * key required length >255 BTS (provider reports 256) → CORRUPT,
     * single iter_next, no reread, no alloc, no fence. Storage put cannot
     * seed key>255 (fixture max 255); inject via adversarial iter_next.
     */
    {
        ninlil_storage_ops_t ops;
        static const uint8_t KEY_A[] = {0x10u};
        REQUIRE(context_init(&context));
        key.data = KEY_A;
        key.length = sizeof(KEY_A);
        value.data = SMALL_VALUE;
        value.length = sizeof(SMALL_VALUE);
        REQUIRE(raw_put(&context, key, value));
        ops = adversarial_ops(context.storage, ADVERSARIAL_ITER_KEY_BTS_OVER_255);
        REQUIRE(run_with_storage(&context, &ops) == NINLIL_E_STORAGE_CORRUPT);
        diagnostics = ninlil_test_allocator_diagnostics(
            context.allocator_fixture);
        REQUIRE(diagnostics.allocate_calls == 0u);
        REQUIRE(diagnostics.deallocate_calls == 0u);
        REQUIRE(adversarial_iter_calls == 1u);
        REQUIRE(context.result.outcome
            == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
        REQUIRE(context.handle != NULL);
        REQUIRE(context_destroy(&context));
    }
    (void)key_over_255;
    return 0;
}

static int test_commit_unknown_convergence(void)
{
    test_context_t context;

    REQUIRE(context_init(&context));
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 1));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(context.handle == NULL);
    REQUIRE(context.result.reopen_required == 1u);
    REQUIRE(context.hook_spy.count == 1u);
    REQUIRE(reopen(&context));
    context.hook_spy.count = 0u;
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED);
    REQUIRE(context.hook_spy.count == 0u);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 0));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(context.handle == NULL);
    REQUIRE(reopen(&context));
    context.hook_spy.count = 0u;
    REQUIRE(run(&context) == NINLIL_OK);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_NEW_BOOTSTRAP_COMMITTED);
    REQUIRE(context.hook_spy.count == 2u);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_closed_status_mapping_and_fencing(void)
{
    static const struct status_case {
        ninlil_storage_status_t port;
        ninlil_status_t api;
        uint32_t fenced;
    } cases[] = {
        {NINLIL_STORAGE_BUSY, NINLIL_E_WOULD_BLOCK, 0u},
        {NINLIL_STORAGE_NO_SPACE, NINLIL_E_CAPACITY_EXHAUSTED, 0u},
        {NINLIL_STORAGE_IO_ERROR, NINLIL_E_STORAGE, 0u},
        {NINLIL_STORAGE_CORRUPT, NINLIL_E_STORAGE_CORRUPT, 0u},
        {NINLIL_STORAGE_UNSUPPORTED_SCHEMA, NINLIL_E_UNSUPPORTED, 0u},
        {NINLIL_STORAGE_COMMIT_UNKNOWN,
            NINLIL_E_STORAGE_COMMIT_UNKNOWN, 1u},
        {(ninlil_storage_status_t)99u, NINLIL_E_STORAGE_CORRUPT, 1u}
    };
    uint32_t index;
    for (index = 0u; index < (uint32_t)(sizeof(cases) / sizeof(cases[0]));
         ++index) {
        test_context_t context;
        REQUIRE(context_init(&context));
        REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_BEGIN, cases[index].port));
        REQUIRE(run(&context) == cases[index].api);
        REQUIRE((context.handle == NULL) == (cases[index].fenced != 0u));
        REQUIRE(context.result.reopen_required == cases[index].fenced);
        REQUIRE(context.result.outcome
            == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
        REQUIRE(context_destroy(&context));
    }
    return 0;
}

static int test_operation_status_matrix(void)
{
    static const struct status_case {
        ninlil_storage_status_t port;
        ninlil_status_t api;
        uint32_t force_fence;
    } cases[] = {
        {NINLIL_STORAGE_BUSY, NINLIL_E_WOULD_BLOCK, 0u},
        {NINLIL_STORAGE_NO_SPACE, NINLIL_E_CAPACITY_EXHAUSTED, 0u},
        {NINLIL_STORAGE_IO_ERROR, NINLIL_E_STORAGE, 0u},
        {NINLIL_STORAGE_CORRUPT, NINLIL_E_STORAGE_CORRUPT, 0u},
        {NINLIL_STORAGE_UNSUPPORTED_SCHEMA, NINLIL_E_UNSUPPORTED, 0u},
        {NINLIL_STORAGE_COMMIT_UNKNOWN,
            NINLIL_E_STORAGE_COMMIT_UNKNOWN, 1u},
        {(ninlil_storage_status_t)99u, NINLIL_E_STORAGE_CORRUPT, 1u}
    };
    static const ninlil_test_storage_operation_t operations[] = {
        NINLIL_TEST_STORAGE_OP_GET,
        NINLIL_TEST_STORAGE_OP_PUT,
        NINLIL_TEST_STORAGE_OP_ITER_OPEN,
        NINLIL_TEST_STORAGE_OP_ITER_NEXT
    };
    uint32_t operation_index;
    uint32_t case_index;

    for (operation_index = 0u;
         operation_index
            < (uint32_t)(sizeof(operations) / sizeof(operations[0]));
         ++operation_index) {
        for (case_index = 0u;
             case_index < (uint32_t)(sizeof(cases) / sizeof(cases[0]));
             ++case_index) {
            test_context_t context;
            REQUIRE(context_init(&context));
            REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
                operations[operation_index], cases[case_index].port));
            REQUIRE(run(&context) == cases[case_index].api);
            REQUIRE((context.handle == NULL)
                == (cases[case_index].force_fence != 0u));
            REQUIRE(context.result.outcome
                == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
            REQUIRE(context.hook_spy.count == 0u);
            REQUIRE(context_destroy(&context));
        }
    }

    for (case_index = 0u;
         case_index < (uint32_t)(sizeof(cases) / sizeof(cases[0]));
         ++case_index) {
        test_context_t context;
        REQUIRE(context_init(&context));
        REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_ROLLBACK, cases[case_index].port));
        REQUIRE(run(&context) == cases[case_index].api);
        REQUIRE(context.handle == NULL);
        REQUIRE(context.result.reopen_required == 1u);
        REQUIRE(context.result.cleanup_status == cases[case_index].port);
        REQUIRE(context.result.outcome
            == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
        REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_PUT) == 0u);
        REQUIRE(context_destroy(&context));
    }

    for (case_index = 0u; case_index < 5u; ++case_index) {
        test_context_t context;
        REQUIRE(context_init(&context));
        REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_COMMIT, cases[case_index].port));
        REQUIRE(run(&context) == cases[case_index].api);
        REQUIRE(context.handle != NULL);
        REQUIRE(context.hook_spy.count == 1u);
        REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_ROLLBACK) == 1u);
        REQUIRE(context_destroy(&context));
    }
    {
        test_context_t context;
        REQUIRE(context_init(&context));
        REQUIRE(ninlil_test_storage_fault_next(context.storage_fixture,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            (ninlil_storage_status_t)99u));
        REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(context.handle == NULL);
        REQUIRE(context.hook_spy.count == 1u);
        REQUIRE(context_destroy(&context));
    }
    return 0;
}

static int test_current_key_oversized_is_corrupt(void)
{
    ninlil_model_runtime_store_key_t model_key;
    uint8_t oversized[300];
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    test_context_t context;
    (void)memset(oversized, 0x7b, sizeof(oversized));
    (void)memset(&model_key, 0, sizeof(model_key));
    REQUIRE(context_init(&context));
    REQUIRE(ninlil_model_runtime_store_build_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &model_key) == NINLIL_OK);
    key.data = model_key.bytes;
    key.length = model_key.length;
    value.data = oversized;
    value.length = sizeof(oversized);
    REQUIRE(raw_put(&context, key, value));
    REQUIRE(run(&context) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_test_storage_call_count(context.storage_fixture,
        NINLIL_TEST_STORAGE_OP_ITER_OPEN) == 0u);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_adversarial_provider_shapes_and_order(void)
{
    static const uint8_t KEY_A[] = {0x10u};
    static const uint8_t KEY_B[] = {0x20u};
    static const uint8_t VALUE[] = {0x01u};
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    ninlil_storage_ops_t ops;
    test_context_t context;
    adversarial_mode_t order_modes[] = {
        ADVERSARIAL_ITER_DUPLICATE,
        ADVERSARIAL_ITER_OUT_OF_ORDER
    };
    uint32_t index;

    for (index = 0u;
         index < (uint32_t)(sizeof(order_modes) / sizeof(order_modes[0]));
         ++index) {
        REQUIRE(context_init(&context));
        key.data = KEY_A;
        key.length = sizeof(KEY_A);
        value.data = VALUE;
        value.length = sizeof(VALUE);
        REQUIRE(raw_put(&context, key, value));
        key.data = KEY_B;
        key.length = sizeof(KEY_B);
        REQUIRE(raw_put(&context, key, value));
        ops = adversarial_ops(context.storage, order_modes[index]);
        REQUIRE(run_with_storage(&context, &ops)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(adversarial_iter_calls == 2u);
        REQUIRE(context.handle != NULL);
        REQUIRE(context_destroy(&context));
    }

    /* S6a: reread path removed; RETRY_* adversarial modes no longer apply. */

    REQUIRE(context_init(&context));
    ops = adversarial_ops(context.storage, ADVERSARIAL_BEGIN_OK_NULL);
    REQUIRE(run_with_storage(&context, &ops) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.handle == NULL);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    ops = adversarial_ops(context.storage,
        ADVERSARIAL_BEGIN_ERROR_WITH_TXN);
    REQUIRE(run_with_storage(&context, &ops) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.handle == NULL);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    ops = adversarial_ops(context.storage, ADVERSARIAL_ITER_OPEN_OK_NULL);
    REQUIRE(run_with_storage(&context, &ops) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.handle == NULL);
    REQUIRE(context_destroy(&context));

    REQUIRE(context_init(&context));
    ops = adversarial_ops(context.storage,
        ADVERSARIAL_ITER_OPEN_ERROR_WITH_ITER);
    REQUIRE(run_with_storage(&context, &ops) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.handle == NULL);
    REQUIRE(context_destroy(&context));
    return 0;
}

static int test_invalid_arguments_do_not_destroy_handle(void)
{
    test_context_t context;
    REQUIRE(context_init(&context));
    (void)memset(&context.result, 0xa5, sizeof(context.result));
    REQUIRE(ninlil_runtime_store_orchestrate_bootstrap(
        NULL, &context.handle,
        &context.validation, &context.hooks, &context.workspace,
        &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(context.result.outcome
        == NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE);
    REQUIRE(context.result.cleanup_status == NINLIL_STORAGE_OK);
    REQUIRE(context.result.reopen_required == 0u);
    REQUIRE(context.handle != NULL);
    context.workspace.candidate_binding.storage_schema =
        UINT32_C(0x11223344);
    REQUIRE(ninlil_runtime_store_orchestrate_bootstrap(
        context.storage, &context.handle,
        &context.validation, &context.hooks, &context.workspace,
        (ninlil_runtime_store_bootstrap_result_t *)&context.workspace)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(context.workspace.candidate_binding.storage_schema
        == UINT32_C(0x11223344));
    REQUIRE(context.handle != NULL);
    REQUIRE(ninlil_runtime_store_orchestrate_bootstrap(
        context.storage,
        (ninlil_storage_handle_t *)&context.workspace,
        &context.validation, &context.hooks, &context.workspace,
        &context.result) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(context.handle != NULL);
    REQUIRE(ninlil_runtime_store_orchestrate_bootstrap(
        (const ninlil_storage_ops_t *)&context.workspace,
        &context.handle, &context.validation,
        &context.hooks, &context.workspace, &context.result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(context.handle != NULL);
    REQUIRE(ninlil_runtime_store_orchestrate_bootstrap(
        context.storage, &context.handle,
        &context.validation,
        (const ninlil_runtime_store_hook_dispatcher_t *)&context.result,
        &context.workspace, &context.result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(context.handle != NULL);
    REQUIRE(context_destroy(&context));
    return 0;
}

int main(void)
{
    if (test_new_then_existing_exact() != 0
        || test_partial_and_profile_mismatch() != 0
        || test_extra_rows_and_oversized_scan() != 0
        || test_rollback_precedence() != 0
        || test_bts_no_reread_boundaries() != 0
        || test_commit_unknown_convergence() != 0
        || test_closed_status_mapping_and_fencing() != 0
        || test_operation_status_matrix() != 0
        || test_current_key_oversized_is_corrupt() != 0
        || test_adversarial_provider_shapes_and_order() != 0
        || test_invalid_arguments_do_not_destroy_handle() != 0) {
        return 1;
    }
    return 0;
}
