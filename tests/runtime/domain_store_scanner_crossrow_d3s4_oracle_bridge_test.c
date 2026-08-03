/*
 * D3-S4 typed authority bridge.
 *
 * The shared authority is append-only: 283 frozen D3-S1/S2/S3 vectors plus
 * the 185 D3-S4 suffix vectors emitted into the typed fixture included here.
 *
 * Production begin performs the already-proved D2 profile gate (17 exact
 * GETs) and opens the baseline iterator in the begin call.  The independent
 * S4 oracle starts at the S4 boundary: it omits those 17 profile GETs and
 * assigns the initial iterator-open event to the first drive call.  The port
 * adapter below makes only that closed projection; all S4 request keys,
 * returned keys, complete returned values, statuses, call windows, and the
 * full 949-byte context image are compared.
 */

#include "domain_store_d3s4.h"
#include "domain_store_scanner.h"
#include "scripted_storage_spy.h"
#include "domain_scan_crossrow_d3s4_fixture.h"

#include <stdio.h>
#include <string.h>

#define D3S4_PREFIX_COUNT ((size_t)283u)
#define D3S4_TOTAL_COUNT ((size_t)468u)
#define PROFILE_ROW_COUNT ((size_t)17u)
#define D3S4_EXPECTED_NEGATIVE_COUNT ((size_t)191u)
#define D3S4_EXPECTED_CONTENT_SHA256                                      \
    "b18f717e2752c9d617d575c86194ef644f301706263674f2666a5d29ed951e25"
#define D3S4_EXPECTED_ORDER_SHA256                                        \
    "17ec848715537a261f274a392d23c586045b87bc0adf1fe65cb1e15c7f0c8c4d"
#define D3S4_EXPECTED_NEGATIVE_SHA256                                     \
    "74e0ded28a87d77f002db181a496a70efd29f601833c08d2379e717fff7f00ee"
#define D3S4_EXPECTED_CANONICAL_SHA256                                    \
    "33d936597ce617952043f6a0324ba616b8d71acf41cc8744d1b3f771abd54f15"

static const char *g_current_id = "";

#define REQUIRE(x)                                                           \
    do {                                                                     \
        if (!(x)) {                                                          \
            (void)fprintf(stderr, "%s:%d: %s: %s\n",                       \
                __FILE__, __LINE__, g_current_id, #x);                       \
            return 1;                                                        \
        }                                                                    \
    } while (0)

typedef struct d3s4_port_adapter {
    ninlil_scripted_storage_spy_t spy;
    ninlil_storage_ops_t ops;
    const ninlil_d3s4_vector_t *vector;
    size_t event_index;
    size_t current_call;
    uint8_t held_initial_iter_open;
    uint8_t suppress_authority_events;
    uint8_t enable_declared_fault;
    uint8_t declared_fault_consumed;
    uint8_t enable_iter_duplicate;
    uint8_t iter_duplicate_injected;
    uint8_t failed;
    size_t iter_open_calls;
    size_t exact_get_calls;
    const uint8_t *iter_duplicate_key;
    size_t iter_duplicate_key_length;
    uint8_t profile_keys[PROFILE_ROW_COUNT][NINLIL_SPY_MAX_KEY];
    uint32_t profile_key_lengths[PROFILE_ROW_COUNT];
    uint8_t profile_values[PROFILE_ROW_COUNT][183u];
    uint32_t profile_value_lengths[PROFILE_ROW_COUNT];
} d3s4_port_adapter_t;

/* Test storage is intentionally BSS, never the sanitizer-sensitive stack. */
static d3s4_port_adapter_t g_adapter;
static d3s4_port_adapter_t g_compose_adapter;

typedef struct d3s4_hook_fixture {
    d3s4_port_adapter_t adapter;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s4_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
} d3s4_hook_fixture_t;

/* BSS keeps the large workspace/spy out of sanitizer-sensitive test stacks. */
static d3s4_hook_fixture_t g_hook_fixture;

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint8_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(first + i);
    }
}

static void default_binding(ninlil_model_runtime_store_binding_t *binding)
{
    (void)memset(binding, 0, sizeof(*binding));
    binding->storage_schema = NINLIL_STORAGE_SCHEMA_M1A;
    binding->role = NINLIL_ROLE_CONTROLLER;
    binding->environment = NINLIL_ENV_TEST;
    set_id(&binding->runtime_id, 0x10u);
    binding->limits.max_services = 7u;
    binding->limits.max_nonterminal_transactions = 20u;
    binding->limits.max_targets_per_transaction = 1u;
    binding->limits.max_logical_payload_bytes = 1000u;
    binding->limits.max_durable_outbox_payload_bytes = 5000u;
    binding->limits.max_attempts_per_target_per_cycle = 8u;
    binding->limits.max_cancel_attempts_per_transaction = 1u;
    binding->limits.max_evidence_per_target = 3u;
    binding->limits.max_retained_terminal_transactions = 30u;
    binding->limits.max_nonterminal_deliveries = 12u;
    binding->limits.max_event_spool_count = 0u;
    binding->limits.max_event_spool_bytes = 0u;
    binding->limits.max_result_cache_entries = 13u;
    binding->limits.max_retained_dispositions = 14u;
    binding->limits.max_ingress_per_step = 15u;
    binding->limits.max_callbacks_per_step = 16u;
    binding->limits.max_state_transitions_per_step = 17u;
    binding->limits.max_bearer_sends_per_step = 18u;
    binding->limits.max_deferred_tokens = 19u;
}

static int install_profile_rows(
    d3s4_port_adapter_t *adapter,
    ninlil_model_runtime_store_binding_t *candidate)
{
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_key_t key;
    uint8_t value[183];
    uint32_t value_length;
    uint32_t key_id;

    default_binding(candidate);
    (void)memset(&identity, 0, sizeof(identity));
    identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&identity.device_id, 0x20u);
    set_id(&identity.installation_id, 0x40u);
    set_id(&identity.site_domain_id, 0x60u);
    identity.binding_epoch = 1u;
    identity.membership_epoch = 1u;

    for (key_id = 1u; key_id <= 17u; ++key_id) {
        ninlil_status_t status;
        if (ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)key_id, &key)
            != NINLIL_OK) {
            return 0;
        }
        value_length = 0u;
        if (key_id == 1u) {
            status = ninlil_model_runtime_store_encode_binding(
                candidate, value, sizeof(value), &value_length);
        } else if (key_id == 2u) {
            status = ninlil_model_runtime_store_encode_identity(
                &identity, value, sizeof(value), &value_length);
        } else if (key_id <= 6u) {
            ninlil_model_runtime_store_counter_t counter;
            counter.kind =
                (ninlil_model_runtime_store_counter_kind_t)(key_id - 2u);
            counter.value = 0u;
            counter.exhausted_marker = 0u;
            status = ninlil_model_runtime_store_encode_counter(
                (ninlil_model_runtime_store_key_id_t)key_id, &counter,
                value, sizeof(value), &value_length);
        } else {
            ninlil_model_runtime_store_capacity_t capacity;
            (void)memset(&capacity, 0, sizeof(capacity));
            capacity.kind = (ninlil_resource_kind_t)(key_id - 6u);
            capacity.limit = 100u + key_id;
            capacity.capacity_epoch = 1u;
            status = ninlil_model_runtime_store_encode_capacity(
                (ninlil_model_runtime_store_key_id_t)key_id, &capacity,
                value, sizeof(value), &value_length);
        }
        if (status != NINLIL_OK) {
            return 0;
        }
        (void)memcpy(
            adapter->profile_keys[key_id - 1u], key.bytes, key.length);
        adapter->profile_key_lengths[key_id - 1u] = key.length;
        (void)memcpy(
            adapter->profile_values[key_id - 1u], value, value_length);
        adapter->profile_value_lengths[key_id - 1u] = value_length;
    }
    return 1;
}

static int profile_key_index(
    const d3s4_port_adapter_t *adapter,
    const uint8_t *key,
    uint32_t key_length)
{
    size_t i;
    for (i = 0u; i < PROFILE_ROW_COUNT; ++i) {
        if (adapter->profile_key_lengths[i] == key_length
            && memcmp(adapter->profile_keys[i], key, key_length) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void port_fail(
    d3s4_port_adapter_t *adapter,
    const char *field,
    const char *actual_op)
{
    if (adapter->failed == 0u) {
        const char *expected_op =
            adapter->event_index < adapter->vector->event_count
            ? adapter->vector->events[adapter->event_index].op : "<end>";
        (void)fprintf(stderr,
            "%s: port %s mismatch event=%zu call=%zu want-op=%s got-op=%s\n",
            g_current_id, field, adapter->event_index, adapter->current_call,
            expected_op, actual_op);
    }
    adapter->failed = 1u;
}

static int storage_expectation_matches(
    const char *expected,
    const char *op,
    ninlil_storage_status_t actual,
    size_t returned_value_length)
{
    if (expected == NULL) {
        /*
         * The independent Mode33 oracle historically left PRESENT null for a
         * closed header GET.  Non-empty returned bytes make the meaning
         * unambiguous and are still compared byte-for-byte below.
         */
        return (strcmp(op, "exact_get") == 0 && returned_value_length > 0u)
            ? actual == NINLIL_STORAGE_OK
            : actual == NINLIL_STORAGE_OK;
    }
    if (strcmp(expected, "PRESENT") == 0) {
        return actual == NINLIL_STORAGE_OK;
    }
    if (strcmp(expected, "ABSENT") == 0 || strcmp(expected, "END") == 0) {
        return actual == NINLIL_STORAGE_NOT_FOUND;
    }
    if (strcmp(expected, "FAULT") == 0) {
        return actual == NINLIL_STORAGE_CORRUPT
            || actual == NINLIL_STORAGE_IO_ERROR;
    }
    return 0;
}

static void compare_port_event(
    d3s4_port_adapter_t *adapter,
    const char *op,
    ninlil_storage_status_t status,
    const uint8_t *request_key,
    size_t request_key_length,
    const uint8_t *returned_key,
    size_t returned_key_length,
    const uint8_t *returned_value,
    size_t returned_value_length)
{
    const ninlil_d3s4_port_event_t *expected;

    if (adapter->suppress_authority_events != 0u) {
        return;
    }
    if (adapter->failed != 0u) {
        return;
    }
    if (adapter->event_index >= adapter->vector->event_count) {
        port_fail(adapter, "extra-event", op);
        return;
    }
    expected = &adapter->vector->events[adapter->event_index];
    if (expected->seq != (int)adapter->event_index
        || expected->on_call != (int)adapter->event_index
        || strcmp(expected->op, op) != 0) {
        port_fail(adapter, "identity", op);
        return;
    }
    if (!storage_expectation_matches(
            expected->storage_status, op, status, returned_value_length)) {
        size_t key_i;
        port_fail(adapter, "status", op);
        (void)fprintf(stderr,
            "  want-status=%s got-status=%d request-key=",
            expected->storage_status == NULL
                ? "<implicit-present>" : expected->storage_status,
            (int)status);
        for (key_i = 0u; key_i < request_key_length; ++key_i) {
            (void)fprintf(stderr, "%02x", request_key[key_i]);
        }
        (void)fprintf(stderr, "\n");
        return;
    }
    if (expected->request_key_len != request_key_length
        || (request_key_length != 0u
            && memcmp(
                expected->request_key, request_key, request_key_length) != 0)) {
        port_fail(adapter, "request-key", op);
        return;
    }
    if (expected->returned_key_len != returned_key_length
        || (returned_key_length != 0u
            && memcmp(
                expected->returned_key, returned_key,
                returned_key_length) != 0)) {
        size_t key_i;
        port_fail(adapter, "returned-key", op);
        (void)fprintf(stderr, "  want-key=");
        for (key_i = 0u; key_i < expected->returned_key_len; ++key_i) {
            (void)fprintf(stderr, "%02x", expected->returned_key[key_i]);
        }
        (void)fprintf(stderr, "\n  got-key =");
        for (key_i = 0u; key_i < returned_key_length; ++key_i) {
            (void)fprintf(stderr, "%02x", returned_key[key_i]);
        }
        (void)fprintf(stderr, "\n");
        return;
    }
    if (expected->value_length != (int)returned_value_length
        || expected->returned_value_len != returned_value_length
        || (returned_value_length != 0u
            && memcmp(
                expected->returned_value, returned_value,
                returned_value_length) != 0)) {
        port_fail(adapter, "returned-value", op);
        return;
    }
    adapter->event_index += 1u;
}

static void compare_void_port_event(
    d3s4_port_adapter_t *adapter, const char *op)
{
    compare_port_event(
        adapter, op, NINLIL_STORAGE_OK,
        NULL, 0u, NULL, 0u, NULL, 0u);
}

static ninlil_storage_status_t adapter_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    return ninlil_spy_ops(&adapter->spy)->open(
        &adapter->spy, storage_namespace, expected_schema, out_handle);
}

static void adapter_close(void *user, ninlil_storage_handle_t handle)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    compare_void_port_event(adapter, "close");
    ninlil_spy_ops(&adapter->spy)->close(&adapter->spy, handle);
}

static ninlil_storage_status_t adapter_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    ninlil_storage_status_t status =
        ninlil_spy_ops(&adapter->spy)->begin(
            &adapter->spy, handle, mode, out_txn);
    compare_port_event(
        adapter, "begin", status, NULL, 0u, NULL, 0u, NULL, 0u);
    return status;
}

static ninlil_storage_status_t adapter_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    ninlil_storage_status_t status;
    int profile_index =
        profile_key_index(adapter, key.data, key.length);

    /*
     * The D2 profile catalog and the independent D3-S4 substrate are separate
     * authority projections.  Some legal D3 carrier keys byte-equal a profile
     * key, so physically merging the two row sets would make one overwrite or
     * mask the other.  Serve the 17 begin-gate GETs from this virtual catalog;
     * the scripted store then contains exactly the D3 rows visible to S4.
     */
    if (profile_index >= 0 && adapter->current_call == 0u) {
        uint32_t value_length =
            adapter->profile_value_lengths[(size_t)profile_index];
        if (inout_value == NULL
            || (inout_value->capacity != 0u && inout_value->data == NULL)) {
            return NINLIL_STORAGE_CORRUPT;
        }
        inout_value->length = 0u;
        if (value_length > inout_value->capacity) {
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        if (value_length != 0u) {
            (void)memcpy(
                inout_value->data,
                adapter->profile_values[(size_t)profile_index],
                value_length);
        }
        inout_value->length = value_length;
        return NINLIL_STORAGE_OK;
    }
    if (adapter->enable_declared_fault != 0u
        && adapter->declared_fault_consumed == 0u
        && adapter->vector->fault_count == 1u
        && strcmp(adapter->vector->faults[0].op, "exact_get") == 0
        && adapter->exact_get_calls
            == (size_t)adapter->vector->faults[0].on_call) {
        status = NINLIL_STORAGE_CORRUPT;
        inout_value->length = 0u;
        adapter->exact_get_calls += 1u;
        adapter->declared_fault_consumed = 1u;
        compare_port_event(
            adapter, "exact_get", status,
            key.data, key.length, NULL, 0u, NULL, 0u);
        return status;
    }
    status = ninlil_spy_ops(&adapter->spy)->get(
        &adapter->spy, txn, key, inout_value);
    adapter->exact_get_calls += 1u;
    compare_port_event(
        adapter, "exact_get", status,
        key.data, key.length, NULL, 0u,
        inout_value->data, inout_value->length);
    return status;
}

static ninlil_storage_status_t adapter_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    return ninlil_spy_ops(&adapter->spy)->put(
        &adapter->spy, txn, key, value);
}

static ninlil_storage_status_t adapter_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    return ninlil_spy_ops(&adapter->spy)->erase(
        &adapter->spy, txn, key);
}

static ninlil_storage_status_t adapter_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    ninlil_storage_status_t status =
        ninlil_spy_ops(&adapter->spy)->iter_open(
            &adapter->spy, txn, prefix, out_iter);
    adapter->iter_open_calls += 1u;
    if (adapter->current_call == 0u
        && adapter->held_initial_iter_open == 0u) {
        if (status != NINLIL_STORAGE_OK
            || prefix.length != 0u || prefix.data != NULL) {
            port_fail(adapter, "held-initial-iter-open", "iter_open");
        }
        adapter->held_initial_iter_open = 1u;
    } else {
        compare_port_event(
            adapter, "iter_open", status,
            NULL, 0u, NULL, 0u, NULL, 0u);
    }
    return status;
}

static ninlil_storage_status_t adapter_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    ninlil_storage_status_t status =
        ninlil_spy_ops(&adapter->spy)->iter_next(
            &adapter->spy, iter, inout_key, inout_value);

    if (adapter->enable_iter_duplicate != 0u
        && adapter->iter_duplicate_injected == 0u
        && adapter->iter_open_calls >= 2u
        && status == NINLIL_STORAGE_OK
        && inout_key->length == adapter->iter_duplicate_key_length
        && memcmp(
            inout_key->data, adapter->iter_duplicate_key,
            inout_key->length) == 0) {
        if (adapter->spy.iter_position == 0u) {
            port_fail(adapter, "duplicate-rewind", "iter_next");
        } else {
            /*
             * Replay this complete storage row once on the next physical
             * ITER_NEXT.  The scripted spy still records both calls and the
             * production scanner receives two byte-identical key/value rows.
             */
            adapter->spy.iter_position -= 1u;
            adapter->iter_duplicate_injected = 1u;
        }
    }
    compare_port_event(
        adapter, "iter_next", status,
        NULL, 0u, inout_key->data, inout_key->length,
        inout_value->data, inout_value->length);
    return status;
}

static void adapter_iter_close(void *user, ninlil_storage_iter_t iter)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    compare_void_port_event(adapter, "iter_close");
    ninlil_spy_ops(&adapter->spy)->iter_close(&adapter->spy, iter);
}

static ninlil_storage_status_t adapter_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    return ninlil_spy_ops(&adapter->spy)->capacity(
        &adapter->spy, handle, out_capacity);
}

static ninlil_storage_status_t adapter_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    return ninlil_spy_ops(&adapter->spy)->commit(
        &adapter->spy, txn, durability);
}

static ninlil_storage_status_t adapter_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    d3s4_port_adapter_t *adapter = (d3s4_port_adapter_t *)user;
    ninlil_storage_status_t status =
        ninlil_spy_ops(&adapter->spy)->rollback(&adapter->spy, txn);
    compare_port_event(
        adapter, "rollback", status,
        NULL, 0u, NULL, 0u, NULL, 0u);
    return status;
}

static void adapter_init(
    d3s4_port_adapter_t *adapter,
    const ninlil_d3s4_vector_t *vector)
{
    ninlil_spy_init(&adapter->spy);
    adapter->ops = *ninlil_spy_ops(&adapter->spy);
    adapter->ops.user = adapter;
    adapter->ops.open = adapter_open;
    adapter->ops.close = adapter_close;
    adapter->ops.begin = adapter_begin;
    adapter->ops.get = adapter_get;
    adapter->ops.put = adapter_put;
    adapter->ops.erase = adapter_erase;
    adapter->ops.iter_open = adapter_iter_open;
    adapter->ops.iter_next = adapter_iter_next;
    adapter->ops.iter_close = adapter_iter_close;
    adapter->ops.capacity = adapter_capacity;
    adapter->ops.commit = adapter_commit;
    adapter->ops.rollback = adapter_rollback;
    adapter->vector = vector;
    adapter->event_index = 0u;
    adapter->current_call = 0u;
    adapter->held_initial_iter_open = 0u;
    adapter->suppress_authority_events = 0u;
    adapter->enable_declared_fault = 0u;
    adapter->declared_fault_consumed = 0u;
    adapter->enable_iter_duplicate = 0u;
    adapter->iter_duplicate_injected = 0u;
    adapter->failed = 0u;
    adapter->iter_open_calls = 0u;
    adapter->exact_get_calls = 0u;
    adapter->iter_duplicate_key = NULL;
    adapter->iter_duplicate_key_length = 0u;
    (void)memset(adapter->profile_keys, 0, sizeof(adapter->profile_keys));
    (void)memset(
        adapter->profile_key_lengths, 0,
        sizeof(adapter->profile_key_lengths));
    (void)memset(adapter->profile_values, 0, sizeof(adapter->profile_values));
    (void)memset(
        adapter->profile_value_lengths, 0,
        sizeof(adapter->profile_value_lengths));
}

static void flush_initial_iter_open(d3s4_port_adapter_t *adapter)
{
    if (adapter->held_initial_iter_open == 0u) {
        port_fail(adapter, "missing-held-initial-iter-open", "iter_open");
        return;
    }
    compare_void_port_event(adapter, "iter_open");
    adapter->held_initial_iter_open = 0u;
}

static int status_from_name(const char *name, ninlil_status_t *out)
{
    if (strcmp(name, "OK") == 0 || strcmp(name, "NINLIL_OK") == 0) {
        *out = NINLIL_OK;
    } else if (strcmp(name, "NINLIL_E_STORAGE_CORRUPT") == 0) {
        *out = NINLIL_E_STORAGE_CORRUPT;
    } else if (strcmp(name, "NINLIL_E_STORAGE") == 0) {
        *out = NINLIL_E_STORAGE;
    } else if (strcmp(name, "NINLIL_E_STORAGE_COMMIT_UNKNOWN") == 0) {
        *out = NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    } else if (strcmp(name, "NINLIL_E_CAPACITY_EXHAUSTED") == 0) {
        *out = NINLIL_E_CAPACITY_EXHAUSTED;
    } else if (strcmp(name, "NINLIL_E_WOULD_BLOCK") == 0) {
        *out = NINLIL_E_WOULD_BLOCK;
    } else if (strcmp(name, "NINLIL_E_UNSUPPORTED") == 0) {
        *out = NINLIL_E_UNSUPPORTED;
    } else if (strcmp(name, "NINLIL_E_INVALID_STATE") == 0) {
        *out = NINLIL_E_INVALID_STATE;
    } else if (strcmp(name, "NINLIL_E_INVALID_ARGUMENT") == 0) {
        *out = NINLIL_E_INVALID_ARGUMENT;
    } else {
        return 0;
    }
    return 1;
}

static int compare_context(
    const ninlil_d3s4_call_t *call,
    const ninlil_domain_scan_d3s4_context_t *context,
    size_t call_index)
{
    const uint8_t *actual = (const uint8_t *)(const void *)context;
    size_t i;
    if (call->context == NULL
        || call->context_len != sizeof(*context)) {
        (void)fprintf(stderr,
            "%s: invalid typed context carrier call=%zu len=%zu\n",
            g_current_id, call_index, call->context_len);
        return 0;
    }
    if (memcmp(call->context, actual, sizeof(*context)) == 0) {
        return 1;
    }
    for (i = 0u; i < sizeof(*context); ++i) {
        if (call->context[i] != actual[i]) {
            (void)fprintf(stderr,
                "%s: context mismatch call=%zu byte=%zu want=%02x got=%02x "
                "phase want=%d got=%u arm want=%d got=%u "
                "last-len want=%d got=%u\n",
                g_current_id, call_index, i,
                (unsigned)call->context[i], (unsigned)actual[i],
                call->phase, (unsigned)context->phase,
                call->arm_cursor, (unsigned)context->arm_cursor,
                (unsigned)call->context[45],
                (unsigned)context->last_carrier_key_len);
            break;
        }
    }
    return 0;
}

static int row_key_less(
    const ninlil_d3s4_row_t *left,
    const ninlil_d3s4_row_t *right)
{
    size_t common = left->key_len < right->key_len
        ? left->key_len : right->key_len;
    int order = common == 0u
        ? 0 : memcmp(left->key, right->key, common);
    if (order != 0) {
        return order < 0;
    }
    return left->key_len < right->key_len;
}

static int add_sorted_row_slice(
    d3s4_port_adapter_t *adapter,
    const ninlil_d3s4_row_t *rows,
    size_t row_count)
{
    uint8_t row_added[NINLIL_SPY_MAX_ROWS];
    size_t i;

    if ((rows == NULL && row_count != 0u)
        || row_count > NINLIL_SPY_MAX_ROWS) {
        return 0;
    }
    (void)memset(row_added, 0, sizeof(row_added));
    for (i = 0u; i < row_count; ++i) {
        size_t candidate_i = row_count;
        size_t scan_i;
        for (scan_i = 0u; scan_i < row_count; ++scan_i) {
            if (row_added[scan_i] == 0u
                && (candidate_i == row_count
                    || row_key_less(
                        &rows[scan_i],
                        &rows[candidate_i]))) {
                candidate_i = scan_i;
            }
        }
        if (candidate_i >= row_count) {
            return 0;
        }
        row_added[candidate_i] = 1u;
        if (!ninlil_spy_add_row(
                &adapter->spy,
                rows[candidate_i].key,
                (uint32_t)rows[candidate_i].key_len,
                rows[candidate_i].value,
                (uint32_t)rows[candidate_i].value_len)) {
            return 0;
        }
    }
    return 1;
}

static int add_sorted_rows(
    d3s4_port_adapter_t *adapter,
    const ninlil_d3s4_vector_t *vector)
{
    return add_sorted_row_slice(
        adapter, vector->rows, vector->row_count);
}

static int run_compose_session(
    const ninlil_d3s4_vector_t *owner,
    const ninlil_d3s4_compose_session_t *compose_session,
    ninlil_domain_scan_result_t *out_result)
{
    d3s4_port_adapter_t *adapter = &g_compose_adapter;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s4_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_status_t actual = NINLIL_E_INVALID_STATE;
    size_t i;

    REQUIRE(owner != NULL);
    REQUIRE(compose_session != NULL);
    REQUIRE(out_result != NULL);
    REQUIRE(compose_session->fault_count == 0u);
    REQUIRE(compose_session->calls != NULL);
    REQUIRE(compose_session->call_count >= 2u);

    adapter_init(adapter, owner);
    adapter->suppress_authority_events = 1u;
    REQUIRE(install_profile_rows(adapter, &candidate));
    REQUIRE(add_sorted_row_slice(
        adapter, compose_session->rows, compose_session->row_count));
    handle = ninlil_spy_open_handle(&adapter->spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0xa5, sizeof(context));
    (void)memset(out_result, 0xa5, sizeof(*out_result));

    for (i = 0u; i < compose_session->call_count; ++i) {
        const ninlil_d3s4_call_t *call = &compose_session->calls[i];
        ninlil_status_t expected;

        adapter->current_call = i;
        REQUIRE(status_from_name(call->returned_status, &expected));
        if (strcmp(call->op, "begin") == 0) {
            actual = ninlil_domain_scan_begin_profiled_d3s4(
                &session, &adapter->ops, &handle, &workspace,
                &candidate, (uint8_t)compose_session->mode, &context);
        } else if (strcmp(call->op, "drive") == 0) {
            if (i == 1u) {
                flush_initial_iter_open(adapter);
            }
            actual = ninlil_domain_scan_d3s4_drive(
                &session, (uint16_t)call->drive_get_quota);
        } else if (strcmp(call->op, "resume") == 0) {
            actual = ninlil_domain_scan_d3s4_resume(
                &session, (uint16_t)call->drive_get_quota);
        } else if (strcmp(call->op, "finalize") == 0) {
            actual = ninlil_domain_scan_d3s4_finalize(
                &session, out_result);
        } else if (strcmp(call->op, "abort") == 0) {
            actual = ninlil_domain_scan_d3s4_abort(
                &session, out_result);
        } else {
            (void)fprintf(stderr,
                "%s: unsupported compose-session call %s\n",
                g_current_id, call->op);
            return 1;
        }
        REQUIRE(actual == expected);
        REQUIRE(adapter->failed == 0u);
        REQUIRE(compare_context(call, &context, i));
    }

    REQUIRE(adapter->held_initial_iter_open == 0u);
    REQUIRE(adapter->spy.trace_overflow == 0u);
    REQUIRE(adapter->spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&adapter->spy));
    REQUIRE(adapter->exact_get_calls == (size_t)compose_session->get_count);
    REQUIRE(status_from_name(compose_session->result_status, &actual));
    REQUIRE(out_result->status == actual);
    REQUIRE((int)out_result->d3s4_disposition_present
        == compose_session->result_present);
    if (compose_session->result_present != 0) {
        REQUIRE((int)out_result->d3s4_disposition
            == compose_session->result_disp);
    }
    return 0;
}

static int verify_composition_contract(void)
{
    ninlil_domain_scan_d3s4_composition_t composition;
    ninlil_domain_scan_d3s4_composition_t snapshot;
    uint8_t present = 0xa5u;
    uint8_t disposition = 0xa5u;

    g_current_id = "D3S4_P10_COMPOSITION_GUARDS";
    ninlil_domain_scan_d3s4_composition_init(&composition);
    REQUIRE(composition.disposition_present == 0u);
    REQUIRE(composition.disposition == 0u);
    REQUIRE(composition.accepted_input_count == 0u);
    REQUIRE(composition.reserved_zero == 0u);

    /* Non-OK carriers are ignored byte-for-byte, including poison bytes. */
    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        &composition, NINLIL_E_STORAGE_CORRUPT, 0xffu, 0xffu)
        == NINLIL_OK);
    REQUIRE(composition.disposition_present == 0u);
    REQUIRE(composition.disposition == 0u);
    REQUIRE(composition.accepted_input_count == 0u);

    /* Successful evaluator-off carriers ignore the disposition byte. */
    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        &composition, NINLIL_OK, 0u, 0xffu) == NINLIL_OK);
    REQUIRE(composition.disposition_present == 0u);
    REQUIRE(composition.disposition == 0u);
    REQUIRE(composition.accepted_input_count == 0u);

    snapshot = composition;
    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        &composition, NINLIL_OK, 2u, 0u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&composition, &snapshot, sizeof(composition)) == 0);
    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        &composition, NINLIL_OK, 1u, 4u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&composition, &snapshot, sizeof(composition)) == 0);

    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        &composition, NINLIL_OK, 1u,
        NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_REQUIRED)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        &composition, NINLIL_OK, 1u,
        NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S6_REQUIRED)
        == NINLIL_OK);
    REQUIRE(composition.accepted_input_count == 2u);
    REQUIRE(ninlil_domain_scan_d3s4_composition_finish(
        &composition, &present, &disposition) == NINLIL_OK);
    REQUIRE(present == 1u);
    REQUIRE(disposition
        == NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED);

    REQUIRE(ninlil_domain_scan_d3s4_composition_add(
        NULL, NINLIL_OK, 1u, 0u) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_d3s4_composition_finish(
        NULL, &present, &disposition) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_d3s4_composition_finish(
        &composition, NULL, &disposition) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_d3s4_composition_finish(
        &composition, &present, NULL) == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int hook_fixture_begin(
    d3s4_hook_fixture_t *fixture,
    const ninlil_d3s4_vector_t *vector,
    uint8_t candidate_mismatch)
{
    ninlil_status_t status;

    (void)memset(fixture, 0, sizeof(*fixture));
    adapter_init(&fixture->adapter, vector);
    fixture->adapter.suppress_authority_events = 1u;
    REQUIRE(install_profile_rows(
        &fixture->adapter, &fixture->candidate));
    REQUIRE(add_sorted_rows(&fixture->adapter, vector));
    if (candidate_mismatch != 0u) {
        /*
         * The virtual profile catalog was encoded above.  Mutating only the
         * caller candidate now exercises the real evaluator-off mismatch
         * path without changing any stored row.
         */
        fixture->candidate.limits.max_services += 1u;
    }
    fixture->handle = ninlil_spy_open_handle(&fixture->adapter.spy);
    ninlil_domain_scan_session_init(&fixture->session);
    (void)memset(&fixture->workspace, 0, sizeof(fixture->workspace));
    (void)memset(&fixture->context, 0xa5, sizeof(fixture->context));
    (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
    fixture->adapter.current_call = 0u;
    status = ninlil_domain_scan_begin_profiled_d3s4(
        &fixture->session, &fixture->adapter.ops, &fixture->handle,
        &fixture->workspace, &fixture->candidate,
        (uint8_t)vector->mode, &fixture->context);
    REQUIRE(status == NINLIL_OK);
    REQUIRE(fixture->adapter.held_initial_iter_open == 1u);
    return 0;
}

static int all_bytes_equal(
    const void *object, size_t object_size, uint8_t value);

static int hook_fixture_drive_complete(
    d3s4_hook_fixture_t *fixture)
{
    size_t step = 0u;

    while (fixture->context.phase
            != NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE
        && fixture->context.phase
            != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
        && step < 8192u) {
        ninlil_status_t status;
        fixture->adapter.current_call = step + 1u;
        if (fixture->adapter.held_initial_iter_open != 0u) {
            flush_initial_iter_open(&fixture->adapter);
        }
        if ((fixture->context.flags
                & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) != 0u) {
            status = ninlil_domain_scan_d3s4_resume(
                &fixture->session, 32u);
        } else {
            status = ninlil_domain_scan_d3s4_drive(
                &fixture->session, 32u);
        }
        REQUIRE(status == NINLIL_OK);
        step += 1u;
    }
    REQUIRE(step < 8192u);
    REQUIRE(fixture->context.phase
        == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE);
    REQUIRE(fixture->session.state
        == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(fixture->adapter.failed == 0u);
    REQUIRE(fixture->adapter.spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&fixture->adapter.spy));
    return 0;
}

static int hook_fixture_step(
    d3s4_hook_fixture_t *fixture,
    uint16_t quota,
    size_t call_index)
{
    ninlil_status_t status;

    fixture->adapter.current_call = call_index;
    if (fixture->adapter.held_initial_iter_open != 0u) {
        flush_initial_iter_open(&fixture->adapter);
    }
    if ((fixture->context.flags
            & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) != 0u) {
        status = ninlil_domain_scan_d3s4_resume(
            &fixture->session, quota);
    } else {
        status = ninlil_domain_scan_d3s4_drive(
            &fixture->session, quota);
    }
    REQUIRE(status == NINLIL_OK);
    return 0;
}

static int hook_fixture_expect_corrupt_finalize(
    d3s4_hook_fixture_t *fixture)
{
    ninlil_status_t status;

    REQUIRE(fixture->session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(fixture->session.has_sticky_primary != 0u);
    REQUIRE(fixture->session.sticky_primary
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(fixture->context.phase
        == NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED);
    (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
    status = ninlil_domain_scan_d3s4_finalize(
        &fixture->session, &fixture->result);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(fixture->result.status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(fixture->result.d3s4_disposition_present == 0u);
    REQUIRE(fixture->result.d3s4_disposition == 0u);
    REQUIRE(all_bytes_equal(
        &fixture->context, sizeof(fixture->context), 0u));
    REQUIRE(fixture->adapter.spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&fixture->adapter.spy));
    return 0;
}

static int hook_fixture_finalize_success(
    d3s4_hook_fixture_t *fixture,
    uint8_t expected_disposition)
{
    ninlil_status_t status;

    REQUIRE(fixture->context.phase
        == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE);
    (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
    status = ninlil_domain_scan_d3s4_finalize(
        &fixture->session, &fixture->result);
    REQUIRE(status == NINLIL_OK);
    REQUIRE(fixture->result.status == NINLIL_OK);
    REQUIRE(fixture->result.d3s4_disposition_present == 1u);
    REQUIRE(fixture->result.d3s4_disposition
        == expected_disposition);
    REQUIRE(all_bytes_equal(
        &fixture->context, sizeof(fixture->context), 0u));
    REQUIRE(fixture->adapter.spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&fixture->adapter.spy));
    return 0;
}

static int hook_fixture_finalize_derived(
    d3s4_hook_fixture_t *fixture,
    uint8_t *out_disposition)
{
    uint8_t disposition = 0xa5u;
    REQUIRE(ninlil_domain_scan_d3s4_ready_disposition(
        &fixture->context, &disposition) == NINLIL_OK);
    REQUIRE(hook_fixture_finalize_success(
        fixture, disposition) == 0);
    if (out_disposition != NULL) {
        *out_disposition = disposition;
    }
    return 0;
}

static int all_bytes_equal(
    const void *object, size_t object_size, uint8_t value)
{
    const uint8_t *bytes = (const uint8_t *)object;
    size_t i;
    for (i = 0u; i < object_size; ++i) {
        if (bytes[i] != value) {
            return 0;
        }
    }
    return 1;
}

static int hook_fixture_abort_cleanup(
    d3s4_hook_fixture_t *fixture)
{
    ninlil_domain_scan_result_t poison;
    ninlil_status_t status;

    if (fixture->session.state == NINLIL_DOMAIN_SCAN_STATE_DONE) {
        return 0;
    }
    (void)memset(&poison, 0xa5, sizeof(poison));
    status = ninlil_domain_scan_d3s4_abort(
        &fixture->session, &poison);
    REQUIRE(status == NINLIL_OK
        || status == NINLIL_E_STORAGE_CORRUPT
        || status == NINLIL_E_UNSUPPORTED);
    REQUIRE(fixture->session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(all_bytes_equal(
        &fixture->context, sizeof(fixture->context), 0u));
    REQUIRE(fixture->adapter.spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&fixture->adapter.spy));
    return 0;
}

static int run_p11_hook_vector(
    const ninlil_d3s4_vector_t *vector)
{
    d3s4_hook_fixture_t *fixture = &g_hook_fixture;
    const char *shape;
    ninlil_status_t status;
    size_t port_before;
    ninlil_domain_scan_session_t session_before;
    ninlil_domain_scan_d3s4_context_t context_before;

    REQUIRE(vector->fault_count == 1u);
    shape = vector->faults[0].shape;
    REQUIRE(shape != NULL);
    g_current_id = vector->id;

    if (strcmp(shape, "evaluator_off") == 0) {
        REQUIRE(hook_fixture_begin(fixture, vector, 1u) == 0);
        fixture->adapter.current_call = 1u;
        flush_initial_iter_open(&fixture->adapter);
        status = ninlil_domain_scan_d3s4_drive(
            &fixture->session, 32u);
        REQUIRE(status == NINLIL_OK);
        REQUIRE(fixture->session.state
            == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
        REQUIRE(fixture->context.phase
            == NINLIL_DOMAIN_SCAN_D3S4_PHASE_BASELINE);
        REQUIRE(fixture->session.profile_exact_active == 0u);
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, &fixture->result);
        REQUIRE(status == NINLIL_E_UNSUPPORTED);
        REQUIRE(fixture->result.status == NINLIL_E_UNSUPPORTED);
        REQUIRE(fixture->result.d3s4_disposition_present == 0u);
        REQUIRE(fixture->result.d3s4_disposition == 0u);
        REQUIRE(fixture->session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
        REQUIRE(all_bytes_equal(
            &fixture->context, sizeof(fixture->context), 0u));
        return 0;
    }

    if (strcmp(shape, "invalid_state_pre_finalize") == 0) {
        REQUIRE(hook_fixture_begin(fixture, vector, 0u) == 0);
        port_before = fixture->adapter.spy.trace_count;
        session_before = fixture->session;
        context_before = fixture->context;
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, &fixture->result);
        REQUIRE(status == NINLIL_E_INVALID_STATE);
        REQUIRE(fixture->adapter.spy.trace_count == port_before);
        REQUIRE(memcmp(
            &fixture->session, &session_before,
            sizeof(session_before)) == 0);
        REQUIRE(memcmp(
            &fixture->context, &context_before,
            sizeof(context_before)) == 0);
        REQUIRE(all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
        REQUIRE(hook_fixture_abort_cleanup(fixture) == 0);
        return 0;
    }

    REQUIRE(hook_fixture_begin(fixture, vector, 0u) == 0);
    REQUIRE(hook_fixture_drive_complete(fixture) == 0);

    if (strcmp(shape, "abort") == 0) {
        REQUIRE(ninlil_domain_scan_note_terminal_corrupt(
            &fixture->session) == NINLIL_E_STORAGE_CORRUPT);
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        status = ninlil_domain_scan_d3s4_abort(
            &fixture->session, &fixture->result);
        REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
        REQUIRE(all_bytes_equal(
            &fixture->context, sizeof(fixture->context), 0u));
        return 0;
    }
    if (strcmp(shape, "cleanup_failure") == 0
        || strcmp(shape, "abort_cleanup_failure") == 0) {
        REQUIRE(ninlil_spy_add_fault(
            &fixture->adapter.spy, NINLIL_SPY_OP_ROLLBACK, 1u,
            NINLIL_STORAGE_CORRUPT, NINLIL_SPY_SHAPE_NATURAL,
            0u, 0u));
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        if (strcmp(shape, "cleanup_failure") == 0) {
            status = ninlil_domain_scan_d3s4_finalize(
                &fixture->session, &fixture->result);
        } else {
            status = ninlil_domain_scan_d3s4_abort(
                &fixture->session, &fixture->result);
        }
        REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
        REQUIRE(all_bytes_equal(
            &fixture->context, sizeof(fixture->context), 0u));
        REQUIRE(fixture->adapter.spy.rollback_calls == 1u);
        REQUIRE(fixture->adapter.spy.close_calls == 1u);
        return 0;
    }

    port_before = fixture->adapter.spy.trace_count;
    session_before = fixture->session;
    context_before = fixture->context;
    (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));

    if (strcmp(shape, "NULL") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, NULL);
    } else if (strcmp(shape, "alias_overlap_session") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session,
            (ninlil_domain_scan_result_t *)(void *)&fixture->session);
    } else if (strcmp(shape, "alias_overlap_workspace") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session,
            (ninlil_domain_scan_result_t *)(void *)&fixture->workspace);
    } else if (strcmp(shape, "alias_overlap_ops") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session,
            (ninlil_domain_scan_result_t *)(void *)&fixture->adapter.ops);
    } else if (strcmp(shape, "alias_overlap_handle_slot") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session,
            (ninlil_domain_scan_result_t *)(void *)&fixture->handle);
    } else if (strcmp(shape, "alias_overlap_s4_context") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session,
            (ninlil_domain_scan_result_t *)(void *)&fixture->context);
    } else if (strcmp(shape, "prevalidation_disjoint_violation") == 0) {
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session,
            (ninlil_domain_scan_result_t *)(void *)
                ((uint8_t *)&fixture->context + 1u));
    } else if (strcmp(shape, "incomplete_shape_mid_yield") == 0) {
        fixture->context.flags = (uint8_t)(
            fixture->context.flags
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME
            | NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE);
        context_before = fixture->context;
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, &fixture->result);
    } else if (strcmp(shape, "invalid_carrier_present_gt1") == 0
        || strcmp(shape, "invalid_carrier_present0_disp_nonzero") == 0
        || strcmp(shape, "invalid_carrier_present1_disp_gt3") == 0) {
        ninlil_domain_scan_d3s4_composition_t composition;
        uint8_t present =
            strcmp(shape, "invalid_carrier_present_gt1") == 0 ? 2u
                : strcmp(
                    shape, "invalid_carrier_present0_disp_nonzero") == 0
                ? 0u : 1u;
        uint8_t disposition =
            strcmp(shape, "invalid_carrier_present_gt1") == 0 ? 0u
                : strcmp(
                    shape, "invalid_carrier_present0_disp_nonzero") == 0
                ? 1u : 4u;
        uint8_t out_present = 0xa5u;
        uint8_t out_disposition = 0xa5u;
        ninlil_domain_scan_d3s4_composition_init(&composition);
        composition.disposition_present = present;
        composition.disposition = disposition;
        status = ninlil_domain_scan_d3s4_composition_finish(
            &composition, &out_present, &out_disposition);
        REQUIRE(status == NINLIL_E_INVALID_STATE);
        REQUIRE(composition.accepted_input_count == 0u);
        REQUIRE(out_present == 0xa5u);
        REQUIRE(out_disposition == 0xa5u);
        REQUIRE(fixture->adapter.spy.trace_count == port_before);
        REQUIRE(memcmp(
            &fixture->session, &session_before,
            sizeof(session_before)) == 0);
        REQUIRE(memcmp(
            &fixture->context, &context_before,
            sizeof(context_before)) == 0);
        REQUIRE(hook_fixture_abort_cleanup(fixture) == 0);
        return 0;
    } else {
        (void)fprintf(stderr,
            "%s: unsupported P11 hook shape %s\n",
            g_current_id, shape);
        return 1;
    }

    REQUIRE(status == NINLIL_E_INVALID_STATE);
    REQUIRE(fixture->adapter.spy.trace_count == port_before);
    REQUIRE(memcmp(
        &fixture->session, &session_before, sizeof(session_before)) == 0);
    REQUIRE(memcmp(
        &fixture->context, &context_before, sizeof(context_before)) == 0);
    if (strcmp(shape, "NULL") == 0
        || strcmp(shape, "incomplete_shape_mid_yield") == 0) {
        REQUIRE(all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
    }
    REQUIRE(hook_fixture_abort_cleanup(fixture) == 0);
    return 0;
}

static uint16_t test_load_u16(const uint8_t bytes[2])
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static int configure_iter_duplicate_hook(
    d3s4_port_adapter_t *adapter,
    const ninlil_d3s4_vector_t *vector)
{
    const uint8_t *previous_key = NULL;
    size_t previous_key_length = 0u;
    size_t i;

    for (i = 0u; i < vector->event_count; ++i) {
        const ninlil_d3s4_port_event_t *event = &vector->events[i];
        if (strcmp(event->op, "iter_next") != 0
            || event->returned_key == NULL
            || event->returned_key_len == 0u) {
            previous_key = NULL;
            previous_key_length = 0u;
            continue;
        }
        if (previous_key_length == event->returned_key_len
            && previous_key != NULL
            && memcmp(
                previous_key, event->returned_key,
                event->returned_key_len) == 0) {
            adapter->iter_duplicate_key = event->returned_key;
            adapter->iter_duplicate_key_length =
                event->returned_key_len;
            adapter->enable_iter_duplicate = 1u;
            return 0;
        }
        previous_key = event->returned_key;
        previous_key_length = event->returned_key_len;
    }
    return 1;
}

static int require_clean_exact_get_key_sequence(
    const d3s4_hook_fixture_t *fixture,
    const ninlil_d3s4_vector_t *vector)
{
    size_t event_i = 0u;
    size_t trace_i = 0u;
    size_t expected_count = 0u;
    size_t actual_count = 0u;

    while (event_i < vector->event_count) {
        const ninlil_d3s4_port_event_t *event =
            &vector->events[event_i++];
        const ninlil_spy_trace_t *trace;

        if (strcmp(event->op, "exact_get") != 0) {
            continue;
        }
        while (trace_i < fixture->adapter.spy.trace_count
            && fixture->adapter.spy.trace[trace_i].op
                != NINLIL_SPY_OP_GET) {
            trace_i += 1u;
        }
        REQUIRE(trace_i < fixture->adapter.spy.trace_count);
        trace = &fixture->adapter.spy.trace[trace_i++];
        REQUIRE(trace->request_key_bytes_length == event->request_key_len);
        REQUIRE(event->request_key_len <= NINLIL_SPY_TRACE_KEY_BYTES);
        REQUIRE(memcmp(
            trace->request_key_bytes, event->request_key,
            event->request_key_len) == 0);
        expected_count += 1u;
    }
    while (trace_i < fixture->adapter.spy.trace_count) {
        if (fixture->adapter.spy.trace[trace_i].op
            == NINLIL_SPY_OP_GET) {
            actual_count += 1u;
        }
        trace_i += 1u;
    }
    REQUIRE(actual_count == 0u);
    REQUIRE(fixture->adapter.exact_get_calls == expected_count);
    return 0;
}

static int run_semantic_hook_vector(
    const ninlil_d3s4_vector_t *vector)
{
    d3s4_hook_fixture_t *fixture = &g_hook_fixture;
    const char *shape = vector->hook_shape;
    size_t step = 1u;
    size_t port_before;
    uint8_t disposition;
    ninlil_status_t status;

    if (shape == NULL && vector->fault_count == 1u) {
        shape = vector->faults[0].shape;
    }
    REQUIRE(shape != NULL);
    g_current_id = vector->id;
    REQUIRE(hook_fixture_begin(fixture, vector, 0u) == 0);

    if (strcmp(shape, "m34_iter_duplicate_chunk_key") == 0) {
        REQUIRE(configure_iter_duplicate_hook(
            &fixture->adapter, vector) == 0);
        while (fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->adapter.iter_duplicate_injected == 1u);
        REQUIRE(hook_fixture_expect_corrupt_finalize(fixture) == 0);
        return 0;
    }

    if (strcmp(shape, "baseline_theta_independent") == 0) {
        REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        REQUIRE(fixture->context.pass_kind
            == NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL);
        REQUIRE(fixture->adapter.spy.iter_next_calls
            == (uint32_t)(vector->row_count + 1u));
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(hook_fixture_finalize_derived(
            fixture, &disposition) == 0);
        return 0;
    }

    if (strcmp(shape, "quota_reissue_completed_get") == 0) {
        uint8_t previous_request[NINLIL_SPY_TRACE_KEY_BYTES];
        uint32_t previous_request_length = 0u;
        uint16_t previous_membership_i = 0u;
        size_t observed_gets = 0u;
        (void)memset(previous_request, 0, sizeof(previous_request));
        while (fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 1u, step++) == 0);
            if (fixture->adapter.exact_get_calls > observed_gets) {
                const ninlil_spy_trace_t *latest = NULL;
                size_t trace_i = fixture->adapter.spy.trace_count;
                uint16_t membership_i =
                    test_load_u16(fixture->context.membership_i);
                while (trace_i > 0u) {
                    trace_i -= 1u;
                    if (fixture->adapter.spy.trace[trace_i].op
                        == NINLIL_SPY_OP_GET) {
                        latest = &fixture->adapter.spy.trace[trace_i];
                        break;
                    }
                }
                REQUIRE(latest != NULL);
                if (previous_request_length
                        == latest->request_key_bytes_length
                    && previous_request_length != 0u
                    && memcmp(
                        previous_request, latest->request_key_bytes,
                        previous_request_length) == 0) {
                    REQUIRE(membership_i > previous_membership_i);
                }
                previous_request_length =
                    latest->request_key_bytes_length;
                (void)memcpy(
                    previous_request, latest->request_key_bytes,
                    previous_request_length);
                previous_membership_i = membership_i;
                observed_gets = fixture->adapter.exact_get_calls;
            }
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->context.phase
            == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE);
        /*
         * The authority hook reissues a just-completed chunk get without
         * advancing its membership state.  The production walk may revisit a
         * chunk for another carrier/member, but never as an immediately
         * duplicated request at this one-member-per-carrier fixture.
         */
        REQUIRE(observed_gets == fixture->adapter.exact_get_calls);
        REQUIRE(observed_gets != 0u);
        REQUIRE(hook_fixture_finalize_derived(
            fixture, &disposition) == 0);
        return 0;
    }

    if (strcmp(shape, "invalid_enum_mbz_state") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        fixture->context.phase = 9u;
        port_before = fixture->adapter.spy.trace_count;
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, &fixture->result);
        REQUIRE(status == NINLIL_E_INVALID_STATE);
        REQUIRE(fixture->adapter.spy.trace_count == port_before);
        REQUIRE(all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
        REQUIRE(hook_fixture_abort_cleanup(fixture) == 0);
        return 0;
    }

    if (strcmp(shape, "partial_sticky_bit_violation") == 0
        || strcmp(shape, "deferred_without_progressed_supersede") == 0) {
        while (fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->context.phase
            == NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE);
        REQUIRE(fixture->context.group_class
            == NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED);
        REQUIRE((fixture->context.flags
            & NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN) != 0u);
        REQUIRE((fixture->context.binding_complete_mask
            & NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED) != 0u);
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED)
            == 0);
        return 0;
    }

    if (strcmp(shape, "member_surface_corrupt_OLD") == 0
        || strcmp(shape, "member_surface_corrupt_NEITHER") == 0
        || strcmp(shape, "member_surface_corrupt_PROGRESSED") == 0) {
        while (fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->context.phase
            == NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE);
        if (strcmp(shape, "member_surface_corrupt_OLD") == 0) {
            fixture->context.group_class =
                NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD;
        } else if (strcmp(
                shape, "member_surface_corrupt_NEITHER") == 0) {
            fixture->context.group_class =
                NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET;
        } else {
            fixture->context.group_class =
                NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED;
            fixture->context.flags = (uint8_t)(
                fixture->context.flags
                & (uint8_t)~NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN);
            fixture->context.binding_complete_mask = (uint8_t)(
                fixture->context.binding_complete_mask
                & (uint8_t)~NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED);
        }
        REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        REQUIRE(hook_fixture_expect_corrupt_finalize(fixture) == 0);
        return 0;
    }

    if (strcmp(shape, "pin_digest_b_omitted") == 0
        || strcmp(shape, "pin_digest_a_reuse_for_index") == 0
        || strcmp(
            shape, "request_scratch_overwrite_membership_target_a") == 0
        || strcmp(
            shape, "request_scratch_overwrite_membership_target_b") == 0) {
        while (!(fixture->context.phase
                    == NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM
                && fixture->context.arm_cursor == 5u)
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->context.arm_cursor == 5u);
        REQUIRE(fixture->context.membership_need_mask == 3u);
        if (strcmp(shape, "pin_digest_b_omitted") == 0) {
            (void)memset(fixture->context.pin_digest_b, 0, 32u);
        } else if (strcmp(
                shape, "pin_digest_a_reuse_for_index") == 0) {
            (void)memcpy(
                fixture->context.pin_digest_b,
                fixture->context.pin_digest_a, 32u);
        } else if (strcmp(
                shape,
                "request_scratch_overwrite_membership_target_a") == 0) {
            fixture->context.membership_key_a[0] ^= 0xffu;
        } else {
            fixture->context.peer_key[0] ^= 0xffu;
        }
        while (fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(hook_fixture_expect_corrupt_finalize(fixture) == 0);
        return 0;
    }

    if (strcmp(shape, "fault_script") == 0) {
        while (!(fixture->context.phase
                    == NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM
                && fixture->context.arm_cursor == 1u)
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(test_load_u16(
            fixture->context.expected_primary_raw_len) > 0u);
        fixture->context.expected_primary_raw[0] ^= 0x01u;
        REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        REQUIRE(hook_fixture_expect_corrupt_finalize(fixture) == 0);
        return 0;
    }

    if (strcmp(shape, "dual_first_hit_early_exit") == 0) {
        while (!(fixture->context.phase
                    == NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM
                && fixture->context.arm_cursor == 5u
                && fixture->context.membership_substep == 1u)
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(test_load_u16(fixture->context.membership_i)
            == test_load_u16(fixture->context.member_count));
        REQUIRE(fixture->context.found_count_a
            == ((fixture->context.membership_need_mask & 1u) != 0u
                ? 1u : 0u));
        REQUIRE(fixture->context.found_count_b
            == ((fixture->context.membership_need_mask & 2u) != 0u
                ? 1u : 0u));
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_LOCAL_COMPLETE) == 0);
        return 0;
    }

    if (strcmp(shape, "per_carrier_arm_bit_set") == 0) {
        while (!(fixture->context.phase
                    == NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM
                && fixture->context.arm_cursor == 6u)
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->context.count_complete_mask == 0u);
        REQUIRE(fixture->context.binding_complete_mask == 0u);
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(fixture->context.count_complete_mask
            == NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE34);
        REQUIRE((fixture->context.binding_complete_mask
            & NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_ALL) != 0u);
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_LOCAL_COMPLETE) == 0);
        return 0;
    }

    if (strcmp(shape, "request_scratch_overwrite_live") == 0) {
        while (fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE
            && fixture->context.phase
                != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
            && step < 8192u) {
            REQUIRE(hook_fixture_step(fixture, 32u, step++) == 0);
            REQUIRE(test_load_u16(
                fixture->context.expected_primary_raw_len) == 0u);
        }
        REQUIRE(step < 8192u);
        REQUIRE(fixture->context.phase
            == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE);
        REQUIRE(hook_fixture_finalize_derived(
            fixture, &disposition) == 0);
        return 0;
    }

    if (strcmp(shape, "whole_result_poison_alias") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, &fixture->result);
        REQUIRE(status == NINLIL_OK);
        REQUIRE(fixture->result.status == NINLIL_OK);
        REQUIRE(fixture->result.d3s4_disposition_present == 1u);
        REQUIRE(!all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
        REQUIRE(all_bytes_equal(
            &fixture->context, sizeof(fixture->context), 0u));
        return 0;
    }

    if (strcmp(shape, "m34_prior_session_manifest") == 0) {
        /*
         * hook_fixture_begin pre-poisons all 949 bytes before the real begin.
         * Successful current-session proof therefore demonstrates that no
         * prior-session manifest cache survives initialization.
         */
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_LOCAL_COMPLETE) == 0);
        return 0;
    }

    if (strcmp(shape, "m33_skip_retired_header_inventory") == 0
        || strcmp(shape, "m33_bit5_lost_subpass_transition") == 0
        || strcmp(shape, "m33_bit5_lost_exhaustion") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(fixture->adapter.iter_open_calls == 3u);
        REQUIRE((fixture->context.binding_complete_mask
            & NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE33) != 0u);
        REQUIRE((fixture->context.binding_complete_mask
            & NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED) != 0u);
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S6_REQUIRED) == 0);
        return 0;
    }

    if (strcmp(shape, "m33_successor_exact_get_walk") == 0
        || strcmp(shape, "m33_incoming_exact_get_walk") == 0) {
        size_t required_header_gets = 0u;
        size_t row_i;
        for (row_i = 0u; row_i < vector->row_count; ++row_i) {
            if (vector->rows[row_i].family == 6
                && vector->rows[row_i].subtype == 126) {
                required_header_gets += 1u;
            }
        }
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        /*
         * Mode33 performs exactly one mandatory header bind per chunk.
         * There is no additional successor/incoming-reference local walk.
         */
        REQUIRE(fixture->adapter.exact_get_calls
            == required_header_gets);
        REQUIRE(hook_fixture_finalize_derived(
            fixture, &disposition) == 0);
        return 0;
    }

    if (strcmp(shape, "illegal_deferred_shape_11_reject") == 0
        || strcmp(
            shape, "m31_32_retirement_eligibility_local_proof") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        if (strcmp(
                shape,
                "m31_32_retirement_eligibility_local_proof") == 0) {
            /*
             * Run the clean production classifier and compare its complete
             * GET-key sequence.  The final predecessor-header GET is the
             * mandatory SUPERSEDE member read; no successor, incoming, or
             * retirement-eligibility probe may follow it.
             */
            REQUIRE(require_clean_exact_get_key_sequence(
                fixture, vector) == 0);
        }
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED)
            == 0);
        return 0;
    }

    if (strcmp(shape, "empty_arm_a_blocks_global") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(fixture->context.count_complete_mask
            == NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE34);
        REQUIRE((fixture->context.binding_complete_mask
            & (NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_A
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_B
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_C
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_ALL))
            == (NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_A
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_B
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_C
                | NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_ALL));
        REQUIRE(hook_fixture_finalize_success(
            fixture,
            NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_LOCAL_COMPLETE) == 0);
        return 0;
    }

    if (strcmp(shape, "incomplete_required_mask") == 0
        || strcmp(shape, "complete_ready_with_deferred") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        if (strcmp(shape, "incomplete_required_mask") == 0) {
            fixture->context.count_complete_mask ^= 1u;
        } else {
            fixture->context.flags = (uint8_t)(
                fixture->context.flags
                | NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN
                | NINLIL_DOMAIN_SCAN_D3S4_FLAG_COMPLETE_READY);
        }
        port_before = fixture->adapter.spy.trace_count;
        (void)memset(&fixture->result, 0xa5, sizeof(fixture->result));
        status = ninlil_domain_scan_d3s4_finalize(
            &fixture->session, &fixture->result);
        REQUIRE(status == NINLIL_E_INVALID_STATE);
        REQUIRE(fixture->adapter.spy.trace_count == port_before);
        REQUIRE(all_bytes_equal(
            &fixture->result, sizeof(fixture->result), 0xa5u));
        REQUIRE(hook_fixture_abort_cleanup(fixture) == 0);
        return 0;
    }

    if (strcmp(shape, "incomplete_finalize_baseline") == 0) {
        REQUIRE(hook_fixture_drive_complete(fixture) == 0);
        REQUIRE(fixture->context.pass_kind
            == NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL);
        REQUIRE((fixture->context.binding_complete_mask
            & NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE33) != 0u);
        REQUIRE(hook_fixture_finalize_derived(
            fixture, &disposition) == 0);
        return 0;
    }

    (void)fprintf(stderr,
        "%s: unsupported semantic hook shape %s\n",
        g_current_id, shape);
    return 1;
}

static int run_production_vector(
    const ninlil_d3s4_vector_t *vector,
    uint8_t enable_declared_fault)
{
    d3s4_port_adapter_t *adapter = &g_adapter;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s4_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_status_t actual = NINLIL_E_INVALID_STATE;
    size_t i;

    g_current_id = vector->id;
    adapter_init(adapter, vector);
    adapter->enable_declared_fault = enable_declared_fault;
    REQUIRE(install_profile_rows(adapter, &candidate));
    REQUIRE(add_sorted_rows(adapter, vector));
    handle = ninlil_spy_open_handle(&adapter->spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0xa5, sizeof(context));
    (void)memset(&result, 0, sizeof(result));

    for (i = 0u; i < vector->call_count; ++i) {
        const ninlil_d3s4_call_t *call = &vector->calls[i];
        ninlil_status_t expected;

        adapter->current_call = i;
        REQUIRE((size_t)call->trace_begin == adapter->event_index);
        REQUIRE(status_from_name(call->returned_status, &expected));
        if (strcmp(call->op, "begin") == 0) {
            actual = ninlil_domain_scan_begin_profiled_d3s4(
                &session, &adapter->ops, &handle, &workspace,
                &candidate, (uint8_t)vector->mode, &context);
        } else if (strcmp(call->op, "drive") == 0) {
            if (i == 1u) {
                flush_initial_iter_open(adapter);
            }
            actual = ninlil_domain_scan_d3s4_drive(
                &session, (uint16_t)call->drive_get_quota);
        } else if (strcmp(call->op, "resume") == 0) {
            actual = ninlil_domain_scan_d3s4_resume(
                &session, (uint16_t)call->drive_get_quota);
        } else if (strcmp(call->op, "finalize") == 0) {
            actual = ninlil_domain_scan_finalize(&session, &result);
        } else if (strcmp(call->op, "abort") == 0) {
            actual = ninlil_domain_scan_abort(&session, &result);
        } else if (strcmp(call->op, "compose") == 0) {
            ninlil_domain_scan_result_t compose_result;
            ninlil_domain_scan_d3s4_composition_t composition;
            uint8_t composed_present = 0xa5u;
            uint8_t composed_disposition = 0xa5u;

            REQUIRE(vector->compose_session_m33 != NULL);
            REQUIRE(vector->compose_input_count == 2);
            REQUIRE(run_compose_session(
                vector, vector->compose_session_m33,
                &compose_result) == 0);
            ninlil_domain_scan_d3s4_composition_init(&composition);
            REQUIRE(ninlil_domain_scan_d3s4_composition_add(
                &composition, result.status,
                result.d3s4_disposition_present,
                result.d3s4_disposition) == NINLIL_OK);
            REQUIRE(ninlil_domain_scan_d3s4_composition_add(
                &composition, compose_result.status,
                compose_result.d3s4_disposition_present,
                compose_result.d3s4_disposition) == NINLIL_OK);
            REQUIRE(composition.accepted_input_count
                == (uint8_t)vector->compose_input_count);
            actual = ninlil_domain_scan_d3s4_composition_finish(
                &composition, &composed_present, &composed_disposition);
            REQUIRE((int)composed_present
                == vector->compose_output_present);
            REQUIRE((int)composed_disposition
                == vector->compose_output_disp);
        } else {
            (void)fprintf(stderr,
                "%s: unsupported production call %s\n",
                g_current_id, call->op);
            return 1;
        }
        if (actual != expected) {
            (void)fprintf(stderr,
                "%s: call=%zu op=%s status want=%d got=%d\n",
                g_current_id, i, call->op, (int)expected, (int)actual);
            return 1;
        }
        REQUIRE(adapter->failed == 0u);
        if ((size_t)call->trace_end != adapter->event_index) {
            (void)fprintf(stderr,
                "%s: call=%zu op=%s trace-end want=%d got=%zu\n",
                g_current_id, i, call->op, call->trace_end,
                adapter->event_index);
            return 1;
        }
        REQUIRE(compare_context(call, &context, i));
    }
    REQUIRE(adapter->held_initial_iter_open == 0u);
    REQUIRE(adapter->event_index == vector->event_count);
    REQUIRE(adapter->spy.trace_overflow == 0u);
    REQUIRE(adapter->spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&adapter->spy));
    if (enable_declared_fault != 0u) {
        REQUIRE(adapter->declared_fault_consumed == 1u);
    }
    REQUIRE(vector->disposition_present
        == (int)result.d3s4_disposition_present);
    if (vector->disposition_present != 0) {
        REQUIRE(vector->disposition == (int)result.d3s4_disposition);
    }
    return 0;
}

static int run_formal_d1_precheck_vector(
    const ninlil_d3s4_vector_t *vector)
{
    d3s4_port_adapter_t *adapter = &g_adapter;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s4_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_status_t expected;
    ninlil_status_t actual;
    size_t calls = 0u;

    g_current_id = vector->id;
    REQUIRE(vector->formal_class != NULL);
    REQUIRE(strcmp(vector->formal_class, "d1_mutation") == 0);
    REQUIRE(vector->execution_scope != NULL);
    REQUIRE(strcmp(
        vector->execution_scope, "formal_precheck_only") == 0);
    REQUIRE(vector->precheck_status != NULL);
    REQUIRE(vector->precheck_error != NULL);
    REQUIRE(vector->precheck_error[0] != '\0');
    REQUIRE(vector->formal_reason != NULL);
    REQUIRE(vector->first_reason != NULL);
    REQUIRE(strcmp(vector->formal_reason, vector->first_reason) == 0);
    REQUIRE(status_from_name(vector->precheck_status, &expected));
    REQUIRE(expected == NINLIL_E_STORAGE_CORRUPT);

    adapter_init(adapter, vector);
    adapter->suppress_authority_events = 1u;
    REQUIRE(install_profile_rows(adapter, &candidate));
    REQUIRE(add_sorted_rows(adapter, vector));
    handle = ninlil_spy_open_handle(&adapter->spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0xa5, sizeof(context));
    (void)memset(&result, 0xa5, sizeof(result));

    actual = ninlil_domain_scan_begin_profiled_d3s4(
        &session, &adapter->ops, &handle, &workspace,
        &candidate, (uint8_t)vector->mode, &context);
    REQUIRE(actual == NINLIL_OK);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_BASELINE);
    REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S4_PASS_BASELINE);
    REQUIRE(adapter->iter_open_calls == 1u);

    /*
     * REP1 first exhausts the coarse baseline, then re-decodes D1 before the
     * S4 row hook on the internal pass.  Drive only until that real structural
     * rejection; never execute the downstream formal-mutation oracle.
     */
    actual = NINLIL_OK;
    while ((session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN
            || session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED)
        && calls < 4096u) {
        adapter->current_call = calls + 1u;
        if ((context.flags
                & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) != 0u) {
            actual = ninlil_domain_scan_d3s4_resume(&session, 32u);
        } else {
            actual = ninlil_domain_scan_d3s4_drive(&session, 32u);
        }
        if (actual != NINLIL_OK) {
            break;
        }
        calls += 1u;
    }
    REQUIRE(calls < 4096u);
    /*
     * A discovering S4 hook publishes sticky FAILED and returns OK; a D2
     * structural rejection may return the sticky status directly.  Both
     * converge on the same terminal Runtime result below.
     */
    REQUIRE(actual == NINLIL_OK || actual == expected);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED);
    REQUIRE(context.group_class == NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT);
    REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S4_PASS_BASELINE
        || context.pass_kind == NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL);
    if (context.pass_kind == NINLIL_DOMAIN_SCAN_D3S4_PASS_BASELINE) {
        REQUIRE(session.profile_exact_active == 0u);
        REQUIRE(adapter->iter_open_calls == 1u);
    } else {
        REQUIRE(session.profile_exact_active == 1u);
        REQUIRE(adapter->iter_open_calls >= 2u);
    }
    REQUIRE(adapter->spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&adapter->spy));

    adapter->current_call = calls + 2u;
    actual = ninlil_domain_scan_d3s4_finalize(&session, &result);
    REQUIRE(actual == expected);
    REQUIRE(result.status == expected);
    REQUIRE(adapter->spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&adapter->spy));
    return 0;
}

static int verify_mode33_formal_metadata(
    const ninlil_d3s4_vector_t *vector)
{
    g_current_id = vector->id;
    REQUIRE(vector->execution_scope != NULL);
    REQUIRE(strcmp(
        vector->execution_scope, "formal_precheck_only") == 0);
    REQUIRE(vector->formal_class != NULL);
    REQUIRE(strcmp(
        vector->formal_class, "mode33_manifest_formal") == 0);
    REQUIRE(vector->precheck_status != NULL);
    REQUIRE(strcmp(vector->precheck_status, "FORMAL_ONLY") == 0);
    REQUIRE(vector->precheck_error != NULL);
    REQUIRE(strcmp(
        vector->precheck_error,
        "mode33_full_manifest_sha_not_runtime_owned") == 0);
    REQUIRE(vector->formal_reason != NULL);
    REQUIRE(vector->first_reason != NULL);
    REQUIRE(strcmp(vector->formal_reason, vector->first_reason) == 0);
    return 0;
}

static int run_cross_mode_origin_vector(
    const ninlil_d3s4_vector_t *vector)
{
    d3s4_port_adapter_t *adapter = &g_adapter;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s4_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_status_t expected;
    ninlil_status_t actual;
    size_t calls = 0u;

    g_current_id = vector->id;
    REQUIRE(vector->cross_mode_class != NULL);
    REQUIRE(strcmp(
        vector->cross_mode_class,
        "mode33_present_bind_mode31_missing_set") == 0);
    REQUIRE(vector->mode
        == NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS);
    REQUIRE(vector->cross_mode_origin_mode
        == NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND);
    REQUIRE(vector->cross_mode_origin_status != NULL);
    REQUIRE(status_from_name(vector->cross_mode_origin_status, &expected));

    adapter_init(adapter, vector);
    adapter->suppress_authority_events = 1u;
    REQUIRE(install_profile_rows(adapter, &candidate));
    REQUIRE(add_sorted_rows(adapter, vector));
    handle = ninlil_spy_open_handle(&adapter->spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0xa5, sizeof(context));
    (void)memset(&result, 0xa5, sizeof(result));

    actual = ninlil_domain_scan_begin_profiled_d3s4(
        &session, &adapter->ops, &handle, &workspace, &candidate,
        (uint8_t)vector->cross_mode_origin_mode, &context);
    REQUIRE(actual == NINLIL_OK);
    while (context.phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE
        && context.phase != NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED
        && calls < 4096u) {
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN
            || session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
        adapter->current_call = calls + 1u;
        if ((context.flags
                & NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME) != 0u) {
            actual = ninlil_domain_scan_d3s4_resume(&session, 32u);
        } else {
            actual = ninlil_domain_scan_d3s4_drive(&session, 32u);
        }
        REQUIRE(actual == NINLIL_OK);
        calls += 1u;
    }
    REQUIRE(calls < 4096u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE);
    REQUIRE(context.binding_complete_mask
        == NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE33);
    REQUIRE(adapter->iter_open_calls == 3u);

    adapter->current_call = calls + 1u;
    actual = ninlil_domain_scan_d3s4_finalize(&session, &result);
    REQUIRE(actual == expected);
    REQUIRE((int)result.d3s4_disposition_present
        == vector->cross_mode_origin_disposition_present);
    REQUIRE((int)result.d3s4_disposition
        == vector->cross_mode_origin_disposition);
    REQUIRE(adapter->spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&adapter->spy));
    return 0;
}

/*
 * Fault vectors are typed and counted now, but not silently passed as
 * production.  Their fault shapes are reference-machine mutation hooks
 * (not Storage Port faults), so a production hook adapter is required before
 * this function may return success.  Keeping it RED protects against claiming
 * a 185/185 bridge while those semantics are absent.
 */
static int fault_vector_requires_closed_hook(
    const ninlil_d3s4_vector_t *vector)
{
    size_t i;
    if (vector->hook_class != NULL || vector->hook_shape != NULL) {
        if (vector->hook_class == NULL || vector->hook_shape == NULL) {
            (void)fprintf(stderr,
                "%s: incomplete typed hook carrier\n", vector->id);
            return -1;
        }
        return 1;
    }
    if (vector->faults == NULL || vector->fault_count == 0u) {
        return 0;
    }
    for (i = 0u; i < vector->fault_count; ++i) {
        if (vector->faults[i].op == NULL
            || vector->faults[i].shape == NULL
            || vector->faults[i].status == NULL) {
            (void)fprintf(stderr,
                "%s: malformed typed fault carrier %zu\n",
                vector->id, i);
            return -1;
        }
    }
    return 1;
}

static int is_exact_get_storage_fault(
    const ninlil_d3s4_vector_t *vector)
{
    size_t occurrence = 0u;
    size_t i;

    if (vector->fault_count != 1u
        || vector->faults == NULL
        || strcmp(vector->faults[0].op, "exact_get") != 0
        || strcmp(
            vector->faults[0].shape, "m31_32_primary_fault") != 0) {
        return 0;
    }
    for (i = 0u; i < vector->event_count; ++i) {
        const ninlil_d3s4_port_event_t *event = &vector->events[i];
        if (strcmp(event->op, "exact_get") != 0) {
            continue;
        }
        if (occurrence == (size_t)vector->faults[0].on_call) {
            return event->storage_status != NULL
                && strcmp(event->storage_status, "FAULT") == 0;
        }
        occurrence += 1u;
    }
    return 0;
}

int main(void)
{
    size_t i;
    size_t production_count = 0u;
    size_t formal_d1_count = 0u;
    size_t formal_mode33_count = 0u;
    size_t cross_mode_count = 0u;
    size_t compose_count = 0u;
    size_t fault_production_count = 0u;
    size_t p11_count = 0u;
    size_t semantic_hook_count = 0u;
    size_t pending_count = 0u;

    REQUIRE(sizeof(ninlil_domain_scan_d3s4_context_t) == 949u);
    REQUIRE(_Alignof(ninlil_domain_scan_d3s4_context_t) == 1u);
    REQUIRE(D3S4_PREFIX_COUNT + NINLIL_D3S4_SUFFIX_COUNT
        == D3S4_TOTAL_COUNT);
    /*
     * Independent C-side pins for the fully expanded authority.  The fixture
     * generator emits the recomputed manifest values; these literals prevent a
     * coherently edited Python manifest/generator pair from silently changing
     * count, order, negative cases, or expanded bytes.
     */
    REQUIRE((size_t)NINLIL_D3S4_EXPANDED_VECTOR_COUNT
        == D3S4_TOTAL_COUNT);
    REQUIRE((size_t)NINLIL_D3S4_EXPANDED_NEGATIVE_COUNT
        == D3S4_EXPECTED_NEGATIVE_COUNT);
    REQUIRE(strcmp(
        NINLIL_D3S4_EXPANDED_CONTENT_SHA256,
        D3S4_EXPECTED_CONTENT_SHA256) == 0);
    REQUIRE(strcmp(
        NINLIL_D3S4_EXPANDED_ORDER_SHA256,
        D3S4_EXPECTED_ORDER_SHA256) == 0);
    REQUIRE(strcmp(
        NINLIL_D3S4_EXPANDED_NEGATIVE_SHA256,
        D3S4_EXPECTED_NEGATIVE_SHA256) == 0);
    REQUIRE(strcmp(
        NINLIL_D3S4_EXPANDED_CANONICAL_SHA256,
        D3S4_EXPECTED_CANONICAL_SHA256) == 0);
    REQUIRE(verify_composition_contract() == 0);

    for (i = 0u; i < NINLIL_D3S4_SUFFIX_COUNT; ++i) {
        const ninlil_d3s4_vector_t *vector = &ninlil_d3s4_vectors[i];
        int fault_lane;
        g_current_id = vector->id;
        REQUIRE(vector->formal_class != NULL);
        if (strcmp(vector->formal_class, "d1_mutation") == 0) {
            REQUIRE(run_formal_d1_precheck_vector(vector) == 0);
            formal_d1_count += 1u;
            continue;
        }
        if (strcmp(
                vector->formal_class,
                "mode33_manifest_formal") == 0) {
            REQUIRE(verify_mode33_formal_metadata(vector) == 0);
            formal_mode33_count += 1u;
            continue;
        }
        REQUIRE(strcmp(vector->formal_class, "ordinary") == 0);
        fault_lane = fault_vector_requires_closed_hook(vector);
        REQUIRE(fault_lane >= 0);
        if (fault_lane != 0) {
            if (vector->fault_count == 1u
                && (strcmp(vector->faults[0].op, "finalize") == 0
                    || strcmp(vector->faults[0].op, "abort") == 0)) {
                REQUIRE(run_p11_hook_vector(vector) == 0);
                production_count += 1u;
                p11_count += 1u;
                continue;
            }
            if (is_exact_get_storage_fault(vector)) {
                REQUIRE(run_production_vector(vector, 1u) == 0);
                production_count += 1u;
                fault_production_count += 1u;
                continue;
            }
            REQUIRE(run_semantic_hook_vector(vector) == 0);
            production_count += 1u;
            semantic_hook_count += 1u;
            continue;
        }
        REQUIRE(run_production_vector(vector, 0u) == 0);
        production_count += 1u;
        if (strcmp(
                vector->calls[vector->call_count - 1u].op,
                "compose") == 0) {
            compose_count += 1u;
        }
        if (vector->cross_mode_class != NULL) {
            REQUIRE(run_cross_mode_origin_vector(vector) == 0);
            cross_mode_count += 1u;
        }
    }

    if (production_count + formal_d1_count + formal_mode33_count
            + pending_count
        != NINLIL_D3S4_SUFFIX_COUNT) {
        (void)fprintf(stderr,
            "D3-S4 bridge count drift production=%zu formal-d1=%zu "
            "formal-mode33=%zu pending=%zu total=%zu\n",
            production_count, formal_d1_count, formal_mode33_count,
            pending_count,
            (size_t)NINLIL_D3S4_SUFFIX_COUNT);
        return 1;
    }
    REQUIRE(formal_d1_count == 29u);
    REQUIRE(formal_mode33_count == 2u);
    REQUIRE(cross_mode_count == 1u);
    REQUIRE(compose_count == 1u);
    if (pending_count != 0u) {
        (void)fprintf(stderr,
            "D3-S4 bridge intentionally RED: production=%zu, "
            "formal-d1=%zu, formal-mode33=%zu, cross-mode=%zu, compose=%zu, "
            "fault-production=%zu, p11=%zu, semantic-hook=%zu, "
            "closed-hook/compose pending=%zu\n",
            production_count, formal_d1_count, formal_mode33_count,
            cross_mode_count, compose_count, fault_production_count,
            p11_count, semantic_hook_count, pending_count);
        return 1;
    }

    (void)printf(
        "domain_store_scanner_crossrow_d3s4_oracle_bridge OK "
        "(authority=%zu prefix=%zu suffix=%zu production=%zu "
        "formal-d1=%zu formal-mode33=%zu cross-mode=%zu compose=%zu "
        "fault-production=%zu p11=%zu semantic-hook=%zu)\n",
        D3S4_TOTAL_COUNT, D3S4_PREFIX_COUNT,
        (size_t)NINLIL_D3S4_SUFFIX_COUNT, production_count,
        formal_d1_count, formal_mode33_count, cross_mode_count,
        compose_count, fault_production_count, p11_count,
        semantic_hook_count);
    return 0;
}
