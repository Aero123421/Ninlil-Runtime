#include "domain_store_scanner.h"

#include "domain_store_codec.h"
#include "runtime_store_codec.h"
#include "scripted_storage_spy.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t ROOT_V1[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

static uint32_t crc32c_bytes(const uint8_t *data, uint32_t length)
{
    return ninlil_model_domain_crc32c(data, length);
}

static void write_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint32_t build_nlr1(
    uint8_t *out,
    uint32_t capacity,
    uint16_t record_type,
    uint16_t record_version,
    const uint8_t *payload,
    uint32_t payload_length)
{
    uint32_t total;
    uint32_t crc;

    total = 16u + payload_length;
    if (total > capacity) {
        return 0u;
    }
    out[0] = (uint8_t)'N';
    out[1] = (uint8_t)'L';
    out[2] = (uint8_t)'R';
    out[3] = (uint8_t)'1';
    write_u16_be(&out[4], record_type);
    write_u16_be(&out[6], record_version);
    write_u32_be(&out[8], payload_length);
    if (payload_length != 0u) {
        (void)memcpy(&out[12], payload, payload_length);
    }
    crc = crc32c_bytes(out, 12u + payload_length);
    write_u32_be(&out[12u + payload_length], crc);
    return total;
}

static int make_family14_key(
    ninlil_model_runtime_store_key_id_t id,
    uint8_t *out,
    uint32_t *out_len)
{
    ninlil_model_runtime_store_key_t key;
    if (ninlil_model_runtime_store_build_key(id, &key) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, key.bytes, key.length);
    *out_len = key.length;
    return 1;
}

static int make_current_domain_key(uint8_t *out, uint32_t *out_len)
{
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t identity;
    uint8_t id[16];

    (void)memset(id, 0x44, sizeof(id));
    identity.data = id;
    identity.length = 16u;
    if (ninlil_model_domain_build_key(
            NINLIL_MODEL_DOMAIN_FAMILY_HEALTH,
            NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT,
            NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
            identity,
            &key) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, key.bytes, key.length);
    *out_len = key.length;
    return 1;
}

static int make_future_key(uint8_t *out, uint32_t *out_len)
{
    (void)memcpy(out, ROOT_V1, 8u);
    out[7] = 0x02u;
    out[8] = 0x10u;
    out[9] = 0x20u;
    out[10] = 0x01u;
    out[11] = 0x01u;
    out[12] = 0x00u;
    *out_len = 13u;
    return 1;
}

static int make_future_value(uint8_t *out, uint32_t *out_len)
{
    uint8_t payload[4] = {0x01u, 0x02u, 0x03u, 0x04u};
    uint32_t length = build_nlr1(out, 64u, 6u, 2u, payload, 4u);
    if (length == 0u) {
        return 0;
    }
    *out_len = length;
    return 1;
}

static int make_malformed_current_key(uint8_t *out, uint32_t *out_len)
{
    (void)memcpy(out, ROOT_V1, 8u);
    out[8] = 0x06u;
    out[9] = 0x10u;
    *out_len = 10u;
    return 1;
}

static int scan_to_end(
    ninlil_domain_scan_session_t *session,
    uint32_t budget)
{
    ninlil_status_t status;

    for (;;) {
        if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            break;
        }
        status = ninlil_domain_scan_advance(session, budget);
        if (status != NINLIL_OK) {
            return (int)status;
        }
        if (session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
            return 0;
        }
        if (session->state == NINLIL_DOMAIN_SCAN_STATE_FAILED) {
            return (int)session->sticky_primary;
        }
    }
    return (int)NINLIL_E_INVALID_STATE;
}

/* --- normal cases --- */

static int test_empty_namespace(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0xA5, sizeof(workspace));
    (void)memset(&result, 0x5A, sizeof(result));

    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.bound_storage == ops);
    REQUIRE(session.bound_handle_slot == &handle);
    REQUIRE(session.bound_workspace == &workspace);
    REQUIRE(session.bound_handle_value == handle);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.ok_row_count == 0u);
    REQUIRE(result.recognizable_future_seen == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    /* S1 transport begin: get exactly zero (hard gate; independent of mutation). */
    REQUIRE(spy.get_calls == 0u);
    REQUIRE(ninlil_spy_call_count(&spy, NINLIL_SPY_OP_GET) == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    REQUIRE(ninlil_spy_iter_close_before_rollback(&spy));
    REQUIRE(ninlil_spy_call_count(&spy, NINLIL_SPY_OP_BEGIN) == 1u);
    REQUIRE(spy.trace[0].mode == NINLIL_STORAGE_READ_ONLY);
    return 0;
}

static int test_family14_and_current(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[32];
    uint8_t value[64];
    uint32_t key_len = 0u;
    uint32_t value_len = 0u;
    uint8_t empty_value[1] = {0};

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);

    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &key_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, empty_value, 0u));
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, key, &key_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, empty_value, 0u));
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION, key, &key_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, empty_value, 0u));
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE, key, &key_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, empty_value, 0u));
    REQUIRE(make_current_domain_key(key, &key_len));
    value_len = build_nlr1(value, sizeof(value), 5u, 1u, empty_value, 0u);
    REQUIRE(value_len != 0u);
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, value, value_len));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.family14_row_count == 4u);
    REQUIRE(result.current_domain_key_count == 1u);
    REQUIRE(result.ok_row_count == 5u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_future_then_end(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[32];
    uint8_t value[64];
    uint32_t key_len = 0u;
    uint32_t value_len = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(make_future_key(key, &key_len));
    REQUIRE(make_future_value(value, &value_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, value, value_len));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 8u) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.recognizable_future_seen == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_budget_1_and_64(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[16];
    uint8_t empty = 0u;
    uint32_t len = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.ok_row_count == 1u);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.ok_row_count == 3u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    return 0;
}

/*
 * 65-row budget boundary:
 *   advance(64) -> OPEN, ok=64, iter_next=64 (no NOT_FOUND)
 *   advance(1)  -> OPEN, ok=65, iter_next=65 (row65 only; budget consumed)
 *   advance(1)  -> EXHAUSTED, iter_next=66 (NOT_FOUND)
 */
static int test_65_rows_budget_boundary(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint32_t i;
    uint8_t empty = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);

    for (i = 0u; i < 65u; ++i) {
        ninlil_model_domain_key_t dkey;
        ninlil_bytes_view_t identity;
        uint8_t id[8];
        (void)memset(id, 0, sizeof(id));
        id[0] = (uint8_t)(i >> 24);
        id[1] = (uint8_t)(i >> 16);
        id[2] = (uint8_t)(i >> 8);
        id[3] = (uint8_t)i;
        identity.data = id;
        identity.length = 8u;
        REQUIRE(ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
                NINLIL_MODEL_DOMAIN_ID_KIND_U64,
                identity,
                &dkey) == NINLIL_OK);
        REQUIRE(ninlil_spy_add_row(
            &spy, dkey.bytes, dkey.length, &empty, 0u));
    }

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);

    REQUIRE(ninlil_domain_scan_advance(&session, 64u) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.ok_row_count == 64u);
    REQUIRE(spy.iter_next_calls == 64u);

    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.ok_row_count == 65u);
    REQUIRE(spy.iter_next_calls == 65u);

    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.ok_row_count == 65u);
    REQUIRE(spy.iter_next_calls == 66u);

    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.ok_row_count == 65u);
    REQUIRE(result.current_domain_key_count == 65u);
    return 0;
}

/* --- causal negatives --- */

static int test_future_then_malformed_corrupt(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[32];
    uint8_t value[64];
    uint32_t key_len = 0u;
    uint32_t value_len = 0u;
    uint8_t empty = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);

    REQUIRE(make_future_key(key, &key_len));
    REQUIRE(make_future_value(value, &value_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, value, value_len));
    (void)memcpy(key, ROOT_V1, 8u);
    key[7] = 0x02u;
    key[8] = 0xFFu;
    key_len = 9u;
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, &empty, 0u));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 8u) == (int)NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.recognizable_future_seen == 1u);
    return 0;
}

static int test_malformed_then_future_stops_before_future(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[32];
    uint8_t value[64];
    uint32_t key_len = 0u;
    uint32_t value_len = 0u;
    uint8_t empty = 0u;
    uint32_t next_calls_at_fail;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);

    REQUIRE(make_malformed_current_key(key, &key_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, &empty, 0u));
    REQUIRE(make_future_key(key, &key_len));
    REQUIRE(make_future_value(value, &value_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, value, value_len));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 8u)
        == NINLIL_E_STORAGE_CORRUPT);
    next_calls_at_fail = spy.iter_next_calls;
    REQUIRE(next_calls_at_fail == 1u);
    REQUIRE(session.recognizable_future_seen == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.iter_next_calls == next_calls_at_fail);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    return 0;
}

/*
 * Distinct causality for candidate override: future row accepted first
 * (candidate flag set, still OPEN), then malformed terminal replaces outcome
 * while candidate flag remains observable on unadopted result.
 */
static int test_candidate_overridden_by_corruption(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[32];
    uint8_t value[64];
    uint32_t key_len = 0u;
    uint32_t value_len = 0u;
    uint8_t empty = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);

    REQUIRE(make_future_key(key, &key_len));
    REQUIRE(make_future_value(value, &value_len));
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, value, value_len));
    (void)memcpy(key, ROOT_V1, 8u);
    key[7] = 0x02u;
    key[8] = 0xFFu;
    key_len = 9u;
    REQUIRE(ninlil_spy_add_row(&spy, key, key_len, &empty, 0u));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    /* First budget step: only the future row (budget 1). */
    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(session.ok_row_count == 1u);
    /* Second step: malformed becomes terminal; candidate not sticky-primary. */
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.recognizable_future_seen == 1u);
    return 0;
}

static int test_duplicate_and_out_of_order(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;
    uint8_t key[16];
    uint8_t empty = 0u;
    uint32_t len = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 8u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    /* Nonzero-Port runtime duplicate defense (formal_precheck is separate zero-Port). */
    REQUIRE(spy.trace_count > 0u);
    REQUIRE(spy.begin_calls == 1u);
    REQUIRE(spy.iter_next_calls >= 2u);
    REQUIRE(spy.mutation_calls == 0u);
    REQUIRE(spy.trace_overflow == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(spy.close_calls == 0u);
    REQUIRE(handle == original);
    REQUIRE(session.original_handle_authority == 0u);

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 8u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.trace_count > 0u);
    REQUIRE(spy.begin_calls == 1u);
    REQUIRE(spy.iter_next_calls >= 2u);
    REQUIRE(spy.mutation_calls == 0u);
    REQUIRE(spy.trace_overflow == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(spy.close_calls == 0u);
    REQUIRE(handle == original);
    REQUIRE(session.original_handle_authority == 0u);
    return 0;
}

static int test_bts_and_not_found_poison(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
        NINLIL_STORAGE_BUFFER_TOO_SMALL, NINLIL_SPY_SHAPE_BTS_LENGTHS,
        300u, 5000u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
        NINLIL_STORAGE_NOT_FOUND, NINLIL_SPY_SHAPE_NOT_FOUND_POISON,
        1u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

static int test_begin_iter_shapes_fence(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    /* OK + NULL begin */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_BEGIN, 1u,
        NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_OK_NULL, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(handle == NULL);
    REQUIRE(session.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);

    /* non-OK + non-NULL begin: rollback abnormal txn, then fence original */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    {
        ninlil_storage_handle_t original = handle;
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_BEGIN, 1u,
            NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_ERROR_WITH_HANDLE, 0u,
            0u));
        ninlil_domain_scan_session_init(&session);
        REQUIRE(ninlil_domain_scan_begin(
                &session, ops, &handle, &workspace) == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
        REQUIRE(handle == NULL);
        REQUIRE(session.reopen_required == 1u);
        REQUIRE(spy.rollback_calls == 1u);
        REQUIRE(spy.close_calls == 1u);
        REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
        /* Exact order: begin → rollback → close (no iter_open/iter_close). */
        REQUIRE(spy.trace_count >= 3u);
        REQUIRE(spy.trace[0].op == NINLIL_SPY_OP_BEGIN);
        REQUIRE(spy.trace[1].op == NINLIL_SPY_OP_ROLLBACK);
        REQUIRE(spy.trace[2].op == NINLIL_SPY_OP_CLOSE);
        REQUIRE(ninlil_spy_call_count(&spy, NINLIL_SPY_OP_ITER_OPEN) == 0u);
        REQUIRE(spy.iter_close_calls == 0u);
    }

    /* OK + NULL iter_open: must fence even if rollback OK */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_OPEN, 1u,
        NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_OK_NULL, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(handle == NULL);
    REQUIRE(session.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);
    REQUIRE(spy.rollback_calls == 1u);
    REQUIRE(ninlil_spy_iter_close_before_rollback(&spy));

    /* non-OK + non-NULL iter_open: consume child + fence */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_OPEN, 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_ERROR_WITH_HANDLE, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(handle == NULL);
    REQUIRE(session.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);
    REQUIRE(spy.iter_close_calls == 1u);
    REQUIRE(spy.rollback_calls == 1u);
    return 0;
}

static int test_unknown_status_and_rollback_failure(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
        (ninlil_storage_status_t)99u, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.fence_pending == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(handle == NULL);
    REQUIRE(result.reopen_required == 1u);

    /* Rollback failure preserves terminal primary */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ROLLBACK, 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_E_STORAGE);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE);
    REQUIRE(result.adopted == 0u);
    REQUIRE(handle == NULL);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(result.cleanup_status == NINLIL_STORAGE_IO_ERROR);

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ROLLBACK, 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 8u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE);
    REQUIRE(result.adopted == 0u);
    REQUIRE(handle == NULL);
    return 0;
}

static int test_misuse_and_budget_zero(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t canary_session[sizeof(session)];
    uint8_t canary_ws[sizeof(workspace)];
    uint8_t canary_result[sizeof(result)];
    uint64_t calls_before;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0x11, sizeof(workspace));
    (void)memset(&result, 0x22, sizeof(result));
    (void)memcpy(canary_session, &session, sizeof(session));
    (void)memcpy(canary_ws, &workspace, sizeof(workspace));
    (void)memcpy(canary_result, &result, sizeof(result));

    calls_before = spy.trace_count;
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.trace_count == calls_before);
    REQUIRE(memcmp(&session, canary_session, sizeof(session)) == 0);

    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&result, canary_result, sizeof(result)) == 0);
    REQUIRE(spy.trace_count == calls_before);

    REQUIRE(ninlil_domain_scan_abort(&session, &result)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&result, canary_result, sizeof(result)) == 0);

    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    (void)memcpy(canary_session, &session, sizeof(session));
    (void)memcpy(canary_ws, &workspace, sizeof(workspace));
    calls_before = spy.trace_count;
    REQUIRE(ninlil_domain_scan_advance(&session, 0u)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == calls_before);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(memcmp(&session, canary_session, sizeof(session)) == 0);
    REQUIRE(memcmp(&workspace, canary_ws, sizeof(workspace)) == 0);

    REQUIRE(scan_to_end(&session, 1u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    calls_before = spy.trace_count;
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_domain_scan_abort(&session, &result)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.trace_count == calls_before);
    return 0;
}

static int test_alias_and_binding(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_scripted_storage_spy_t spy2;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_workspace_t workspace2;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t handle2;
    const ninlil_storage_ops_t *ops;
    const ninlil_storage_ops_t *ops2;
    uint64_t calls_before;
    ninlil_domain_scan_state_t live_state;
    uint8_t result_canary[sizeof(result)];

    ninlil_spy_init(&spy);
    ninlil_spy_init(&spy2);
    ops = ninlil_spy_ops(&spy);
    ops2 = ninlil_spy_ops(&spy2);
    handle = ninlil_spy_open_handle(&spy);
    handle2 = ninlil_spy_open_handle(&spy2);
    ninlil_domain_scan_session_init(&session);
    calls_before = spy.trace_count;

    REQUIRE(ninlil_domain_scan_begin(
            NULL, ops, &handle, &workspace) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_begin(
            &session, NULL, &handle, &workspace) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, NULL, &workspace) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, NULL) == NINLIL_E_INVALID_ARGUMENT);
    {
        ninlil_storage_handle_t null_handle = NULL;
        REQUIRE(ninlil_domain_scan_begin(
                &session, ops, &null_handle, &workspace)
            == NINLIL_E_INVALID_ARGUMENT);
    }
    /* session/workspace overlap at begin */
    {
        ninlil_domain_scan_session_t *alias_session =
            (ninlil_domain_scan_session_t *)(void *)&workspace;
        REQUIRE(ninlil_domain_scan_begin(
                alias_session, ops, &handle, &workspace)
            == NINLIL_E_INVALID_ARGUMENT);
    }
    /* ops/workspace overlap */
    {
        ninlil_storage_ops_t *alias_ops =
            (ninlil_storage_ops_t *)(void *)&workspace;
        *alias_ops = *ops;
        REQUIRE(ninlil_domain_scan_begin(
                &session, alias_ops, &handle, &workspace)
            == NINLIL_E_INVALID_ARGUMENT);
    }
    /* handle slot / workspace overlap */
    {
        ninlil_storage_handle_t *alias_handle =
            (ninlil_storage_handle_t *)(void *)&workspace;
        *alias_handle = handle;
        REQUIRE(ninlil_domain_scan_begin(
                &session, ops, alias_handle, &workspace)
            == NINLIL_E_INVALID_ARGUMENT);
    }
    REQUIRE(spy.trace_count == calls_before);

    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    live_state = session.state;
    REQUIRE(live_state == NINLIL_DOMAIN_SCAN_STATE_OPEN);

    /*
     * API surface removes mid-session substitution: advance/finalize/abort
     * cannot accept alternate Port/workspace/handle. Bound deps drive cleanup.
     */
    REQUIRE(session.bound_storage == ops);
    REQUIRE(session.bound_workspace == &workspace);
    REQUIRE(session.bound_handle_slot == &handle);

    (void)memset(&result, 0xC3, sizeof(result));
    (void)memcpy(result_canary, &result, sizeof(result));
    calls_before = spy.trace_count + spy2.trace_count;

    /* abort (legal on OPEN): out_result overlapping session — Port 0 */
    {
        ninlil_domain_scan_result_t *alias_result =
            (ninlil_domain_scan_result_t *)(void *)&session;
        REQUIRE(ninlil_domain_scan_abort(&session, alias_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
        REQUIRE(spy.trace_count + spy2.trace_count == calls_before);
    }
    /* abort: out_result overlapping bound workspace */
    {
        ninlil_domain_scan_result_t *alias_result =
            (ninlil_domain_scan_result_t *)(void *)&workspace;
        REQUIRE(ninlil_domain_scan_abort(&session, alias_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
        REQUIRE(spy.trace_count + spy2.trace_count == calls_before);
    }
    /* abort: out_result overlapping handle slot */
    {
        ninlil_domain_scan_result_t *alias_result =
            (ninlil_domain_scan_result_t *)(void *)&handle;
        REQUIRE(ninlil_domain_scan_abort(&session, alias_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    }
    /* abort: out_result overlapping bound ops object */
    {
        ninlil_domain_scan_result_t *alias_result =
            (ninlil_domain_scan_result_t *)(void *)(uintptr_t)ops;
        REQUIRE(ninlil_domain_scan_abort(&session, alias_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
        REQUIRE(spy.trace_count + spy2.trace_count == calls_before);
    }

    /* Exhaust then re-check finalize alias rejection with live EXHAUSTED. */
    REQUIRE(scan_to_end(&session, 8u) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    calls_before = spy.trace_count + spy2.trace_count;
    {
        ninlil_domain_scan_result_t *alias_result =
            (ninlil_domain_scan_result_t *)(void *)&workspace;
        REQUIRE(ninlil_domain_scan_finalize(&session, alias_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
        REQUIRE(spy.trace_count + spy2.trace_count == calls_before);
    }
    {
        ninlil_domain_scan_result_t *alias_result =
            (ninlil_domain_scan_result_t *)(void *)(uintptr_t)ops;
        REQUIRE(ninlil_domain_scan_finalize(&session, alias_result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
        REQUIRE(spy.trace_count + spy2.trace_count == calls_before);
    }

    /* Alternate spy unused: cleanup still hits original bound provider. */
    (void)ops2;
    (void)handle2;
    (void)workspace2;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(spy.rollback_calls == 1u);
    REQUIRE(spy2.rollback_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_abort_path(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[16];
    uint8_t empty = 0u;
    uint32_t len = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));

    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_abort(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    REQUIRE(ninlil_spy_iter_close_before_rollback(&spy));
    return 0;
}

static int test_unchanged_prevalidation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t ws_canary[sizeof(workspace)];
    uint8_t result_canary[sizeof(result)];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0x3C, sizeof(workspace));
    (void)memset(&result, 0xC3, sizeof(result));
    (void)memcpy(ws_canary, &workspace, sizeof(workspace));
    (void)memcpy(result_canary, &result, sizeof(result));

    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, NULL) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&workspace, ws_canary, sizeof(workspace)) == 0);

    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&result, result_canary, sizeof(result)) == 0);
    return 0;
}

/* Counter overflow is D2-detectable corruption; never wraps; no partial mutation. */
static int test_counter_overflow_no_partial_mutation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t key[32];
    uint8_t empty = 0u;
    uint32_t len = 0u;
    uint8_t prev_canary[255];
    uint8_t has_prev_before;
    uint32_t prev_len_before;
    uint64_t family_before;
    uint64_t current_before;
    uint64_t ok_before;
    uint8_t future_before;

    /* --- ok_row_count at MAX: no family/previous advance on family14 row --- */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    session.ok_row_count = UINT64_MAX;
    session.family14_row_count = 7u;
    session.current_domain_key_count = 3u;
    session.has_previous = 0u;
    session.previous_key_length = 0u;
    (void)memset(workspace.previous_key, 0xABu, sizeof(workspace.previous_key));
    (void)memcpy(prev_canary, workspace.previous_key, sizeof(prev_canary));
    family_before = session.family14_row_count;
    current_before = session.current_domain_key_count;
    ok_before = session.ok_row_count;
    has_prev_before = session.has_previous;
    prev_len_before = session.previous_key_length;
    future_before = session.recognizable_future_seen;
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.ok_row_count == ok_before);
    REQUIRE(session.family14_row_count == family_before);
    REQUIRE(session.current_domain_key_count == current_before);
    REQUIRE(session.has_previous == has_prev_before);
    REQUIRE(session.previous_key_length == prev_len_before);
    REQUIRE(memcmp(workspace.previous_key, prev_canary, sizeof(prev_canary))
        == 0);
    REQUIRE(session.recognizable_future_seen == future_before);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* --- family14 at MAX: sub-counter fails; ok/previous unchanged --- */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    session.family14_row_count = UINT64_MAX;
    session.ok_row_count = 0u;
    session.has_previous = 0u;
    (void)memset(workspace.previous_key, 0xCDu, sizeof(workspace.previous_key));
    (void)memcpy(prev_canary, workspace.previous_key, sizeof(prev_canary));
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.family14_row_count == UINT64_MAX);
    REQUIRE(session.ok_row_count == 0u);
    REQUIRE(session.has_previous == 0u);
    REQUIRE(memcmp(workspace.previous_key, prev_canary, sizeof(prev_canary))
        == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* --- current_domain at MAX on a CURRENT domain row --- */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(make_current_domain_key(key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    session.current_domain_key_count = UINT64_MAX;
    session.ok_row_count = 0u;
    session.has_previous = 0u;
    (void)memset(workspace.previous_key, 0xEFu, sizeof(workspace.previous_key));
    (void)memcpy(prev_canary, workspace.previous_key, sizeof(prev_canary));
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.current_domain_key_count == UINT64_MAX);
    REQUIRE(session.ok_row_count == 0u);
    REQUIRE(session.has_previous == 0u);
    REQUIRE(memcmp(workspace.previous_key, prev_canary, sizeof(prev_canary))
        == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/*
 * Handle-slot drift: scanner closes ORIGINAL bound handle exactly once;
 * foreign slot left untouched; NULL slot not treated as already-fenced match.
 */
static int test_handle_slot_drift_fence_original(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    ninlil_storage_handle_t foreign;
    static int foreign_token = 0x5A;
    const ninlil_storage_ops_t *ops;
    uint8_t key[16];
    uint8_t empty = 0u;
    uint32_t len = 0u;

    /* --- slot cleared to NULL mid-session --- */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(session.original_handle_authority == 1u);
    handle = NULL; /* drift: NULL while authority live */
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(handle == NULL); /* still NULL; scanner did not invent a value */
    REQUIRE(session.original_handle_authority == 0u);
    /* No double-close on second cleanup attempt (session DONE). */
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.close_calls == 1u);

    /* --- slot replaced with foreign non-NULL token --- */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    foreign = (ninlil_storage_handle_t)&foreign_token;
    REQUIRE(make_family14_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, key, &len));
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    handle = foreign; /* drift: foreign replacement */
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, foreign) == 0u);
    REQUIRE(handle == foreign); /* foreign left untouched */
    REQUIRE(session.original_handle_authority == 0u);
    return 0;
}

/* Normal successful adopt must not close the caller's original handle. */
static int test_success_finalize_does_not_close_handle(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 8u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.reopen_required == 0u);
    REQUIRE(spy.close_calls == 0u);
    REQUIRE(handle == original);
    REQUIRE(session.original_handle_authority == 0u);
    return 0;
}

static int test_dsr2_workspace_bound(void)
{
    /* S2 packed workspace: S1 scratch + encoded/views/validated/candidate.
     * Ceiling is Normative exact; exact sizeof may include alignment padding. */
    REQUIRE(sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES);
    REQUIRE(NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES == 8192u);
    REQUIRE(sizeof(ninlil_domain_scan_workspace_t)
        >= NINLIL_DOMAIN_SCAN_KEY_CAPACITY
            + NINLIL_DOMAIN_SCAN_VALUE_CAPACITY
            + NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY
            + NINLIL_DOMAIN_SCAN_ENCODED_VALUES_BYTES);
    return 0;
}

static int test_dsr2_bts_no_alloc(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
        NINLIL_STORAGE_BUFFER_TOO_SMALL, NINLIL_SPY_SHAPE_BTS_LENGTHS,
        256u, 65536u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.allocator_calls == 0u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* ---- D2-S2 profiled-begin direct unit tests (§15.10.8) ---- */

static void s2_set_id(ninlil_id128_t *id, uint8_t first)
{
    uint8_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(first + i);
    }
}

static void s2_default_binding(ninlil_model_runtime_store_binding_t *b)
{
    (void)memset(b, 0, sizeof(*b));
    b->storage_schema = NINLIL_STORAGE_SCHEMA_M1A;
    b->role = NINLIL_ROLE_CONTROLLER;
    b->environment = NINLIL_ENV_TEST;
    s2_set_id(&b->runtime_id, 0x10u);
    b->limits.max_services = 7u;
    b->limits.max_nonterminal_transactions = 20u;
    b->limits.max_targets_per_transaction = 1u;
    b->limits.max_logical_payload_bytes = 1000u;
    b->limits.max_durable_outbox_payload_bytes = 5000u;
    b->limits.max_attempts_per_target_per_cycle = 8u;
    b->limits.max_cancel_attempts_per_transaction = 1u;
    b->limits.max_evidence_per_target = 3u;
    b->limits.max_retained_terminal_transactions = 30u;
    b->limits.max_nonterminal_deliveries = 12u;
    b->limits.max_event_spool_count = 0u;
    b->limits.max_event_spool_bytes = 0u;
    b->limits.max_result_cache_entries = 13u;
    b->limits.max_retained_dispositions = 14u;
    b->limits.max_ingress_per_step = 15u;
    b->limits.max_callbacks_per_step = 16u;
    b->limits.max_state_transitions_per_step = 17u;
    b->limits.max_bearer_sends_per_step = 18u;
    b->limits.max_deferred_tokens = 19u;
}

static int s2_install_full_profile(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_model_runtime_store_binding_t *candidate)
{
    uint32_t key_id;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_key_t key;
    uint8_t value[183];
    uint32_t value_length;

    s2_default_binding(candidate);
    (void)memset(&identity, 0, sizeof(identity));
    identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    s2_set_id(&identity.device_id, 0x20u);
    s2_set_id(&identity.installation_id, 0x40u);
    s2_set_id(&identity.site_domain_id, 0x60u);
    identity.binding_epoch = 1u;
    identity.membership_epoch = 1u;

    for (key_id = 1u; key_id <= 17u; ++key_id) {
        ninlil_status_t st;
        if (ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)key_id, &key)
            != NINLIL_OK) {
            return 0;
        }
        value_length = 0u;
        if (key_id == 1u) {
            st = ninlil_model_runtime_store_encode_binding(
                candidate, value, sizeof(value), &value_length);
        } else if (key_id == 2u) {
            st = ninlil_model_runtime_store_encode_identity(
                &identity, value, sizeof(value), &value_length);
        } else if (key_id <= 6u) {
            ninlil_model_runtime_store_counter_t counter;
            counter.kind =
                (ninlil_model_runtime_store_counter_kind_t)(key_id - 2u);
            counter.value = 0u;
            counter.exhausted_marker = 0u;
            st = ninlil_model_runtime_store_encode_counter(
                (ninlil_model_runtime_store_key_id_t)key_id, &counter, value,
                sizeof(value), &value_length);
        } else {
            ninlil_model_runtime_store_capacity_t cap;
            (void)memset(&cap, 0, sizeof(cap));
            cap.kind = (ninlil_resource_kind_t)(key_id - 6u);
            cap.limit = 100u + key_id;
            cap.capacity_epoch = 1u;
            st = ninlil_model_runtime_store_encode_capacity(
                (ninlil_model_runtime_store_key_id_t)key_id, &cap, value,
                sizeof(value), &value_length);
        }
        if (st != NINLIL_OK) {
            return 0;
        }
        if (!ninlil_spy_add_row(
                spy, key.bytes, key.length, value, value_length)) {
            return 0;
        }
    }
    return 1;
}

static int test_s2_workspace_ceiling(void)
{
    REQUIRE(sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES);
    REQUIRE(NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES == 8192u);
    /* No second 4096 value buffer: iter value is the only 4096 region. */
    REQUIRE(NINLIL_DOMAIN_SCAN_VALUE_CAPACITY == 4096u);
    REQUIRE(NINLIL_DOMAIN_SCAN_ENCODED_VALUES_BYTES == 1143u);
    return 0;
}

static int test_s2_candidate_null_and_alias(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t *handle_alias;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_ops_t ops_local;
    uint64_t before;
    ninlil_domain_scan_state_t idle_state;
    uint8_t session_canary[sizeof(session)];
    uint8_t workspace_canary[sizeof(workspace)];
    uint8_t candidate_canary[sizeof(candidate)];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    s2_default_binding(&candidate);
    before = spy.trace_count;
    idle_state = session.state;
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(workspace_canary, &workspace, sizeof(workspace));
    (void)memcpy(candidate_canary, &candidate, sizeof(candidate));

    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_IDLE);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&workspace, workspace_canary, sizeof(workspace)) == 0);

    /* candidate overlaps workspace (copy region lives inside workspace). */
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &workspace.candidate)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(session.state == idle_state);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&workspace, workspace_canary, sizeof(workspace)) == 0);

    /* candidate overlaps session object. */
    {
        ninlil_model_runtime_store_binding_t *cand_on_session =
            (ninlil_model_runtime_store_binding_t *)(void *)&session;
        REQUIRE(ninlil_domain_scan_begin_profiled(
                &session, ops, &handle, &workspace, cand_on_session)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(spy.trace_count == before);
        REQUIRE(session.state == idle_state);
    }

    /* candidate overlaps ops table object. */
    ops_local = *ops;
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, &ops_local, &handle, &workspace,
            (const ninlil_model_runtime_store_binding_t *)(void *)&ops_local)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(session.state == idle_state);

    /* candidate overlaps handle slot. */
    handle_alias = &handle;
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, handle_alias, &workspace,
            (const ninlil_model_runtime_store_binding_t *)(void *)handle_alias)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(session.state == idle_state);
    REQUIRE(memcmp(&candidate, candidate_canary, sizeof(candidate)) == 0);
    return 0;
}

static int test_s2_candidate_copied_before_port(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    /* Wipe caller candidate after begin: scanner must not reread it. */
    (void)memset(&candidate, 0, sizeof(candidate));
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.profile_exact_active == 1u);
    REQUIRE(result.family14_row_count == 17u);
    REQUIRE(result.profile_get_present_mask
        == NINLIL_DOMAIN_SCAN_PROFILE_ALL_MASK);
    REQUIRE(result.family14_iter_seen_mask
        == NINLIL_DOMAIN_SCAN_PROFILE_ALL_MASK);
    REQUIRE(spy.get_calls == 17u);
    REQUIRE(spy.iter_open_calls == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_s2_missing_keys_no_iter_open(void)
{
    uint32_t missing;

    for (missing = 1u; missing <= 17u; ++missing) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        uint32_t key_id;

        ninlil_spy_init(&spy);
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        s2_default_binding(&candidate);
        /* Install all keys except `missing`. */
        {
            ninlil_model_runtime_store_identity_t identity;
            (void)memset(&identity, 0, sizeof(identity));
            identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
                | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
                | NINLIL_LOCAL_IDENTITY_HAS_SITE;
            s2_set_id(&identity.device_id, 0x20u);
            s2_set_id(&identity.installation_id, 0x40u);
            s2_set_id(&identity.site_domain_id, 0x60u);
            identity.binding_epoch = 1u;
            identity.membership_epoch = 1u;
            for (key_id = 1u; key_id <= 17u; ++key_id) {
                ninlil_model_runtime_store_key_t key;
                uint8_t value[183];
                uint32_t value_length = 0u;
                ninlil_status_t st;
                if (key_id == missing) {
                    continue;
                }
                REQUIRE(ninlil_model_runtime_store_build_key(
                        (ninlil_model_runtime_store_key_id_t)key_id, &key)
                    == NINLIL_OK);
                if (key_id == 1u) {
                    st = ninlil_model_runtime_store_encode_binding(
                        &candidate, value, sizeof(value), &value_length);
                } else if (key_id == 2u) {
                    st = ninlil_model_runtime_store_encode_identity(
                        &identity, value, sizeof(value), &value_length);
                } else if (key_id <= 6u) {
                    ninlil_model_runtime_store_counter_t counter;
                    counter.kind =
                        (ninlil_model_runtime_store_counter_kind_t)(key_id - 2u);
                    counter.value = 0u;
                    counter.exhausted_marker = 0u;
                    st = ninlil_model_runtime_store_encode_counter(
                        (ninlil_model_runtime_store_key_id_t)key_id, &counter,
                        value, sizeof(value), &value_length);
                } else {
                    ninlil_model_runtime_store_capacity_t cap;
                    (void)memset(&cap, 0, sizeof(cap));
                    cap.kind = (ninlil_resource_kind_t)(key_id - 6u);
                    cap.limit = 1u;
                    cap.capacity_epoch = 1u;
                    st = ninlil_model_runtime_store_encode_capacity(
                        (ninlil_model_runtime_store_key_id_t)key_id, &cap,
                        value, sizeof(value), &value_length);
                }
                REQUIRE(st == NINLIL_OK);
                REQUIRE(ninlil_spy_add_row(
                    &spy, key.bytes, key.length, value, value_length));
            }
        }
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        REQUIRE(ninlil_domain_scan_begin_profiled(
                &session, ops, &handle, &workspace, &candidate)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
        REQUIRE(spy.iter_open_calls == 0u);
        REQUIRE(spy.get_calls == 17u);
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }
    return 0;
}

static int test_s2_get_bts_no_reread(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, 1u,
        NINLIL_STORAGE_BUFFER_TOO_SMALL, NINLIL_SPY_SHAPE_BTS_LENGTHS, 0u,
        200u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.get_calls == 1u); /* no reread */
    REQUIRE(spy.iter_open_calls == 0u);
    REQUIRE(spy.allocator_calls == 0u);
    return 0;
}

static int test_s2_iterator_value_disagreement(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    /* After get retained bytes, mutate storage row before iterator walk. */
    REQUIRE(spy.row_count >= 1u);
    if (spy.rows[0].value_length > 0u) {
        spy.rows[0].value[spy.rows[0].value_length - 1u] ^= 0x5Au;
    }
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    return 0;
}

static int test_s2_iterator_missing_catalog_key(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    /* Drop last catalog row so iterator never yields key 17. */
    REQUIRE(spy.row_count == 17u);
    spy.row_count = 16u;
    REQUIRE(scan_to_end(&session, 64u) != 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.has_sticky_primary != 0u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.family14_iter_seen_mask
        != result.profile_get_present_mask);
    return 0;
}

static int test_s2_mismatch_skip_and_f14_override(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_model_runtime_store_binding_t stored;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t bad_key[16];
    uint32_t bad_len = 0u;

    /* mismatch mode: stored binding != candidate; domain malformed skipped */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &stored));
    s2_default_binding(&candidate);
    candidate.limits.max_services = 99u; /* semantic mismatch */
    REQUIRE(make_malformed_current_key(bad_key, &bad_len));
    REQUIRE(ninlil_spy_add_row(&spy, bad_key, bad_len, NULL, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.profile_mismatch == 1u);
    REQUIRE(session.profile_exact_active == 0u);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.profile_mismatch == 1u);
    REQUIRE(result.ok_row_count == 18u); /* 17 catalog + 1 skipped malformed */

    /* f14 noncatalog overrides mismatch candidate */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &stored));
    s2_default_binding(&candidate);
    candidate.limits.max_services = 99u;
    (void)memcpy(bad_key, ROOT_V1, 8u);
    bad_key[8] = 0x03u;
    bad_key[9] = 0x00u; /* noncatalog counter suffix */
    bad_len = 10u;
    REQUIRE(ninlil_spy_add_row(&spy, bad_key, bad_len, NULL, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.profile_mismatch == 1u);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    return 0;
}

static int test_s2_future_profile_and_corrupt_precedence(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_model_runtime_store_key_t key;
    uint8_t value[183];
    uint32_t value_length;
    uint32_t key_id;

    /* Future-only: binding version 2 => future_profile_candidate / UNSUPPORTED */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    s2_default_binding(&candidate);
    for (key_id = 1u; key_id <= 17u; ++key_id) {
        ninlil_model_runtime_store_identity_t identity;
        ninlil_status_t st;
        REQUIRE(ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)key_id, &key)
            == NINLIL_OK);
        (void)memset(&identity, 0, sizeof(identity));
        identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
            | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
            | NINLIL_LOCAL_IDENTITY_HAS_SITE;
        s2_set_id(&identity.device_id, 0x20u);
        s2_set_id(&identity.installation_id, 0x40u);
        s2_set_id(&identity.site_domain_id, 0x60u);
        identity.binding_epoch = 1u;
        identity.membership_epoch = 1u;
        if (key_id == 1u) {
            st = ninlil_model_runtime_store_encode_binding(
                &candidate, value, sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
            value[6] = 0u;
            value[7] = 2u;
            {
                uint32_t crc = crc32c_bytes(value, 12u + 167u);
                write_u32_be(&value[12u + 167u], crc);
            }
        } else if (key_id == 2u) {
            st = ninlil_model_runtime_store_encode_identity(
                &identity, value, sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
        } else if (key_id <= 6u) {
            ninlil_model_runtime_store_counter_t counter;
            counter.kind =
                (ninlil_model_runtime_store_counter_kind_t)(key_id - 2u);
            counter.value = 0u;
            counter.exhausted_marker = 0u;
            st = ninlil_model_runtime_store_encode_counter(
                (ninlil_model_runtime_store_key_id_t)key_id, &counter, value,
                sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
        } else {
            ninlil_model_runtime_store_capacity_t cap;
            (void)memset(&cap, 0, sizeof(cap));
            cap.kind = (ninlil_resource_kind_t)(key_id - 6u);
            cap.limit = 1u;
            cap.capacity_epoch = 1u;
            st = ninlil_model_runtime_store_encode_capacity(
                (ninlil_model_runtime_store_key_id_t)key_id, &cap, value,
                sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
        }
        REQUIRE(ninlil_spy_add_row(
            &spy, key.bytes, key.length, value, value_length));
    }
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.future_profile_candidate == 1u);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.future_profile_candidate == 1u);
    REQUIRE(result.adopted == 0u);

    /*
     * Single mixed snapshot: binding version 2 (future) AND corrupt identity CRC.
     * validate_snapshot aggregates CORRUPT over UNSUPPORTED; iter_open == 0.
     */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    s2_default_binding(&candidate);
    for (key_id = 1u; key_id <= 17u; ++key_id) {
        ninlil_model_runtime_store_identity_t identity;
        ninlil_status_t st;
        REQUIRE(ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)key_id, &key)
            == NINLIL_OK);
        (void)memset(&identity, 0, sizeof(identity));
        identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
            | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
            | NINLIL_LOCAL_IDENTITY_HAS_SITE;
        s2_set_id(&identity.device_id, 0x20u);
        s2_set_id(&identity.installation_id, 0x40u);
        s2_set_id(&identity.site_domain_id, 0x60u);
        identity.binding_epoch = 1u;
        identity.membership_epoch = 1u;
        if (key_id == 1u) {
            st = ninlil_model_runtime_store_encode_binding(
                &candidate, value, sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
            /* Future version on binding. */
            value[6] = 0u;
            value[7] = 2u;
            {
                uint32_t crc = crc32c_bytes(value, 12u + 167u);
                write_u32_be(&value[12u + 167u], crc);
            }
        } else if (key_id == 2u) {
            st = ninlil_model_runtime_store_encode_identity(
                &identity, value, sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
            /* Distinct corrupt identity CRC (not version future). */
            value[value_length - 1u] ^= 0xFFu;
        } else if (key_id <= 6u) {
            ninlil_model_runtime_store_counter_t counter;
            counter.kind =
                (ninlil_model_runtime_store_counter_kind_t)(key_id - 2u);
            counter.value = 0u;
            counter.exhausted_marker = 0u;
            st = ninlil_model_runtime_store_encode_counter(
                (ninlil_model_runtime_store_key_id_t)key_id, &counter, value,
                sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
        } else {
            ninlil_model_runtime_store_capacity_t cap;
            (void)memset(&cap, 0, sizeof(cap));
            cap.kind = (ninlil_resource_kind_t)(key_id - 6u);
            cap.limit = 1u;
            cap.capacity_epoch = 1u;
            st = ninlil_model_runtime_store_encode_capacity(
                (ninlil_model_runtime_store_key_id_t)key_id, &cap, value,
                sizeof(value), &value_length);
            REQUIRE(st == NINLIL_OK);
        }
        REQUIRE(ninlil_spy_add_row(
            &spy, key.bytes, key.length, value, value_length));
    }
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.iter_open_calls == 0u);
    REQUIRE(session.future_profile_candidate == 0u);
    REQUIRE(session.profile_exact_active == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    return 0;
}

static int test_s2_get_descriptor_rewrite_rejected(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;
    uint8_t preseed[183];
    uint32_t preseed_len = 0u;

    /* Rewrite data pointer: preseed slot with valid binding; provider redirects. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_model_runtime_store_encode_binding(
            &candidate, preseed, sizeof(preseed), &preseed_len)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, 1u,
        NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_REWRITE_DATA_PTR, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    /* Preseed encoded binding slot with valid prior bytes (stale if accepted). */
    (void)memcpy(workspace.encoded_values, preseed, preseed_len);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.get_calls == 1u);
    REQUIRE(spy.iter_open_calls == 0u);
    REQUIRE(session.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);
    REQUIRE(handle == NULL);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    /* Slot must still hold preseed (provider must not have been trusted). */
    REQUIRE(memcmp(workspace.encoded_values, preseed, preseed_len) == 0);

    /* Rewrite capacity descriptor. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, 2u,
        NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_REWRITE_CAPACITY, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.get_calls == 2u);
    REQUIRE(spy.iter_open_calls == 0u);
    REQUIRE(session.reopen_required == 1u);
    REQUIRE(spy.close_calls == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * Literal catalog key (root/family/suffix) — independent of production
 * build_key for order proof.
 */
static void s2_literal_catalog_key(
    uint32_t key_id,
    uint8_t *out,
    uint32_t *out_length)
{
    static const uint8_t root[8] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
    };

    (void)memcpy(out, root, sizeof(root));
    if (key_id == 1u) {
        out[8] = 0x01u;
        *out_length = 9u;
    } else if (key_id == 2u) {
        out[8] = 0x02u;
        *out_length = 9u;
    } else if (key_id <= 6u) {
        out[8] = 0x03u;
        out[9] = (uint8_t)(key_id - 2u);
        *out_length = 10u;
    } else {
        out[8] = 0x04u;
        out[9] = (uint8_t)(key_id - 6u);
        *out_length = 10u;
    }
}

static int test_s2_one_iterator_and_call_order(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    size_t i;
    int saw_get = 0;
    int saw_open = 0;
    uint32_t gets_before_open = 0u;
    uint32_t expected_key_id = 1u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(spy.iter_open_calls == 1u);
    REQUIRE(spy.get_calls == 17u);
    for (i = 0u; i < spy.trace_count; ++i) {
        if (spy.trace[i].op == NINLIL_SPY_OP_GET) {
            uint8_t want[16];
            uint32_t want_len = 0u;

            REQUIRE(saw_open == 0);
            saw_get = 1;
            gets_before_open += 1u;
            REQUIRE(expected_key_id <= 17u);
            s2_literal_catalog_key(expected_key_id, want, &want_len);
            /* GET request keys live in request_key_*; key_bytes is ITER_NEXT only. */
            REQUIRE(spy.trace[i].request_key_bytes_length == want_len);
            REQUIRE(memcmp(spy.trace[i].request_key_bytes, want, want_len)
                == 0);
            expected_key_id += 1u;
        } else if (spy.trace[i].op == NINLIL_SPY_OP_ITER_OPEN) {
            REQUIRE(saw_get != 0);
            REQUIRE(gets_before_open == 17u);
            REQUIRE(expected_key_id == 18u);
            saw_open = 1;
        }
    }
    REQUIRE(saw_open != 0);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_s2_iter_descriptor_rewrite_rejected(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;

    /* Rewrite data pointer on first iter_next. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
            NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_REWRITE_DATA_PTR, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0xA5, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.fence_pending == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(handle == NULL);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    /* Rewrite capacity descriptor on first iter_next. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
            NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_REWRITE_CAPACITY, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.fence_pending == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(handle == NULL);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* ---- D2-S4 exact-get direct unit tests (§15.11) ---- */

static int test_s4_exact_get_present_absent_zero_exhausted(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    uint8_t absent_key[11];
    uint8_t zero_key[11];
    uint64_t ok_before;
    uint64_t f14_before;
    uint32_t iter_open_before;
    uint32_t get_before;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    /* Zero-length present key: exact_get only; abort without advancing it
     * (non-catalog empty value is S3-corrupt if visited under exact profile). */
    (void)memcpy(zero_key, ROOT_V1, 8u);
    zero_key[8] = 0x7Fu;
    zero_key[9] = 0x00u;
    zero_key[10] = 0x99u;
    REQUIRE(ninlil_spy_add_row(&spy, zero_key, 11u, NULL, 0u));
    (void)memcpy(absent_key, ROOT_V1, 8u);
    absent_key[8] = 0x7Fu;
    absent_key[9] = 0x00u;
    absent_key[10] = 0xAAu;

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    iter_open_before = spy.iter_open_calls;
    get_before = spy.get_calls;
    ok_before = session.ok_row_count;
    f14_before = session.family14_row_count;

    /* Present: catalog key 1 while iterator live. */
    {
        ninlil_model_runtime_store_key_t ck;
        REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
            == NINLIL_OK);
        key.data = ck.bytes;
        key.length = ck.length;
        (void)memset(&exact, 0xA5, sizeof(exact));
        REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
            == NINLIL_OK);
        REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);
        REQUIRE(exact.value.length == 183u);
        REQUIRE(exact.value.data == workspace.value);
        REQUIRE(session.ok_row_count == ok_before);
        REQUIRE(session.family14_row_count == f14_before);
        REQUIRE(spy.get_calls == get_before + 1u);
        REQUIRE(spy.iter_open_calls == iter_open_before);
    }

    /* Absent. */
    key.data = absent_key;
    key.length = 11u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_ABSENT);
    REQUIRE(exact.value.data == NULL);
    REQUIRE(exact.value.length == 0u);

    /* Present zero-length. */
    key.data = zero_key;
    key.length = 11u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);
    REQUIRE(exact.value.length == 0u);
    REQUIRE(exact.value.data == NULL);
    REQUIRE(ninlil_domain_scan_abort(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 0u);
    REQUIRE(spy.iter_open_calls == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    /* EXHAUSTED exact_get on catalog-only snapshot. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    {
        ninlil_model_runtime_store_key_t ck;
        REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, &ck)
            == NINLIL_OK);
        key.data = ck.bytes;
        key.length = ck.length;
        REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
            == NINLIL_OK);
        REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);
        REQUIRE(exact.value.length == 84u);
    }
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(spy.iter_open_calls == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_s4_exact_get_key_alias_and_shape(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_domain_scan_exact_get_result_t prior;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t ck;
    uint64_t before_gets;
    ninlil_domain_scan_state_t before_state;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
        == NINLIL_OK);
    (void)memcpy(workspace.key, ck.bytes, ck.length);
    (void)memcpy(workspace.previous_key, ck.bytes, ck.length);
    before_gets = spy.get_calls;
    before_state = session.state;
    (void)memset(&exact, 0x3C, sizeof(exact));
    prior = exact;

    /* NULL key / length 0 / length >255 */
    key.data = NULL;
    key.length = 1u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    REQUIRE(session.state == before_state);

    key.data = ck.bytes;
    key.length = 0u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);

    key.data = ck.bytes;
    key.length = 256u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);

    /* Alias into workspace->value is illegal. */
    key.data = workspace.value;
    key.length = ck.length;
    (void)memcpy(workspace.value, ck.bytes, ck.length);
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);

    /* Alias into encoded_values is illegal. */
    key.data = workspace.encoded_values;
    key.length = ck.length;
    (void)memcpy(workspace.encoded_values, ck.bytes, ck.length);
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.get_calls == before_gets);

    /* Borrow workspace->key is legal (S4 exception). */
    key.data = workspace.key;
    key.length = ck.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);
    REQUIRE(exact.value.length == 183u);

    /* Borrow workspace->previous_key is legal. */
    key.data = workspace.previous_key;
    key.length = ck.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);

    /* out_result overlapping session is illegal. */
    {
        ninlil_domain_scan_exact_get_result_t *alias =
            (ninlil_domain_scan_exact_get_result_t *)(void *)&session;
        key.data = ck.bytes;
        key.length = ck.length;
        before_gets = spy.get_calls;
        REQUIRE(ninlil_domain_scan_exact_get(&session, key, alias)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(spy.get_calls == before_gets);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    }
    return 0;
}

static int test_s4_exact_get_state_gates_and_sticky(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_domain_scan_exact_get_result_t prior;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t ck;
    uint64_t before_gets;

    /* IDLE reject */
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&exact, 0x11, sizeof(exact));
    prior = exact;
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
        == NINLIL_OK);
    key.data = ck.bytes;
    key.length = ck.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    before_gets = spy.get_calls;
    (void)memset(&exact, 0x22, sizeof(exact));
    prior = exact;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets + 1u);

    /* Sticky FAILED → exact_get rejected Port 0. */
    before_gets = spy.get_calls;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.get_calls == before_gets);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_E_STORAGE);
    REQUIRE(result.adopted == 0u);

    /* DONE reject */
    before_gets = spy.get_calls;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.get_calls == before_gets);
    return 0;
}

static int test_s4_exact_get_handle_drift_and_resume(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    ninlil_storage_handle_t foreign;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t ck;
    uint64_t ok_mid;
    int foreign_token = 99;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 3u) == NINLIL_OK);
    ok_mid = session.ok_row_count;
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
        == NINLIL_OK);
    key.data = ck.bytes;
    key.length = ck.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(session.ok_row_count == ok_mid);
    /* Iterator resumes after exact_get. */
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.family14_row_count == 17u);
    REQUIRE(session.ok_row_count == 17u);
    REQUIRE(spy.iter_open_calls == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);

    /* Fresh session: handle drift on exact_get. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    foreign = (ninlil_storage_handle_t)&foreign_token;
    handle = foreign;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.fence_pending == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, foreign) == 0u);
    return 0;
}

static int test_s4_exact_get_bts_and_repeat_overwrite(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t k1;
    ninlil_model_runtime_store_key_t k2;
    uint8_t first_byte;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &k1)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY, &k2)
        == NINLIL_OK);
    key.data = k1.bytes;
    key.length = k1.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);
    first_byte = exact.value.data[0];
    REQUIRE(first_byte == (uint8_t)'N');
    key.data = k2.bytes;
    key.length = k2.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact) == NINLIL_OK);
    REQUIRE(exact.presence == NINLIL_DOMAIN_SCAN_EXACT_PRESENT);
    REQUIRE(exact.value.length == 84u);
    /* Prior borrow is overwritten in the single value buffer. */
    REQUIRE(workspace.value[0] == (uint8_t)'N');
    REQUIRE(exact.value.data == workspace.value);
    REQUIRE(ninlil_domain_scan_abort(&session, &result) == NINLIL_OK);

    /* BTS no reread. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u,
        NINLIL_STORAGE_BUFFER_TOO_SMALL, NINLIL_SPY_SHAPE_BTS_LENGTHS, 0u,
        4097u));
    key.data = k1.bytes;
    key.length = k1.length;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(spy.allocator_calls == 0u);
    REQUIRE(spy.get_calls == 18u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * OPEN/EXHAUSTED with corrupted live-session authority must sticky
 * STORAGE_CORRUPT + FAILED, Port 0, out_result unchanged — before alias maps
 * the same condition to INVALID_ARGUMENT.
 */
static int test_s4_exact_get_live_authority_corrupt(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_domain_scan_exact_get_result_t prior;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t ck;
    uint64_t before_gets;
    ninlil_storage_ops_t broken_ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
        == NINLIL_OK);
    key.data = ck.bytes;
    key.length = ck.length;
    (void)memset(&exact, 0x5A, sizeof(exact));
    prior = exact;
    before_gets = spy.get_calls;

    /* null bound_storage */
    session.bound_storage = NULL;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    /* Restore authority for cleanup/alias after the Port-0 observation. */
    session.bound_storage = ops;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);

    /* Fresh OPEN: null bound_workspace */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    before_gets = spy.get_calls;
    prior = exact;
    session.bound_workspace = NULL;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    session.bound_workspace = &workspace;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Fresh OPEN: null bound_handle_slot */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    before_gets = spy.get_calls;
    prior = exact;
    session.bound_handle_slot = NULL;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    session.bound_handle_slot = &handle;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Fresh OPEN: missing required get op */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    before_gets = spy.get_calls;
    prior = exact;
    broken_ops = *ops;
    broken_ops.get = NULL;
    session.bound_storage = &broken_ops;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    session.bound_storage = ops;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Fresh OPEN: txn_live=0 */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    before_gets = spy.get_calls;
    prior = exact;
    session.txn_live = 0u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    /* Restore for cleanup so finalize does not double-fault port paths. */
    session.txn_live = 1u;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Fresh OPEN: iter_live=0 */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    before_gets = spy.get_calls;
    prior = exact;
    session.iter_live = 0u;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    session.iter_live = 1u;
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Alias invalid remains INVALID_ARGUMENT with session/output unchanged. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    before_gets = spy.get_calls;
    (void)memset(&exact, 0x3C, sizeof(exact));
    prior = exact;
    key.data = workspace.value;
    key.length = ck.length;
    (void)memcpy(workspace.value, ck.bytes, ck.length);
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets);
    REQUIRE(ninlil_domain_scan_abort(&session, &result) == NINLIL_OK);
    return 0;
}

static int test_s4_exact_get_ok_bad_and_nonempty_length(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_domain_scan_exact_get_result_t prior;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t ck;
    uint64_t before_gets;

    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
        == NINLIL_OK);
    key.data = ck.bytes;
    key.length = ck.length;

    /* OK + length > capacity */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u,
        NINLIL_STORAGE_OK, NINLIL_SPY_SHAPE_OK_BAD_LENGTH, 0u, 4097u));
    before_gets = spy.get_calls;
    (void)memset(&exact, 0xA5, sizeof(exact));
    prior = exact;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.fence_pending == 0u);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets + 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 0u);
    REQUIRE(spy.close_calls == 0u);

    /* IO + nonempty length → CORRUPT, no fence */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH, 0u,
        1u));
    before_gets = spy.get_calls;
    prior = exact;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.fence_pending == 0u);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets + 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 0u);

    /* COMMIT_UNKNOWN + nonempty: shape → CORRUPT, fence still set */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u,
        NINLIL_STORAGE_COMMIT_UNKNOWN, NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH,
        0u, 1u));
    before_gets = spy.get_calls;
    prior = exact;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.fence_pending == 1u);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets + 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(handle == NULL);

    /* Unknown + poison length: fence + CORRUPT */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u,
        (ninlil_storage_status_t)99u, NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH,
        0u, 2u));
    before_gets = spy.get_calls;
    prior = exact;
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.fence_pending == 1u);
    REQUIRE(memcmp(&exact, &prior, sizeof(exact)) == 0);
    REQUIRE(spy.get_calls == before_gets + 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.reopen_required == 1u);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* D2-S5: note_terminal_corrupt state gates + preserve flags/Port0. */
static int test_s5_note_terminal_corrupt_gates(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_exact_get_result_t exact;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_bytes_view_t key;
    ninlil_model_runtime_store_key_t ck;
    uint64_t before_trace;
    uint8_t future_before;
    uint64_t ok_before;
    uint8_t has_prev_before;
    uint32_t prev_len_before;
    uint8_t prev_canary[255];

    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));

    /* IDLE */
    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_IDLE);
    REQUIRE(session.has_sticky_primary == 0u);

    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    before_trace = spy.trace_count;
    ok_before = session.ok_row_count;
    future_before = session.recognizable_future_seen;
    has_prev_before = session.has_previous;
    prev_len_before = session.previous_key_length;
    (void)memcpy(prev_canary, workspace.previous_key, sizeof(prev_canary));
    REQUIRE(session.iter_live == 1u);
    REQUIRE(session.txn_live == 1u);

    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.ok_row_count == ok_before);
    REQUIRE(session.recognizable_future_seen == future_before);
    REQUIRE(session.has_previous == has_prev_before);
    REQUIRE(session.previous_key_length == prev_len_before);
    REQUIRE(memcmp(workspace.previous_key, prev_canary, sizeof(prev_canary))
        == 0);
    REQUIRE(session.iter_live == 1u);
    REQUIRE(session.txn_live == 1u);
    REQUIRE(spy.trace_count == before_trace); /* Port 0 */

    /* FAILED re-note: no mutation */
    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(spy.trace_count == before_trace);

    /* advance/exact_get rejected after note */
    REQUIRE(ninlil_domain_scan_advance(&session, 1u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_model_runtime_store_build_key(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &ck)
        == NINLIL_OK);
    key.data = ck.bytes;
    key.length = ck.length;
    (void)memset(&exact, 0xA5, sizeof(exact));
    REQUIRE(ninlil_domain_scan_exact_get(&session, key, &exact)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.trace_count == before_trace);

    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);

    /* DONE */
    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* D2-S5: sticky CORRUPT from note outranks future/mismatch candidates. */
static int test_s5_note_outranks_future_and_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_model_runtime_store_binding_t stored;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t future_key[16];
    uint8_t future_value[64];
    uint32_t future_key_len = 0u;
    uint32_t future_value_len = 0u;

    /* future then note */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(make_future_key(future_key, &future_key_len));
    REQUIRE(make_future_value(future_value, &future_value_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, future_key, future_key_len, future_value, future_value_len));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.recognizable_future_seen == 1u);
    REQUIRE(result.adopted == 0u);

    /* mismatch then note */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &stored));
    s2_default_binding(&candidate);
    candidate.limits.max_services = 99u;
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.profile_mismatch == 1u);
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.profile_mismatch == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.profile_mismatch == 1u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * D2-S5: fresh-session restart from front after partial abort.
 * Same-session budget resume is NOT labeled restart.
 */
static int test_s5_fresh_session_restart_from_front(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint64_t first_ok;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    first_ok = session.ok_row_count;
    REQUIRE(first_ok == 1u);
    REQUIRE(ninlil_domain_scan_abort(&session, &result) == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);

    /* Fresh session — not same-session budget resume. */
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.ok_row_count == 0u);
    REQUIRE(session.has_previous == 0u);
    REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
    REQUIRE(session.ok_row_count == 1u); /* from front again */
    REQUIRE(scan_to_end(&session, 64u) == 0);
    REQUIRE(session.ok_row_count == 17u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * D2-S5 invariant-only: first sticky is preserved across note.
 *
 * Seeds a legal private OPEN session with a pre-existing non-CORRUPT sticky
 * (simulating a prior Port-path primary), then calls note:
 *   return STORAGE_CORRUPT, but stored first sticky remains unchanged;
 *   finalize result preserves the first sticky (not overwritten by note).
 *
 * Label: INVARIANT-ONLY / not reachable D3 semantics. Production note never
 * invents a non-CORRUPT sticky itself; this unit only proves first-sticky
 * hold when one is already present before note.
 */
static int test_s5_first_sticky_preserved_on_note_invariant_only(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint64_t before_trace;
    uint64_t ok_before;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.has_sticky_primary == 0u);

    /* Seed a pre-existing non-CORRUPT sticky while still OPEN (private). */
    session.has_sticky_primary = 1u;
    session.sticky_primary = NINLIL_E_STORAGE;
    ok_before = session.ok_row_count;
    before_trace = spy.trace_count;

    REQUIRE(ninlil_domain_scan_note_terminal_corrupt(&session)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    /* Return is CORRUPT, but first sticky remains NINLIL_E_STORAGE. */
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
    REQUIRE(session.ok_row_count == ok_before);
    REQUIRE(spy.trace_count == before_trace); /* Port 0 */

    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_E_STORAGE);
    REQUIRE(result.status == NINLIL_E_STORAGE);
    REQUIRE(result.adopted == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* D2-S5: live sizeof + single 4096 value buffer + ceiling. */
static int test_s5_dsr2_live_sizeof_and_single_value(void)
{
    ninlil_domain_scan_workspace_t workspace;

    REQUIRE(NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES == 8192u);
    REQUIRE(sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES);
    REQUIRE(sizeof(workspace.value) == 4096u);
    REQUIRE(sizeof(workspace.key) == 255u);
    REQUIRE(sizeof(workspace.previous_key) == 255u);
    /* No second value-class buffer field in the workspace object. */
    REQUIRE(sizeof(workspace)
        == sizeof(ninlil_domain_scan_workspace_t));
    (void)memset(&workspace, 0, sizeof(workspace));
    return 0;
}

int main(void)
{
    if (test_empty_namespace() != 0) {
        return 1;
    }
    if (test_family14_and_current() != 0) {
        return 1;
    }
    if (test_future_then_end() != 0) {
        return 1;
    }
    if (test_budget_1_and_64() != 0) {
        return 1;
    }
    if (test_65_rows_budget_boundary() != 0) {
        return 1;
    }
    if (test_future_then_malformed_corrupt() != 0) {
        return 1;
    }
    if (test_malformed_then_future_stops_before_future() != 0) {
        return 1;
    }
    if (test_candidate_overridden_by_corruption() != 0) {
        return 1;
    }
    if (test_duplicate_and_out_of_order() != 0) {
        return 1;
    }
    if (test_bts_and_not_found_poison() != 0) {
        return 1;
    }
    if (test_begin_iter_shapes_fence() != 0) {
        return 1;
    }
    if (test_unknown_status_and_rollback_failure() != 0) {
        return 1;
    }
    if (test_misuse_and_budget_zero() != 0) {
        return 1;
    }
    if (test_alias_and_binding() != 0) {
        return 1;
    }
    if (test_abort_path() != 0) {
        return 1;
    }
    if (test_unchanged_prevalidation() != 0) {
        return 1;
    }
    if (test_counter_overflow_no_partial_mutation() != 0) {
        return 1;
    }
    if (test_handle_slot_drift_fence_original() != 0) {
        return 1;
    }
    if (test_success_finalize_does_not_close_handle() != 0) {
        return 1;
    }
    if (test_dsr2_workspace_bound() != 0) {
        return 1;
    }
    if (test_dsr2_bts_no_alloc() != 0) {
        return 1;
    }
    if (test_s2_workspace_ceiling() != 0) {
        return 1;
    }
    if (test_s2_candidate_null_and_alias() != 0) {
        return 1;
    }
    if (test_s2_candidate_copied_before_port() != 0) {
        return 1;
    }
    if (test_s2_missing_keys_no_iter_open() != 0) {
        return 1;
    }
    if (test_s2_get_bts_no_reread() != 0) {
        return 1;
    }
    if (test_s2_iterator_value_disagreement() != 0) {
        return 1;
    }
    if (test_s2_iterator_missing_catalog_key() != 0) {
        return 1;
    }
    if (test_s2_mismatch_skip_and_f14_override() != 0) {
        return 1;
    }
    if (test_s2_future_profile_and_corrupt_precedence() != 0) {
        return 1;
    }
    if (test_s2_get_descriptor_rewrite_rejected() != 0) {
        return 1;
    }
    if (test_s2_one_iterator_and_call_order() != 0) {
        return 1;
    }
    if (test_s2_iter_descriptor_rewrite_rejected() != 0) {
        return 1;
    }
    if (test_s4_exact_get_present_absent_zero_exhausted() != 0) {
        return 1;
    }
    if (test_s4_exact_get_key_alias_and_shape() != 0) {
        return 1;
    }
    if (test_s4_exact_get_state_gates_and_sticky() != 0) {
        return 1;
    }
    if (test_s4_exact_get_handle_drift_and_resume() != 0) {
        return 1;
    }
    if (test_s4_exact_get_bts_and_repeat_overwrite() != 0) {
        return 1;
    }
    if (test_s4_exact_get_live_authority_corrupt() != 0) {
        return 1;
    }
    if (test_s4_exact_get_ok_bad_and_nonempty_length() != 0) {
        return 1;
    }
    if (test_s5_note_terminal_corrupt_gates() != 0) {
        return 1;
    }
    if (test_s5_note_outranks_future_and_mismatch() != 0) {
        return 1;
    }
    if (test_s5_fresh_session_restart_from_front() != 0) {
        return 1;
    }
    if (test_s5_first_sticky_preserved_on_note_invariant_only() != 0) {
        return 1;
    }
    if (test_s5_dsr2_live_sizeof_and_single_value() != 0) {
        return 1;
    }
    return 0;
}
