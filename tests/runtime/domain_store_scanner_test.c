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
    REQUIRE(ninlil_spy_add_row(&spy, key, len, &empty, 0u));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin(
            &session, ops, &handle, &workspace) == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 8u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
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
    REQUIRE(sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES);
    REQUIRE(sizeof(ninlil_domain_scan_workspace_t)
        == NINLIL_DOMAIN_SCAN_KEY_CAPACITY
            + NINLIL_DOMAIN_SCAN_VALUE_CAPACITY
            + NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY);
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
    return 0;
}
