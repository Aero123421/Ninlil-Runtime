#include "storage_canonical_plan.h"

#include <limits.h>
#include <stdint.h>
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

/*
 * Test-local behavioral mirror of the production static helper. The view
 * bound proof below establishes why production staging overflow is
 * unreachable through the public canonical-view input shape.
 */
static int test_checked_add_u64(uint64_t left, uint64_t right, uint64_t *out)
{
    if (out == NULL || left > UINT64_MAX - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

typedef struct plan_spy {
    ninlil_storage_ops_t ops;
    uint64_t max_entries;
    uint64_t used_entries;
    uint64_t max_bytes;
    uint64_t used_bytes;
    uint32_t capacity_calls;
    uint32_t begin_calls;
    uint32_t put_calls;
    uint32_t erase_calls;
    uint32_t commit_calls;
    uint32_t rollback_calls;
    int txn_token;
} plan_spy_t;

static ninlil_storage_status_t spy_capacity(
    void *user, ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    plan_spy_t *spy = (plan_spy_t *)user;
    (void)handle;
    spy->capacity_calls += 1u;
    out_capacity->max_entries = spy->max_entries;
    out_capacity->used_entries = spy->used_entries;
    out_capacity->max_bytes = spy->max_bytes;
    out_capacity->used_bytes = spy->used_bytes;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t spy_begin(
    void *user, ninlil_storage_handle_t handle, ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    plan_spy_t *spy = (plan_spy_t *)user;
    (void)handle;
    REQUIRE(mode == NINLIL_STORAGE_READ_WRITE);
    spy->begin_calls += 1u;
    *out_transaction = &spy->txn_token;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t spy_put(
    void *user, ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key, ninlil_bytes_view_t value)
{
    plan_spy_t *spy = (plan_spy_t *)user;
    REQUIRE(transaction == &spy->txn_token);
    REQUIRE(key.data != NULL && key.length != 0u);
    REQUIRE(value.length == 0u || value.data != NULL);
    spy->put_calls += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t spy_erase(
    void *user, ninlil_storage_txn_t transaction, ninlil_bytes_view_t key)
{
    plan_spy_t *spy = (plan_spy_t *)user;
    REQUIRE(transaction == &spy->txn_token);
    REQUIRE(key.data != NULL && key.length != 0u);
    spy->erase_calls += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t spy_commit(
    void *user, ninlil_storage_txn_t transaction,
    ninlil_durability_t durability)
{
    plan_spy_t *spy = (plan_spy_t *)user;
    REQUIRE(transaction == &spy->txn_token);
    REQUIRE(durability == NINLIL_DURABILITY_FULL);
    spy->commit_calls += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t spy_rollback(
    void *user, ninlil_storage_txn_t transaction)
{
    plan_spy_t *spy = (plan_spy_t *)user;
    REQUIRE(transaction == &spy->txn_token);
    spy->rollback_calls += 1u;
    return NINLIL_STORAGE_OK;
}

static void spy_init(plan_spy_t *spy,
    uint64_t max_entries, uint64_t used_entries,
    uint64_t max_bytes, uint64_t used_bytes)
{
    (void)memset(spy, 0, sizeof(*spy));
    spy->max_entries = max_entries;
    spy->used_entries = used_entries;
    spy->max_bytes = max_bytes;
    spy->used_bytes = used_bytes;
    spy->ops.abi_version = NINLIL_ABI_VERSION;
    spy->ops.struct_size = (uint16_t)sizeof(spy->ops);
    spy->ops.user = spy;
    spy->ops.begin = spy_begin;
    spy->ops.put = spy_put;
    spy->ops.erase = spy_erase;
    spy->ops.capacity = spy_capacity;
    spy->ops.commit = spy_commit;
    spy->ops.rollback = spy_rollback;
}

static ninlil_storage_canonical_row_t row(
    const uint8_t *key, uint32_t key_length,
    const uint8_t *value, uint32_t value_length)
{
    ninlil_storage_canonical_row_t result;
    result.key.data = key;
    result.key.length = key_length;
    result.value.data = value;
    result.value.length = value_length;
    return result;
}

static int test_exact_64_and_65_mutation_zero(void)
{
    plan_spy_t spy;
    ninlil_storage_canonical_row_t begin[32];
    ninlil_storage_canonical_row_t final[33];
    ninlil_storage_canonical_view_t begin_view;
    ninlil_storage_canonical_view_t final_view;
    ninlil_storage_canonical_result_t result;
    uint8_t begin_keys[32];
    uint8_t final_keys[33];
    uint8_t values[33];
    uint32_t index;

    for (index = 0u; index < 32u; ++index) {
        begin_keys[index] = (uint8_t)(0x10u + index);
        begin[index] = row(&begin_keys[index], 1u, &values[index], 1u);
    }
    for (index = 0u; index < 33u; ++index) {
        final_keys[index] = (uint8_t)(0x80u + index);
        final[index] = row(&final_keys[index], 1u, &values[index], 1u);
    }
    begin_view.rows = begin;
    begin_view.row_count = 32u;
    final_view.rows = final;
    final_view.row_count = 32u;
    spy_init(&spy, 32u, 32u, 69632u, 32u * 18u);
    REQUIRE(ninlil_storage_canonical_apply(&spy.ops, &spy,
        begin_view, final_view, NULL, NULL, &result) == NINLIL_STORAGE_OK);
    REQUIRE(result.metrics.staging_entries == 64u);
    REQUIRE(spy.capacity_calls == 1u && spy.begin_calls == 1u);
    REQUIRE(spy.put_calls == 32u && spy.erase_calls == 32u);
    REQUIRE(spy.commit_calls == 1u && spy.rollback_calls == 0u);

    final_view.row_count = 33u;
    spy_init(&spy, 32u, 32u, 69632u, 32u * 18u);
    REQUIRE(ninlil_storage_canonical_apply(&spy.ops, &spy,
        begin_view, final_view, NULL, NULL, &result)
        == NINLIL_STORAGE_NO_SPACE);
    REQUIRE(result.metrics.staging_entries == 65u);
    REQUIRE(spy.capacity_calls == 1u && spy.begin_calls == 0u);
    REQUIRE(spy.put_calls == 0u && spy.erase_calls == 0u
        && spy.commit_calls == 0u && spy.rollback_calls == 0u);
    return 0;
}

static int test_exact_139264_and_139265_mutation_zero(void)
{
    static uint8_t large[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
    static uint8_t tail[4063u];
    static const uint8_t begin_keys[2] = {0x10u, 0x11u};
    static const uint8_t final_keys[2] = {0x20u, 0x21u};
    ninlil_storage_canonical_row_t begin[2];
    ninlil_storage_canonical_row_t final[2];
    ninlil_storage_canonical_view_t begin_view;
    ninlil_storage_canonical_view_t final_view;
    ninlil_storage_canonical_result_t result;
    plan_spy_t spy;

    begin[0] = row(&begin_keys[0], 1u, large, sizeof(large));
    begin[1] = row(&begin_keys[1], 1u, tail, 4062u);
    final[0] = row(&final_keys[0], 1u, large, sizeof(large));
    final[1] = row(&final_keys[1], 1u, tail, 4062u);
    begin_view.rows = begin;
    begin_view.row_count = 2u;
    final_view.rows = final;
    final_view.row_count = 2u;
    spy_init(&spy, 32u, 2u, 69632u, 69632u);
    REQUIRE(ninlil_storage_canonical_apply(&spy.ops, &spy,
        begin_view, final_view, NULL, NULL, &result) == NINLIL_STORAGE_OK);
    REQUIRE(result.metrics.staging_bytes == 139264u);
    REQUIRE(spy.begin_calls == 1u && spy.put_calls == 2u
        && spy.erase_calls == 2u && spy.commit_calls == 1u);

    final[1] = row(&final_keys[1], 1u, tail, 4063u);
    spy_init(&spy, 32u, 2u, 69632u, 69632u);
    REQUIRE(ninlil_storage_canonical_apply(&spy.ops, &spy,
        begin_view, final_view, NULL, NULL, &result)
        == NINLIL_STORAGE_NO_SPACE);
    REQUIRE(result.metrics.staging_bytes == 139265u);
    REQUIRE(spy.capacity_calls == 1u && spy.begin_calls == 0u
        && spy.put_calls == 0u && spy.erase_calls == 0u
        && spy.commit_calls == 0u);
    return 0;
}

static int test_degenerate_empty_claim_is_rejected(void)
{
    plan_spy_t spy;
    ninlil_storage_canonical_view_t empty;
    ninlil_storage_canonical_result_t result;

    empty.rows = NULL;
    empty.row_count = 0u;
    spy_init(&spy, 32u, 0u, 69632u, 0u);
    REQUIRE(ninlil_storage_canonical_apply(&spy.ops, &spy,
        empty, empty, NULL, NULL, &result) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(result.metrics.staging_entries == 0u
        && result.metrics.staging_bytes == 0u);
    REQUIRE(spy.capacity_calls == 0u && spy.begin_calls == 0u
        && spy.put_calls == 0u && spy.erase_calls == 0u
        && spy.commit_calls == 0u);
    return 0;
}

/*
 * Normative capacity allows maxima up to UINT64_MAX-1 (not half-range).
 * Fixture/providers may still refuse UINT64_MAX as non-finite.
 */
static int test_uint64_max_minus_one_maxima_accepted(void)
{
    plan_spy_t spy;
    static const uint8_t begin_key = 0x10u;
    static const uint8_t final_key = 0x20u;
    static const uint8_t value = 0xAAu;
    ninlil_storage_canonical_row_t begin[1];
    ninlil_storage_canonical_row_t final[1];
    ninlil_storage_canonical_view_t begin_view;
    ninlil_storage_canonical_view_t final_view;
    ninlil_storage_canonical_result_t result;
    const uint64_t max_entries = UINT64_MAX - 1u;
    const uint64_t max_bytes = UINT64_MAX - 1u;

    begin[0] = row(&begin_key, 1u, &value, 1u);
    final[0] = row(&final_key, 1u, &value, 1u);
    begin_view.rows = begin;
    begin_view.row_count = 1u;
    final_view.rows = final;
    final_view.row_count = 1u;
    spy_init(&spy, max_entries, 1u, max_bytes, 18u);
    REQUIRE(ninlil_storage_canonical_apply(&spy.ops, &spy,
        begin_view, final_view, NULL, NULL, &result) == NINLIL_STORAGE_OK);
    REQUIRE(result.metrics.staging_entries == 2u);
    REQUIRE(result.metrics.staging_bytes == 36u);
    REQUIRE(spy.capacity_calls == 1u && spy.begin_calls == 1u);
    REQUIRE(spy.put_calls == 1u && spy.erase_calls == 1u);
    REQUIRE(spy.commit_calls == 1u && spy.rollback_calls == 0u);
    return 0;
}

/*
 * Behavioral negative for the checked-add rule, plus compile-time evidence
 * that valid view metrics cannot reach production staging overflow: row_count
 * is uint32_t and per-row logical bytes are bounded, so two successful views
 * always fit in uint64_t. This does not claim direct linkage to the production
 * static helper.
 */
static int test_checked_add_overflow_helper_and_view_bound(void)
{
    uint64_t sum = 7u;
    const uint64_t max_row_bytes =
        UINT64_C(16) + 255u + (uint64_t)NINLIL_M1A_MAX_STORAGE_VALUE_BYTES;
    uint64_t max_view_bytes;
    uint64_t two_views;

    REQUIRE(test_checked_add_u64(UINT64_MAX, 1u, &sum) == 0);
    REQUIRE(sum == 7u);
    REQUIRE(test_checked_add_u64(UINT64_MAX - 1u, 2u, &sum) == 0);
    REQUIRE(test_checked_add_u64(1u, 2u, &sum) == 1);
    REQUIRE(sum == 3u);

    REQUIRE(sizeof(((ninlil_storage_canonical_view_t *)0)->row_count)
        == sizeof(uint32_t));
    REQUIRE(max_row_bytes
        == UINT64_C(16) + 255u + (uint64_t)NINLIL_M1A_MAX_STORAGE_VALUE_BYTES);
    REQUIRE(max_row_bytes <= (UINT64_MAX / (uint64_t)UINT32_MAX));
    max_view_bytes = (uint64_t)UINT32_MAX * max_row_bytes;
    REQUIRE(max_view_bytes <= (UINT64_MAX / 2u));
    REQUIRE(test_checked_add_u64(max_view_bytes, max_view_bytes, &two_views)
        == 1);
    REQUIRE(two_views == max_view_bytes * 2u);
    return 0;
}

int main(void)
{
    if (test_exact_64_and_65_mutation_zero() != 0
        || test_exact_139264_and_139265_mutation_zero() != 0
        || test_degenerate_empty_claim_is_rejected() != 0
        || test_uint64_max_minus_one_maxima_accepted() != 0
        || test_checked_add_overflow_helper_and_view_bound() != 0) {
        return 1;
    }
    (void)puts("storage canonical production planner tests passed");
    return 0;
}
