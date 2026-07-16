/* Provider-neutral final-view and iterator-snapshot conformance vectors. */
#ifndef NINLIL_TEST_STORAGE_PROVIDER_CONFORMANCE_H
#define NINLIL_TEST_STORAGE_PROVIDER_CONFORMANCE_H

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <stdint.h>
#include <string.h>

static ninlil_bytes_view_t spc_bytes(const void *data, uint32_t length)
{
    ninlil_bytes_view_t view;
    view.data = (const uint8_t *)data;
    view.length = length;
    return view;
}

static ninlil_mut_bytes_t spc_mut(void *data, uint32_t capacity)
{
    ninlil_mut_bytes_t value;
    value.data = (uint8_t *)data;
    value.capacity = capacity;
    value.length = 0u;
    return value;
}

#define SPC_REQUIRE(condition)                                                 \
    do {                                                                       \
        if (!(condition)) {                                                    \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)

/* Test oracle for the M1a Core plan precondition in docs/12 and docs/14. */
static int spc_checked_add_u64(uint64_t left, uint64_t right, uint64_t *out)
{
    if (out == NULL || left > UINT64_MAX - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

static int spc_core_plan_within_staging_bound(
    uint64_t max_entries,
    uint64_t max_bytes,
    uint64_t begin_entries,
    uint64_t begin_bytes,
    uint64_t final_entries,
    uint64_t final_bytes,
    uint64_t intermediate_entries,
    uint64_t intermediate_bytes)
{
    uint64_t staging_entries;
    uint64_t staging_bytes;

    if (max_entries == 0u || max_bytes == 0u
        || begin_entries > max_entries || final_entries > max_entries
        || begin_bytes > max_bytes || final_bytes > max_bytes
        || !spc_checked_add_u64(begin_entries, final_entries, &staging_entries)
        || !spc_checked_add_u64(begin_bytes, final_bytes, &staging_bytes)) {
        return 0;
    }
    return intermediate_entries <= staging_entries
        && intermediate_bytes <= staging_bytes;
}

/*
 * The caller supplies a fresh handle whose configured committed capacity is
 * exactly 32 entries and at least 69,632 logical bytes. A zero return means
 * success; a non-zero return is the failing line in this header.
 */
static int ninlil_test_storage_provider_final_view_contract(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle)
{
    static uint8_t large_a[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
    static uint8_t large_b[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
    static uint8_t oversized[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES + 1u];
    static uint8_t output[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
    static uint8_t filler_a[4062u];
    static uint8_t filler_b[4062u];
    static const uint8_t max_key_a[] = {0x01u};
    static const uint8_t max_key_b[] = {0x02u};
    static const uint8_t byte_key_c[] = {0x03u};
    static const uint8_t byte_key_d[] = {0x04u};
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t old_iter = NULL;
    ninlil_storage_iter_t new_iter = NULL;
    ninlil_mut_bytes_t out;
    ninlil_mut_bytes_t out_key;
    ninlil_storage_capacity_t capacity;
    uint8_t keys[64u][2u];
    uint8_t values[64u];
    uint32_t index;

    SPC_REQUIRE(ops != NULL && handle != NULL);
    (void)memset(large_a, 0xA5, sizeof(large_a));
    (void)memset(large_b, 0x5A, sizeof(large_b));
    (void)memset(oversized, 0xC3, sizeof(oversized));
    (void)memset(filler_a, 0x3C, sizeof(filler_a));
    (void)memset(filler_b, 0xC3, sizeof(filler_b));

    /* Exact inclusive bounds are legal; one above is never a Core plan. */
    SPC_REQUIRE(spc_core_plan_within_staging_bound(
        32u, 69632u, 32u, 69632u, 32u, 69632u, 64u, 139264u));
    SPC_REQUIRE(!spc_core_plan_within_staging_bound(
        32u, 69632u, 32u, 69632u, 32u, 69632u, 65u, 139264u));
    SPC_REQUIRE(!spc_core_plan_within_staging_bound(
        32u, 69632u, 32u, 69632u, 32u, 69632u, 64u, 139265u));

    /* Inclusive 65,536-byte value and same-key replacement. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(
                    ops->user,
                    txn,
                    spc_bytes(max_key_a, sizeof(max_key_a)),
                    spc_bytes(large_a, sizeof(large_a)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(
                    ops->user,
                    txn,
                    spc_bytes(max_key_a, sizeof(max_key_a)),
                    spc_bytes(large_b, sizeof(large_b)))
        == NINLIL_STORAGE_OK);
    out = spc_mut(output, sizeof(output));
    SPC_REQUIRE(ops->get(
                    ops->user,
                    txn,
                    spc_bytes(max_key_a, sizeof(max_key_a)),
                    &out)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(out.length == sizeof(large_b)
        && memcmp(output, large_b, sizeof(large_b)) == 0);
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Put-before-erase is independent of transient old+new value bytes. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(
                    ops->user,
                    txn,
                    spc_bytes(max_key_b, sizeof(max_key_b)),
                    spc_bytes(large_a, sizeof(large_a)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->erase(
                    ops->user, txn, spc_bytes(max_key_a, sizeof(max_key_a)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Replace the max-value row with exactly 32 small committed rows. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->erase(
                    ops->user, txn, spc_bytes(max_key_b, sizeof(max_key_b)))
        == NINLIL_STORAGE_OK);
    for (index = 0u; index < 32u; ++index) {
        keys[index][0] = 0x80u;
        keys[index][1] = (uint8_t)index;
        values[index] = (uint8_t)(index + 1u);
        SPC_REQUIRE(ops->put(
                        ops->user,
                        txn,
                        spc_bytes(keys[index], 2u),
                        spc_bytes(&values[index], 1u))
            == NINLIL_STORAGE_OK);
    }
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Exact 64-entry intermediate: 32 new puts before all 32 old erases. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    for (index = 32u; index < 64u; ++index) {
        keys[index][0] = 0x81u;
        keys[index][1] = (uint8_t)(index - 32u);
        values[index] = (uint8_t)(index + 1u);
        SPC_REQUIRE(ops->put(
                        ops->user,
                        txn,
                        spc_bytes(keys[index], 2u),
                        spc_bytes(&values[index], 1u))
            == NINLIL_STORAGE_OK);
    }
    for (index = 0u; index < 32u; ++index) {
        SPC_REQUIRE(ops->erase(
                        ops->user, txn, spc_bytes(keys[index], 2u))
            == NINLIL_STORAGE_OK);
    }
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    SPC_REQUIRE(ops->capacity(ops->user, handle, &capacity)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(capacity.used_entries == 32u);

    /* iter_open owns a fixed deep snapshot; a new iterator sees mutations. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->iter_open(
                    ops->user, txn, spc_bytes(keys[33], 2u), &old_iter)
        == NINLIL_STORAGE_OK);
    values[33] = 0xF1u;
    SPC_REQUIRE(ops->put(
                    ops->user,
                    txn,
                    spc_bytes(keys[33], 2u),
                    spc_bytes(&values[33], 1u))
        == NINLIL_STORAGE_OK);
    out_key = spc_mut(output, 2u);
    out = spc_mut(output + 2u, 1u);
    SPC_REQUIRE(ops->iter_next(ops->user, old_iter, &out_key, &out)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(out.length == 1u && output[2] == 34u);
    SPC_REQUIRE(ops->iter_open(
                    ops->user, txn, spc_bytes(keys[33], 2u), &new_iter)
        == NINLIL_STORAGE_OK);
    out_key = spc_mut(output, 2u);
    out = spc_mut(output + 2u, 1u);
    SPC_REQUIRE(ops->iter_next(ops->user, new_iter, &out_key, &out)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(out.length == 1u && output[2] == 0xF1u);
    ops->iter_close(ops->user, old_iter);
    old_iter = NULL;
    ops->iter_close(ops->user, new_iter);
    new_iter = NULL;

    /* Rejected single-value overflow is mutation-0. */
    SPC_REQUIRE(ops->put(
                    ops->user,
                    txn,
                    spc_bytes(keys[33], 2u),
                    spc_bytes(oversized, sizeof(oversized)))
        == NINLIL_STORAGE_NO_SPACE);
    out = spc_mut(output, 1u);
    SPC_REQUIRE(ops->get(
                    ops->user, txn, spc_bytes(keys[33], 2u), &out)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(out.length == 1u && output[0] == 0xF1u);
    SPC_REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Reset to empty before the exact logical-byte boundary vector. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    for (index = 32u; index < 64u; ++index) {
        SPC_REQUIRE(ops->erase(
                        ops->user, txn, spc_bytes(keys[index], 2u))
            == NINLIL_STORAGE_OK);
    }
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* 65,553 + 4,079 = exact committed max 69,632 logical bytes. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(ops->user,
                    txn,
                    spc_bytes(max_key_a, sizeof(max_key_a)),
                    spc_bytes(large_a, sizeof(large_a)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(ops->user,
                    txn,
                    spc_bytes(max_key_b, sizeof(max_key_b)),
                    spc_bytes(filler_a, sizeof(filler_a)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Distinct full final view first reaches exact 139,264-byte staging. */
    SPC_REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(ops->user,
                    txn,
                    spc_bytes(byte_key_c, sizeof(byte_key_c)),
                    spc_bytes(large_b, sizeof(large_b)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->put(ops->user,
                    txn,
                    spc_bytes(byte_key_d, sizeof(byte_key_d)),
                    spc_bytes(filler_b, sizeof(filler_b)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->erase(
                    ops->user, txn, spc_bytes(max_key_a, sizeof(max_key_a)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->erase(
                    ops->user, txn, spc_bytes(max_key_b, sizeof(max_key_b)))
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    SPC_REQUIRE(ops->capacity(ops->user, handle, &capacity)
        == NINLIL_STORAGE_OK);
    SPC_REQUIRE(capacity.used_entries == 2u && capacity.used_bytes == 69632u);
    return 0;
}

#undef SPC_REQUIRE

#endif /* NINLIL_TEST_STORAGE_PROVIDER_CONFORMANCE_H */
