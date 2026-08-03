/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_host_store.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                       \
                "%s:%d: requirement failed: %s\n",                           \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct fixture {
    ninlil_mfdt_v1_host_store_t *store;
    ninlil_mfdt_v1_store_port_t port;
} fixture_t;

static fixture_t fixture_open(void)
{
    fixture_t fixture;

    (void)memset(&fixture, 0, sizeof(fixture));
    fixture.store = ninlil_mfdt_v1_host_store_create();
    if (fixture.store != NULL
        && ninlil_mfdt_v1_host_store_open_port(
            fixture.store,
            &fixture.port) != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_host_store_destroy(fixture.store);
        (void)memset(&fixture, 0, sizeof(fixture));
    }
    return fixture;
}

static void fixture_close(fixture_t *fixture)
{
    if (fixture->store != NULL) {
        ninlil_mfdt_v1_host_store_close_port(
            fixture->store,
            &fixture->port);
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
    }
    (void)memset(fixture, 0, sizeof(*fixture));
}

static void make_key(
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const char kind[4],
    uint8_t transfer_number)
{
    uint8_t index;

    (void)memcpy(key, kind, 4u);
    for (index = 0u; index < 16u; ++index) {
        key[4u + index] = (uint8_t)(transfer_number + index);
    }
}

static int inventory(
    fixture_t *fixture,
    uint32_t *keys,
    uint64_t *logical,
    uint64_t *generation,
    uint64_t *full_count)
{
    return ninlil_mfdt_v1_host_store_inventory(
        fixture->store,
        keys,
        logical,
        generation,
        full_count);
}

static int full_begin_actual(fixture_t *fixture)
{
    uint32_t keys;
    uint64_t logical;
    uint64_t generation;
    uint64_t full_count;

    if (inventory(
            fixture,
            &keys,
            &logical,
            &generation,
            &full_count) != NINLIL_MFDT_V1_OK) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    return ninlil_mfdt_v1_store_full_begin(
        &fixture->port,
        keys,
        logical);
}

static int commit_one(
    fixture_t *fixture,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len)
{
    int rc = full_begin_actual(fixture);

    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_put(
            &fixture->port,
            key,
            value,
            value_len);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_store_full_commit(&fixture->port);
    } else if (fixture->port.full_open != 0u) {
        (void)ninlil_mfdt_v1_store_full_rollback(&fixture->port);
    }
    return rc;
}

static int read_value(
    fixture_t *fixture,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value,
    uint32_t cap,
    uint32_t *length,
    int *present)
{
    return ninlil_mfdt_v1_store_read(
        &fixture->port,
        key,
        value,
        cap,
        length,
        present);
}

static int test_guarantee_and_status_contract(void)
{
    const ninlil_mfdt_v1_store_guarantees_t *guarantees =
        ninlil_mfdt_v1_host_store_guarantees();
    ninlil_mfdt_v1_store_guarantees_t candidate;
    ninlil_storage_ops_t invalid_ops;
    ninlil_mfdt_v1_store_port_t port;

    REQUIRE(guarantees != NULL);
    REQUIRE(guarantees->struct_size == sizeof(*guarantees));
    REQUIRE(guarantees->flags == NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS);
    REQUIRE(guarantees->committed_keys_max == 32u);
    REQUIRE(guarantees->committed_logical_bytes_max == 384476u);
    REQUIRE(guarantees->full_staging_logical_bytes_max == 50303u);
    REQUIRE(guarantees->begin_final_row_images_max == 34u);
    REQUIRE(guarantees->begin_final_union_logical_bytes_max == 434779u);
    REQUIRE(guarantees->full_ops_max == 4u);
    REQUIRE(ninlil_mfdt_v1_store_guarantees_validate(guarantees)
        == NINLIL_MFDT_V1_OK);

    candidate = *guarantees;
    candidate.struct_size = (uint32_t)(sizeof(candidate) - 1u);
    REQUIRE(ninlil_mfdt_v1_store_guarantees_validate(&candidate)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    candidate = *guarantees;
    candidate.flags &= ~NINLIL_MFDT_V1_STORE_ATOMIC_FULL;
    REQUIRE(ninlil_mfdt_v1_store_guarantees_validate(&candidate)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    candidate = *guarantees;
    candidate.committed_keys_max = 31u;
    REQUIRE(ninlil_mfdt_v1_store_guarantees_validate(&candidate)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    candidate = *guarantees;
    candidate.flags |= ((uint32_t)1u << 31);
    REQUIRE(ninlil_mfdt_v1_store_guarantees_validate(&candidate)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(ninlil_mfdt_v1_store_map_status(NINLIL_STORAGE_OK)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_map_status(NINLIL_STORAGE_NO_SPACE)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(ninlil_mfdt_v1_store_map_status(NINLIL_STORAGE_IO_ERROR)
        == NINLIL_MFDT_V1_ERR_STORAGE);
    REQUIRE(ninlil_mfdt_v1_store_map_status(
        NINLIL_STORAGE_COMMIT_UNKNOWN) == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN);
    REQUIRE(ninlil_mfdt_v1_store_map_status(
        (ninlil_storage_status_t)UINT32_C(0xfedcba98))
        == NINLIL_MFDT_V1_ERR_CORRUPT);

    (void)memset(&invalid_ops, 0, sizeof(invalid_ops));
    invalid_ops.abi_version = NINLIL_ABI_VERSION;
    invalid_ops.struct_size = (uint16_t)(sizeof(invalid_ops) - 1u);
    REQUIRE(ninlil_mfdt_v1_store_port_init(
        &port,
        &invalid_ops,
        (ninlil_storage_handle_t)&invalid_ops,
        guarantees) == NINLIL_MFDT_V1_ERR_PARAM);
    return 0;
}

static int test_replace_erase_and_no_pool_leak(void)
{
    fixture_t fixture = fixture_open();
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t keys4[4][NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value[32];
    uint8_t output[32];
    uint32_t count;
    uint32_t output_len;
    uint64_t logical;
    uint64_t generation;
    uint64_t full_count;
    int present;
    uint32_t cycle;
    uint8_t index;

    REQUIRE(fixture.store != NULL);
    make_key(key, "NM3S", 1u);
    (void)memset(value, 0x11, sizeof(value));
    REQUIRE(commit_one(&fixture, key, value, 3u) == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &count, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(count == 1u && logical == 39u && full_count == 1u);

    REQUIRE(commit_one(&fixture, key, value, 9u) == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &count, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(count == 1u && logical == 45u && full_count == 2u);
    REQUIRE(read_value(
        &fixture, key, output, sizeof(output), &output_len, &present)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 1 && output_len == 9u);

    for (cycle = 0u; cycle < 200u; ++cycle) {
        uint32_t length = (cycle % 31u) + 1u;
        value[0] = (uint8_t)cycle;
        REQUIRE(commit_one(&fixture, key, value, length)
            == NINLIL_MFDT_V1_OK);
    }
    REQUIRE(read_value(
        &fixture, key, output, sizeof(output), &output_len, &present)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 1 && output_len == 14u);
    REQUIRE(output[0] == (uint8_t)199u);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_erase(&fixture.port, key)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &count, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(count == 0u && logical == 0u);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_erase(&fixture.port, key)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &count, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(count == 0u && logical == 0u);

    for (index = 0u; index < 4u; ++index) {
        make_key(keys4[index], "NRC1", (uint8_t)(20u + index));
    }
    for (index = 0u; index < 4u; index = (uint8_t)(index + 2u)) {
        REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
        REQUIRE(ninlil_mfdt_v1_store_full_put(
            &fixture.port, keys4[index], value, 1u) == NINLIL_MFDT_V1_OK);
        REQUIRE(ninlil_mfdt_v1_store_full_put(
            &fixture.port, keys4[index + 1u], value, 1u)
            == NINLIL_MFDT_V1_OK);
        REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
            == NINLIL_MFDT_V1_OK);
    }
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    for (index = 0u; index < 4u; ++index) {
        REQUIRE(ninlil_mfdt_v1_store_full_erase(
            &fixture.port, keys4[index]) == NINLIL_MFDT_V1_OK);
    }
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &count, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(count == 0u && logical == 0u);

    fixture_close(&fixture);
    return 0;
}

static int test_duplicate_conflict_and_second_put_atomicity(void)
{
    fixture_t fixture = fixture_open();
    uint8_t key_a[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t key_b[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
    uint32_t keys;
    uint64_t logical;
    uint64_t generation;
    uint64_t full_count;

    REQUIRE(fixture.store != NULL);
    make_key(key_a, "NM3S", 2u);
    make_key(key_b, "NRC1", 2u);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_a, value, sizeof(value)) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_a, value, sizeof(value))
        == NINLIL_MFDT_V1_ERR_STATE);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        != NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 0u && logical == 0u && full_count == 0u);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_a, value, sizeof(value)) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_erase(&fixture.port, key_a)
        == NINLIL_MFDT_V1_ERR_STATE);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        != NINLIL_MFDT_V1_OK);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_erase(&fixture.port, key_a)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_a, value, sizeof(value))
        == NINLIL_MFDT_V1_ERR_STATE);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        != NINLIL_MFDT_V1_OK);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_a, value, sizeof(value)) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_host_store_fault_next(
        fixture.store,
        NINLIL_MFDT_V1_HOST_STORE_OP_PUT,
        NINLIL_STORAGE_NO_SPACE,
        NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE));
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_b, value, sizeof(value))
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 0u && logical == 0u && full_count == 0u);
    REQUIRE(ninlil_mfdt_v1_host_store_call_count(
        fixture.store, NINLIL_MFDT_V1_HOST_STORE_OP_ROLLBACK) >= 4u);

    fixture_close(&fixture);
    return 0;
}

static int fill_exact_host_max(
    fixture_t *fixture,
    uint8_t *active_value,
    uint8_t *nrc1_value,
    uint8_t *terminal_value)
{
    uint8_t active_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t terminal_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t group;
    int rc;

    for (group = 0u; group < 16u; ++group) {
        make_key(nrc1_key, "NRC1", group);
        if (group < 4u) {
            make_key(active_key, "NM3S", group);
            rc = full_begin_actual(fixture);
            if (rc == NINLIL_MFDT_V1_OK) {
                rc = ninlil_mfdt_v1_store_full_put(
                    &fixture->port,
                    active_key,
                    active_value,
                    NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
            }
        } else {
            make_key(terminal_key, "NM30", group);
            rc = full_begin_actual(fixture);
            if (rc == NINLIL_MFDT_V1_OK) {
                rc = ninlil_mfdt_v1_store_full_put(
                    &fixture->port,
                    terminal_key,
                    terminal_value,
                    NINLIL_MFDT_V1_NM30_BYTES);
            }
        }
        if (rc == NINLIL_MFDT_V1_OK) {
            rc = ninlil_mfdt_v1_store_full_put(
                &fixture->port,
                nrc1_key,
                nrc1_value,
                NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
        }
        if (rc == NINLIL_MFDT_V1_OK) {
            rc = ninlil_mfdt_v1_store_full_commit(&fixture->port);
        }
        if (rc != NINLIL_MFDT_V1_OK) {
            if (fixture->port.full_open != 0u) {
                (void)ninlil_mfdt_v1_store_full_rollback(&fixture->port);
            }
            return rc;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static int test_exact_capacity_staging_union_and_inventory_lie(void)
{
    fixture_t fixture = fixture_open();
    uint8_t *active_value =
        (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u);
    uint8_t *nrc1_value =
        (uint8_t *)malloc(NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    uint8_t terminal_value[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t active_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t seventeenth_active[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t seventeenth_nrc1[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t readback[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u];
    uint32_t keys;
    uint32_t readback_len;
    uint64_t logical;
    uint64_t generation;
    uint64_t full_count;
    uint64_t generation_before;
    uint64_t full_before;
    int present;

    REQUIRE(fixture.store != NULL);
    REQUIRE(active_value != NULL && nrc1_value != NULL);
    (void)memset(
        active_value,
        0xa1,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u);
    (void)memset(
        nrc1_value,
        0xb2,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    (void)memset(terminal_value, 0xc3, sizeof(terminal_value));
    REQUIRE(fill_exact_host_max(
        &fixture, active_value, nrc1_value, terminal_value)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 32u);
    REQUIRE(logical == 384476u);
    REQUIRE(full_count == 16u);

    make_key(active_key, "NM3S", 0u);
    make_key(nrc1_key, "NRC1", 0u);
    active_value[0] = 0xd4u;
    nrc1_value[0] = 0xe5u;
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        active_key,
        active_value,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        nrc1_key,
        nrc1_value,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES) == NINLIL_MFDT_V1_OK);
    REQUIRE(fixture.port.staged_logical_bytes == 50303u);
    REQUIRE(fixture.port.begin_committed_logical_bytes
            + fixture.port.staged_logical_bytes == 434779u);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        active_key,
        active_value,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        nrc1_key,
        nrc1_value,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(read_value(
        &fixture,
        active_key,
        readback,
        sizeof(readback),
        &readback_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 1);
    REQUIRE(readback_len == NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    REQUIRE(readback[0] == 0xd4u);

    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation_before, &full_before)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        active_key,
        active_value,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX + 1u) == NINLIL_MFDT_V1_OK);
    /* Final committed view would be exact maximum + 1 byte. */
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 32u && logical == 384476u);
    REQUIRE(generation == generation_before && full_count == full_before);

    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation_before, &full_before)
        == NINLIL_MFDT_V1_OK);
    make_key(seventeenth_active, "NM3S", 100u);
    make_key(seventeenth_nrc1, "NRC1", 100u);
    /* Deliberately lie low: the reference provider still checks exact truth. */
    REQUIRE(ninlil_mfdt_v1_store_full_begin(&fixture.port, 0u, 0u)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        seventeenth_active,
        active_value,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port,
        seventeenth_nrc1,
        nrc1_value,
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 32u && logical == 384476u);
    REQUIRE(generation == generation_before && full_count == full_before);
    REQUIRE(read_value(
        &fixture,
        seventeenth_active,
        readback,
        sizeof(readback),
        &readback_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 0);

    free(nrc1_value);
    free(active_value);
    fixture_close(&fixture);
    return 0;
}

static int test_exact_committed_key_ceiling(void)
{
    fixture_t fixture = fixture_open();
    uint8_t key_a[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t key_b[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value = 0x5au;
    uint32_t keys;
    uint64_t logical;
    uint64_t generation;
    uint64_t full_count;
    uint64_t generation_before;
    uint64_t full_before;
    uint8_t pair;

    REQUIRE(fixture.store != NULL);
    for (pair = 0u; pair < 16u; ++pair) {
        make_key(key_a, "NRC1", (uint8_t)(pair * 2u));
        make_key(key_b, "NRC1", (uint8_t)(pair * 2u + 1u));
        REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
        REQUIRE(ninlil_mfdt_v1_store_full_put(
            &fixture.port, key_a, &value, 1u) == NINLIL_MFDT_V1_OK);
        REQUIRE(ninlil_mfdt_v1_store_full_put(
            &fixture.port, key_b, &value, 1u) == NINLIL_MFDT_V1_OK);
        REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
            == NINLIL_MFDT_V1_OK);
    }
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation_before, &full_before)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 32u && logical == 1184u);

    make_key(key_a, "NRC1", 200u);
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key_a, &value, 1u) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == 32u && logical == 1184u);
    REQUIRE(generation == generation_before && full_count == full_before);

    fixture_close(&fixture);
    return 0;
}

static int test_commit_old_new_and_prepublish_io(void)
{
    fixture_t fixture = fixture_open();
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t old_value[4] = {1u, 2u, 3u, 4u};
    uint8_t new_value[4] = {5u, 6u, 7u, 8u};
    uint8_t third_value[4] = {9u, 10u, 11u, 12u};
    uint8_t output[4];
    uint32_t keys;
    uint32_t output_len;
    uint64_t logical;
    uint64_t generation;
    uint64_t full_count;
    uint64_t old_generation;
    uint64_t old_full_count;
    int present;

    REQUIRE(fixture.store != NULL);
    make_key(key, "NM3S", 9u);
    REQUIRE(commit_one(&fixture, key, old_value, sizeof(old_value))
        == NINLIL_MFDT_V1_OK);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &old_generation, &old_full_count)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key, new_value, sizeof(new_value))
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_host_store_fault_next(
        fixture.store,
        NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
        NINLIL_STORAGE_IO_ERROR,
        NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE));
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_STORAGE);
    REQUIRE(read_value(
        &fixture, key, output, sizeof(output), &output_len, &present)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 1 && output_len == sizeof(old_value));
    REQUIRE(memcmp(output, old_value, sizeof(old_value)) == 0);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key, new_value, sizeof(new_value))
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_host_store_fault_next(
        fixture.store,
        NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_OLD));
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN);
    REQUIRE(read_value(
        &fixture, key, output, sizeof(output), &output_len, &present)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(memcmp(output, old_value, sizeof(old_value)) == 0);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(generation == old_generation && full_count == old_full_count);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key, new_value, sizeof(new_value))
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_host_store_fault_next(
        fixture.store,
        NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NEW));
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN);
    REQUIRE(read_value(
        &fixture, key, output, sizeof(output), &output_len, &present)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(memcmp(output, new_value, sizeof(new_value)) == 0);
    REQUIRE(inventory(
        &fixture, &keys, &logical, &generation, &full_count)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(generation == old_generation + 1u);
    REQUIRE(full_count == old_full_count + 1u);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, key, third_value, sizeof(third_value))
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(read_value(
        &fixture, key, output, sizeof(output), &output_len, &present)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(memcmp(output, third_value, sizeof(third_value)) == 0);

    fixture_close(&fixture);
    return 0;
}

static int test_snapshot_serialization_prefix_and_cleanup(void)
{
    fixture_t fixture = fixture_open();
    ninlil_mfdt_v1_store_snapshot_t snapshot;
    uint8_t active_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t key_out[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value[8] = {0xabu, 0xcdu};
    uint8_t value_out[8];
    uint32_t value_len;
    int done;

    REQUIRE(fixture.store != NULL);
    (void)memset(&snapshot, 0, sizeof(snapshot));
    make_key(active_key, "NM3S", 1u);
    make_key(nrc1_key, "NRC1", 1u);
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, active_key, value, 2u) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &fixture.port, nrc1_key, value, 1u) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_commit(&fixture.port)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
        &fixture.port,
        (const uint8_t *)"NM3S",
        4u,
        &snapshot) == NINLIL_MFDT_V1_OK);
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_ERR_BUSY);
    REQUIRE(ninlil_mfdt_v1_store_snapshot_next(
        &snapshot,
        key_out,
        value_out,
        sizeof(value_out),
        &value_len,
        &done) == NINLIL_MFDT_V1_OK);
    REQUIRE(done == 0 && value_len == 2u);
    REQUIRE(memcmp(key_out, active_key, sizeof(key_out)) == 0);
    REQUIRE(ninlil_mfdt_v1_store_snapshot_next(
        &snapshot,
        key_out,
        value_out,
        sizeof(value_out),
        &value_len,
        &done) == NINLIL_MFDT_V1_OK);
    REQUIRE(done == 1);
    REQUIRE(ninlil_mfdt_v1_store_snapshot_end(&snapshot)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
        &fixture.port, NULL, 0u, &snapshot) == NINLIL_MFDT_V1_ERR_BUSY);
    REQUIRE(ninlil_mfdt_v1_store_full_rollback(&fixture.port)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(ninlil_mfdt_v1_host_store_fault_next(
        fixture.store,
        NINLIL_MFDT_V1_HOST_STORE_OP_ITER_OPEN,
        NINLIL_STORAGE_IO_ERROR,
        NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE));
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
        &fixture.port, NULL, 0u, &snapshot)
        == NINLIL_MFDT_V1_ERR_STORAGE);
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_rollback(&fixture.port)
        == NINLIL_MFDT_V1_OK);

    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
        &fixture.port, NULL, 0u, &snapshot) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_host_store_fault_next(
        fixture.store,
        NINLIL_MFDT_V1_HOST_STORE_OP_ITER_NEXT,
        NINLIL_STORAGE_IO_ERROR,
        NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE));
    REQUIRE(ninlil_mfdt_v1_store_snapshot_next(
        &snapshot,
        key_out,
        value_out,
        sizeof(value_out),
        &value_len,
        &done) == NINLIL_MFDT_V1_ERR_STORAGE);
    REQUIRE(ninlil_mfdt_v1_store_snapshot_end(&snapshot)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(full_begin_actual(&fixture) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_rollback(&fixture.port)
        == NINLIL_MFDT_V1_OK);

    ninlil_mfdt_v1_host_store_close_port(fixture.store, &fixture.port);
    REQUIRE(ninlil_mfdt_v1_host_store_open_port(
        fixture.store, &fixture.port) == NINLIL_MFDT_V1_OK);
    REQUIRE(read_value(
        &fixture,
        active_key,
        value_out,
        sizeof(value_out),
        &value_len,
        &done) == NINLIL_MFDT_V1_OK);
    REQUIRE(done == 1 && value_len == 2u);

    fixture_close(&fixture);
    return 0;
}

static int run_test(const char *name, int (*test)(void))
{
    int rc = test();

    if (rc != 0) {
        (void)fprintf(stderr, "FAIL %s\n", name);
        return rc;
    }
    (void)printf("PASS %s\n", name);
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += run_test(
        "guarantee_and_status_contract",
        test_guarantee_and_status_contract);
    failures += run_test(
        "replace_erase_and_no_pool_leak",
        test_replace_erase_and_no_pool_leak);
    failures += run_test(
        "duplicate_conflict_and_second_put_atomicity",
        test_duplicate_conflict_and_second_put_atomicity);
    failures += run_test(
        "exact_capacity_staging_union_and_inventory_lie",
        test_exact_capacity_staging_union_and_inventory_lie);
    failures += run_test(
        "exact_committed_key_ceiling",
        test_exact_committed_key_ceiling);
    failures += run_test(
        "commit_old_new_and_prepublish_io",
        test_commit_old_new_and_prepublish_io);
    failures += run_test(
        "snapshot_serialization_prefix_and_cleanup",
        test_snapshot_serialization_prefix_and_cleanup);
    if (failures != 0) {
        (void)fprintf(stderr, "%d Host store test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
