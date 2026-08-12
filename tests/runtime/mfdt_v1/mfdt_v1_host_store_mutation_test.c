/* SPDX-License-Identifier: Apache-2.0 */
/*
 *
 * Behavioral contract for the dedicated typed COMMIT_UNKNOWN mutation
 * provider. Coordinator recovery consumes the same provider in the integrated
 * Host acceptance binary.
 */
#include "mfdt_v1_typed_mutation_provider.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                       \
                "WITNESS_FAIL %s:%d: %s\n",                                  \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void make_key(
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const char kind[4],
    uint8_t seed)
{
    uint8_t index;

    (void)memcpy(key, kind, 4u);
    for (index = 0u; index < 16u; ++index) {
        key[4u + index] = (uint8_t)(seed + index);
    }
}

static int read_exact(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value,
    uint32_t value_cap,
    uint32_t *value_len,
    int *present)
{
    return ninlil_mfdt_v1_store_read(
        port,
        key,
        value,
        value_cap,
        value_len,
        present);
}

static int exercise_view(
    const char *witness,
    mfdt_v1_mutation_view_t view,
    uint32_t expected_keys,
    uint64_t expected_full_count,
    int expect_first,
    int expect_second,
    int expect_injected,
    int expect_first_corrupt)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        mfdt_v1_typed_mutation_provider_create();
    ninlil_mfdt_v1_store_port_t port;
    uint8_t key_first[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t key_second[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t key_injected[NINLIL_MFDT_V1_KEY_BYTES];
    const uint8_t value_first[] = {0x10u, 0x11u, 0x12u};
    const uint8_t value_second[] = {0x20u, 0x21u};
    const uint8_t value_injected[] = {0x30u};
    uint8_t output[8];
    uint32_t output_len;
    uint32_t keys;
    uint64_t logical_bytes;
    uint64_t generation;
    uint64_t full_count;
    int present;
    int rc;

    REQUIRE(provider != NULL);
    (void)memset(&port, 0, sizeof(port));
    REQUIRE(mfdt_v1_typed_mutation_provider_open_port(
        provider,
        &port) == NINLIL_MFDT_V1_OK);
    make_key(key_first, "NM3S", 1u);
    make_key(key_second, "NRC1", 1u);
    make_key(key_injected, "NM30", 1u);
    REQUIRE(mfdt_v1_typed_mutation_provider_set_injected_row(
        provider,
        key_injected,
        value_injected,
        sizeof(value_injected)));
    REQUIRE(mfdt_v1_typed_mutation_provider_arm(provider, view));
    REQUIRE(ninlil_mfdt_v1_store_full_begin(&port, 0u, 0u)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &port,
        key_first,
        value_first,
        sizeof(value_first)) == NINLIL_MFDT_V1_OK);
    REQUIRE(ninlil_mfdt_v1_store_full_put(
        &port,
        key_second,
        value_second,
        sizeof(value_second)) == NINLIL_MFDT_V1_OK);
    rc = ninlil_mfdt_v1_store_full_commit(&port);
    REQUIRE(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN);
    REQUIRE(port.full_open == 0u);

    REQUIRE(mfdt_v1_typed_mutation_provider_inventory(
        provider,
        &keys,
        &logical_bytes,
        &generation,
        &full_count) == NINLIL_MFDT_V1_OK);
    REQUIRE(keys == expected_keys);
    REQUIRE(logical_bytes >= (uint64_t)expected_keys * 36u);
    REQUIRE(full_count == expected_full_count);
    REQUIRE(generation >= full_count);

    (void)memset(output, 0, sizeof(output));
    REQUIRE(read_exact(
        &port,
        key_first,
        output,
        sizeof(output),
        &output_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == expect_first);
    if (expect_first != 0) {
        REQUIRE(output_len == sizeof(value_first));
        if (expect_first_corrupt != 0) {
            REQUIRE(output[0] == (uint8_t)(value_first[0] ^ 0xffu));
            REQUIRE(memcmp(
                output + 1u,
                value_first + 1u,
                sizeof(value_first) - 1u) == 0);
        } else {
            REQUIRE(memcmp(
                output,
                value_first,
                sizeof(value_first)) == 0);
        }
    }
    REQUIRE(read_exact(
        &port,
        key_second,
        output,
        sizeof(output),
        &output_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == expect_second);
    REQUIRE(read_exact(
        &port,
        key_injected,
        output,
        sizeof(output),
        &output_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == expect_injected);

    mfdt_v1_typed_mutation_provider_close_port(provider, &port);
    mfdt_v1_typed_mutation_provider_destroy(provider);
    (void)printf("WITNESS_PASS %s\n", witness);
    return 0;
}

static int test_old(void)
{
    return exercise_view(
        "typed_cu_old",
        MFDT_V1_MUTATION_OLD,
        0u,
        0u,
        0,
        0,
        0,
        0);
}

static int test_new(void)
{
    return exercise_view(
        "typed_cu_new",
        MFDT_V1_MUTATION_NEW,
        2u,
        1u,
        1,
        1,
        0,
        0);
}

static int test_partial(void)
{
    return exercise_view(
        "typed_cu_partial",
        MFDT_V1_MUTATION_PARTIAL,
        1u,
        1u,
        1,
        0,
        0,
        0);
}

static int test_both(void)
{
    return exercise_view(
        "typed_cu_both",
        MFDT_V1_MUTATION_BOTH,
        3u,
        2u,
        1,
        1,
        1,
        0);
}

static int test_extra(void)
{
    return exercise_view(
        "typed_cu_extra",
        MFDT_V1_MUTATION_EXTRA,
        3u,
        2u,
        1,
        1,
        1,
        0);
}

static int test_third(void)
{
    return exercise_view(
        "typed_cu_third",
        MFDT_V1_MUTATION_THIRD,
        2u,
        1u,
        1,
        1,
        0,
        1);
}

static int test_absent(void)
{
    return exercise_view(
        "typed_cu_absent",
        MFDT_V1_MUTATION_ABSENT,
        0u,
        0u,
        0,
        0,
        0,
        0);
}

static int run_test(const char *name, int (*test)(void))
{
    int rc = test();

    if (rc != 0) {
        (void)fprintf(stderr, "TEST_FAIL %s\n", name);
        return 1;
    }
    (void)printf("TEST_PASS %s\n", name);
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += run_test("old", test_old);
    failures += run_test("new", test_new);
    failures += run_test("partial", test_partial);
    failures += run_test("both", test_both);
    failures += run_test("extra", test_extra);
    failures += run_test("third", test_third);
    failures += run_test("absent", test_absent);
    if (failures != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_host_store_mutation_test FAILED (%d)\n",
            failures);
        return 1;
    }
    (void)printf("mfdt_v1_host_store_mutation_test OK\n");
    return 0;
}
