/*
 * Shared test helpers for private Fabric v1 direct-compile tests.
 * Caller-owned fixed buffers only. No heap in production path under test.
 */
#ifndef NINLIL_TESTS_TRANSPORT_FABRIC_V1_TEST_COMMON_H
#define NINLIL_TESTS_TRANSPORT_FABRIC_V1_TEST_COMMON_H

#include "fabric_private_api.h"

#include <stdio.h>
#include <string.h>

static int g_fabric_test_failures;

static inline int fabric_test_pointer_outside_range(
    const void *pointer, const void *range_begin, uint32_t range_length)
{
    uintptr_t address = (uintptr_t)pointer;
    uintptr_t begin = (uintptr_t)range_begin;

    return address < begin || address - begin >= (uintptr_t)range_length;
}

#define FABRIC_REQUIRE(cond)                                                \
    do {                                                                    \
        if (!(cond)) {                                                      \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "FAIL %s:%d: %s\n",                                         \
                __FILE__,                                                   \
                __LINE__,                                                   \
                #cond);                                                     \
            g_fabric_test_failures++;                                       \
            return 1;                                                       \
        }                                                                   \
    } while (0)

#define FABRIC_REQUIRE_EQ_U32(a, b)                                         \
    do {                                                                    \
        uint32_t _a = (uint32_t)(a);                                        \
        uint32_t _b = (uint32_t)(b);                                        \
        if (_a != _b) {                                                     \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "FAIL %s:%d: %s (%u) != %s (%u)\n",                         \
                __FILE__,                                                   \
                __LINE__,                                                   \
                #a,                                                         \
                (unsigned)_a,                                               \
                #b,                                                         \
                (unsigned)_b);                                              \
            g_fabric_test_failures++;                                       \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static void fabric_test_pattern(uint8_t *dst, uint8_t start, uint32_t len)
{
    uint32_t i;
    for (i = 0u; i < len; ++i) {
        dst[i] = (uint8_t)((start + (uint8_t)i) & 0xffu);
    }
}


#endif /* NINLIL_TESTS_TRANSPORT_FABRIC_V1_TEST_COMMON_H */
