/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_tls_arena.h"
#include "wifi_tls_resource_policy.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(expr)                                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            (void)fprintf(                                                   \
                stderr, "require failed: %s:%d: %s\n",                      \
                __FILE__, __LINE__, #expr);                                  \
            return 1;                                                        \
        }                                                                    \
    } while (0)

typedef union aligned_region_4096 {
    max_align_t alignment;
    uint8_t bytes[4096];
} aligned_region_4096_t;

typedef union aligned_region_1024 {
    max_align_t alignment;
    uint8_t bytes[1024];
} aligned_region_1024_t;

static int test_resource_policy(void)
{
    ninlil_wifi_tls_resource_view_t view;
    ninlil_wifi_tls_io_classifier_t classifier;
    (void)memset(&view, 0, sizeof(view));
    view.psram_enabled = 1u;
    view.internal_free_bytes =
        NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET
        + NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP;
    view.internal_largest_free_block_bytes =
        NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET;
    view.psram_free_bytes = NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET;
    view.psram_largest_free_block_bytes =
        NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_OK);

    view.psram_enabled = 0u;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_PSRAM_DISABLED);
    view.psram_enabled = 1u;

    view.internal_free_bytes -= 1u;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_INTERNAL_FREE);
    view.internal_free_bytes += 1u;

    view.internal_largest_free_block_bytes -= 1u;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_INTERNAL_FRAGMENTED);
    view.internal_largest_free_block_bytes += 1u;

    view.psram_free_bytes -= 1u;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_PSRAM_FREE);
    view.psram_free_bytes += 1u;

    view.psram_largest_free_block_bytes -= 1u;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_PSRAM_FRAGMENTED);
    view.psram_largest_free_block_bytes += 1u;

    view.active_sessions = NINLIL_WIFI_ESP_TLS_MAX_SESSIONS;
    REQUIRE(
        ninlil_wifi_tls_resource_admit(&view)
        == NINLIL_WIFI_TLS_ADMISSION_SESSION_CAPACITY);

    REQUIRE(
        NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET
            + NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET
        == NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET);
    REQUIRE(
        NINLIL_WIFI_ESP_TLS_TOTAL_ALLOCATION_BUDGET
                + NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP
            == NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES);
    REQUIRE(
        NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES
        == 327680u);
    REQUIRE(
        NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET
            + 2u * NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET
            + NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP
            + NINLIL_WIFI_ESP_TLS_EXECUTION_STACK_BYTES
            + NINLIL_WIFI_ESP_TLS_CRYPTO_DMA_BYTES
        == NINLIL_WIFI_ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE);
    REQUIRE(
        NINLIL_WIFI_ESP_TLS_MAP_REMAINDER_OBSERVATION
            - NINLIL_WIFI_ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE
        == NINLIL_WIFI_ESP_TLS_MAP_OBSERVATION_SLACK);

    (void)memset(&classifier, 0, sizeof(classifier));
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(&classifier, 777u)
        == NINLIL_WIFI_TLS_ALLOCATION_INTERNAL);
    REQUIRE(ninlil_wifi_tls_io_classifier_begin(&classifier));
    REQUIRE(!ninlil_wifi_tls_io_classifier_begin(&classifier));
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(&classifier, 777u)
        == NINLIL_WIFI_TLS_ALLOCATION_INTERNAL);
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO);
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO);
    REQUIRE(ninlil_wifi_tls_io_classifier_finish(&classifier));
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_INTERNAL);

    REQUIRE(ninlil_wifi_tls_io_classifier_begin(&classifier));
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO);
    REQUIRE(!ninlil_wifi_tls_io_classifier_finish(&classifier));

    REQUIRE(ninlil_wifi_tls_io_classifier_begin(&classifier));
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO);
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_REJECT);
    REQUIRE(
        ninlil_wifi_tls_io_classifier_route(
            &classifier, NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES)
        == NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO);
    REQUIRE(!ninlil_wifi_tls_io_classifier_finish(&classifier));
    return 0;
}

static int test_arena_boundaries_and_fragmentation(void)
{
    aligned_region_4096_t region;
    ninlil_wifi_tls_arena_t arena;
    ninlil_wifi_tls_arena_snapshot_t snapshot;
    uint8_t *a;
    uint8_t *b;
    uint8_t *c;
    uint8_t *d;
    uint8_t *large;
    size_t i;
    REQUIRE(
        ninlil_wifi_tls_arena_init(&arena, region.bytes, sizeof(region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);

    a = (uint8_t *)ninlil_wifi_tls_arena_calloc(&arena, 1u, 700u);
    b = (uint8_t *)ninlil_wifi_tls_arena_calloc(&arena, 7u, 100u);
    c = (uint8_t *)ninlil_wifi_tls_arena_calloc(&arena, 2u, 350u);
    d = (uint8_t *)ninlil_wifi_tls_arena_calloc(&arena, 1u, 700u);
    REQUIRE(a != NULL && b != NULL && c != NULL && d != NULL);
    for (i = 0u; i < 700u; ++i) {
        REQUIRE(a[i] == 0u && b[i] == 0u && c[i] == 0u && d[i] == 0u);
    }
    REQUIRE(ninlil_wifi_tls_arena_owns(&arena, a));
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, a)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, c)
        == NINLIL_WIFI_TLS_ARENA_OK);
    /* Total free is sufficient, but no contiguous block is: no heap spill. */
    REQUIRE(ninlil_wifi_tls_arena_calloc(&arena, 1u, 1300u) == NULL);
    REQUIRE(
        ninlil_wifi_tls_arena_snapshot(&arena, &snapshot)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(snapshot.oom_count == 1u);
    REQUIRE(snapshot.outstanding_allocations == 2u);

    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, b)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, d)
        == NINLIL_WIFI_TLS_ARENA_OK);
    large = (uint8_t *)ninlil_wifi_tls_arena_calloc(&arena, 1u, 3000u);
    REQUIRE(large != NULL);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, large)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_snapshot(&arena, &snapshot)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(snapshot.current_bytes == 0u);
    REQUIRE(snapshot.outstanding_allocations == 0u);
    REQUIRE(snapshot.peak_bytes <= sizeof(region.bytes));
    REQUIRE(
        ninlil_wifi_tls_arena_zeroize(&arena)
        == NINLIL_WIFI_TLS_ARENA_OK);
    for (i = 0u; i < sizeof(region.bytes); ++i) {
        REQUIRE(region.bytes[i] == 0u);
    }
    return 0;
}

static int test_faults(void)
{
    aligned_region_1024_t region;
    aligned_region_1024_t corrupt_region;
    ninlil_wifi_tls_arena_t arena;
    ninlil_wifi_tls_arena_t corrupt_arena;
    ninlil_wifi_tls_arena_snapshot_t snapshot;
    uint8_t foreign = 0u;
    uint8_t *value;
    REQUIRE(
        ninlil_wifi_tls_arena_init(&arena, region.bytes, sizeof(region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);
    ninlil_wifi_tls_arena_set_fail_after(&arena, 0u);
    REQUIRE(ninlil_wifi_tls_arena_calloc(&arena, 1u, 16u) == NULL);
    REQUIRE(
        ninlil_wifi_tls_arena_snapshot(&arena, &snapshot)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(snapshot.oom_count == 1u);
    ninlil_wifi_tls_arena_set_fail_after(&arena, SIZE_MAX);
    value = (uint8_t *)ninlil_wifi_tls_arena_calloc(&arena, 1u, 16u);
    REQUIRE(value != NULL);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(&arena, value, 16u)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(
            &arena, value + 1u, 16u)
        == NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(&arena, value, 15u)
        == NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(
            &arena, region.bytes + sizeof(region.bytes) - 1u, 16u)
        == NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, &foreign)
        == NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, value)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(&arena, value, 16u)
        == NINLIL_WIFI_TLS_ARENA_DOUBLE_FREE);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&arena, value)
        == NINLIL_WIFI_TLS_ARENA_DOUBLE_FREE);
    REQUIRE(
        ninlil_wifi_tls_arena_calloc(&arena, SIZE_MAX, 2u) == NULL);
    REQUIRE(
        ninlil_wifi_tls_arena_zeroize(&arena)
        == NINLIL_WIFI_TLS_ARENA_OK);

    REQUIRE(
        ninlil_wifi_tls_arena_init(
            &corrupt_arena,
            corrupt_region.bytes,
            sizeof(corrupt_region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);
    value =
        (uint8_t *)ninlil_wifi_tls_arena_calloc(&corrupt_arena, 1u, 32u);
    REQUIRE(value != NULL);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(
            &corrupt_arena, value, 32u)
        == NINLIL_WIFI_TLS_ARENA_OK);
    value[32] ^= UINT8_C(0x01); /* exact tail-canary corruption */
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(
            &corrupt_arena, value, 32u)
        == NINLIL_WIFI_TLS_ARENA_CORRUPT);
    REQUIRE(
        ninlil_wifi_tls_arena_snapshot(&corrupt_arena, &snapshot)
        == NINLIL_WIFI_TLS_ARENA_CORRUPT);
    REQUIRE(
        ninlil_wifi_tls_arena_free(&corrupt_arena, value)
        == NINLIL_WIFI_TLS_ARENA_CORRUPT);
    return 0;
}

static int test_owner_scoped_free(void)
{
    aligned_region_1024_t global_region;
    aligned_region_1024_t owner_a_internal_region;
    aligned_region_1024_t owner_a_psram_region;
    aligned_region_1024_t owner_b_region;
    ninlil_wifi_tls_arena_t global_arena;
    ninlil_wifi_tls_arena_t owner_a_internal_arena;
    ninlil_wifi_tls_arena_t owner_a_psram_arena;
    ninlil_wifi_tls_arena_t owner_b_arena;
    uint8_t *global_value;
    uint8_t *owner_a_internal_value;
    uint8_t *owner_a_psram_value;
    uint8_t *owner_b_value;
    REQUIRE(
        ninlil_wifi_tls_arena_init(
            &global_arena, global_region.bytes, sizeof(global_region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_init(
            &owner_a_internal_arena,
            owner_a_internal_region.bytes,
            sizeof(owner_a_internal_region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_init(
            &owner_a_psram_arena,
            owner_a_psram_region.bytes,
            sizeof(owner_a_psram_region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_init(
            &owner_b_arena,
            owner_b_region.bytes,
            sizeof(owner_b_region.bytes))
        == NINLIL_WIFI_TLS_ARENA_OK);
    global_value =
        (uint8_t *)ninlil_wifi_tls_arena_calloc(&global_arena, 1u, 32u);
    owner_a_internal_value = (uint8_t *)ninlil_wifi_tls_arena_calloc(
        &owner_a_internal_arena, 1u, 32u);
    owner_a_psram_value = (uint8_t *)ninlil_wifi_tls_arena_calloc(
        &owner_a_psram_arena, 1u, 32u);
    owner_b_value =
        (uint8_t *)ninlil_wifi_tls_arena_calloc(&owner_b_arena, 1u, 32u);
    REQUIRE(
        global_value != NULL && owner_a_internal_value != NULL
        && owner_a_psram_value != NULL && owner_b_value != NULL);

    /* Owner A cannot free owner B or CRYPTO_GLOBAL allocations. */
    REQUIRE(
        ninlil_wifi_tls_arena_free_owned_pair(
            &owner_a_internal_arena, &owner_a_psram_arena, owner_b_value)
        == NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER);
    REQUIRE(
        ninlil_wifi_tls_arena_free_owned_pair(
            &owner_a_internal_arena, &owner_a_psram_arena, global_value)
        == NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(
            &owner_b_arena, owner_b_value, 32u)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_validate_live_allocation(
            &global_arena, global_value, 32u)
        == NINLIL_WIFI_TLS_ARENA_OK);

    REQUIRE(
        ninlil_wifi_tls_arena_free_owned_pair(
            &owner_a_internal_arena,
            &owner_a_psram_arena,
            owner_a_internal_value)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_free_owned_pair(
            &owner_a_internal_arena,
            &owner_a_psram_arena,
            owner_a_psram_value)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_free_owned_pair(
            &global_arena, NULL, global_value)
        == NINLIL_WIFI_TLS_ARENA_OK);
    REQUIRE(
        ninlil_wifi_tls_arena_free_owned_pair(
            &owner_b_arena, NULL, owner_b_value)
        == NINLIL_WIFI_TLS_ARENA_OK);
    return 0;
}

int main(void)
{
    if (test_resource_policy() != 0
        || test_arena_boundaries_and_fragmentation() != 0
        || test_faults() != 0 || test_owner_scoped_free() != 0) {
        return 1;
    }
    (void)puts(
        "wifi_v1_tls_arena_test: PASS boundaries fragmentation faults "
        "exact-live owner-scope");
    return 0;
}
