#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_ARENA_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_ARENA_H

/*
 * Fixed-region allocator used by the ESP TLS allocation profile.
 *
 * The caller owns the backing region.  This allocator never calls malloc,
 * calloc, realloc, free, or a platform heap.  Metadata and tail canaries live
 * inside the supplied region, so reservation and allocation accounting cannot
 * recursively allocate.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_wifi_tls_arena_status {
    NINLIL_WIFI_TLS_ARENA_OK = 0,
    NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT = 1,
    NINLIL_WIFI_TLS_ARENA_OOM = 2,
    NINLIL_WIFI_TLS_ARENA_CORRUPT = 3,
    NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER = 4,
    NINLIL_WIFI_TLS_ARENA_DOUBLE_FREE = 5,
    NINLIL_WIFI_TLS_ARENA_BUSY = 6
} ninlil_wifi_tls_arena_status_t;

typedef struct ninlil_wifi_tls_arena_snapshot {
    size_t capacity_bytes;
    size_t current_bytes;
    size_t peak_bytes;
    size_t largest_free_bytes;
    uint32_t outstanding_allocations;
    uint32_t oom_count;
    uint32_t corruption_count;
} ninlil_wifi_tls_arena_snapshot_t;

typedef struct ninlil_wifi_tls_arena {
    uint8_t *base;
    size_t capacity_bytes;
    size_t current_bytes;
    size_t peak_bytes;
    size_t allocation_attempts;
    size_t fail_after_attempt;
    uint32_t outstanding_allocations;
    uint32_t oom_count;
    uint32_t corruption_count;
    uint32_t magic;
} ninlil_wifi_tls_arena_t;

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_init(
    ninlil_wifi_tls_arena_t *arena,
    void *region,
    size_t region_bytes);

/*
 * Test/fault-injection seam shared by the pure Host tests.  SIZE_MAX disables
 * injection.  Setting zero fails the next allocation.
 */
void ninlil_wifi_tls_arena_set_fail_after(
    ninlil_wifi_tls_arena_t *arena,
    size_t successful_attempts);

void *ninlil_wifi_tls_arena_calloc(
    ninlil_wifi_tls_arena_t *arena,
    size_t count,
    size_t element_bytes);

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_free(
    ninlil_wifi_tls_arena_t *arena,
    void *pointer);

/*
 * Frees only from the current owner's allowed arena pair.  A pointer in any
 * other arena is foreign even when that other arena is otherwise valid.
 * secondary may be NULL for a single-arena owner such as CRYPTO_GLOBAL.
 */
ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_free_owned_pair(
    ninlil_wifi_tls_arena_t *primary,
    ninlil_wifi_tls_arena_t *secondary,
    void *pointer);

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_snapshot(
    const ninlil_wifi_tls_arena_t *arena,
    ninlil_wifi_tls_arena_snapshot_t *out);

int ninlil_wifi_tls_arena_owns(
    const ninlil_wifi_tls_arena_t *arena,
    const void *pointer);

/*
 * Proves that pointer is the exact payload start of one live allocation whose
 * original requested size equals expected_requested_bytes.  Interior pointers,
 * free blocks, wrong sizes, damaged metadata, and damaged tail canaries never
 * pass this check.
 */
ninlil_wifi_tls_arena_status_t
ninlil_wifi_tls_arena_validate_live_allocation(
    const ninlil_wifi_tls_arena_t *arena,
    const void *pointer,
    size_t expected_requested_bytes);

/*
 * Requires outstanding == 0.  Zeroes the full reserved region and invalidates
 * the allocator; the platform owner may then return the region to its exact
 * capability heap.
 */
ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_zeroize(
    ninlil_wifi_tls_arena_t *arena);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_ARENA_H */
