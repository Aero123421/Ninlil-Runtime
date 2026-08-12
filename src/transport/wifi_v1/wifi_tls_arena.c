/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_tls_arena.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WIFI_TLS_ARENA_MAGIC UINT32_C(0x4e544152) /* NTAR */
#define WIFI_TLS_BLOCK_MAGIC UINT32_C(0x4e54424c) /* NTBL */
#define WIFI_TLS_BLOCK_FREE UINT32_C(0xf4eef4ee)
#define WIFI_TLS_BLOCK_USED UINT32_C(0xa110ca7e)
#define WIFI_TLS_TAIL_CANARY UINT32_C(0x71e2c53d)

typedef struct wifi_tls_block_fields {
    size_t span_bytes;
    size_t requested_bytes;
    uint32_t magic;
    uint32_t state;
} wifi_tls_block_fields_t;

typedef union wifi_tls_block {
    wifi_tls_block_fields_t fields;
    max_align_t alignment;
} wifi_tls_block_t;

#define WIFI_TLS_ARENA_ALIGNMENT ((size_t)_Alignof(max_align_t))
#define WIFI_TLS_BLOCK_HEADER_BYTES ((size_t)sizeof(wifi_tls_block_t))
#define WIFI_TLS_TAIL_BYTES ((size_t)sizeof(uint32_t))

static int add_overflow_size(size_t a, size_t b, size_t *out)
{
    if (out == NULL || a > SIZE_MAX - b) {
        return 1;
    }
    *out = a + b;
    return 0;
}

static int mul_overflow_size(size_t a, size_t b, size_t *out)
{
    if (out == NULL || (a != 0u && b > SIZE_MAX / a)) {
        return 1;
    }
    *out = a * b;
    return 0;
}

static int align_up_size(size_t value, size_t *out)
{
    const size_t mask = WIFI_TLS_ARENA_ALIGNMENT - 1u;
    size_t sum;
    if (out == NULL
        || (WIFI_TLS_ARENA_ALIGNMENT
                & (WIFI_TLS_ARENA_ALIGNMENT - 1u))
            != 0u
        || add_overflow_size(value, mask, &sum)) {
        return 1;
    }
    *out = sum & ~mask;
    return 0;
}

static void secure_zero(void *pointer, size_t bytes)
{
    volatile uint8_t *cursor = (volatile uint8_t *)pointer;
    while (cursor != NULL && bytes != 0u) {
        *cursor++ = 0u;
        --bytes;
    }
}

static void write_tail(uint8_t *payload, size_t requested, uint32_t value)
{
    (void)memcpy(payload + requested, &value, sizeof(value));
}

static uint32_t read_tail(const uint8_t *payload, size_t requested)
{
    uint32_t value = 0u;
    (void)memcpy(&value, payload + requested, sizeof(value));
    return value;
}

static int arena_header_valid(const ninlil_wifi_tls_arena_t *arena)
{
    return arena != NULL && arena->magic == WIFI_TLS_ARENA_MAGIC
        && arena->base != NULL
        && arena->capacity_bytes >= WIFI_TLS_BLOCK_HEADER_BYTES
        && ((uintptr_t)arena->base % WIFI_TLS_ARENA_ALIGNMENT) == 0u
        && (arena->capacity_bytes % WIFI_TLS_ARENA_ALIGNMENT) == 0u;
}

static int block_valid(
    const ninlil_wifi_tls_arena_t *arena,
    size_t offset,
    const wifi_tls_block_t *block)
{
    size_t minimum;
    if (!arena_header_valid(arena) || block == NULL
        || block->fields.magic != WIFI_TLS_BLOCK_MAGIC
        || (block->fields.state != WIFI_TLS_BLOCK_FREE
            && block->fields.state != WIFI_TLS_BLOCK_USED)
        || block->fields.span_bytes < WIFI_TLS_BLOCK_HEADER_BYTES
        || (block->fields.span_bytes % WIFI_TLS_ARENA_ALIGNMENT) != 0u
        || offset > arena->capacity_bytes
        || block->fields.span_bytes > arena->capacity_bytes - offset) {
        return 0;
    }
    if (block->fields.state == WIFI_TLS_BLOCK_USED) {
        if (add_overflow_size(
                WIFI_TLS_BLOCK_HEADER_BYTES,
                block->fields.requested_bytes,
                &minimum)
            || add_overflow_size(minimum, WIFI_TLS_TAIL_BYTES, &minimum)
            || minimum > block->fields.span_bytes) {
            return 0;
        }
    } else if (block->fields.requested_bytes != 0u) {
        return 0;
    }
    return 1;
}

static void mark_corrupt(ninlil_wifi_tls_arena_t *arena)
{
    if (arena != NULL) {
        arena->corruption_count += 1u;
        arena->magic = 0u;
    }
}

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_init(
    ninlil_wifi_tls_arena_t *arena,
    void *region,
    size_t region_bytes)
{
    wifi_tls_block_t *first;
    size_t usable;
    if (arena == NULL || region == NULL
        || ((uintptr_t)region % WIFI_TLS_ARENA_ALIGNMENT) != 0u) {
        return NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT;
    }
    usable = region_bytes & ~(WIFI_TLS_ARENA_ALIGNMENT - 1u);
    if (usable < WIFI_TLS_BLOCK_HEADER_BYTES + WIFI_TLS_TAIL_BYTES
            + WIFI_TLS_ARENA_ALIGNMENT
        || usable > UINT32_MAX) {
        return NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT;
    }
    (void)memset(arena, 0, sizeof(*arena));
    (void)memset(region, 0, usable);
    arena->base = (uint8_t *)region;
    arena->capacity_bytes = usable;
    arena->fail_after_attempt = SIZE_MAX;
    arena->magic = WIFI_TLS_ARENA_MAGIC;
    first = (wifi_tls_block_t *)arena->base;
    first->fields.span_bytes = usable;
    first->fields.requested_bytes = 0u;
    first->fields.magic = WIFI_TLS_BLOCK_MAGIC;
    first->fields.state = WIFI_TLS_BLOCK_FREE;
    return NINLIL_WIFI_TLS_ARENA_OK;
}

void ninlil_wifi_tls_arena_set_fail_after(
    ninlil_wifi_tls_arena_t *arena,
    size_t successful_attempts)
{
    if (arena_header_valid(arena)) {
        arena->allocation_attempts = 0u;
        arena->fail_after_attempt = successful_attempts;
    }
}

void *ninlil_wifi_tls_arena_calloc(
    ninlil_wifi_tls_arena_t *arena,
    size_t count,
    size_t element_bytes)
{
    size_t requested;
    size_t needed;
    size_t offset = 0u;
    if (!arena_header_valid(arena)
        || mul_overflow_size(count, element_bytes, &requested)
        || requested == 0u
        || add_overflow_size(WIFI_TLS_BLOCK_HEADER_BYTES, requested, &needed)
        || add_overflow_size(needed, WIFI_TLS_TAIL_BYTES, &needed)
        || align_up_size(needed, &needed)) {
        if (arena != NULL && arena->magic == WIFI_TLS_ARENA_MAGIC) {
            arena->oom_count += 1u;
        }
        return NULL;
    }
    if (arena->allocation_attempts >= arena->fail_after_attempt) {
        arena->allocation_attempts += 1u;
        arena->oom_count += 1u;
        return NULL;
    }
    arena->allocation_attempts += 1u;
    while (offset < arena->capacity_bytes) {
        wifi_tls_block_t *block =
            (wifi_tls_block_t *)(void *)(arena->base + offset);
        size_t allocated_span;
        size_t remainder;
        uint8_t *payload;
        if (!block_valid(arena, offset, block)) {
            mark_corrupt(arena);
            return NULL;
        }
        if (block->fields.state != WIFI_TLS_BLOCK_FREE
            || block->fields.span_bytes < needed) {
            offset += block->fields.span_bytes;
            continue;
        }
        allocated_span = needed;
        remainder = block->fields.span_bytes - needed;
        if (remainder
            < WIFI_TLS_BLOCK_HEADER_BYTES + WIFI_TLS_TAIL_BYTES
                + WIFI_TLS_ARENA_ALIGNMENT) {
            allocated_span = block->fields.span_bytes;
            remainder = 0u;
        }
        block->fields.span_bytes = allocated_span;
        block->fields.requested_bytes = requested;
        block->fields.magic = WIFI_TLS_BLOCK_MAGIC;
        block->fields.state = WIFI_TLS_BLOCK_USED;
        if (remainder != 0u) {
            wifi_tls_block_t *next =
                (wifi_tls_block_t *)(void *)(
                    arena->base + offset + allocated_span);
            next->fields.span_bytes = remainder;
            next->fields.requested_bytes = 0u;
            next->fields.magic = WIFI_TLS_BLOCK_MAGIC;
            next->fields.state = WIFI_TLS_BLOCK_FREE;
        }
        payload = (uint8_t *)(void *)(block + 1);
        (void)memset(payload, 0, requested);
        write_tail(payload, requested, WIFI_TLS_TAIL_CANARY);
        arena->current_bytes += allocated_span;
        arena->outstanding_allocations += 1u;
        if (arena->current_bytes > arena->peak_bytes) {
            arena->peak_bytes = arena->current_bytes;
        }
        return payload;
    }
    arena->oom_count += 1u;
    return NULL;
}

static int coalesce_free_blocks(ninlil_wifi_tls_arena_t *arena)
{
    size_t offset = 0u;
    while (offset < arena->capacity_bytes) {
        wifi_tls_block_t *block =
            (wifi_tls_block_t *)(void *)(arena->base + offset);
        if (!block_valid(arena, offset, block)) {
            return 0;
        }
        while (block->fields.state == WIFI_TLS_BLOCK_FREE
               && offset + block->fields.span_bytes
                   < arena->capacity_bytes) {
            const size_t next_offset = offset + block->fields.span_bytes;
            wifi_tls_block_t *next =
                (wifi_tls_block_t *)(void *)(arena->base + next_offset);
            if (!block_valid(arena, next_offset, next)) {
                return 0;
            }
            if (next->fields.state != WIFI_TLS_BLOCK_FREE) {
                break;
            }
            block->fields.span_bytes += next->fields.span_bytes;
            secure_zero(next, WIFI_TLS_BLOCK_HEADER_BYTES);
        }
        offset += block->fields.span_bytes;
    }
    return offset == arena->capacity_bytes;
}

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_free(
    ninlil_wifi_tls_arena_t *arena,
    void *pointer)
{
    size_t offset = 0u;
    if (pointer == NULL) {
        return NINLIL_WIFI_TLS_ARENA_OK;
    }
    if (!arena_header_valid(arena)) {
        return NINLIL_WIFI_TLS_ARENA_CORRUPT;
    }
    while (offset < arena->capacity_bytes) {
        wifi_tls_block_t *block =
            (wifi_tls_block_t *)(void *)(arena->base + offset);
        uint8_t *payload;
        if (!block_valid(arena, offset, block)) {
            mark_corrupt(arena);
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        payload = (uint8_t *)(void *)(block + 1);
        if (payload != (uint8_t *)pointer) {
            offset += block->fields.span_bytes;
            continue;
        }
        if (block->fields.state == WIFI_TLS_BLOCK_FREE) {
            arena->corruption_count += 1u;
            return NINLIL_WIFI_TLS_ARENA_DOUBLE_FREE;
        }
        if (read_tail(payload, block->fields.requested_bytes)
            != WIFI_TLS_TAIL_CANARY) {
            mark_corrupt(arena);
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        if (arena->outstanding_allocations == 0u
            || arena->current_bytes < block->fields.span_bytes) {
            mark_corrupt(arena);
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        secure_zero(payload, block->fields.requested_bytes);
        write_tail(payload, block->fields.requested_bytes, 0u);
        arena->current_bytes -= block->fields.span_bytes;
        arena->outstanding_allocations -= 1u;
        block->fields.requested_bytes = 0u;
        block->fields.state = WIFI_TLS_BLOCK_FREE;
        if (!coalesce_free_blocks(arena)) {
            mark_corrupt(arena);
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        return NINLIL_WIFI_TLS_ARENA_OK;
    }
    arena->corruption_count += 1u;
    return NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER;
}

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_free_owned_pair(
    ninlil_wifi_tls_arena_t *primary,
    ninlil_wifi_tls_arena_t *secondary,
    void *pointer)
{
    if (pointer == NULL) {
        return NINLIL_WIFI_TLS_ARENA_OK;
    }
    if (!arena_header_valid(primary)
        || (secondary != NULL && !arena_header_valid(secondary))) {
        return NINLIL_WIFI_TLS_ARENA_CORRUPT;
    }
    if (ninlil_wifi_tls_arena_owns(primary, pointer)) {
        return ninlil_wifi_tls_arena_free(primary, pointer);
    }
    if (secondary != NULL
        && ninlil_wifi_tls_arena_owns(secondary, pointer)) {
        return ninlil_wifi_tls_arena_free(secondary, pointer);
    }
    return NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER;
}

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_snapshot(
    const ninlil_wifi_tls_arena_t *arena,
    ninlil_wifi_tls_arena_snapshot_t *out)
{
    size_t offset = 0u;
    size_t largest = 0u;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (!arena_header_valid(arena) || out == NULL) {
        return NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT;
    }
    while (offset < arena->capacity_bytes) {
        const wifi_tls_block_t *block =
            (const wifi_tls_block_t *)(const void *)(arena->base + offset);
        if (!block_valid(arena, offset, block)) {
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        if (block->fields.state == WIFI_TLS_BLOCK_USED
            && read_tail(
                   (const uint8_t *)(const void *)(block + 1),
                   block->fields.requested_bytes)
                != WIFI_TLS_TAIL_CANARY) {
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        if (block->fields.state == WIFI_TLS_BLOCK_FREE
            && block->fields.span_bytes > WIFI_TLS_BLOCK_HEADER_BYTES
                + WIFI_TLS_TAIL_BYTES) {
            const size_t available = block->fields.span_bytes
                - WIFI_TLS_BLOCK_HEADER_BYTES - WIFI_TLS_TAIL_BYTES;
            if (available > largest) {
                largest = available;
            }
        }
        offset += block->fields.span_bytes;
    }
    out->capacity_bytes = arena->capacity_bytes;
    out->current_bytes = arena->current_bytes;
    out->peak_bytes = arena->peak_bytes;
    out->largest_free_bytes = largest;
    out->outstanding_allocations = arena->outstanding_allocations;
    out->oom_count = arena->oom_count;
    out->corruption_count = arena->corruption_count;
    return NINLIL_WIFI_TLS_ARENA_OK;
}

int ninlil_wifi_tls_arena_owns(
    const ninlil_wifi_tls_arena_t *arena,
    const void *pointer)
{
    const uintptr_t start =
        arena_header_valid(arena) ? (uintptr_t)arena->base : 0u;
    const uintptr_t value = (uintptr_t)pointer;
    return pointer != NULL && start != 0u && value >= start
        && value < start + arena->capacity_bytes;
}

ninlil_wifi_tls_arena_status_t
ninlil_wifi_tls_arena_validate_live_allocation(
    const ninlil_wifi_tls_arena_t *arena,
    const void *pointer,
    size_t expected_requested_bytes)
{
    size_t offset = 0u;
    if (!arena_header_valid(arena)) {
        return NINLIL_WIFI_TLS_ARENA_CORRUPT;
    }
    if (pointer == NULL || expected_requested_bytes == 0u) {
        return NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT;
    }
    while (offset < arena->capacity_bytes) {
        const wifi_tls_block_t *block =
            (const wifi_tls_block_t *)(const void *)(arena->base + offset);
        const uint8_t *payload;
        if (!block_valid(arena, offset, block)) {
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        payload = (const uint8_t *)(const void *)(block + 1);
        if (block->fields.state == WIFI_TLS_BLOCK_USED
            && read_tail(payload, block->fields.requested_bytes)
                != WIFI_TLS_TAIL_CANARY) {
            return NINLIL_WIFI_TLS_ARENA_CORRUPT;
        }
        if (payload == (const uint8_t *)pointer) {
            if (block->fields.state != WIFI_TLS_BLOCK_USED) {
                return NINLIL_WIFI_TLS_ARENA_DOUBLE_FREE;
            }
            return block->fields.requested_bytes == expected_requested_bytes
                ? NINLIL_WIFI_TLS_ARENA_OK
                : NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT;
        }
        offset += block->fields.span_bytes;
    }
    return NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER;
}

ninlil_wifi_tls_arena_status_t ninlil_wifi_tls_arena_zeroize(
    ninlil_wifi_tls_arena_t *arena)
{
    uint8_t *base;
    size_t capacity;
    if (!arena_header_valid(arena)) {
        return NINLIL_WIFI_TLS_ARENA_INVALID_ARGUMENT;
    }
    if (arena->outstanding_allocations != 0u
        || arena->current_bytes != 0u) {
        return NINLIL_WIFI_TLS_ARENA_BUSY;
    }
    base = arena->base;
    capacity = arena->capacity_bytes;
    secure_zero(base, capacity);
    secure_zero(arena, sizeof(*arena));
    return NINLIL_WIFI_TLS_ARENA_OK;
}
