/* SPDX-License-Identifier: Apache-2.0 */
/* Private PA-S1a custom-memory bridge for the exact vendored libedhoc slice. */
#ifndef NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_EDHOC_ALLOCATOR_H
#define NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_EDHOC_ALLOCATOR_H

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_PA_S1_EDHOC_PRIVATE __attribute__((visibility("hidden")))
#else
#define NINLIL_PA_S1_EDHOC_PRIVATE
#endif

/* Harness ceiling: two slots; M1 trace: one live 32-byte allocation. */
#define NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOTS ((uint32_t)2u)
#define NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES ((uint32_t)64u)

typedef union ninlil_pa_s1_edhoc_slot_v1 {
    max_align_t alignment;
    uint8_t bytes[NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES];
} ninlil_pa_s1_edhoc_slot_v1_t;

typedef struct ninlil_pa_s1_edhoc_allocator_v1 {
    ninlil_pa_s1_edhoc_slot_v1_t slots[NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOTS];
    uint32_t requested[NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOTS];
    uint32_t live[NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOTS];
    uint32_t allocation_calls;
    uint32_t successful_allocations;
    uint32_t frees;
    uint32_t live_blocks;
    uint32_t live_bytes;
    uint32_t peak_live_blocks;
    uint32_t peak_live_bytes;
    uint32_t fail_on_call;
    uint32_t active;
} ninlil_pa_s1_edhoc_allocator_v1_t;

/*
 * Private, caller-owned, and serialized. Zero-initialize before first use.
 * This is an explicit-owner allocator; the libedhoc process-global hook ABI
 * is deliberately confined to the test adapter and is not a Runtime owner.
 * `end` rejects a live allocation and wipes all workspace before reuse.
 */
NINLIL_PA_S1_EDHOC_PRIVATE int ninlil_pa_s1_edhoc_allocator_v1_begin(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator);
NINLIL_PA_S1_EDHOC_PRIVATE int ninlil_pa_s1_edhoc_allocator_v1_end(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator);
NINLIL_PA_S1_EDHOC_PRIVATE void ninlil_pa_s1_edhoc_allocator_v1_fail_on(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator, uint32_t allocation_call);
NINLIL_PA_S1_EDHOC_PRIVATE void *ninlil_pa_s1_edhoc_allocator_v1_alloc(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator, size_t size);
NINLIL_PA_S1_EDHOC_PRIVATE void ninlil_pa_s1_edhoc_allocator_v1_free(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator, void *pointer);

#endif
