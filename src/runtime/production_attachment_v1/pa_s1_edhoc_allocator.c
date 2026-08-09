/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s1_edhoc_allocator.h"

#include <string.h>

static void secure_zero(void *data, size_t size)
{
    volatile uint8_t *cursor = (volatile uint8_t *)data;

    while (size != 0u) {
        *cursor++ = 0u;
        --size;
    }
}

static void reset_slots(ninlil_pa_s1_edhoc_allocator_v1_t *allocator)
{
    secure_zero(allocator->slots, sizeof(allocator->slots));
    secure_zero(allocator->requested, sizeof(allocator->requested));
    secure_zero(allocator->live, sizeof(allocator->live));
    allocator->live_blocks = 0u;
    allocator->live_bytes = 0u;
}

int ninlil_pa_s1_edhoc_allocator_v1_begin(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator)
{
    if (allocator == NULL || allocator->active != 0u) {
        return 0;
    }
    reset_slots(allocator);
    allocator->allocation_calls = 0u;
    allocator->successful_allocations = 0u;
    allocator->frees = 0u;
    allocator->peak_live_blocks = 0u;
    allocator->peak_live_bytes = 0u;
    allocator->active = 1u;
    return 1;
}

int ninlil_pa_s1_edhoc_allocator_v1_end(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator)
{
    if (allocator == NULL || allocator->active == 0u ||
        allocator->live_blocks != 0u) {
        return 0;
    }
    allocator->active = 0u;
    reset_slots(allocator);
    return 1;
}

void ninlil_pa_s1_edhoc_allocator_v1_fail_on(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator, uint32_t allocation_call)
{
    if (allocator != NULL) {
        allocator->fail_on_call = allocation_call;
    }
}

void *ninlil_pa_s1_edhoc_allocator_v1_alloc(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator, size_t size)
{
    uint32_t index;
    uint32_t requested;

    if (allocator == NULL || allocator->active == 0u ||
        size > NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES) {
        return NULL;
    }
    allocator->allocation_calls += 1u;
    if (allocator->fail_on_call != 0u &&
        allocator->allocation_calls == allocator->fail_on_call) {
        return NULL;
    }
    requested = (uint32_t)size;
    for (index = 0u; index < NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOTS; ++index) {
        if (allocator->live[index] == 0u) {
            allocator->live[index] = 1u;
            allocator->requested[index] = requested;
            secure_zero(allocator->slots[index].bytes,
                NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES);
            allocator->successful_allocations += 1u;
            allocator->live_blocks += 1u;
            allocator->live_bytes += requested;
            if (allocator->live_blocks > allocator->peak_live_blocks) {
                allocator->peak_live_blocks = allocator->live_blocks;
            }
            if (allocator->live_bytes > allocator->peak_live_bytes) {
                allocator->peak_live_bytes = allocator->live_bytes;
            }
            return allocator->slots[index].bytes;
        }
    }
    return NULL;
}

void ninlil_pa_s1_edhoc_allocator_v1_free(
    ninlil_pa_s1_edhoc_allocator_v1_t *allocator, void *pointer)
{
    uint32_t index;

    if (pointer == NULL || allocator == NULL || allocator->active == 0u) {
        return;
    }
    for (index = 0u; index < NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOTS; ++index) {
        if (pointer == allocator->slots[index].bytes && allocator->live[index] != 0u) {
            secure_zero(allocator->slots[index].bytes,
                NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES);
            allocator->live_bytes -= allocator->requested[index];
            allocator->requested[index] = 0u;
            allocator->live[index] = 0u;
            allocator->live_blocks -= 1u;
            allocator->frees += 1u;
            return;
        }
    }
}
