/* SPDX-License-Identifier: Apache-2.0 */
#include "runtime_internal.h"
#include "runtime_terminal_owner_projection.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                            \
    do {                                                                      \
        if (!(c)) {                                                           \
            (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c);   \
            return 1;                                                         \
        }                                                                     \
    } while (0)

typedef struct owner_probe {
    uint32_t calls;
} owner_probe_t;

static uint64_t current_context(void *user)
{
    owner_probe_t *probe = (owner_probe_t *)user;
    probe->calls += 1u;
    return 7u;
}

static void set_id(ninlil_id128_t *id, uint8_t first, uint8_t last)
{
    (void)memset(id, 0, sizeof(*id));
    id->bytes[0] = first;
    id->bytes[15] = last;
}

int main(void)
{
    static ninlil_runtime_t runtime;
    static ninlil_rt_transaction_slot_t slots[4];
    ninlil_rt_transaction_slot_t before[4];
    ninlil_execution_ops_t execution;
    ninlil_platform_ops_t platform;
    ninlil_rt_private_terminal_owner_v1_t owner;
    owner_probe_t probe;
    uint32_t cursor = 0u;
    uint32_t wrap_pending = 0u;
    uint32_t present = 0u;
    uint32_t more = 0u;

    (void)memset(&runtime, 0, sizeof(runtime));
    (void)memset(slots, 0, sizeof(slots));
    (void)memset(&execution, 0, sizeof(execution));
    (void)memset(&platform, 0, sizeof(platform));
    (void)memset(&probe, 0, sizeof(probe));
    execution.abi_version = NINLIL_ABI_VERSION;
    execution.struct_size = (uint16_t)sizeof(execution);
    execution.user = &probe;
    execution.current_context_id = current_context;
    platform.abi_version = NINLIL_ABI_VERSION;
    platform.struct_size = (uint16_t)sizeof(platform);
    platform.execution = &execution;
    runtime.magic = NINLIL_RT_MAGIC;
    runtime.lifecycle = NINLIL_RT_LIFECYCLE_LIVE;
    runtime.owner_context_id = 7u;
    runtime.platform = &platform;
    runtime.transactions = slots;
    runtime.transaction_capacity = 4u;

    slots[0].in_use = 1u; /* nonterminal: skipped */
    slots[0].record_revision = 1u;
    set_id(&slots[0].transaction_id, 0xAAu, 0x01u);
    slots[1].in_use = 1u;
    slots[1].terminal = 1u;
    slots[1].origin_admission = 1u;
    slots[1].record_revision = 4u;
    set_id(&slots[1].transaction_id, 0x01u, 0x09u);
    slots[2].in_use = 1u;
    slots[2].terminal = 1u;
    slots[2].origin_admission = 0u;
    slots[2].record_revision = 8u;
    set_id(&slots[2].transaction_id, 0x00u, 0x0Bu);
    (void)memcpy(before, slots, sizeof(slots));

    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_OK);
    REQUIRE(present == 1u && cursor == 2u && more == 1u);
    REQUIRE(owner.release_token == UINT64_C(0x0100000000000000));
    REQUIRE(memcmp(&owner.transaction_id, &slots[1].transaction_id, 16u) == 0);
    REQUIRE(memcmp(before, slots, sizeof(slots)) == 0);

    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_OK);
    REQUIRE(present == 1u && cursor == 3u && more == 1u);
    REQUIRE(owner.release_token == 11u); /* first half zero: fallback */
    REQUIRE(memcmp(&owner.transaction_id, &slots[2].transaction_id, 16u) == 0);
    REQUIRE(memcmp(before, slots, sizeof(slots)) == 0);

    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_OK);
    REQUIRE(present == 0u && cursor == 4u && more == 0u);
    REQUIRE(memcmp(before, slots, sizeof(slots)) == 0);

    cursor = 0u; /* caller-owned replay cursor */
    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_OK);
    REQUIRE(present == 1u && owner.release_token
        == UINT64_C(0x0100000000000000));
    REQUIRE(probe.calls == 0u); /* projection is RAM-only and calls no Port */

    slots[1].record_revision = 0u;
    cursor = 1u;
    present = 1u;
    more = 1u;
    (void)memset(&owner, 0xa5, sizeof(owner));
    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(cursor == 1u && present == 0u && more == 0u);
    REQUIRE(owner.release_token == 0u);
    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(cursor == 1u && present == 0u && more == 0u);
    REQUIRE(probe.calls == 0u);

    slots[0].terminal = 1u;
    cursor = 3u;
    wrap_pending = 1u;
    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_OK);
    REQUIRE(cursor == 0u && wrap_pending == 0u);
    REQUIRE(present == 0u && more == 1u);
    REQUIRE(ninlil_rt_private_terminal_owner_next_v1(
                &runtime, &cursor, &wrap_pending, &owner, &present, &more)
        == NINLIL_OK);
    REQUIRE(cursor == 1u && present == 1u);
    REQUIRE(memcmp(&owner.transaction_id, &slots[0].transaction_id, 16u) == 0);
    (void)printf("runtime_terminal_owner_projection_test: PASS\n");
    return 0;
}
