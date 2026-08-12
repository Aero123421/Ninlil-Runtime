/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TX_EXCLUSIVE_TRANCHE_H
#define NINLIL_TX_EXCLUSIVE_TRANCHE_H

/*
 * docs/30 §9.2 TX exclusive reservation — checked final partial tranche.
 *
 * Shared pure helper used by:
 *   - r7_frag pure engine (r7_frag_core)
 *   - r7_frag session lane_tx_alloc
 *   - production N6 tx_burn
 *
 * Semantics (exact):
 *   - durable reserved_exclusive / ram_limit is exclusive next free
 *   - assignable data counters: 1 .. UINT64_MAX-1
 *   - terminal exclusive UINT64_MAX means no further assignable counters
 *   - grow = min(B, room) with room = UINT64_MAX - ram_limit
 *   - final partial tranche reserves the last 1..63 counters up through MAX-1
 *
 * Heap-free, no I/O, no side effects.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical block size B (docs/30). Callers may pass their local macro. */
#ifndef NINLIL_TX_EXCLUSIVE_BLOCK_DEFAULT
#define NINLIL_TX_EXCLUSIVE_BLOCK_DEFAULT ((uint64_t)64u)
#endif

/*
 * Compute next exclusive reserved limit after growth.
 *
 * @param ram_limit  current exclusive next-free (must be < UINT64_MAX to grow)
 * @param block      B (typically 64)
 * @param out_U      on success: new exclusive in (ram_limit, UINT64_MAX]
 * @return 1 success, 0 refuse (RESOURCE / new context required)
 */
static inline int ninlil_tx_exclusive_grow(
    uint64_t ram_limit,
    uint64_t block,
    uint64_t *out_U)
{
    uint64_t room;
    uint64_t grow;

    if (out_U == NULL || block == 0u) {
        return 0;
    }
    if (ram_limit >= UINT64_MAX) {
        return 0;
    }
    /* Counters still assignable starting at ram_limit through UINT64_MAX-1. */
    room = UINT64_MAX - ram_limit;
    if (room == 0u) {
        return 0;
    }
    grow = (room < block) ? room : block;
    *out_U = ram_limit + grow;
    return 1;
}

/* Assignable data-counter domain: 1 .. UINT64_MAX-1. */
static inline int ninlil_tx_counter_assignable(uint64_t c)
{
    return c != 0u && c < UINT64_MAX;
}

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TX_EXCLUSIVE_TRANCHE_H */
