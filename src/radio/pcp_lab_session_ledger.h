#ifndef NINLIL_RADIO_PCP_LAB_SESSION_LEDGER_H
#define NINLIL_RADIO_PCP_LAB_SESSION_LEDGER_H

/*
 * Production-private LAB session durable ledger for R2 PCP composition.
 *
 * Fixed BSS, no heap/VLA. Implements ninlil_storage_ops for PCP issue/consume
 * FIFO durability within a single boot session.
 *
 * Nonclaims: not power-cut HIL FULL, not flash-backed, not Japan legal.
 * Power-cut residual remains true until ESP flash FULL adapter is used.
 */

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_PCP_LAB_LEDGER_MAX_NS ((uint32_t)2u)
#define NINLIL_PCP_LAB_LEDGER_MAX_ENTRIES ((uint32_t)16u)
#define NINLIL_PCP_LAB_LEDGER_MAX_KEY ((uint32_t)32u)
#define NINLIL_PCP_LAB_LEDGER_MAX_VAL ((uint32_t)256u)
#define NINLIL_PCP_LAB_LEDGER_MAX_NS_NAME ((uint32_t)32u)

/*
 * Opaque BSS object (no heap). Bound is exact ceiling for private
 * ledger_impl_t layout:
 *   entry ≈ 12 + KEY + VAL = 300
 *   ns    ≈ 2×16 entries + name + counters ≈ 4.8 KiB
 *   txn   ≈ 16 staging entries ≈ 4.8 KiB each × 2
 *   + iters + ninlil_storage_ops_t
 * Measured sizeof(ledger_impl_t) ≈ 19560 on C11 (AppleClang/arm64).
 * 24 KiB ceiling leaves alignment headroom across toolchains without
 * ballooning BSS. The .c unit static-asserts impl ≤ opaque.
 */
#define NINLIL_PCP_LAB_SESSION_LEDGER_OPAQUE_BYTES ((size_t)24576u)

typedef struct ninlil_pcp_lab_session_ledger {
    uint8_t opaque[NINLIL_PCP_LAB_SESSION_LEDGER_OPAQUE_BYTES];
} ninlil_pcp_lab_session_ledger_t;

#define NINLIL_PCP_LAB_SESSION_LEDGER_INIT \
    {                                      \
        {                                  \
            0                              \
        }                                  \
    }

/*
 * Zero-init then call init. out_ops points into ledger storage (immutable
 * while ledger is live). No heap.
 */
int ninlil_pcp_lab_session_ledger_init(
    ninlil_pcp_lab_session_ledger_t *ledger,
    const ninlil_storage_ops_t **out_ops);

void ninlil_pcp_lab_session_ledger_shutdown(
    ninlil_pcp_lab_session_ledger_t *ledger);

size_t ninlil_pcp_lab_session_ledger_object_bytes(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_PCP_LAB_SESSION_LEDGER_H */
