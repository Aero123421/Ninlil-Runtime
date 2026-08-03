#ifndef NINLIL_R7_FRAG_TARGET_SMOKE_H
#define NINLIL_R7_FRAG_TARGET_SMOKE_H

/*
 * Deterministic private NRW1 LINK/FRAG target smoke (host + ESP when enabled).
 * LINK_ACK, 2+ fragment reorder/duplicate/loss/restart, exact E2E reassembly.
 * Not public ABI. Not installed. Not RF/HIL.
 */

#include "r7_crypto_provider.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 0 = all vectors pass; nonzero = first failing class. */
int32_t ninlil_r7_frag_target_smoke_run(
    const ninlil_r7_crypto_provider *provider);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_TARGET_SMOKE_H */
