/*
 * Production composition surface for private RRMP (ADR-0019/0020).
 *
 * Production TU provides only real bind/recover against caller-supplied
 * platform storage + optional outbound provider / scope derivation.
 * Synthetic RAM store, fake outbound, and deterministic lifecycle KATs live
 * in host fixtures / ESP target smoke — not in this production surface.
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_COMPOSITION_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_COMPOSITION_H

#include "rrmp_abi.h"

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bind real platform storage + optional outbound provider + scope derivation.
 * storage_ops and storage_handle are required (no synthetic fallback).
 * Returns 1 on success, 0 on failure.
 */
int ninlil_rrmp_composition_bind(
    ninlil_rrmp_owner_t *owner,
    const ninlil_storage_ops_t *storage_ops,
    ninlil_storage_handle_t storage_handle,
    const ninlil_rrmp_outbound_provider_t *outbound,
    const ninlil_rrmp_scope_derivation_ctx_t *scope_ctx);

/* Cold boot: recover dual+soft from bound storage (empty store OK). */
int ninlil_rrmp_composition_recover(ninlil_rrmp_owner_t *owner);

#ifdef __cplusplus
}
#endif

#endif
