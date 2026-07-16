/*
 * Pure single-use tx-gate lease registry (docs/22).
 * Host tests compile without FreeRTOS.
 * Registry layout: ninlil_esp_idf/detail/tx_gate_lease_registry.h (unstable).
 *
 * Trusted helpers are static inline (no default global ELF symbols).
 */

#ifndef NINLIL_ESP_IDF_TX_GATE_LEASE_LOGIC_H
#define NINLIL_ESP_IDF_TX_GATE_LEASE_LOGIC_H

#include "ninlil_esp_idf/detail/tx_gate_lease_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

void ninlil_esp_idf_tx_gate_lease_registry_clear(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg);

/* Publish current provider under idle set. Returns 0 ok, non-zero fail.
 * Re-stages/validates ops (public set path). */
int ninlil_esp_idf_tx_gate_lease_registry_set_ops(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    const ninlil_tx_gate_ops_t *ops);

/*
 * Trusted initial publish: store original identity only.
 * validated_known is stack proof only (never stored).
 * Does NOT re-stage or re-read identity. static inline → no global T.
 */
static inline int ninlil_esp_idf_tx_gate_lease_registry_set_ops_trusted(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    const ninlil_tx_gate_ops_t *identity,
    const ninlil_tx_gate_ops_t *validated_known)
{
    if (reg == NULL || identity == NULL || validated_known == NULL) {
        return 1;
    }
    if (reg->occupied_count != 0u) {
        return 1;
    }
    if (reg->epoch == UINT32_MAX) {
        return 1;
    }
    (void)validated_known;
    reg->current_ops = identity;
    reg->epoch += 1u;
    return 0;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_tx_gate_lease_registry_acquire(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    ninlil_esp_idf_tx_gate_lease_t *out_lease);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_tx_gate_lease_registry_release(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    const ninlil_esp_idf_tx_gate_lease_t *lease);

#ifdef __cplusplus
}
#endif

#endif
