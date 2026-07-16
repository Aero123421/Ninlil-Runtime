/*
 * Unstable concrete storage detail — experimental owner lease registry layout.
 * NOT part of the stable public main API surface (owner_task.h).
 * Path: ninlil_esp_idf/detail/ — storage + pure internal only.
 * Spec: docs/22
 */

#ifndef NINLIL_ESP_IDF_DETAIL_TX_GATE_LEASE_REGISTRY_H
#define NINLIL_ESP_IDF_DETAIL_TX_GATE_LEASE_REGISTRY_H

#include "ninlil_esp_idf/owner_task.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_esp_idf_tx_gate_lease_slot {
    uint8_t occupied;
    uint8_t reserved[3];
    uint32_t token;
    uint32_t epoch;
    const ninlil_tx_gate_ops_t *ops;
} ninlil_esp_idf_tx_gate_lease_slot_t;

typedef struct ninlil_esp_idf_tx_gate_lease_registry {
    ninlil_esp_idf_tx_gate_lease_slot_t
        slots[NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES];
    uint32_t occupied_count;
    uint32_t next_token; /* 1..UINT32_MAX-1 issued; UINT32_MAX = exhausted */
    uint32_t epoch;
    const ninlil_tx_gate_ops_t *current_ops;
} ninlil_esp_idf_tx_gate_lease_registry_t;

#ifdef __cplusplus
}
#endif

#endif
