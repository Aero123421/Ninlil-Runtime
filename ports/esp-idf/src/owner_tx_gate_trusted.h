/*
 * Internal trusted initial tx_gate publish (cell init only).
 * static inline — no default global ELF symbol.
 * Requires concrete owner storage (FreeRTOS backend TU only).
 */

#ifndef NINLIL_ESP_IDF_OWNER_TX_GATE_TRUSTED_H
#define NINLIL_ESP_IDF_OWNER_TX_GATE_TRUSTED_H

#include "ninlil_esp_idf/owner_task_storage.h"

#include "tx_gate_lease_logic.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Publish original identity after pre-owner-write validation proof.
 * Does not re-stage/re-read identity. Stores identity pointer only.
 */
static inline ninlil_esp_idf_owner_status_t
ninlil_esp_idf_owner_task_publish_tx_gate_trusted(
    ninlil_esp_idf_owner_task_t *t,
    const ninlil_tx_gate_ops_t *identity,
    const ninlil_tx_gate_ops_t *validated_known)
{
    uint8_t lc;

    if (t == NULL || t->mux_ready == 0u || identity == NULL
        || validated_known == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }

    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    lc = t->published_lifecycle;
    if (lc != NINLIL_ESP_IDF_OWNER_LC_STOPPED
        && lc != NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (t->lease_reg.occupied_count != 0u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_BUSY;
    }
    if (ninlil_esp_idf_tx_gate_lease_registry_set_ops_trusted(
            &t->lease_reg, identity, validated_known)
        != 0) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    portEXIT_CRITICAL(&t->mux);
    return NINLIL_ESP_IDF_OWNER_OK;
}

#ifdef __cplusplus
}
#endif

#endif
