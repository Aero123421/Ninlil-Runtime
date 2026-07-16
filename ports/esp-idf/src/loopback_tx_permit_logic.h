#ifndef NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_LOGIC_H
#define NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_LOGIC_H

#include "ninlil_esp_idf/loopback_tx_permit.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_LOOPBACK_SLOT_FREE ((uint8_t)0u)
#define NINLIL_ESP_IDF_LOOPBACK_SLOT_LIVE ((uint8_t)1u)
#define NINLIL_ESP_IDF_LOOPBACK_SLOT_RELEASED ((uint8_t)2u)

int ninlil_esp_idf_loopback_tx_permit_init_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_esp_idf_loopback_tx_permit_config_t *config,
    ninlil_tx_gate_status_t (*acquire)(
        void *user,
        const ninlil_tx_request_t *request,
        const ninlil_time_sample_t *now,
        ninlil_tx_permit_t *out_permit),
    void (*release_unused)(void *user, const ninlil_tx_permit_t *permit));

void ninlil_esp_idf_loopback_tx_permit_shutdown_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate);

/* Returns 0 if shutdown allowed (no live permits), non-zero if blocked. */
int ninlil_esp_idf_loopback_tx_permit_shutdown_blocked_by_live(
    const ninlil_esp_idf_loopback_tx_permit_t *gate);

ninlil_tx_gate_status_t ninlil_esp_idf_loopback_tx_permit_acquire_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit);

void ninlil_esp_idf_loopback_tx_permit_release_unused_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_tx_permit_t *permit);

int ninlil_esp_idf_loopback_tx_permit_policy_allows(
    ninlil_environment_t environment,
    uint32_t loopback_enabled);

#ifdef __cplusplus
}
#endif

#endif
