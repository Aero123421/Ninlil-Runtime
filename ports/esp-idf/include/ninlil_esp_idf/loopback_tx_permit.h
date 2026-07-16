/*
 * Port-owned virtual/loopback TxPermit (experimental).
 * Deny-by-default; TEST + explicit enable only.
 *
 * ABI staging + non-overlap (docs/22):
 * - init config: stage header + declared struct_size full-range nonoverlap vs
 *   gate storage; known prefix local only; never re-read config after gate write.
 * - acquire request/now: same declared-range staging; out_permit fixed nonoverlap.
 * - release: forward extension allowed; identity is known semantic fields only
 *   (struct_size excluded); extension tail not read for match.
 */

#ifndef NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_H
#define NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_MAX_LIVE ((uint32_t)8u)

typedef struct ninlil_esp_idf_loopback_tx_permit_config {
    NINLIL_STRUCT_HEADER;
    ninlil_environment_t environment;
    uint32_t loopback_enabled;
} ninlil_esp_idf_loopback_tx_permit_config_t;

typedef struct ninlil_esp_idf_loopback_tx_permit_slot {
    uint8_t state; /* 0 free, 1 live, 2 released */
    uint8_t reserved0[3];
    ninlil_tx_permit_t permit;
    ninlil_id128_t transaction_id;
    ninlil_bearer_message_kind_t message_kind;
    uint32_t logical_bytes;
    ninlil_digest256_t content_digest;
} ninlil_esp_idf_loopback_tx_permit_slot_t;

typedef struct ninlil_esp_idf_loopback_tx_permit_stats {
    uint32_t acquire_ok;
    uint32_t acquire_denied;
    uint32_t release_ok;
    uint32_t reuse_denied;
} ninlil_esp_idf_loopback_tx_permit_stats_t;

typedef struct ninlil_esp_idf_loopback_tx_permit {
    ninlil_tx_gate_ops_t ops;
    uint32_t lifecycle; /* 0 zero, 1 active, 2 retired */
    ninlil_environment_t environment;
    uint32_t loopback_enabled;
    uint32_t live_count;
    uint32_t next_permit_seq;
    uint32_t seq_exhausted;
    ninlil_esp_idf_loopback_tx_permit_slot_t
        slots[NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_MAX_LIVE];
    ninlil_esp_idf_loopback_tx_permit_stats_t stats;
} ninlil_esp_idf_loopback_tx_permit_t;

int ninlil_esp_idf_loopback_tx_permit_init(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_esp_idf_loopback_tx_permit_config_t *config);

/* Checked shutdown: fails if not active or still has live permits? */
int ninlil_esp_idf_loopback_tx_permit_shutdown(
    ninlil_esp_idf_loopback_tx_permit_t *gate);

const ninlil_tx_gate_ops_t *ninlil_esp_idf_loopback_tx_permit_ops(
    ninlil_esp_idf_loopback_tx_permit_t *gate);

#ifdef __cplusplus
}
#endif

#endif
