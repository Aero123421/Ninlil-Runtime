#ifndef NINLIL_C3_LAB_CONTEXT_LIFECYCLE_H
#define NINLIL_C3_LAB_CONTEXT_LIFECYCLE_H

/*
 * C3-LAB secure wire context lifecycle (V1 item 8; docs/34 T1c + W1/L1 basic).
 * Production-private. Not public ABI.
 *
 * Hop/E2E bidirectional contexts, DATA/ACK lanes, epoch fence, counter burn,
 * replay state, clean restart, COMMIT_UNKNOWN restart. M5 not implemented —
 * restart requires fresh M4 handshake (no token/secret re-inject after fence).
 */

#include "m4_lab_install_token.h"
#include "r7_context_binding.h"
#include "r7_crypto_provider.h"
#include "r7_t1c_hop_install_owner.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_C3_LAB_RX_WINDOW ((uint32_t)64u)
#define NINLIL_C3_LAB_DURABLE_RECORD_BYTES ((size_t)48u)
#define NINLIL_C3_LAB_DURABLE_KEY_BYTES ((size_t)16u)

#define NINLIL_C3_LAB_LANE_DATA ((uint8_t)0u)
#define NINLIL_C3_LAB_LANE_ACK ((uint8_t)1u)

#define NINLIL_C3_LAB_OK ((uint32_t)0u)
#define NINLIL_C3_LAB_INVALID_ARGUMENT ((uint32_t)1u)
#define NINLIL_C3_LAB_STRUCTURAL ((uint32_t)2u)
#define NINLIL_C3_LAB_REJECTED ((uint32_t)3u)
#define NINLIL_C3_LAB_STALE ((uint32_t)4u)
#define NINLIL_C3_LAB_REPLAY ((uint32_t)5u)
#define NINLIL_C3_LAB_COUNTER ((uint32_t)6u)
#define NINLIL_C3_LAB_AUTH_FAILED ((uint32_t)7u)
#define NINLIL_C3_LAB_FENCED ((uint32_t)8u)
#define NINLIL_C3_LAB_COMMIT_UNKNOWN ((uint32_t)9u)
#define NINLIL_C3_LAB_BACKEND_FAILED ((uint32_t)10u)

typedef uint32_t ninlil_c3_lab_status_t;

typedef enum ninlil_c3_lab_lifecycle_state {
    NINLIL_C3_LAB_STATE_NONE = 0,
    NINLIL_C3_LAB_STATE_ACTIVE = 1,
    NINLIL_C3_LAB_STATE_FENCED = 2,
    NINLIL_C3_LAB_STATE_COMMIT_UNKNOWN = 3,
    NINLIL_C3_LAB_STATE_RESTART_REQUIRED = 4
} ninlil_c3_lab_lifecycle_state_t;

typedef struct ninlil_c3_lab_lane_context {
    uint8_t active;
    uint64_t tx_next_counter;
    uint64_t rx_highest;
    uint64_t rx_window_base;
    uint64_t rx_bitmap;
    uint8_t hop_key16[16];
    uint8_t hop_iv12[12];
} ninlil_c3_lab_lane_context_t;

typedef struct ninlil_c3_lab_hop_context {
    uint8_t installed;
    uint32_t hop_context_id;
    uint64_t epoch;
    uint64_t key_generation;
    uint8_t direction_code;
    ninlil_c3_lab_lane_context_t data;
    ninlil_c3_lab_lane_context_t ack;
} ninlil_c3_lab_hop_context_t;

typedef struct ninlil_c3_lab_e2e_context {
    uint8_t installed;
    uint32_t e2e_context_id;
    uint64_t epoch;
    uint64_t key_generation;
    uint8_t key16[16];
    uint8_t iv12[12];
    uint64_t tx_next_counter;
    uint64_t rx_highest;
    uint64_t rx_window_base;
    uint64_t rx_bitmap;
} ninlil_c3_lab_e2e_context_t;

typedef struct ninlil_c3_lab_context_store {
    const ninlil_r7_crypto_provider *provider;
    ninlil_c3_lab_lifecycle_state_t state;
    uint64_t freshness_epoch;
    uint32_t installed_token_count;
    uint32_t consumed_token_count;
    uint32_t nonce_reuse_count;
    ninlil_c3_lab_hop_context_t hop_tx;
    ninlil_c3_lab_hop_context_t hop_rx;
    ninlil_c3_lab_e2e_context_t e2e_tx;
    ninlil_c3_lab_e2e_context_t e2e_rx;
    uint8_t token_fingerprint_seen[32];
    uint8_t has_token_fingerprint;
} ninlil_c3_lab_context_store_t;

typedef struct ninlil_c3_lab_install_result {
    uint32_t hop_context_id;
    uint32_t e2e_context_id;
    uint64_t epoch;
} ninlil_c3_lab_install_result_t;

void ninlil_c3_lab_context_store_init(
    ninlil_c3_lab_context_store_t *store,
    const ninlil_r7_crypto_provider *provider);

ninlil_c3_lab_status_t ninlil_c3_lab_install_from_token(
    ninlil_c3_lab_context_store_t *store,
    ninlil_r7_t1c_hop_install_token_t *token,
    ninlil_c3_lab_install_result_t *out_result);

ninlil_c3_lab_status_t ninlil_c3_lab_install_responder(
    ninlil_c3_lab_context_store_t *store,
    const ninlil_m4_lab_install_binding_t *binding,
    const uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN],
    const uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN],
    ninlil_c3_lab_install_result_t *out_result);

ninlil_c3_lab_status_t ninlil_c3_lab_context_clean_restart(
    ninlil_c3_lab_context_store_t *store);

ninlil_c3_lab_status_t ninlil_c3_lab_context_commit_unknown_restart(
    ninlil_c3_lab_context_store_t *store);

ninlil_c3_lab_status_t ninlil_c3_lab_tx_burn_counter(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t *out_counter);

ninlil_c3_lab_status_t ninlil_c3_lab_rx_precheck(
    const ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t counter);

ninlil_c3_lab_status_t ninlil_c3_lab_rx_admit(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t counter);

ninlil_c3_lab_status_t ninlil_c3_lab_encode_durable_admission(
    const ninlil_c3_lab_context_store_t *store,
    uint32_t hop_context_id,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t counter,
    uint8_t out_key[NINLIL_C3_LAB_DURABLE_KEY_BYTES],
    uint8_t out_value[NINLIL_C3_LAB_DURABLE_RECORD_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_C3_LAB_CONTEXT_LIFECYCLE_H */
