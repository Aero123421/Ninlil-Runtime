#ifndef NINLIL_M4_LAB_INSTALL_TOKEN_H
#define NINLIL_M4_LAB_INSTALL_TOKEN_H

/*
 * M4 LAB authenticated Hop install token mint (docs/34 §4; item 7).
 * Mints incomplete tokens for T1c consume (item 8). Durable record in V1 allowlist.
 */

#include "m4_lab_primitive.h"
#include "r7_context_binding.h"
#include "r7_crypto_provider.h"
#include "r7_t1c_hop_install_owner.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_M4_LAB_INSTALL_TOKEN_ABI ((uint16_t)1u)
#define NINLIL_M4_LAB_DURABLE_RECORD_BYTES ((uint16_t)72u)

#define NINLIL_M4_LAB_TOKEN_STATE_MINTED   ((uint8_t)1u)
#define NINLIL_M4_LAB_TOKEN_STATE_CONSUMED ((uint8_t)2u)

typedef struct ninlil_m4_lab_install_binding {
    uint8_t site_domain_len;
    uint8_t site_domain[NINLIL_M4_LAB_SITE_DOMAIN_MAX];
    uint8_t attachment_id_len;
    uint8_t attachment_id[NINLIL_M4_LAB_STABLE_ID_MAX];
    uint8_t initiator_stable_id_len;
    uint8_t initiator_stable_id[NINLIL_M4_LAB_STABLE_ID_MAX];
    uint8_t responder_stable_id_len;
    uint8_t responder_stable_id[NINLIL_M4_LAB_STABLE_ID_MAX];
    uint64_t membership_epoch;
    uint64_t attachment_epoch;
    uint32_t hop_context_id;
    uint32_t session_id;
    uint8_t direction_code;
    uint8_t alloc_side;
    uint8_t pad[2];
} ninlil_m4_lab_install_binding_t;

struct ninlil_r7_t1c_hop_install_token {
    uint16_t abi_version;
    uint16_t struct_size;
    uint32_t live;
    uint32_t consumed;
    uint32_t session_id;
    uint32_t pad;
    uint8_t traffic_secret32[32];
    uint8_t expected_digest32[32];
    ninlil_r7_t1c_hop_install_claim_t claim;
};

typedef struct ninlil_m4_lab_install_token_mint_result {
    int success;
    uint8_t token_fingerprint[32];
    uint8_t durable_key[16];
    uint8_t durable_value[NINLIL_M4_LAB_DURABLE_RECORD_BYTES];
} ninlil_m4_lab_install_token_mint_result_t;

ninlil_m4_lab_status_t ninlil_m4_lab_install_token_mint(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_m4_lab_install_binding_t *binding,
    const uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN],
    const uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN],
    ninlil_r7_t1c_hop_install_token_t *out_token,
    ninlil_m4_lab_install_token_mint_result_t *out_result);

ninlil_r7_t1c_hop_accept_status_t ninlil_m4_lab_install_token_consume(
    void *user,
    ninlil_r7_t1c_hop_install_token_t *mutable_token,
    ninlil_r7_t1c_hop_install_claim_t *claim_out);

void ninlil_m4_lab_install_token_ops_init(
    ninlil_r7_t1c_hop_install_ops_t *ops);

ninlil_m4_lab_status_t ninlil_m4_lab_install_token_encode_durable(
    uint32_t session_id,
    uint64_t membership_epoch,
    uint64_t attachment_epoch,
    uint32_t hop_context_id,
    uint64_t key_generation,
    const uint8_t token_fingerprint[32],
    uint8_t out_key[16],
    uint8_t out_value[NINLIL_M4_LAB_DURABLE_RECORD_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_M4_LAB_INSTALL_TOKEN_H */
