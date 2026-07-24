#ifndef NINLIL_M4_LAB_HANDSHAKE_H
#define NINLIL_M4_LAB_HANDSHAKE_H

/*
 * M4 LAB Join/Attachment handshake state machine (docs/03 Attachment).
 * request -> challenge -> response -> install. Explicit reject on all failures.
 */

#include "m4_lab_install_token.h"
#include "m4_lab_membership.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_M4_LAB_HANDSHAKE_FRAME_MAX ((size_t)128u)
#define NINLIL_M4_LAB_REPLAY_WINDOW       ((uint32_t)16u)

typedef enum ninlil_m4_lab_attachment_state {
    NINLIL_M4_LAB_ATTACHMENT_DETACHED = 0,
    NINLIL_M4_LAB_ATTACHMENT_DISCOVERING = 1,
    NINLIL_M4_LAB_ATTACHMENT_AUTHENTICATING = 2,
    NINLIL_M4_LAB_ATTACHMENT_ATTACHED = 3
} ninlil_m4_lab_attachment_state_t;

typedef enum ninlil_m4_lab_handshake_role {
    NINLIL_M4_LAB_ROLE_CONTROLLER = 0,
    NINLIL_M4_LAB_ROLE_ENDPOINT = 1
} ninlil_m4_lab_handshake_role_t;

typedef struct ninlil_m4_lab_credential {
    uint8_t root_key32[NINLIL_M4_LAB_ROOT_KEY_LEN];
    uint8_t stable_id_len;
    uint8_t stable_id[NINLIL_M4_LAB_STABLE_ID_MAX];
} ninlil_m4_lab_credential_t;

typedef struct ninlil_m4_lab_handshake_config {
    uint8_t site_domain_len;
    uint8_t site_domain[NINLIL_M4_LAB_SITE_DOMAIN_MAX];
    uint8_t controller_stable_id_len;
    uint8_t controller_stable_id[NINLIL_M4_LAB_STABLE_ID_MAX];
    uint64_t membership_epoch;
    uint32_t next_session_id;
    uint32_t next_hop_context_id;
} ninlil_m4_lab_handshake_config_t;

typedef struct ninlil_m4_lab_handshake_context {
    ninlil_m4_lab_handshake_role_t role;
    ninlil_m4_lab_attachment_state_t state;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_membership_registry_t *membership;
    const ninlil_r7_crypto_provider *provider;
    uint64_t now_ms;
    uint32_t active_session_id;
    uint8_t challenge_frame[NINLIL_M4_LAB_HANDSHAKE_FRAME_MAX];
    size_t challenge_frame_len;
    uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN];
    uint64_t challenge_expires_ms;
    uint32_t replay_ids[NINLIL_M4_LAB_REPLAY_WINDOW];
    uint32_t replay_count;
    ninlil_m4_lab_join_request_t last_request;
    int has_request;
    ninlil_r7_t1c_hop_install_token_t install_token;
    int has_install_token;
    ninlil_m4_lab_install_token_mint_result_t mint_result;
} ninlil_m4_lab_handshake_context_t;

typedef struct ninlil_m4_lab_handshake_step_result {
    int success;
    uint32_t reject_reason;
    uint8_t out_frame[NINLIL_M4_LAB_HANDSHAKE_FRAME_MAX];
    size_t out_frame_len;
    uint8_t out_frame_type;
    ninlil_m4_lab_attachment_state_t new_state;
} ninlil_m4_lab_handshake_step_result_t;

void ninlil_m4_lab_handshake_init(
    ninlil_m4_lab_handshake_context_t *ctx,
    ninlil_m4_lab_handshake_role_t role,
    ninlil_m4_lab_membership_registry_t *membership,
    const ninlil_r7_crypto_provider *provider,
    const ninlil_m4_lab_handshake_config_t *config);

/* Endpoint: begin join (emit request). */
ninlil_m4_lab_status_t ninlil_m4_lab_handshake_endpoint_begin(
    ninlil_m4_lab_handshake_context_t *ctx,
    const ninlil_m4_lab_credential_t *endpoint_cred,
    ninlil_m4_lab_handshake_step_result_t *out);

/* Controller: handle request (emit challenge or reject). */
ninlil_m4_lab_status_t ninlil_m4_lab_handshake_controller_on_request(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_handshake_step_result_t *out);

/* Endpoint: handle challenge (emit response or reject). */
ninlil_m4_lab_status_t ninlil_m4_lab_handshake_endpoint_on_challenge(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_m4_lab_credential_t *endpoint_cred,
    ninlil_m4_lab_handshake_step_result_t *out);

/* Controller: handle response (emit install or reject). */
ninlil_m4_lab_status_t ninlil_m4_lab_handshake_controller_on_response(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_m4_lab_credential_t *endpoint_cred,
    ninlil_m4_lab_handshake_step_result_t *out);

/* Endpoint: handle install (complete attachment). */
ninlil_m4_lab_status_t ninlil_m4_lab_handshake_endpoint_on_install(
    ninlil_m4_lab_handshake_context_t *ctx,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_handshake_step_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_M4_LAB_HANDSHAKE_H */
