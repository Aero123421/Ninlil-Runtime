#ifndef NINLIL_M4_LAB_PRIMITIVE_H
#define NINLIL_M4_LAB_PRIMITIVE_H

/*
 * M4 LAB Join/Attachment — C1 stateless primitives (docs/05 LAB profile).
 * Production-private under src/radio/. Not public ABI.
 *
 * SEMANTIC: M4_LAB_JOIN_BOOTSTRAP_SEPARATE_PROFILE
 * SEMANTIC: M4_LAB_CRC_AUTH_BOUNDARY_PER_STAGE
 * SEMANTIC: M4_LAB_FALSE_SUCCESS_FORBIDDEN
 *
 * Stateless: frame codec, CRC32C boundary, challenge/nonce codec,
 * identity proof pure verification (HMAC-SHA256 via R7 T0 provider).
 */

#include "r7_crypto_provider.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_M4_LAB_WIRE_PROFILE_ID ((uint8_t)0x04u)
#define NINLIL_M4_LAB_FRAME_VERSION   ((uint8_t)1u)

#define NINLIL_M4_LAB_MAGIC_0 ((uint8_t)0x4du) /* 'M' */
#define NINLIL_M4_LAB_MAGIC_1 ((uint8_t)0x34u) /* '4' */
#define NINLIL_M4_LAB_MAGIC_2 ((uint8_t)0x4cu) /* 'L' */
#define NINLIL_M4_LAB_MAGIC_3 ((uint8_t)0x42u) /* 'B' */

#define NINLIL_M4_LAB_FRAME_JOIN_REQUEST  ((uint8_t)0x01u)
#define NINLIL_M4_LAB_FRAME_JOIN_CHALLENGE ((uint8_t)0x02u)
#define NINLIL_M4_LAB_FRAME_JOIN_RESPONSE ((uint8_t)0x03u)
#define NINLIL_M4_LAB_FRAME_JOIN_INSTALL  ((uint8_t)0x04u)
#define NINLIL_M4_LAB_FRAME_JOIN_REJECT   ((uint8_t)0x05u)

#define NINLIL_M4_LAB_SITE_DOMAIN_MAX     ((uint16_t)16u)
#define NINLIL_M4_LAB_STABLE_ID_MAX       ((uint16_t)32u)
#define NINLIL_M4_LAB_NONCE_LEN           ((size_t)16u)
#define NINLIL_M4_LAB_PROOF_LEN           ((size_t)32u)
#define NINLIL_M4_LAB_ROOT_KEY_LEN        ((size_t)32u)

#define NINLIL_M4_LAB_CHALLENGE_TTL_MS    ((uint64_t)30000u)

#define NINLIL_M4_LAB_REJECT_NONE              ((uint32_t)0u)
#define NINLIL_M4_LAB_REJECT_CRC               ((uint32_t)1u)
#define NINLIL_M4_LAB_REJECT_MEMBERSHIP        ((uint32_t)2u)
#define NINLIL_M4_LAB_REJECT_CREDENTIAL        ((uint32_t)3u)
#define NINLIL_M4_LAB_REJECT_CHALLENGE         ((uint32_t)4u)
#define NINLIL_M4_LAB_REJECT_REPLAY            ((uint32_t)5u)
#define NINLIL_M4_LAB_REJECT_EXPIRED           ((uint32_t)6u)
#define NINLIL_M4_LAB_REJECT_STRUCTURAL        ((uint32_t)7u)

#define NINLIL_M4_LAB_OK               ((int32_t)0)
#define NINLIL_M4_LAB_INVALID_ARGUMENT ((int32_t)1)
#define NINLIL_M4_LAB_STRUCTURAL       ((int32_t)2)
#define NINLIL_M4_LAB_CRC              ((int32_t)3)
#define NINLIL_M4_LAB_CREDENTIAL       ((int32_t)4)
#define NINLIL_M4_LAB_EXPIRED          ((int32_t)5)
#define NINLIL_M4_LAB_BACKEND_FAILED   ((int32_t)6)

typedef int32_t ninlil_m4_lab_status_t;

typedef struct ninlil_m4_lab_bytes {
    const uint8_t *bytes;
    uint16_t length;
} ninlil_m4_lab_bytes_t;

typedef struct ninlil_m4_lab_join_request {
    uint64_t membership_epoch;
    uint8_t environment_code;
    uint8_t site_domain_len;
    uint8_t site_domain[NINLIL_M4_LAB_SITE_DOMAIN_MAX];
    uint8_t device_stable_id_len;
    uint8_t device_stable_id[NINLIL_M4_LAB_STABLE_ID_MAX];
} ninlil_m4_lab_join_request_t;

typedef struct ninlil_m4_lab_join_challenge {
    uint8_t nonce[NINLIL_M4_LAB_NONCE_LEN];
    uint64_t expires_ms;
    uint64_t membership_epoch;
    uint32_t session_id;
} ninlil_m4_lab_join_challenge_t;

typedef struct ninlil_m4_lab_join_response {
    uint32_t session_id;
    uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN];
} ninlil_m4_lab_join_response_t;

typedef struct ninlil_m4_lab_join_install {
    uint32_t session_id;
    uint8_t token_fingerprint[32];
} ninlil_m4_lab_join_install_t;

typedef struct ninlil_m4_lab_join_reject {
    uint32_t reason;
} ninlil_m4_lab_join_reject_t;

/* CRC32C (Castagnoli) over frame bytes excluding trailing 4-byte CRC field. */
uint32_t ninlil_m4_lab_crc32c(const uint8_t *bytes, size_t len);

int ninlil_m4_lab_frame_verify_crc(
    const uint8_t *frame,
    size_t frame_len);

/*
 * Identity proof (pure verification boundary):
 * proof = HMAC-SHA256(root_key32, challenge_frame_without_crc || stable_id)
 */
ninlil_m4_lab_status_t ninlil_m4_lab_identity_proof_compute(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t root_key32[NINLIL_M4_LAB_ROOT_KEY_LEN],
    const uint8_t *challenge_frame,
    size_t challenge_frame_len,
    ninlil_m4_lab_bytes_t stable_id,
    uint8_t out_proof[NINLIL_M4_LAB_PROOF_LEN]);

ninlil_m4_lab_status_t ninlil_m4_lab_identity_proof_verify(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t root_key32[NINLIL_M4_LAB_ROOT_KEY_LEN],
    const uint8_t *challenge_frame,
    size_t challenge_frame_len,
    ninlil_m4_lab_bytes_t stable_id,
    const uint8_t proof[NINLIL_M4_LAB_PROOF_LEN]);

int ninlil_m4_lab_challenge_not_expired(
    uint64_t now_ms,
    uint64_t expires_ms);

/* Fixed-layout frame codecs (CRC appended). Returns encoded length or negative status. */
int32_t ninlil_m4_lab_encode_join_request(
    const ninlil_m4_lab_join_request_t *req,
    uint8_t *out,
    size_t out_capacity);

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_request(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_request_t *out);

int32_t ninlil_m4_lab_encode_join_challenge(
    const ninlil_m4_lab_join_challenge_t *ch,
    uint8_t *out,
    size_t out_capacity);

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_challenge(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_challenge_t *out);

int32_t ninlil_m4_lab_encode_join_response(
    const ninlil_m4_lab_join_response_t *resp,
    uint8_t *out,
    size_t out_capacity);

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_response(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_response_t *out);

int32_t ninlil_m4_lab_encode_join_install(
    const ninlil_m4_lab_join_install_t *inst,
    uint8_t *out,
    size_t out_capacity);

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_install(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_install_t *out);

int32_t ninlil_m4_lab_encode_join_reject(
    const ninlil_m4_lab_join_reject_t *rej,
    uint8_t *out,
    size_t out_capacity);

ninlil_m4_lab_status_t ninlil_m4_lab_decode_join_reject(
    const uint8_t *frame,
    size_t frame_len,
    ninlil_m4_lab_join_reject_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_M4_LAB_PRIMITIVE_H */
