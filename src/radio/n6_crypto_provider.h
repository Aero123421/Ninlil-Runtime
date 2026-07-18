#ifndef NINLIL_RADIO_N6_CRYPTO_PROVIDER_H
#define NINLIL_RADIO_N6_CRYPTO_PROVIDER_H

/*
 * N6 crypto ops vtable + host helpers (docs/30 §8 / §20).
 *
 * SEMANTIC: N6_PRIVATE_ONLY_NO_PUBLIC_ABI
 * SEMANTIC: N6_HKDF_SHA256_LABELS_EXACT
 * SEMANTIC: N6_CHUNK_D_PRIVATE_HOST_CANDIDATE
 *
 * Production-private under src/radio/. Not installed. Not R6 complete.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_N6_SHA256_BYTES ((size_t)32u)
#define NINLIL_N6_AEAD_KEY_BYTES ((size_t)16u)
#define NINLIL_N6_AEAD_IV_BYTES ((size_t)12u)
#define NINLIL_N6_TRAFFIC_SECRET_BYTES ((size_t)32u)
#define NINLIL_N6_SCOPE_DIGEST_OUT_BYTES ((size_t)28u)
#define NINLIL_N6_NS_FINGERPRINT_OUT_BYTES ((size_t)12u)
#define NINLIL_N6_NODE_ID_OUT_BYTES ((size_t)16u)

/* Exact ASCII labels (no NUL in info input). */
#define NINLIL_N6_LABEL_HOP_DATA_KEY "NINLIL-R6-HOP-DATA-KEY-v1"
#define NINLIL_N6_LABEL_HOP_DATA_IV "NINLIL-R6-HOP-DATA-IV-v1"
#define NINLIL_N6_LABEL_HOP_ACK_KEY "NINLIL-R6-HOP-ACK-KEY-v1"
#define NINLIL_N6_LABEL_HOP_ACK_IV "NINLIL-R6-HOP-ACK-IV-v1"
#define NINLIL_N6_LABEL_E2E_KEY "NINLIL-R6-E2E-KEY-v1"
#define NINLIL_N6_LABEL_E2E_IV "NINLIL-R6-E2E-IV-v1"
#define NINLIL_N6_LABEL_NODE_ID "NINLIL-R6-NODE-ID-v1"

typedef struct ninlil_n6_crypto_ops {
    void *ctx;
    /* Return 0 on success; nonzero fail-closed. */
    int (*sha256)(void *ctx, const uint8_t *in, size_t n, uint8_t out32[32]);
    int (*hkdf_sha256)(
        void *ctx,
        const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_len,
        const uint8_t *info,
        size_t info_len,
        uint8_t *okm,
        size_t okm_len);
} ninlil_n6_crypto_ops_t;

/* Host default ops: domain_store SHA-256 + local HMAC/HKDF. */
const ninlil_n6_crypto_ops_t *ninlil_n6_crypto_host_ops(void);

/* Best-effort secret wipe (volatile stores). */
void ninlil_n6_secure_zero(void *p, size_t n);

/*
 * scope_digest28 =
 *   SHA-256(local_node_id16 || layer || direction || epoch_be8 || receiver16)[0..28)
 */
int ninlil_n6_scope_digest28(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t local_node_id[16],
    uint8_t layer_code,
    uint8_t direction_code,
    uint64_t membership_epoch,
    const uint8_t receiver_node_id[16],
    uint8_t out28[28]);

/*
 * ns_fingerprint12 =
 *   SHA-256(receiver16 || layer || epoch_be8 || alloc_side)[0..12)
 */
int ninlil_n6_ns_fingerprint12(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t receiver_node_id[16],
    uint8_t layer_code,
    uint64_t membership_epoch,
    uint8_t alloc_side,
    uint8_t out12[12]);

/* Canonical node id16 from stable_id (docs/30 §5.3.0). */
int ninlil_n6_node_id16_from_stable(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t *stable_id,
    size_t stable_id_len,
    uint8_t out16[16]);

typedef struct ninlil_n6_hop_derived_keys {
    uint8_t data_key16[NINLIL_N6_AEAD_KEY_BYTES];
    uint8_t data_iv12[NINLIL_N6_AEAD_IV_BYTES];
    uint8_t ack_key16[NINLIL_N6_AEAD_KEY_BYTES];
    uint8_t ack_iv12[NINLIL_N6_AEAD_IV_BYTES];
} ninlil_n6_hop_derived_keys_t;

typedef struct ninlil_n6_e2e_derived_keys {
    uint8_t key16[NINLIL_N6_AEAD_KEY_BYTES];
    uint8_t iv12[NINLIL_N6_AEAD_IV_BYTES];
} ninlil_n6_e2e_derived_keys_t;

/* salt = hop_context_binding_digest32; ikm = traffic_secret32. */
int ninlil_n6_derive_hop_keys(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t binding_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_n6_hop_derived_keys_t *out);

/* salt = e2e_context_binding_digest32; ikm = traffic_secret32. */
int ninlil_n6_derive_e2e_keys(
    const ninlil_n6_crypto_ops_t *ops,
    const uint8_t binding_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_n6_e2e_derived_keys_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_N6_CRYPTO_PROVIDER_H */
