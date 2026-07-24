#ifndef NINLIL_R7_CONTEXT_BINDING_H
#define NINLIL_R7_CONTEXT_BINDING_H

/*
 * R7 T1b private context binding + verified HKDF schedule (docs/33, ADR-0013).
 *
 * SEMANTIC: R7_T1B_PRIVATE_PURE_BINDING_SCHEDULE_ONLY
 * SEMANTIC: R7_T1B_R6_SECTION8_BYTE_EXACT
 * SEMANTIC: R7_T1B_FIXED_PROFILE_AND_LABELS_NOT_CALLER_SELECTED
 * SEMANTIC: R7_T1B_VERIFIED_DERIVE_ONLY
 * SEMANTIC: R7_T1B_ATOMIC_TYPED_KEY_BUNDLES
 * SEMANTIC: R7_T1B_FAILURE_CALLER_MUTATION_ZERO
 * SEMANTIC: R7_T1B_INTERNAL_SECRETS_ZERO_ALL_PATHS
 * SEMANTIC: R7_T1B_PUBLIC_ABI_UNCHANGED
 *
 * Production-private under src/radio/. Not public ABI. Not installed.
 * No OS / heap / VLA / OpenSSL / mbedTLS / N6 / R2 / R5 / W1 / radio / product-specific.
 * Crypto only via ninlil_r7_crypto_* portable wrapper (docs/31 / T0).
 */

#include "r7_crypto_provider.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Fixed domains (docs/33 §§3–4; not caller-selected)                          */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_BINDING_PROFILE_ID ((uint8_t)0x11u)
#define NINLIL_R7_BINDING_ALLOWED_KIND_MASK ((uint16_t)0x0003u)

#define NINLIL_R7_BINDING_ENV_LAB ((uint8_t)1u)
#define NINLIL_R7_BINDING_ENV_FIELD ((uint8_t)2u)

#define NINLIL_R7_BINDING_DIR_IR ((uint8_t)0u)
#define NINLIL_R7_BINDING_DIR_RI ((uint8_t)1u)

#define NINLIL_R7_BINDING_SITE_MAX ((uint16_t)16u)
#define NINLIL_R7_BINDING_ID_MAX ((uint16_t)32u)

#define NINLIL_R7_BINDING_HOP_CANON_MAX ((size_t)207u)
#define NINLIL_R7_BINDING_E2E_CANON_MAX ((size_t)205u)
#define NINLIL_R7_BINDING_DIGEST_LEN ((size_t)32u)

/* -------------------------------------------------------------------------- */
/* Closed status catalog (numeric values fixed; not public/wire ABI)          */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_BINDING_OK ((int32_t)0)
#define NINLIL_R7_BINDING_INVALID_ARGUMENT ((int32_t)1)
#define NINLIL_R7_BINDING_STRUCTURAL ((int32_t)2)
#define NINLIL_R7_BINDING_CAPACITY ((int32_t)3)
#define NINLIL_R7_BINDING_ALIAS ((int32_t)4)
#define NINLIL_R7_BINDING_MISMATCH ((int32_t)5)
#define NINLIL_R7_BINDING_BACKEND_FAILED ((int32_t)6)
#define NINLIL_R7_BINDING_INTERNAL_CONTRACT ((int32_t)7)

typedef int32_t ninlil_r7_binding_status;

/* -------------------------------------------------------------------------- */
/* Exact private types (docs/33 §3)                                           */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_binding_bytes {
    const uint8_t *bytes;
    uint16_t length;
} ninlil_r7_binding_bytes;

typedef struct ninlil_r7_hop_binding_input {
    uint8_t environment_code;
    ninlil_r7_binding_bytes site_domain;
    uint64_t membership_epoch;
    ninlil_r7_binding_bytes attachment_id;
    uint64_t attachment_epoch;
    ninlil_r7_binding_bytes initiator_stable_id;
    ninlil_r7_binding_bytes responder_stable_id;
    ninlil_r7_binding_bytes controller_authority_id;
    uint64_t controller_term;
    uint32_t hop_context_id;
    uint8_t direction_code;
} ninlil_r7_hop_binding_input;

typedef struct ninlil_r7_e2e_binding_input {
    uint8_t environment_code;
    ninlil_r7_binding_bytes site_domain;
    uint64_t membership_epoch;
    ninlil_r7_binding_bytes e2e_security_id;
    uint64_t e2e_security_epoch;
    ninlil_r7_binding_bytes sender_stable_id;
    ninlil_r7_binding_bytes receiver_stable_id;
    ninlil_r7_binding_bytes authority_id;
    uint64_t authority_term;
    uint32_t e2e_context_id;
    uint8_t direction_code;
} ninlil_r7_e2e_binding_input;

typedef struct ninlil_r7_hop_key_bundle {
    uint8_t data_key16[16];
    uint8_t data_iv12[12];
    uint8_t ack_key16[16];
    uint8_t ack_iv12[12];
} ninlil_r7_hop_key_bundle;

typedef struct ninlil_r7_e2e_key_bundle {
    uint8_t key16[16];
    uint8_t iv12[12];
} ninlil_r7_e2e_key_bundle;

/* -------------------------------------------------------------------------- */
/* Exact private API (docs/33 §5) — six functions only                        */
/* -------------------------------------------------------------------------- */

int32_t ninlil_r7_encode_hop_binding(
    const ninlil_r7_hop_binding_input *input,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int32_t ninlil_r7_encode_e2e_binding(
    const ninlil_r7_e2e_binding_input *input,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int32_t ninlil_r7_digest_hop_binding(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *input,
    uint8_t out_digest32[32]);

int32_t ninlil_r7_digest_e2e_binding(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *input,
    uint8_t out_digest32[32]);

int32_t ninlil_r7_derive_hop_key_bundle_verified(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_hop_binding_input *input,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_hop_key_bundle *out_bundle);

int32_t ninlil_r7_derive_e2e_key_bundle_verified(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_e2e_binding_input *input,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    ninlil_r7_e2e_key_bundle *out_bundle);

/*
 * Private test seams. Declared only when NINLIL_R7_BINDING_TEST_BUILD is set.
 * Production builds must not export these symbols.
 */
#ifdef NINLIL_R7_BINDING_TEST_BUILD

int ninlil_r7_binding_test_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len);

/*
 * Secret-zeroization probe (test-only). When installed, every secure-zero of
 * internal canonical/digest/secret/PRK/OKM candidates records:
 *   - total zero_calls / zero_bytes
 *   - ordered size log (exact multiset evidence for encode/digest/derive)
 *   - optional post-zero content of the last span into region[]
 * Production builds must not export this type or the setter.
 */
#define NINLIL_R7_BINDING_TEST_ZERO_LOG_MAX ((size_t)32u)

typedef struct ninlil_r7_binding_test_secret_probe {
    uint8_t *region;
    size_t capacity;
    size_t last_len;
    size_t zero_calls;
    size_t zero_bytes;
    size_t log_count;
    size_t log_sizes[NINLIL_R7_BINDING_TEST_ZERO_LOG_MAX];
} ninlil_r7_binding_test_secret_probe;

void ninlil_r7_binding_test_set_secret_probe(
    ninlil_r7_binding_test_secret_probe *probe);

#endif /* NINLIL_R7_BINDING_TEST_BUILD */

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_CONTEXT_BINDING_H */
