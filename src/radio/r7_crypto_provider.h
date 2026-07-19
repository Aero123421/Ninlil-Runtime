#ifndef NINLIL_R7_CRYPTO_PROVIDER_H
#define NINLIL_R7_CRYPTO_PROVIDER_H

/*
 * R7 private crypto provider ABI v1 + portable wrapper (docs/31).
 *
 * SEMANTIC: R7_CRYPTO_PRIVATE_ONLY
 * SEMANTIC: R7_PROVIDER_ABI_EXACT_V1
 * SEMANTIC: PORTABLE_WRAPPER_OWNS_VALIDATION
 * SEMANTIC: AEAD_FAILURE_CALLER_MUTATION_ZERO
 * SEMANTIC: OPEN_VERIFY_BEFORE_PUBLISH
 * SEMANTIC: ALL_PARTIAL_ALIAS_REJECT
 * SEMANTIC: INTERNAL_SECRET_ZERO_ALL_PATHS
 *
 * Production-private under src/radio/. Not public ABI. Not installed.
 * No OS / heap / VLA / crypto-library headers in portable sources.
 *
 * All exported types/functions/macros use NINLIL_R7_ / ninlil_r7_ prefixes
 * to avoid OSS symbol collisions even for private linkage.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Exact provider ABI version                                                 */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION ((uint32_t)1u)

/* -------------------------------------------------------------------------- */
/* Bounded domains (R7 portable wrapper accepts only these)                   */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_CRYPTO_AES128_KEY_LEN ((size_t)16u)
#define NINLIL_R7_CRYPTO_AES128_NONCE_LEN ((size_t)12u)
#define NINLIL_R7_CRYPTO_AES128_TAG_LEN ((size_t)16u)

/* AAD: 0..19; body: 0..220; sealed CT||TAG: 16..236 */
#define NINLIL_R7_CRYPTO_AAD_MAX ((size_t)19u)
#define NINLIL_R7_CRYPTO_BODY_MAX ((size_t)220u)
#define NINLIL_R7_CRYPTO_SEALED_MAX ((size_t)236u) /* BODY_MAX + TAG */
#define NINLIL_R7_CRYPTO_SEALED_MIN ((size_t)16u)  /* empty body + TAG */

#define NINLIL_R7_CRYPTO_SHA256_LEN ((size_t)32u)
#define NINLIL_R7_CRYPTO_HKDF_PRK_LEN ((size_t)32u)

/*
 * R7 key schedule OKM is exactly 12 (IV) or 16 (key) bytes.
 * RFC 5869 max is 255*HashLen; portable wrapper rejects all other lengths.
 */
#define NINLIL_R7_CRYPTO_HKDF_OKM_IV_LEN ((size_t)12u)
#define NINLIL_R7_CRYPTO_HKDF_OKM_KEY_LEN ((size_t)16u)
#define NINLIL_R7_CRYPTO_HKDF_OKM_MAX ((size_t)16u)

/*
 * SHA-256 wrapper message 0..2048 (FRAG reassembled ceiling inclusive).
 * HKDF Extract salt/IKM exact 32. Expand info 0..25; OKM 12 or 16.
 */
#define NINLIL_R7_CRYPTO_SHA256_MSG_MAX ((size_t)2048u)
#define NINLIL_R7_CRYPTO_HKDF_SALT_LEN ((size_t)32u)
#define NINLIL_R7_CRYPTO_HKDF_IKM_LEN ((size_t)32u)
#define NINLIL_R7_CRYPTO_HKDF_INFO_MAX ((size_t)25u)

/* -------------------------------------------------------------------------- */
/* Closed portable status catalog (numeric values fixed; not wire ABI)        */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_CRYPTO_OK ((int)0)
#define NINLIL_R7_CRYPTO_INVALID_ARGUMENT ((int)1)
#define NINLIL_R7_CRYPTO_CAPACITY ((int)2)
#define NINLIL_R7_CRYPTO_ALIAS ((int)3)
#define NINLIL_R7_CRYPTO_AUTH_FAILED ((int)4)
#define NINLIL_R7_CRYPTO_BACKEND_FAILED ((int)5)
#define NINLIL_R7_CRYPTO_INTERNAL_CONTRACT ((int)6)

typedef int ninlil_r7_crypto_status;

/* -------------------------------------------------------------------------- */
/* Closed raw backend AEAD / op results                                       */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_CRYPTO_RAW_OK ((int)0)
#define NINLIL_R7_CRYPTO_RAW_AUTH_FAILED ((int)1)
#define NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED ((int)2)

typedef int ninlil_r7_crypto_raw_status;

/* -------------------------------------------------------------------------- */
/* Provider callbacks — all non-NULL when validated                           */
/* -------------------------------------------------------------------------- */

/*
 * Every callback is synchronous and completes exactly once before returning.
 * A callback must not retain any pointer passed by the wrapper, must not call
 * back into this same provider, and must not modify any input span.  `ctx` is
 * adapter-owned, remains valid for the whole wrapper call, is disjoint from
 * every caller/wrapper span, and any concurrent use is the adapter's
 * responsibility.  Candidate output spans are the only mutable spans.
 * The caller keeps the provider object itself alive and byte-immutable until
 * the wrapper returns; the wrapper treats the object as read-only throughout.
 */

/*
 * SHA-256: write exactly 32 bytes to out_digest on RAW_OK.
 * Returns RAW_OK or RAW_BACKEND_FAILED only (AUTH is not meaningful).
 */
typedef ninlil_r7_crypto_raw_status (*ninlil_r7_crypto_sha256_fn)(
    void *ctx,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_digest[NINLIL_R7_CRYPTO_SHA256_LEN]);

/*
 * HKDF-Extract (RFC 5869, SHA-256): write exactly 32-byte PRK on RAW_OK.
 * Portable R7 schedule domain: salt and IKM are each exact 32 bytes.
 */
typedef ninlil_r7_crypto_raw_status (*ninlil_r7_crypto_hkdf_extract_sha256_fn)(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN]);

/*
 * HKDF-Expand (RFC 5869, SHA-256): write exactly okm_len bytes on RAW_OK.
 * Portable wrapper only invokes with okm_len in {12, 16}, info_len 0..25.
 */
typedef ninlil_r7_crypto_raw_status (*ninlil_r7_crypto_hkdf_expand_sha256_fn)(
    void *ctx,
    const uint8_t prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len);

/*
 * Raw AES-128-GCM seal: write sealed = CT||TAG (pt_len + 16) into out_sealed.
 * out_capacity is the candidate buffer capacity (exact expected = pt_len + TAG).
 * On success, *produced_len must equal the exact sealed length.
 * Returns RAW_OK or RAW_BACKEND_FAILED.
 * AUTH_FAILED is not a valid seal result (maps to INTERNAL_CONTRACT in wrapper).
 */
typedef ninlil_r7_crypto_raw_status (*ninlil_r7_crypto_aes128_gcm_seal_fn)(
    void *ctx,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_sealed,
    size_t out_capacity,
    size_t *produced_len);

/*
 * Raw AES-128-GCM open: sealed is CT||TAG; write PT (sealed_len - 16) to out_pt.
 * out_capacity is the candidate buffer capacity (exact expected = sealed_len - TAG).
 * On success, *produced_len must equal the exact plaintext length.
 * Returns RAW_OK, RAW_AUTH_FAILED, or RAW_BACKEND_FAILED.
 */
typedef ninlil_r7_crypto_raw_status (*ninlil_r7_crypto_aes128_gcm_open_fn)(
    void *ctx,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *sealed,
    size_t sealed_len,
    uint8_t *out_plaintext,
    size_t out_capacity,
    size_t *produced_len);

/*
 * Exact provider ABI v1 layout (field order is part of the contract):
 *   1. abi_version   (u32, exact 1)
 *   2. struct_size   (u32, exact sizeof(ninlil_r7_crypto_provider))
 *   3. reserved_zero (u64, exact 0)
 *   4. ctx
 *   5. sha256
 *   6. hkdf_extract_sha256
 *   7. hkdf_expand_sha256
 *   8. aes128_gcm_seal
 *   9. aes128_gcm_open
 *
 * ctx is adapter-owned: stable for the call, disjoint from caller data spans,
 * and must not mutate any memory except the adapter's private state.
 */
typedef struct ninlil_r7_crypto_provider {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t reserved_zero;
    void *ctx;
    ninlil_r7_crypto_sha256_fn sha256;
    ninlil_r7_crypto_hkdf_extract_sha256_fn hkdf_extract_sha256;
    ninlil_r7_crypto_hkdf_expand_sha256_fn hkdf_expand_sha256;
    ninlil_r7_crypto_aes128_gcm_seal_fn aes128_gcm_seal;
    ninlil_r7_crypto_aes128_gcm_open_fn aes128_gcm_open;
} ninlil_r7_crypto_provider;

/* -------------------------------------------------------------------------- */
/* Portable API                                                               */
/* -------------------------------------------------------------------------- */

/* Shape check only; never invokes callbacks. */
ninlil_r7_crypto_status ninlil_r7_crypto_provider_validate(
    const ninlil_r7_crypto_provider *provider);

/*
 * SHA-256 wrapper: candidate digest then publish. Failure: out mutation 0.
 * msg may be NULL only when msg_len == 0. msg_len domain: 0..2048.
 */
ninlil_r7_crypto_status ninlil_r7_crypto_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_digest[NINLIL_R7_CRYPTO_SHA256_LEN]);

/*
 * HKDF-Extract wrapper: candidate PRK then publish. Failure: out mutation 0.
 * Portable R7 domain: salt_len == 32 and ikm_len == 32 (both non-NULL).
 */
ninlil_r7_crypto_status ninlil_r7_crypto_hkdf_extract_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN]);

/*
 * HKDF-Expand wrapper: candidate OKM then publish. Failure: out mutation 0.
 * okm_len must be 12 or 16. info NULL iff info_len == 0. info_len 0..25.
 */
ninlil_r7_crypto_status ninlil_r7_crypto_hkdf_expand_sha256(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len);

/*
 * AES-128-GCM seal: key16, nonce12, AAD 0..19, PT 0..220.
 * out_capacity must equal plaintext_len + 16 exactly.
 * *out_len updated only on success. Sealed form: CT||TAG16.
 * All prevalidation failures: provider call 0, caller mutation 0.
 */
ninlil_r7_crypto_status ninlil_r7_crypto_aes128_gcm_seal(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

/*
 * AES-128-GCM open: sealed CT||TAG, body 0..220 => sealed 16..236.
 * out_capacity must equal sealed_len - 16 exactly.
 * Verify-before-publish via wrapper candidate; *out_len only on success.
 */
ninlil_r7_crypto_status ninlil_r7_crypto_aes128_gcm_open(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *sealed,
    size_t sealed_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

/*
 * Sole R7 nonce helper (docs/30 / docs/31 §8):
 *   nonce[0..3]  = static_iv12[0..3]
 *   nonce[4..11] = static_iv12[4..11] XOR counter_u64_be
 * counter domain: 1 .. UINT64_MAX-1. Reject 0 and UINT64_MAX.
 * No provider involved. Failure: out mutation 0.
 */
ninlil_r7_crypto_status ninlil_r7_crypto_nonce_from_counter(
    const uint8_t static_iv12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    uint64_t counter,
    uint8_t out_nonce12[NINLIL_R7_CRYPTO_AES128_NONCE_LEN]);

/*
 * Private test seam: direct span-overlap / uintptr-overflow helper.
 * Only declared/defined when NINLIL_R7_CRYPTO_TEST_BUILD is set.
 * Production builds must not export this symbol.
 */
#ifdef NINLIL_R7_CRYPTO_TEST_BUILD
int ninlil_r7_crypto_test_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_CRYPTO_PROVIDER_H */
