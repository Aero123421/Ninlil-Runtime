/*
 * R7 ESP-IDF mbedTLS private crypto adapter.
 *
 * ESP-IDF v5.5.3 supplied mbedTLS only: SHA-256, RFC 5869 HKDF-SHA-256,
 * AES-128-GCM Seal/Open (CT||TAG16). No heap, VLA, OS deps, or hand-written
 * AES/GHASH. Contexts are call-local with init/free on every path.
 *
 * Secrets and intermediates are erased with mbedtls_platform_zeroize.
 */

#include "r7_crypto_mbedtls.h"

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

/*
 * ESP-IDF v5.5.3 declares HKDF APIs even when the implementation is excluded
 * by Kconfig. Fail at adapter compile time instead of producing a component
 * archive that only fails when a real consumer pulls this object at link.
 */
#if !defined(MBEDTLS_HKDF_C)
#error "Ninlil R7 crypto requires CONFIG_MBEDTLS_HKDF_C=y"
#endif

/* RFC 5869: L <= 255 * HashLen for SHA-256. */
#define NINLIL_R7_MBEDTLS_HKDF_OKM_MAX \
    ((size_t)(255u * NINLIL_R7_CRYPTO_SHA256_LEN))

/* AES-128 keybits for mbedtls_gcm_setkey (fixed; no size_t→int path). */
#define NINLIL_R7_MBEDTLS_AES128_KEYBITS ((unsigned int)128u)

/*
 * struct_size is published as uint32_t. Fail compile if the exact ABI v1
 * layout cannot be represented (matches OpenSSL adapter guard).
 */
_Static_assert(
    sizeof(ninlil_r7_crypto_provider) <= UINT32_MAX,
    "R7 provider ABI size must fit struct_size");

static int ninlil_r7_mbedtls_ptr_valid(const void *p, size_t len)
{
    return len == 0u || p != NULL;
}

static void ninlil_r7_mbedtls_zeroize(void *p, size_t n)
{
    if (p != NULL && n > 0u) {
        mbedtls_platform_zeroize(p, n);
    }
}

/*
 * Checked add for sealed length: plaintext_len + TAG without wrap.
 * Returns 0 and writes *out_sum on success; 1 on overflow.
 */
static int ninlil_r7_mbedtls_add_tag_len(size_t body_len, size_t *out_sum)
{
    if (out_sum == NULL) {
        return 1;
    }
    if (body_len > (SIZE_MAX - NINLIL_R7_CRYPTO_AES128_TAG_LEN)) {
        return 1;
    }
    *out_sum = body_len + NINLIL_R7_CRYPTO_AES128_TAG_LEN;
    return 0;
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_sha256(
    void *ctx,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_digest[NINLIL_R7_CRYPTO_SHA256_LEN])
{
    mbedtls_sha256_context sha_ctx;
    int ret;
    int inited = 0;
    int ok = 0;

    (void)ctx;
    if (out_digest == NULL || !ninlil_r7_mbedtls_ptr_valid(msg, msg_len)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    mbedtls_sha256_init(&sha_ctx);
    inited = 1;

    /* is224 = 0 => SHA-256 */
    ret = mbedtls_sha256_starts(&sha_ctx, 0);
    if (ret != 0) {
        goto cleanup;
    }
    if (msg_len > 0u) {
        ret = mbedtls_sha256_update(&sha_ctx, msg, msg_len);
        if (ret != 0) {
            goto cleanup;
        }
    }
    ret = mbedtls_sha256_finish(&sha_ctx, out_digest);
    if (ret != 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (inited) {
        mbedtls_sha256_free(&sha_ctx);
    }
    if (!ok) {
        ninlil_r7_mbedtls_zeroize(out_digest, NINLIL_R7_CRYPTO_SHA256_LEN);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_hkdf_extract_sha256(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN])
{
    const mbedtls_md_info_t *md_info;
    int ret;
    int ok = 0;

    (void)ctx;
    if (out_prk == NULL || !ninlil_r7_mbedtls_ptr_valid(salt, salt_len) ||
        !ninlil_r7_mbedtls_ptr_valid(ikm, ikm_len)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    /*
     * mbedtls_hkdf_extract: empty salt (salt == NULL && salt_len == 0) is
     * valid RFC 5869 (HashLen zeros). Non-empty requires non-NULL salt.
     */
    ret = mbedtls_hkdf_extract(
        md_info,
        salt,
        salt_len,
        ikm,
        ikm_len,
        out_prk);
    if (ret != 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (!ok) {
        ninlil_r7_mbedtls_zeroize(out_prk, NINLIL_R7_CRYPTO_HKDF_PRK_LEN);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_hkdf_expand_sha256(
    void *ctx,
    const uint8_t prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len)
{
    const mbedtls_md_info_t *md_info;
    int ret;
    int ok = 0;

    (void)ctx;
    if (prk == NULL || out_okm == NULL || okm_len == 0u ||
        okm_len > NINLIL_R7_MBEDTLS_HKDF_OKM_MAX ||
        !ninlil_r7_mbedtls_ptr_valid(info, info_len)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    ret = mbedtls_hkdf_expand(
        md_info,
        prk,
        NINLIL_R7_CRYPTO_HKDF_PRK_LEN,
        info,
        info_len,
        out_okm,
        okm_len);
    if (ret != 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (!ok) {
        ninlil_r7_mbedtls_zeroize(out_okm, okm_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_aes128_gcm_seal(
    void *ctx,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_sealed,
    size_t out_capacity,
    size_t *produced_len)
{
    mbedtls_gcm_context gcm;
    size_t expected;
    int ret;
    int inited = 0;
    int output_started = 0;
    int ok = 0;
    uint8_t *ct_dst;
    uint8_t *tag_dst;

    (void)ctx;
    if (key == NULL || nonce == NULL || out_sealed == NULL || produced_len == NULL ||
        !ninlil_r7_mbedtls_ptr_valid(aad, aad_len) ||
        !ninlil_r7_mbedtls_ptr_valid(plaintext, plaintext_len) ||
        ninlil_r7_mbedtls_add_tag_len(plaintext_len, &expected) != 0) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    if (out_capacity != expected) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    ct_dst = out_sealed;
    tag_dst = out_sealed + plaintext_len;

    mbedtls_gcm_init(&gcm);
    inited = 1;

    ret = mbedtls_gcm_setkey(
        &gcm, MBEDTLS_CIPHER_ID_AES, key, NINLIL_R7_MBEDTLS_AES128_KEYBITS);
    if (ret != 0) {
        goto cleanup;
    }

    /*
     * mbedtls_gcm_crypt_and_tag writes ciphertext to output and tag to tag.
     * Sealed form is CT || TAG16 into the single candidate buffer.
     * Empty plaintext: still authenticate AAD and emit TAG16 only.
     */
    output_started = 1;
    ret = mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        plaintext_len,
        nonce,
        NINLIL_R7_CRYPTO_AES128_NONCE_LEN,
        aad,
        aad_len,
        plaintext,
        ct_dst,
        NINLIL_R7_CRYPTO_AES128_TAG_LEN,
        tag_dst);
    if (ret != 0) {
        goto cleanup;
    }

    /* Success: update produced_len only after full CT||TAG is written. */
    *produced_len = expected;
    ok = 1;

cleanup:
    if (inited) {
        mbedtls_gcm_free(&gcm);
    }
    if (!ok) {
        if (output_started) {
            ninlil_r7_mbedtls_zeroize(out_sealed, out_capacity);
        }
        /* produced_len left unchanged on failure. */
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_aes128_gcm_open(
    void *ctx,
    const uint8_t key[NINLIL_R7_CRYPTO_AES128_KEY_LEN],
    const uint8_t nonce[NINLIL_R7_CRYPTO_AES128_NONCE_LEN],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *sealed,
    size_t sealed_len,
    uint8_t *out_plaintext,
    size_t out_capacity,
    size_t *produced_len)
{
    mbedtls_gcm_context gcm;
    const uint8_t *tag;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t empty_output;
    uint8_t *output_arg;
    int ret;
    int inited = 0;
    int output_started = 0;
    ninlil_r7_crypto_raw_status result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;

    (void)ctx;
    empty_output = 0u;

    if (key == NULL || nonce == NULL || sealed == NULL || produced_len == NULL ||
        !ninlil_r7_mbedtls_ptr_valid(aad, aad_len) ||
        sealed_len < NINLIL_R7_CRYPTO_AES128_TAG_LEN) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    ciphertext_len = sealed_len - NINLIL_R7_CRYPTO_AES128_TAG_LEN;
    if (out_capacity != ciphertext_len ||
        !ninlil_r7_mbedtls_ptr_valid(out_plaintext, out_capacity)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    ciphertext = sealed;
    tag = sealed + ciphertext_len;
    output_arg = (out_capacity > 0u) ? out_plaintext : &empty_output;

    mbedtls_gcm_init(&gcm);
    inited = 1;

    ret = mbedtls_gcm_setkey(
        &gcm, MBEDTLS_CIPHER_ID_AES, key, NINLIL_R7_MBEDTLS_AES128_KEYBITS);
    if (ret != 0) {
        goto cleanup;
    }

    /*
     * mbedtls_gcm_auth_decrypt verifies the tag before returning success.
     * On auth failure it returns MBEDTLS_ERR_GCM_AUTH_FAILED and may have
     * written partial plaintext into the candidate; we zeroize that buffer
     * and never update produced_len. Caller publish is owned by portable
     * wrapper (verify-before-publish).
     */
    output_started = 1;
    ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        ciphertext_len,
        nonce,
        NINLIL_R7_CRYPTO_AES128_NONCE_LEN,
        aad,
        aad_len,
        tag,
        NINLIL_R7_CRYPTO_AES128_TAG_LEN,
        ciphertext,
        output_arg);
    if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
        goto cleanup;
    }
    if (ret != 0) {
        result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
        goto cleanup;
    }

    *produced_len = ciphertext_len;
    result = NINLIL_R7_CRYPTO_RAW_OK;

cleanup:
    if (inited) {
        mbedtls_gcm_free(&gcm);
    }
    if (result != NINLIL_R7_CRYPTO_RAW_OK) {
        if (output_started && out_capacity > 0u) {
            ninlil_r7_mbedtls_zeroize(out_plaintext, out_capacity);
        }
        /* produced_len left unchanged on failure. */
    }
    ninlil_r7_mbedtls_zeroize(&empty_output, sizeof(empty_output));
    return result;
}

NINLIL_ESP_IDF_INTERNAL ninlil_r7_crypto_status
ninlil_r7_crypto_mbedtls_provider_init(ninlil_r7_crypto_provider *out_provider)
{
    /* Zero all bytes first so padding cannot leak into *out_provider. */
    ninlil_r7_crypto_provider candidate = {0};

    if (out_provider == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

    candidate.abi_version = NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION;
    candidate.struct_size = (uint32_t)sizeof(candidate);
    candidate.reserved_zero = 0u;
    candidate.ctx = NULL;
    candidate.sha256 = ninlil_r7_mbedtls_sha256;
    candidate.hkdf_extract_sha256 = ninlil_r7_mbedtls_hkdf_extract_sha256;
    candidate.hkdf_expand_sha256 = ninlil_r7_mbedtls_hkdf_expand_sha256;
    candidate.aes128_gcm_seal = ninlil_r7_mbedtls_aes128_gcm_seal;
    candidate.aes128_gcm_open = ninlil_r7_mbedtls_aes128_gcm_open;

    if (ninlil_r7_crypto_provider_validate(&candidate) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }

    *out_provider = candidate;
    return NINLIL_R7_CRYPTO_OK;
}
