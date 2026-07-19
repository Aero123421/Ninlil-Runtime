/*
 * R7 OpenSSL 3 Host crypto adapter.
 *
 * Provider-based EVP only: fetched SHA-256, HKDF-SHA256, AES-128-GCM.
 * No deprecated low-level crypto API and no hand-written primitive.
 */

#include "r7_crypto_openssl3.h"

#include <limits.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR != 3
#error "Ninlil R7 Host crypto adapter requires OpenSSL major version exactly 3"
#endif

#define NINLIL_R7_OPENSSL3_HKDF_MAX ((size_t)(255u * NINLIL_R7_CRYPTO_SHA256_LEN))

_Static_assert(
    sizeof(ninlil_r7_crypto_provider) <= UINT32_MAX,
    "R7 provider ABI size must fit struct_size");

static int ninlil_r7_openssl3_ptr_valid(const void *p, size_t len)
{
    return len == 0u || p != NULL;
}

static ninlil_r7_crypto_raw_status ninlil_r7_openssl3_sha256(
    void *ctx,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_digest[NINLIL_R7_CRYPTO_SHA256_LEN])
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int digest_len = 0u;
    int ok = 0;

    (void)ctx;
    if (out_digest == NULL || !ninlil_r7_openssl3_ptr_valid(msg, msg_len)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    md = EVP_MD_fetch(NULL, "SHA256", NULL);
    md_ctx = EVP_MD_CTX_new();
    if (md == NULL || md_ctx == NULL) {
        goto cleanup;
    }
    if (EVP_DigestInit_ex(md_ctx, md, NULL) <= 0) {
        goto cleanup;
    }
    if (msg_len > 0u && EVP_DigestUpdate(md_ctx, msg, msg_len) <= 0) {
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(md_ctx, out_digest, &digest_len) <= 0 ||
        digest_len != (unsigned int)NINLIL_R7_CRYPTO_SHA256_LEN) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(md);
    if (!ok) {
        OPENSSL_cleanse(out_digest, NINLIL_R7_CRYPTO_SHA256_LEN);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_openssl3_hkdf_extract_sha256(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN])
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    char digest_name[] = "SHA256";
    OSSL_PARAM params[5];
    int ok = 0;

    (void)ctx;
    if (out_prk == NULL || !ninlil_r7_openssl3_ptr_valid(salt, salt_len) ||
        !ninlil_r7_openssl3_ptr_valid(ikm, ikm_len)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto cleanup;
    }
    kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (kdf_ctx == NULL) {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest_name, 0u);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)(uintptr_t)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)(uintptr_t)ikm, ikm_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(
            kdf_ctx, out_prk, NINLIL_R7_CRYPTO_HKDF_PRK_LEN, params) <= 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    if (!ok) {
        OPENSSL_cleanse(out_prk, NINLIL_R7_CRYPTO_HKDF_PRK_LEN);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_openssl3_hkdf_expand_sha256(
    void *ctx,
    const uint8_t prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    char digest_name[] = "SHA256";
    OSSL_PARAM params[5];
    int ok = 0;

    (void)ctx;
    if (prk == NULL || out_okm == NULL || okm_len == 0u ||
        okm_len > NINLIL_R7_OPENSSL3_HKDF_MAX ||
        !ninlil_r7_openssl3_ptr_valid(info, info_len)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto cleanup;
    }
    kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (kdf_ctx == NULL) {
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest_name, 0u);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        (void *)(uintptr_t)prk,
        NINLIL_R7_CRYPTO_HKDF_PRK_LEN);
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, (void *)(uintptr_t)info, info_len);
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kdf_ctx, out_okm, okm_len, params) <= 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    if (!ok) {
        OPENSSL_cleanse(out_okm, okm_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status ninlil_r7_openssl3_aes128_gcm_seal(
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
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    size_t expected;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    int part_len = 0;
    int final_len = 0;
    int total_len = 0;
    int output_started = 0;
    int ok = 0;

    (void)ctx;
    if (key == NULL || nonce == NULL || out_sealed == NULL || produced_len == NULL ||
        !ninlil_r7_openssl3_ptr_valid(aad, aad_len) ||
        !ninlil_r7_openssl3_ptr_valid(plaintext, plaintext_len) ||
        aad_len > (size_t)INT_MAX || plaintext_len > (size_t)INT_MAX ||
        plaintext_len > SIZE_MAX - NINLIL_R7_CRYPTO_AES128_TAG_LEN) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    expected = plaintext_len + NINLIL_R7_CRYPTO_AES128_TAG_LEN;
    if (out_capacity != expected) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    cipher = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || cipher_ctx == NULL) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(
            cipher_ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            (int)NINLIL_R7_CRYPTO_AES128_NONCE_LEN,
            NULL) <= 0 ||
        EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, key, nonce) <= 0) {
        goto cleanup;
    }
    if (aad_len > 0u &&
        EVP_EncryptUpdate(cipher_ctx, NULL, &part_len, aad, (int)aad_len) <= 0) {
        goto cleanup;
    }
    if (plaintext_len > 0u) {
        output_started = 1;
        if (EVP_EncryptUpdate(
                cipher_ctx,
                out_sealed,
                &part_len,
                plaintext,
                (int)plaintext_len) <= 0) {
            goto cleanup;
        }
        if (part_len < 0 || (size_t)part_len > plaintext_len) {
            goto cleanup;
        }
        total_len = part_len;
    }
    output_started = 1;
    if (EVP_EncryptFinal_ex(cipher_ctx, final_block, &final_len) <= 0) {
        goto cleanup;
    }
    if (final_len != 0 || (size_t)total_len != plaintext_len ||
        EVP_CIPHER_CTX_ctrl(
            cipher_ctx,
            EVP_CTRL_GCM_GET_TAG,
            (int)NINLIL_R7_CRYPTO_AES128_TAG_LEN,
            out_sealed + plaintext_len) <= 0) {
        goto cleanup;
    }

    *produced_len = expected;
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_CIPHER_free(cipher);
    if (!ok) {
        if (output_started) {
            OPENSSL_cleanse(out_sealed, out_capacity);
        }
    }
    OPENSSL_cleanse(final_block, sizeof(final_block));
    return ok ? NINLIL_R7_CRYPTO_RAW_OK : NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
}

static ninlil_r7_crypto_raw_status ninlil_r7_openssl3_aes128_gcm_open(
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
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    uint8_t empty_output = 0u;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    uint8_t *output_arg;
    const uint8_t *tag;
    size_t ciphertext_len;
    int part_len = 0;
    int final_len = 0;
    int total_len = 0;
    int output_started = 0;
    int final_result;
    ninlil_r7_crypto_raw_status result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;

    (void)ctx;
    if (key == NULL || nonce == NULL || sealed == NULL || produced_len == NULL ||
        !ninlil_r7_openssl3_ptr_valid(aad, aad_len) ||
        sealed_len < NINLIL_R7_CRYPTO_AES128_TAG_LEN || aad_len > (size_t)INT_MAX) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    ciphertext_len = sealed_len - NINLIL_R7_CRYPTO_AES128_TAG_LEN;
    if (ciphertext_len > (size_t)INT_MAX || out_capacity != ciphertext_len ||
        !ninlil_r7_openssl3_ptr_valid(out_plaintext, out_capacity)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    output_arg = out_capacity > 0u ? out_plaintext : &empty_output;
    tag = sealed + ciphertext_len;

    cipher = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || cipher_ctx == NULL) {
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(
            cipher_ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            (int)NINLIL_R7_CRYPTO_AES128_NONCE_LEN,
            NULL) <= 0 ||
        EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, key, nonce) <= 0) {
        goto cleanup;
    }
    if (aad_len > 0u &&
        EVP_DecryptUpdate(cipher_ctx, NULL, &part_len, aad, (int)aad_len) <= 0) {
        goto cleanup;
    }
    if (ciphertext_len > 0u) {
        output_started = 1;
        if (EVP_DecryptUpdate(
                cipher_ctx,
                output_arg,
                &part_len,
                sealed,
                (int)ciphertext_len) <= 0) {
            goto cleanup;
        }
        if (part_len < 0 || (size_t)part_len > ciphertext_len) {
            goto cleanup;
        }
        total_len = part_len;
    }
    if (EVP_CIPHER_CTX_ctrl(
            cipher_ctx,
            EVP_CTRL_GCM_SET_TAG,
            (int)NINLIL_R7_CRYPTO_AES128_TAG_LEN,
            (void *)(uintptr_t)tag) <= 0) {
        goto cleanup;
    }

    output_started = 1;
    final_result = EVP_DecryptFinal_ex(cipher_ctx, final_block, &final_len);
    if (final_result <= 0) {
        result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
        goto cleanup;
    }
    if (final_len != 0 || (size_t)total_len != ciphertext_len) {
        goto cleanup;
    }

    *produced_len = ciphertext_len;
    result = NINLIL_R7_CRYPTO_RAW_OK;

cleanup:
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_CIPHER_free(cipher);
    if (result != NINLIL_R7_CRYPTO_RAW_OK && output_started && out_capacity > 0u) {
        OPENSSL_cleanse(out_plaintext, out_capacity);
    }
    OPENSSL_cleanse(&empty_output, sizeof(empty_output));
    OPENSSL_cleanse(final_block, sizeof(final_block));
    return result;
}

ninlil_r7_crypto_status ninlil_r7_crypto_openssl3_provider_init(
    ninlil_r7_crypto_provider *out_provider)
{
    /* Zero-initialize padding too: publishing uninitialized object bytes would
     * make the private ABI nondeterministic and could disclose stack data. */
    ninlil_r7_crypto_provider candidate = {0};

    if (out_provider == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (OPENSSL_version_major() < 3u) {
        return NINLIL_R7_CRYPTO_BACKEND_FAILED;
    }

    candidate.abi_version = NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION;
    candidate.struct_size = (uint32_t)sizeof(candidate);
    candidate.reserved_zero = 0u;
    candidate.ctx = NULL;
    candidate.sha256 = ninlil_r7_openssl3_sha256;
    candidate.hkdf_extract_sha256 = ninlil_r7_openssl3_hkdf_extract_sha256;
    candidate.hkdf_expand_sha256 = ninlil_r7_openssl3_hkdf_expand_sha256;
    candidate.aes128_gcm_seal = ninlil_r7_openssl3_aes128_gcm_seal;
    candidate.aes128_gcm_open = ninlil_r7_openssl3_aes128_gcm_open;

    if (ninlil_r7_crypto_provider_validate(&candidate) != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }
    *out_provider = candidate;
    return NINLIL_R7_CRYPTO_OK;
}
