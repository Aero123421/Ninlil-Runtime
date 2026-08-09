/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s2_edhoc_crypto.h"

#include "edhoc_values.h"

#include <limits.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#if !defined(MBEDTLS_CCM_C) || !defined(MBEDTLS_CHACHA20_C) \
    || !defined(MBEDTLS_POLY1305_C) || !defined(MBEDTLS_CHACHAPOLY_C)
#error "PA-S2a requires ESP-IDF mbedTLS CCM, ChaCha20, Poly1305, and ChaChaPoly"
#endif
#else
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR != 3
#error "PA-S2a Host adapter requires OpenSSL major version exactly 3"
#endif
#endif

#define PA_S2_SHA256_BYTES ((size_t)32u)
#define PA_S2_SUITE2_KEY_BYTES ((size_t)16u)
#define PA_S2_SUITE2_NONCE_BYTES ((size_t)13u)
#define PA_S2_SUITE2_TAG_BYTES ((size_t)8u)
#define PA_S2_SUITE3_KEY_BYTES ((size_t)32u)
#define PA_S2_SUITE3_NONCE_BYTES ((size_t)12u)
#define PA_S2_SUITE3_TAG_BYTES ((size_t)16u)
#define PA_S2_KEY_GENERATION_MAX ((uint32_t)0x00ffffffu)

_Static_assert(CONFIG_LIBEDHOC_KEY_ID_LEN == 4,
    "PA-S2a requires libedhoc exact four-byte key identifiers");
_Static_assert(NINLIL_PA_S2_EDHOC_KEY_ID_BYTES == CONFIG_LIBEDHOC_KEY_ID_LEN,
    "PA-S2a key-id contract drift");

static void secure_zero(void *data, size_t size)
{
    volatile uint8_t *cursor = (volatile uint8_t *)data;

    while (size != 0u) {
        *cursor++ = 0u;
        --size;
    }
}

static int pointer_valid(const void *pointer, size_t size)
{
    return size == 0u || pointer != NULL;
}

static int ranges_overlap(const void *left, size_t left_size,
    const void *right, size_t right_size)
{
    uintptr_t left_start;
    uintptr_t right_start;

    if (left_size == 0u || right_size == 0u) {
        return 0;
    }
    if (left == NULL || right == NULL) {
        return 1;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_size > UINTPTR_MAX - left_start
        || right_size > UINTPTR_MAX - right_start) {
        return 1;
    }
    return left_start < right_start + right_size
        && right_start < left_start + left_size;
}

static int external_span_ok(
    const ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const void *pointer, size_t size)
{
    return owner != NULL && pointer_valid(pointer, size)
        && !ranges_overlap(owner, sizeof(*owner), pointer, size);
}

static int suite_valid(uint32_t suite)
{
    return suite == NINLIL_PA_S2_EDHOC_SUITE_2
        || suite == NINLIL_PA_S2_EDHOC_SUITE_3;
}

static size_t suite_key_bytes(uint32_t suite)
{
    return suite == NINLIL_PA_S2_EDHOC_SUITE_2
        ? PA_S2_SUITE2_KEY_BYTES : PA_S2_SUITE3_KEY_BYTES;
}

static size_t suite_nonce_bytes(uint32_t suite)
{
    return suite == NINLIL_PA_S2_EDHOC_SUITE_2
        ? PA_S2_SUITE2_NONCE_BYTES : PA_S2_SUITE3_NONCE_BYTES;
}

static size_t suite_tag_bytes(uint32_t suite)
{
    return suite == NINLIL_PA_S2_EDHOC_SUITE_2
        ? PA_S2_SUITE2_TAG_BYTES : PA_S2_SUITE3_TAG_BYTES;
}

static int enter_owner(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner)
{
    if (owner == NULL || owner->active != 1u || !suite_valid(owner->suite)) {
        return EDHOC_ERROR_BAD_STATE;
    }
    if (owner->in_call != 0u) {
        return EDHOC_ERROR_NOT_PERMITTED;
    }
    owner->in_call = 1u;
    return EDHOC_SUCCESS;
}

static void leave_owner(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner)
{
    owner->in_call = 0u;
}

static void encode_key_id(uint32_t slot, uint32_t generation,
    uint8_t key_id[NINLIL_PA_S2_EDHOC_KEY_ID_BYTES])
{
    key_id[0] = (uint8_t)(slot + 1u);
    key_id[1] = (uint8_t)((generation >> 16u) & 0xffu);
    key_id[2] = (uint8_t)((generation >> 8u) & 0xffu);
    key_id[3] = (uint8_t)(generation & 0xffu);
}

static int decode_key_id(const uint8_t key_id[NINLIL_PA_S2_EDHOC_KEY_ID_BYTES],
    uint32_t *slot, uint32_t *generation)
{
    uint32_t slot_byte;
    uint32_t parsed_generation;

    if (key_id == NULL || slot == NULL || generation == NULL) {
        return 0;
    }
    slot_byte = key_id[0];
    parsed_generation = ((uint32_t)key_id[1] << 16u)
        | ((uint32_t)key_id[2] << 8u) | (uint32_t)key_id[3];
    if (slot_byte == 0u || slot_byte > NINLIL_PA_S2_EDHOC_KEY_SLOTS
        || parsed_generation == 0u) {
        return 0;
    }
    *slot = slot_byte - 1u;
    *generation = parsed_generation;
    return 1;
}

static ninlil_pa_s2_edhoc_key_slot_v1_t *lookup_key(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner, const void *key_id,
    enum edhoc_key_type expected_type)
{
    uint32_t slot_index;
    uint32_t generation;
    ninlil_pa_s2_edhoc_key_slot_v1_t *slot;

    if (!decode_key_id((const uint8_t *)key_id, &slot_index, &generation)) {
        return NULL;
    }
    slot = &owner->key_slots[slot_index];
    if (slot->live != 1u || slot->generation != generation
        || slot->key_type != (uint32_t)expected_type
        || slot->bytes_used == 0u
        || slot->bytes_used > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX) {
        return NULL;
    }
    return slot;
}

#if defined(ESP_PLATFORM)
static int platform_sha256(const uint8_t *input, size_t input_size,
    uint8_t output[PA_S2_SHA256_BYTES])
{
    mbedtls_sha256_context context;
    int status;
    int ok = 0;

    mbedtls_sha256_init(&context);
    status = mbedtls_sha256_starts(&context, 0);
    if (status == 0 && input_size != 0u) {
        status = mbedtls_sha256_update(&context, input, input_size);
    }
    if (status == 0) {
        status = mbedtls_sha256_finish(&context, output);
    }
    if (status == 0) {
        ok = 1;
    }
    mbedtls_sha256_free(&context);
    if (!ok) {
        mbedtls_platform_zeroize(output, PA_S2_SHA256_BYTES);
    }
    return ok;
}

static int platform_hkdf_extract(const uint8_t *salt, size_t salt_size,
    const uint8_t *ikm, size_t ikm_size,
    uint8_t output[PA_S2_SHA256_BYTES])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md == NULL
        || mbedtls_hkdf_extract(md, salt, salt_size, ikm, ikm_size, output)
            != 0) {
        mbedtls_platform_zeroize(output, PA_S2_SHA256_BYTES);
        return 0;
    }
    return 1;
}

static int platform_hkdf_expand(const uint8_t prk[PA_S2_SHA256_BYTES],
    const uint8_t *info, size_t info_size, uint8_t *output, size_t output_size)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md == NULL
        || mbedtls_hkdf_expand(
               md, prk, PA_S2_SHA256_BYTES, info, info_size, output, output_size)
            != 0) {
        mbedtls_platform_zeroize(output, output_size);
        return 0;
    }
    return 1;
}

static int platform_seal(uint32_t suite, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
    const uint8_t *plaintext, size_t plaintext_size, uint8_t *sealed)
{
    int status;

    if (suite == NINLIL_PA_S2_EDHOC_SUITE_2) {
        mbedtls_ccm_context context;
        mbedtls_ccm_init(&context);
        status = mbedtls_ccm_setkey(
            &context, MBEDTLS_CIPHER_ID_AES, key, 128u);
        if (status == 0) {
            status = mbedtls_ccm_encrypt_and_tag(&context, plaintext_size,
                nonce, PA_S2_SUITE2_NONCE_BYTES, aad, aad_size, plaintext,
                sealed, sealed + plaintext_size, PA_S2_SUITE2_TAG_BYTES);
        }
        mbedtls_ccm_free(&context);
    } else {
        mbedtls_chachapoly_context context;
        mbedtls_chachapoly_init(&context);
        status = mbedtls_chachapoly_setkey(&context, key);
        if (status == 0) {
            status = mbedtls_chachapoly_encrypt_and_tag(&context,
                plaintext_size, nonce, aad, aad_size, plaintext, sealed,
                sealed + plaintext_size);
        }
        mbedtls_chachapoly_free(&context);
    }
    return status == 0;
}

static int platform_open(uint32_t suite, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
    const uint8_t *sealed, size_t plaintext_size, uint8_t *plaintext)
{
    int status;

    if (suite == NINLIL_PA_S2_EDHOC_SUITE_2) {
        mbedtls_ccm_context context;
        mbedtls_ccm_init(&context);
        status = mbedtls_ccm_setkey(
            &context, MBEDTLS_CIPHER_ID_AES, key, 128u);
        if (status == 0) {
            status = mbedtls_ccm_auth_decrypt(&context, plaintext_size,
                nonce, PA_S2_SUITE2_NONCE_BYTES, aad, aad_size, sealed,
                plaintext, sealed + plaintext_size, PA_S2_SUITE2_TAG_BYTES);
        }
        mbedtls_ccm_free(&context);
    } else {
        mbedtls_chachapoly_context context;
        mbedtls_chachapoly_init(&context);
        status = mbedtls_chachapoly_setkey(&context, key);
        if (status == 0) {
            status = mbedtls_chachapoly_auth_decrypt(&context,
                plaintext_size, nonce, aad, aad_size,
                sealed + plaintext_size, sealed, plaintext);
        }
        mbedtls_chachapoly_free(&context);
    }
    return status == 0;
}
#else
static int platform_sha256(const uint8_t *input, size_t input_size,
    uint8_t output[PA_S2_SHA256_BYTES])
{
    EVP_MD *digest = NULL;
    EVP_MD_CTX *context = NULL;
    unsigned int produced = 0u;
    int ok = 0;

    digest = EVP_MD_fetch(NULL, "SHA256", NULL);
    context = EVP_MD_CTX_new();
    if (digest != NULL && context != NULL
        && EVP_DigestInit_ex(context, digest, NULL) > 0
        && (input_size == 0u
            || EVP_DigestUpdate(context, input, input_size) > 0)
        && EVP_DigestFinal_ex(context, output, &produced) > 0
        && produced == (unsigned int)PA_S2_SHA256_BYTES) {
        ok = 1;
    }
    EVP_MD_CTX_free(context);
    EVP_MD_free(digest);
    if (!ok) {
        OPENSSL_cleanse(output, PA_S2_SHA256_BYTES);
    }
    return ok;
}

static int platform_hkdf_extract(const uint8_t *salt, size_t salt_size,
    const uint8_t *ikm, size_t ikm_size,
    uint8_t output[PA_S2_SHA256_BYTES])
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *context = NULL;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    char digest_name[] = "SHA256";
    uint8_t empty = 0u;
    OSSL_PARAM parameters[5];
    int ok = 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf != NULL) {
        context = EVP_KDF_CTX_new(kdf);
    }
    parameters[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    parameters[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest_name, 0u);
    parameters[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
        salt_size == 0u ? &empty : (void *)(uintptr_t)salt, salt_size);
    parameters[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
        ikm_size == 0u ? &empty : (void *)(uintptr_t)ikm, ikm_size);
    parameters[4] = OSSL_PARAM_construct_end();
    if (context != NULL
        && EVP_KDF_derive(context, output, PA_S2_SHA256_BYTES, parameters) > 0) {
        ok = 1;
    }
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(&empty, sizeof(empty));
    if (!ok) {
        OPENSSL_cleanse(output, PA_S2_SHA256_BYTES);
    }
    return ok;
}

static int platform_hkdf_expand(const uint8_t prk[PA_S2_SHA256_BYTES],
    const uint8_t *info, size_t info_size, uint8_t *output, size_t output_size)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *context = NULL;
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
    char digest_name[] = "SHA256";
    uint8_t empty = 0u;
    OSSL_PARAM parameters[5];
    int ok = 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf != NULL) {
        context = EVP_KDF_CTX_new(kdf);
    }
    parameters[0] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    parameters[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest_name, 0u);
    parameters[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
        (void *)(uintptr_t)prk, PA_S2_SHA256_BYTES);
    parameters[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
        info_size == 0u ? &empty : (void *)(uintptr_t)info, info_size);
    parameters[4] = OSSL_PARAM_construct_end();
    if (context != NULL
        && EVP_KDF_derive(context, output, output_size, parameters) > 0) {
        ok = 1;
    }
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(&empty, sizeof(empty));
    if (!ok) {
        OPENSSL_cleanse(output, output_size);
    }
    return ok;
}

static const char *cipher_name(uint32_t suite)
{
    return suite == NINLIL_PA_S2_EDHOC_SUITE_2
        ? "AES-128-CCM" : "CHACHA20-POLY1305";
}

static int platform_seal(uint32_t suite, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
    const uint8_t *plaintext, size_t plaintext_size, uint8_t *sealed)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *context = NULL;
    uint8_t empty = 0u;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    size_t nonce_size = suite_nonce_bytes(suite);
    size_t tag_size = suite_tag_bytes(suite);
    int part = 0;
    int final_size = 0;
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, cipher_name(suite), NULL);
    context = EVP_CIPHER_CTX_new();
    if (cipher == NULL || context == NULL
        || EVP_EncryptInit_ex(context, cipher, NULL, NULL, NULL) <= 0
        || EVP_CIPHER_CTX_ctrl(
               context, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_size, NULL)
            <= 0) {
        goto cleanup;
    }
    if (suite == NINLIL_PA_S2_EDHOC_SUITE_2
        && EVP_CIPHER_CTX_ctrl(
               context, EVP_CTRL_AEAD_SET_TAG, (int)tag_size, NULL)
            <= 0) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) <= 0) {
        goto cleanup;
    }
    if (suite == NINLIL_PA_S2_EDHOC_SUITE_2
        && EVP_EncryptUpdate(
               context, NULL, &part, NULL, (int)plaintext_size)
            <= 0) {
        goto cleanup;
    }
    if (aad_size != 0u
        && EVP_EncryptUpdate(context, NULL, &part, aad, (int)aad_size) <= 0) {
        goto cleanup;
    }
    if (EVP_EncryptUpdate(context, sealed, &part,
            plaintext_size == 0u ? &empty : plaintext, (int)plaintext_size)
            <= 0
        || part < 0 || (size_t)part != plaintext_size) {
        goto cleanup;
    }
    if (suite == NINLIL_PA_S2_EDHOC_SUITE_3) {
        if (EVP_EncryptFinal_ex(context, final_block, &final_size) <= 0
            || final_size != 0) {
            goto cleanup;
        }
    }
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, (int)tag_size,
            sealed + plaintext_size)
        <= 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(&empty, sizeof(empty));
    OPENSSL_cleanse(final_block, sizeof(final_block));
    return ok;
}

static int platform_open(uint32_t suite, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size,
    const uint8_t *sealed, size_t plaintext_size, uint8_t *plaintext)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *context = NULL;
    uint8_t empty = 0u;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    size_t nonce_size = suite_nonce_bytes(suite);
    size_t tag_size = suite_tag_bytes(suite);
    int part = 0;
    int final_size = 0;
    int ok = 0;

    cipher = EVP_CIPHER_fetch(NULL, cipher_name(suite), NULL);
    context = EVP_CIPHER_CTX_new();
    if (cipher == NULL || context == NULL
        || EVP_DecryptInit_ex(context, cipher, NULL, NULL, NULL) <= 0
        || EVP_CIPHER_CTX_ctrl(
               context, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_size, NULL)
            <= 0
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, (int)tag_size,
               (void *)(uintptr_t)(sealed + plaintext_size))
            <= 0
        || EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) <= 0) {
        goto cleanup;
    }
    if (suite == NINLIL_PA_S2_EDHOC_SUITE_2
        && EVP_DecryptUpdate(
               context, NULL, &part, NULL, (int)plaintext_size)
            <= 0) {
        goto cleanup;
    }
    if (aad_size != 0u
        && EVP_DecryptUpdate(context, NULL, &part, aad, (int)aad_size) <= 0) {
        goto cleanup;
    }
    if (EVP_DecryptUpdate(context,
            plaintext_size == 0u ? &empty : plaintext, &part, sealed,
            (int)plaintext_size)
            <= 0
        || part < 0 || (size_t)part != plaintext_size) {
        goto cleanup;
    }
    if (suite == NINLIL_PA_S2_EDHOC_SUITE_3) {
        if (EVP_DecryptFinal_ex(context, final_block, &final_size) <= 0
            || final_size != 0) {
            goto cleanup;
        }
    }
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(&empty, sizeof(empty));
    OPENSSL_cleanse(final_block, sizeof(final_block));
    return ok;
}
#endif

static int pa_import_key(void *context, enum edhoc_key_type key_type,
    const uint8_t *raw_key, size_t raw_key_length, void *key_id)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    uint8_t candidate_id[NINLIL_PA_S2_EDHOC_KEY_ID_BYTES];
    size_t expected = 0u;
    uint32_t index;
    uint32_t generation;
    int status;

    secure_zero(candidate_id, sizeof(candidate_id));
    status = enter_owner(owner);
    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (key_type != EDHOC_KT_EXTRACT && key_type != EDHOC_KT_EXPAND
        && key_type != EDHOC_KT_ENCRYPT && key_type != EDHOC_KT_DECRYPT) {
        status = EDHOC_ERROR_NOT_SUPPORTED;
        goto done;
    }
    if (raw_key == NULL || key_id == NULL || raw_key_length == 0u
        || raw_key_length > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
        || !external_span_ok(owner, raw_key, raw_key_length)
        || !external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || ranges_overlap(raw_key, raw_key_length, key_id,
            NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)) {
        status = EDHOC_ERROR_INVALID_ARGUMENT;
        goto done;
    }
    if (key_type == EDHOC_KT_EXTRACT) {
        expected = raw_key_length;
    } else if (key_type == EDHOC_KT_EXPAND) {
        expected = PA_S2_SHA256_BYTES;
    } else if (key_type == EDHOC_KT_ENCRYPT || key_type == EDHOC_KT_DECRYPT) {
        expected = suite_key_bytes(owner->suite);
    }
    if (raw_key_length != expected) {
        status = EDHOC_ERROR_INVALID_ARGUMENT;
        goto done;
    }
    if (owner->next_generation == 0u
        || owner->next_generation > PA_S2_KEY_GENERATION_MAX) {
        status = EDHOC_ERROR_BAD_STATE;
        goto done;
    }
    for (index = 0u; index < NINLIL_PA_S2_EDHOC_KEY_SLOTS; ++index) {
        if (owner->key_slots[index].live == 0u) {
            break;
        }
    }
    if (index == NINLIL_PA_S2_EDHOC_KEY_SLOTS) {
        status = EDHOC_ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    generation = owner->next_generation;
    owner->next_generation = generation == PA_S2_KEY_GENERATION_MAX
        ? 0u : generation + 1u;
    secure_zero(&owner->key_slots[index], sizeof(owner->key_slots[index]));
    (void)memcpy(owner->key_slots[index].bytes, raw_key, raw_key_length);
    owner->key_slots[index].bytes_used = (uint32_t)raw_key_length;
    owner->key_slots[index].generation = generation;
    owner->key_slots[index].key_type = (uint32_t)key_type;
    owner->key_slots[index].live = 1u;
    encode_key_id(index, generation, candidate_id);
    (void)memcpy(key_id, candidate_id, sizeof(candidate_id));
    status = EDHOC_SUCCESS;

done:
    secure_zero(candidate_id, sizeof(candidate_id));
    leave_owner(owner);
    return status;
}

static int pa_destroy_key(void *context, void *key_id)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    uint32_t index;
    uint32_t generation;
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (!external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || !decode_key_id((const uint8_t *)key_id, &index, &generation)
        || owner->key_slots[index].live != 1u
        || owner->key_slots[index].generation != generation) {
        status = EDHOC_ERROR_BAD_STATE;
    } else {
        secure_zero(&owner->key_slots[index], sizeof(owner->key_slots[index]));
        status = EDHOC_SUCCESS;
    }
    leave_owner(owner);
    return status;
}

static int pa_make_key_pair(void *context, const void *key_id,
    uint8_t *private_key, size_t private_key_size, size_t *private_key_length,
    uint8_t *public_key, size_t public_key_size, size_t *public_key_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    int status = enter_owner(owner);
    if (status == EDHOC_SUCCESS) {
        if (!external_span_ok(
                owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
            || private_key_length == NULL || public_key_length == NULL
            || !external_span_ok(
                owner, private_key_length, sizeof(*private_key_length))
            || !external_span_ok(
                owner, public_key_length, sizeof(*public_key_length))
            || private_key_size > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
            || public_key_size > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
            || !external_span_ok(owner, private_key, private_key_size)
            || !external_span_ok(owner, public_key, public_key_size)
            || ranges_overlap(private_key, private_key_size,
                public_key, public_key_size)
            || ranges_overlap(private_key, private_key_size,
                private_key_length, sizeof(*private_key_length))
            || ranges_overlap(public_key, public_key_size,
                public_key_length, sizeof(*public_key_length))
            || ranges_overlap(private_key_length, sizeof(*private_key_length),
                public_key_length, sizeof(*public_key_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                private_key_length, sizeof(*private_key_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                public_key_length, sizeof(*public_key_length))) {
            leave_owner(owner);
            return EDHOC_ERROR_INVALID_ARGUMENT;
        }
        *private_key_length = 0u;
        *public_key_length = 0u;
        if (private_key != NULL) {
            secure_zero(private_key, private_key_size);
        }
        if (public_key != NULL) {
            secure_zero(public_key, public_key_size);
        }
        leave_owner(owner);
        status = EDHOC_ERROR_NOT_SUPPORTED;
    }
    return status;
}

static int pa_key_agreement(void *context, const void *key_id,
    const uint8_t *peer_public_key, size_t peer_public_key_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    int status = enter_owner(owner);
    if (status == EDHOC_SUCCESS) {
        if (!external_span_ok(
                owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
            || shared_secret_length == NULL
            || !external_span_ok(
                owner, peer_public_key, peer_public_key_length)
            || !external_span_ok(
                owner, shared_secret_length, sizeof(*shared_secret_length))
            || shared_secret_size > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
            || !external_span_ok(owner, shared_secret, shared_secret_size)
            || ranges_overlap(peer_public_key, peer_public_key_length,
                shared_secret, shared_secret_size)
            || ranges_overlap(shared_secret, shared_secret_size,
                shared_secret_length, sizeof(*shared_secret_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                shared_secret_length, sizeof(*shared_secret_length))) {
            leave_owner(owner);
            return EDHOC_ERROR_INVALID_ARGUMENT;
        }
        *shared_secret_length = 0u;
        if (shared_secret != NULL) {
            secure_zero(shared_secret, shared_secret_size);
        }
        leave_owner(owner);
        status = EDHOC_ERROR_NOT_SUPPORTED;
    }
    return status;
}

static int pa_signature(void *context, const void *key_id,
    const uint8_t *input, size_t input_length, uint8_t *signature,
    size_t signature_size, size_t *signature_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    int status = enter_owner(owner);
    if (status == EDHOC_SUCCESS) {
        if (!external_span_ok(
                owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
            || signature_length == NULL
            || !external_span_ok(owner, input, input_length)
            || !external_span_ok(
                owner, signature_length, sizeof(*signature_length))
            || signature_size > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
            || !external_span_ok(owner, signature, signature_size)
            || ranges_overlap(
                input, input_length, signature, signature_size)
            || ranges_overlap(signature, signature_size,
                signature_length, sizeof(*signature_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                signature_length, sizeof(*signature_length))) {
            leave_owner(owner);
            return EDHOC_ERROR_INVALID_ARGUMENT;
        }
        *signature_length = 0u;
        if (signature != NULL) {
            secure_zero(signature, signature_size);
        }
        leave_owner(owner);
        status = EDHOC_ERROR_NOT_SUPPORTED;
    }
    return status;
}

static int pa_verify(void *context, const void *key_id, const uint8_t *input,
    size_t input_length, const uint8_t *signature, size_t signature_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    int status = enter_owner(owner);
    if (status == EDHOC_SUCCESS) {
        if (!external_span_ok(
                owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
            || !external_span_ok(owner, input, input_length)
            || !external_span_ok(owner, signature, signature_length)) {
            leave_owner(owner);
            return EDHOC_ERROR_INVALID_ARGUMENT;
        }
        leave_owner(owner);
        status = EDHOC_ERROR_NOT_SUPPORTED;
    }
    return status;
}

static int pa_extract(void *context, const void *key_id, const uint8_t *salt,
    size_t salt_length, uint8_t *prk, size_t prk_size, size_t *prk_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    ninlil_pa_s2_edhoc_key_slot_v1_t *slot;
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (!external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || prk == NULL || prk_length == NULL
        || !external_span_ok(owner, salt, salt_length)
        || !external_span_ok(owner, prk, prk_size)
        || !external_span_ok(owner, prk_length, sizeof(*prk_length))
        || salt_length > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
        || prk_size > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
        || ranges_overlap(salt, salt_length, prk, prk_size)
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            prk, prk_size)
        || ranges_overlap(prk, prk_size, prk_length, sizeof(*prk_length))
        || ranges_overlap(
            salt, salt_length, prk_length, sizeof(*prk_length))
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            prk_length, sizeof(*prk_length))) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    *prk_length = 0u;
    if (prk_size < PA_S2_SHA256_BYTES) {
        leave_owner(owner);
        return EDHOC_ERROR_BUFFER_TOO_SMALL;
    }
    slot = lookup_key(owner, key_id, EDHOC_KT_EXTRACT);
    if (slot == NULL || !platform_hkdf_extract(salt, salt_length, slot->bytes,
            slot->bytes_used, owner->workspace)) {
        status = slot == NULL ? EDHOC_ERROR_BAD_STATE
                              : EDHOC_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    (void)memcpy(prk, owner->workspace, PA_S2_SHA256_BYTES);
    *prk_length = PA_S2_SHA256_BYTES;
    status = EDHOC_SUCCESS;

done:
    secure_zero(owner->workspace, sizeof(owner->workspace));
    leave_owner(owner);
    return status;
}

static int pa_expand(void *context, const void *key_id, const uint8_t *info,
    size_t info_length, uint8_t *output, size_t output_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    ninlil_pa_s2_edhoc_key_slot_v1_t *slot;
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (!external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || !external_span_ok(owner, info, info_length)
        || !external_span_ok(owner, output, output_length)
        || output_length == 0u
        || output_length > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
        || info_length > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX
        || ranges_overlap(info, info_length, output, output_length)
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            output, output_length)) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    slot = lookup_key(owner, key_id, EDHOC_KT_EXPAND);
    if (slot == NULL || !platform_hkdf_expand(
            slot->bytes, info, info_length, owner->workspace, output_length)) {
        status = slot == NULL ? EDHOC_ERROR_BAD_STATE
                              : EDHOC_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    (void)memcpy(output, owner->workspace, output_length);
    status = EDHOC_SUCCESS;

done:
    secure_zero(owner->workspace, sizeof(owner->workspace));
    leave_owner(owner);
    return status;
}

static int pa_encrypt(void *context, const void *key_id, const uint8_t *nonce,
    size_t nonce_length, const uint8_t *aad, size_t aad_length,
    const uint8_t *plaintext, size_t plaintext_length, uint8_t *ciphertext,
    size_t ciphertext_size, size_t *ciphertext_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    ninlil_pa_s2_edhoc_key_slot_v1_t *slot;
    size_t expected;
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (plaintext_length > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    expected = plaintext_length + suite_tag_bytes(owner->suite);
    if (!external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || ciphertext == NULL || ciphertext_length == NULL
        || !external_span_ok(owner, nonce, nonce_length)
        || !external_span_ok(owner, aad, aad_length)
        || !external_span_ok(owner, plaintext, plaintext_length)
        || !external_span_ok(owner, ciphertext, ciphertext_size)
        || !external_span_ok(
            owner, ciphertext_length, sizeof(*ciphertext_length))
        || nonce_length != suite_nonce_bytes(owner->suite)
        || aad_length > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX
        || ciphertext_size > NINLIL_PA_S2_EDHOC_WORKSPACE_BYTES
        || ranges_overlap(
            plaintext, plaintext_length, ciphertext, ciphertext_size)
        || ranges_overlap(nonce, nonce_length, ciphertext, ciphertext_size)
        || ranges_overlap(aad, aad_length, ciphertext, ciphertext_size)
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            ciphertext, ciphertext_size)
        || ranges_overlap(ciphertext, ciphertext_size, ciphertext_length,
            sizeof(*ciphertext_length))
        || ranges_overlap(plaintext, plaintext_length, ciphertext_length,
            sizeof(*ciphertext_length))
        || ranges_overlap(aad, aad_length, ciphertext_length,
            sizeof(*ciphertext_length))
        || ranges_overlap(nonce, nonce_length, ciphertext_length,
            sizeof(*ciphertext_length))
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            ciphertext_length, sizeof(*ciphertext_length))) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    *ciphertext_length = 0u;
    if (ciphertext_size < expected) {
        leave_owner(owner);
        return EDHOC_ERROR_BUFFER_TOO_SMALL;
    }
    slot = lookup_key(owner, key_id, EDHOC_KT_ENCRYPT);
    if (slot == NULL || slot->bytes_used != suite_key_bytes(owner->suite)
        || !platform_seal(owner->suite, slot->bytes, nonce, aad, aad_length,
            plaintext, plaintext_length, owner->workspace)) {
        status = slot == NULL ? EDHOC_ERROR_BAD_STATE
                              : EDHOC_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    (void)memcpy(ciphertext, owner->workspace, expected);
    *ciphertext_length = expected;
    status = EDHOC_SUCCESS;

done:
    secure_zero(owner->workspace, sizeof(owner->workspace));
    leave_owner(owner);
    return status;
}

static int pa_decrypt(void *context, const void *key_id, const uint8_t *nonce,
    size_t nonce_length, const uint8_t *aad, size_t aad_length,
    const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext,
    size_t plaintext_size, size_t *plaintext_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    ninlil_pa_s2_edhoc_key_slot_v1_t *slot;
    size_t tag_size;
    size_t expected;
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    tag_size = suite_tag_bytes(owner->suite);
    if (ciphertext_length < tag_size) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    expected = ciphertext_length - tag_size;
    if (!external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || plaintext_length == NULL
        || (expected != 0u && plaintext == NULL)
        || !external_span_ok(owner, nonce, nonce_length)
        || !external_span_ok(owner, aad, aad_length)
        || !external_span_ok(owner, ciphertext, ciphertext_length)
        || !external_span_ok(owner, plaintext, plaintext_size)
        || !external_span_ok(
            owner, plaintext_length, sizeof(*plaintext_length))
        || nonce_length != suite_nonce_bytes(owner->suite)
        || aad_length > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX
        || expected > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX
        || ciphertext_length > NINLIL_PA_S2_EDHOC_WORKSPACE_BYTES
        || plaintext_size > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX
        || ranges_overlap(
            ciphertext, ciphertext_length, plaintext, plaintext_size)
        || ranges_overlap(nonce, nonce_length, plaintext, plaintext_size)
        || ranges_overlap(aad, aad_length, plaintext, plaintext_size)
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            plaintext, plaintext_size)
        || ranges_overlap(plaintext, plaintext_size, plaintext_length,
            sizeof(*plaintext_length))
        || ranges_overlap(ciphertext, ciphertext_length, plaintext_length,
            sizeof(*plaintext_length))
        || ranges_overlap(aad, aad_length, plaintext_length,
            sizeof(*plaintext_length))
        || ranges_overlap(nonce, nonce_length, plaintext_length,
            sizeof(*plaintext_length))
        || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
            plaintext_length, sizeof(*plaintext_length))) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    *plaintext_length = 0u;
    if (plaintext_size < expected) {
        leave_owner(owner);
        return EDHOC_ERROR_BUFFER_TOO_SMALL;
    }
    slot = lookup_key(owner, key_id, EDHOC_KT_DECRYPT);
    if (slot == NULL || slot->bytes_used != suite_key_bytes(owner->suite)
        || !platform_open(owner->suite, slot->bytes, nonce, aad, aad_length,
            ciphertext, expected, owner->workspace)) {
        status = slot == NULL ? EDHOC_ERROR_BAD_STATE
                              : EDHOC_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    if (expected != 0u) {
        (void)memcpy(plaintext, owner->workspace, expected);
    }
    *plaintext_length = expected;
    status = EDHOC_SUCCESS;

done:
    secure_zero(owner->workspace, sizeof(owner->workspace));
    leave_owner(owner);
    return status;
}

static int pa_hash(void *context, const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (hash == NULL || hash_length == NULL
        || hash_size > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
        || input_length > NINLIL_PA_S2_EDHOC_BODY_BYTES_MAX
        || !external_span_ok(owner, input, input_length)
        || !external_span_ok(owner, hash, hash_size)
        || !external_span_ok(owner, hash_length, sizeof(*hash_length))
        || ranges_overlap(input, input_length, hash, hash_size)
        || ranges_overlap(
            hash, hash_size, hash_length, sizeof(*hash_length))
        || ranges_overlap(
            input, input_length, hash_length, sizeof(*hash_length))) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    *hash_length = 0u;
    if (hash_size < PA_S2_SHA256_BYTES) {
        leave_owner(owner);
        return EDHOC_ERROR_BUFFER_TOO_SMALL;
    }
    if (!platform_sha256(input, input_length, owner->workspace)) {
        status = EDHOC_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    (void)memcpy(hash, owner->workspace, PA_S2_SHA256_BYTES);
    *hash_length = PA_S2_SHA256_BYTES;
    status = EDHOC_SUCCESS;

done:
    secure_zero(owner->workspace, sizeof(owner->workspace));
    leave_owner(owner);
    return status;
}

static const struct edhoc_keys PA_KEYS = {
    .import_key = pa_import_key,
    .destroy_key = pa_destroy_key,
};

static const struct edhoc_crypto PA_CRYPTO = {
    .make_key_pair = pa_make_key_pair,
    .key_agreement = pa_key_agreement,
    .signature = pa_signature,
    .verify = pa_verify,
    .extract = pa_extract,
    .expand = pa_expand,
    .encrypt = pa_encrypt,
    .decrypt = pa_decrypt,
    .hash = pa_hash,
};

int ninlil_pa_s2_edhoc_crypto_owner_v1_begin(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner, uint32_t suite)
{
    if (owner == NULL || !suite_valid(suite)) {
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return EDHOC_ERROR_NOT_PERMITTED;
    }
    if (owner->active != 0u) {
        return EDHOC_ERROR_BAD_STATE;
    }
    secure_zero(owner, sizeof(*owner));
    owner->suite = suite;
    owner->next_generation = 1u;
    owner->active = 1u;
    return EDHOC_SUCCESS;
}

int ninlil_pa_s2_edhoc_crypto_owner_v1_bindings(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner, struct edhoc_keys *keys,
    struct edhoc_crypto *crypto)
{
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (keys == NULL || crypto == NULL
        || !external_span_ok(owner, keys, sizeof(*keys))
        || !external_span_ok(owner, crypto, sizeof(*crypto))
        || ranges_overlap(keys, sizeof(*keys), crypto, sizeof(*crypto))) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    *keys = PA_KEYS;
    *crypto = PA_CRYPTO;
    leave_owner(owner);
    return EDHOC_SUCCESS;
}

int ninlil_pa_s2_edhoc_crypto_owner_v1_end(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner)
{
    if (owner == NULL || owner->active != 1u || owner->in_call != 0u) {
        return owner != NULL && owner->in_call != 0u
            ? EDHOC_ERROR_NOT_PERMITTED : EDHOC_ERROR_BAD_STATE;
    }
    secure_zero(owner, sizeof(*owner));
    return EDHOC_SUCCESS;
}
