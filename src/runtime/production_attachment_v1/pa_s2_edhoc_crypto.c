/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s2_edhoc_crypto.h"

#include "edhoc_values.h"

#include <limits.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#endif
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#if !defined(MBEDTLS_CCM_C) || !defined(MBEDTLS_CHACHA20_C) \
    || !defined(MBEDTLS_POLY1305_C) || !defined(MBEDTLS_CHACHAPOLY_C)
#error "PA-S2a requires ESP-IDF mbedTLS CCM, ChaCha20, Poly1305, and ChaChaPoly"
#endif
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256 \
    && (!defined(MBEDTLS_ECP_C) || !defined(MBEDTLS_ECDH_C) \
        || !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED))
#error "PA-S2b1 requires ESP-IDF mbedTLS ECP, ECDH, and secp256r1"
#endif
#else
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#endif
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

#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
#define PA_S2B1_P256_BYTES ((size_t)32u)
#define PA_S2B1_P256_COMPACT_BYTES ((size_t)33u)
#define PA_S2B1_EPHEMERAL_BYTES ((size_t)64u)
#define PA_S2B1_TOKEN_OFFSET ((size_t)32u)
#define PA_S2B1_DRAW_ATTEMPTS ((uint32_t)8u)
#define PA_S2B1_BACKING_KEY_TYPE UINT32_C(0xffffffff)

static const uint8_t PA_S2B1_P256_ORDER[PA_S2B1_P256_BYTES] = {
    0xffu, 0xffu, 0xffu, 0xffu, 0x00u, 0x00u, 0x00u, 0x00u,
    0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    0xbcu, 0xe6u, 0xfau, 0xadu, 0xa7u, 0x17u, 0x9eu, 0x84u,
    0xf3u, 0xb9u, 0xcau, 0xc2u, 0xfcu, 0x63u, 0x25u, 0x51u,
};
#endif

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

#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
static int constant_time_equal(
    const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0u;
    size_t index;

    for (index = 0u; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static int all_zero(const uint8_t *bytes, size_t size)
{
    uint8_t aggregate = 0u;
    size_t index;

    for (index = 0u; index < size; ++index) {
        aggregate |= bytes[index];
    }
    return aggregate == 0u;
}

static int scalar_valid(const uint8_t scalar[PA_S2B1_P256_BYTES])
{
    size_t index;

    if (all_zero(scalar, PA_S2B1_P256_BYTES)) {
        return 0;
    }
    for (index = 0u; index < PA_S2B1_P256_BYTES; ++index) {
        if (scalar[index] < PA_S2B1_P256_ORDER[index]) {
            return 1;
        }
        if (scalar[index] > PA_S2B1_P256_ORDER[index]) {
            return 0;
        }
    }
    return 0;
}

static int entropy_fill(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    uint8_t output[PA_S2B1_P256_BYTES])
{
    ninlil_port_status_t status;

    secure_zero(output, PA_S2B1_P256_BYTES);
    if (owner->entropy.fill == NULL) {
        return 0;
    }
    status = owner->entropy.fill(
        owner->entropy.user, output, (uint32_t)PA_S2B1_P256_BYTES);
    if (status != NINLIL_PORT_OK) {
        secure_zero(output, PA_S2B1_P256_BYTES);
        return 0;
    }
    return 1;
}

static int draw_scalar(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    uint8_t scalar[PA_S2B1_P256_BYTES])
{
    uint32_t attempt;

    for (attempt = 0u; attempt < PA_S2B1_DRAW_ATTEMPTS; ++attempt) {
        if (!entropy_fill(owner, scalar)) {
            return 0;
        }
        if (scalar_valid(scalar)) {
            return 1;
        }
        secure_zero(scalar, PA_S2B1_P256_BYTES);
    }
    return 0;
}

static int draw_token(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const uint8_t scalar[PA_S2B1_P256_BYTES],
    uint8_t token[PA_S2B1_P256_BYTES])
{
    uint32_t attempt;

    for (attempt = 0u; attempt < PA_S2B1_DRAW_ATTEMPTS; ++attempt) {
        if (!entropy_fill(owner, token)) {
            return 0;
        }
        if (!all_zero(token, PA_S2B1_P256_BYTES)
            && !constant_time_equal(token, scalar, PA_S2B1_P256_BYTES)) {
            return 1;
        }
        secure_zero(token, PA_S2B1_P256_BYTES);
    }
    return 0;
}
#endif

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
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
static int pa_s2b1_mbedtls_rng(
    void *context, unsigned char *output, size_t output_size)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner =
        (ninlil_pa_s2_edhoc_crypto_owner_v1_t *)context;

    if (owner == NULL || output == NULL || output_size == 0u
        || output_size > UINT32_MAX || owner->entropy.fill == NULL
        || owner->entropy.fill(owner->entropy.user, output,
               (uint32_t)output_size) != NINLIL_PORT_OK) {
        if (output != NULL) {
            secure_zero(output, output_size);
        }
        return -1;
    }
    return 0;
}

static int platform_p256_public_from_scalar(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const uint8_t scalar[PA_S2B1_P256_BYTES],
    uint8_t public_x[PA_S2B1_P256_BYTES])
{
    uint8_t compact[PA_S2B1_P256_COMPACT_BYTES];
    mbedtls_ecp_group group;
    mbedtls_ecp_point point;
    mbedtls_mpi private_value;
    size_t compact_size = 0u;
    int status;
    int ok = 0;

    secure_zero(public_x, PA_S2B1_P256_BYTES);
    secure_zero(compact, sizeof(compact));
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&private_value);
    status = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (status == 0) {
        status = mbedtls_mpi_read_binary(
            &private_value, scalar, PA_S2B1_P256_BYTES);
    }
    if (status == 0) {
        status = mbedtls_ecp_check_privkey(&group, &private_value);
    }
    if (status == 0) {
        status = mbedtls_ecp_mul(&group, &point, &private_value, &group.G,
            pa_s2b1_mbedtls_rng, owner);
    }
    if (status == 0) {
        status = mbedtls_ecp_check_pubkey(&group, &point);
    }
    if (status == 0) {
        status = mbedtls_ecp_point_write_binary(&group, &point,
            MBEDTLS_ECP_PF_COMPRESSED, &compact_size,
            compact, sizeof(compact));
    }
    if (status == 0 && compact_size == sizeof(compact)
        && (compact[0] == 0x02u || compact[0] == 0x03u)) {
        (void)memcpy(public_x, compact + 1u, PA_S2B1_P256_BYTES);
    } else if (status == 0) {
        status = -1;
    }
    if (status == 0) {
        ok = 1;
    }
    mbedtls_mpi_free(&private_value);
    mbedtls_ecp_point_free(&point);
    mbedtls_ecp_group_free(&group);
    secure_zero(compact, sizeof(compact));
    if (!ok) {
        secure_zero(public_x, PA_S2B1_P256_BYTES);
    }
    return ok;
}

static int platform_p256_shared(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const uint8_t scalar[PA_S2B1_P256_BYTES],
    const uint8_t peer_x[PA_S2B1_P256_BYTES],
    uint8_t shared[PA_S2B1_P256_BYTES])
{
    uint8_t compact[PA_S2B1_P256_COMPACT_BYTES];
    mbedtls_ecp_group group;
    mbedtls_ecp_point peer;
    mbedtls_mpi private_value;
    mbedtls_mpi secret;
    int status;
    int ok = 0;

    secure_zero(shared, PA_S2B1_P256_BYTES);
    compact[0] = 0x02u;
    (void)memcpy(compact + 1u, peer_x, PA_S2B1_P256_BYTES);
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&private_value);
    mbedtls_mpi_init(&secret);
    status = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (status == 0) {
        status = mbedtls_mpi_read_binary(
            &private_value, scalar, PA_S2B1_P256_BYTES);
    }
    if (status == 0) {
        status = mbedtls_ecp_check_privkey(&group, &private_value);
    }
    if (status == 0) {
        status = mbedtls_ecp_point_read_binary(
            &group, &peer, compact, sizeof(compact));
    }
    if (status == 0) {
        status = mbedtls_ecp_check_pubkey(&group, &peer);
    }
    if (status == 0) {
        status = mbedtls_ecdh_compute_shared(&group, &secret, &peer,
            &private_value, pa_s2b1_mbedtls_rng, owner);
    }
    if (status == 0) {
        status = mbedtls_mpi_write_binary(
            &secret, shared, PA_S2B1_P256_BYTES);
    }
    if (status == 0) {
        ok = 1;
    }
    mbedtls_mpi_free(&secret);
    mbedtls_mpi_free(&private_value);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_group_free(&group);
    secure_zero(compact, sizeof(compact));
    if (!ok) {
        secure_zero(shared, PA_S2B1_P256_BYTES);
    }
    return ok;
}
#endif

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
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
static int platform_p256_public_from_scalar(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const uint8_t scalar[PA_S2B1_P256_BYTES],
    uint8_t public_x[PA_S2B1_P256_BYTES])
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BN_CTX *context = NULL;
    BIGNUM *private_value = NULL;
    BIGNUM *x = NULL;
    int ok = 0;

    (void)owner;
    secure_zero(public_x, PA_S2B1_P256_BYTES);
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group != NULL) {
        point = EC_POINT_new(group);
    }
    context = BN_CTX_new();
    private_value = BN_bin2bn(
        scalar, (int)PA_S2B1_P256_BYTES, NULL);
    x = BN_new();
    if (private_value != NULL) {
        BN_set_flags(private_value, BN_FLG_CONSTTIME);
    }
    if (group != NULL && point != NULL && context != NULL
        && private_value != NULL && x != NULL
        && EC_POINT_mul(group, point, private_value, NULL, NULL, context) > 0
        && EC_POINT_is_at_infinity(group, point) == 0
        && EC_POINT_get_affine_coordinates(group, point, x, NULL, context) > 0
        && BN_bn2binpad(x, public_x, (int)PA_S2B1_P256_BYTES)
            == (int)PA_S2B1_P256_BYTES) {
        ok = 1;
    }
    BN_clear_free(x);
    BN_clear_free(private_value);
    BN_CTX_free(context);
    EC_POINT_clear_free(point);
    EC_GROUP_free(group);
    if (!ok) {
        secure_zero(public_x, PA_S2B1_P256_BYTES);
    }
    return ok;
}

static int platform_p256_shared(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const uint8_t scalar[PA_S2B1_P256_BYTES],
    const uint8_t peer_x[PA_S2B1_P256_BYTES],
    uint8_t shared[PA_S2B1_P256_BYTES])
{
    uint8_t compact[PA_S2B1_P256_COMPACT_BYTES];
    EC_GROUP *group = NULL;
    EC_POINT *peer = NULL;
    EC_POINT *shared_point = NULL;
    BN_CTX *context = NULL;
    BIGNUM *private_value = NULL;
    BIGNUM *x = NULL;
    BIGNUM *prime = NULL;
    int ok = 0;

    (void)owner;
    secure_zero(shared, PA_S2B1_P256_BYTES);
    compact[0] = 0x02u;
    (void)memcpy(compact + 1u, peer_x, PA_S2B1_P256_BYTES);
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group != NULL) {
        peer = EC_POINT_new(group);
        shared_point = EC_POINT_new(group);
    }
    context = BN_CTX_new();
    private_value = BN_bin2bn(
        scalar, (int)PA_S2B1_P256_BYTES, NULL);
    x = BN_bin2bn(peer_x, (int)PA_S2B1_P256_BYTES, NULL);
    prime = BN_new();
    if (private_value != NULL) {
        BN_set_flags(private_value, BN_FLG_CONSTTIME);
    }
    if (group != NULL && peer != NULL && shared_point != NULL
        && context != NULL && private_value != NULL && x != NULL
        && prime != NULL && EC_GROUP_get_curve(group, prime, NULL, NULL, context) > 0
        && BN_cmp(x, prime) < 0
        && EC_POINT_oct2point(
               group, peer, compact, sizeof(compact), context) > 0
        && EC_POINT_is_on_curve(group, peer, context) == 1
        && EC_POINT_is_at_infinity(group, peer) == 0
        && EC_POINT_mul(
               group, shared_point, NULL, peer, private_value, context) > 0
        && EC_POINT_is_at_infinity(group, shared_point) == 0
        && EC_POINT_get_affine_coordinates(
               group, shared_point, x, NULL, context) > 0
        && BN_bn2binpad(x, shared, (int)PA_S2B1_P256_BYTES)
            == (int)PA_S2B1_P256_BYTES) {
        ok = 1;
    }
    BN_clear_free(prime);
    BN_clear_free(x);
    BN_clear_free(private_value);
    BN_CTX_free(context);
    EC_POINT_clear_free(shared_point);
    EC_POINT_clear_free(peer);
    EC_GROUP_free(group);
    secure_zero(compact, sizeof(compact));
    if (!ok) {
        secure_zero(shared, PA_S2B1_P256_BYTES);
    }
    return ok;
}
#endif

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
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    int make_pair_handle = 0;
#endif

    secure_zero(candidate_id, sizeof(candidate_id));
    status = enter_owner(owner);
    if (status != EDHOC_SUCCESS) {
        return status;
    }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    if (key_type == EDHOC_KT_KEY_AGREEMENT) {
        ninlil_pa_s2_edhoc_key_slot_v1_t *match = NULL;
        uint32_t match_index = 0u;

        if (raw_key == NULL || raw_key_length != PA_S2B1_P256_BYTES
            || key_id == NULL
            || !external_span_ok(owner, raw_key, raw_key_length)
            || !external_span_ok(
                owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
            || ranges_overlap(raw_key, raw_key_length, key_id,
                NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)) {
            status = EDHOC_ERROR_INVALID_ARGUMENT;
            goto done;
        }
        for (index = 0u; index < NINLIL_PA_S2_EDHOC_KEY_SLOTS; ++index) {
            ninlil_pa_s2_edhoc_key_slot_v1_t *candidate =
                &owner->key_slots[index];
            if (candidate->live == 1u
                && candidate->key_type == PA_S2B1_BACKING_KEY_TYPE
                && candidate->bytes_used == PA_S2B1_EPHEMERAL_BYTES
                && constant_time_equal(candidate->bytes + PA_S2B1_TOKEN_OFFSET,
                    raw_key, PA_S2B1_P256_BYTES)) {
                if (match != NULL) {
                    status = EDHOC_ERROR_BAD_STATE;
                    goto done;
                }
                match = candidate;
                match_index = index;
            }
        }
        if (match == NULL || match->operation_live != 0u
            || match->use_count >= 2u || match->generation == 0u
            || match->generation > PA_S2_KEY_GENERATION_MAX - 2u) {
            status = EDHOC_ERROR_BAD_STATE;
            goto done;
        }
        generation = match->generation + match->use_count + 1u;
        match->operation_generation = generation;
        match->operation_live = 1u;
        match->operation_used = 0u;
        match->use_count += 1u;
        encode_key_id(match_index, generation, candidate_id);
        (void)memcpy(key_id, candidate_id, sizeof(candidate_id));
        status = EDHOC_SUCCESS;
        goto done;
    }
    if (key_type == EDHOC_KT_MAKE_KEY_PAIR) {
        if (raw_key != NULL || raw_key_length != 0u || key_id == NULL
            || owner->entropy.fill == NULL
            || !external_span_ok(
                owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)) {
            status = EDHOC_ERROR_INVALID_ARGUMENT;
            goto done;
        }
        make_pair_handle = 1;
    } else
#endif
    if (key_type != EDHOC_KT_EXTRACT && key_type != EDHOC_KT_EXPAND
        && key_type != EDHOC_KT_ENCRYPT && key_type != EDHOC_KT_DECRYPT) {
        status = EDHOC_ERROR_NOT_SUPPORTED;
        goto done;
    }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    if (!make_pair_handle &&
#else
    if (
#endif
        (raw_key == NULL || key_id == NULL || raw_key_length == 0u
        || raw_key_length > NINLIL_PA_S2_EDHOC_KEY_BYTES_MAX
        || !external_span_ok(owner, raw_key, raw_key_length)
        || !external_span_ok(
            owner, key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES)
        || ranges_overlap(raw_key, raw_key_length, key_id,
            NINLIL_PA_S2_EDHOC_KEY_ID_BYTES))) {
        status = EDHOC_ERROR_INVALID_ARGUMENT;
        goto done;
    }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    if (make_pair_handle) {
        expected = 0u;
    } else
#endif
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
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    if (!make_pair_handle)
#endif
    {
        (void)memcpy(owner->key_slots[index].bytes, raw_key, raw_key_length);
    }
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
        || owner->key_slots[index].live != 1u) {
        status = EDHOC_ERROR_BAD_STATE;
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    } else if (owner->key_slots[index].key_type == PA_S2B1_BACKING_KEY_TYPE) {
        ninlil_pa_s2_edhoc_key_slot_v1_t *slot = &owner->key_slots[index];
        if (slot->operation_live != 1u
            || slot->operation_generation != generation
            || slot->use_count == 0u || slot->use_count > 2u) {
            status = EDHOC_ERROR_BAD_STATE;
        } else if (slot->operation_used != 1u) {
            secure_zero(slot, sizeof(*slot));
            status = EDHOC_ERROR_BAD_STATE;
        } else if (slot->use_count == 2u) {
            secure_zero(slot, sizeof(*slot));
            status = EDHOC_SUCCESS;
        } else {
            slot->operation_generation = 0u;
            slot->operation_live = 0u;
            slot->operation_used = 0u;
            status = EDHOC_SUCCESS;
        }
#endif
    } else if (owner->key_slots[index].generation != generation) {
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
            || ranges_overlap(private_key, private_key_size,
                public_key_length, sizeof(*public_key_length))
            || ranges_overlap(public_key, public_key_size,
                public_key_length, sizeof(*public_key_length))
            || ranges_overlap(public_key, public_key_size,
                private_key_length, sizeof(*private_key_length))
            || ranges_overlap(private_key_length, sizeof(*private_key_length),
                public_key_length, sizeof(*public_key_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                private_key_length, sizeof(*private_key_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                public_key_length, sizeof(*public_key_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                private_key, private_key_size)
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                public_key, public_key_size)) {
            leave_owner(owner);
            return EDHOC_ERROR_INVALID_ARGUMENT;
        }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
        if (private_key_size < PA_S2B1_P256_BYTES
            || public_key_size < PA_S2B1_P256_BYTES) {
            leave_owner(owner);
            return EDHOC_ERROR_BUFFER_TOO_SMALL;
        }
#endif
        *private_key_length = 0u;
        *public_key_length = 0u;
        if (private_key != NULL) {
            secure_zero(private_key, private_key_size);
        }
        if (public_key != NULL) {
            secure_zero(public_key, public_key_size);
        }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
        {
            uint8_t scalar[PA_S2B1_P256_BYTES];
            uint8_t token[PA_S2B1_P256_BYTES];
            uint8_t public_x[PA_S2B1_P256_BYTES];
            uint32_t handle_index;
            uint32_t handle_generation;
            uint32_t backing_index;
            uint32_t backing_generation;
            ninlil_pa_s2_edhoc_key_slot_v1_t *handle;
            ninlil_pa_s2_edhoc_key_slot_v1_t *backing = NULL;

            secure_zero(scalar, sizeof(scalar));
            secure_zero(token, sizeof(token));
            secure_zero(public_x, sizeof(public_x));
            if (!decode_key_id((const uint8_t *)key_id,
                    &handle_index, &handle_generation)) {
                status = EDHOC_ERROR_BAD_STATE;
                goto make_done;
            }
            handle = &owner->key_slots[handle_index];
            if (handle->live != 1u
                || handle->generation != handle_generation
                || handle->key_type != (uint32_t)EDHOC_KT_MAKE_KEY_PAIR
                || handle->bytes_used != 0u || handle->use_count != 0u) {
                status = EDHOC_ERROR_BAD_STATE;
                goto make_done;
            }
            for (backing_index = 0u;
                 backing_index < NINLIL_PA_S2_EDHOC_KEY_SLOTS;
                 ++backing_index) {
                if (owner->key_slots[backing_index].live == 0u) {
                    backing = &owner->key_slots[backing_index];
                    break;
                }
            }
            if (backing == NULL) {
                status = EDHOC_ERROR_NOT_ENOUGH_MEMORY;
                goto make_done;
            }
            if (owner->next_generation == 0u
                || owner->next_generation > PA_S2_KEY_GENERATION_MAX - 2u) {
                status = EDHOC_ERROR_BAD_STATE;
                goto make_done;
            }
            if (!draw_scalar(owner, scalar) || !draw_token(owner, scalar, token)
                || !platform_p256_public_from_scalar(
                    owner, scalar, public_x)) {
                status = EDHOC_ERROR_CRYPTO_FAILURE;
                goto make_done;
            }
            backing_generation = owner->next_generation;
            owner->next_generation =
                backing_generation == PA_S2_KEY_GENERATION_MAX - 2u
                ? 0u : backing_generation + 3u;
            secure_zero(backing, sizeof(*backing));
            (void)memcpy(backing->bytes, scalar, PA_S2B1_P256_BYTES);
            (void)memcpy(backing->bytes + PA_S2B1_TOKEN_OFFSET,
                token, PA_S2B1_P256_BYTES);
            backing->bytes_used = (uint32_t)PA_S2B1_EPHEMERAL_BYTES;
            backing->generation = backing_generation;
            backing->key_type = PA_S2B1_BACKING_KEY_TYPE;
            backing->live = 1u;
            handle->use_count = 1u;
            (void)memcpy(private_key, token, PA_S2B1_P256_BYTES);
            (void)memcpy(public_key, public_x, PA_S2B1_P256_BYTES);
            *private_key_length = PA_S2B1_P256_BYTES;
            *public_key_length = PA_S2B1_P256_BYTES;
            status = EDHOC_SUCCESS;

make_done:
            secure_zero(scalar, sizeof(scalar));
            secure_zero(token, sizeof(token));
            secure_zero(public_x, sizeof(public_x));
        }
#else
        status = EDHOC_ERROR_NOT_SUPPORTED;
#endif
        leave_owner(owner);
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
            || ranges_overlap(peer_public_key, peer_public_key_length,
                shared_secret_length, sizeof(*shared_secret_length))
            || ranges_overlap(shared_secret, shared_secret_size,
                shared_secret_length, sizeof(*shared_secret_length))
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                peer_public_key, peer_public_key_length)
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                shared_secret, shared_secret_size)
            || ranges_overlap(key_id, NINLIL_PA_S2_EDHOC_KEY_ID_BYTES,
                shared_secret_length, sizeof(*shared_secret_length))) {
            leave_owner(owner);
            return EDHOC_ERROR_INVALID_ARGUMENT;
        }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
        if (peer_public_key_length != PA_S2B1_P256_BYTES
            || shared_secret_size < PA_S2B1_P256_BYTES) {
            leave_owner(owner);
            return peer_public_key_length != PA_S2B1_P256_BYTES
                ? EDHOC_ERROR_INVALID_ARGUMENT : EDHOC_ERROR_BUFFER_TOO_SMALL;
        }
#endif
        *shared_secret_length = 0u;
        if (shared_secret != NULL) {
            secure_zero(shared_secret, shared_secret_size);
        }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
        {
            uint8_t candidate[PA_S2B1_P256_BYTES];
            uint32_t slot_index;
            uint32_t operation_generation;
            ninlil_pa_s2_edhoc_key_slot_v1_t *slot;

            secure_zero(candidate, sizeof(candidate));
            if (!decode_key_id((const uint8_t *)key_id,
                    &slot_index, &operation_generation)) {
                status = EDHOC_ERROR_BAD_STATE;
            } else {
                slot = &owner->key_slots[slot_index];
                if (slot->live != 1u
                    || slot->key_type != PA_S2B1_BACKING_KEY_TYPE
                    || slot->bytes_used != PA_S2B1_EPHEMERAL_BYTES
                    || slot->operation_live != 1u
                    || slot->operation_generation != operation_generation
                    || slot->operation_used != 0u
                    || slot->use_count == 0u || slot->use_count > 2u) {
                    if (slot->live == 1u
                        && slot->key_type == PA_S2B1_BACKING_KEY_TYPE
                        && slot->operation_live == 1u
                        && slot->operation_generation == operation_generation
                        && slot->operation_used != 0u) {
                        secure_zero(slot, sizeof(*slot));
                    }
                    status = EDHOC_ERROR_BAD_STATE;
                } else if (!platform_p256_shared(owner, slot->bytes,
                               peer_public_key, candidate)) {
                    secure_zero(slot, sizeof(*slot));
                    status = EDHOC_ERROR_CRYPTO_FAILURE;
                } else {
                    (void)memcpy(
                        shared_secret, candidate, PA_S2B1_P256_BYTES);
                    *shared_secret_length = PA_S2B1_P256_BYTES;
                    slot->operation_used = 1u;
                    status = EDHOC_SUCCESS;
                }
            }
            secure_zero(candidate, sizeof(candidate));
        }
#else
        status = EDHOC_ERROR_NOT_SUPPORTED;
#endif
        leave_owner(owner);
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

#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
int ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const ninlil_entropy_ops_t *entropy)
{
    int status = enter_owner(owner);

    if (status != EDHOC_SUCCESS) {
        return status;
    }
    if (entropy == NULL || entropy->abi_version != NINLIL_ABI_VERSION
        || entropy->struct_size < sizeof(*entropy) || entropy->fill == NULL
        || !external_span_ok(owner, entropy, sizeof(*entropy))
        || (entropy->user != NULL
            && ranges_overlap(owner, sizeof(*owner), entropy->user, 1u))) {
        leave_owner(owner);
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    if (owner->entropy.fill != NULL) {
        leave_owner(owner);
        return EDHOC_ERROR_BAD_STATE;
    }
    owner->entropy = *entropy;
    leave_owner(owner);
    return EDHOC_SUCCESS;
}
#endif

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
