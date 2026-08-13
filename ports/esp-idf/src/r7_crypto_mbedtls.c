/* SPDX-License-Identifier: Apache-2.0 */
/*
 * R7 ESP-IDF mbedTLS private crypto adapter.
 *
 * ESP-IDF v5.5.3 supplied mbedTLS only: SHA-256, RFC 5869 HKDF-SHA-256,
 * AES-128-GCM Seal/Open (CT||TAG16). No direct/default-heap call, VLA, OS
 * dependency, or hand-written AES/GHASH.  Any mbedTLS-owned allocation flows
 * through the composition allocator. Contexts are call-local with init/free
 * on every path.
 *
 * Secrets and intermediates are erased with mbedtls_platform_zeroize.
 */

#include "r7_crypto_mbedtls.h"

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
#include "wifi_esp_tls_allocator.h"
#endif

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

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_sha256_raw(
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

static ninlil_r7_crypto_raw_status
ninlil_r7_mbedtls_hkdf_extract_sha256_raw(
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

static ninlil_r7_crypto_raw_status
ninlil_r7_mbedtls_hkdf_expand_sha256_raw(
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

static ninlil_r7_crypto_raw_status
ninlil_r7_mbedtls_aes128_gcm_seal_raw(
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

static ninlil_r7_crypto_raw_status
ninlil_r7_mbedtls_aes128_gcm_open_raw(
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

#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
typedef struct ninlil_r7_mbedtls_owner_context {
    uint32_t owner;
    uint8_t active;
    atomic_uchar call_state;
    uint8_t reserved[2];
} ninlil_r7_mbedtls_owner_context;

#define NINLIL_R7_MBEDTLS_CALL_ACTIVE ((unsigned char)0x01u)
#define NINLIL_R7_MBEDTLS_CALL_CONFLICT ((unsigned char)0x02u)
#define NINLIL_R7_MBEDTLS_CALL_CLOSING ((unsigned char)0x04u)

static ninlil_r7_mbedtls_owner_context s_r7_owner = {
    .owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID
};

#if defined(NINLIL_WIFI_ESP_TLS_ALLOCATOR_TEST_BUILD)
void ninlil_r7_crypto_mbedtls_test_reset(void)
{
    s_r7_owner.owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    s_r7_owner.active = 0u;
    atomic_store_explicit(
        &s_r7_owner.call_state, 0u, memory_order_release);
    s_r7_owner.reserved[0] = 0u;
    s_r7_owner.reserved[1] = 0u;
}
#endif

static int ninlil_r7_mbedtls_owner_begin(void *ctx)
{
    ninlil_r7_mbedtls_owner_context *owner =
        (ninlil_r7_mbedtls_owner_context *)ctx;
    unsigned char observed;
    if (owner != &s_r7_owner || owner->active == 0u
        || owner->owner == NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID) {
        return 0;
    }
    observed = atomic_load_explicit(
        &owner->call_state, memory_order_acquire);
    for (;;) {
        unsigned char desired;
        if (observed == 0u) {
            desired = NINLIL_R7_MBEDTLS_CALL_ACTIVE;
            if (atomic_compare_exchange_weak_explicit(
                    &owner->call_state,
                    &observed,
                    desired,
                    memory_order_acq_rel,
                    memory_order_acquire)) {
                break;
            }
            continue;
        }
        desired =
            (unsigned char)(observed | NINLIL_R7_MBEDTLS_CALL_CONFLICT);
        if (atomic_compare_exchange_weak_explicit(
                &owner->call_state,
                &observed,
                desired,
                memory_order_acq_rel,
                memory_order_acquire)) {
            /*
             * Only the active callback touches the non-concurrent allocator.
             * It observes this conflict during finish and establishes the
             * fatal fence.  This caller fails without racing allocator state.
             */
            return 0;
        }
    }
    if (ninlil_wifi_esp_tls_allocator_owner_enter(owner->owner)
        != NINLIL_WIFI_OK) {
        atomic_store_explicit(
            &owner->call_state, 0u, memory_order_release);
        return 0;
    }
    return 1;
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_owner_finish(
    void *ctx,
    ninlil_r7_crypto_raw_status raw_status)
{
    ninlil_r7_mbedtls_owner_context *owner =
        (ninlil_r7_mbedtls_owner_context *)ctx;
    ninlil_wifi_status_t leave_status;
    unsigned char observed;
    int conflict_fenced = 0;
    if (owner != &s_r7_owner || owner->active == 0u
        || atomic_load_explicit(
               &owner->call_state, memory_order_acquire)
            == 0u) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    observed = (unsigned char)(
        atomic_fetch_or_explicit(
            &owner->call_state,
            NINLIL_R7_MBEDTLS_CALL_CLOSING,
            memory_order_acq_rel)
        | NINLIL_R7_MBEDTLS_CALL_CLOSING);
    if ((observed & NINLIL_R7_MBEDTLS_CALL_CONFLICT) != 0u) {
        (void)ninlil_wifi_esp_tls_allocator_owner_enter(owner->owner);
        conflict_fenced = 1;
    }
    leave_status =
        ninlil_wifi_esp_tls_allocator_owner_leave_checked(owner->owner);
    /*
     * Keep CALL_ACTIVE set until every racing entry either marks CONFLICT or
     * observes zero and becomes the next valid call.  A late conflict after
     * allocator leave is converted to a wrong-leave fatal fence by the sole
     * active callback; failed callers never touch allocator state.
     */
    observed = atomic_load_explicit(
        &owner->call_state, memory_order_acquire);
    for (;;) {
        unsigned char expected;
        if ((observed & NINLIL_R7_MBEDTLS_CALL_CONFLICT) != 0u
            && conflict_fenced == 0) {
            (void)ninlil_wifi_esp_tls_allocator_owner_leave_checked(
                owner->owner);
            conflict_fenced = 1;
        }
        expected = observed;
        if (atomic_compare_exchange_weak_explicit(
                &owner->call_state,
                &expected,
                0u,
                memory_order_release,
                memory_order_acquire)) {
            break;
        }
        observed = expected;
    }
    return leave_status == NINLIL_WIFI_OK
            && conflict_fenced == 0
        ? raw_status
        : NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
}
#endif

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_sha256(
    void *ctx,
    const uint8_t *msg,
    size_t msg_len,
    uint8_t out_digest[NINLIL_R7_CRYPTO_SHA256_LEN])
{
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    ninlil_r7_crypto_raw_status status;
    if (!ninlil_r7_mbedtls_owner_begin(ctx)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    status = ninlil_r7_mbedtls_sha256_raw(
        NULL, msg, msg_len, out_digest);
    return ninlil_r7_mbedtls_owner_finish(ctx, status);
#else
    return ninlil_r7_mbedtls_sha256_raw(
        ctx, msg, msg_len, out_digest);
#endif
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_hkdf_extract_sha256(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN])
{
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    ninlil_r7_crypto_raw_status status;
    if (!ninlil_r7_mbedtls_owner_begin(ctx)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    status = ninlil_r7_mbedtls_hkdf_extract_sha256_raw(
        NULL, salt, salt_len, ikm, ikm_len, out_prk);
    return ninlil_r7_mbedtls_owner_finish(ctx, status);
#else
    return ninlil_r7_mbedtls_hkdf_extract_sha256_raw(
        ctx, salt, salt_len, ikm, ikm_len, out_prk);
#endif
}

static ninlil_r7_crypto_raw_status ninlil_r7_mbedtls_hkdf_expand_sha256(
    void *ctx,
    const uint8_t prk[NINLIL_R7_CRYPTO_HKDF_PRK_LEN],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len)
{
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    ninlil_r7_crypto_raw_status status;
    if (!ninlil_r7_mbedtls_owner_begin(ctx)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    status = ninlil_r7_mbedtls_hkdf_expand_sha256_raw(
        NULL, prk, info, info_len, out_okm, okm_len);
    return ninlil_r7_mbedtls_owner_finish(ctx, status);
#else
    return ninlil_r7_mbedtls_hkdf_expand_sha256_raw(
        ctx, prk, info, info_len, out_okm, okm_len);
#endif
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
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    ninlil_r7_crypto_raw_status status;
    if (!ninlil_r7_mbedtls_owner_begin(ctx)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    status = ninlil_r7_mbedtls_aes128_gcm_seal_raw(
        NULL,
        key,
        nonce,
        aad,
        aad_len,
        plaintext,
        plaintext_len,
        out_sealed,
        out_capacity,
        produced_len);
    return ninlil_r7_mbedtls_owner_finish(ctx, status);
#else
    return ninlil_r7_mbedtls_aes128_gcm_seal_raw(
        ctx,
        key,
        nonce,
        aad,
        aad_len,
        plaintext,
        plaintext_len,
        out_sealed,
        out_capacity,
        produced_len);
#endif
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
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    ninlil_r7_crypto_raw_status status;
    if (!ninlil_r7_mbedtls_owner_begin(ctx)) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    status = ninlil_r7_mbedtls_aes128_gcm_open_raw(
        NULL,
        key,
        nonce,
        aad,
        aad_len,
        sealed,
        sealed_len,
        out_plaintext,
        out_capacity,
        produced_len);
    return ninlil_r7_mbedtls_owner_finish(ctx, status);
#else
    return ninlil_r7_mbedtls_aes128_gcm_open_raw(
        ctx,
        key,
        nonce,
        aad,
        aad_len,
        sealed,
        sealed_len,
        out_plaintext,
        out_capacity,
        produced_len);
#endif
}

NINLIL_ESP_IDF_INTERNAL ninlil_r7_crypto_status
ninlil_r7_crypto_mbedtls_provider_init(ninlil_r7_crypto_provider *out_provider)
{
    /* Zero all bytes first so padding cannot leak into *out_provider. */
    ninlil_r7_crypto_provider candidate = {0};
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    ninlil_wifi_status_t allocator_status;
    uint32_t owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    int registered_now = 0;
#endif

    if (out_provider == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }

#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    /*
     * Bootstrap is deliberately before provider validation/publication and
     * before every mbedTLS call reachable from this factory.
     */
    allocator_status = ninlil_wifi_esp_tls_allocator_bootstrap();
    if (allocator_status != NINLIL_WIFI_OK) {
        return allocator_status == NINLIL_WIFI_CAPACITY
                || allocator_status == NINLIL_WIFI_UNAVAILABLE
            ? NINLIL_R7_CRYPTO_CAPACITY
            : NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }
    /*
     * The co-tenant adapter is an explicit singleton.  Publishing a second
     * provider that aliases the same owner would let one close invalidate the
     * other, so duplicate factory calls fail without mutating the caller.
     */
    if (s_r7_owner.active != 0u) {
        return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }
    allocator_status = ninlil_wifi_esp_tls_allocator_other_register(
        NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1,
        NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET,
        &owner);
    if (allocator_status != NINLIL_WIFI_OK) {
        return allocator_status == NINLIL_WIFI_CAPACITY
                || allocator_status == NINLIL_WIFI_UNAVAILABLE
            ? NINLIL_R7_CRYPTO_CAPACITY
            : NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }
    s_r7_owner.owner = owner;
    s_r7_owner.active = 1u;
    atomic_store_explicit(
        &s_r7_owner.call_state, 0u, memory_order_release);
    registered_now = 1;
#endif

    candidate.abi_version = NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION;
    candidate.struct_size = (uint32_t)sizeof(candidate);
    candidate.reserved_zero = 0u;
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    candidate.ctx = &s_r7_owner;
#else
    candidate.ctx = NULL;
#endif
    candidate.sha256 = ninlil_r7_mbedtls_sha256;
    candidate.hkdf_extract_sha256 = ninlil_r7_mbedtls_hkdf_extract_sha256;
    candidate.hkdf_expand_sha256 = ninlil_r7_mbedtls_hkdf_expand_sha256;
    candidate.aes128_gcm_seal = ninlil_r7_mbedtls_aes128_gcm_seal;
    candidate.aes128_gcm_open = ninlil_r7_mbedtls_aes128_gcm_open;

    if (ninlil_r7_crypto_provider_validate(&candidate) != NINLIL_R7_CRYPTO_OK) {
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
        if (registered_now != 0) {
            (void)ninlil_wifi_esp_tls_allocator_other_release(
                s_r7_owner.owner);
            s_r7_owner.owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
            s_r7_owner.active = 0u;
            atomic_store_explicit(
                &s_r7_owner.call_state, 0u, memory_order_release);
        }
#endif
        return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
    }

    *out_provider = candidate;
    return NINLIL_R7_CRYPTO_OK;
}

NINLIL_ESP_IDF_INTERNAL ninlil_r7_crypto_status
ninlil_r7_crypto_mbedtls_provider_close(
    ninlil_r7_crypto_provider *provider)
{
    if (provider == NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
    if (ninlil_r7_crypto_provider_validate(provider)
            != NINLIL_R7_CRYPTO_OK
        || provider->sha256 != ninlil_r7_mbedtls_sha256
        || provider->hkdf_extract_sha256
            != ninlil_r7_mbedtls_hkdf_extract_sha256
        || provider->hkdf_expand_sha256
            != ninlil_r7_mbedtls_hkdf_expand_sha256
        || provider->aes128_gcm_seal
            != ninlil_r7_mbedtls_aes128_gcm_seal
        || provider->aes128_gcm_open
            != ninlil_r7_mbedtls_aes128_gcm_open) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
#if defined(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    {
        ninlil_wifi_esp_tls_allocator_snapshot_t snapshot;
        if (provider->ctx != &s_r7_owner || s_r7_owner.active == 0u
            || atomic_load_explicit(
                   &s_r7_owner.call_state, memory_order_acquire)
                != 0u
            || ninlil_wifi_esp_tls_allocator_other_snapshot(
                   NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1,
                   &snapshot)
                != NINLIL_WIFI_OK) {
            return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
        }
        if (snapshot.current_bytes != 0u
            || snapshot.outstanding_allocations != 0u) {
            (void)ninlil_wifi_esp_tls_allocator_other_release(
                s_r7_owner.owner);
            return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
        }
        if (ninlil_wifi_esp_tls_allocator_other_release(
                s_r7_owner.owner)
            != NINLIL_WIFI_OK) {
            return NINLIL_R7_CRYPTO_INTERNAL_CONTRACT;
        }
        s_r7_owner.owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
        s_r7_owner.active = 0u;
        atomic_store_explicit(
            &s_r7_owner.call_state, 0u, memory_order_release);
        s_r7_owner.reserved[0] = 0u;
        s_r7_owner.reserved[1] = 0u;
    }
#else
    if (provider->ctx != NULL) {
        return NINLIL_R7_CRYPTO_INVALID_ARGUMENT;
    }
#endif
    ninlil_r7_mbedtls_zeroize(provider, sizeof(*provider));
    return NINLIL_R7_CRYPTO_OK;
}

#undef NINLIL_R7_MBEDTLS_CALL_ACTIVE
#undef NINLIL_R7_MBEDTLS_CALL_CONFLICT
#undef NINLIL_R7_MBEDTLS_CALL_CLOSING
