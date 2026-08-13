/* SPDX-License-Identifier: Apache-2.0 */
#include "fake_esp_mbedtls.h"

#include "esp_heap_caps.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FAKE_HEAP_RECORDS 16u
#define FAKE_HEAP_FREE_BYTES ((size_t)UINT32_C(0x40000000))

typedef struct fake_heap_record {
    void *pointer;
    size_t bytes;
    uint32_t caps;
} fake_heap_record_t;

static struct {
    void *(*calloc_func)(size_t, size_t);
    void (*free_func)(void *);
    fake_heap_record_t heap[FAKE_HEAP_RECORDS];
    ninlil_test_fake_esp_mbedtls_snapshot_t snapshot;
    ninlil_test_fake_esp_mbedtls_reentry_fn reentry;
    void *reentry_user;
} s_fake;

static void note_crypto_call(void)
{
    s_fake.snapshot.crypto_calls += 1u;
    if (s_fake.calloc_func == NULL || s_fake.free_func == NULL) {
        s_fake.snapshot.crypto_before_allocator += 1u;
    }
}

static uint8_t fold_bytes(const unsigned char *bytes, size_t length)
{
    uint8_t value = 0u;
    size_t index;
    for (index = 0u; index < length; ++index) {
        value = (uint8_t)(value ^ bytes[index] ^ (uint8_t)index);
    }
    return value;
}

void ninlil_test_fake_esp_mbedtls_reset(void)
{
    uint32_t index;
    for (index = 0u; index < FAKE_HEAP_RECORDS; ++index) {
        free(s_fake.heap[index].pointer);
    }
    (void)memset(&s_fake, 0, sizeof(s_fake));
}

ninlil_test_fake_esp_mbedtls_snapshot_t
ninlil_test_fake_esp_mbedtls_snapshot(void)
{
    return s_fake.snapshot;
}

void ninlil_test_fake_esp_mbedtls_set_reentry(
    ninlil_test_fake_esp_mbedtls_reentry_fn function,
    void *user)
{
    s_fake.reentry = function;
    s_fake.reentry_user = user;
}

void *heap_caps_calloc(size_t count, size_t size, uint32_t caps)
{
    void *result;
    uint32_t index;
    if (count != 0u && size > SIZE_MAX / count) {
        return NULL;
    }
    result = calloc(count, size);
    if (result == NULL) {
        return NULL;
    }
    for (index = 0u; index < FAKE_HEAP_RECORDS; ++index) {
        if (s_fake.heap[index].pointer == NULL) {
            s_fake.heap[index].pointer = result;
            s_fake.heap[index].bytes = count * size;
            s_fake.heap[index].caps = caps;
            s_fake.snapshot.raw_heap_allocations += 1u;
            s_fake.snapshot.raw_heap_outstanding += 1u;
            return result;
        }
    }
    free(result);
    return NULL;
}

void heap_caps_free(void *pointer)
{
    uint32_t index;
    if (pointer == NULL) {
        return;
    }
    for (index = 0u; index < FAKE_HEAP_RECORDS; ++index) {
        if (s_fake.heap[index].pointer == pointer) {
            free(pointer);
            (void)memset(&s_fake.heap[index], 0, sizeof(s_fake.heap[index]));
            if (s_fake.snapshot.raw_heap_outstanding != 0u) {
                s_fake.snapshot.raw_heap_outstanding -= 1u;
            }
            return;
        }
    }
}

size_t heap_caps_get_free_size(uint32_t caps)
{
    (void)caps;
    return FAKE_HEAP_FREE_BYTES;
}

size_t heap_caps_get_largest_free_block(uint32_t caps)
{
    (void)caps;
    return FAKE_HEAP_FREE_BYTES;
}

int esp_ptr_internal(const void *pointer)
{
    uint32_t index;
    for (index = 0u; index < FAKE_HEAP_RECORDS; ++index) {
        if (s_fake.heap[index].pointer == pointer) {
            return (s_fake.heap[index].caps & MALLOC_CAP_INTERNAL) != 0u;
        }
    }
    return 0;
}

int esp_ptr_external_ram(const void *pointer)
{
    uint32_t index;
    for (index = 0u; index < FAKE_HEAP_RECORDS; ++index) {
        if (s_fake.heap[index].pointer == pointer) {
            return (s_fake.heap[index].caps & MALLOC_CAP_SPIRAM) != 0u;
        }
    }
    return 0;
}

int esp_psram_is_initialized(void)
{
    return 1;
}

int mbedtls_platform_set_calloc_free(
    void *(*calloc_func)(size_t, size_t),
    void (*free_func)(void *))
{
    if (calloc_func == NULL || free_func == NULL
        || s_fake.calloc_func != NULL || s_fake.free_func != NULL) {
        return -1;
    }
    s_fake.calloc_func = calloc_func;
    s_fake.free_func = free_func;
    s_fake.snapshot.allocator_install_calls += 1u;
    return 0;
}

void mbedtls_platform_zeroize(void *pointer, size_t bytes)
{
    volatile uint8_t *cursor = (volatile uint8_t *)pointer;
    while (cursor != NULL && bytes != 0u) {
        *cursor++ = 0u;
        bytes -= 1u;
    }
}

static const mbedtls_md_info_t s_sha256_info = {32u, 64u};

const mbedtls_md_info_t *mbedtls_md_info_from_type(int type)
{
    note_crypto_call();
    return type == MBEDTLS_MD_SHA256 ? &s_sha256_info : NULL;
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    note_crypto_call();
    if (ctx != NULL) {
        (void)memset(ctx, 0, sizeof(*ctx));
    }
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    note_crypto_call();
    if (ctx != NULL) {
        mbedtls_platform_zeroize(ctx, sizeof(*ctx));
    }
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    note_crypto_call();
    if (ctx == NULL || is224 != 0) {
        return -1;
    }
    ctx->opaque[0] = UINT8_C(0x5a);
    return 0;
}

int mbedtls_sha256_update(
    mbedtls_sha256_context *ctx,
    const unsigned char *input,
    size_t length)
{
    note_crypto_call();
    if (ctx == NULL || (length != 0u && input == NULL)) {
        return -1;
    }
    ctx->opaque[1] ^= fold_bytes(input, length);
    return 0;
}

int mbedtls_sha256_finish(
    mbedtls_sha256_context *ctx,
    unsigned char output[32])
{
    size_t index;
    note_crypto_call();
    if (ctx == NULL || output == NULL) {
        return -1;
    }
    for (index = 0u; index < 32u; ++index) {
        output[index] =
            (uint8_t)(ctx->opaque[0] ^ ctx->opaque[1] ^ (uint8_t)index);
    }
    return 0;
}

int mbedtls_sha256(
    const unsigned char *input,
    size_t length,
    unsigned char output[32],
    int is224)
{
    mbedtls_sha256_context context;
    if (output == NULL || (length != 0u && input == NULL)) {
        return -1;
    }
    mbedtls_sha256_init(&context);
    if (mbedtls_sha256_starts(&context, is224) != 0
        || mbedtls_sha256_update(&context, input, length) != 0
        || mbedtls_sha256_finish(&context, output) != 0) {
        mbedtls_sha256_free(&context);
        return -1;
    }
    mbedtls_sha256_free(&context);
    return 0;
}

static int fake_hmac_alloc_pair(void **first, void **second)
{
    *first = NULL;
    *second = NULL;
    if (s_fake.calloc_func == NULL || s_fake.free_func == NULL) {
        return -1;
    }
    /*
     * Host fault tests exercise the exact production owner code, while target
     * ABI request sizes are independently compile-gated.  These Host sizes
     * fit the target reservation despite the wider Host max_align_t.
     */
    *first = s_fake.calloc_func(1u, 64u);
    if (*first == NULL) {
        return -1;
    }
    *second = s_fake.calloc_func(1u, 96u);
    if (*second == NULL) {
        s_fake.free_func(*first);
        *first = NULL;
        return -1;
    }
    return 0;
}

int mbedtls_hkdf_extract(
    const mbedtls_md_info_t *md,
    const unsigned char *salt,
    size_t salt_len,
    const unsigned char *ikm,
    size_t ikm_len,
    unsigned char *prk)
{
    void *first;
    void *second;
    ninlil_test_fake_esp_mbedtls_reentry_fn reentry;
    void *reentry_user;
    size_t index;
    uint8_t folded;
    note_crypto_call();
    reentry = s_fake.reentry;
    reentry_user = s_fake.reentry_user;
    s_fake.reentry = NULL;
    s_fake.reentry_user = NULL;
    if (reentry != NULL) {
        reentry(reentry_user);
    }
    if (md != &s_sha256_info || prk == NULL
        || (salt_len != 0u && salt == NULL)
        || (ikm_len != 0u && ikm == NULL)
        || fake_hmac_alloc_pair(&first, &second) != 0) {
        return -1;
    }
    folded = (uint8_t)(fold_bytes(salt, salt_len)
        ^ fold_bytes(ikm, ikm_len));
    for (index = 0u; index < 32u; ++index) {
        prk[index] = (uint8_t)(folded ^ (uint8_t)index);
    }
    s_fake.free_func(second);
    s_fake.free_func(first);
    return 0;
}

int mbedtls_hkdf_expand(
    const mbedtls_md_info_t *md,
    const unsigned char *prk,
    size_t prk_len,
    const unsigned char *info,
    size_t info_len,
    unsigned char *okm,
    size_t okm_len)
{
    void *first;
    void *second;
    size_t index;
    uint8_t folded;
    note_crypto_call();
    if (md != &s_sha256_info || prk == NULL || prk_len < 32u
        || okm == NULL || (info_len != 0u && info == NULL)
        || fake_hmac_alloc_pair(&first, &second) != 0) {
        return -1;
    }
    folded = (uint8_t)(fold_bytes(prk, prk_len)
        ^ fold_bytes(info, info_len));
    for (index = 0u; index < okm_len; ++index) {
        okm[index] = (uint8_t)(folded ^ (uint8_t)index);
    }
    s_fake.free_func(second);
    s_fake.free_func(first);
    return 0;
}

int mbedtls_hkdf(
    const mbedtls_md_info_t *md,
    const unsigned char *salt,
    size_t salt_len,
    const unsigned char *ikm,
    size_t ikm_len,
    const unsigned char *info,
    size_t info_len,
    unsigned char *okm,
    size_t okm_len)
{
    unsigned char prk[32];
    int result;
    note_crypto_call();
    result = mbedtls_hkdf_extract(
        md, salt, salt_len, ikm, ikm_len, prk);
    if (result == 0) {
        result = mbedtls_hkdf_expand(
            md, prk, sizeof(prk), info, info_len, okm, okm_len);
    }
    mbedtls_platform_zeroize(prk, sizeof(prk));
    return result;
}

void mbedtls_gcm_init(mbedtls_gcm_context *ctx)
{
    note_crypto_call();
    if (ctx != NULL) {
        (void)memset(ctx, 0, sizeof(*ctx));
    }
}

void mbedtls_gcm_free(mbedtls_gcm_context *ctx)
{
    note_crypto_call();
    if (ctx != NULL) {
        if (ctx->cipher_context != NULL && s_fake.free_func != NULL) {
            s_fake.free_func(ctx->cipher_context);
            ctx->cipher_context = NULL;
        }
        mbedtls_platform_zeroize(ctx, sizeof(*ctx));
    }
}

int mbedtls_gcm_setkey(
    mbedtls_gcm_context *ctx,
    int cipher,
    const unsigned char *key,
    unsigned int keybits)
{
    note_crypto_call();
    if (ctx == NULL || key == NULL || cipher != MBEDTLS_CIPHER_ID_AES
        || keybits != 128u || s_fake.calloc_func == NULL
        || s_fake.free_func == NULL) {
        return -1;
    }
    if (ctx->cipher_context != NULL) {
        s_fake.free_func(ctx->cipher_context);
        ctx->cipher_context = NULL;
    }
    /*
     * Production requests sizeof(mbedtls_aes_context), target-probed
     * separately.  The Host request is smaller so the wider Host arena header
     * still fits the same 304-byte reservation while exercising the exact
     * owner allocation/free path.
     */
    ctx->cipher_context = s_fake.calloc_func(1u, 240u);
    if (ctx->cipher_context == NULL) {
        return -1;
    }
    (void)memcpy(ctx->key, key, sizeof(ctx->key));
    ctx->keyed = 1u;
    return 0;
}

static void fake_gcm_tag(
    const mbedtls_gcm_context *ctx,
    const unsigned char *iv,
    size_t iv_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *body,
    size_t body_len,
    unsigned char *tag,
    size_t tag_len)
{
    size_t index;
    uint8_t folded = (uint8_t)(fold_bytes(ctx->key, sizeof(ctx->key))
        ^ fold_bytes(iv, iv_len) ^ fold_bytes(aad, aad_len)
        ^ fold_bytes(body, body_len));
    for (index = 0u; index < tag_len; ++index) {
        tag[index] = (uint8_t)(folded ^ (uint8_t)index);
    }
}

int mbedtls_gcm_crypt_and_tag(
    mbedtls_gcm_context *ctx,
    int mode,
    size_t length,
    const unsigned char *iv,
    size_t iv_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *input,
    unsigned char *output,
    size_t tag_len,
    unsigned char *tag)
{
    size_t index;
    note_crypto_call();
    if (ctx == NULL || ctx->keyed == 0u || mode != MBEDTLS_GCM_ENCRYPT
        || iv == NULL || tag == NULL || tag_len != 16u
        || (aad_len != 0u && aad == NULL)
        || (length != 0u && (input == NULL || output == NULL))) {
        return -1;
    }
    for (index = 0u; index < length; ++index) {
        output[index] = (uint8_t)(input[index] ^ ctx->key[index % 16u]);
    }
    fake_gcm_tag(ctx, iv, iv_len, aad, aad_len, output, length, tag, tag_len);
    return 0;
}

int mbedtls_gcm_auth_decrypt(
    mbedtls_gcm_context *ctx,
    size_t length,
    const unsigned char *iv,
    size_t iv_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *tag,
    size_t tag_len,
    const unsigned char *input,
    unsigned char *output)
{
    unsigned char expected[16];
    size_t index;
    note_crypto_call();
    if (ctx == NULL || ctx->keyed == 0u || iv == NULL || tag == NULL
        || tag_len != sizeof(expected) || (aad_len != 0u && aad == NULL)
        || (length != 0u && (input == NULL || output == NULL))) {
        return -1;
    }
    fake_gcm_tag(
        ctx, iv, iv_len, aad, aad_len, input, length, expected,
        sizeof(expected));
    if (memcmp(expected, tag, sizeof(expected)) != 0) {
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    for (index = 0u; index < length; ++index) {
        output[index] = (uint8_t)(input[index] ^ ctx->key[index % 16u]);
    }
    return 0;
}

void mbedtls_ecp_group_init(mbedtls_ecp_group *group)
{
    note_crypto_call();
    if (group != NULL) {
        group->active = 0u;
    }
}

void mbedtls_ecp_group_free(mbedtls_ecp_group *group)
{
    note_crypto_call();
    if (group != NULL) {
        group->active = 0u;
    }
}

int mbedtls_ecp_group_load(mbedtls_ecp_group *group, int id)
{
    note_crypto_call();
    if (group == NULL || id != MBEDTLS_ECP_DP_SECP256R1) {
        return -1;
    }
    group->active = 1u;
    return 0;
}

void mbedtls_x509_crt_init(mbedtls_x509_crt *certificate)
{
    note_crypto_call();
    if (certificate != NULL) {
        certificate->active = 1u;
    }
}

void mbedtls_x509_crt_free(mbedtls_x509_crt *certificate)
{
    note_crypto_call();
    if (certificate != NULL) {
        certificate->active = 0u;
    }
}
