/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_MBEDTLS_GCM_H
#define NINLIL_TEST_FAKE_MBEDTLS_GCM_H

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_CIPHER_ID_AES 2
#define MBEDTLS_GCM_ENCRYPT 1
#define MBEDTLS_ERR_GCM_AUTH_FAILED (-0x0012)

typedef struct mbedtls_gcm_context {
    uint8_t key[16];
    uint8_t keyed;
    void *cipher_context;
} mbedtls_gcm_context;

void mbedtls_gcm_init(mbedtls_gcm_context *ctx);
void mbedtls_gcm_free(mbedtls_gcm_context *ctx);
int mbedtls_gcm_setkey(
    mbedtls_gcm_context *ctx,
    int cipher,
    const unsigned char *key,
    unsigned int keybits);
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
    unsigned char *tag);
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
    unsigned char *output);

#endif
