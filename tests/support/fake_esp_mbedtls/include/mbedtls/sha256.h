/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_MBEDTLS_SHA256_H
#define NINLIL_TEST_FAKE_MBEDTLS_SHA256_H

#include <stddef.h>

typedef struct mbedtls_sha256_context {
    unsigned char opaque[108];
} mbedtls_sha256_context;

void mbedtls_sha256_init(mbedtls_sha256_context *ctx);
void mbedtls_sha256_free(mbedtls_sha256_context *ctx);
int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224);
int mbedtls_sha256_update(
    mbedtls_sha256_context *ctx,
    const unsigned char *input,
    size_t length);
int mbedtls_sha256_finish(
    mbedtls_sha256_context *ctx,
    unsigned char output[32]);
int mbedtls_sha256(
    const unsigned char *input,
    size_t length,
    unsigned char output[32],
    int is224);

#endif
