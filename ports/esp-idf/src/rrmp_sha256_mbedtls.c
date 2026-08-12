/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ESP-IDF mbedTLS adapter for the private RRMP SHA-256 contract.
 */
#include "rrmp_sha256_provider.h"

#include "mbedtls/sha256.h"

int ninlil_rrmp_sha256_provider(
    const uint8_t *bytes, size_t length, uint8_t out[32])
{
    size_t i;
    if (bytes != NULL && out != NULL
        && mbedtls_sha256(bytes, length, out, 0) == 0) {
        return 1;
    }
    if (out != NULL) {
        for (i = 0u; i < 32u; ++i) {
            out[i] = 0u;
        }
    }
    return 0;
}
