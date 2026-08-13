/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_SHA256_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_SHA256_H

/*
 * Portable SHA-256 provider for private wifi_v1.
 * Host: OpenSSL (exact TLS profile companion).
 * ESP:  mbedTLS (no OpenSSL headers on target).
 * Call sites must not include openssl/sha.h or mbedtls/sha256.h directly.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* out[32] = SHA-256(data[0..length)). Always succeeds for valid non-null args. */
void ninlil_wifi_sha256(
    const uint8_t *data,
    size_t length,
    uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_SHA256_H */
