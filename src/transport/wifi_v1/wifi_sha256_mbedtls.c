/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ESP mbedTLS SHA-256 backend for private wifi_v1.
 * Compiled only under ESP_PLATFORM (no OpenSSL).
 */
#include "wifi_sha256.h"

#if defined(ESP_PLATFORM)

#include "mbedtls/sha256.h"

#include <string.h>

void ninlil_wifi_sha256(
    const uint8_t *data,
    size_t length,
    uint8_t out[32])
{
    if (out == NULL) {
        return;
    }
    if (data == NULL) {
        (void)memset(out, 0, 32u);
        return;
    }
    /* is224 = 0 → SHA-256 */
    (void)mbedtls_sha256(data, length, out, 0);
}

#endif /* ESP_PLATFORM */
