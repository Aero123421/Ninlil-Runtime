/*
 * Host OpenSSL SHA-256 backend for private wifi_v1.
 * Compiled only on Host (not ESP_PLATFORM).
 */
#include "wifi_sha256.h"

#if !defined(ESP_PLATFORM)

#include <openssl/sha.h>

#include <string.h>

void ninlil_wifi_sha256(
    const uint8_t *data,
    size_t length,
    uint8_t out[32])
{
    if (out == NULL) {
        return;
    }
    if (data == NULL || length == 0u) {
        (void)memset(out, 0, 32u);
        if (data == NULL) {
            return;
        }
    }
    (void)SHA256(data, length, out);
}

#endif /* !ESP_PLATFORM */
