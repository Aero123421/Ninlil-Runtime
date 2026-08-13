/* SPDX-License-Identifier: Apache-2.0 */
#if defined(ESP_PLATFORM)

/*
 * Build-only authority for the pinned ESP-IDF mbedTLS record-buffer sizes.
 *
 * ssl_misc.h is an mbedTLS private header and must not leak into the runtime
 * adapter.  This isolated translation unit opts into private access solely to
 * compile the two exact size assertions against the target SDK/configuration.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "ssl_misc.h"

#include "wifi_tls_resource_policy.h"

#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include <stddef.h>
#include <stdint.h>

#if defined(MBEDTLS_BLOCK_CIPHER_C)
#error "R7 exact GCM closure requires the measured legacy cipher allocation"
#endif
#if defined(MBEDTLS_MD_SHA256_VIA_PSA)
#error "R7 exact HKDF closure requires the legacy SHA-256 md allocation"
#endif

#define NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(request_bytes) \
    ((16u + (request_bytes) + 4u + 7u) & ~(size_t)7u)

_Static_assert(
    MBEDTLS_SSL_IN_BUFFER_LEN == NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES,
    "pinned ESP mbedTLS inbound buffer size drift");
_Static_assert(
    MBEDTLS_SSL_OUT_BUFFER_LEN == NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES,
    "pinned ESP mbedTLS outbound buffer size drift");
_Static_assert(sizeof(max_align_t) == 16u, "pinned Xtensa max_align_t size");
_Static_assert(
    _Alignof(max_align_t) == 8u, "pinned Xtensa max_align_t alignment");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(sizeof(mbedtls_sha256_context))
        == 128u,
    "pinned R7 SHA-256 arena charge");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(128u) == 152u,
    "pinned R7 HMAC arena charge");
_Static_assert(
    sizeof(mbedtls_aes_context) == 280u,
    "pinned R7 legacy AES context request");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(sizeof(mbedtls_aes_context))
        == NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET,
    "pinned R7 GCM arena charge");

/*
 * Target-nm proof arrays.  Their symbol sizes are the measured target values;
 * the HIL application retains each array with a volatile read.  They are
 * const/flash data and are not counted as runtime allocator reservations.
 */
const uint8_t ninlil_wifi_esp_tls_target_max_align_size_probe
    [sizeof(max_align_t)] = {0};
const uint8_t ninlil_wifi_esp_tls_target_max_align_alignment_probe
    [_Alignof(max_align_t)] = {0};
const uint8_t ninlil_wifi_esp_tls_target_r7_sha_context_size_probe
    [sizeof(mbedtls_sha256_context)] = {0};
const uint8_t ninlil_wifi_esp_tls_target_r7_sha_charge_probe
    [NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(sizeof(mbedtls_sha256_context))] = {0};
const uint8_t ninlil_wifi_esp_tls_target_r7_hmac_charge_probe
    [NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(128u)] = {0};
const uint8_t ninlil_wifi_esp_tls_target_r7_aes_context_size_probe
    [sizeof(mbedtls_aes_context)] = {0};
const uint8_t ninlil_wifi_esp_tls_target_r7_gcm_charge_probe
    [NINLIL_WIFI_ESP_TLS_ARENA_CHARGE(sizeof(mbedtls_aes_context))] = {0};
const uint8_t ninlil_wifi_esp_tls_target_r7_reservation_probe
    [NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET] = {0};

size_t ninlil_wifi_esp_tls_target_in_buffer_bytes(void)
{
    return MBEDTLS_SSL_IN_BUFFER_LEN;
}

size_t ninlil_wifi_esp_tls_target_out_buffer_bytes(void)
{
    return MBEDTLS_SSL_OUT_BUFFER_LEN;
}

#undef NINLIL_WIFI_ESP_TLS_ARENA_CHARGE

#endif
