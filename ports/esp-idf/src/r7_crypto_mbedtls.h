#ifndef NINLIL_R7_CRYPTO_MBEDTLS_H
#define NINLIL_R7_CRYPTO_MBEDTLS_H

/*
 * R7 private ESP-IDF crypto adapter for supplied mbedTLS (ESP-IDF v5.5.3).
 *
 * Production-private under ports/esp-idf/src/. Not public ABI. Not installed.
 * Exposes no mbedTLS types. All symbols use ninlil_r7_ prefix.
 *
 * SEMANTIC: R7_CRYPTO_PRIVATE_ONLY
 * SEMANTIC: R7_PROVIDER_ABI_EXACT_V1
 * SEMANTIC: HOST_OPENSSL3_ESP_MBEDTLS_SPLIT
 * SEMANTIC: NO_PRODUCTION_HAND_WRITTEN_AES_GHASH
 */

#include "ninlil_esp_idf_internal.h"
#include "r7_crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize an exact provider ABI v1 value backed by ESP-IDF supplied mbedTLS.
 *
 * Success publishes the whole provider to *out_provider. Failure leaves
 * *out_provider byte-unchanged. NULL is INVALID_ARGUMENT.
 *
 * Private binary symbol: NINLIL_ESP_IDF_INTERNAL (not public / not installed).
 */
NINLIL_ESP_IDF_INTERNAL ninlil_r7_crypto_status
ninlil_r7_crypto_mbedtls_provider_init(ninlil_r7_crypto_provider *out_provider);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_CRYPTO_MBEDTLS_H */
