/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_RESOURCE_POLICY_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_RESOURCE_POLICY_H

/* ADR-0018 §14.1.1 exact ESP32-S3 target-software-candidate envelope. */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET 98304u
#define NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET 12288u
#define NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET 86016u
#define NINLIL_WIFI_ESP_TLS_SESSION_POOL_BUDGET 196608u
#define NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET 65536u
#define NINLIL_WIFI_ESP_TLS_TOTAL_ALLOCATION_BUDGET 262144u
#define NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP 65536u
#define NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES 327680u
#define NINLIL_WIFI_ESP_TLS_EXECUTION_STACK_BYTES 8192u
#define NINLIL_WIFI_ESP_TLS_CRYPTO_DMA_BYTES 0u
#define NINLIL_WIFI_ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE 163840u
#define NINLIL_WIFI_ESP_TLS_MAP_REMAINDER_OBSERVATION 171825u
#define NINLIL_WIFI_ESP_TLS_MAP_OBSERVATION_SLACK 7985u
#define NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES 16685u
#define NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES 4415u
#define NINLIL_WIFI_ESP_TLS_MAX_SESSIONS 2u

/*
 * ADR-0026 Proposed Wi-Fi + Accepted-R7-raw composition amendment.
 *
 * These constants do not replace the ADR-0018 Accepted/candidate values above.
 * The 304-byte R7 owner is a separately identified OTHER_REGISTERED
 * reservation whose exact target layout is proved by the ESP closure gate.
 */
#define NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET 304u
#define NINLIL_WIFI_ESP_TLS_OTHER_REGISTERED_POOL_BUDGET 304u
#define NINLIL_WIFI_ESP_TLS_WIFI_R7_COMPOSITION_TOTAL_BUDGET 262448u
#define NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ENVELOPE 164144u
#define NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ONLY_REQUIREMENT_BYTES 327984u

typedef struct ninlil_wifi_tls_resource_view {
    size_t internal_free_bytes;
    size_t internal_largest_free_block_bytes;
    size_t psram_free_bytes;
    size_t psram_largest_free_block_bytes;
    uint32_t active_sessions;
    uint8_t psram_enabled;
} ninlil_wifi_tls_resource_view_t;

typedef enum ninlil_wifi_tls_admission_result {
    NINLIL_WIFI_TLS_ADMISSION_OK = 0,
    NINLIL_WIFI_TLS_ADMISSION_SESSION_CAPACITY = 1,
    NINLIL_WIFI_TLS_ADMISSION_PSRAM_DISABLED = 2,
    NINLIL_WIFI_TLS_ADMISSION_INTERNAL_FREE = 3,
    NINLIL_WIFI_TLS_ADMISSION_INTERNAL_FRAGMENTED = 4,
    NINLIL_WIFI_TLS_ADMISSION_PSRAM_FREE = 5,
    NINLIL_WIFI_TLS_ADMISSION_PSRAM_FRAGMENTED = 6
} ninlil_wifi_tls_admission_result_t;

ninlil_wifi_tls_admission_result_t ninlil_wifi_tls_resource_admit(
    const ninlil_wifi_tls_resource_view_t *view);

typedef enum ninlil_wifi_tls_allocation_tier {
    NINLIL_WIFI_TLS_ALLOCATION_INTERNAL = 0,
    NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO = 1,
    NINLIL_WIFI_TLS_ALLOCATION_REJECT = 2
} ninlil_wifi_tls_allocation_tier_t;

typedef struct ninlil_wifi_tls_io_classifier {
    uint8_t active;
    uint8_t inbound_count;
    uint8_t outbound_count;
    uint8_t violation;
} ninlil_wifi_tls_io_classifier_t;

int ninlil_wifi_tls_io_classifier_begin(
    ninlil_wifi_tls_io_classifier_t *classifier);

ninlil_wifi_tls_allocation_tier_t ninlil_wifi_tls_io_classifier_route(
    ninlil_wifi_tls_io_classifier_t *classifier,
    size_t requested_bytes);

/*
 * Always leaves the scope when it was active.  Returns true only for exactly
 * one pinned inbound and one pinned outbound allocation and no violation.
 */
int ninlil_wifi_tls_io_classifier_finish(
    ninlil_wifi_tls_io_classifier_t *classifier);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_RESOURCE_POLICY_H */
