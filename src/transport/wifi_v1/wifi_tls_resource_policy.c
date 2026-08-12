/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_tls_resource_policy.h"

_Static_assert(
    NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET
            + NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET
        == NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET,
    "ESP TLS tier sum");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_MAX_SESSIONS
            * NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET
        == NINLIL_WIFI_ESP_TLS_SESSION_POOL_BUDGET,
    "ESP TLS session pool");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_SESSION_POOL_BUDGET
            + NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET
        == NINLIL_WIFI_ESP_TLS_TOTAL_ALLOCATION_BUDGET,
    "ESP TLS total allocation");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_TOTAL_ALLOCATION_BUDGET
            + NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP
        == NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES,
    "ESP TLS original internal-only release requirement");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET
            + NINLIL_WIFI_ESP_TLS_MAX_SESSIONS
                * NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET
            + NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP
            + NINLIL_WIFI_ESP_TLS_EXECUTION_STACK_BYTES
            + NINLIL_WIFI_ESP_TLS_CRYPTO_DMA_BYTES
        == NINLIL_WIFI_ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE,
    "ESP TLS internal envelope");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_MAP_REMAINDER_OBSERVATION
            - NINLIL_WIFI_ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE
        == NINLIL_WIFI_ESP_TLS_MAP_OBSERVATION_SLACK,
    "ESP TLS observed map slack");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET
        == NINLIL_WIFI_ESP_TLS_OTHER_REGISTERED_POOL_BUDGET,
    "ESP R7 is the sole admitted OTHER_REGISTERED owner");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_TOTAL_ALLOCATION_BUDGET
            + NINLIL_WIFI_ESP_TLS_OTHER_REGISTERED_POOL_BUDGET
        == NINLIL_WIFI_ESP_TLS_WIFI_R7_COMPOSITION_TOTAL_BUDGET,
    "ESP Wi-Fi + R7 composition total");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE
            + NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET
        == NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ENVELOPE,
    "ESP Wi-Fi + R7 tiered internal envelope");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES
            + NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET
        == NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ONLY_REQUIREMENT_BYTES,
    "ESP Wi-Fi + R7 conservative internal-only requirement");

ninlil_wifi_tls_admission_result_t ninlil_wifi_tls_resource_admit(
    const ninlil_wifi_tls_resource_view_t *view)
{
    if (view == NULL
        || view->active_sessions >= NINLIL_WIFI_ESP_TLS_MAX_SESSIONS) {
        return NINLIL_WIFI_TLS_ADMISSION_SESSION_CAPACITY;
    }
    if (view->psram_enabled == 0u) {
        return NINLIL_WIFI_TLS_ADMISSION_PSRAM_DISABLED;
    }
    if (view->internal_free_bytes
        < (size_t)NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET
            + (size_t)NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP) {
        return NINLIL_WIFI_TLS_ADMISSION_INTERNAL_FREE;
    }
    if (view->internal_largest_free_block_bytes
        < NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET) {
        return NINLIL_WIFI_TLS_ADMISSION_INTERNAL_FRAGMENTED;
    }
    if (view->psram_free_bytes < NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET) {
        return NINLIL_WIFI_TLS_ADMISSION_PSRAM_FREE;
    }
    if (view->psram_largest_free_block_bytes
        < NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET) {
        return NINLIL_WIFI_TLS_ADMISSION_PSRAM_FRAGMENTED;
    }
    return NINLIL_WIFI_TLS_ADMISSION_OK;
}

int ninlil_wifi_tls_io_classifier_begin(
    ninlil_wifi_tls_io_classifier_t *classifier)
{
    if (classifier == NULL || classifier->active != 0u) {
        return 0;
    }
    classifier->active = 1u;
    classifier->inbound_count = 0u;
    classifier->outbound_count = 0u;
    classifier->violation = 0u;
    return 1;
}

ninlil_wifi_tls_allocation_tier_t ninlil_wifi_tls_io_classifier_route(
    ninlil_wifi_tls_io_classifier_t *classifier,
    size_t requested_bytes)
{
    if (classifier == NULL || classifier->active == 0u) {
        return NINLIL_WIFI_TLS_ALLOCATION_INTERNAL;
    }
    if (requested_bytes == NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES) {
        if (classifier->inbound_count != 0u) {
            classifier->violation = 1u;
            return NINLIL_WIFI_TLS_ALLOCATION_REJECT;
        }
        classifier->inbound_count += 1u;
        return NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO;
    }
    if (requested_bytes == NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES) {
        if (classifier->outbound_count != 0u) {
            classifier->violation = 1u;
            return NINLIL_WIFI_TLS_ALLOCATION_REJECT;
        }
        classifier->outbound_count += 1u;
        return NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO;
    }
    return NINLIL_WIFI_TLS_ALLOCATION_INTERNAL;
}

int ninlil_wifi_tls_io_classifier_finish(
    ninlil_wifi_tls_io_classifier_t *classifier)
{
    int valid;
    if (classifier == NULL || classifier->active == 0u) {
        return 0;
    }
    valid = classifier->violation == 0u
        && classifier->inbound_count == 1u
        && classifier->outbound_count == 1u;
    classifier->active = 0u;
    return valid;
}
