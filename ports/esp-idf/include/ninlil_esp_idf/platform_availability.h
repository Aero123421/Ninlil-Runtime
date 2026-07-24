#ifndef NINLIL_ESP_IDF_PLATFORM_AVAILABILITY_H
#define NINLIL_ESP_IDF_PLATFORM_AVAILABILITY_H

#include "ninlil/platform.h"

typedef enum ninlil_esp_idf_platform_provider_kind {
    NINLIL_ESP_IDF_PROVIDER_ALLOCATOR = 1,
    NINLIL_ESP_IDF_PROVIDER_EXECUTION = 2,
    NINLIL_ESP_IDF_PROVIDER_CLOCK = 3,
    NINLIL_ESP_IDF_PROVIDER_ENTROPY = 4,
    NINLIL_ESP_IDF_PROVIDER_STORAGE = 5,
    NINLIL_ESP_IDF_PROVIDER_BEARER = 6,
    NINLIL_ESP_IDF_PROVIDER_TX_GATE = 7,
    NINLIL_ESP_IDF_PROVIDER_ORIGIN_AUTHORIZATION = 8
} ninlil_esp_idf_platform_provider_kind_t;

typedef enum ninlil_esp_idf_provider_lab_status {
    NINLIL_ESP_IDF_PROVIDER_STATUS_IMPLEMENTED = 1,
    NINLIL_ESP_IDF_PROVIDER_STATUS_LAB_UNAVAILABLE = 2,
    NINLIL_ESP_IDF_PROVIDER_STATUS_V2 = 3
} ninlil_esp_idf_provider_lab_status_t;

ninlil_esp_idf_provider_lab_status_t ninlil_esp_idf_provider_catalog_status(
    ninlil_esp_idf_platform_provider_kind_t kind);

ninlil_port_status_t ninlil_esp_idf_provider_admission_request(
    ninlil_esp_idf_platform_provider_kind_t kind,
    const void *ops);

int ninlil_esp_idf_platform_ops_admit(const ninlil_platform_ops_t *platform);

#endif
