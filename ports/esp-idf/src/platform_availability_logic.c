#include "platform_availability_logic.h"

ninlil_esp_idf_provider_lab_status_t ninlil_esp_idf_provider_catalog_status(
    ninlil_esp_idf_platform_provider_kind_t kind)
{
    switch (kind) {
    case NINLIL_ESP_IDF_PROVIDER_EXECUTION:
    case NINLIL_ESP_IDF_PROVIDER_CLOCK:
    case NINLIL_ESP_IDF_PROVIDER_ENTROPY:
    case NINLIL_ESP_IDF_PROVIDER_STORAGE:
    case NINLIL_ESP_IDF_PROVIDER_TX_GATE:
        return NINLIL_ESP_IDF_PROVIDER_STATUS_IMPLEMENTED;
    case NINLIL_ESP_IDF_PROVIDER_ALLOCATOR:
    case NINLIL_ESP_IDF_PROVIDER_BEARER:
    case NINLIL_ESP_IDF_PROVIDER_ORIGIN_AUTHORIZATION:
        return NINLIL_ESP_IDF_PROVIDER_STATUS_LAB_UNAVAILABLE;
    default:
        return NINLIL_ESP_IDF_PROVIDER_STATUS_V2;
    }
}

ninlil_port_status_t ninlil_esp_idf_provider_admission_request(
    ninlil_esp_idf_platform_provider_kind_t kind,
    const void *ops)
{
    ninlil_esp_idf_provider_lab_status_t status =
        ninlil_esp_idf_provider_catalog_status(kind);

    if (status == NINLIL_ESP_IDF_PROVIDER_STATUS_LAB_UNAVAILABLE
        || status == NINLIL_ESP_IDF_PROVIDER_STATUS_V2) {
        (void)ops;
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (ops == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    return NINLIL_PORT_OK;
}

int ninlil_esp_idf_platform_ops_admit(const ninlil_platform_ops_t *platform)
{
    if (platform == NULL) {
        return -1;
    }
    if (platform->allocator != NULL || platform->bearer != NULL
        || platform->origin_authorization != NULL) {
        return -1;
    }
    if (platform->execution == NULL || platform->clock == NULL
        || platform->entropy == NULL || platform->storage == NULL
        || platform->tx_gate == NULL) {
        return -1;
    }
    return 0;
}
