#ifndef NINLIL_ESP_IDF_OWNER_PUBLISH_LOGIC_H
#define NINLIL_ESP_IDF_OWNER_PUBLISH_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_esp_idf_owner_publish {
    uint32_t accepting;
    uint32_t generation;
    uint8_t lifecycle;
    uint8_t reserved[3];
} ninlil_esp_idf_owner_publish_t;

int ninlil_esp_idf_owner_publish_allows_post(
    const ninlil_esp_idf_owner_publish_t *pub);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_build_post(
    uint32_t published_generation,
    uint32_t accepting,
    uint8_t kind,
    int from_isr,
    const uint8_t *payload,
    uint16_t payload_len,
    ninlil_esp_idf_owner_msg_t *out_msg);

#ifdef __cplusplus
}
#endif

#endif
