#ifndef NINLIL_ESP_IDF_ENTROPY_PUBLISH_LOGIC_H
#define NINLIL_ESP_IDF_ENTROPY_PUBLISH_LOGIC_H

#include "ninlil_esp_idf/entropy.h"

int ninlil_esp_idf_entropy_storage_is_zero(
    const ninlil_esp_idf_entropy_t *entropy);

int ninlil_esp_idf_entropy_publish_once(
    ninlil_esp_idf_entropy_t *entropy,
    ninlil_port_status_t (*fill)(void *, uint8_t *, uint32_t),
    uint32_t policy,
    uint32_t generation);

void ninlil_esp_idf_entropy_retire_storage(
    ninlil_esp_idf_entropy_t *entropy);

#endif
