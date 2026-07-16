#ifndef NINLIL_ESP_IDF_EXECUTION_INIT_LOGIC_H
#define NINLIL_ESP_IDF_EXECUTION_INIT_LOGIC_H

#include "ninlil_esp_idf/execution.h"

int ninlil_esp_idf_execution_init_with_context(
    ninlil_esp_idf_execution_t *execution,
    uint64_t (*current_context_id)(void *));

void ninlil_esp_idf_execution_shutdown_host(
    ninlil_esp_idf_execution_t *execution);

#endif
