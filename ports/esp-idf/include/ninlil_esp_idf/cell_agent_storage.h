#ifndef NINLIL_ESP_IDF_CELL_AGENT_STORAGE_H
#define NINLIL_ESP_IDF_CELL_AGENT_STORAGE_H

#include "ninlil_esp_idf/cell_agent.h"
#include "ninlil_esp_idf/owner_task_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Cell state lives under owner.mux (api_lifecycle inside owner). */
struct ninlil_esp_idf_cell_agent {
    ninlil_esp_idf_owner_task_t owner;
};

#ifdef __cplusplus
}
#endif

#endif
