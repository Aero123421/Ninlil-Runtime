#ifndef NINLIL_ESP_IDF_OWNER_LIFECYCLE_LOGIC_H
#define NINLIL_ESP_IDF_OWNER_LIFECYCLE_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#ifdef __cplusplus
extern "C" {
#endif

void ninlil_esp_idf_owner_core_clear(ninlil_esp_idf_owner_core_t *core);
void ninlil_esp_idf_owner_stats_sat_inc(uint32_t *counter);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_begin_start(
    ninlil_esp_idf_owner_core_t *core);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_complete_start(
    ninlil_esp_idf_owner_core_t *core,
    uint64_t owner_context_id);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_begin_stop(
    ninlil_esp_idf_owner_core_t *core);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_mark_join_ack_core(
    ninlil_esp_idf_owner_core_t *core);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_complete_join(
    ninlil_esp_idf_owner_core_t *core);
void ninlil_esp_idf_owner_fail_joined(ninlil_esp_idf_owner_core_t *core);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_check_confinement(
    const ninlil_esp_idf_owner_core_t *core,
    uint32_t token_generation,
    uint64_t current_context_id);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_apply_msg(
    ninlil_esp_idf_owner_core_t *core,
    const ninlil_esp_idf_owner_msg_t *msg,
    uint64_t current_context_id);

#ifdef __cplusplus
}
#endif

#endif
