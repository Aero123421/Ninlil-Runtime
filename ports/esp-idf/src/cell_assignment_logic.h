/*
 * Typed cell/channel/role assignment validation (Controller -> Cell Agent).
 */

#ifndef NINLIL_ESP_IDF_CELL_ASSIGNMENT_LOGIC_H
#define NINLIL_ESP_IDF_CELL_ASSIGNMENT_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Shape validation only (no owner state). Returns OK or POISON/INVALID.
 */
ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_assignment_validate_shape(
    const ninlil_esp_idf_cell_assignment_t *assignment);

/*
 * Pack assignment into mailbox payload bytes (exact sizeof assignment).
 */
ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_assignment_pack(
    const ninlil_esp_idf_cell_assignment_t *assignment,
    uint8_t *out_payload,
    uint16_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_CELL_ASSIGNMENT_LOGIC_H */
