#include "cell_assignment_logic.h"

#include <string.h>

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_assignment_validate_shape(
    const ninlil_esp_idf_cell_assignment_t *assignment)
{
    if (assignment == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (assignment->role != NINLIL_ROLE_CELL_AGENT_RESERVED
        || assignment->assignment_epoch == 0u
        || assignment->controller_term == 0u
        || assignment->reserved_zero != 0u) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_assignment_pack(
    const ninlil_esp_idf_cell_assignment_t *assignment,
    uint8_t *out_payload,
    uint16_t *out_len)
{
    ninlil_esp_idf_owner_status_t status;

    if (out_payload == NULL || out_len == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    status = ninlil_esp_idf_cell_assignment_validate_shape(assignment);
    if (status != NINLIL_ESP_IDF_OWNER_OK) {
        return status;
    }
    if (sizeof(*assignment) > NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    (void)memcpy(out_payload, assignment, sizeof(*assignment));
    *out_len = (uint16_t)sizeof(*assignment);
    return NINLIL_ESP_IDF_OWNER_OK;
}
