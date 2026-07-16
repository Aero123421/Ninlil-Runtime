#ifndef NINLIL_ESP_IDF_OWNER_MAILBOX_LOGIC_H
#define NINLIL_ESP_IDF_OWNER_MAILBOX_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Host pure ring only — not used by FreeRTOS backend. */
void ninlil_esp_idf_owner_pure_mailbox_clear(
    ninlil_esp_idf_owner_pure_mailbox_t *mb);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_pure_mailbox_push(
    ninlil_esp_idf_owner_pure_mailbox_t *mb,
    const ninlil_esp_idf_owner_msg_t *msg);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_pure_mailbox_pop(
    ninlil_esp_idf_owner_pure_mailbox_t *mb,
    ninlil_esp_idf_owner_msg_t *out);

#ifdef __cplusplus
}
#endif

#endif
