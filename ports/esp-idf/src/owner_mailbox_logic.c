#include "owner_mailbox_logic.h"

#include <string.h>

void ninlil_esp_idf_owner_pure_mailbox_clear(
    ninlil_esp_idf_owner_pure_mailbox_t *mb)
{
    if (mb != NULL) {
        (void)memset(mb, 0, sizeof(*mb));
    }
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_pure_mailbox_push(
    ninlil_esp_idf_owner_pure_mailbox_t *mb,
    const ninlil_esp_idf_owner_msg_t *msg)
{
    uint32_t i;

    if (mb == NULL || msg == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (msg->payload_len > NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    if (mb->count >= NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH) {
        return NINLIL_ESP_IDF_OWNER_MAILBOX_FULL;
    }
    i = mb->tail % NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH;
    mb->slots[i] = *msg;
    mb->tail = (mb->tail + 1u) % NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH;
    mb->count += 1u;
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_pure_mailbox_pop(
    ninlil_esp_idf_owner_pure_mailbox_t *mb,
    ninlil_esp_idf_owner_msg_t *out)
{
    uint32_t i;

    if (mb == NULL || out == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (mb->count == 0u) {
        return NINLIL_ESP_IDF_OWNER_MAILBOX_EMPTY;
    }
    i = mb->head % NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH;
    *out = mb->slots[i];
    (void)memset(&mb->slots[i], 0, sizeof(mb->slots[i]));
    mb->head = (mb->head + 1u) % NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH;
    mb->count -= 1u;
    return NINLIL_ESP_IDF_OWNER_OK;
}
