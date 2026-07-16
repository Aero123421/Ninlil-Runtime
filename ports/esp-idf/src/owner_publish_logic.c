#include "owner_publish_logic.h"

#include <string.h>

int ninlil_esp_idf_owner_publish_allows_post(
    const ninlil_esp_idf_owner_publish_t *pub)
{
    return pub != NULL && pub->accepting != 0u && pub->generation != 0u;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_build_post(
    uint32_t published_generation,
    uint32_t accepting,
    uint8_t kind,
    int from_isr,
    const uint8_t *payload,
    uint16_t payload_len,
    ninlil_esp_idf_owner_msg_t *out_msg)
{
    if (out_msg == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (payload_len > NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES
        || (payload_len > 0u && payload == NULL)) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    if (kind != NINLIL_ESP_IDF_OWNER_MSG_TICK
        && kind != NINLIL_ESP_IDF_OWNER_MSG_CONTROL_SUMMARY
        && kind != NINLIL_ESP_IDF_OWNER_MSG_ASSIGNMENT
        && kind != NINLIL_ESP_IDF_OWNER_MSG_SELF_STOP_PROBE) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    if (from_isr != 0 && kind != NINLIL_ESP_IDF_OWNER_MSG_TICK) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    if (accepting == 0u || published_generation == 0u) {
        return NINLIL_ESP_IDF_OWNER_NOT_ACCEPTING;
    }
    (void)memset(out_msg, 0, sizeof(*out_msg));
    out_msg->kind = kind;
    out_msg->flags = (from_isr != 0) ? 1u : 0u;
    out_msg->payload_len = payload_len;
    out_msg->generation = published_generation;
    if (payload_len > 0u) {
        (void)memcpy(out_msg->payload, payload, (size_t)payload_len);
    }
    return NINLIL_ESP_IDF_OWNER_OK;
}
