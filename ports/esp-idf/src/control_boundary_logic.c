#include "control_boundary_logic.h"

#include "control_frame_codec.h"

#include <string.h>

ninlil_esp_idf_control_boundary_status_t
ninlil_esp_idf_control_boundary_summarize_frame(
    const uint8_t *frame_bytes,
    size_t frame_length,
    ninlil_esp_idf_owner_control_summary_t *out_summary)
{
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t framing;
    ninlil_status_t status;
    ninlil_bytes_view_t encoded;

    if (frame_bytes == NULL || out_summary == NULL || frame_length == 0u) {
        return NINLIL_ESP_IDF_CONTROL_BOUNDARY_INVALID_ARGUMENT;
    }
    if (frame_length > (size_t)UINT32_MAX) {
        return NINLIL_ESP_IDF_CONTROL_BOUNDARY_INVALID_ARGUMENT;
    }

    (void)memset(&view, 0, sizeof(view));
    (void)memset(&encoded, 0, sizeof(encoded));
    encoded.data = frame_bytes;
    encoded.length = (uint32_t)frame_length;
    framing = NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
    status = ninlil_model_control_frame_decode(encoded, &view, &framing);
    if (status != NINLIL_OK
        || framing != NINLIL_MODEL_CONTROL_FRAME_RESULT_OK) {
        return NINLIL_ESP_IDF_CONTROL_BOUNDARY_FRAMING_FAIL;
    }

    /*
     * Boundary: keep header fields only. Do not retain or return payload
     * bytes (view.payload may borrow encoded). Callers must not treat this
     * as assignment apply or custody success.
     */
    (void)memset(out_summary, 0, sizeof(*out_summary));
    out_summary->frame_type = view.type;
    out_summary->reserved_zero = 0u;
    out_summary->payload_length = view.payload_length;
    out_summary->stream_or_cell_id = view.stream_or_cell_id;
    out_summary->sequence = view.sequence;
    return NINLIL_ESP_IDF_CONTROL_BOUNDARY_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_control_boundary_pack_summary(
    const ninlil_esp_idf_owner_control_summary_t *summary,
    uint8_t *out_payload,
    uint16_t *out_len)
{
    if (summary == NULL || out_payload == NULL || out_len == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (summary->reserved_zero != 0u) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    if (sizeof(*summary) > NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES) {
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    (void)memcpy(out_payload, summary, sizeof(*summary));
    *out_len = (uint16_t)sizeof(*summary);
    return NINLIL_ESP_IDF_OWNER_OK;
}
