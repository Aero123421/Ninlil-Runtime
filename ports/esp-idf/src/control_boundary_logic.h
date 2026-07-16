/*
 * NCG1 framing boundary helpers for Cell Agent skeleton.
 * Framing success is not assignment apply or custody.
 *
 * Uses portable control_frame_codec (private). No ESP/FreeRTOS headers.
 */

#ifndef NINLIL_ESP_IDF_CONTROL_BOUNDARY_LOGIC_H
#define NINLIL_ESP_IDF_CONTROL_BOUNDARY_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ninlil_esp_idf_control_boundary_status_t;

#define NINLIL_ESP_IDF_CONTROL_BOUNDARY_OK \
    ((ninlil_esp_idf_control_boundary_status_t)0u)
#define NINLIL_ESP_IDF_CONTROL_BOUNDARY_INVALID_ARGUMENT \
    ((ninlil_esp_idf_control_boundary_status_t)1u)
#define NINLIL_ESP_IDF_CONTROL_BOUNDARY_FRAMING_FAIL \
    ((ninlil_esp_idf_control_boundary_status_t)2u)

/*
 * One-shot NCG1 decode into header summary only.
 * Does NOT copy frame payload into summary or diagnostics.
 * Does NOT apply cell assignment.
 */
ninlil_esp_idf_control_boundary_status_t
ninlil_esp_idf_control_boundary_summarize_frame(
    const uint8_t *frame_bytes,
    size_t frame_length,
    ninlil_esp_idf_owner_control_summary_t *out_summary);

/*
 * Pack summary into mailbox payload for CONTROL_SUMMARY posts.
 */
ninlil_esp_idf_owner_status_t ninlil_esp_idf_control_boundary_pack_summary(
    const ninlil_esp_idf_owner_control_summary_t *summary,
    uint8_t *out_payload,
    uint16_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_CONTROL_BOUNDARY_LOGIC_H */
