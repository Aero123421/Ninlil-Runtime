/*
 * Owner-task config pure staging used by owner_task_init (docs/22).
 * Host tests share this exact helper — not a generic abi_stage proxy alone.
 * Private binary symbol: NINLIL_ESP_IDF_INTERNAL (not public API / not installed).
 */

#ifndef NINLIL_ESP_IDF_OWNER_CONFIG_STAGE_LOGIC_H
#define NINLIL_ESP_IDF_OWNER_CONFIG_STAGE_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#include "abi_header_stage_logic.h"
#include "ninlil_esp_idf_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stage owner config against owner concrete storage:
 *  - storage pointer/size contract: both absent (NULL,0) or both present;
 *    NULL&&size!=0 and non-NULL&&size==0 are closed rejects
 *  - out_local required; out_hdr optional (NULL allowed)
 *  - out_local / out_hdr must not alias each other or owner_storage range
 *    (uintptr checked; pointer relational ops forbidden)
 *  - ABI header + declared struct_size full-range nonoverlap (forward extension OK)
 *  - known prefix only into out_local (never copies caller extension tail)
 *  - reserved_zero must be 0
 * Returns 0 ok, non-zero fail. out_local/out_hdr only written on success
 * (temps stage + validate, then commit).
 */
NINLIL_ESP_IDF_INTERNAL int ninlil_esp_idf_owner_config_stage(
    const ninlil_esp_idf_owner_task_config_t *cfg,
    const void *owner_storage,
    size_t owner_storage_size,
    ninlil_esp_idf_owner_task_config_t *out_local,
    ninlil_esp_idf_abi_header_t *out_hdr);

#ifdef __cplusplus
}
#endif

#endif
