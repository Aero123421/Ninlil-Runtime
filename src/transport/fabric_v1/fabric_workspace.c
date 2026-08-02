#include "fabric_workspace.h"

#include "fabric_private_util.h"

/* Return 0 OK, 1 INVALID_ARGUMENT, 7 CORRUPT — matches private status codes. */
uint32_t ninlil_fabric_private_workspace_layout_proof_v1(
    uint32_t *out_total,
    ninlil_fabric_ws_region_info_t out_regions[NINLIL_FABRIC_WS_REGION_COUNT])
{
    static const ninlil_fabric_ws_region_info_t k_regions[NINLIL_FABRIC_WS_REGION_COUNT]
        = {
              { NINLIL_FABRIC_WS_OFF_NFL1_QUEUE,
                  NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES, 1u, "nfl1_queue" },
              { NINLIL_FABRIC_WS_OFF_CODEC_SCRATCH,
                  NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES, 1u, "codec_scratch" },
              { NINLIL_FABRIC_WS_OFF_REGISTRY, NINLIL_FABRIC_WS_REGISTRY_BYTES,
                  8u, "registry" },
              { NINLIL_FABRIC_WS_OFF_POLICY_INDEX,
                  NINLIL_FABRIC_WS_POLICY_INDEX_BYTES, 8u, "policy_index" },
              { NINLIL_FABRIC_WS_OFF_AUTHORITY_INDEX,
                  NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES, 8u,
                  "authority_index" },
              { NINLIL_FABRIC_WS_OFF_ATTEMPT, NINLIL_FABRIC_WS_ATTEMPT_BYTES,
                  8u, "attempt_slots" },
              { NINLIL_FABRIC_WS_OFF_TRIGGER, NINLIL_FABRIC_WS_TRIGGER_BYTES,
                  8u, "trigger_slots" },
              { NINLIL_FABRIC_WS_OFF_QUEUE_DESC,
                  NINLIL_FABRIC_WS_QUEUE_DESC_BYTES, 8u, "queue_descriptors" },
              { NINLIL_FABRIC_WS_OFF_TIMERS, NINLIL_FABRIC_WS_TIMERS_BYTES, 8u,
                  "timers" },
              { NINLIL_FABRIC_WS_OFF_REG_METRICS,
                  NINLIL_FABRIC_WS_REG_METRICS_BYTES, 8u,
                  "registration_metrics" },
              { NINLIL_FABRIC_WS_OFF_CONTROL, NINLIL_FABRIC_WS_CONTROL_BYTES,
                  (uint32_t)_Alignof(max_align_t), "control_scan_storage" },
          };
    uint32_t i;
    uint32_t cursor = 0u;

    if (out_total == NULL || out_regions == NULL) {
        return 1u; /* INVALID_ARGUMENT */
    }
    for (i = 0u; i < NINLIL_FABRIC_WS_REGION_COUNT; ++i) {
        if (k_regions[i].offset != cursor) {
            return 7u; /* CORRUPT */
        }
        if (k_regions[i].size == 0u) {
            return 7u;
        }
        if (k_regions[i].alignment > 1u
            && (k_regions[i].offset % k_regions[i].alignment) != 0u) {
            return 7u;
        }
        cursor += k_regions[i].size;
        out_regions[i] = k_regions[i];
    }
    if (cursor != NINLIL_FABRIC_WORKSPACE_BYTES) {
        return 7u;
    }
    *out_total = cursor;
    return 0u; /* OK */
}
