/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Runtime-owned adapter for Fabric's opaque path-selected callback.
 * Fabric never imports this header or any RRMP type.
 *
 * No product vocabulary. Private candidate only.
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_FABRIC_DISPATCH_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_FABRIC_DISPATCH_H

#include "rrmp_abi.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_rrmp_fabric_select_view {
    uint8_t selected_instance_id[16];
    uint8_t has_selection; /* 1 if select resolved a path */
    uint8_t selection_finalized; /* 1 only after select+auth+RF+enrich success */
    uint32_t requires_custody; /* from fabric query */
    uint64_t path_selection_epoch;
    uint64_t now_ms;
} ninlil_rrmp_fabric_select_view_t;

/*
 * After final Fabric selection + enrichment success: pin selected instance.
 * If requires_custody and queue has work, run one fair forward_service_once.
 * selection_finalized=0 → zero mutation (reject-path safety).
 * FEATURE_OFF / owner=NULL → no-op OK (does not fail Fabric select).
 */
ninlil_route_status_u32 ninlil_rrmp_fabric_on_path_selected(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_fabric_select_view_t *view,
    ninlil_route_result_v1_t *out_opt);

/* Exact callback shape declared privately by fabric_private_api.h. */
void ninlil_rrmp_fabric_path_selected_hook_v1(
    void *user,
    const uint8_t selected_instance_id[16],
    uint32_t has_selection,
    uint32_t requires_custody,
    uint64_t path_selection_epoch,
    uint64_t now_ms);

/* Read last fabric path pin (test/diagnostic). */
int ninlil_rrmp_fabric_last_path(
    ninlil_rrmp_owner_t *owner,
    uint8_t selected_instance_id_out[16],
    uint64_t *epoch_out);

#ifdef __cplusplus
}
#endif

#endif
