/*
 * Narrow compile-time Fabric to RRMP select seam.
 *
 * Fabric is independently buildable:
 *  - RRMP OFF: this header is a pure no-op inline (no rrmp includes).
 *  - RRMP ON: calls ninlil_rrmp_fabric_on_path_selected after path select.
 *
 * Call site (fabric_private_core only AFTER select + auth + RF + enrich
 * success). Arguments in order:
 *   rrmp_owner (the owner bound to this Fabric instance),
 *   selected_instance_id,
 *   has_selection (1 on final success),
 *   requires_custody,
 *   path_selection_epoch,
 *   now_ms.
 *
 * Reject paths must not call this (zero RRMP mutation).
 * See docs/work/fabric-rrmp-select-call-site.patch for a conflict-free insert.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_RRMP_SELECT_HOOK_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_RRMP_SELECT_HOOK_H

#include <stdint.h>
#include <string.h>

#if defined(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1) && \
    (NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
#include "rrmp_fabric_dispatch.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct ninlil_rrmp_owner;

static inline void ninlil_fabric_rrmp_on_path_selected(
    struct ninlil_rrmp_owner *rrmp_owner,
    const uint8_t selected_instance_id[16],
    uint32_t has_selection,
    uint32_t requires_custody,
    uint64_t path_selection_epoch,
    uint64_t now_ms)
{
#if defined(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1) && \
    (NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
    ninlil_rrmp_fabric_select_view_t view;
    if (selected_instance_id == NULL) {
        return;
    }
    /*
     * Reject or non-final inputs: still build a view with selection_finalized=0
     * so RRMP dispatch performs zero mutation.
     */
    (void)memset(&view, 0, sizeof(view));
    view.has_selection = has_selection ? 1u : 0u;
    view.requires_custody = requires_custody;
    view.path_selection_epoch = path_selection_epoch;
    view.now_ms = now_ms;
    /* Finalized only when has_selection is true (caller post-enrich only). */
    view.selection_finalized = has_selection ? 1u : 0u;
    {
        uint8_t i;
        for (i = 0u; i < 16u; ++i) {
            view.selected_instance_id[i] = selected_instance_id[i];
        }
    }
    (void)ninlil_rrmp_fabric_on_path_selected(rrmp_owner, &view, NULL);
#else
    (void)rrmp_owner;
    (void)selected_instance_id;
    (void)has_selection;
    (void)requires_custody;
    (void)path_selection_epoch;
    (void)now_ms;
#endif
}

#ifdef __cplusplus
}
#endif

#endif
