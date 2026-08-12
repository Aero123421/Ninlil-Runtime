/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_fabric_dispatch.h"
#include "rrmp_util.h"

#include <string.h>

void ninlil_rrmp_fabric_path_selected_hook_v1(
    void *user,
    const uint8_t selected_instance_id[16],
    uint32_t has_selection,
    uint32_t requires_custody,
    uint64_t path_selection_epoch,
    uint64_t now_ms)
{
    ninlil_rrmp_fabric_select_view_t view;

    if (selected_instance_id == NULL) {
        return;
    }
    (void)memset(&view, 0, sizeof(view));
    (void)memcpy(
        view.selected_instance_id, selected_instance_id,
        sizeof(view.selected_instance_id));
    view.has_selection = has_selection != 0u ? 1u : 0u;
    view.selection_finalized = view.has_selection;
    view.requires_custody = requires_custody;
    view.path_selection_epoch = path_selection_epoch;
    view.now_ms = now_ms;
    (void)ninlil_rrmp_fabric_on_path_selected(
        (ninlil_rrmp_owner_t *)user, &view, NULL);
}

ninlil_route_status_u32 ninlil_rrmp_fabric_on_path_selected(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_fabric_select_view_t *view,
    ninlil_route_result_v1_t *out_opt)
{
    ninlil_route_result_v1_t local;
    ninlil_route_result_v1_t *out = out_opt != NULL ? out_opt : &local;

    ninlil_rrmp_memzero(out, sizeof(*out));
    out->api_version = 1u;
    out->struct_size = 128u;
    if (view == NULL) {
        out->status = NINLIL_ROUTE_INVALID_ARGUMENT;
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (owner == NULL) {
        /* Fabric select not bound to RRMP — silent success. */
        out->status = NINLIL_ROUTE_OK;
        return NINLIL_ROUTE_OK;
    }
    /*
     * Zero mutation on reject paths: Fabric must only finalize after
     * select+auth+RF-check+enrich success. Pre-validation calls are no-ops.
     */
    if (!view->selection_finalized || !view->has_selection) {
        out->status = NINLIL_ROUTE_OK;
        return NINLIL_ROUTE_OK;
    }
    ninlil_rrmp_core_set_fabric_path(
        owner, view->selected_instance_id, view->path_selection_epoch);
    if (view->requires_custody == 0u) {
        out->status = NINLIL_ROUTE_OK;
        return NINLIL_ROUTE_OK;
    }
    /* Custody: service one fair queue item if any. */
    {
        ninlil_route_status_u32 st =
            ninlil_rrmp_core_forward_service_once(owner, out);
        if (st == NINLIL_ROUTE_NOT_ACTIVE) {
            out->status = NINLIL_ROUTE_OK;
            return NINLIL_ROUTE_OK;
        }
        return st;
    }
}

int ninlil_rrmp_fabric_last_path(
    ninlil_rrmp_owner_t *owner,
    uint8_t selected_instance_id_out[16],
    uint64_t *epoch_out)
{
    return ninlil_rrmp_core_get_fabric_path(
        owner, selected_instance_id_out, epoch_out);
}
