/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_seam.h"
#include "rrmp_util.h"

#include <string.h>

ninlil_route_status_u32 ninlil_rrmp_seam_admit_from_nfl1_view(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_nfl1_hop_view_t *hop, ninlil_route_result_v1_t *out)
{
    ninlil_route_forward_admit_req_v1_t req;
    if (hop == NULL) {
        if (out != NULL) {
            ninlil_rrmp_memzero(out, sizeof(*out));
            out->api_version = 1u;
            out->struct_size = 128u;
            out->status = NINLIL_ROUTE_INVALID_ARGUMENT;
        }
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = 1u;
    req.preamble.struct_size = 128u;
    req.ingress_hop_context_id = hop->ingress_hop_context_id;
    req.route_handle = hop->route_handle;
    req.route_generation = hop->route_generation;
    req.hop_remaining = hop->hop_remaining;
    req.flags = hop->is_frag_transfer ? 1u : 0u;
    memcpy(req.e2e_header_digest32, hop->e2e_header_digest32, 32u);
    req.outer_rx_counter = hop->outer_rx_counter;
    req.admission_now_ms = hop->now_ms;
    req.item_deadline_ms = hop->item_deadline_ms;
    req.remaining_link_groups = hop->remaining_link_groups;
    req.remaining_attempts = hop->remaining_attempts;
    req.max_airtime_ms = hop->max_airtime_ms;
    req.turnaround_ms = hop->turnaround_ms;
    req.link_ack_wait_ms = hop->link_ack_wait_ms;
    req.scheduler_guard_ms = hop->scheduler_guard_ms;
    req.inter_group_gap_ms = hop->inter_group_gap_ms;
    req.priority_class = hop->priority_class;
    req.caller_item_token = hop->caller_item_token;
    return ninlil_rrmp_core_forward_admit_with_carrier(
        owner, &req,
        hop->application_data, hop->application_data_len,
        hop->attempt_id16, out);
}

void ninlil_rrmp_seam_apply_r7_frag_view(
    ninlil_rrmp_nfl1_hop_view_t *hop, const ninlil_rrmp_r7_frag_view_t *frag)
{
    if (hop == NULL || frag == NULL) {
        return;
    }
    hop->remaining_link_groups = frag->remaining_link_groups;
    hop->remaining_attempts = frag->remaining_attempts;
    hop->max_airtime_ms = frag->max_airtime_ms;
    hop->is_frag_transfer = 1u;
}

ninlil_route_status_u32 ninlil_rrmp_seam_fabric_forward_once(
    ninlil_rrmp_owner_t *owner,
    ninlil_route_result_v1_t *out)
{
    return ninlil_rrmp_core_forward_service_once(owner, out);
}

/*
 * Production fabric relay cycle — NO fabricated LINK_ACK and NO auto-complete.
 *
 *   admit → fair service once → hop materialize + outbound provider submit
 *
 * Completion and LINK_ACK require separate authenticated inbound evidence via
 * ninlil_rrmp_core_link_ack_from_evidence + ninlil_route_forward_complete.
 * Without a bound outbound provider, hop fails UNSUPPORTED_CAPABILITY.
 */
ninlil_route_status_u32 ninlil_rrmp_seam_fabric_relay_cycle(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_nfl1_hop_view_t *hop,
    uint8_t tx_permit_granted,
    ninlil_rrmp_hop_tx_view_t *tx_out,
    ninlil_route_result_v1_t *out)
{
    ninlil_route_status_u32 st;
    ninlil_route_result_v1_t admit_out;
    ninlil_route_result_v1_t svc_out;
    uint64_t oh;

    if (out == NULL) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->api_version = 1u;
    out->struct_size = 128u;
    if (hop == NULL) {
        out->status = NINLIL_ROUTE_INVALID_ARGUMENT;
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (owner == NULL) {
        out->status = NINLIL_ROUTE_INVALID_ARGUMENT;
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }

    st = ninlil_rrmp_seam_admit_from_nfl1_view(owner, hop, &admit_out);
    if (st != NINLIL_ROUTE_OK) {
        *out = admit_out;
        return st;
    }
    oh = admit_out.opaque_local_handle;
    if (oh == 0u) {
        out->status = NINLIL_ROUTE_CORRUPT;
        return NINLIL_ROUTE_CORRUPT;
    }

    st = ninlil_rrmp_core_forward_service_once(owner, &svc_out);
    if (st != NINLIL_ROUTE_OK) {
        *out = svc_out;
        return st;
    }
    if (svc_out.opaque_local_handle != oh) {
        /* Fairness may pick another item first; require exact ownership. */
        out->status = NINLIL_ROUTE_NOT_ACTIVE;
        return NINLIL_ROUTE_NOT_ACTIVE;
    }

    st = ninlil_rrmp_core_hop_forward_execute(
        owner, oh, NULL, 0u, tx_permit_granted, tx_out);
    if (st != NINLIL_ROUTE_OK) {
        out->status = st;
        out->opaque_local_handle = oh;
        return st;
    }

    /* Submitted to outbound provider; custody retained until authenticated ACK. */
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->api_version = 1u;
    out->struct_size = 128u;
    out->status = NINLIL_ROUTE_OK;
    out->opaque_local_handle = oh;
    out->detail_flags = 1u; /* bit0: awaiting authenticated LINK_ACK */
    if (tx_out != NULL) {
        out->hop_remaining_out = tx_out->hop_remaining_out;
        out->route_handle = tx_out->route_handle;
        out->route_generation = tx_out->route_generation;
    }
    return NINLIL_ROUTE_OK;
}
