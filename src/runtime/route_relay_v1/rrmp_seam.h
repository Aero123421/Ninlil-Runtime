/*
 * Composition seams with private Fabric/NFL1 and R7 LINK/FRAG without
 * changing those modules' contracts. Thin adapters only.
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_SEAM_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_SEAM_H

#include "rrmp_abi.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NFL1-shaped hop envelope handoff into route forward_admit. */
typedef struct ninlil_rrmp_nfl1_hop_view {
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint8_t hop_remaining;
    uint8_t e2e_header_digest32[32];
    uint64_t outer_rx_counter;
    uint64_t now_ms;
    uint8_t is_frag_transfer;
    uint8_t priority_class;
    uint16_t remaining_link_groups;
    uint16_t remaining_attempts;
    uint32_t max_airtime_ms;
    uint32_t turnaround_ms;
    uint32_t link_ack_wait_ms;
    uint32_t scheduler_guard_ms;
    uint32_t inter_group_gap_ms;
    uint64_t item_deadline_ms;
    uint64_t caller_item_token;
    /*
     * Borrowed only for the duration of admission; RRMP copy-owns it before
     * returning OK. NULL/0 is an explicit custody-only hop.
     */
    const uint8_t *application_data;
    uint16_t application_data_len;
    uint8_t attempt_id16[16];
} ninlil_rrmp_nfl1_hop_view_t;

ninlil_route_status_u32 ninlil_rrmp_seam_admit_from_nfl1_view(
    const ninlil_rrmp_nfl1_hop_view_t *hop, ninlil_route_result_v1_t *out);

/* R7 FRAG remaining groups/attempts feed drain/forward gates only. */
typedef struct ninlil_rrmp_r7_frag_view {
    uint16_t remaining_link_groups;
    uint16_t remaining_attempts;
    uint32_t max_airtime_ms;
} ninlil_rrmp_r7_frag_view_t;

void ninlil_rrmp_seam_apply_r7_frag_view(
    ninlil_rrmp_nfl1_hop_view_t *hop, const ninlil_rrmp_r7_frag_view_t *frag);

/* Fabric path: after select, service one forward from core queue. */
ninlil_route_status_u32 ninlil_rrmp_seam_fabric_forward_once(
    ninlil_route_result_v1_t *out);

/*
 * Generic Fabric/NFL1 relay cycle (no product vocabulary):
 *   admit (durable NEP1 LIVE + queue E2E body)
 *   → fair dequeue once
 *   → hop execute under TxPermit (materialize rewrap + outbound provider submit)
 *
 * Does NOT fabricate LINK_ACK or complete. detail_flags bit0 = awaiting ACK.
 * Authenticated LINK_ACK: ninlil_rrmp_core_link_ack_from_evidence.
 * Complete: ninlil_route_forward_complete after authentic ACK only.
 */
ninlil_route_status_u32 ninlil_rrmp_seam_fabric_relay_cycle(
    const ninlil_rrmp_nfl1_hop_view_t *hop,
    uint8_t tx_permit_granted,
    ninlil_rrmp_hop_tx_view_t *tx_out,
    ninlil_route_result_v1_t *out);

#ifdef __cplusplus
}
#endif

#endif
