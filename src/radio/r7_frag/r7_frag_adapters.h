/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_R7_FRAG_ADAPTERS_H
#define NINLIL_R7_FRAG_ADAPTERS_H

/*
 * Private adapters: FRAG session → production N6 / R1 / R2 / L1↔W1 event bus.
 * Unbound ⇒ fail-closed (no fake success). Host spy records exact call order.
 * Mark-only R2 callbacks are removed: R2 path uses ninlil_pcp_issue only.
 * Not public ABI. Not installed.
 */

#include "n6_context_store.h"
#include "pcp_authority.h"
#include "r7_crypto_provider.h"
#include "r7_frag_checked_issue.h"
#include "r7_frag_issue_coordinator.h"
#include "radio_hal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R7_FRAG_SPY_MAX ((size_t)64u)

#define NINLIL_R7_FRAG_SPY_N6_TX_BURN ((uint8_t)1u)
#define NINLIL_R7_FRAG_SPY_N6_RX_PRE ((uint8_t)2u)
#define NINLIL_R7_FRAG_SPY_N6_RX_ADMIT ((uint8_t)3u)
#define NINLIL_R7_FRAG_SPY_N6_RX_ABORT ((uint8_t)4u)
#define NINLIL_R7_FRAG_SPY_R1_TX ((uint8_t)5u)
#define NINLIL_R7_FRAG_SPY_R2_ISSUE ((uint8_t)6u)
#define NINLIL_R7_FRAG_SPY_W1_STAMP ((uint8_t)7u)
#define NINLIL_R7_FRAG_SPY_W1_FRAME_READY ((uint8_t)8u)
#define NINLIL_R7_FRAG_SPY_W1_SEAL_FAIL ((uint8_t)9u)
#define NINLIL_R7_FRAG_SPY_L1_TX_RESULT ((uint8_t)10u)

typedef struct ninlil_r7_frag_spy {
    uint8_t events[NINLIL_R7_FRAG_SPY_MAX];
    size_t count;
} ninlil_r7_frag_spy_t;

void ninlil_r7_frag_spy_reset(ninlil_r7_frag_spy_t *spy);
void ninlil_r7_frag_spy_push(ninlil_r7_frag_spy_t *spy, uint8_t ev);

/* L1↔W1 closed 7-event kinds (docs/30 §1.1.1). */
#define NINLIL_R7_FRAG_EV_STAMP_FIELDS ((uint8_t)1u)
#define NINLIL_R7_FRAG_EV_FRAME_READY ((uint8_t)2u)
#define NINLIL_R7_FRAG_EV_SEAL_FAIL ((uint8_t)3u)
#define NINLIL_R7_FRAG_EV_LENGTH_CLASS ((uint8_t)4u)
#define NINLIL_R7_FRAG_EV_TX_RESULT ((uint8_t)5u)
#define NINLIL_R7_FRAG_EV_DRAIN_QUARANTINE ((uint8_t)6u)
#define NINLIL_R7_FRAG_EV_OWNER_TERMINAL ((uint8_t)7u)

typedef struct ninlil_r7_frag_l1w1_event {
    uint16_t event_schema; /* exact 1 */
    uint8_t event_kind;    /* 1..7 */
    uint64_t owner_token;
    uint64_t candidate_token;
    uint8_t detail0;
    uint8_t detail1;
} ninlil_r7_frag_l1w1_event_t;

typedef struct ninlil_r7_frag_l1w1_bus {
    ninlil_r7_frag_l1w1_event_t log[NINLIL_R7_FRAG_SPY_MAX];
    size_t count;
} ninlil_r7_frag_l1w1_bus_t;

void ninlil_r7_frag_l1w1_reset(ninlil_r7_frag_l1w1_bus_t *bus);
int32_t ninlil_r7_frag_l1w1_emit(
    ninlil_r7_frag_l1w1_bus_t *bus,
    ninlil_r7_frag_spy_t *spy,
    uint8_t kind,
    uint64_t owner,
    uint64_t candidate,
    uint8_t d0,
    uint8_t d1);

/*
 * Production orchestrator binding (no mark-only R2 callback).
 * pcp + live_valid required for issue; hal + pcp_permit_ops for R1.
 */
typedef struct ninlil_r7_frag_orch {
    ninlil_n6_t *n6;
    ninlil_n6_handle_t hop_data_handle;
    ninlil_n6_handle_t hop_ack_handle;
    ninlil_n6_handle_t e2e_handle;
    ninlil_radio_hal_t *hal;
    ninlil_pcp_t *pcp;
    ninlil_pcp_live_profile_t live;
    uint8_t live_valid;
    uint64_t trusted_now_ms;
    uint8_t clock_trusted;
    uint8_t clock_uncertain;
    const ninlil_r7_crypto_provider *crypto;
    ninlil_r7_frag_spy_t *spy;
    ninlil_r7_frag_l1w1_bus_t *bus;
    /* Owner-local issue state; no process-global mutable fallback. */
    ninlil_r7_frag_issue_coordinator_t issue_coordinator;
    ninlil_r7_r5_issue_registry_t issue_registry;
    /*
     * Coordinator-owned held/queued issued Permit (same identity as prod_orch).
     * Resume via orch_outer_tx with identical outer bytes; never re-issue.
     */
    uint8_t held_live;
    uint8_t held_queued;
    uint64_t held_auth;
    uint64_t held_permit_sequence;
    uint32_t held_outer_len;
    uint8_t held_outer_digest[32];
    uint8_t held_outer[256];
    ninlil_radio_hal_permit_snapshot_t held_permit;
} ninlil_r7_frag_orch_t;

/*
 * TX path after OUTER sealed: STAMP→FRAME_READY→real R2 issue→admit→R1.
 * Same coordinator state machine as prod_orch (no local release of issued).
 * QUEUED/HELD retain Permit+outer; resume with identical outer bytes.
 * Unbound n6/hal/pcp/live/clock/crypto/sha256 ⇒ fail-closed (return 2).
 */
int32_t ninlil_r7_frag_orch_outer_tx(
    ninlil_r7_frag_orch_t *orch,
    uint64_t owner_token,
    uint64_t candidate_token,
    const uint8_t *outer_frame,
    size_t outer_len);

/* N6 wrappers with spy. Unbound n6 ⇒ fail-closed status. */
int32_t ninlil_r7_frag_orch_n6_tx_burn(
    ninlil_r7_frag_orch_t *orch,
    ninlil_n6_handle_t handle,
    uint8_t lane_kind,
    ninlil_n6_tx_lease_t *out_lease);

int32_t ninlil_r7_frag_orch_n6_rx_precheck(
    ninlil_r7_frag_orch_t *orch,
    ninlil_n6_handle_t handle,
    uint8_t lane_kind,
    uint64_t counter,
    ninlil_n6_rx_ticket_t *out_ticket);

int32_t ninlil_r7_frag_orch_n6_rx_admit(
    ninlil_r7_frag_orch_t *orch,
    ninlil_n6_rx_ticket_t *ticket);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_ADAPTERS_H */
