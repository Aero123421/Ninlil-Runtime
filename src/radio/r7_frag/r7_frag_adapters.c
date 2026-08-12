/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private FRAG adapters: production N6 / R1 / R2 / L1W1 with host spy.
 * Sole R2 issue path: ninlil_r7_private_issue_checked_with_owner_epoch
 * (docs/30 §15.3.1). Same authority coordinator SM as prod_orch — no local
 * release of issued Permits on QUEUED/HELD/NOT_BEFORE.
 */

#include "r7_frag_adapters.h"

#include "r7_crypto_provider.h"
#include "r7_frag_checked_issue.h"
#include "r7_frag_issue_coordinator.h"

#include <stdint.h>
#include <string.h>

void ninlil_r7_frag_spy_reset(ninlil_r7_frag_spy_t *spy)
{
    if (spy == NULL) {
        return;
    }
    memset(spy, 0, sizeof(*spy));
}

void ninlil_r7_frag_spy_push(ninlil_r7_frag_spy_t *spy, uint8_t ev)
{
    if (spy == NULL || spy->count >= NINLIL_R7_FRAG_SPY_MAX) {
        return;
    }
    spy->events[spy->count++] = ev;
}

void ninlil_r7_frag_l1w1_reset(ninlil_r7_frag_l1w1_bus_t *bus)
{
    if (bus == NULL) {
        return;
    }
    memset(bus, 0, sizeof(*bus));
}

int32_t ninlil_r7_frag_l1w1_emit(
    ninlil_r7_frag_l1w1_bus_t *bus,
    ninlil_r7_frag_spy_t *spy,
    uint8_t kind,
    uint64_t owner,
    uint64_t candidate,
    uint8_t d0,
    uint8_t d1)
{
    if (kind < 1u || kind > 7u) {
        return 1;
    }
    if (bus != NULL && bus->count < NINLIL_R7_FRAG_SPY_MAX) {
        ninlil_r7_frag_l1w1_event_t *e = &bus->log[bus->count++];
        e->event_schema = 1u;
        e->event_kind = kind;
        e->owner_token = owner;
        e->candidate_token = candidate;
        e->detail0 = d0;
        e->detail1 = d1;
    }
    if (spy != NULL) {
        uint8_t sp = 0u;
        if (kind == NINLIL_R7_FRAG_EV_STAMP_FIELDS) {
            sp = NINLIL_R7_FRAG_SPY_W1_STAMP;
        } else if (kind == NINLIL_R7_FRAG_EV_FRAME_READY) {
            sp = NINLIL_R7_FRAG_SPY_W1_FRAME_READY;
        } else if (kind == NINLIL_R7_FRAG_EV_SEAL_FAIL) {
            sp = NINLIL_R7_FRAG_SPY_W1_SEAL_FAIL;
        } else if (kind == NINLIL_R7_FRAG_EV_TX_RESULT) {
            sp = NINLIL_R7_FRAG_SPY_L1_TX_RESULT;
        }
        if (sp != 0u) {
            ninlil_r7_frag_spy_push(spy, sp);
        }
    }
    return 0;
}

static int digest_sha(
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t *frame,
    size_t frame_len,
    uint8_t out32[32])
{
    if (crypto == NULL || crypto->sha256 == NULL || frame == NULL
        || out32 == NULL) {
        return 1;
    }
    return ninlil_r7_crypto_sha256(crypto, frame, frame_len, out32)
            == NINLIL_R7_CRYPTO_OK
        ? 0
        : 1;
}

static void orch_held_clear(ninlil_r7_frag_orch_t *orch)
{
    if (orch == NULL) {
        return;
    }
    orch->held_live = 0u;
    orch->held_queued = 0u;
    orch->held_auth = 0u;
    orch->held_permit_sequence = 0u;
    orch->held_outer_len = 0u;
    memset(orch->held_outer_digest, 0, sizeof(orch->held_outer_digest));
    memset(orch->held_outer, 0, sizeof(orch->held_outer));
    memset(&orch->held_permit, 0, sizeof(orch->held_permit));
}

static void orch_held_store(
    ninlil_r7_frag_orch_t *orch,
    uint64_t auth,
    uint8_t queued,
    const uint8_t dig[32],
    const uint8_t *outer,
    size_t outer_len,
    const ninlil_radio_hal_permit_snapshot_t *permit)
{
    orch_held_clear(orch);
    orch->held_live = 1u;
    orch->held_queued = queued;
    orch->held_auth = auth;
    orch->held_permit_sequence = permit->permit_sequence;
    orch->held_outer_len = (uint32_t)outer_len;
    memcpy(orch->held_outer_digest, dig, 32u);
    if (outer_len > 0u && outer_len <= sizeof(orch->held_outer)) {
        memcpy(orch->held_outer, outer, outer_len);
    }
    orch->held_permit = *permit;
}

/* Terminal complete: coordinator + R5 only — never on hold/queued. */
static void orch_coord_finish(
    ninlil_r7_frag_orch_t *orch,
    uint64_t auth,
    uint64_t seq)
{
    (void)ninlil_r7_frag_issue_coordinator_complete(
        &orch->issue_coordinator, auth, seq, NULL);
    ninlil_r7_r5_issue_registry_release(&orch->issue_registry, seq);
    orch_held_clear(orch);
}

int32_t ninlil_r7_frag_orch_outer_tx(
    ninlil_r7_frag_orch_t *orch,
    uint64_t owner_token,
    uint64_t candidate_token,
    const uint8_t *outer_frame,
    size_t outer_len)
{
    ninlil_pcp_issue_request_t req;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t view;
    ninlil_radio_hal_error_t err;
    ninlil_radio_hal_status_t hst;
    ninlil_pcp_error_t perr;
    ninlil_pcp_status_t pst;
    ninlil_radio_hal_live_binding_t hlive;
    uint8_t outer_digest[32];
    uint64_t auth;
    int32_t cst;

    if (orch == NULL || outer_frame == NULL || outer_len == 0u
        || outer_len > 256u || owner_token == 0u || candidate_token == 0u) {
        return 1;
    }
    if (orch->pcp == NULL || orch->hal == NULL || orch->crypto == NULL
        || orch->crypto->sha256 == NULL || !orch->live_valid
        || !orch->clock_trusted || orch->clock_uncertain) {
        return 2;
    }
    auth = (uint64_t)(uintptr_t)orch->pcp;
    if (digest_sha(orch->crypto, outer_frame, outer_len, outer_digest) != 0) {
        return 2;
    }

    /*
     * Exact-object resume: same outer digest held under coordinator.
     * Never re-issue; never local-release issued identity.
     */
    if (orch->held_live != 0u
        && orch->held_auth == auth
        && orch->held_outer_len == (uint32_t)outer_len
        && memcmp(orch->held_outer_digest, outer_digest, 32u) == 0
        && ninlil_r7_frag_issue_coordinator_outer_matches(
            &orch->issue_coordinator, auth, orch->held_permit_sequence,
            outer_digest,
            (uint32_t)outer_len)) {
        if (orch->held_queued != 0u
            && !ninlil_r7_frag_issue_coordinator_is_head(
                &orch->issue_coordinator, auth,
                orch->held_permit_sequence)) {
            return 6; /* still queued */
        }
        if (ninlil_r7_frag_issue_coordinator_slot_state(
                &orch->issue_coordinator, auth,
                orch->held_permit_sequence)
            == NINLIL_R7_COORD_ST_HELD) {
            cst = ninlil_r7_frag_issue_coordinator_resume_tx(
                &orch->issue_coordinator, auth,
                orch->held_permit_sequence);
        } else {
            cst = ninlil_r7_frag_issue_coordinator_begin_tx(
                &orch->issue_coordinator, auth,
                orch->held_permit_sequence);
        }
        if (cst != NINLIL_R7_COORD_OK) {
            return 6;
        }
        memset(&view, 0, sizeof(view));
        view.bytes = outer_frame;
        view.length = (uint32_t)outer_len;
        memset(&err, 0, sizeof(err));
        ninlil_r7_frag_spy_push(orch->spy, NINLIL_R7_FRAG_SPY_R1_TX);
        hst = ninlil_radio_hal_transmit_with_permit(
            orch->hal, &orch->held_permit, &view, &err);
        if (hst == NINLIL_RADIO_HAL_NOT_BEFORE
            || err.reason == NINLIL_RADIO_HAL_REASON_NOT_BEFORE
            || hst == NINLIL_RADIO_HAL_BUSY) {
            (void)ninlil_r7_frag_issue_coordinator_hold_retry(
                &orch->issue_coordinator, auth,
                orch->held_permit_sequence);
            orch->held_queued = 0u;
            (void)ninlil_r7_frag_l1w1_emit(
                orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
                candidate_token, (uint8_t)hst, 0u);
            return (int32_t)hst;
        }
        if (hst == NINLIL_RADIO_HAL_EXPIRED
            || err.reason == NINLIL_RADIO_HAL_REASON_EXPIRED
            || hst == NINLIL_RADIO_HAL_SEQ_EXHAUSTED) {
            orch_coord_finish(orch, auth, orch->held_permit_sequence);
            (void)ninlil_r7_frag_l1w1_emit(
                orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
                candidate_token, (uint8_t)hst, 0u);
            return (int32_t)hst;
        }
        if (hst == NINLIL_RADIO_HAL_OK) {
            orch_coord_finish(orch, auth, orch->held_permit_sequence);
            (void)ninlil_r7_frag_l1w1_emit(
                orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
                candidate_token, 0u, 0u);
            return 0;
        }
        /* Other failures: complete under authority SM (no silent local drop). */
        orch_coord_finish(orch, auth, orch->held_permit_sequence);
        (void)ninlil_r7_frag_l1w1_emit(
            orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
            candidate_token, (uint8_t)hst, 0u);
        return (int32_t)hst;
    }

    if (orch->held_live != 0u) {
        /* Different outer while held: refuse dual-issue. */
        return 6;
    }

    if (ninlil_r7_frag_l1w1_emit(
            orch->bus, orch->spy, NINLIL_R7_FRAG_EV_STAMP_FIELDS, owner_token,
            candidate_token, 2u, 0u)
        != 0) {
        return 3;
    }
    if (ninlil_r7_frag_l1w1_emit(
            orch->bus, orch->spy, NINLIL_R7_FRAG_EV_FRAME_READY, owner_token,
            candidate_token, 2u, 0u)
        != 0) {
        return 3;
    }

    memset(&req, 0, sizeof(req));
    req.hardware_profile_id = orch->live.hardware_profile_id;
    req.hardware_profile_rev = orch->live.hardware_profile_rev;
    req.regulatory_profile_id = orch->live.regulatory_profile_id;
    req.regulatory_profile_rev = orch->live.regulatory_profile_rev;
    req.site_assignment_id = orch->live.site_assignment_id;
    req.site_assignment_rev = orch->live.site_assignment_rev;
    req.site_assignment_epoch = orch->live.site_assignment_epoch;
    req.transmitter_id = orch->live.transmitter_id;
    req.channel_id = orch->live.channel_id;
    req.phy = orch->live.phy;
    req.max_airtime_us = (orch->live.max_airtime_us > 0u
            && orch->live.max_airtime_us < 50000u)
        ? orch->live.max_airtime_us
        : 50000u;
    if (req.max_airtime_us > orch->live.max_airtime_us
        && orch->live.max_airtime_us > 0u) {
        req.max_airtime_us = orch->live.max_airtime_us;
    }
    req.frame_byte_length = (uint32_t)outer_len;
    req.frame_digest_algorithm = 1u;
    req.not_before_ms = 0u;
    req.expiry_ms = UINT64_MAX;
    memcpy(req.frame_digest, outer_digest, 32u);

    memset(&hlive, 0, sizeof(hlive));
    hlive.hardware_profile_id = orch->live.hardware_profile_id;
    hlive.hardware_profile_rev = orch->live.hardware_profile_rev;
    hlive.regulatory_profile_id = orch->live.regulatory_profile_id;
    hlive.regulatory_profile_rev = orch->live.regulatory_profile_rev;
    hlive.site_assignment_id = orch->live.site_assignment_id;
    hlive.site_assignment_rev = orch->live.site_assignment_rev;
    hlive.site_assignment_epoch = orch->live.site_assignment_epoch;
    hlive.transmitter_id = orch->live.transmitter_id;
    hlive.channel_id = orch->live.channel_id;
    hlive.phy = orch->live.phy;
    hlive.max_airtime_us = req.max_airtime_us;
    {
        ninlil_radio_hal_error_t le;
        memset(&le, 0, sizeof(le));
        if (ninlil_radio_hal_set_live_binding(orch->hal, &hlive, &le)
            != NINLIL_RADIO_HAL_OK) {
            return 5;
        }
    }

    ninlil_r7_frag_spy_push(orch->spy, NINLIL_R7_FRAG_SPY_R2_ISSUE);
    memset(&permit, 0, sizeof(permit));
    memset(&perr, 0, sizeof(perr));
    {
        ninlil_r7_checked_issue_result_t cir;
        int32_t ist;
        ist = ninlil_r7_private_issue_checked_with_owner_epoch(
            orch->pcp, &orch->live, orch->live.site_assignment_epoch, &req,
            &orch->issue_registry, &permit, &cir);
        pst = cir.pcp_status;
        perr = cir.pcp_error;
        (void)perr;
        if (ist != NINLIL_R7_CHECKED_ISSUE_OK || cir.issued == 0u
            || pst != NINLIL_PCP_OK) {
            return 4;
        }
        if (cir.sample_valid != 0u && cir.sample.trusted != 0u) {
            orch->trusted_now_ms = cir.sample.now_ms;
        }
    }

    {
        ninlil_r7_coord_admit_t admit;
        memset(&admit, 0, sizeof(admit));
        admit.authority_token = auth;
        admit.permit_sequence = permit.permit_sequence;
        admit.bind_token = (uintptr_t)orch;
        admit.outer_len = (uint32_t)outer_len;
        admit.issue_now_ms = orch->trusted_now_ms;
        memcpy(admit.outer_digest, outer_digest, 32u);
        cst = ninlil_r7_frag_issue_coordinator_admit(
            &orch->issue_coordinator, &admit);
        if (cst == NINLIL_R7_COORD_QUEUED) {
            /* Retain issued Permit+outer; no TX; no local release. */
            orch_held_store(
                orch, auth, 1u, outer_digest, outer_frame, outer_len, &permit);
            (void)ninlil_r7_frag_l1w1_emit(
                orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
                candidate_token, (uint8_t)NINLIL_R7_L1_FIFO_OUT_OF_ORDER, 0u);
            return 6;
        }
        if (cst != NINLIL_R7_COORD_OK) {
            /* Cannot admit: authority-wide revoke (issued orphan), not silent. */
            ninlil_pcp_error_t rev;
            memset(&rev, 0, sizeof(rev));
            (void)ninlil_pcp_revoke_all_outstanding(orch->pcp, &rev);
            ninlil_r7_frag_issue_coordinator_complete_all_authority(
                &orch->issue_coordinator, auth);
            ninlil_r7_r5_issue_registry_release(
                &orch->issue_registry, permit.permit_sequence);
            return 6;
        }
        if (ninlil_r7_frag_issue_coordinator_begin_tx(
                &orch->issue_coordinator, auth, permit.permit_sequence)
            != NINLIL_R7_COORD_OK) {
            /* Keep coordinator ownership; store held for resume. */
            orch_held_store(
                orch, auth, 1u, outer_digest, outer_frame, outer_len, &permit);
            return 6;
        }
        memset(&view, 0, sizeof(view));
        view.bytes = outer_frame;
        view.length = (uint32_t)outer_len;
        memset(&err, 0, sizeof(err));
        ninlil_r7_frag_spy_push(orch->spy, NINLIL_R7_FRAG_SPY_R1_TX);
        hst = ninlil_radio_hal_transmit_with_permit(
            orch->hal, &permit, &view, &err);
        if (hst == NINLIL_RADIO_HAL_NOT_BEFORE
            || err.reason == NINLIL_RADIO_HAL_REASON_NOT_BEFORE
            || hst == NINLIL_RADIO_HAL_BUSY) {
            (void)ninlil_r7_frag_issue_coordinator_hold_retry(
                &orch->issue_coordinator, auth, permit.permit_sequence);
            orch_held_store(
                orch, auth, 0u, outer_digest, outer_frame, outer_len, &permit);
            (void)ninlil_r7_frag_l1w1_emit(
                orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
                candidate_token, (uint8_t)hst, 0u);
            return (int32_t)hst;
        }
        if (hst == NINLIL_RADIO_HAL_EXPIRED
            || err.reason == NINLIL_RADIO_HAL_REASON_EXPIRED
            || hst == NINLIL_RADIO_HAL_SEQ_EXHAUSTED) {
            orch_coord_finish(orch, auth, permit.permit_sequence);
            (void)ninlil_r7_frag_l1w1_emit(
                orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
                candidate_token, (uint8_t)hst, 0u);
            return (int32_t)hst;
        }
        orch_coord_finish(orch, auth, permit.permit_sequence);
        (void)ninlil_r7_frag_l1w1_emit(
            orch->bus, orch->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
            candidate_token, (uint8_t)hst, 0u);
        return (hst == NINLIL_RADIO_HAL_OK) ? 0 : (int32_t)hst;
    }
}

int32_t ninlil_r7_frag_orch_n6_tx_burn(
    ninlil_r7_frag_orch_t *orch,
    ninlil_n6_handle_t handle,
    uint8_t lane_kind,
    ninlil_n6_tx_lease_t *out_lease)
{
    ninlil_n6_status_t st;
    if (orch == NULL || orch->n6 == NULL || out_lease == NULL) {
        return (int32_t)NINLIL_N6_INVALID_ARGUMENT;
    }
    ninlil_r7_frag_spy_push(orch->spy, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    st = ninlil_n6_tx_burn(orch->n6, handle, lane_kind, out_lease);
    return (int32_t)st;
}

int32_t ninlil_r7_frag_orch_n6_rx_precheck(
    ninlil_r7_frag_orch_t *orch,
    ninlil_n6_handle_t handle,
    uint8_t lane_kind,
    uint64_t counter,
    ninlil_n6_rx_ticket_t *out_ticket)
{
    ninlil_n6_status_t st;
    if (orch == NULL || orch->n6 == NULL || out_ticket == NULL) {
        return (int32_t)NINLIL_N6_INVALID_ARGUMENT;
    }
    ninlil_r7_frag_spy_push(orch->spy, NINLIL_R7_FRAG_SPY_N6_RX_PRE);
    st = ninlil_n6_rx_precheck(orch->n6, handle, lane_kind, counter, out_ticket);
    return (int32_t)st;
}

int32_t ninlil_r7_frag_orch_n6_rx_admit(
    ninlil_r7_frag_orch_t *orch,
    ninlil_n6_rx_ticket_t *ticket)
{
    ninlil_n6_status_t st;
    if (orch == NULL || orch->n6 == NULL || ticket == NULL) {
        return (int32_t)NINLIL_N6_INVALID_ARGUMENT;
    }
    ninlil_r7_frag_spy_push(orch->spy, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
    st = ninlil_n6_rx_admit_after_aead(orch->n6, ticket);
    return (int32_t)st;
}
