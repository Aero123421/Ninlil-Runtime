/* SPDX-License-Identifier: Apache-2.0 */
/*
 * R7 private R5→R2 checked-issue (docs/30 §15.3.1–15.3.2).
 * Process-local; not public ABI.
 *
 * Sole sample owner: ninlil_r2_private_sample_authority_clock → pin accepted
 * class-D S → ninlil_pcp_issue (no re-sample). R5/L1 never sample or inject S.
 * CLOCK_FAULT durable F_c only via ninlil_r2_private_commit_clock_fault_fence.
 */

#include "r7_frag_checked_issue.h"

#include "r7_r2_authority_clock.h"

#include "ninlil/version.h"

#include <string.h>

static void axes_precheck_zero(ninlil_r7_checked_issue_result_t *r)
{
    r->business_mutation = NINLIL_R7_BUSINESS_ZERO;
    r->clock_fence_mutation = NINLIL_R7_META_ZERO;
    r->txn_provenance = NINLIL_R7_PRECHECK_ZERO;
}

static void result_init(ninlil_r7_checked_issue_result_t *r)
{
    memset(r, 0, sizeof(*r));
    r->result_catalog = NINLIL_R7_RESULT_CATALOG_R2_PCP;
    r->stage = NINLIL_PCP_STAGE_ISSUE;
    axes_precheck_zero(r);
    r->l1_class = NINLIL_R7_L1_TERMINAL_UNISSUED;
}

void ninlil_r7_r5_issue_registry_init(ninlil_r7_r5_issue_registry_t *reg)
{
    if (reg == NULL) {
        return;
    }
    memset(reg, 0, sizeof(*reg));
}

void ninlil_r7_r5_issue_registry_clear(ninlil_r7_r5_issue_registry_t *reg)
{
    if (reg == NULL) {
        return;
    }
    memset(reg->live, 0, sizeof(reg->live));
    memset(reg->permit_sequence, 0, sizeof(reg->permit_sequence));
    memset(reg->owner_epoch, 0, sizeof(reg->owner_epoch));
    memset(reg->issue_now_ms, 0, sizeof(reg->issue_now_ms));
    reg->count = 0u;
}

void ninlil_r7_r5_issue_registry_fini(ninlil_r7_r5_issue_registry_t *reg)
{
    ninlil_r7_r5_issue_registry_init(reg);
}

size_t ninlil_r7_r5_issue_registry_count(const ninlil_r7_r5_issue_registry_t *reg)
{
    size_t i;
    size_t n = 0u;
    if (reg == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_R7_R5_ISSUE_REGISTRY_CAP; i++) {
        if (reg->live[i] != 0u) {
            n++;
        }
    }
    return n;
}

void ninlil_r7_r5_issue_registry_release(
    ninlil_r7_r5_issue_registry_t *reg,
    uint64_t permit_sequence)
{
    size_t i;
    if (reg == NULL || permit_sequence == 0u) {
        return;
    }
    for (i = 0u; i < NINLIL_R7_R5_ISSUE_REGISTRY_CAP; i++) {
        if (reg->live[i] != 0u
            && reg->permit_sequence[i] == permit_sequence) {
            reg->live[i] = 0u;
            reg->permit_sequence[i] = 0u;
            reg->owner_epoch[i] = 0u;
            reg->issue_now_ms[i] = 0u;
            if (reg->count > 0u) {
                reg->count--;
            }
            return;
        }
    }
}

static int32_t r5_registry_insert(
    ninlil_r7_r5_issue_registry_t *reg,
    uint64_t permit_sequence,
    uint64_t owner_epoch,
    uint64_t issue_now_ms)
{
    size_t i;
    if (reg == NULL || permit_sequence == 0u) {
        return NINLIL_R7_CHECKED_ISSUE_REGISTRY;
    }
    for (i = 0u; i < NINLIL_R7_R5_ISSUE_REGISTRY_CAP; i++) {
        if (reg->live[i] != 0u
            && reg->permit_sequence[i] == permit_sequence) {
            return NINLIL_R7_CHECKED_ISSUE_REGISTRY; /* dual-truth */
        }
    }
    for (i = 0u; i < NINLIL_R7_R5_ISSUE_REGISTRY_CAP; i++) {
        if (reg->live[i] == 0u) {
            reg->live[i] = 1u;
            reg->permit_sequence[i] = permit_sequence;
            reg->owner_epoch[i] = owner_epoch;
            reg->issue_now_ms[i] = issue_now_ms;
            if (reg->count < NINLIL_R7_R5_ISSUE_REGISTRY_CAP) {
                reg->count++;
            }
            return NINLIL_R7_CHECKED_ISSUE_OK;
        }
    }
    return NINLIL_R7_CHECKED_ISSUE_REGISTRY;
}

int32_t ninlil_r7_default_validation_cb(
    void *user,
    const ninlil_r7_class_d_sample_t *S,
    const ninlil_r7_validation_context_t *static_plan,
    ninlil_r7_issue_window_t *out_window)
{
    uint64_t exp;
    (void)user;
    if (out_window != NULL) {
        memset(out_window, 0, sizeof(*out_window));
    }
    if (S == NULL || static_plan == NULL || out_window == NULL) {
        return NINLIL_R7_VAL_RECONCILE;
    }
    if (S->fence_clock != 0u || S->trusted == 0u) {
        return NINLIL_R7_VAL_RECONCILE;
    }
    /*
     * owner_epoch is site-assignment authority (R5-gated vs live).
     * S.epoch is class-D clock epoch — not interchangeable with assignment.
     * Do not VAL_AUTHORITY on assignment≠clock; that was the L1 inject path.
     */
    if (static_plan->owner_epoch != 0u
        && static_plan->live.site_assignment_epoch != 0u
        && static_plan->owner_epoch != static_plan->live.site_assignment_epoch) {
        return NINLIL_R7_VAL_AUTHORITY;
    }
    if (static_plan->max_airtime_us == 0u
        || static_plan->frame_byte_length == 0u) {
        return NINLIL_R7_VAL_TERMINAL;
    }
    /* not_before = S.now; expiry = min(owner_deadline, S.now+60000). */
    out_window->not_before_ms = S->now_ms;
    exp = S->now_ms;
    if (exp <= UINT64_MAX - 60000u) {
        exp = exp + 60000u;
    } else {
        exp = UINT64_MAX;
    }
    if (static_plan->owner_deadline_ms != 0u
        && static_plan->owner_deadline_ms < exp) {
        exp = static_plan->owner_deadline_ms;
    }
    if (exp <= out_window->not_before_ms) {
        return NINLIL_R7_VAL_RECONCILE;
    }
    out_window->expiry_ms = exp;
    out_window->valid = 1u;
    return NINLIL_R7_VAL_OK;
}

/*
 * Carry exact pcp_error stage/reason into the result axis. Never invent
 * collapsed reason codes that diverge from authority (e.g. magic 11).
 */
static void apply_pcp_error_axis(ninlil_r7_checked_issue_result_t *r)
{
    if (r == NULL) {
        return;
    }
    r->stage = r->pcp_error.stage;
    r->reason = r->pcp_error.reason;
    if (r->stage == 0u && r->pcp_error.status != NINLIL_PCP_OK) {
        r->stage = NINLIL_PCP_STAGE_ISSUE;
    }
}

static void map_val_to_result(
    int32_t val,
    ninlil_r7_checked_issue_result_t *r)
{
    axes_precheck_zero(r);
    r->stage = NINLIL_PCP_STAGE_ISSUE;
    if (val == NINLIL_R7_VAL_TERMINAL) {
        r->exact_status = NINLIL_PCP_STRUCT;
        r->pcp_status = NINLIL_PCP_STRUCT;
        r->reason = NINLIL_PCP_REASON_STRUCT_INVALID;
        r->pcp_error.status = NINLIL_PCP_STRUCT;
        r->pcp_error.stage = NINLIL_PCP_STAGE_ISSUE;
        r->pcp_error.reason = NINLIL_PCP_REASON_STRUCT_INVALID;
        r->l1_class = NINLIL_R7_L1_TERMINAL_UNISSUED;
        return;
    }
    if (val == NINLIL_R7_VAL_RETRYABLE) {
        r->exact_status = NINLIL_PCP_CAPACITY;
        r->pcp_status = NINLIL_PCP_CAPACITY;
        r->reason = NINLIL_PCP_REASON_CAPACITY;
        r->pcp_error.status = NINLIL_PCP_CAPACITY;
        r->pcp_error.stage = NINLIL_PCP_STAGE_ISSUE;
        r->pcp_error.reason = NINLIL_PCP_REASON_CAPACITY;
        r->l1_class = NINLIL_R7_L1_RETRYABLE_UNISSUED;
        return;
    }
    if (val == NINLIL_R7_VAL_AUTHORITY) {
        r->exact_status = NINLIL_PCP_PROFILE_MISMATCH;
        r->pcp_status = NINLIL_PCP_PROFILE_MISMATCH;
        r->reason = NINLIL_PCP_REASON_PROFILE_MISMATCH;
        r->pcp_error.status = NINLIL_PCP_PROFILE_MISMATCH;
        r->pcp_error.stage = NINLIL_PCP_STAGE_ISSUE;
        r->pcp_error.reason = NINLIL_PCP_REASON_PROFILE_MISMATCH;
        r->l1_class = NINLIL_R7_L1_AUTHORITY_DIVERGENCE;
        return;
    }
    /* VAL_RECONCILE or unknown */
    r->exact_status = NINLIL_PCP_INVALID_STATE;
    r->pcp_status = NINLIL_PCP_INVALID_STATE;
    r->reason = NINLIL_PCP_REASON_CONTRACT;
    r->pcp_error.status = NINLIL_PCP_INVALID_STATE;
    r->pcp_error.stage = NINLIL_PCP_STAGE_ISSUE;
    r->pcp_error.reason = NINLIL_PCP_REASON_CONTRACT;
    r->l1_class = NINLIL_R7_L1_RECONCILE_REQUIRED;
}

static void map_pcp_to_axes(
    ninlil_pcp_status_t pst,
    ninlil_r7_checked_issue_result_t *r)
{
    r->exact_status = pst;
    r->pcp_status = pst;
    /* Always surface exact stage/reason from authority error (no collapse). */
    apply_pcp_error_axis(r);
    if (pst == NINLIL_PCP_OK) {
        r->business_mutation = NINLIL_R7_ISSUED_FULL;
        r->clock_fence_mutation = NINLIL_R7_META_ZERO;
        r->txn_provenance = NINLIL_R7_ISSUED_COMMITTED;
        r->l1_class = NINLIL_R7_L1_OK_ISSUED;
        r->issued = 1u;
        return;
    }
    r->business_mutation = NINLIL_R7_BUSINESS_ZERO;
    r->clock_fence_mutation = NINLIL_R7_META_ZERO;
    r->txn_provenance = NINLIL_R7_PRECHECK_ZERO;
    r->issued = 0u;
    if (pst == NINLIL_PCP_CLOCK_UNCERTAIN) {
        r->l1_class = NINLIL_R7_L1_CLOCK_PATH_DROP;
        return;
    }
    if (pst == NINLIL_PCP_CLOCK_FAULT) {
        /* Durable fence claimed only when F_C committed (authority sticky). */
        r->clock_fence_mutation = NINLIL_R7_F_C_FULL;
        r->txn_provenance = NINLIL_R7_CLOCK_FENCE_COMMITTED;
        r->l1_class = NINLIL_R7_L1_CLOCK_PATH_DROP;
        return;
    }
    if (pst == NINLIL_PCP_CAPACITY || pst == NINLIL_PCP_BUSY
        || pst == NINLIL_PCP_BUSY_OUTSTANDING) {
        r->l1_class = NINLIL_R7_L1_RETRYABLE_UNISSUED;
        return;
    }
    if (pst == NINLIL_PCP_BUSY_REENTRY) {
        r->l1_class = NINLIL_R7_L1_RETRYABLE_PIPELINE;
        return;
    }
    if (pst == NINLIL_PCP_ALIAS) {
        r->l1_class = NINLIL_R7_L1_RETRYABLE_PIPELINE;
        return;
    }
    if (pst == NINLIL_PCP_PROFILE_MISMATCH) {
        r->l1_class = NINLIL_R7_L1_AUTHORITY_DIVERGENCE;
        return;
    }
    if (pst == NINLIL_PCP_COMMIT_UNKNOWN || pst == NINLIL_PCP_STORAGE_FENCE) {
        r->business_mutation = NINLIL_R7_BUSINESS_AMBIGUOUS;
        r->txn_provenance = NINLIL_R7_PROV_AMBIGUOUS;
        r->l1_class = NINLIL_R7_L1_RECONCILE_REQUIRED;
        return;
    }
    if (pst == NINLIL_PCP_STORAGE_IO) {
        /* Distinct from COMMIT_UNKNOWN: I/O fence, reconcile not dual-truth. */
        r->business_mutation = NINLIL_R7_BUSINESS_AMBIGUOUS;
        r->txn_provenance = NINLIL_R7_PROV_AMBIGUOUS;
        r->l1_class = NINLIL_R7_L1_RECONCILE_REQUIRED;
        return;
    }
    if (pst == NINLIL_PCP_CORRUPT_FENCE) {
        r->l1_class = NINLIL_R7_L1_OPERATOR_RECOVERY_REQUIRED;
        return;
    }
    if (pst == NINLIL_PCP_INVALID_STATE) {
        /* Prefer W1 repair when reason is contract/epoch; else transition. */
        if (r->reason == NINLIL_PCP_REASON_CONTRACT
            || r->reason == NINLIL_PCP_REASON_EPOCH_MISMATCH) {
            r->l1_class = NINLIL_R7_L1_EPOCH_W1_REPAIR;
        } else {
            r->l1_class = NINLIL_R7_L1_EPOCH_TRANSITION_REQUIRED;
        }
        return;
    }
    if (pst == NINLIL_PCP_INVALID_ARGUMENT || pst == NINLIL_PCP_STRUCT
        || pst == NINLIL_PCP_SEQ_EXHAUSTED) {
        r->l1_class = NINLIL_R7_L1_TERMINAL_UNISSUED;
        return;
    }
    /* Unknown status: operator recovery — do not invent retryable success. */
    r->l1_class = NINLIL_R7_L1_OPERATOR_RECOVERY_REQUIRED;
}

static uint64_t epoch_lo_from_sample(const ninlil_time_sample_t *ts)
{
    uint64_t lo = 0u;
    size_t i;
    if (ts == NULL) {
        return 0u;
    }
    /* LE first 8 bytes of epoch id (portable host interpretation). */
    for (i = 0u; i < 8u; i++) {
        lo |= ((uint64_t)ts->clock_epoch_id.bytes[i]) << (8u * i);
    }
    return lo;
}

static void r2_clear_pin(ninlil_pcp_t *pcp)
{
    if (pcp != NULL) {
        ninlil_pcp_issue_sample_clear(pcp);
    }
}

int32_t ninlil_r2_private_issue_checked_owner_epoch(
    ninlil_pcp_t *pcp,
    const ninlil_r7_validation_context_t *static_plan,
    ninlil_r7_validation_cb_fn validation_cb,
    void *validation_user,
    ninlil_radio_hal_permit_snapshot_t *out_permit,
    ninlil_r7_checked_issue_result_t *out_result)
{
    ninlil_r7_issue_window_t win;
    ninlil_pcp_issue_request_t req;
    ninlil_pcp_status_t pst;
    ninlil_pcp_error_t perr;
    ninlil_time_sample_t ts;
    ninlil_r7_class_d_sample_t S;
    int32_t val;

    if (out_result != NULL) {
        result_init(out_result);
    }
    if (out_permit != NULL) {
        memset(out_permit, 0, sizeof(*out_permit));
    }
    if (pcp == NULL || static_plan == NULL || validation_cb == NULL
        || out_permit == NULL || out_result == NULL) {
        if (out_result != NULL) {
            out_result->exact_status = NINLIL_PCP_INVALID_ARGUMENT;
            out_result->pcp_status = NINLIL_PCP_INVALID_ARGUMENT;
            out_result->l1_class = NINLIL_R7_L1_TERMINAL_UNISSUED;
        }
        return NINLIL_R7_CHECKED_ISSUE_INVALID;
    }

    /* (3) R2 samples S exactly once and pins for pcp_issue. */
    memset(&ts, 0, sizeof(ts));
    memset(&perr, 0, sizeof(perr));
    pst = ninlil_pcp_issue_sample_pin(pcp, &ts, &perr);
    out_result->pcp_error = perr;

    memset(&S, 0, sizeof(S));
    if (pst == NINLIL_PCP_OK) {
        S.now_ms = ts.now_ms;
        S.epoch_id_lo = epoch_lo_from_sample(&ts);
        S.trusted = 1u;
        S.fence_clock = 0u;
        out_result->sample_valid = 1u;
        out_result->sample = S;
    } else if (pst == NINLIL_PCP_CLOCK_UNCERTAIN) {
        S.now_ms = ts.now_ms;
        S.epoch_id_lo = epoch_lo_from_sample(&ts);
        S.trusted = 0u;
        S.fence_clock = 0u;
        out_result->sample_valid = 1u;
        out_result->sample = S;
        /* Gate before validation_cb; drop pin — no RW issue. */
        r2_clear_pin(pcp);
        out_result->exact_status = NINLIL_PCP_CLOCK_UNCERTAIN;
        out_result->pcp_status = NINLIL_PCP_CLOCK_UNCERTAIN;
        out_result->l1_class = NINLIL_R7_L1_CLOCK_PATH_DROP;
        return NINLIL_R7_CHECKED_ISSUE_R2;
    } else if (pst == NINLIL_PCP_CLOCK_FAULT) {
        S.fence_clock = 1u;
        S.trusted = 0u;
        out_result->sample_valid = 1u;
        out_result->sample = S;
        r2_clear_pin(pcp);
        out_result->exact_status = NINLIL_PCP_CLOCK_FAULT;
        out_result->pcp_status = NINLIL_PCP_CLOCK_FAULT;
        apply_pcp_error_axis(out_result);
        out_result->clock_fence_mutation = NINLIL_R7_F_C_FULL;
        out_result->txn_provenance = NINLIL_R7_CLOCK_FENCE_COMMITTED;
        out_result->l1_class = NINLIL_R7_L1_CLOCK_PATH_DROP;
        return NINLIL_R7_CHECKED_ISSUE_R2;
    } else {
        r2_clear_pin(pcp);
        map_pcp_to_axes(pst, out_result);
        return NINLIL_R7_CHECKED_ISSUE_R2;
    }

    /* (4) Sample/epoch gates (trusted class-D only proceeds). */
    if (S.fence_clock != 0u) {
        r2_clear_pin(pcp);
        out_result->exact_status = NINLIL_PCP_CLOCK_FAULT;
        out_result->pcp_status = NINLIL_PCP_CLOCK_FAULT;
        out_result->pcp_error.status = NINLIL_PCP_CLOCK_FAULT;
        out_result->pcp_error.stage = NINLIL_PCP_STAGE_ISSUE;
        out_result->pcp_error.reason = NINLIL_PCP_REASON_CLOCK_FAULT;
        apply_pcp_error_axis(out_result);
        out_result->clock_fence_mutation = NINLIL_R7_F_C_FULL;
        out_result->txn_provenance = NINLIL_R7_CLOCK_FENCE_COMMITTED;
        out_result->l1_class = NINLIL_R7_L1_CLOCK_PATH_DROP;
        return NINLIL_R7_CHECKED_ISSUE_R2;
    }
    if (S.trusted == 0u) {
        r2_clear_pin(pcp);
        out_result->exact_status = NINLIL_PCP_CLOCK_UNCERTAIN;
        out_result->pcp_status = NINLIL_PCP_CLOCK_UNCERTAIN;
        out_result->l1_class = NINLIL_R7_L1_CLOCK_PATH_DROP;
        return NINLIL_R7_CHECKED_ISSUE_R2;
    }
    /* Epoch: when owner_epoch set, require match to assignment epoch in plan. */
    if (static_plan->owner_epoch != 0u
        && static_plan->live.site_assignment_epoch != 0u
        && static_plan->owner_epoch
            != static_plan->live.site_assignment_epoch) {
        r2_clear_pin(pcp);
        out_result->exact_status = NINLIL_PCP_PROFILE_MISMATCH;
        out_result->pcp_status = NINLIL_PCP_PROFILE_MISMATCH;
        out_result->l1_class = NINLIL_R7_L1_AUTHORITY_DIVERGENCE;
        return NINLIL_R7_CHECKED_ISSUE_R2;
    }

    /* (5) Trusted class-D only: validation_cb — no clock sample inside. */
    memset(&win, 0, sizeof(win));
    val = validation_cb(validation_user, &S, static_plan, &win);
    if (val != NINLIL_R7_VAL_OK || win.valid == 0u
        || win.expiry_ms <= win.not_before_ms) {
        if (val == NINLIL_R7_VAL_OK) {
            val = NINLIL_R7_VAL_RECONCILE;
        }
        r2_clear_pin(pcp);
        map_val_to_result(val, out_result);
        return NINLIL_R7_CHECKED_ISSUE_R2;
    }

    /* (6) Single RW issue — consumes sticky pin (same S; no re-sample). */
    memset(&req, 0, sizeof(req));
    req.hardware_profile_id = static_plan->live.hardware_profile_id;
    req.hardware_profile_rev = static_plan->live.hardware_profile_rev;
    req.regulatory_profile_id = static_plan->live.regulatory_profile_id;
    req.regulatory_profile_rev = static_plan->live.regulatory_profile_rev;
    req.site_assignment_id = static_plan->live.site_assignment_id;
    req.site_assignment_rev = static_plan->live.site_assignment_rev;
    req.site_assignment_epoch = static_plan->live.site_assignment_epoch;
    req.transmitter_id = static_plan->live.transmitter_id;
    req.channel_id = static_plan->live.channel_id;
    req.phy = static_plan->live.phy;
    req.max_airtime_us = static_plan->max_airtime_us;
    memcpy(req.frame_digest, static_plan->frame_digest, 32u);
    req.frame_digest_algorithm = 1u;
    req.frame_byte_length = static_plan->frame_byte_length;
    req.not_before_ms = win.not_before_ms;
    req.expiry_ms = win.expiry_ms;

    memset(&perr, 0, sizeof(perr));
    pst = ninlil_pcp_issue(pcp, &req, out_permit, &perr);
    /* Issue always consumes pin on entry; ensure no residual pin. */
    r2_clear_pin(pcp);
    out_result->pcp_error = perr;
    map_pcp_to_axes(pst, out_result);
    if (pst != NINLIL_PCP_OK) {
        memset(out_permit, 0, sizeof(*out_permit));
        return NINLIL_R7_CHECKED_ISSUE_R2;
    }
    return NINLIL_R7_CHECKED_ISSUE_OK;
}

int32_t ninlil_r5_private_activate_profiles_with_authority_epoch(
    ninlil_r7_r5_issue_registry_t *owner,
    const ninlil_r7_class_d_sample_t *accepted_class_d_snapshot,
    uint64_t snapshot_id,
    uint64_t sample_generation,
    uint64_t l1_issuer_token,
    uint64_t expected_authority_epoch)
{
    int32_t st = NINLIL_R7_CHECKED_ISSUE_OK;

    if (owner == NULL || accepted_class_d_snapshot == NULL || snapshot_id == 0u
        || sample_generation == 0u || l1_issuer_token == 0u) {
        return NINLIL_R7_CHECKED_ISSUE_INVALID;
    }
    if (owner->in_api != 0u) {
        return NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
    }
    owner->in_api = 1u;
    if (accepted_class_d_snapshot->trusted == 0u
        || accepted_class_d_snapshot->fence_clock != 0u) {
        st = NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
        goto done;
    }
    /* Single-use snapshot_id; forge without L1 token rejected. */
    if (owner->activate_token != 0u
        && l1_issuer_token != owner->activate_token) {
        st = NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
        goto done;
    }
    if (owner->activate_snapshot_id_used != 0u
        && snapshot_id == owner->activate_snapshot_id_used) {
        st = NINLIL_R7_CHECKED_ISSUE_REGISTRY; /* replay */
        goto done;
    }
    if (expected_authority_epoch != 0u
        && accepted_class_d_snapshot->epoch_id_lo != 0u
        && expected_authority_epoch
            != accepted_class_d_snapshot->epoch_id_lo) {
        st = NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
        goto done;
    }
    owner->activate_snapshot_id_used = snapshot_id;
    owner->activate_token = l1_issuer_token;
done:
    owner->in_api = 0u;
    return st;
}

int32_t ninlil_r5_private_issue_checked_with_owner_epoch(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    uint64_t owner_epoch,
    const ninlil_pcp_issue_request_t *req,
    ninlil_r7_r5_issue_registry_t *registry,
    ninlil_r7_validation_cb_fn validation_cb,
    void *validation_user,
    ninlil_radio_hal_permit_snapshot_t *out_permit,
    ninlil_r7_checked_issue_result_t *out_result)
{
    ninlil_r7_validation_context_t plan;
    int32_t st;

    if (out_result != NULL) {
        result_init(out_result);
    }
    if (out_permit != NULL) {
        memset(out_permit, 0, sizeof(*out_permit));
    }
    if (pcp == NULL || live == NULL || req == NULL || registry == NULL
        || out_permit == NULL || out_result == NULL) {
        return NINLIL_R7_CHECKED_ISSUE_INVALID;
    }
    /* R5 whole-path guard (preflight → R2 → registry). */
    if (registry->in_api != 0u) {
        out_result->exact_status = NINLIL_PCP_BUSY_REENTRY;
        out_result->pcp_status = NINLIL_PCP_BUSY_REENTRY;
        out_result->l1_class = NINLIL_R7_L1_RETRYABLE_PIPELINE;
        return NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
    }
    registry->in_api = 1u;

    /* (1) R5 static preflight — no sample. */
    if (live->site_assignment_epoch == 0u
        || live->hardware_profile_rev == 0u
        || live->regulatory_profile_rev == 0u) {
        out_result->exact_status = NINLIL_PCP_INVALID_ARGUMENT;
        out_result->pcp_status = NINLIL_PCP_INVALID_ARGUMENT;
        out_result->l1_class = NINLIL_R7_L1_TERMINAL_UNISSUED;
        registry->in_api = 0u;
        return NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
    }
    if (owner_epoch != 0u && owner_epoch != live->site_assignment_epoch) {
        out_result->exact_status = NINLIL_PCP_PROFILE_MISMATCH;
        out_result->pcp_status = NINLIL_PCP_PROFILE_MISMATCH;
        out_result->l1_class = NINLIL_R7_L1_AUTHORITY_DIVERGENCE;
        registry->in_api = 0u;
        return NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
    }
    if (req->max_airtime_us == 0u
        || (live->max_airtime_us != 0u
            && req->max_airtime_us > live->max_airtime_us)
        || req->frame_byte_length == 0u) {
        out_result->exact_status = NINLIL_PCP_INVALID_ARGUMENT;
        out_result->pcp_status = NINLIL_PCP_INVALID_ARGUMENT;
        out_result->l1_class = NINLIL_R7_L1_TERMINAL_UNISSUED;
        registry->in_api = 0u;
        return NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
    }
    if (ninlil_r7_r5_issue_registry_count(registry)
        >= NINLIL_R7_R5_ISSUE_REGISTRY_CAP) {
        out_result->exact_status = NINLIL_PCP_CAPACITY;
        out_result->pcp_status = NINLIL_PCP_CAPACITY;
        out_result->l1_class = NINLIL_R7_L1_RETRYABLE_UNISSUED;
        registry->in_api = 0u;
        return NINLIL_R7_CHECKED_ISSUE_PREFLIGHT;
    }

    /* (2) Immutable validation context (copy-owned). No clock sample. */
    memset(&plan, 0, sizeof(plan));
    plan.live = *live;
    plan.owner_epoch = owner_epoch;
    plan.owner_deadline_ms = req->expiry_ms;
    plan.max_airtime_us = req->max_airtime_us;
    plan.frame_byte_length = req->frame_byte_length;
    memcpy(plan.frame_digest, req->frame_digest, 32u);

    if (validation_cb == NULL) {
        validation_cb = ninlil_r7_default_validation_cb;
        validation_user = NULL;
    }

    st = ninlil_r2_private_issue_checked_owner_epoch(
        pcp, &plan, validation_cb, validation_user, out_permit, out_result);
    if (st != NINLIL_R7_CHECKED_ISSUE_OK || out_result->issued == 0u) {
        registry->in_api = 0u;
        return st;
    }

    /* (7) R5 registry insert — failure is RECONCILE (dual-truth risk). */
    {
        uint64_t now_ms = out_result->sample_valid != 0u
            ? out_result->sample.now_ms
            : 0u;
        if (r5_registry_insert(
                registry, out_permit->permit_sequence, owner_epoch, now_ms)
            != NINLIL_R7_CHECKED_ISSUE_OK) {
            memset(out_permit, 0, sizeof(*out_permit));
            out_result->issued = 0u;
            out_result->business_mutation = NINLIL_R7_BUSINESS_AMBIGUOUS;
            out_result->txn_provenance = NINLIL_R7_PROV_AMBIGUOUS;
            out_result->l1_class = NINLIL_R7_L1_RECONCILE_REQUIRED;
            out_result->exact_status = NINLIL_PCP_OK;
            out_result->pcp_status = NINLIL_PCP_OK;
            registry->in_api = 0u;
            return NINLIL_R7_CHECKED_ISSUE_REGISTRY;
        }
    }
    registry->in_api = 0u;
    return NINLIL_R7_CHECKED_ISSUE_OK;
}

int32_t ninlil_r7_private_issue_checked_with_owner_epoch(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    uint64_t owner_epoch,
    const ninlil_pcp_issue_request_t *req,
    ninlil_r7_r5_issue_registry_t *registry,
    ninlil_radio_hal_permit_snapshot_t *out_permit,
    ninlil_r7_checked_issue_result_t *out_result)
{
    return ninlil_r5_private_issue_checked_with_owner_epoch(
        pcp, live, owner_epoch, req, registry, NULL, NULL, out_permit,
        out_result);
}
