/* SPDX-License-Identifier: Apache-2.0 */
/*
 * docs/30 §11.2.3 closed R2 private sample_authority_clock implementation.
 */

#include "r7_r2_authority_clock.h"

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <string.h>

static int id16_is_zero(const uint8_t id[16])
{
    size_t i;
    for (i = 0u; i < 16u; i++) {
        if (id[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int id16_eq(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16u) == 0 ? 1 : 0;
}

static void result_zero_axes(ninlil_r2_authority_clock_result_t *out)
{
    out->business_mutation = NINLIL_R2_SAMPLE_BUSINESS_ZERO;
    out->durable_meta_mutation = NINLIL_R2_SAMPLE_META_ZERO;
    out->txn_provenance = NINLIL_R2_SAMPLE_PRECHECK_ZERO;
    out->result_catalog = NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP;
}

static void result_precheck(
    ninlil_r2_authority_clock_result_t *out,
    uint8_t typed,
    ninlil_pcp_status_t st,
    ninlil_pcp_stage_t stage,
    ninlil_pcp_reason_t reason)
{
    result_zero_axes(out);
    out->typed_class = typed;
    out->sample_fields_valid = 0u;
    out->exact_status = st;
    out->stage = stage;
    out->reason = reason;
}

static void fill_meta_from_pcp(
    const ninlil_pcp_t *pcp, ninlil_r2_authority_clock_result_t *out)
{
    out->meta_published = pcp->published != 0u ? 1u : 0u;
    out->fence_bits = pcp->fence_bits;
    out->fence_code = pcp->fence_code;
    if (pcp->published == 0u) {
        out->meta_state = NINLIL_R2_META_STATE_UNPUBLISHED;
        out->trusted_baseline_valid = 0u;
        memset(out->meta_last_trusted_epoch_id, 0, 16u);
        out->meta_last_trusted_now_ms = 0u;
        return;
    }
    if (pcp->ram_trust.valid != 0u
        && !id16_is_zero(pcp->ram_trust.clock_epoch_id)) {
        out->meta_state = NINLIL_R2_META_STATE_TRUSTED_BASELINE;
        out->trusted_baseline_valid = 1u;
        memcpy(
            out->meta_last_trusted_epoch_id,
            pcp->ram_trust.clock_epoch_id,
            16u);
        out->meta_last_trusted_now_ms = pcp->ram_trust.now_ms;
    } else {
        /* Published but no trusted baseline (state2 INITIAL_UNTRUSTED). */
        out->meta_state = NINLIL_R2_META_STATE_INITIAL_UNTRUSTED_FENCED;
        out->trusted_baseline_valid = 0u;
        memset(out->meta_last_trusted_epoch_id, 0, 16u);
        out->meta_last_trusted_now_ms = 0u;
    }
}

/*
 * Apply §11.2.3 common durable CLOCK fence helper and map three-axis axes.
 * F_C_FULL only on FULL_OK; COMMIT_UNKNOWN → META_AMBIGUOUS (never collapse).
 */
static void apply_clock_fault_axes(
    ninlil_pcp_t *pcp,
    ninlil_pcp_fence_code_t code,
    ninlil_r2_authority_clock_result_t *out)
{
    uint8_t durable;

    durable = ninlil_r2_private_commit_clock_fault_fence(pcp, code);
    out->business_mutation = NINLIL_R2_SAMPLE_BUSINESS_ZERO;
    if (durable == NINLIL_R2_FC_DURABLE_FULL_OK) {
        out->typed_class = NINLIL_R2_SAMPLE_CLOCK_FAULT;
        out->durable_meta_mutation = NINLIL_R2_SAMPLE_F_C_FULL;
        out->txn_provenance = NINLIL_R2_SAMPLE_CLOCK_FENCE_COMMITTED;
    } else if (durable == NINLIL_R2_FC_DURABLE_COMMIT_UNKNOWN) {
        out->typed_class = NINLIL_R2_SAMPLE_COMMIT_UNKNOWN;
        out->durable_meta_mutation = NINLIL_R2_SAMPLE_META_AMBIGUOUS;
        out->txn_provenance = NINLIL_R2_SAMPLE_PROV_AMBIGUOUS;
    } else if (durable == NINLIL_R2_FC_DURABLE_UNPUBLISHED) {
        out->typed_class = NINLIL_R2_SAMPLE_META_UNPUBLISHED;
        out->durable_meta_mutation = NINLIL_R2_SAMPLE_META_ZERO;
        out->txn_provenance = NINLIL_R2_SAMPLE_PRECHECK_ZERO;
    } else {
        /* Definite storage fail — STORAGE/CORRUPT path, not F_C_FULL claim. */
        out->typed_class = NINLIL_R2_SAMPLE_STORAGE_IO;
        out->durable_meta_mutation = NINLIL_R2_SAMPLE_META_ZERO;
        out->txn_provenance = NINLIL_R2_SAMPLE_PRECHECK_ZERO;
    }
    out->sample_fields_valid = 0u;
    out->exact_status = (durable == NINLIL_R2_FC_DURABLE_COMMIT_UNKNOWN)
        ? NINLIL_PCP_COMMIT_UNKNOWN
        : NINLIL_PCP_CLOCK_FAULT;
    out->stage = NINLIL_PCP_STAGE_ISSUE;
    out->reason = (durable == NINLIL_R2_FC_DURABLE_COMMIT_UNKNOWN)
        ? NINLIL_PCP_REASON_COMMIT_UNKNOWN
        : NINLIL_PCP_REASON_CLOCK_FAULT;
}

int ninlil_r2_authority_clock_is_class_d(
    const ninlil_r2_authority_clock_result_t *result)
{
    if (result == NULL) {
        return 0;
    }
    return (result->typed_class == NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH
               && result->sample_fields_valid != 0u)
        ? 1
        : 0;
}

int32_t ninlil_r2_private_sample_authority_clock(
    ninlil_pcp_t *pcp,
    const ninlil_r2_authority_clock_request_t *request,
    ninlil_r2_authority_clock_result_t *out_result)
{
    ninlil_time_sample_t sample;
    ninlil_port_status_t pst;
    uint8_t s_epoch[16];
    uint8_t m_epoch[16];
    uint8_t w_epoch[16];
    uint8_t m_valid;
    uint8_t w_valid;
    uint64_t m_now;
    uint64_t w_now;
    int s_eq_m;
    int s_eq_w;
    int blocking_fence;

    if (out_result == NULL) {
        return 1;
    }
    memset(out_result, 0, sizeof(*out_result));
    result_zero_axes(out_result);

    if (pcp == NULL || request == NULL) {
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_INVALID_ARGUMENT,
            NINLIL_PCP_INVALID_ARGUMENT,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_NULL_ARG);
        return 1;
    }

    if (pcp->lifecycle != NINLIL_PCP_LC_ACTIVE) {
        if (pcp->lifecycle == NINLIL_PCP_LC_SHUTDOWN) {
            result_precheck(
                out_result,
                NINLIL_R2_SAMPLE_SHUTDOWN,
                NINLIL_PCP_SHUTDOWN,
                NINLIL_PCP_STAGE_ISSUE,
                NINLIL_PCP_REASON_SHUTDOWN);
        } else {
            result_precheck(
                out_result,
                NINLIL_R2_SAMPLE_UNBOUND,
                NINLIL_PCP_INVALID_STATE,
                NINLIL_PCP_STAGE_ISSUE,
                NINLIL_PCP_REASON_INVALID_STATE);
        }
        return 0;
    }

    if (pcp->in_api != 0u) {
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_REENTRY,
            NINLIL_PCP_BUSY_REENTRY,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_BUSY_REENTRY);
        return 0;
    }

    if (pcp->clock_bound == 0u || pcp->clock_ops.now == NULL) {
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_UNBOUND,
            NINLIL_PCP_UNBOUND_CLOCK,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_UNBOUND_CLOCK);
        return 0;
    }

    /* 0. Published gate before clock (SAMPLE_META_UNPUBLISHED). */
    if (pcp->published == 0u) {
        fill_meta_from_pcp(pcp, out_result);
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_META_UNPUBLISHED,
            NINLIL_PCP_INVALID_STATE,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_INVALID_STATE);
        out_result->meta_published = 0u;
        return 0;
    }

    fill_meta_from_pcp(pcp, out_result);

    /* Routine floor: ram_trust must be trusted baseline. */
    if (pcp->ram_trust.valid == 0u
        || id16_is_zero(pcp->ram_trust.clock_epoch_id)) {
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_TRUST_MIRROR_INVALID,
            NINLIL_PCP_INVALID_STATE,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_INVALID_STATE);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }

    blocking_fence =
        (pcp->fence_bits
            & (NINLIL_PCP_FENCE_BIT_STORAGE | NINLIL_PCP_FENCE_BIT_CLOCK
                | NINLIL_PCP_FENCE_BIT_CORRUPT))
        != 0u;

    /* 1. Sample platform clock once. */
    memset(&sample, 0, sizeof(sample));
    pst = pcp->clock_ops.now(pcp->clock_ops.user, &sample);
    if (pst == NINLIL_PORT_TEMPORARY_FAILURE) {
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_TEMP_UNCERTAIN,
            NINLIL_PCP_CLOCK_UNCERTAIN,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_CLOCK_UNCERTAIN);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }
    if (pst == NINLIL_PORT_PERMANENT_FAILURE) {
        apply_clock_fault_axes(pcp, NINLIL_PCP_FC_CLOCK_PERM, out_result);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }
    if (pst != NINLIL_PORT_OK) {
        apply_clock_fault_axes(pcp, NINLIL_PCP_FC_CLOCK_UNKNOWN, out_result);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }

    /* Ill-formed OK sample. */
    if (sample.abi_version != NINLIL_ABI_VERSION
        || sample.struct_size < (uint16_t)sizeof(ninlil_time_sample_t)
        || sample.reserved_zero != 0u
        || (sample.trust != NINLIL_CLOCK_TRUSTED
            && sample.trust != NINLIL_CLOCK_UNCERTAIN)
        || id16_is_zero(sample.clock_epoch_id.bytes)) {
        apply_clock_fault_axes(pcp, NINLIL_PCP_FC_CLOCK_ILLFORMED, out_result);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }

    if (sample.trust == NINLIL_CLOCK_UNCERTAIN) {
        result_precheck(
            out_result,
            NINLIL_R2_SAMPLE_TEMP_UNCERTAIN,
            NINLIL_PCP_CLOCK_UNCERTAIN,
            NINLIL_PCP_STAGE_ISSUE,
            NINLIL_PCP_REASON_CLOCK_UNCERTAIN);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }

    /* TRUSTED sample S. */
    memcpy(s_epoch, sample.clock_epoch_id.bytes, 16u);
    memcpy(m_epoch, pcp->ram_trust.clock_epoch_id, 16u);
    m_valid = 1u;
    m_now = pcp->ram_trust.now_ms;
    w_valid = request->watermark_valid != 0u ? 1u : 0u;
    if (w_valid != 0u) {
        memcpy(w_epoch, request->watermark_epoch_id, 16u);
        w_now = request->watermark_now_ms;
        if (id16_is_zero(w_epoch)) {
            w_valid = 0u;
        }
    } else {
        memset(w_epoch, 0, 16u);
        w_now = 0u;
    }

    /* Same-epoch regression vs floors → CLOCK_FAULT + durable F_c helper. */
    if (m_valid != 0u && id16_eq(s_epoch, m_epoch) && sample.now_ms < m_now) {
        apply_clock_fault_axes(pcp, NINLIL_PCP_FC_CLOCK_REGRESSION, out_result);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }
    if (w_valid != 0u && id16_eq(s_epoch, w_epoch) && sample.now_ms < w_now) {
        apply_clock_fault_axes(pcp, NINLIL_PCP_FC_CLOCK_REGRESSION, out_result);
        fill_meta_from_pcp(pcp, out_result);
        return 0;
    }

    s_eq_m = (m_valid != 0u && id16_eq(s_epoch, m_epoch)) ? 1 : 0;
    s_eq_w = (w_valid != 0u && id16_eq(s_epoch, w_epoch)) ? 1 : 0;

    /* Populate sample fields (trusted). */
    memcpy(out_result->sample_epoch_id, s_epoch, 16u);
    out_result->sample_now_ms = sample.now_ms;
    out_result->sample_trust = NINLIL_CLOCK_TRUSTED;
    out_result->sample_fields_valid = 1u;
    fill_meta_from_pcp(pcp, out_result);
    result_zero_axes(out_result);
    out_result->exact_status = NINLIL_PCP_OK;
    out_result->stage = NINLIL_PCP_STAGE_ISSUE;
    out_result->reason = NINLIL_PCP_REASON_NONE;

    /* Four-way epoch class (exact). */
    if (s_eq_m != 0 && s_eq_w != 0) {
        /* Class D candidate: also requires blocking fences clear. */
        if (blocking_fence != 0) {
            /* Same-epoch but blocked: not class D accept. */
            if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CLOCK) != 0u) {
                out_result->typed_class = NINLIL_R2_SAMPLE_CLOCK_FAULT;
                out_result->sample_fields_valid = 0u;
                out_result->exact_status = NINLIL_PCP_CLOCK_FAULT;
                out_result->reason = NINLIL_PCP_REASON_CLOCK_FAULT;
                out_result->durable_meta_mutation = NINLIL_R2_SAMPLE_F_C_FULL;
                out_result->txn_provenance =
                    NINLIL_R2_SAMPLE_CLOCK_FENCE_COMMITTED;
            } else if ((pcp->fence_bits & NINLIL_PCP_FENCE_BIT_CORRUPT) != 0u) {
                out_result->typed_class = NINLIL_R2_SAMPLE_CORRUPT;
                out_result->sample_fields_valid = 0u;
                out_result->exact_status = NINLIL_PCP_CORRUPT_FENCE;
                out_result->reason = NINLIL_PCP_REASON_CORRUPT_FENCE;
            } else {
                out_result->typed_class = NINLIL_R2_SAMPLE_STORAGE_IO;
                out_result->sample_fields_valid = 0u;
                out_result->exact_status = NINLIL_PCP_STORAGE_FENCE;
                out_result->reason = NINLIL_PCP_REASON_STORAGE_FENCE;
            }
            return 0;
        }
        out_result->typed_class = NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH;
        return 0;
    }
    if (s_eq_m != 0 && s_eq_w == 0) {
        /* Class A: S==M, W absent or mismatch. */
        out_result->typed_class = NINLIL_R2_SAMPLE_W1_REPAIR;
        return 0;
    }
    if (s_eq_w != 0 && s_eq_m == 0) {
        /* Class B: S==W, S!=M. */
        out_result->typed_class = NINLIL_R2_SAMPLE_AUTHORITY_DIVERGENCE;
        return 0;
    }
    /* Class C: S differs from both (or both absent). */
    out_result->typed_class = NINLIL_R2_SAMPLE_EPOCH_TRANSITION_REQUIRED;
    return 0;
}

int32_t ninlil_r2_private_load_authority_clock_baseline(
    ninlil_pcp_t *pcp,
    ninlil_r2_authority_clock_baseline_result_t *out_result)
{
    if (out_result == NULL) {
        return 1;
    }
    memset(out_result, 0, sizeof(*out_result));
    out_result->result_catalog = NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP;
    out_result->stage = NINLIL_PCP_STAGE_RECOVER;
    if (pcp == NULL) {
        out_result->exact_status = NINLIL_PCP_INVALID_ARGUMENT;
        out_result->reason = NINLIL_PCP_REASON_NULL_ARG;
        return 1;
    }
    if (pcp->lifecycle != NINLIL_PCP_LC_ACTIVE) {
        out_result->exact_status = NINLIL_PCP_INVALID_STATE;
        out_result->reason = NINLIL_PCP_REASON_INVALID_STATE;
        return 0;
    }
    out_result->published = pcp->published != 0u ? 1u : 0u;
    out_result->fence_bits = pcp->fence_bits;
    out_result->fence_code = pcp->fence_code;
    if (pcp->published == 0u) {
        out_result->meta_state = NINLIL_R2_META_STATE_UNPUBLISHED;
        out_result->trusted_baseline_valid = 0u;
        out_result->exact_status = NINLIL_PCP_OK;
        return 0;
    }
    if (pcp->ram_trust.valid != 0u
        && !id16_is_zero(pcp->ram_trust.clock_epoch_id)) {
        out_result->meta_state = NINLIL_R2_META_STATE_TRUSTED_BASELINE;
        out_result->trusted_baseline_valid = 1u;
        memcpy(
            out_result->last_trusted_epoch_id,
            pcp->ram_trust.clock_epoch_id,
            16u);
        out_result->last_trusted_now_ms = pcp->ram_trust.now_ms;
    } else {
        out_result->meta_state = NINLIL_R2_META_STATE_INITIAL_UNTRUSTED_FENCED;
        out_result->trusted_baseline_valid = 0u;
    }
    out_result->exact_status = NINLIL_PCP_OK;
    return 0;
}
