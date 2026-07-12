#ifndef NINLIL_DOMAIN_STORE_D3S2_H
#define NINLIL_DOMAIN_STORE_D3S2_H

/*
 * D3-S2 private declared multi-count / same-txn multipass context
 * (docs/17 §18.13).
 *
 * Production-private; not installed. Not a public C ABI.
 *
 * D3-S2 implementation boundary (this slice):
 *   - Fixed context layout (sizeof 306 / align 1 / ceiling 320)
 *   - Closed modes 21..26 (k₂=6; 1 session = 1 mode = 1 READ_ONLY txn)
 *   - begin_profiled_d3s2 prevalidation (mode ∈ 21..26; dual-bound forbidden)
 *   - Same-txn phase machine: baseline D2 once + sequential zero-prefix
 *     iterator close/reopen; PASS_INTERNAL freezes D2 counters/profile/future
 *   - B0–B11 row_budget / mid-pass resume; stream H2 vs known-slot B6k close
 *   - Mode-scoped FOCUS/BIND sets; fail-closed lifecycle
 * Stage5 D3 bind, D3-S3..S12, D3 overall, D4, and public Runtime are pending.
 * Does not re-claim D3-S1 exact-1 success.
 */

#include <stddef.h>
#include <stdint.h>

#include <ninlil/platform.h>
#include <ninlil/runtime.h>

#include "domain_store_codec.h"
#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — avoid circular include with domain_store_scanner.h. */
typedef struct ninlil_domain_scan_session ninlil_domain_scan_session_t;
typedef struct ninlil_domain_scan_workspace ninlil_domain_scan_workspace_t;

/* Closed modes 21..26 (docs/17 §18.13.2). */
typedef enum ninlil_domain_scan_d3s2_mode {
    NINLIL_DOMAIN_SCAN_D3S2_MODE_TX_ATTEMPT = 21,
    NINLIL_DOMAIN_SCAN_D3S2_MODE_DELIVERY_ATTEMPT = 22,
    NINLIL_DOMAIN_SCAN_D3S2_MODE_EVIDENCE = 23,
    NINLIL_DOMAIN_SCAN_D3S2_MODE_REVERSE_REPLY = 24,
    NINLIL_DOMAIN_SCAN_D3S2_MODE_RETRY = 25,
    NINLIL_DOMAIN_SCAN_D3S2_MODE_MANAGEMENT = 26
} ninlil_domain_scan_d3s2_mode_t;

#define NINLIL_DOMAIN_SCAN_D3S2_MODE_MIN ((uint8_t)21u)
#define NINLIL_DOMAIN_SCAN_D3S2_MODE_MAX ((uint8_t)26u)
#define NINLIL_DOMAIN_SCAN_D3S2_MODE_IMPLEMENTED_MAX \
    NINLIL_DOMAIN_SCAN_D3S2_MODE_MAX

/* Pass kinds (§18.13.5). */
#define NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE ((uint8_t)0u)
#define NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL ((uint8_t)1u)

/* Phase machine (§18.13.4). Control order ≠ Stage 5 scan order. */
typedef enum ninlil_domain_scan_d3s2_phase {
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_IDLE = 0,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BASELINE = 1,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER = 2,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT = 3,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_INDEX = 4,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_EVIDENCE = 5,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_REPLY = 6,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_RETRY = 7,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_MANAGEMENT = 8,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_ATTEMPT = 9,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_INDEX = 10,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_EVIDENCE = 11,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_REPLY = 12,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_RETRY = 13,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_BIND_MANAGEMENT = 14,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE = 15,
    NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED = 16
} ninlil_domain_scan_d3s2_phase_t;

/* flags bits (§18.13.12). bit0–3 Normative; bit4–5 private drive coord. */
#define NINLIL_DOMAIN_SCAN_D3S2_FLAG_BASELINE_DONE ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S2_FLAG_BIND_PHASE_ACTIVE ((uint8_t)0x04u)
#define NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY ((uint8_t)0x08u)
/* Private drive coordination inside existing flags u8 (no layout growth). */
#define NINLIL_DOMAIN_SCAN_D3S2_FLAG_NEED_REOPEN ((uint8_t)0x10u)
#define NINLIL_DOMAIN_SCAN_D3S2_FLAG_CARRIER_INSTALLED ((uint8_t)0x20u)

/*
 * count_complete_mask / binding_complete_mask family bits (§18.13.12.1).
 * bit0 ATTEMPT, bit1 INDEX, bit2 EVIDENCE, bit3 REPLY, bit4 RETRY,
 * bit5 MANAGEMENT; bit6–7 MBZ.
 */
#define NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE ((uint8_t)0x04u)
#define NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY ((uint8_t)0x08u)
#define NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY ((uint8_t)0x10u)
#define NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT ((uint8_t)0x20u)

#define NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES ((uint32_t)306u)
#define NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_CEILING_BYTES ((uint32_t)320u)
#define NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY ((uint32_t)45u)
#define NINLIL_DOMAIN_SCAN_D3S2_FOCUS_RAW_CAPACITY ((uint32_t)80u)
#define NINLIL_DOMAIN_SCAN_D3S2_SOURCE_AUX_CAPACITY ((uint32_t)16u)
#define NINLIL_DOMAIN_SCAN_D3S2_TX_ID_BYTES ((uint32_t)16u)
#define NINLIL_DOMAIN_SCAN_D3S2_DIGEST_BYTES ((uint32_t)32u)

/*
 * Doc-first aggregate ceilings (§18.13.13). Scanner 8192 and Stage5-alone
 * 8704 are unchanged. Outer future aggregate when S1+S2 co-resident = 9152.
 */
#define NINLIL_DOMAIN_SCAN_D3S2_STAGE5_SEAM_ALONE_CEILING_BYTES \
    ((uint32_t)8704u)
#define NINLIL_DOMAIN_SCAN_D3S2_STAGE5_FUTURE_PACKED_BYTES ((uint32_t)8384u)
#define NINLIL_DOMAIN_SCAN_D3S2_S1_CONTEXT_CEILING_BYTES ((uint32_t)448u)
#define NINLIL_DOMAIN_SCAN_D3S2_OUTER_AGGREGATE_CEILING_BYTES \
    ((uint32_t)9152u)
#define NINLIL_DOMAIN_SCAN_D3S2_AGGREGATE_PACKED_SUM_BYTES \
    ((uint32_t)(NINLIL_DOMAIN_SCAN_D3S2_STAGE5_FUTURE_PACKED_BYTES \
        + 421u + NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES)) /* 9111 */

/*
 * Fixed D3-S2 multipass context (all uint8 fields; natural align 1).
 * Separate from scanner workspace and S1 context. Mutation of Storage: never.
 * Exact offsets per docs/17 §18.13.12.
 */
struct ninlil_domain_scan_d3s2_context {
    uint8_t last_carrier_key[NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY];
    uint8_t last_carrier_key_len; /* 0 = none (−∞) */
    uint8_t focus_raw80[NINLIL_DOMAIN_SCAN_D3S2_FOCUS_RAW_CAPACITY];
    uint8_t focus_raw_len; /* 0 | 16 | 80 */
    uint8_t focus_tx_id[NINLIL_DOMAIN_SCAN_D3S2_TX_ID_BYTES];
    uint8_t focus_primary_key_digest[NINLIL_DOMAIN_SCAN_D3S2_DIGEST_BYTES];
    uint8_t focus_owner_kind; /* 1 TX | 2 DLV | 0 none */
    uint8_t focus_family_gate;
    uint8_t declared_a[8];
    uint8_t declared_b[8];
    uint8_t declared_c[8];
    uint8_t declared_reply_count[4];
    uint8_t declared_L;
    uint8_t declared_retry_recent_n;
    uint8_t declared_flags;
    uint8_t observed_a[8];
    uint8_t observed_b[8];
    uint8_t observed_c[8];
    uint8_t observed_reply_mask;
    uint8_t evidence_slot_mask[2];
    uint8_t retry_slot_mask;
    uint8_t peer_key[NINLIL_DOMAIN_SCAN_D3S2_PEER_KEY_CAPACITY];
    uint8_t peer_key_len;
    uint8_t source_aux[NINLIL_DOMAIN_SCAN_D3S2_SOURCE_AUX_CAPACITY];
    uint8_t source_aux_len;
    uint8_t phase;
    uint8_t pass_kind; /* 0 BASELINE | 1 INTERNAL */
    uint8_t flags;
    uint8_t count_complete_mask;
    uint8_t binding_complete_mask;
    uint8_t focus_mode; /* 21..26 immutable after begin */
    uint8_t cleanup_skip; /* 0|1; Mode21/22 plan PRESENT only */
};
typedef struct ninlil_domain_scan_d3s2_context ninlil_domain_scan_d3s2_context_t;

#if defined(__cplusplus)
static_assert(
    sizeof(ninlil_domain_scan_d3s2_context_t)
        == NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES,
    "D3-S2 context sizeof must be exactly 306");
static_assert(
    sizeof(ninlil_domain_scan_d3s2_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_CEILING_BYTES,
    "D3-S2 context exceeds object ceiling 320");
static_assert(
    alignof(ninlil_domain_scan_d3s2_context_t) == 1,
    "D3-S2 context alignment must be 1");
#else
_Static_assert(
    sizeof(ninlil_domain_scan_d3s2_context_t)
        == NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES,
    "D3-S2 context sizeof must be exactly 306");
_Static_assert(
    sizeof(ninlil_domain_scan_d3s2_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_CEILING_BYTES,
    "D3-S2 context exceeds object ceiling 320");
_Static_assert(
    _Alignof(ninlil_domain_scan_d3s2_context_t) == 1,
    "D3-S2 context alignment must be 1");
#endif

/*
 * Production-private D3-S2 profiled begin (docs/17 §18.13.14).
 * Prevalidation (before mutation / Port): mode ∈ 21..26, context non-NULL,
 * pairwise disjoint session/workspace/ops/handle/candidate/context,
 * context within object ceiling. Success: focus_mode := mode (immutable),
 * baseline D2 once (PASS_BASELINE), phase BASELINE.
 * Violation: Port 0, INVALID_ARGUMENT, state unchanged.
 * Dual-bound with D3-S1 is forbidden (bound_d3_context stays NULL).
 * Existing begin_profiled remains D2-only; begin_profiled_d3s1 modes 1..20 only.
 */
ninlil_status_t ninlil_domain_scan_begin_profiled_d3s2(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s2_context_t *context);

/*
 * Same-txn sequential zero-prefix iterator reopen (docs/17 §18.13.14).
 * Legal OPEN/EXHAUSTED + txn live + no sticky. Closes live iterator if any,
 * reopens zero-prefix, resets pass-local previous_key only.
 * Does not rollback txn; does not re-run D2 baseline/profile gate.
 * Does not clear frozen D2 counters / profile / future diagnostics.
 */
ninlil_status_t ninlil_domain_scan_reopen_zero_prefix_iter(
    ninlil_domain_scan_session_t *session);

/*
 * S2 phase-machine drive (docs/17 §18.13.5.1 B0–B11).
 * May call advance with caller budget; obeys mid-pass resume (B5), stream
 * H2 close (B6), known-slot B6k close, BIND EXHAUSTED mask (B8).
 * row_budget==0 → INVALID_ARGUMENT, Port 0, unchanged (B0).
 * Does not finalize as the first place count is compared while txn live.
 */
ninlil_status_t ninlil_domain_scan_d3s2_drive(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget);

/*
 * H1: after S3 success under PASS_INTERNAL, before previous_key update.
 * SELECT / FOCUS stream / BIND predicates. Must not touch frozen D2 counters.
 * Production path only; called from process_ok_row when S2 is bound.
 */
ninlil_status_t ninlil_domain_scan_d3s2_on_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok);

/*
 * H2: inside advance after true EXHAUSTED, before return OK.
 * FOCUS stream close only (B6). Known-slot uses B6k, not H2.
 */
ninlil_status_t ninlil_domain_scan_d3s2_on_exhausted(
    ninlil_domain_scan_session_t *session);

/* Required mask helpers (pure; mode-scoped). */
uint8_t ninlil_domain_scan_d3s2_required_count_mask(uint8_t focus_mode);
uint8_t ninlil_domain_scan_d3s2_required_binding_mask(uint8_t focus_mode);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_DOMAIN_STORE_D3S2_H */
