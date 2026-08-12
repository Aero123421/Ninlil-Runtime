/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_R7_FRAG_CHECKED_ISSUE_H
#define NINLIL_R7_FRAG_CHECKED_ISSUE_H

/*
 * R7 private R5→R2 checked-issue (docs/30 §15.3.1–15.3.2).
 *
 * Sole production L1 issue path:
 *   L1 → ninlil_r5_private_issue_checked_with_owner_epoch
 *      → ninlil_r2_private_issue_checked_owner_epoch
 *
 * R5: static preflight (no sample) → immutable validation context → R2 call
 *     → registry insert on OK_ISSUED.
 * R2: samples trusted class-D S exactly once via ninlil_pcp_issue_sample_pin
 *     → sample/epoch/outstanding gates → trusted-class-D validation_cb
 *     → single ninlil_pcp_issue which consumes the same pin (no re-sample).
 *
 * R5 and L1 MUST NOT sample or inject caller times as S.
 * Call sites MUST NOT invoke ninlil_pcp_issue directly.
 * Not public ABI. Not installed.
 */

#include "pcp_authority.h"
#include "radio_hal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Closed result catalog (docs/30 §15.3.2) ---- */

#define NINLIL_R7_RESULT_CATALOG_R2_PCP ((uint8_t)1u)

/* business_mutation */
#define NINLIL_R7_BUSINESS_ZERO ((uint8_t)0u)
#define NINLIL_R7_ISSUED_FULL ((uint8_t)1u)
#define NINLIL_R7_BUSINESS_AMBIGUOUS ((uint8_t)2u)

/* clock_fence_mutation */
#define NINLIL_R7_META_ZERO ((uint8_t)0u)
#define NINLIL_R7_F_C_FULL ((uint8_t)1u)
#define NINLIL_R7_META_AMBIGUOUS ((uint8_t)2u)

/* txn_provenance */
#define NINLIL_R7_PRECHECK_ZERO ((uint8_t)0u)
#define NINLIL_R7_RW_ABORT_ZERO ((uint8_t)1u)
#define NINLIL_R7_ISSUED_COMMITTED ((uint8_t)2u)
#define NINLIL_R7_CLOCK_FENCE_COMMITTED ((uint8_t)3u)
#define NINLIL_R7_PROV_AMBIGUOUS ((uint8_t)4u)

/*
 * Closed L1 result class set (docs/30 §15.3.2 exact; gate set-equality).
 * Values are dense 0..10; do not renumber without updating vector catalog.
 */
#define NINLIL_R7_L1_OK_ISSUED ((uint8_t)0u)
#define NINLIL_R7_L1_RETRYABLE_UNISSUED ((uint8_t)1u)
#define NINLIL_R7_L1_TERMINAL_UNISSUED ((uint8_t)2u)
#define NINLIL_R7_L1_CLOCK_PATH_DROP ((uint8_t)3u)
#define NINLIL_R7_L1_RECONCILE_REQUIRED ((uint8_t)4u)
#define NINLIL_R7_L1_AUTHORITY_DIVERGENCE ((uint8_t)5u)
#define NINLIL_R7_L1_EPOCH_TRANSITION_REQUIRED ((uint8_t)6u)
#define NINLIL_R7_L1_EPOCH_W1_REPAIR ((uint8_t)7u)
#define NINLIL_R7_L1_FIFO_OUT_OF_ORDER ((uint8_t)8u)
#define NINLIL_R7_L1_OPERATOR_RECOVERY_REQUIRED ((uint8_t)9u)
#define NINLIL_R7_L1_RETRYABLE_PIPELINE ((uint8_t)10u)
#define NINLIL_R7_L1_CLASS_COUNT ((uint8_t)11u)

/* validation_cb closed results */
#define NINLIL_R7_VAL_OK ((int32_t)0)
#define NINLIL_R7_VAL_TERMINAL ((int32_t)1)
#define NINLIL_R7_VAL_RETRYABLE ((int32_t)2)
#define NINLIL_R7_VAL_AUTHORITY ((int32_t)3)
#define NINLIL_R7_VAL_RECONCILE ((int32_t)4)

/* Adapter status */
#define NINLIL_R7_CHECKED_ISSUE_OK ((int32_t)0)
#define NINLIL_R7_CHECKED_ISSUE_INVALID ((int32_t)1)
#define NINLIL_R7_CHECKED_ISSUE_PREFLIGHT ((int32_t)2)
#define NINLIL_R7_CHECKED_ISSUE_R2 ((int32_t)3)
#define NINLIL_R7_CHECKED_ISSUE_REGISTRY ((int32_t)4)

/* R5 issue registry capacity (global Permit FIFO bound companion). */
#define NINLIL_R7_R5_ISSUE_REGISTRY_CAP ((size_t)8u)

/* Issue pipeline retry cap (docs/30 positive 100ms/max8). */
#define NINLIL_R7_ISSUE_RETRY_MAX ((uint8_t)8u)
#define NINLIL_R7_ISSUE_RETRY_BACKOFF_MS ((uint64_t)100u)

typedef struct ninlil_r7_class_d_sample {
    uint64_t now_ms;
    uint64_t epoch_id_lo;
    uint8_t trusted; /* 1 = class-D trusted; 0 = uncertain/fault */
    uint8_t fence_clock; /* 1 = clock fence observed */
} ninlil_r7_class_d_sample_t;

typedef struct ninlil_r7_issue_window {
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    uint8_t valid;
} ninlil_r7_issue_window_t;

typedef struct ninlil_r7_validation_context {
    ninlil_pcp_live_profile_t live;
    uint64_t owner_epoch;
    uint64_t owner_deadline_ms;
    uint32_t max_airtime_us;
    uint32_t frame_byte_length;
    uint8_t frame_digest[32];
} ninlil_r7_validation_context_t;

/*
 * Read-only validation callback. MUST NOT sample clock / activate profiles.
 * S is the sole trusted sample for this issue path (R2-owned).
 */
typedef int32_t (*ninlil_r7_validation_cb_fn)(
    void *user,
    const ninlil_r7_class_d_sample_t *S,
    const ninlil_r7_validation_context_t *static_plan,
    ninlil_r7_issue_window_t *out_window);

typedef struct ninlil_r7_checked_issue_result {
    uint8_t result_catalog; /* R2_PCP */
    ninlil_pcp_status_t exact_status;
    /*
     * Exact PCP stage/reason (uint32 authority codes). Never collapse reason
     * 11 (PROFILE_MISMATCH) into L1 class ordinals; preserve perr fields.
     */
    ninlil_pcp_stage_t stage;
    ninlil_pcp_reason_t reason;
    uint8_t business_mutation;
    uint8_t clock_fence_mutation;
    uint8_t txn_provenance;
    uint8_t l1_class;
    uint8_t issued; /* 1 iff OK_ISSUED + permit valid */
    ninlil_pcp_error_t pcp_error;
    /* Back-compat aliases for call sites */
    ninlil_pcp_status_t pcp_status;
    /* Accepted class-D sample used on this path (valid when sample_valid). */
    uint8_t sample_valid;
    ninlil_r7_class_d_sample_t sample;
} ninlil_r7_checked_issue_result_t;

/*
 * Caller-owned R5 issue state (volatile, private ABI). The row registry,
 * whole-path reentry guard, and activation replay identity live together so
 * distinct Runtime/Cell owners never share mutable process state. A zeroed
 * object is valid; init/fini wipe every byte. clear drops issue rows while
 * retaining the activation replay identity for the live owner lifetime.
 */
typedef struct ninlil_r7_r5_issue_registry {
    uint8_t live[NINLIL_R7_R5_ISSUE_REGISTRY_CAP];
    uint64_t permit_sequence[NINLIL_R7_R5_ISSUE_REGISTRY_CAP];
    uint64_t owner_epoch[NINLIL_R7_R5_ISSUE_REGISTRY_CAP];
    uint64_t issue_now_ms[NINLIL_R7_R5_ISSUE_REGISTRY_CAP];
    size_t count;
    uint8_t in_api;
    uint64_t activate_snapshot_id_used;
    uint64_t activate_token;
} ninlil_r7_r5_issue_registry_t;

void ninlil_r7_r5_issue_registry_init(ninlil_r7_r5_issue_registry_t *reg);
void ninlil_r7_r5_issue_registry_clear(ninlil_r7_r5_issue_registry_t *reg);
void ninlil_r7_r5_issue_registry_fini(ninlil_r7_r5_issue_registry_t *reg);
size_t ninlil_r7_r5_issue_registry_count(
    const ninlil_r7_r5_issue_registry_t *reg);
/* Drop row after L1 cleanup (FIFO drain). No-op if not present. */
void ninlil_r7_r5_issue_registry_release(
    ninlil_r7_r5_issue_registry_t *reg,
    uint64_t permit_sequence);

/* Default validation_cb: VAL_OK + window from S when trusted class-D. */
int32_t ninlil_r7_default_validation_cb(
    void *user,
    const ninlil_r7_class_d_sample_t *S,
    const ninlil_r7_validation_context_t *static_plan,
    ninlil_r7_issue_window_t *out_window);

/*
 * R2 private checked-issue (docs name).
 * Samples S exactly once via ninlil_pcp_issue_sample_pin; no caller S;
 * single pcp_issue consumes the pin (no re-sample / no TOCTOU).
 */
int32_t ninlil_r2_private_issue_checked_owner_epoch(
    ninlil_pcp_t *pcp,
    const ninlil_r7_validation_context_t *static_plan,
    ninlil_r7_validation_cb_fn validation_cb,
    void *validation_user,
    ninlil_radio_hal_permit_snapshot_t *out_permit,
    ninlil_r7_checked_issue_result_t *out_result);

/*
 * R5 private checked-issue (docs name). Sole L1 entry.
 * Static preflight (no sample) → build context → R2 → registry insert.
 * R5 in_api covers whole path (preflight through registry).
 */
int32_t ninlil_r5_private_issue_checked_with_owner_epoch(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    uint64_t owner_epoch,
    const ninlil_pcp_issue_request_t *req,
    ninlil_r7_r5_issue_registry_t *registry,
    ninlil_r7_validation_cb_fn validation_cb,
    void *validation_user,
    ninlil_radio_hal_permit_snapshot_t *out_permit,
    ninlil_r7_checked_issue_result_t *out_result);

/*
 * L1-only profile activation with accepted class-D same-S snapshot
 * (docs/30 §15.3.1.1). Single-use snapshot_id; no re-sample.
 */
int32_t ninlil_r5_private_activate_profiles_with_authority_epoch(
    ninlil_r7_r5_issue_registry_t *owner,
    const ninlil_r7_class_d_sample_t *accepted_class_d_snapshot,
    uint64_t snapshot_id,
    uint64_t sample_generation,
    uint64_t l1_issuer_token,
    uint64_t expected_authority_epoch);

/*
 * Convenience for production orch: uses default validation_cb and the
 * required caller-owned registry. No caller S — R2 samples once.
 */
int32_t ninlil_r7_private_issue_checked_with_owner_epoch(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    uint64_t owner_epoch,
    const ninlil_pcp_issue_request_t *req,
    ninlil_r7_r5_issue_registry_t *registry,
    ninlil_radio_hal_permit_snapshot_t *out_permit,
    ninlil_r7_checked_issue_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_CHECKED_ISSUE_H */
