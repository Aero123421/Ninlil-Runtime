#ifndef NINLIL_DOMAIN_STORE_SCANNER_H
#define NINLIL_DOMAIN_STORE_SCANNER_H

/*
 * D2-S3 private Domain Store bounded scanner core.
 * Production-private; not installed. Not a public C ABI.
 *
 * Implements docs/17-foundation-domain-store.md §15.1–15.7 / §15.10 / §15.9 S3.
 * Production path: ninlil_domain_scan_begin_profiled (required candidate,
 * same-txn 17 get + validate/compare + one zero-prefix iterator).
 * Exact-profile CURRENT family 5/6 rows: typed same-record (business+7d)
 * or witness header/chunk local framing (7e/7f). S1 transport-only begin is
 * TEST-build only (NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN) and does
 * not run domain body structural validation.
 *
 * No cross-row (D3), S4 exact-get seam, recovery mutation (D4), or Stage 5
 * orchestration (S6). Does not claim D2 / DSR1 / DSR2 complete.
 *
 * Ownership binding:
 *   begin binds non-owning pointers to storage ops, handle slot, and
 *   workspace plus a snapshot of the original handle value into the session.
 *   Profiled begin also exact-copies the candidate binding into workspace
 *   before the first Port call and never retains the caller pointer.
 *   advance/finalize/abort use only those bound fields for Port calls and
 *   cleanup; callers cannot substitute a different Port/handle/workspace
 *   mid-session via the API surface.
 *
 * Private precondition while the session is live (OPEN/EXHAUSTED/FAILED):
 *   the caller must not mutate the bound handle slot contents, replace the
 *   bound ops table object, or replace/repurpose the bound workspace object.
 *   Handle-slot drift is checked against the begin-time snapshot before Port
 *   use when still safe; full detection of all external mutations is not
 *   claimed.
 */

#include <stddef.h>
#include <stdint.h>

#include <ninlil/platform.h>
#include <ninlil/runtime.h>

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "runtime_store_bootstrap.h"
#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Doc bound DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES (private; not public ABI). */
#define NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES ((uint32_t)8192u)
#define NINLIL_DOMAIN_SCAN_KEY_CAPACITY ((uint32_t)255u)
#define NINLIL_DOMAIN_SCAN_VALUE_CAPACITY ((uint32_t)4096u)
#define NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY ((uint32_t)255u)
#define NINLIL_DOMAIN_SCAN_ENCODED_VALUES_BYTES \
    NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_VALUE_BYTES
#define NINLIL_DOMAIN_SCAN_PROFILE_ALL_MASK \
    NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK

typedef enum ninlil_domain_scan_state {
    NINLIL_DOMAIN_SCAN_STATE_IDLE = 0,
    NINLIL_DOMAIN_SCAN_STATE_OPEN = 1,
    NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED = 2,
    NINLIL_DOMAIN_SCAN_STATE_FAILED = 3,
    NINLIL_DOMAIN_SCAN_STATE_DONE = 4
} ninlil_domain_scan_state_t;

/*
 * S3 exact-profile structural scratch: large typed/witness bodies live here,
 * never as large scanner-stack locals. Union keeps sizeof(workspace)<=8192.
 * Not a second 4096 value buffer.
 */
typedef union ninlil_domain_scan_row_scratch {
    ninlil_model_domain_typed_record_t typed;
    ninlil_model_domain_witness_header_t witness_header;
    ninlil_model_domain_witness_chunk_t witness_chunk;
} ninlil_domain_scan_row_scratch_t;

/*
 * Caller-owned fixed scratch (Runtime arena).
 * S1: key + value + previous-key.
 * S2: packed encoded family1-4 values + views + validated snapshot +
 *     candidate binding copy.
 * S3: row_validate_scratch union for typed/witness same-record path.
 * No second 4096 value buffer.
 * Has-previous is an explicit session flag; length 0 is never a first-row
 * sentinel.
 */
typedef struct ninlil_domain_scan_workspace {
    uint8_t key[NINLIL_DOMAIN_SCAN_KEY_CAPACITY];
    uint8_t value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];
    uint8_t previous_key[NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY];
    uint8_t encoded_values[NINLIL_DOMAIN_SCAN_ENCODED_VALUES_BYTES];
    ninlil_bytes_view_t encoded_views[
        NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT];
    ninlil_model_runtime_store_validated_snapshot_t validated;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_domain_scan_row_scratch_t row_validate_scratch;
} ninlil_domain_scan_workspace_t;

#if defined(__cplusplus)
static_assert(
    sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES,
    "D2-S3 domain scan workspace exceeds DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES");
#else
_Static_assert(
    sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES,
    "D2-S3 domain scan workspace exceeds DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES");
#endif

/*
 * Session/control object. Zero-initialize or call session_init only on
 * fresh/non-live storage. Calling session_init on OPEN/EXHAUSTED/FAILED is a
 * caller contract violation that can leak Port resources; it is not safe to
 * wipe a live session.
 *
 * DONE is terminal for this object; begin re-entry requires a new session
 * (fresh init), never DONE→IDLE reuse.
 *
 * Counter overflow (ok/family14/current-domain) is D2-detectable corruption
 * (sticky STORAGE_CORRUPT); increments never wrap.
 */
typedef struct ninlil_domain_scan_session {
    ninlil_domain_scan_state_t state;
    /* Bound at successful begin pre-validation / Port path start. */
    const ninlil_storage_ops_t *bound_storage;
    ninlil_storage_handle_t *bound_handle_slot;
    ninlil_domain_scan_workspace_t *bound_workspace;
    ninlil_storage_handle_t bound_handle_value;
    /*
     * Scanner still holds fence authority over bound_handle_value (has not
     * yet closed it). Independent of the caller slot's current contents.
     */
    uint8_t original_handle_authority;
    ninlil_storage_txn_t txn;
    ninlil_storage_iter_t iter;
    uint8_t txn_live;
    uint8_t iter_live;
    uint8_t has_previous;
    uint32_t previous_key_length;
    uint8_t has_sticky_primary;
    ninlil_status_t sticky_primary;
    uint8_t recognizable_future_seen;
    uint8_t profile_mismatch;
    uint8_t future_profile_candidate;
    uint8_t profile_exact_active;
    /* 1 after successful production profiled gate (reconciliation required). */
    uint8_t profile_reconciliation;
    uint32_t profile_get_present_mask;
    uint32_t family14_iter_seen_mask;
    uint64_t family14_row_count;
    uint64_t current_domain_key_count;
    uint64_t ok_row_count;
    uint32_t reopen_required;
    ninlil_storage_status_t cleanup_status;
    uint8_t fence_pending;
} ninlil_domain_scan_session_t;

/*
 * Authoritative result is published only by successful adopt finalize.
 * Unadopted outcomes keep adopted=0; status still reports finalize/abort
 * aggregation. Profile diagnostics are oracle-visible private fields.
 */
typedef struct ninlil_domain_scan_result {
    uint32_t adopted;
    ninlil_status_t status;
    uint32_t reopen_required;
    ninlil_storage_status_t cleanup_status;
    uint64_t family14_row_count;
    uint64_t current_domain_key_count;
    uint64_t ok_row_count;
    uint8_t recognizable_future_seen;
    uint8_t profile_exact_active;
    uint8_t profile_mismatch;
    uint8_t future_profile_candidate;
    uint32_t profile_get_present_mask;
    uint32_t family14_iter_seen_mask;
} ninlil_domain_scan_result_t;

/*
 * Initialize a fresh/non-live session object to IDLE with zero live Port
 * children. Must not be used to wipe OPEN/EXHAUSTED/FAILED sessions.
 */
void ninlil_domain_scan_session_init(ninlil_domain_scan_session_t *session);

/*
 * Production profiled begin (tests-OFF release only begin).
 * Required non-NULL typed candidate; same READ_ONLY txn; exact 17 get order
 * with typed capacities; validate_snapshot + compare_binding; one zero-prefix
 * iterator. Candidate is exact-copied into workspace before the first Port
 * call; the caller pointer is never retained.
 */
ninlil_status_t ninlil_domain_scan_begin_profiled(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate);

#if defined(NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN)
/*
 * TEST-build S1 transport-only begin (no get / no profile gate).
 * Compile-declared only under NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN.
 * Absent from tests-OFF release declaration and object symbols.
 * Forbidden for S6 / Stage 5 / production orchestration.
 */
ninlil_status_t ninlil_domain_scan_begin(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace);
#endif

/*
 * Process up to row_budget successful OK rows using bound Port/workspace.
 * row_budget==0 is INVALID_ARGUMENT with Port call 0.
 */
ninlil_status_t ninlil_domain_scan_advance(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget);

/*
 * Cleanup tree + outcome aggregation on bound Port/handle. out_result must be
 * pairwise disjoint from session, bound workspace, bound ops object, and bound
 * handle slot; overlap is INVALID_ARGUMENT with Port 0 and live state
 * unchanged.
 */
ninlil_status_t ninlil_domain_scan_finalize(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result);

/* Discard result and run the same cleanup tree. Always unadopted. */
ninlil_status_t ninlil_domain_scan_abort(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_DOMAIN_STORE_SCANNER_H */
