#ifndef NINLIL_DOMAIN_STORE_SCANNER_H
#define NINLIL_DOMAIN_STORE_SCANNER_H

/*
 * D2-S5 private Domain Store bounded scanner core.
 * Production-private; not installed. Not a public C ABI.
 *
 * Implements docs/17-foundation-domain-store.md §15.1–15.7 / §15.10 / §15.11
 * / §15.12 / §15.9 S1–S5.
 * Production path: ninlil_domain_scan_begin_profiled (required candidate,
 * same-txn 17 get + validate/compare + one zero-prefix iterator).
 * Exact-profile CURRENT family 5/6 rows: typed same-record (business+7d)
 * or witness header/chunk local framing (7e/7f). S4 same-snapshot
 * production-private exact_get while the sole iterator remains live.
 * S5 composition: note_terminal_corrupt D3 injection seam + DSR1/DSR2
 * complete gates (D2 bounded scanner only).
 * S1 transport-only begin is TEST-build only
 * (NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN) and does not run domain
 * body structural validation.
 *
 * Claims D2 (bounded scanner) / DSR1_SCAN / DSR2_ESP_BOUND complete and hosts
 * the completed D3-S1 private begin_profiled_d3s1 + Modes 1–20 evaluator.
 * Private D3-S2 (begin_profiled_d3s2 / multipass) is implemented.
 * Private D3-S3 (begin_profiled_d3s3 / BLOB lifecycle) is under development and
 * not claimed complete. D3 overall / Stage 5 / D4 / public Runtime / ESP-IDF
 * / hardware remain incomplete. S1 and S2 contexts are mutually exclusive
 * per session when S2 is bound.
 * Session does not retain full ID sets or unused xref digest/kind/count fields.
 *
 * Ownership binding:
 *   begin binds non-owning pointers to storage ops, handle slot, and
 *   workspace plus a snapshot of the original handle value into the session.
 *   Profiled begin also exact-copies the candidate binding into workspace
 *   before the first Port call and never retains the caller pointer.
 *   advance/exact_get/finalize/abort use only those bound fields for Port
 *   calls and cleanup; callers cannot substitute a different
 *   Port/handle/workspace mid-session via the API surface.
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
 * S4: exact_get reuses the single value buffer (capacity NINLIL_DOMAIN_SCAN_VALUE_CAPACITY).
 * No second max-value buffer. No full-ID set.
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
    "D2-S5 domain scan workspace exceeds DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES");
#else
_Static_assert(
    sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES,
    "D2-S5 domain scan workspace exceeds DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES");
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
/* Incomplete: full layouts in domain_store_d3s1.h / d3s2.h / d3s3.h (not installed). */
struct ninlil_domain_scan_d3s1_context;
struct ninlil_domain_scan_d3s2_context;
struct ninlil_domain_scan_d3s3_context;

/* bound_d3_kind: exclusive S1/S2/S3 (or none). Not a public ABI. */
#define NINLIL_DOMAIN_SCAN_D3_KIND_NONE ((uint8_t)0u)
#define NINLIL_DOMAIN_SCAN_D3_KIND_S1 ((uint8_t)1u)
#define NINLIL_DOMAIN_SCAN_D3_KIND_S2 ((uint8_t)2u)
#define NINLIL_DOMAIN_SCAN_D3_KIND_S3 ((uint8_t)3u)

typedef struct ninlil_domain_scan_session {
    ninlil_domain_scan_state_t state;
    /* Bound at successful begin pre-validation / Port path start. */
    const ninlil_storage_ops_t *bound_storage;
    ninlil_storage_handle_t *bound_handle_slot;
    ninlil_domain_scan_workspace_t *bound_workspace;
    /*
     * D3 context binding (non-owning). S1/S2/S3 are mutually exclusive and
     * share one pointer slot so session future sizeof stays within the S1a
     * 144-byte pin (docs/17 §18.12). Dual-bound is forbidden.
     * Active type is bound_d3_kind (packed with other u8s below):
     *   0 = none (D2-only), 1 = S1, 2 = S2, 3 = S3.
     * Stage5 does not bind/run D3 until S12.
     */
    union {
        struct ninlil_domain_scan_d3s1_context *bound_d3_context;
        struct ninlil_domain_scan_d3s2_context *bound_d3s2_context;
        struct ninlil_domain_scan_d3s3_context *bound_d3s3_context;
    };
    ninlil_storage_handle_t bound_handle_value;
    /*
     * Scanner still holds fence authority over bound_handle_value (has not
     * yet closed it). Independent of the caller slot's current contents.
     */
    uint8_t original_handle_authority;
    /* Packed with adjacent u8s; not between pointers (keeps session ≤144). */
    uint8_t bound_d3_kind;
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
 * D2-S4 same-snapshot exact get (docs/17 §15.11).
 * Legal only in OPEN and EXHAUSTED. Performs exactly one Storage get on the
 * bound READ_ONLY txn while the sole iterator remains live. Never consumes
 * row_budget or changes ok-row counters / iterator position.
 *
 * key: length 1..255, non-NULL. May borrow external storage or
 * workspace->key / workspace->previous_key (S4 exception to generic
 * readonly-input alias). Must be address-safe and disjoint from
 * workspace->value (output area) and from out_result.
 *
 * On OK+PRESENT: out_result borrows workspace->value until the next
 * advance / exact_get / finalize / abort. Present zero-length uses
 * presence=PRESENT with empty view. Clean NOT_FOUND returns OK+ABSENT.
 * Port-path failure leaves *out_result unchanged and sets sticky/FAILED.
 */
typedef enum ninlil_domain_scan_exact_presence {
    NINLIL_DOMAIN_SCAN_EXACT_ABSENT = 0,
    NINLIL_DOMAIN_SCAN_EXACT_PRESENT = 1
} ninlil_domain_scan_exact_presence_t;

typedef struct ninlil_domain_scan_exact_get_result {
    ninlil_domain_scan_exact_presence_t presence;
    ninlil_bytes_view_t value;
} ninlil_domain_scan_exact_get_result_t;

ninlil_status_t ninlil_domain_scan_exact_get(
    ninlil_domain_scan_session_t *session,
    ninlil_bytes_view_t key,
    ninlil_domain_scan_exact_get_result_t *out_result);

/*
 * D2-S5 D3 corruption injection / aggregation seam (docs/17 §15.12.2).
 * Production-private. No status argument. No public include change.
 *
 * NULL session -> INVALID_ARGUMENT (Port 0).
 * Legal only in OPEN or EXHAUSTED:
 *   Port call 0; set first sticky primary to STORAGE_CORRUPT; state FAILED;
 *   preserve candidate/future flags, counters, previous key, workspace,
 *   iter/txn ownership, binding, fence_pending; no cleanup/fence;
 *   return STORAGE_CORRUPT.
 * IDLE / DONE / FAILED -> INVALID_STATE with no mutation and Port 0.
 *
 * D3 supplies finding correctness; this API only injects sticky terminal
 * corruption so finalize/abort aggregation outranks future/profile candidates.
 */
ninlil_status_t ninlil_domain_scan_note_terminal_corrupt(
    ninlil_domain_scan_session_t *session);

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
