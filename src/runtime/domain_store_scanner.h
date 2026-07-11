#ifndef NINLIL_DOMAIN_STORE_SCANNER_H
#define NINLIL_DOMAIN_STORE_SCANNER_H

/*
 * D2-S1 private Domain Store bounded scanner core.
 * Production-private; not installed. Not a public C ABI.
 *
 * Implements docs/17-foundation-domain-store.md §15.1–15.7 / §15.4 S1
 * coarse classification only. No profile gate (S2), body structural (S3),
 * cross-row (D3), recovery mutation (D4), or Stage 5 orchestration (S6).
 *
 * Ownership binding:
 *   begin() binds non-owning pointers to storage ops, handle slot, and
 *   workspace plus a snapshot of the original handle value into the session.
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

#ifdef __cplusplus
extern "C" {
#endif

/* Doc bound DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES (private; not public ABI). */
#define NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES ((uint32_t)8192u)
#define NINLIL_DOMAIN_SCAN_KEY_CAPACITY ((uint32_t)255u)
#define NINLIL_DOMAIN_SCAN_VALUE_CAPACITY ((uint32_t)4096u)
#define NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY ((uint32_t)255u)

typedef enum ninlil_domain_scan_state {
    NINLIL_DOMAIN_SCAN_STATE_IDLE = 0,
    NINLIL_DOMAIN_SCAN_STATE_OPEN = 1,
    NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED = 2,
    NINLIL_DOMAIN_SCAN_STATE_FAILED = 3,
    NINLIL_DOMAIN_SCAN_STATE_DONE = 4
} ninlil_domain_scan_state_t;

/*
 * Caller-owned fixed scratch (Runtime arena). One key + value + previous-key.
 * Has-previous is an explicit session flag; length 0 is never a first-row
 * sentinel.
 */
typedef struct ninlil_domain_scan_workspace {
    uint8_t key[NINLIL_DOMAIN_SCAN_KEY_CAPACITY];
    uint8_t value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];
    uint8_t previous_key[NINLIL_DOMAIN_SCAN_PREVIOUS_KEY_CAPACITY];
} ninlil_domain_scan_workspace_t;

#if defined(__cplusplus)
static_assert(
    sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES,
    "D2-S1 domain scan workspace exceeds DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES");
#else
_Static_assert(
    sizeof(ninlil_domain_scan_workspace_t)
        <= NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES,
    "D2-S1 domain scan workspace exceeds DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES");
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
    uint8_t profile_mismatch; /* S2 seam; S1 always 0 */
    uint8_t future_profile_candidate; /* S2 seam; S1 always 0 */
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
 * aggregation.
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
} ninlil_domain_scan_result_t;

/*
 * Initialize a fresh/non-live session object to IDLE with zero live Port
 * children. Must not be used to wipe OPEN/EXHAUSTED/FAILED sessions.
 */
void ninlil_domain_scan_session_init(ninlil_domain_scan_session_t *session);

/*
 * Begin READ_ONLY txn + zero-prefix iterator and bind storage/handle/workspace
 * into the session. Pre-validation failures return without Port calls and
 * leave session/workspace unchanged.
 */
ninlil_status_t ninlil_domain_scan_begin(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace);

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
