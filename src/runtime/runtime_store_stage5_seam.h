#ifndef NINLIL_RUNTIME_STORE_STAGE5_SEAM_H
#define NINLIL_RUNTIME_STORE_STAGE5_SEAM_H

/*
 * D2-S6 private fail-closed Stage 5 integration seam.
 * Production-private; not installed; not a public C ABI.
 *
 * Composes L2b1 bootstrap-only orchestrator + production domain scanner
 * (begin_profiled only). Does not complete Stage 5, D3, D4, identity,
 * health, public runtime_create, Bearer/clock/entropy, Stage 9, or ESP-IDF.
 *
 * Explicit non-claims:
 *   - D3 finding correctness
 *   - D4 recovery / metadata mutation
 *   - identity rotation
 *   - health reconstruction / publish
 *   - public runtime_create / Runtime publish
 *   - Bearer / clock / entropy open
 *   - Stage 9 publish gate
 *   - ESP-IDF / hardware
 *   - storage_recovery_complete (always false from this seam)
 */

#include "domain_store_scanner.h"
#include "runtime_store_orchestrator.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fixed positive advance budget for the existing-profile scan lifecycle.
 * Matches D2 composition budget 64 (docs/17 D2-S5 / S6).
 */
#define NINLIL_RUNTIME_STORE_STAGE5_SCAN_BUDGET ((uint32_t)64u)

/*
 * Private integration outcomes. Not a public status enum.
 * NONE: no successful integration step (or scanner non-adopt path).
 * NEW_BOOTSTRAP_STAGE5_PENDING: L2b1 wrote FULL 17; scanner not invoked;
 *   no Runtime/Bearer publish; Stage 5 still incomplete.
 * EXISTING_SCAN_ADOPTED_D3_PENDING: scanner finalize adopted OK; Stage 5
 *   still incomplete (D3/D4 pending); storage_recovery_complete remains 0.
 *
 * Never publish OK with OUTCOME_NONE (closed: maps to STORAGE_CORRUPT).
 */
typedef enum ninlil_runtime_store_stage5_outcome {
    NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE = 0,
    NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING = 1,
    NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING = 2
} ninlil_runtime_store_stage5_outcome_t;

typedef struct ninlil_runtime_store_stage5_result {
    ninlil_runtime_store_stage5_outcome_t outcome;
    ninlil_storage_status_t cleanup_status;
    uint32_t reopen_required;
    /* Always 0: this seam never claims Stage 5 / recovery complete. */
    uint32_t storage_recovery_complete;
    /* L2b1 diagnostics (bootstrap path and pre-scan failure). */
    ninlil_runtime_store_bootstrap_outcome_t bootstrap_outcome;
    /*
     * scan_ran: 1 only when the scanner lifecycle was actually entered
     * (begin_profiled was called). Prevalidation rejects and L2b1-only
     * paths leave this 0. A failed begin_profiled still sets scan_ran=1.
     */
    uint32_t scan_ran;
    uint32_t scan_adopted;
    ninlil_status_t scan_status;
    uint64_t family14_row_count;
    uint64_t current_domain_key_count;
    uint64_t ok_row_count;
    uint8_t recognizable_future_seen;
    uint8_t profile_exact_active;
    uint8_t profile_mismatch;
    uint8_t future_profile_candidate;
    uint32_t profile_get_present_mask;
    uint32_t family14_iter_seen_mask;
} ninlil_runtime_store_stage5_result_t;

/*
 * Caller-owned bounded Stage 5 workspace.
 *
 * Production contract: allocate from the Runtime arena (never task stack).
 * Host unit tests may place this on the test stack for convenience, but that
 * does not relax the production arena requirement.
 *
 * Seam functions themselves must not declare workspace-sized automatic locals;
 * they accept a caller-owned pointer only.
 *
 * candidate_binding + session live outside the phase union so L2b1→scan
 * handoff can preserve the exact L2b1 candidate while reusing phase memory.
 * No heap allocation in the seam.
 */
typedef struct ninlil_runtime_store_stage5_workspace {
    ninlil_model_runtime_store_binding_t candidate_binding;
    ninlil_domain_scan_session_t session;
    union {
        ninlil_runtime_store_bootstrap_workspace_t l2b1;
        ninlil_domain_scan_workspace_t scan;
    } phase;
} ninlil_runtime_store_stage5_workspace_t;

/*
 * Documented current ceiling from actual layout:
 *   candidate (144) + session (144 with optional D3 ptr; Stage5 does not bind D3)
 *   + max(L2b1 ws, scanner ws 8192)
 * Round headroom for alignment/padding. Not a permanent ESP stack budget.
 */
#define NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES ((uint32_t)8704u)

#if defined(__cplusplus)
static_assert(sizeof(ninlil_runtime_store_stage5_workspace_t)
        <= NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES,
    "Stage5 seam workspace exceeds documented current ceiling");
#else
_Static_assert(sizeof(ninlil_runtime_store_stage5_workspace_t)
        <= NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES,
    "Stage5 seam workspace exceeds documented current ceiling");
#endif

/*
 * Private Stage 5 fail-closed hookup.
 *
 * 1. Call L2b1 orchestrate_bootstrap first (same handle/validation/hooks).
 * 2. NEW_BOOTSTRAP_COMMITTED → NEW_BOOTSTRAP_STAGE5_PENDING + NINLIL_OK;
 *    scanner is not invoked (pre-bootstrap empty path has no profiled scan).
 * 3. EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED → copy L2b1 candidate, then
 *    real scanner lifecycle: session_init, begin_profiled, advance(64) until
 *    EXHAUSTED/FAILED, finalize. Never TEST transport begin. Never
 *    note_terminal_corrupt (no real D3). Never reimplement scanner SM.
 * 4. Scanner adopted OK → EXISTING_SCAN_ADOPTED_D3_PENDING + NINLIL_OK;
 *    storage_recovery_complete stays 0; Stage 5 incomplete.
 * 5. Scanner OK with adopted==0 → STORAGE_CORRUPT + OUTCOME_NONE (never OK+NONE).
 * 6. Scanner UNSUPPORTED/CORRUPT/Port/fence map exactly; adopted false;
 *    reopen_required/cleanup_status and original-handle fencing preserved;
 *    no second precedence layer.
 *
 * No bearer/clock/entropy parameters: the seam cannot open them.
 *
 * Prevalidation publication contract:
 *   Validate all required pointers, storage ops, non-NULL handle, and
 *   pairwise alias/disjointness before any out_result or workspace mutation.
 *   Pairwise checks include storage↔validation and, when hooks is non-NULL,
 *   hooks↔storage and hooks↔validation (const-const uintptr ranges).
 *   Every INVALID_ARGUMENT prevalidation failure leaves poisoned
 *   out_result/workspace bytes unchanged. Outputs are initialized only after
 *   full prevalidation succeeds.
 */
ninlil_status_t ninlil_runtime_store_stage5_private_hookup(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_runtime_store_hook_dispatcher_t *hooks,
    ninlil_runtime_store_stage5_workspace_t *workspace,
    ninlil_runtime_store_stage5_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_STORE_STAGE5_SEAM_H */
