#include "runtime_store_stage5_seam.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int ranges_are_disjoint(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;

    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - left_start
        || right_length > UINTPTR_MAX - right_start) {
        return 0;
    }
    return left_start + left_length <= right_start
        || right_start + right_length <= left_start;
}

static int storage_ops_required_present(const ninlil_storage_ops_t *storage)
{
    return storage != NULL
        && storage->close != NULL
        && storage->begin != NULL
        && storage->get != NULL
        && storage->put != NULL
        && storage->iter_open != NULL
        && storage->iter_next != NULL
        && storage->iter_close != NULL
        && storage->commit != NULL
        && storage->rollback != NULL;
}

/*
 * Full prevalidation before any out_result/workspace mutation.
 * Returns 1 when arguments are usable; 0 → INVALID_ARGUMENT with poison retained.
 */
static int prevalidate_arguments(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_runtime_store_hook_dispatcher_t *hooks,
    ninlil_runtime_store_stage5_workspace_t *workspace,
    ninlil_runtime_store_stage5_result_t *out_result)
{
    if (out_result == NULL
        || storage == NULL
        || inout_handle == NULL
        || validation == NULL
        || workspace == NULL
        || !storage_ops_required_present(storage)
        || *inout_handle == NULL) {
        return 0;
    }

    if (!ranges_are_disjoint(out_result, sizeof(*out_result),
            storage, sizeof(*storage))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            validation, sizeof(*validation))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(workspace, sizeof(*workspace),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(validation, sizeof(*validation),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(validation, sizeof(*validation),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(storage, sizeof(*storage),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(storage, sizeof(*storage),
            inout_handle, sizeof(*inout_handle))) {
        return 0;
    }

    if (hooks != NULL) {
        if (!ranges_are_disjoint(out_result, sizeof(*out_result),
                hooks, sizeof(*hooks))
            || !ranges_are_disjoint(hooks, sizeof(*hooks),
                workspace, sizeof(*workspace))
            || !ranges_are_disjoint(hooks, sizeof(*hooks),
                inout_handle, sizeof(*inout_handle))) {
            return 0;
        }
    }

    return 1;
}

static void publish_scan_diagnostics(
    ninlil_runtime_store_stage5_result_t *out_result,
    const ninlil_domain_scan_result_t *scan_result)
{
    /* scan_ran: scanner lifecycle was entered (begin_profiled returned). */
    out_result->scan_ran = 1u;
    out_result->scan_adopted = scan_result->adopted;
    out_result->scan_status = scan_result->status;
    out_result->family14_row_count = scan_result->family14_row_count;
    out_result->current_domain_key_count =
        scan_result->current_domain_key_count;
    out_result->ok_row_count = scan_result->ok_row_count;
    out_result->recognizable_future_seen =
        scan_result->recognizable_future_seen;
    out_result->profile_exact_active = scan_result->profile_exact_active;
    out_result->profile_mismatch = scan_result->profile_mismatch;
    out_result->future_profile_candidate =
        scan_result->future_profile_candidate;
    out_result->profile_get_present_mask =
        scan_result->profile_get_present_mask;
    out_result->family14_iter_seen_mask =
        scan_result->family14_iter_seen_mask;
    if (scan_result->reopen_required != 0u) {
        out_result->reopen_required = 1u;
    }
    if (scan_result->cleanup_status != NINLIL_STORAGE_OK) {
        out_result->cleanup_status = scan_result->cleanup_status;
    }
}

static ninlil_status_t run_existing_profile_scan(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_runtime_store_stage5_workspace_t *workspace,
    ninlil_runtime_store_stage5_result_t *out_result)
{
    ninlil_domain_scan_result_t scan_result;
    ninlil_status_t status;

    /*
     * Preserve the exact L2b1 candidate binding before reusing phase memory
     * for the scanner workspace. candidate_binding lives outside the phase
     * union; the copy must complete before any phase zeroing.
     */
    workspace->candidate_binding =
        workspace->phase.l2b1.candidate_binding;
    (void)memset(&workspace->phase.scan, 0, sizeof(workspace->phase.scan));
    ninlil_domain_scan_session_init(&workspace->session);

    status = ninlil_domain_scan_begin_profiled(
        &workspace->session,
        storage,
        inout_handle,
        &workspace->phase.scan,
        &workspace->candidate_binding);
    if (status != NINLIL_OK) {
        /*
         * begin_profiled was entered: scan_ran becomes 1 even on failure.
         * begin_profiled runs cleanup_tree on Port-path failure and ends
         * DONE; pre-Port rejects leave IDLE. Never finalize twice.
         */
        out_result->scan_ran = 1u;
        out_result->scan_adopted = 0u;
        out_result->scan_status = status;
        out_result->outcome = NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE;
        if (workspace->session.reopen_required != 0u) {
            out_result->reopen_required = 1u;
        }
        if (workspace->session.cleanup_status != NINLIL_STORAGE_OK) {
            out_result->cleanup_status = workspace->session.cleanup_status;
        }
        out_result->recognizable_future_seen =
            workspace->session.recognizable_future_seen;
        out_result->profile_exact_active =
            workspace->session.profile_exact_active;
        out_result->profile_mismatch = workspace->session.profile_mismatch;
        out_result->future_profile_candidate =
            workspace->session.future_profile_candidate;
        out_result->profile_get_present_mask =
            workspace->session.profile_get_present_mask;
        out_result->family14_iter_seen_mask =
            workspace->session.family14_iter_seen_mask;
        return status;
    }

    while (workspace->session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        status = ninlil_domain_scan_advance(
            &workspace->session, NINLIL_RUNTIME_STORE_STAGE5_SCAN_BUDGET);
        if (status != NINLIL_OK) {
            break;
        }
    }

    (void)memset(&scan_result, 0, sizeof(scan_result));
    status = ninlil_domain_scan_finalize(
        &workspace->session, &scan_result);
    publish_scan_diagnostics(out_result, &scan_result);
    out_result->storage_recovery_complete = 0u;

    if (status == NINLIL_OK && scan_result.adopted != 0u) {
        out_result->outcome =
            NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING;
        return NINLIL_OK;
    }

    /*
     * Closed mapping: never publish OK + OUTCOME_NONE.
     * Scanner finalize OK with adopted==0 is inconsistent with Stage5 adopt
     * success and maps to STORAGE_CORRUPT (fail-closed).
     */
    out_result->outcome = NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE;
    if (status == NINLIL_OK) {
        out_result->scan_status = NINLIL_E_STORAGE_CORRUPT;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return status;
}

ninlil_status_t ninlil_runtime_store_stage5_private_hookup(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_runtime_store_hook_dispatcher_t *hooks,
    ninlil_runtime_store_stage5_workspace_t *workspace,
    ninlil_runtime_store_stage5_result_t *out_result)
{
    ninlil_runtime_store_bootstrap_result_t bootstrap_result;
    ninlil_status_t status;

    /*
     * Prevalidation is complete before any out_result/workspace write.
     * INVALID_ARGUMENT failures retain caller poison in both objects.
     */
    if (!prevalidate_arguments(
            storage, inout_handle, validation, hooks, workspace, out_result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->storage_recovery_complete = 0u;
    (void)memset(workspace, 0, sizeof(*workspace));
    (void)memset(&bootstrap_result, 0, sizeof(bootstrap_result));

    status = ninlil_runtime_store_orchestrate_bootstrap(
        storage,
        inout_handle,
        validation,
        hooks,
        &workspace->phase.l2b1,
        &bootstrap_result);

    out_result->bootstrap_outcome = bootstrap_result.outcome;
    out_result->cleanup_status = bootstrap_result.cleanup_status;
    out_result->reopen_required = bootstrap_result.reopen_required;
    out_result->storage_recovery_complete = 0u;
    /* Scanner lifecycle not entered yet. */
    out_result->scan_ran = 0u;

    if (status != NINLIL_OK) {
        out_result->outcome = NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE;
        return status;
    }

    if (bootstrap_result.outcome
        == NINLIL_RUNTIME_STORE_NEW_BOOTSTRAP_COMMITTED) {
        /*
         * Pre-bootstrap empty path: L2b1 performed FULL 17 write.
         * Do not invoke the profiled scanner. Explicitly no Runtime/Bearer
         * publish. Stage 5 remains incomplete.
         */
        out_result->outcome =
            NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING;
        out_result->scan_ran = 0u;
        out_result->scan_adopted = 0u;
        out_result->storage_recovery_complete = 0u;
        return NINLIL_OK;
    }

    if (bootstrap_result.outcome
        != NINLIL_RUNTIME_STORE_EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED) {
        out_result->outcome = NINLIL_RUNTIME_STORE_STAGE5_OUTCOME_NONE;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    return run_existing_profile_scan(
        storage, inout_handle, workspace, out_result);
}
