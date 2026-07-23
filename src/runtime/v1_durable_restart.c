#include "v1_durable_restart.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

ninlil_status_t ninlil_v1_durable_restart_recovery(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    uint32_t commit_unknown_active,
    ninlil_runtime_store_stage5_workspace_t *workspace,
    ninlil_v1_durable_restart_result_t *out_result)
{
    ninlil_status_t status;
    ninlil_status_t gate_status;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    status = ninlil_runtime_store_stage5_private_hookup(
        storage,
        inout_handle,
        validation,
        NULL,
        workspace,
        &out_result->stage5);
    if (status != NINLIL_OK) {
        return status;
    }
    if (out_result->stage5.scan_adopted == 0u) {
        return status;
    }

    gate_status = ninlil_v1_durable_recovery_publication_gate_storage(
        storage,
        *inout_handle,
        commit_unknown_active,
        &out_result->publication);
    if (gate_status != NINLIL_OK) {
        out_result->storage_recovery_complete = 0u;
        return gate_status;
    }

    if (out_result->publication.success_evidence_count != 0u
        && out_result->publication.adopted != 0u) {
        out_result->storage_recovery_complete = 1u;
    }
    return NINLIL_OK;
}
