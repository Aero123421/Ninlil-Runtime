#ifndef NINLIL_V1_DURABLE_RESTART_H
#define NINLIL_V1_DURABLE_RESTART_H

/*
 * V1-LAB unit 1b: POSIX SQLite restart recovery (production-private).
 * Composes Stage5 seam + durable publication gate. Not public ABI.
 *
 * storage_recovery_complete=1 only when scanner adopt + publication gate OK
 * (success evidence > 0, false success 0).
 */

#include "runtime_store_stage5_seam.h"
#include "v1_durable_allowlist.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_v1_durable_restart_result {
    ninlil_runtime_store_stage5_result_t stage5;
    ninlil_v1_durable_recovery_publication_result_t publication;
    /* 1 iff scanner adopted and publication gate published success evidence. */
    uint32_t storage_recovery_complete;
} ninlil_v1_durable_restart_result_t;

/*
 * Existing-profile restart recovery: Stage5 seam then storage-scanned publication
 * gate. commit_unknown_active!=0 forces COMMIT_UNKNOWN reject (evidence 0).
 */
ninlil_status_t ninlil_v1_durable_restart_recovery(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    uint32_t commit_unknown_active,
    ninlil_runtime_store_stage5_workspace_t *workspace,
    ninlil_v1_durable_restart_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_V1_DURABLE_RESTART_H */
