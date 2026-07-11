#ifndef NINLIL_RUNTIME_STORE_ORCHESTRATOR_H
#define NINLIL_RUNTIME_STORE_ORCHESTRATOR_H

#include "runtime_lifecycle_model.h"
#include "runtime_store_bootstrap.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RUNTIME_STORE_HOOK_BEFORE_NAMESPACE_BINDING_COMMIT \
    "runtime.before_namespace_binding_commit"
#define NINLIL_RUNTIME_STORE_HOOK_AFTER_NAMESPACE_BINDING_COMMIT \
    "runtime.after_namespace_binding_commit"

typedef enum ninlil_runtime_store_bootstrap_outcome {
    NINLIL_RUNTIME_STORE_BOOTSTRAP_OUTCOME_NONE = 0,
    NINLIL_RUNTIME_STORE_NEW_BOOTSTRAP_COMMITTED = 1,
    NINLIL_RUNTIME_STORE_EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED = 2
} ninlil_runtime_store_bootstrap_outcome_t;

typedef struct ninlil_runtime_store_hook_dispatcher {
    void *user;
    void (*dispatch)(void *user, const char *hook_name);
} ninlil_runtime_store_hook_dispatcher_t;

typedef struct ninlil_runtime_store_bootstrap_result {
    ninlil_runtime_store_bootstrap_outcome_t outcome;
    ninlil_storage_status_t cleanup_status;
    uint32_t reopen_required;
} ninlil_runtime_store_bootstrap_result_t;

/*
 * Caller-owned bounded memory. It is intended for a Runtime-owned arena, not
 * an ESP32 task stack. Oversized iterator values use the Runtime allocator
 * transiently and are never retained here.
 */
typedef struct ninlil_runtime_store_bootstrap_workspace {
    ninlil_model_runtime_store_binding_t candidate_binding;
    union {
        struct {
            uint8_t encoded_values[
                NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_VALUE_BYTES];
            ninlil_model_runtime_store_encoded_snapshot_t encoded;
            ninlil_model_runtime_store_validated_snapshot_t validated;
        } existing;
        struct {
            ninlil_model_runtime_store_bootstrap_plan_t plan;
            ninlil_model_runtime_store_bootstrap_record_t record;
        } bootstrap;
        struct {
            uint8_t key[255];
            uint8_t previous_key[255];
            uint8_t value[
                NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES];
        } scan;
    } phase;
} ninlil_runtime_store_bootstrap_workspace_t;

#if defined(__cplusplus)
static_assert(sizeof(ninlil_runtime_store_bootstrap_workspace_t) <= 2560u,
    "Runtime Store bootstrap workspace exceeds the L2b1 bound");
#else
_Static_assert(sizeof(ninlil_runtime_store_bootstrap_workspace_t) <= 2560u,
    "Runtime Store bootstrap workspace exceeds the L2b1 bound");
#endif

/*
 * The Storage handle has already been opened by the caller. On a fencing
 * condition this function closes it and writes NULL to *inout_handle.
 * Domain recovery and identity comparison/rotation deliberately remain later
 * stages; an existing exact profile therefore returns RECOVERY_REQUIRED.
 * When out_result does not overlap another participating range, outcome and
 * diagnostics are reset to NONE/zero before remaining validation continues.
 * An out_result-overlap failure leaves every participating range unchanged.
 */
ninlil_status_t ninlil_runtime_store_orchestrate_bootstrap(
    const ninlil_storage_ops_t *storage,
    const ninlil_allocator_ops_t *allocator,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_runtime_store_hook_dispatcher_t *hooks,
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    ninlil_runtime_store_bootstrap_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
