#ifndef NINLIL_RUNTIME_DOMAIN_SCHEMA1_STARTUP_OWNER_H
#define NINLIL_RUNTIME_DOMAIN_SCHEMA1_STARTUP_OWNER_H

/*
 * ADR-0022 Canonical Domain schema1 startup owner (HOST_CANDIDATE).
 *
 * Production-private, feature-gated (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING).
 * Not installed. Not public ABI. Uses real ninlil_storage_ops.
 *
 * Current private scaffold order (storage recovery, no Bearer/callback/handle):
 *   T0 0-row RW scan -> T1a 17 FULL -> T1b 16 FULL
 *   -> T2 cross-row exact -> T3 rescan fence -> T4 identity
 *   -> T5 trusted clock FULL -> T6 health reconstruct (mutation 0)
 *
 * T2/T3/T6 above are not the complete ADR-0022 authorities yet: D3-S4..S12,
 * D4 convergence, durable health reconstruction, and the canonical operational
 * writers remain incomplete.  Consequently this scaffold may be exercised by
 * private authority tests, but it MUST NOT authorize a public Runtime.
 *
 * Workspace is caller-owned (Runtime arena). No workspace-sized stack locals.
 */

#include "domain_schema1_runtime_binding.h"
#include "domain_schema1_startup_authority.h"
#include "domain_store_body_codec.h"
#include "runtime_lifecycle_model.h"
#include "storage_canonical_plan.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Single fail-closed publication gate for the current implementation state.
 *
 * Promotion to 1u is forbidden until all of the following are accepted and
 * bound to this owner: D3-S1..S12, D4 convergence, real T6 durable-health
 * reconstruction, canonical Domain operational writers, and the mandatory
 * Host/portability acceptance matrix.  This is private implementation state,
 * not public ABI and not a user-configurable feature switch.
 */
#define NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY 0u

#define NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP ((uint32_t)255u)
/* Iterator scan may observe up to private domain record max (4096). */
#define NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_VALUE_CAP ((uint32_t)4096u)
/*
 * Materialized CU snapshot copies. Kind-1 witness chunk complete values are
 * ~882B; keep headroom under private record max without full 4096×48.
 */
#define NINLIL_DOMAIN_SCHEMA1_OWNER_SNAP_VALUE_CAP ((uint32_t)1024u)
/*
 * FOUNDATION-SMALL-1 worst case:
 *   33 bootstrap/metadata + (Controller max_services 16 * 5 new rows).
 * The owner workspace is transient arena storage during Runtime create, not
 * embedded permanently in the live Runtime.
 */
#define NINLIL_DOMAIN_SCHEMA1_MAX_PROFILE_SERVICES ((uint32_t)16u)
#define NINLIL_DOMAIN_SCHEMA1_ROWS_PER_SERVICE ((uint32_t)5u)
#define NINLIL_DOMAIN_SCHEMA1_BASELINE_ROW_COUNT ((uint32_t)33u)
#define NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP \
    ((uint32_t)(NINLIL_DOMAIN_SCHEMA1_BASELINE_ROW_COUNT \
        + NINLIL_DOMAIN_SCHEMA1_MAX_PROFILE_SERVICES \
            * NINLIL_DOMAIN_SCHEMA1_ROWS_PER_SERVICE))

typedef enum ninlil_domain_schema1_owner_outcome {
    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_NONE = 0,
    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_NEW_FULL = 1,
    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_EXISTING_ADOPTED = 2,
    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_COMMIT_UNKNOWN = 3,
    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_FENCED = 4
} ninlil_domain_schema1_owner_outcome_t;

typedef struct ninlil_domain_schema1_owner_result {
    ninlil_domain_schema1_owner_outcome_t outcome;
    ninlil_status_t status;
    ninlil_storage_status_t cleanup_status;
    uint32_t reopen_required;
    /*
     * Private scaffold transcript only. Neither field overrides
     * NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY.
     */
    uint32_t storage_recovery_t0_t6_complete;
    uint32_t t7_ready; /* private stage-order test; never public authority */
    uint32_t wrote_t1a;
    uint32_t wrote_t1b;
    uint32_t wrote_t5;
    ninlil_domain_schema1_t1a_class_t t1a_class;
    ninlil_domain_schema1_group_class_t t1b_class;
    ninlil_domain_schema1_group_class_t t5_class;
    ninlil_domain_schema1_startup_transcript_t transcript;
    ninlil_domain_schema1_lab_namespace_class_t lab_class;
} ninlil_domain_schema1_owner_result_t;

/*
 * Caller-owned workspace (Runtime arena only; not ESP task stack).
 * Scan value cap is 4096 (frame policy). Records are packed here, not on stack.
 */
typedef struct ninlil_domain_schema1_owner_workspace {
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_domain_schema1_bootstrap_plan_t boot_plan;
    ninlil_domain_schema1_metadata_plan_t meta_plan;
    ninlil_domain_schema1_t5_clock_plan_t t5_plan;
    ninlil_domain_schema1_startup_state_t stages;
    ninlil_domain_schema1_bootstrap_record_t boot_records[
        NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT];
    ninlil_domain_schema1_metadata_record_t meta_records[
        NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT];
    ninlil_storage_canonical_row_t apply_rows[
        NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP];
    ninlil_domain_schema1_snapshot_row_t snapshot_rows[
        NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP];
    /* Snapshot materialization buffers (key/value copies for CU classify). */
    uint8_t snap_key[NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP]
                    [NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP];
    uint32_t snap_key_len[NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP];
    uint8_t snap_value[NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP]
                      [NINLIL_DOMAIN_SCHEMA1_OWNER_SNAP_VALUE_CAP];
    uint32_t snap_value_len[NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP];
    uint32_t snap_count;
    uint8_t scan_key[NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP];
    uint8_t scan_value[NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_VALUE_CAP];
    /* Typed D1 decode scratch. Never placed on the create task stack. */
    ninlil_model_domain_typed_record_t typed_record;
    uint8_t trusted_epoch[16];
    uint64_t trusted_now_ms;
} ninlil_domain_schema1_owner_workspace_t;

/* Soft ceiling for arena placement (not task stack). */
#define NINLIL_DOMAIN_SCHEMA1_OWNER_WORKSPACE_CEILING_BYTES \
    ((uint32_t)(sizeof(ninlil_domain_schema1_owner_workspace_t) + 256u))

/*
 * Private T0–T6 scaffold on an already-open handle.
 * Never opens Bearer, never installs callback, never publishes public handle.
 * On COMMIT_UNKNOWN fences handle (close+NULL, reopen_required=1).
 * A success result is not a production-complete recovery claim while
 * NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY is 0u.
 */
ninlil_status_t ninlil_domain_schema1_owner_run_storage_recovery(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_time_sample_t *trusted_sample_or_null,
    ninlil_domain_schema1_owner_workspace_t *workspace,
    ninlil_domain_schema1_owner_result_t *out_result);

/*
 * Private T7 stage-order test after Bearer open + metrics entropy succeeded.
 * Requires storage_recovery_t0_t6_complete from a prior owner result.
 * Still does not attach service callbacks or return a public service handle.
 * Public Runtime code must not call this while the readiness gate is 0u.
 */
ninlil_status_t ninlil_domain_schema1_owner_t7_publication_gate(
    const ninlil_domain_schema1_owner_result_t *storage_result,
    uint32_t bearer_open_ok,
    uint32_t metrics_entropy_ok,
    ninlil_domain_schema1_startup_state_t *stages,
    ninlil_domain_schema1_owner_result_t *out_result);

/*
 * Kind-1 SERVICE_REGISTER atomic group (M=5) on real storage.
 * ALL_NEW durable adoption only — callbacks/handle remain 0 until caller
 * attaches volatile callbacks after OK (explicit reattach contract).
 */
typedef struct ninlil_domain_schema1_kind1_owner_result {
    ninlil_status_t status;
    ninlil_domain_schema1_group_class_t class;
    uint32_t wrote;
    uint32_t reopen_required;
} ninlil_domain_schema1_kind1_owner_result_t;

/*
 * Deprecated thin entry — always returns NINLIL_E_UNSUPPORTED.
 * Production path: ninlil_domain_schema1_service_register (heap workspace,
 * full-namespace begin/final, CU classify_readback OLD/NEW/CORRUPT).
 * Kept only so call sites fail closed rather than silently no-op.
 */
ninlil_status_t ninlil_domain_schema1_kind1_owner_commit(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_schema1_kind1_plan_t *plan,
    const ninlil_bytes_view_t *member_values /* length 5, may be NULL */,
    ninlil_domain_schema1_kind1_owner_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
