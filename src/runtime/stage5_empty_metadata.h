#ifndef NINLIL_STAGE5_EMPTY_METADATA_H
#define NINLIL_STAGE5_EMPTY_METADATA_H

/*
 * Private Stage 5 empty-domain metadata-init orchestrator (docs/17 §1 / §10.1).
 *
 * Production-private. Not installed. Not a public C ABI.
 *
 * This private initializer/fencer contract is complete for its closed scope.
 * Stage 5 overall completion, D3/D4, public Runtime publish, and
 * COMMIT_UNKNOWN old/new digest convergence are separate responsibilities.
 *
 * Authority binding (anti dead-end / race):
 *   Every commit/validate/clock call requires the L2b1-accepted
 *   ninlil_model_runtime_validation_result_t. Same RW/RO txn re-proves
 *   bootstrap exact-17 by building the canonical plan from that authority
 *   (build_bootstrap_plan + record_at) and byte-exact comparing each get
 *   against expected values. Internal validate_snapshot consistency alone
 *   is never treated as authority match — a race-replaced but
 *   self-consistent binding/identity must fail CORRUPT with put 0.
 *
 * Same txn order (commit / validate / clock before domain put):
 *   1) bootstrap-17 authority exact match (binding/identity/zero counters/
 *      capacity limits/epochs),
 *   2) (commit/validate) 16-key classify + surplus/future scan,
 *   3) write / no-op / CORRUPT as documented.
 *
 * Handle fence: every Port status+shape contributes sticky fence_pending;
 * COMMIT_UNKNOWN / unknown / unsafe shape → close+NULL+reopen_required=1
 * after txn consume. No old/new convergence here.
 *
 * Prevalidation (INVALID_ARGUMENT, Port 0, out_result bytes unchanged):
 *   required pointers; *inout_handle non-NULL; accepted_validation non-NULL
 *   with status==NINLIL_OK; ops complete; pairwise non-alias among storage,
 *   handle slot, validation, workspace, out_result (+ sample for clock).
 *
 * Explicit non-claims: public runtime_create, Stage 5 complete, D3/D4
 * convergence, post-write fresh scan adopt, Command/Event E2E.
 */

#include "domain_store_codec.h"
#include "domain_store_body_codec.h"
#include "runtime_lifecycle_model.h"
#include "runtime_store_bootstrap.h"
#include "runtime_store_codec.h"

#include <ninlil/platform.h>
#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_STAGE5_EMPTY_METADATA_RECORD_COUNT ((uint32_t)16u)
#define NINLIL_STAGE5_EMPTY_HEAD_INDEX_COUNT ((uint32_t)15u)

/* Family 3/4 Runtime Store values are << domain 4KiB (binding max 183). */
#define NINLIL_STAGE5_EMPTY_MEMBER_VALUE_CAPACITY ((uint32_t)256u)
#define NINLIL_STAGE5_EMPTY_SCAN_KEY_CAPACITY ((uint32_t)255u)
#define NINLIL_STAGE5_EMPTY_SCAN_VALUE_CAPACITY \
    NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES

/*
 * Arena-owned workspace ceiling (not ESP task stack). Includes scan buffers,
 * bootstrap packed values, plan, and one record_at scratch.
 */
#define NINLIL_STAGE5_EMPTY_METADATA_WORKSPACE_CEILING_BYTES \
    ((uint32_t)24576u)

typedef struct ninlil_stage5_empty_metadata_result {
    ninlil_storage_status_t cleanup_status;
    /* 1 when handle was closed/NULLed; caller must reopen. */
    uint32_t reopen_required;
    /* 1 only when this call performed a successful 0/16 FULL write+commit. */
    uint32_t wrote_metadata;
    /*
     * Validate path only: 1 iff CLOCK is TRUSTED after successful adopt.
     * Always 0 on any failure.
     */
    uint32_t clock_trusted;
} ninlil_stage5_empty_metadata_result_t;

typedef struct ninlil_stage5_empty_metadata_workspace {
    uint8_t member_value[NINLIL_STAGE5_EMPTY_MEMBER_VALUE_CAPACITY];
    uint8_t encoded_value[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    uint8_t body[NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES];
    uint8_t clock_body[NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES];
    /* Same-txn zero-prefix surplus scan (scanner-composition style). */
    uint8_t scan_key[NINLIL_STAGE5_EMPTY_SCAN_KEY_CAPACITY];
    uint8_t scan_value[NINLIL_STAGE5_EMPTY_SCAN_VALUE_CAPACITY];
    uint8_t previous_key[NINLIL_STAGE5_EMPTY_SCAN_KEY_CAPACITY];
    uint32_t previous_key_length;
    ninlil_model_domain_key_t domain_key;
    ninlil_model_runtime_store_key_t member_key;
    ninlil_model_domain_digest_t member_key_digest;
    ninlil_model_domain_digest_t member_value_digest;
    ninlil_model_domain_digest_t composite_identity;
    /* Prebuilt expected metadata keys for surplus classification. */
    ninlil_model_domain_key_t expected_keys[
        NINLIL_STAGE5_EMPTY_METADATA_RECORD_COUNT];
    /* Same-txn bootstrap-17 authority re-proof. */
    uint8_t bootstrap_encoded[
        NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_VALUE_BYTES];
    ninlil_model_runtime_store_validated_snapshot_t bootstrap_validated;
    ninlil_model_runtime_store_bootstrap_plan_t bootstrap_plan;
    ninlil_model_runtime_store_bootstrap_record_t bootstrap_record;
} ninlil_stage5_empty_metadata_workspace_t;

#if defined(__cplusplus)
static_assert(
    sizeof(ninlil_stage5_empty_metadata_workspace_t)
        <= NINLIL_STAGE5_EMPTY_METADATA_WORKSPACE_CEILING_BYTES,
    "stage5 empty metadata workspace exceeds arena ceiling");
#else
_Static_assert(
    sizeof(ninlil_stage5_empty_metadata_workspace_t)
        <= NINLIL_STAGE5_EMPTY_METADATA_WORKSPACE_CEILING_BYTES,
    "stage5 empty metadata workspace exceeds arena ceiling");
#endif

/*
 * One READ_WRITE FULL transaction: authority bootstrap-17 + 16-key classify +
 * same-txn surplus proof, then write / no-op / CORRUPT.
 *
 * accepted_validation: L2b1-accepted config authority (required, status OK).
 */
ninlil_status_t ninlil_stage5_empty_metadata_commit(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result);

/*
 * READ_ONLY: authority bootstrap-17 + surplus-zero + exact 16 content/binding.
 * Success only after rollback OK. clock_trusted=0 on any failure.
 */
ninlil_status_t ninlil_stage5_empty_metadata_validate(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result);

/*
 * First UNINITIALIZED → TRUSTED only. Re-proves bootstrap-17 authority in
 * the same RW txn before any clock put.
 *
 * Already TRUSTED: same epoch+now → OK mutation 0; else CONFLICT mutation 0.
 * Subsequent accepted sample updates are a separate Stage 7 API.
 */
ninlil_status_t ninlil_stage5_clock_baseline_commit_trusted(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_time_sample_t *trusted_sample,
    const ninlil_model_runtime_validation_result_t *accepted_validation,
    ninlil_stage5_empty_metadata_workspace_t *workspace,
    ninlil_stage5_empty_metadata_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_STAGE5_EMPTY_METADATA_H */
