#ifndef NINLIL_V1_DURABLE_ALLOWLIST_H
#define NINLIL_V1_DURABLE_ALLOWLIST_H

/*
 * V1-LAB durable profile closed allowlist (unit 1a).
 * Production-private; not installed; not a public C ABI.
 *
 * Writer gate: fail-closed before any durable put (generation 0, explicit
 * error, no false success). Recovery publication gate: reject allowlist-
 * external / unknown / corrupt / mixed rows and COMMIT_UNKNOWN restart
 * before publication (success evidence 0, bounded termination).
 *
 * Scope: D3-S1..S3 fully verifiable record kinds/states/operations only.
 * D3-S4..S12, public ABI changes, and test weakening are out of scope.
 */

#include <ninlil/platform.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT ((uint32_t)30u)
#define NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT ((uint32_t)14u)

typedef enum ninlil_v1_durable_record_kind {
    NINLIL_V1_DURABLE_KIND_RS_BINDING = 1,
    NINLIL_V1_DURABLE_KIND_RS_IDENTITY = 2,
    NINLIL_V1_DURABLE_KIND_RS_COUNTER_TRANSACTION = 3,
    NINLIL_V1_DURABLE_KIND_RS_COUNTER_ORDERED_INPUT = 4,
    NINLIL_V1_DURABLE_KIND_RS_COUNTER_ASSIGNED_OWNER = 5,
    NINLIL_V1_DURABLE_KIND_RS_COUNTER_VISITED_OWNER = 6,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_SERVICE = 7,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TRANSACTION = 8,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_TARGET = 9,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_OUTBOX_BYTES = 10,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DELIVERY = 11,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_COUNT = 12,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVENT_SPOOL_BYTES = 13,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_RESULT_CACHE = 14,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_EVIDENCE = 15,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_INGRESS = 16,
    NINLIL_V1_DURABLE_KIND_RS_CAPACITY_DEFERRED_TOKEN = 17,
    NINLIL_V1_DURABLE_KIND_DOM_WITNESS_HEAD_INDEX = 18,
    NINLIL_V1_DURABLE_KIND_DOM_CLOCK_BASELINE = 19,
    NINLIL_V1_DURABLE_KIND_SPINE_SERVICE_MARKER = 20,
    NINLIL_V1_DURABLE_KIND_SPINE_TXN_ADMISSION = 21,
    NINLIL_V1_DURABLE_KIND_SPINE_CANCEL_ADMISSION = 22,
    NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_STARTED = 23,
    NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_EVIDENCE = 24,
    NINLIL_V1_DURABLE_KIND_SPINE_DELIVERY_OUTCOME = 25,
    NINLIL_V1_DURABLE_KIND_SPINE_EVENT_SPOOL = 26,
    NINLIL_V1_DURABLE_KIND_SPINE_EVENT_RESUME = 27,
    NINLIL_V1_DURABLE_KIND_SPINE_EVENT_DISCARD = 28,
    NINLIL_V1_DURABLE_KIND_SPINE_RETRY_STATE = 29,
    NINLIL_V1_DURABLE_KIND_SPINE_RESERVATION = 30
} ninlil_v1_durable_record_kind_t;

typedef enum ninlil_v1_durable_verification_owner {
    NINLIL_V1_DURABLE_OWNER_S1 = 1,
    NINLIL_V1_DURABLE_OWNER_S2 = 2,
    NINLIL_V1_DURABLE_OWNER_S3 = 3
} ninlil_v1_durable_verification_owner_t;

typedef enum ninlil_v1_durable_operation {
    NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT = 1,
    NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT = 2,
    NINLIL_V1_DURABLE_OP_CLOCK_TRUSTED_COMMIT = 3,
    NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT = 4,
    NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT = 5,
    NINLIL_V1_DURABLE_OP_CANCEL_ADMISSION_COMMIT = 6,
    NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT = 7,
    NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT = 8,
    NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT = 9,
    NINLIL_V1_DURABLE_OP_EVENT_SPOOL_COMMIT = 10,
    NINLIL_V1_DURABLE_OP_EVENT_RESUME_COMMIT = 11,
    NINLIL_V1_DURABLE_OP_EVENT_DISCARD_COMMIT = 12,
    NINLIL_V1_DURABLE_OP_RETRY_STATE_COMMIT = 13,
    NINLIL_V1_DURABLE_OP_RESERVATION_COMMIT = 14
} ninlil_v1_durable_operation_t;

typedef enum ninlil_v1_durable_recovery_reject_reason {
    NINLIL_V1_DURABLE_RECOVERY_REJECT_NONE = 0,
    NINLIL_V1_DURABLE_RECOVERY_REJECT_ALLOWLIST_EXTERNAL = 1,
    NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN = 2,
    NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT = 3,
    NINLIL_V1_DURABLE_RECOVERY_REJECT_MIXED = 4,
    NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN = 5
} ninlil_v1_durable_recovery_reject_reason_t;

typedef struct ninlil_v1_durable_allowlist_row {
    ninlil_v1_durable_record_kind_t kind;
    ninlil_v1_durable_verification_owner_t owner;
    const char *name;
} ninlil_v1_durable_allowlist_row_t;

typedef struct ninlil_v1_durable_recovery_publication_result {
    uint32_t adopted;
    uint32_t success_evidence_count;
    ninlil_v1_durable_recovery_reject_reason_t reject_reason;
} ninlil_v1_durable_recovery_publication_result_t;

/* Closed authority table (compile-time sized). */
extern const ninlil_v1_durable_allowlist_row_t
    g_ninlil_v1_durable_allowlist_table[
        NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT];

/*
 * Classify a storage row key/value into a V1-LAB record kind.
 * Returns NINLIL_OK with *out_kind on match; NINLIL_E_UNSUPPORTED if
 * outside the closed V1-LAB profile; other errors for corrupt shape.
 */
ninlil_status_t ninlil_v1_durable_classify_row(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_v1_durable_record_kind_t *out_kind);

/*
 * Writer gate: operation + row must be in the closed operation→kind matrix.
 * Fail-closed: NINLIL_E_UNSUPPORTED (no put, no false success).
 */
ninlil_status_t ninlil_v1_durable_writer_gate_check(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);

/*
 * Sole production durable put entry (writer gate enforced).
 * When inout_fence is non-NULL, sets *inout_fence on COMMIT_UNKNOWN or
 * unknown raw storage status (sticky OR).
 */
ninlil_status_t ninlil_v1_durable_storage_put(
    ninlil_v1_durable_operation_t operation,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *inout_fence);

/*
 * Recovery publication gate: scan rows before publish/recovery complete.
 * commit_unknown_active!=0 → reject COMMIT_UNKNOWN (success evidence 0).
 * On any reject: adopted=0, success_evidence_count=0.
 */
ninlil_status_t ninlil_v1_durable_recovery_publication_gate(
    const ninlil_bytes_view_t *row_keys,
    const ninlil_bytes_view_t *row_values,
    uint32_t row_count,
    uint32_t commit_unknown_active,
    ninlil_v1_durable_recovery_publication_result_t *out_result);

/*
 * Publication gate over committed storage rows (namespace iterator).
 * Bounded: iterator fail-closed; no heap. Used by V1 restart recovery (unit 1b).
 */
ninlil_status_t ninlil_v1_durable_recovery_publication_gate_storage(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    uint32_t commit_unknown_active,
    ninlil_v1_durable_recovery_publication_result_t *out_result);

/*
 * RED probe: synthetic allowlist-external domain kind for negative tests.
 * Returns NINLIL_E_UNSUPPORTED from writer_gate_check (never OK).
 */
ninlil_status_t ninlil_v1_durable_probe_disallowed_writer_kind(
    ninlil_v1_durable_operation_t operation,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_V1_DURABLE_ALLOWLIST_H */
