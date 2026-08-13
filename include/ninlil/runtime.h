/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Ninlil Foundation Runtime public contract.
 * Normative details: docs/04-runtime-api-and-storage.md and
 * docs/12-foundation-abi.md.
 *
 * Ownership/lifetime: except for the post-validation destroy rule documented
 * at ninlil_runtime_destroy(), input pointers and views are borrowed for the
 * call. create copies configuration values, the storage namespace and platform
 * vtable values; non-NULL vtable/callback user pointees and function code stay
 * caller-owned through Runtime destruction. Runtime owns its opaque Service
 * handles. Callback views expire on callback return; copy a delivery token's
 * value when deferring work rather than retaining a callback pointer.
 *
 * Execution: create captures the owner context, Runtime creates no thread, and
 * callbacks run only inside runtime_step. Mutating calls from another context
 * or from a callback are rejected; only the documented read-only query/list/
 * capacity/metrics callback exceptions apply.
 *
 * Status taxonomy: ninlil_status_t reports API invocation, not Application
 * success. Submission result, Delivery disposition and Transaction outcome
 * are separate semantic outputs. A durability COMMIT_UNKNOWN is never success.
 */
#ifndef NINLIL_RUNTIME_H
#define NINLIL_RUNTIME_H

#include "ninlil/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_resource_limits {
    NINLIL_STRUCT_HEADER;
    uint32_t max_services;
    uint32_t max_nonterminal_transactions;
    uint32_t max_targets_per_transaction;
    uint32_t max_logical_payload_bytes;
    uint64_t max_durable_outbox_payload_bytes;
    uint32_t max_attempts_per_target_per_cycle;
    uint32_t max_cancel_attempts_per_transaction;
    uint32_t max_evidence_per_target;
    uint32_t max_retained_terminal_transactions;
    uint32_t max_nonterminal_deliveries;
    uint32_t max_event_spool_count;
    uint64_t max_event_spool_bytes;
    uint32_t max_result_cache_entries;
    uint32_t max_retained_dispositions;
    uint32_t max_ingress_per_step;
    uint32_t max_callbacks_per_step;
    uint32_t max_state_transitions_per_step;
    uint32_t max_bearer_sends_per_step;
    uint32_t max_deferred_tokens;
    uint32_t reserved_zero;
} ninlil_resource_limits_t;

typedef struct ninlil_runtime_config {
    NINLIL_STRUCT_HEADER;
    ninlil_role_t role;
    ninlil_environment_t environment;
    ninlil_id128_t runtime_id;
    ninlil_local_identity_t local_identity;
    ninlil_bytes_view_t storage_namespace;
    ninlil_resource_limits_t limits;
    uint64_t terminal_retention_ms;
    uint64_t result_cache_retention_ms;
    uint64_t observation_retention_ms;
    uint32_t reserved_zero;
} ninlil_runtime_config_t;

typedef struct ninlil_step_budget {
    NINLIL_STRUCT_HEADER;
    uint32_t max_ingress_messages;
    uint32_t max_callbacks;
    uint32_t max_state_transitions;
    uint32_t max_bearer_sends;
} ninlil_step_budget_t;

typedef struct ninlil_step_result {
    NINLIL_STRUCT_HEADER;
    uint32_t ingress_processed;
    uint32_t callbacks_invoked;
    uint32_t state_transitions;
    uint32_t bearer_sends;
    uint32_t transactions_terminalized;
    uint32_t events_parked;
    uint32_t more_work;
    uint32_t has_next_wake;
    ninlil_id128_t next_wake_clock_epoch_id;
    uint64_t next_wake_at_ms;
    ninlil_runtime_health_t health;
    ninlil_reason_t degraded_reason;
    uint32_t reserved_zero;
} ninlil_step_result_t;

#define NINLIL_HEALTH_OK                   ((ninlil_runtime_health_t)1u)
#define NINLIL_HEALTH_DEGRADED             ((ninlil_runtime_health_t)2u)
#define NINLIL_HEALTH_FATAL                ((ninlil_runtime_health_t)3u) /* M1a reserved; never generated */

#define NINLIL_RESOURCE_SERVICE            ((ninlil_resource_kind_t)1u)
#define NINLIL_RESOURCE_TRANSACTION        ((ninlil_resource_kind_t)2u)
#define NINLIL_RESOURCE_TARGET             ((ninlil_resource_kind_t)3u)
#define NINLIL_RESOURCE_OUTBOX_BYTES       ((ninlil_resource_kind_t)4u)
#define NINLIL_RESOURCE_DELIVERY           ((ninlil_resource_kind_t)5u)
#define NINLIL_RESOURCE_EVENT_SPOOL_COUNT  ((ninlil_resource_kind_t)6u)
#define NINLIL_RESOURCE_EVENT_SPOOL_BYTES  ((ninlil_resource_kind_t)7u)
#define NINLIL_RESOURCE_RESULT_CACHE       ((ninlil_resource_kind_t)8u)
#define NINLIL_RESOURCE_EVIDENCE           ((ninlil_resource_kind_t)9u)
#define NINLIL_RESOURCE_INGRESS            ((ninlil_resource_kind_t)10u)
#define NINLIL_RESOURCE_DEFERRED_TOKEN     ((ninlil_resource_kind_t)11u)

typedef struct ninlil_capacity_entry {
    NINLIL_STRUCT_HEADER;
    ninlil_resource_kind_t kind;
    uint32_t reserved_zero;
    uint64_t limit;
    uint64_t used;
    uint64_t reserved;
    uint64_t high_water;
    uint64_t capacity_epoch;
} ninlil_capacity_entry_t;

typedef struct ninlil_capacity_snapshot {
    NINLIL_STRUCT_HEADER;
    /* Caller-owned array. Initialize every provided entry ABI header. */
    ninlil_capacity_entry_t *entries;
    uint32_t entry_capacity;
    /* Required/written count is exactly 11 resource kinds in numeric order. */
    uint32_t entry_count;
} ninlil_capacity_snapshot_t;

typedef struct ninlil_metrics_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t metrics_epoch_id;
    ninlil_id128_t started_clock_epoch_id;
    uint64_t started_at_ms;
    uint64_t submission_calls;
    uint64_t admitted_ready;
    uint64_t already_admitted;
    uint64_t rejected;
    uint64_t idempotency_conflicts;
    uint64_t transactions_satisfied;
    uint64_t transactions_expired;
    uint64_t transactions_failed_definitive;
    uint64_t transactions_outcome_unknown;
    uint64_t events_parked;
    uint64_t events_resumed;
    uint64_t events_discarded;
    uint64_t late_evidence;
    uint64_t duplicate_logical_delivery;
    uint64_t application_callback_invocations;
    uint64_t reconcile_invocations;
    uint64_t delivery_token_timeouts;
    uint64_t storage_failures;
    uint64_t bearer_would_block;
} ninlil_metrics_snapshot_t;

/*
 * Ownership/output: borrows config/platform; copies their values and namespace.
 * On NINLIL_OK, publishes a caller-held Runtime handle; otherwise *out_runtime
 * is NULL. Captures the calling execution context as owner; callback entry is
 * not possible during create.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_CONFLICT,
 * NINLIL_E_CAPACITY_EXHAUSTED, NINLIL_E_STORAGE,
 * NINLIL_E_STORAGE_CORRUPT, NINLIL_E_STORAGE_COMMIT_UNKNOWN,
 * NINLIL_E_CLOCK_UNCERTAIN, NINLIL_E_ENTROPY, NINLIL_E_WOULD_BLOCK,
 * NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_runtime_create(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_runtime_t **out_runtime);

/*
 * Ownership/output: failures before DESTROYING (invalid handle/state, zero or
 * wrong context, or re-entry) do not consume runtime. Once DESTROYING is
 * entered, every return status consumes runtime and all Runtime-owned Service/
 * token handles; cleanup failure never restores them. Owner context only;
 * callback entry is rejected.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_INVALID_STATE, NINLIL_E_WRONG_THREAD, NINLIL_E_REENTRANT,
 * NINLIL_E_DEGRADED, NINLIL_E_WOULD_BLOCK,
 * NINLIL_E_CAPACITY_EXHAUSTED, NINLIL_E_STORAGE,
 * NINLIL_E_STORAGE_CORRUPT, NINLIL_E_STORAGE_COMMIT_UNKNOWN.
 */
ninlil_status_t ninlil_runtime_destroy(ninlil_runtime_t *runtime);

/*
 * Ownership/output: borrows descriptor/callback tables, copies descriptor text
 * and callback/user pointer values, and returns a Runtime-owned Service handle.
 * Caller retains non-NULL user pointees and callback code through destroy.
 * Owner context only; callback entry is rejected.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_REENTRANT, NINLIL_E_CONFLICT, NINLIL_E_CAPACITY_EXHAUSTED,
 * NINLIL_E_STORAGE, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_STORAGE_COMMIT_UNKNOWN, NINLIL_E_WOULD_BLOCK,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_service_register(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_service_t **out_service);

/*
 * Ownership/output: borrows submission and all nested views for the call;
 * admission success durably copies them. Owner context only; callback entry is
 * rejected. NINLIL_OK reports API completion, so inspect out_result->kind for
 * admitted, replayed, rejected, or idempotency-conflict semantics.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_REENTRANT,
 * NINLIL_E_CAPACITY_EXHAUSTED, NINLIL_E_STORAGE,
 * NINLIL_E_STORAGE_CORRUPT, NINLIL_E_STORAGE_COMMIT_UNKNOWN,
 * NINLIL_E_CLOCK_UNCERTAIN, NINLIL_E_ENTROPY, NINLIL_E_WOULD_BLOCK,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_submit(
    ninlil_service_t *service,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result);

/*
 * Ownership/output: borrows offer_id and returns an INVALID semantic result.
 * Owner context only; callback entry is rejected. M1a has no counter-offer
 * acceptance: a well-formed call returns NINLIL_E_UNSUPPORTED, never NINLIL_OK.
 * Reachable statuses: NINLIL_E_INVALID_ARGUMENT, NINLIL_E_ABI_MISMATCH,
 * NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD, NINLIL_E_REENTRANT,
 * NINLIL_E_STORAGE_COMMIT_UNKNOWN, NINLIL_E_INVALID_STATE,
 * NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_offer_accept(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *offer_id,
    ninlil_submission_result_t *out_result);

/*
 * Ownership/output: borrows transaction_id; out_result is caller-owned. Owner
 * context on a Controller only; callback entry is rejected. NINLIL_OK reports
 * the persisted cancel-request state, not completed remote cancellation; inspect
 * out_result->kind/current_outcome.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_REENTRANT, NINLIL_E_NOT_FOUND, NINLIL_E_CAPACITY_EXHAUSTED,
 * NINLIL_E_STORAGE, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_STORAGE_COMMIT_UNKNOWN, NINLIL_E_WOULD_BLOCK,
 * NINLIL_E_CLOCK_UNCERTAIN, NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_cancel_request(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result);

/*
 * Ownership/output: borrows request and audit_metadata; out_result is
 * caller-owned. Endpoint owner context only; callback entry is rejected.
 * NINLIL_OK includes replay, conflict, stale, non-parked, and limit semantic
 * results; inspect out_result->kind rather than treating OK as a state change.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_REENTRANT, NINLIL_E_NOT_FOUND, NINLIL_E_CAPACITY_EXHAUSTED,
 * NINLIL_E_STORAGE, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_STORAGE_COMMIT_UNKNOWN, NINLIL_E_CLOCK_UNCERTAIN,
 * NINLIL_E_WOULD_BLOCK, NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result);

/*
 * Ownership/output: borrows request and audit_metadata; out_result is
 * caller-owned. Endpoint owner context only; callback entry is rejected.
 * NINLIL_OK includes replay, conflict, stale, and already-released semantics;
 * only DISCARDED/ALREADY_DISCARDED makes spool_released non-zero.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_REENTRANT, NINLIL_E_NOT_FOUND, NINLIL_E_CAPACITY_EXHAUSTED,
 * NINLIL_E_STORAGE, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_STORAGE_COMMIT_UNKNOWN, NINLIL_E_CLOCK_UNCERTAIN,
 * NINLIL_E_WOULD_BLOCK, NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result);

/*
 * Ownership/output: borrows transaction_id; caller owns snapshot and target
 * array. BUFFER_TOO_SMALL changes only required target_count; other errors
 * preserve buffer identity/capacity and clear semantic output. Owner context;
 * read-only callback entry is allowed.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD, NINLIL_E_NOT_FOUND,
 * NINLIL_E_BUFFER_TOO_SMALL, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_transaction_query(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *inout_snapshot);

/*
 * Ownership/output: borrows query; caller owns page/items. Writes an ascending
 * partial page within item_capacity and uses cursor/has_more, not
 * BUFFER_TOO_SMALL. Owner context; read-only callback entry is allowed.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_transaction_list(
    ninlil_runtime_t *runtime,
    const ninlil_query_t *query,
    ninlil_transaction_page_t *inout_page);

/*
 * Ownership/output: token is a copied value; result/evidence are borrowed for
 * the call and evidence is deep-copied before a successful durable commit.
 * Owner context only; callback entry is rejected. NINLIL_OK consumes the active
 * token and commits the Application result; it is not a new Application call.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD, NINLIL_E_REENTRANT,
 * NINLIL_E_NOT_FOUND, NINLIL_E_INVALID_STATE, NINLIL_E_CLOCK_UNCERTAIN,
 * NINLIL_E_DEGRADED, NINLIL_E_CAPACITY_EXHAUSTED,
 * NINLIL_E_WOULD_BLOCK, NINLIL_E_STORAGE, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_STORAGE_COMMIT_UNKNOWN.
 */
ninlil_status_t ninlil_delivery_complete(
    ninlil_runtime_t *runtime,
    const ninlil_delivery_token_t *token,
    const ninlil_application_result_t *result);

/*
 * Ownership/output: borrows budget and writes a caller-owned bounded-work
 * snapshot. Owner context only; nested/re-entrant step is rejected. Callbacks
 * may run synchronously inside this call; counters/health are scheduler output,
 * not Transaction outcome or Application success. NINLIL_E_UNSUPPORTED below
 * is reachable only from an enabled private-candidate attachment and does not
 * expand the public Foundation completion claim.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_UNSUPPORTED, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_REENTRANT,
 * NINLIL_E_CAPACITY_EXHAUSTED, NINLIL_E_STORAGE,
 * NINLIL_E_STORAGE_CORRUPT, NINLIL_E_STORAGE_COMMIT_UNKNOWN,
 * NINLIL_E_CLOCK_UNCERTAIN, NINLIL_E_ENTROPY, NINLIL_E_WOULD_BLOCK,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_runtime_step(
    ninlil_runtime_t *runtime,
    const ninlil_step_budget_t *budget,
    ninlil_step_result_t *out_result);

/*
 * Ownership/output: caller owns snapshot/entries. All 11 entries are required;
 * BUFFER_TOO_SMALL publishes only entry_count. Owner context; read-only callback
 * entry is allowed. Values are resource accounting, not admission guarantees.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_BUFFER_TOO_SMALL, NINLIL_E_STORAGE_CORRUPT,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_capacity_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_capacity_snapshot_t *inout_snapshot);

/*
 * Ownership/output: writes a caller-owned logical metrics snapshot; it does not
 * increment counters. Owner context; read-only callback entry is allowed.
 * Metrics are diagnostics and do not replace Transaction semantic output.
 * Reachable statuses: NINLIL_OK, NINLIL_E_INVALID_ARGUMENT,
 * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD,
 * NINLIL_E_INVALID_STATE, NINLIL_E_DEGRADED.
 */
ninlil_status_t ninlil_metrics_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_metrics_snapshot_t *out_snapshot);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_H */
