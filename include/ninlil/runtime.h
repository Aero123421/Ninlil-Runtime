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
    ninlil_capacity_entry_t *entries;
    uint32_t entry_capacity;
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

ninlil_status_t ninlil_runtime_create(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_runtime_t **out_runtime);

ninlil_status_t ninlil_runtime_destroy(ninlil_runtime_t *runtime);

ninlil_status_t ninlil_service_register(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_service_t **out_service);

ninlil_status_t ninlil_submit(
    ninlil_service_t *service,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_offer_accept(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *offer_id,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_cancel_request(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result);

ninlil_status_t ninlil_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result);

ninlil_status_t ninlil_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result);

ninlil_status_t ninlil_transaction_query(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *inout_snapshot);

ninlil_status_t ninlil_transaction_list(
    ninlil_runtime_t *runtime,
    const ninlil_query_t *query,
    ninlil_transaction_page_t *inout_page);

ninlil_status_t ninlil_delivery_complete(
    ninlil_runtime_t *runtime,
    const ninlil_delivery_token_t *token,
    const ninlil_application_result_t *result);

ninlil_status_t ninlil_runtime_step(
    ninlil_runtime_t *runtime,
    const ninlil_step_budget_t *budget,
    ninlil_step_result_t *out_result);

ninlil_status_t ninlil_capacity_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_capacity_snapshot_t *inout_snapshot);

ninlil_status_t ninlil_metrics_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_metrics_snapshot_t *out_snapshot);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_H */
