#ifndef NINLIL_RUNTIME_INTERNAL_H
#define NINLIL_RUNTIME_INTERNAL_H

/*
 * V1-LAB unit 2a private runtime body (spine). Not public ABI.
 */

#include "runtime_lifecycle_model.h"
#include "resource_ledger.h"
#include "runtime_store_stage5_seam.h"
#include "stage5_empty_metadata.h"
#include "submission_preflight.h"
#include "v1_durable_allowlist.h"
#include "runtime_v1_transaction_codec.h"

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_MAGIC ((uint32_t)0x4e524c31u)

typedef enum ninlil_rt_lifecycle {
    NINLIL_RT_LIFECYCLE_CREATING = 1,
    NINLIL_RT_LIFECYCLE_LIVE = 2,
    NINLIL_RT_LIFECYCLE_DESTROYING = 3,
    NINLIL_RT_LIFECYCLE_DESTROYED = 4
} ninlil_rt_lifecycle_t;

typedef enum ninlil_rt_step_phase {
    NINLIL_RT_STEP_PHASE_IDLE = 0,
    NINLIL_RT_STEP_PHASE_CLOCK = 1,
    NINLIL_RT_STEP_PHASE_RECOVERY = 2,
    NINLIL_RT_STEP_PHASE_BEARER = 3,
    NINLIL_RT_STEP_PHASE_WORK = 4,
    NINLIL_RT_STEP_PHASE_PROJECT = 5
} ninlil_rt_step_phase_t;

struct ninlil_service {
    uint32_t magic;
    struct ninlil_runtime *runtime;
    uint32_t slot_index;
};

typedef struct ninlil_rt_service_slot {
    uint32_t in_use;
    uint32_t attached;
    ninlil_service_t public_handle;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_model_submission_service_t model_service;
    uint64_t quota_inflight;
    uint64_t quota_admissions;
    uint64_t quota_payload_bytes;
    uint8_t quota_window_epoch[16];
    uint64_t quota_window_start_ms;
} ninlil_rt_service_slot_t;

typedef enum ninlil_rt_delivery_phase {
    NINLIL_RT_DELIVERY_NONE = 0,
    NINLIL_RT_DELIVERY_QUEUED = 1,
    NINLIL_RT_DELIVERY_STARTED = 2,
    NINLIL_RT_DELIVERY_EVIDENCED = 3,
    NINLIL_RT_DELIVERY_OUTCOME = 4,
    NINLIL_RT_DELIVERY_PARKED = 5,
    NINLIL_RT_DELIVERY_RECOVERY_REQUIRED = 6
} ninlil_rt_delivery_phase_t;

typedef enum ninlil_rt_token_state {
    NINLIL_RT_TOKEN_NONE = 0,
    NINLIL_RT_TOKEN_ACTIVE = 1,
    NINLIL_RT_TOKEN_CONSUMED = 2,
    NINLIL_RT_TOKEN_EXPIRED = 3,
    NINLIL_RT_TOKEN_RECOVERY_REQUIRED = 4
} ninlil_rt_token_state_t;

#define NINLIL_RT_V1_MAX_TARGETS_PER_TXN 4u
#define NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES 926u
#define NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN 8u

typedef struct ninlil_rt_target_slot {
    uint8_t in_use;
    uint8_t evidence_recorded;
    uint8_t pending_dispatch;
    uint8_t reserved_zero;
    ninlil_concrete_target_t target;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
} ninlil_rt_target_slot_t;

#define NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY 8u

typedef struct ninlil_rt_v1_latest_state_scope {
    uint8_t in_use;
    uint8_t reserved_zero[3];
    ninlil_id128_t service_app_id;
    uint64_t last_applied_generation;
} ninlil_rt_v1_latest_state_scope_t;

typedef struct ninlil_rt_v1_measurement_scope {
    uint8_t in_use;
    uint8_t reserved_zero[3];
    ninlil_id128_t service_app_id;
    uint64_t highest_batch_sequence;
    uint64_t retained_through_sequence;
} ninlil_rt_v1_measurement_scope_t;

typedef struct ninlil_rt_v1_transfer_scope {
    uint8_t in_use;
    uint8_t state;
    uint8_t apply_count;
    uint8_t reserved_zero;
    ninlil_id128_t transaction_id;
    uint32_t bytes_received;
    uint32_t expected_total_bytes;
} ninlil_rt_v1_transfer_scope_t;

typedef struct ninlil_rt_v1_config_scope {
    uint8_t in_use;
    uint8_t stage;
    uint8_t reserved_zero[2];
    ninlil_id128_t service_app_id;
    uint64_t active_revision;
    uint64_t last_known_good_revision;
} ninlil_rt_v1_config_scope_t;

typedef struct ninlil_rt_v1_family_workspace {
    ninlil_rt_v1_latest_state_scope_t latest_state[NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY];
    ninlil_rt_v1_measurement_scope_t measurement[NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY];
    ninlil_rt_v1_transfer_scope_t transfer[NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY];
    ninlil_rt_v1_config_scope_t config[NINLIL_RT_V1_FAMILY_SCOPE_CAPACITY];
} ninlil_rt_v1_family_workspace_t;

typedef struct ninlil_rt_metrics_counters {
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
} ninlil_rt_metrics_counters_t;

/*
 * LAB-private transition hook seam.  It is intentionally absent from the
 * installed/public ABI; private conformance tests use it to place faults at
 * named commit boundaries without adding production Port methods.
 */
typedef void (*ninlil_rt_private_transition_hook_fn)(
    void *user,
    const char *name);

typedef struct ninlil_rt_event_retry_summary {
    uint64_t retry_cycle_id;
    uint32_t attempt_count;
    uint32_t delivery_possible_any;
    ninlil_reason_t last_reason;
    uint32_t reserved_zero;
    ninlil_id128_t last_observed_clock_epoch_id;
    uint64_t last_observed_at_ms;
} ninlil_rt_event_retry_summary_t;

typedef struct ninlil_rt_transaction_slot {
    uint32_t in_use;
    uint32_t terminal;
    uint32_t origin_admission;
    uint32_t has_late_evidence;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    uint32_t attempt_prepared;
    uint32_t attempt_count;
    ninlil_id128_t attempt_ids[NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN];
    ninlil_id128_t service_app_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    ninlil_family_t family;
    ninlil_evidence_stage_t required_evidence;
    ninlil_evidence_stage_t latest_evidence;
    ninlil_application_result_kind_t application_result_kind;
    ninlil_disposition_t application_disposition;
    ninlil_reason_t application_result_reason;
    ninlil_effect_certainty_t application_effect_certainty;
    ninlil_retry_guidance_t application_retry_guidance;
    uint64_t application_retry_delay_ms;
    uint32_t application_evidence_length;
    uint8_t application_evidence[128];
    ninlil_deadline_verdict_t deadline_verdict;
    uint64_t transaction_sequence;
    uint64_t record_revision;
    ninlil_cancel_kind_t cancel_kind;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    uint32_t pending_dispatch;
    ninlil_rt_delivery_phase_t delivery_phase;
    uint64_t delivery_count;
    ninlil_rt_token_state_t token_state;
    uint32_t deferred_wait;
    ninlil_id128_t token_clock_epoch_id;
    uint64_t token_generation;
    uint64_t delivery_started_at_ms;
    uint64_t token_expires_at_ms;
    uint64_t application_completion_timeout_ms;
    uint64_t spool_revision;
    uint32_t event_park_cause;
    uint32_t event_discarded;
    uint32_t retry_budget;
    uint64_t retry_cycle_id;
    uint32_t attempt_in_cycle;
    uint64_t cumulative_attempts;
    uint32_t retry_summary_count;
    ninlil_rt_event_retry_summary_t retry_summaries[
        NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS];
    uint64_t older_retry_cycle_count;
    uint64_t older_retry_attempt_count;
    uint32_t older_retry_delivery_possible_any;
    ninlil_reason_t older_retry_last_reason;
    ninlil_id128_t older_retry_last_observed_clock_epoch_id;
    uint64_t older_retry_last_observed_at_ms;
    uint64_t next_retry_ms;
    ninlil_id128_t next_retry_clock_epoch_id;
    uint64_t effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_id128_t admission_clock_epoch_id;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t generation;
    uint32_t resume_op_count;
    ninlil_id128_t last_resume_operation_id;
    uint32_t evidence_recorded;
    uint32_t outcome_recorded;
    uint32_t payload_length;
    uint8_t semantic_priority;
    uint8_t bearer_route;
    uint32_t reservation_active;
    uint32_t reservation_evidence_units;
    uint64_t admitted_at_ms;
    uint64_t attempt_receipt_timeout_ms;
    uint64_t retry_backoff_ms;
    ninlil_id128_t send_observed_clock_epoch_id;
    uint64_t send_observed_at_ms;
    uint64_t last_bearer_availability_epoch;
    uint64_t last_consumed_bearer_availability_epoch;
    uint32_t send_observation_closed;
    uint32_t reverse_receipt_closed;
    uint32_t ingress_pending;
    uint32_t receipt_pending;
    uint64_t ordered_input_sequence;
    uint8_t owned_payload[NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES];
    ninlil_admission_assurance_t assurance;
    uint32_t bound_target_count;
    ninlil_rt_target_slot_t bound_targets[NINLIL_RT_V1_MAX_TARGETS_PER_TXN];
} ninlil_rt_transaction_slot_t;

struct ninlil_runtime {
    uint32_t magic;
    ninlil_rt_lifecycle_t lifecycle;
    uint64_t owner_context_id;
    const ninlil_platform_ops_t *platform;
    ninlil_model_runtime_config_projection_t config;
    ninlil_model_capacity_limits_t capacity_limits;
    ninlil_model_resource_ledger_t resource_ledger;
    ninlil_model_resource_ledger_t resource_ledger_scratch;
    uint32_t resource_ledger_restore_mask;
    uint8_t *namespace_bytes;
    uint32_t namespace_length;
    ninlil_storage_handle_t storage;
    ninlil_bearer_handle_t bearer;
    uint32_t storage_recovery_complete;
    uint32_t commit_unknown_fence;
    ninlil_time_sample_t started_sample;
    ninlil_id128_t metrics_epoch_id;
    ninlil_rt_metrics_counters_t metrics;
    ninlil_rt_private_transition_hook_fn private_transition_hook;
    void *private_transition_hook_user;
    ninlil_runtime_health_t health;
    ninlil_reason_t degraded_reason;
    uint64_t transaction_sequence;
    uint64_t last_assigned_scheduler_owner_sequence;
    uint64_t last_assigned_ordered_input_sequence;
    uint64_t last_visited_scheduler_owner_sequence;
    ninlil_rt_service_slot_t *services;
    uint32_t service_count;
    uint32_t service_capacity;
    ninlil_rt_transaction_slot_t *transactions;
    uint32_t transaction_count;
    uint32_t transaction_capacity;
    uint32_t nonterminal_transaction_count;
    uint32_t in_step;
    uint32_t in_callback;
    ninlil_rt_step_phase_t step_phase;
    uint32_t pending_work;
    uint32_t bearer_state_present;
    uint32_t bearer_available;
    uint64_t bearer_availability_epoch;
    ninlil_id128_t bearer_observed_clock_epoch_id;
    uint64_t bearer_observed_at_ms;
    uint32_t step_bearer_state_valid;
    uint32_t step_bearer_available;
    uint64_t step_bearer_availability_epoch;
    ninlil_runtime_store_stage5_workspace_t stage5_ws;
    ninlil_stage5_empty_metadata_workspace_t empty_ws;
    ninlil_rt_v1_family_workspace_t family_workspace;
    /*
     * Owner-thread-only durable transaction workspaces. Keeping these on the
     * Runtime object prevents multi-kilobyte automatic frames on ESP32 while
     * retaining bounded, allocation-free encode/decode and atomic candidate
     * publication.
     */
    uint8_t transaction_codec_bytes[
        NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t durable_scan_value[
        NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    ninlil_application_result_t callback_result_scratch;
    uint8_t callback_evidence_scratch[NINLIL_MAX_EVIDENCE_BYTES];
    ninlil_rt_transaction_slot_t transaction_decode_scratch;
    ninlil_rt_transaction_slot_t transaction_scratch;
};

ninlil_status_t ninlil_rt_validate_live_runtime(
    ninlil_runtime_t *runtime,
    uint32_t allow_destroying);

/*
 * A COMMIT_UNKNOWN result makes the durable truth unknowable in the current
 * process.  Read-only inspection and destroy remain available, but every
 * mutation entry point must fail before consulting any mutable Port or
 * consuming a work budget.  Only destroy followed by create/recovery may
 * clear this fence.
 */
ninlil_status_t ninlil_rt_validate_mutation_allowed(
    const ninlil_runtime_t *runtime);

ninlil_status_t ninlil_rt_validate_owner_thread(
    ninlil_runtime_t *runtime,
    uint32_t allow_callback);

void ninlil_rt_zero_submission_result(ninlil_submission_result_t *result);
void ninlil_rt_zero_cancel_result(ninlil_cancel_result_t *result);
void ninlil_rt_zero_step_result(ninlil_step_result_t *result);

ninlil_rt_transaction_slot_t *ninlil_rt_find_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id);

ninlil_rt_transaction_slot_t *ninlil_rt_alloc_transaction(
    ninlil_runtime_t *runtime);

int ninlil_rt_service_descriptor_matches_transaction(
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_rt_transaction_slot_t *transaction);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_INTERNAL_H */
