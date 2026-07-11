#ifndef NINLIL_MODEL_SUBMISSION_ADMISSION_H
#define NINLIL_MODEL_SUBMISSION_ADMISSION_H

#include "submission_preflight.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MODEL_ADMISSION_MAX_PAYLOAD_BYTES ((uint32_t)1024u)
#define NINLIL_MODEL_TRANSACTION_ID_MAX_DRAWS ((uint32_t)4u)

typedef enum ninlil_model_entropy_draw_state {
    NINLIL_MODEL_ENTROPY_DRAW_FULL = 1,
    NINLIL_MODEL_ENTROPY_DRAW_TEMPORARY_FAILURE = 2,
    NINLIL_MODEL_ENTROPY_DRAW_PERMANENT_FAILURE = 3,
    NINLIL_MODEL_ENTROPY_DRAW_PARTIAL = 4
} ninlil_model_entropy_draw_state_t;

typedef enum ninlil_model_transaction_collision_state {
    NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED = 1,
    NINLIL_MODEL_TRANSACTION_ID_UNIQUE = 2,
    NINLIL_MODEL_TRANSACTION_ID_COLLISION = 3,
    NINLIL_MODEL_TRANSACTION_LOOKUP_BUSY = 4,
    NINLIL_MODEL_TRANSACTION_LOOKUP_IO_ERROR = 5,
    NINLIL_MODEL_TRANSACTION_LOOKUP_CORRUPT = 6
} ninlil_model_transaction_collision_state_t;

typedef struct ninlil_model_transaction_id_draw {
    uint32_t ordinal;
    ninlil_model_entropy_draw_state_t entropy_state;
    ninlil_id128_t candidate;
    ninlil_model_transaction_collision_state_t collision_state;
} ninlil_model_transaction_id_draw_t;

typedef struct ninlil_model_owned_payload {
    uint32_t length;
    uint32_t content_verified;
    ninlil_digest256_t verified_content_digest;
    uint8_t bytes[NINLIL_MODEL_ADMISSION_MAX_PAYLOAD_BYTES];
} ninlil_model_owned_payload_t;

typedef struct ninlil_model_descriptor_contract_extension {
    ninlil_direction_t direction;
    ninlil_admission_authority_t admission_authority;
    ninlil_apply_contract_t apply_contract;
    ninlil_custody_policy_t custody_policy;
    uint32_t target_limit;
    uint32_t max_attempts_per_target_per_cycle;
    uint32_t reserved_zero;
    uint64_t attempt_receipt_timeout_ms;
    uint64_t retry_backoff_ms;
    uint64_t application_completion_timeout_ms;
    uint64_t required_dedup_window_ms;
} ninlil_model_descriptor_contract_extension_t;

typedef struct ninlil_model_immutable_descriptor_snapshot {
    ninlil_model_submission_service_t registered_service;
    ninlil_model_descriptor_contract_extension_t contract;
} ninlil_model_immutable_descriptor_snapshot_t;

typedef enum ninlil_model_initial_queue_kind {
    NINLIL_MODEL_INITIAL_COMMAND_OUTBOX = 1,
    NINLIL_MODEL_INITIAL_EVENT_SPOOL = 2
} ninlil_model_initial_queue_kind_t;

typedef enum ninlil_model_initial_family_state {
    NINLIL_MODEL_INITIAL_DESIRED_TARGET_READY = 1,
    NINLIL_MODEL_INITIAL_EVENT_HELD_READY = 2
} ninlil_model_initial_family_state_t;

typedef struct ninlil_model_initial_target_spool_snapshot {
    ninlil_model_initial_family_state_t family_state;
    ninlil_reason_t reason;
    ninlil_evidence_stage_t highest_evidence;
    ninlil_evidence_stage_t latest_evidence;
    ninlil_effect_certainty_t effect_certainty;
    ninlil_deadline_verdict_t deadline_verdict;
    uint32_t dispatch_fenced;
    uint32_t attempts_in_cycle;
    uint64_t retry_cycle_id;
    uint64_t cumulative_attempts;
    ninlil_id128_t current_attempt_id;
    uint32_t timer_present;
    uint32_t cancel_state;
    uint32_t delivery_possible;
    ninlil_event_park_cause_t event_park_cause;
    uint64_t spool_revision;
    ninlil_evidence_stage_t evidence_summary_latest;
    uint32_t evidence_summary_late;
    uint32_t evidence_raw_used;
} ninlil_model_initial_target_spool_snapshot_t;

typedef struct ninlil_model_admission_reservation_manifest {
    uint32_t evidence_summary_used;
    uint32_t evidence_raw_reserved;
    uint32_t command_cancel_slots;
    uint32_t command_cancel_outbox_metadata_slots;
    uint32_t event_resume_slots;
    uint32_t event_resume_slot_bytes;
    uint32_t event_discard_slots;
    uint32_t event_discard_slot_bytes;
    uint64_t event_management_total_bytes;
} ninlil_model_admission_reservation_manifest_t;

typedef struct ninlil_model_mapping_scope {
    ninlil_id128_t source_application_instance_id;
    ninlil_text_id_t namespace_id;
    ninlil_text_id_t service_id;
} ninlil_model_mapping_scope_t;

typedef struct ninlil_model_admission_mapping_record {
    ninlil_model_mapping_scope_t scope;
    ninlil_model_idempotency_key_t caller_key;
    ninlil_id128_t transaction_id;
    ninlil_digest256_t canonical_submission_digest;
} ninlil_model_admission_mapping_record_t;

typedef struct ninlil_model_event_mapping_record {
    ninlil_model_mapping_scope_t scope;
    ninlil_id128_t event_id;
    ninlil_model_idempotency_key_t caller_key;
    ninlil_id128_t transaction_id;
    ninlil_digest256_t canonical_submission_digest;
} ninlil_model_event_mapping_record_t;

typedef struct ninlil_model_bound_grant_record {
    ninlil_model_origin_grant_snapshot_t decision;
    ninlil_party_t source;
    ninlil_service_identity_t service;
    ninlil_concrete_target_t target;
    ninlil_id128_t event_id;
    ninlil_digest256_t content_digest;
    ninlil_evidence_stage_t required_evidence;
    uint32_t payload_length;
} ninlil_model_bound_grant_record_t;

#define NINLIL_MODEL_ADMISSION_WRITE_TRANSACTION_ID_INDEX ((uint32_t)1u << 0)
#define NINLIL_MODEL_ADMISSION_WRITE_TRANSACTION_COUNTER ((uint32_t)1u << 1)
#define NINLIL_MODEL_ADMISSION_WRITE_OWNER_COUNTER       ((uint32_t)1u << 2)
#define NINLIL_MODEL_ADMISSION_WRITE_OWNER_BINDING       ((uint32_t)1u << 3)
#define NINLIL_MODEL_ADMISSION_WRITE_TRANSACTION         ((uint32_t)1u << 4)
#define NINLIL_MODEL_ADMISSION_WRITE_TARGET              ((uint32_t)1u << 5)
#define NINLIL_MODEL_ADMISSION_WRITE_DESCRIPTOR          ((uint32_t)1u << 6)
#define NINLIL_MODEL_ADMISSION_WRITE_PAYLOAD             ((uint32_t)1u << 7)
#define NINLIL_MODEL_ADMISSION_WRITE_CALLER_MAPPING      ((uint32_t)1u << 8)
#define NINLIL_MODEL_ADMISSION_WRITE_QUOTA               ((uint32_t)1u << 9)
#define NINLIL_MODEL_ADMISSION_WRITE_RESOURCES           ((uint32_t)1u << 10)
#define NINLIL_MODEL_ADMISSION_WRITE_INITIAL_QUEUE       ((uint32_t)1u << 11)
#define NINLIL_MODEL_ADMISSION_WRITE_EVIDENCE            ((uint32_t)1u << 12)
#define NINLIL_MODEL_ADMISSION_WRITE_EVENT_MAPPING       ((uint32_t)1u << 13)
#define NINLIL_MODEL_ADMISSION_WRITE_GRANT               ((uint32_t)1u << 14)
#define NINLIL_MODEL_ADMISSION_WRITE_COMMAND_CANCEL      ((uint32_t)1u << 15)
#define NINLIL_MODEL_ADMISSION_WRITE_EVENT_MANAGEMENT    ((uint32_t)1u << 16)

typedef struct ninlil_model_admission_write_set {
    ninlil_durability_t durability;
    uint32_t record_mask;
    ninlil_id128_t transaction_id;
    ninlil_model_admission_plan_t plan;
    ninlil_model_owned_payload_t payload;
    ninlil_model_immutable_descriptor_snapshot_t descriptor;
    ninlil_model_admission_mapping_record_t caller_mapping;
    uint32_t event_mapping_present;
    ninlil_model_event_mapping_record_t event_mapping;
    uint32_t grant_snapshot_present;
    ninlil_model_bound_grant_record_t grant_snapshot;
    ninlil_model_initial_queue_kind_t initial_queue_kind;
    ninlil_model_initial_target_spool_snapshot_t initial_family_snapshot;
    ninlil_transaction_state_t initial_transaction_state;
    ninlil_outcome_t initial_outcome;
    ninlil_reason_t initial_reason;
    uint64_t transaction_record_revision;
    uint64_t event_spool_revision;
    uint32_t command_cancel_reservation_present;
    uint32_t event_management_reservation_present;
    ninlil_model_admission_reservation_manifest_t reservation_manifest;
    ninlil_model_quota_commit_plan_t committed_quota;
    ninlil_model_resource_ledger_t committed_resource_ledger;
    ninlil_admission_assurance_t assurance;
} ninlil_model_admission_write_set_t;

typedef enum ninlil_model_id_allocation_action {
    NINLIL_MODEL_ID_ALLOCATION_NEEDS_DRAW = 1,
    NINLIL_MODEL_ID_ALLOCATION_TERMINAL = 2,
    NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT = 3
} ninlil_model_id_allocation_action_t;

typedef struct ninlil_model_id_allocation_input {
    ninlil_model_admission_plan_t preflight_plan;
    ninlil_model_owned_payload_t payload;
    ninlil_model_descriptor_contract_extension_t descriptor_contract;
    uint32_t draw_count;
    ninlil_model_transaction_id_draw_t
        draws[NINLIL_MODEL_TRANSACTION_ID_MAX_DRAWS];
} ninlil_model_id_allocation_input_t;

typedef struct ninlil_model_id_allocation_result {
    ninlil_model_id_allocation_action_t action;
    ninlil_status_t api_status;
    ninlil_submission_result_t public_result;
    uint32_t draws_consumed;
    uint32_t next_draw_ordinal;
    uint32_t health_degraded;
    ninlil_reason_t health_add_cause;
    uint32_t health_clear_entropy_transaction_id;
    ninlil_model_admission_write_set_t write_set;
} ninlil_model_id_allocation_result_t;

typedef enum ninlil_model_admission_commit_state {
    NINLIL_MODEL_ADMISSION_COMMIT_OK = 1,
    NINLIL_MODEL_ADMISSION_COMMIT_NO_SPACE = 2,
    NINLIL_MODEL_ADMISSION_COMMIT_BUSY = 3,
    NINLIL_MODEL_ADMISSION_COMMIT_IO_ERROR = 4,
    NINLIL_MODEL_ADMISSION_COMMIT_CORRUPT = 5,
    NINLIL_MODEL_ADMISSION_COMMIT_UNKNOWN = 6
} ninlil_model_admission_commit_state_t;

typedef enum ninlil_model_admission_ownership {
    NINLIL_MODEL_ADMISSION_OWNERSHIP_NOT_ESTABLISHED = 0,
    NINLIL_MODEL_ADMISSION_OWNERSHIP_ESTABLISHED = 1,
    NINLIL_MODEL_ADMISSION_OWNERSHIP_UNRESOLVED = 2
} ninlil_model_admission_ownership_t;

typedef enum ninlil_model_admission_recovery_action {
    NINLIL_MODEL_ADMISSION_RECOVERY_NONE = 0,
    NINLIL_MODEL_ADMISSION_RECOVERY_FENCE_AND_REOPEN_JOURNAL = 1
} ninlil_model_admission_recovery_action_t;

typedef struct ninlil_model_admission_commit_input {
    ninlil_model_admission_write_set_t write_set;
    ninlil_model_admission_commit_state_t commit_state;
} ninlil_model_admission_commit_input_t;

typedef struct ninlil_model_admission_recovery_probe {
    ninlil_id128_t transaction_id;
    ninlil_model_mapping_scope_t mapping_scope;
    ninlil_model_idempotency_key_t caller_key;
    ninlil_digest256_t canonical_submission_digest;
    uint32_t event_id_present;
    ninlil_id128_t event_id;
} ninlil_model_admission_recovery_probe_t;

typedef struct ninlil_model_admission_commit_result {
    ninlil_status_t api_status;
    ninlil_submission_result_t public_result;
    ninlil_model_admission_ownership_t ownership;
    uint32_t durable_write_set_present;
    uint32_t recovery_required;
    ninlil_model_admission_recovery_action_t recovery_action;
    ninlil_id128_t journal_operation_id;
    ninlil_reason_t health_add_cause;
    uint32_t recovery_probe_present;
    ninlil_model_admission_recovery_probe_t recovery_probe;
    /*
     * On COMMIT_UNKNOWN this is the expected atomic group, not a statement of
     * durability. Journal reopening is authoritative; the probe is diagnostic.
     */
    uint32_t staged_write_set_present;
    ninlil_model_admission_write_set_t staged_write_set_for_reconcile;
    ninlil_model_admission_write_set_t durable_write_set;
} ninlil_model_admission_commit_result_t;

ninlil_status_t ninlil_model_reduce_transaction_id_allocation(
    const ninlil_model_id_allocation_input_t *input,
    ninlil_model_id_allocation_result_t *out_result);

ninlil_status_t ninlil_model_reduce_admission_commit(
    const ninlil_model_admission_commit_input_t *input,
    ninlil_model_admission_commit_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
