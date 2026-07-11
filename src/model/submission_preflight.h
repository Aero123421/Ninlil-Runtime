#ifndef NINLIL_MODEL_SUBMISSION_PREFLIGHT_H
#define NINLIL_MODEL_SUBMISSION_PREFLIGHT_H

#include "resource_ledger_batch.h"

#include <ninlil/transaction.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_model_submission_preflight_action {
    NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL = 1,
    NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION = 2,
    NINLIL_MODEL_SUBMISSION_PREFLIGHT_CAPACITY_BLOCK_COMMIT_REQUIRED = 3
} ninlil_model_submission_preflight_action_t;

typedef enum ninlil_model_local_submission_side {
    NINLIL_MODEL_LOCAL_SUBMISSION_SENDER = 1,
    NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER = 2
} ninlil_model_local_submission_side_t;

typedef enum ninlil_model_mapping_state {
    NINLIL_MODEL_MAPPING_ABSENT = 1,
    NINLIL_MODEL_MAPPING_MATCH = 2,
    NINLIL_MODEL_MAPPING_MISMATCH = 3,
    NINLIL_MODEL_MAPPING_STORAGE_FAILURE = 4
} ninlil_model_mapping_state_t;

typedef enum ninlil_model_origin_authority_fact {
    NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE = 1,
    NINLIL_MODEL_ORIGIN_AUTH_ALLOW = 2,
    NINLIL_MODEL_ORIGIN_AUTH_DENY = 3,
    NINLIL_MODEL_ORIGIN_AUTH_TEMPORARY_FAILURE = 4,
    NINLIL_MODEL_ORIGIN_AUTH_PERMANENT_OR_INVALID = 5
} ninlil_model_origin_authority_fact_t;

typedef enum ninlil_model_admission_clock_state {
    NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED = 1,
    NINLIL_MODEL_ADMISSION_CLOCK_TEMPORARY_OR_UNCERTAIN = 2,
    NINLIL_MODEL_ADMISSION_CLOCK_PERMANENT_OR_INVALID = 3
} ninlil_model_admission_clock_state_t;

typedef struct ninlil_model_existing_admission {
    ninlil_id128_t transaction_id;
    ninlil_digest256_t canonical_submission_digest;
    ninlil_admission_assurance_t assurance;
} ninlil_model_existing_admission_t;

typedef struct ninlil_model_mapping_fact {
    ninlil_model_mapping_state_t state;
    ninlil_status_t failure_status;
    uint32_t record_verified;
    ninlil_model_existing_admission_t existing;
} ninlil_model_mapping_fact_t;

typedef struct ninlil_model_submission_service {
    ninlil_family_t family;
    ninlil_model_local_submission_side_t local_side;
    ninlil_party_t source;
    ninlil_service_identity_t identity;
    uint16_t schema_major;
    uint16_t schema_minor_min;
    uint16_t schema_minor_max;
    uint16_t reserved_zero_u16;
    uint32_t supported_evidence_mask;
    uint32_t logical_payload_limit;
    uint32_t inflight_limit;
    uint32_t admission_window_ms;
    uint32_t max_admissions_per_window;
    uint32_t max_payload_bytes_per_window;
    uint32_t max_evidence_per_target;
    uint64_t minimum_deadline_ms;
    uint64_t maximum_deadline_ms;
    uint64_t maximum_evidence_grace_ms;
} ninlil_model_submission_service_t;

typedef struct ninlil_model_idempotency_key {
    uint8_t length;
    uint8_t bytes[64];
} ninlil_model_idempotency_key_t;

typedef struct ninlil_model_semantic_submission {
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t target_count;
    ninlil_concrete_target_t target;
    ninlil_evidence_stage_t required_evidence;
    uint32_t payload_length;
    uint32_t content_digest_matches;
    uint64_t effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_model_idempotency_key_t idempotency_key;
    ninlil_digest256_t content_digest;
    ninlil_digest256_t canonical_submission_digest;
    ninlil_id128_t event_id;
    uint64_t generation;
} ninlil_model_semantic_submission_t;

typedef struct ninlil_model_admission_clock_fact {
    ninlil_model_admission_clock_state_t state;
    ninlil_id128_t clock_epoch_id;
    uint64_t now_ms;
} ninlil_model_admission_clock_fact_t;

typedef struct ninlil_model_origin_grant_snapshot {
    ninlil_id128_t provider_id;
    uint64_t provider_revision;
    ninlil_digest256_t decision_digest;
    ninlil_id128_t grant_id;
    uint64_t grant_revision;
    ninlil_id128_t clock_epoch_id;
    uint64_t evaluated_at_ms;
    uint64_t valid_from_ms;
    uint64_t expires_at_ms;
    uint32_t max_payload_bytes;
    uint32_t max_active_spool_count;
    uint64_t max_active_spool_bytes;
    uint32_t rate_window_ms;
    uint32_t max_admissions_per_window;
    uint32_t max_attempts_per_retry_cycle;
} ninlil_model_origin_grant_snapshot_t;

typedef struct ninlil_model_origin_authority_result {
    /* ALLOW and DENY mean the outer adapter already validated the Port tuple. */
    ninlil_model_origin_authority_fact_t fact;
    ninlil_reason_t deny_reason;
    ninlil_retry_guidance_t deny_guidance;
    uint64_t deny_retry_delay_ms;
    ninlil_model_origin_grant_snapshot_t grant;
} ninlil_model_origin_authority_result_t;

typedef struct ninlil_model_service_quota_snapshot {
    uint64_t inflight_count;
    uint64_t admissions_in_window;
    uint64_t payload_bytes_in_window;
    uint32_t window_is_current;
} ninlil_model_service_quota_snapshot_t;

typedef struct ninlil_model_event_grant_usage {
    uint64_t active_spool_count;
    uint64_t active_spool_bytes;
} ninlil_model_event_grant_usage_t;

typedef struct ninlil_model_submission_preflight_input {
    ninlil_model_submission_service_t service;
    ninlil_model_semantic_submission_t submission;
    ninlil_model_mapping_fact_t caller_key_mapping;
    ninlil_model_mapping_fact_t event_id_mapping;
    ninlil_model_admission_clock_fact_t clock;
    uint64_t last_transaction_sequence;
    uint64_t last_scheduler_owner_sequence;
    ninlil_model_origin_authority_result_t authority;
    ninlil_model_service_quota_snapshot_t quota;
    ninlil_model_event_grant_usage_t event_grant_usage;
    ninlil_model_resource_ledger_t resource_ledger;
} ninlil_model_submission_preflight_input_t;

typedef struct ninlil_model_quota_commit_plan {
    ninlil_id128_t clock_epoch_id;
    uint64_t window_started_at_ms;
    uint64_t next_inflight_count;
    uint64_t next_admissions_in_window;
    uint64_t next_payload_bytes_in_window;
    uint64_t next_event_active_spool_count;
    uint64_t next_event_active_spool_bytes;
} ninlil_model_quota_commit_plan_t;

typedef struct ninlil_model_resource_reservation_plan {
    uint32_t reserve_request_count;
    ninlil_model_capacity_batch_request_t
        reserve_requests[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    uint32_t commit_request_count;
    ninlil_model_capacity_batch_request_t
        commit_requests[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    ninlil_model_resource_ledger_t reserved_ledger;
    ninlil_model_resource_ledger_t committed_ledger;
} ninlil_model_resource_reservation_plan_t;

typedef struct ninlil_model_admission_plan {
    ninlil_family_t family;
    ninlil_model_submission_service_t registered_service;
    ninlil_party_t source;
    ninlil_concrete_target_t target;
    ninlil_service_identity_t service;
    ninlil_model_idempotency_key_t idempotency_key;
    ninlil_digest256_t content_digest;
    ninlil_digest256_t canonical_submission_digest;
    ninlil_id128_t event_id;
    uint64_t generation;
    ninlil_evidence_stage_t required_evidence;
    uint32_t payload_length;
    uint64_t transaction_sequence;
    uint64_t scheduler_owner_sequence;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_ms;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t absolute_evidence_close_ms;
    ninlil_model_quota_commit_plan_t quota;
    ninlil_model_resource_reservation_plan_t resources;
    ninlil_model_origin_grant_snapshot_t grant;
} ninlil_model_admission_plan_t;

/*
 * This preflight plan is pointer-free. The next slice must combine it with the
 * still caller-owned payload bytes and the registered immutable descriptor
 * record identified by service before transaction-ID allocation/FULL commit.
 * No payload ownership or descriptor durability is established here.
 */

typedef struct ninlil_model_capacity_block_plan {
    ninlil_model_resource_ledger_t next_ledger;
    ninlil_resource_kind_t failing_kind;
    uint32_t failing_request_ordinal;
} ninlil_model_capacity_block_plan_t;

typedef struct ninlil_model_submission_preflight_result {
    ninlil_model_submission_preflight_action_t action;
    ninlil_status_t api_status;
    ninlil_submission_result_t public_result;
    ninlil_model_admission_plan_t admission;
    ninlil_model_capacity_block_plan_t capacity_block;
} ninlil_model_submission_preflight_result_t;

ninlil_status_t ninlil_model_submission_preflight(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
