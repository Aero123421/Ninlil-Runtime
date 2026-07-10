#ifndef NINLIL_TRANSACTION_H
#define NINLIL_TRANSACTION_H

#include "ninlil/service.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_submission {
    NINLIL_STRUCT_HEADER;
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t reserved_zero;
    const ninlil_concrete_target_t *targets;
    uint32_t target_count;
    ninlil_evidence_stage_t required_evidence;
    uint64_t effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_bytes_view_t idempotency_key;
    ninlil_digest256_t content_digest;
    ninlil_id128_t event_id;
    uint64_t generation;
    ninlil_bytes_view_t payload;
} ninlil_submission_t;

#define NINLIL_ASSURANCE_NONE               ((ninlil_assurance_profile_t)0u)
#define NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL ((ninlil_assurance_profile_t)1u)

typedef struct ninlil_admission_assurance {
    NINLIL_STRUCT_HEADER;
    ninlil_assurance_profile_t assurance_profile;
    uint32_t submission_validated;
    uint32_t target_roster_fixed;
    uint32_t descriptor_snapshot_fixed;
    uint32_t local_journal_committed;
    uint32_t local_capacity_reserved;
    uint32_t idempotency_mapping_committed;
    uint32_t origin_grant_snapshot_committed;
    uint32_t remote_capacity_reserved;
    uint32_t route_feasibility_verified;
    uint32_t receive_window_reserved;
    uint32_t bearer_capacity_reserved;
    uint32_t airtime_reserved;
    uint32_t compliance_permit_issued;
    uint32_t reserved_zero;
} ninlil_admission_assurance_t;

typedef struct ninlil_submission_result {
    NINLIL_STRUCT_HEADER;
    ninlil_submission_kind_t kind;
    ninlil_reason_t reason;
    ninlil_retry_guidance_t retry_guidance;
    uint32_t reserved_zero;
    uint64_t retry_delay_ms;
    ninlil_id128_t transaction_id;
    ninlil_digest256_t canonical_submission_digest;
    ninlil_admission_assurance_t assurance;
} ninlil_submission_result_t;

typedef struct ninlil_target_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_concrete_target_t target;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_evidence_stage_t latest_evidence;
    uint32_t attempt_in_cycle;
    uint64_t retry_cycle_id;
    uint64_t cumulative_attempts;
} ninlil_target_snapshot_t;

typedef struct ninlil_transaction_snapshot {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    ninlil_family_t family;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    ninlil_deadline_verdict_t deadline_verdict;
    ninlil_evidence_stage_t required_evidence;
    ninlil_evidence_stage_t latest_evidence;
    ninlil_reason_t reason;
    ninlil_event_park_cause_t event_park_cause;
    uint64_t generation;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_ms;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    uint64_t transaction_sequence;
    uint64_t record_revision;
    uint64_t event_spool_revision;
    uint32_t target_count;
    uint32_t target_capacity;
    ninlil_target_snapshot_t *targets;
    uint32_t has_late_evidence;
    uint32_t explicitly_discarded;
    ninlil_admission_assurance_t assurance;
} ninlil_transaction_snapshot_t;

typedef struct ninlil_transaction_summary {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_service_identity_t service;
    ninlil_family_t family;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_ms;
    uint64_t transaction_sequence;
    uint64_t record_revision;
} ninlil_transaction_summary_t;

typedef struct ninlil_query {
    NINLIL_STRUCT_HEADER;
    uint64_t after_transaction_sequence;
    ninlil_id128_t admission_clock_epoch_id;
    uint64_t admitted_at_or_after_ms;
    uint32_t family_mask;
    uint32_t include_terminal;
    uint32_t include_nonterminal;
    uint32_t has_admitted_at_filter;
    uint32_t reserved_zero;
} ninlil_query_t;

typedef struct ninlil_transaction_page {
    NINLIL_STRUCT_HEADER;
    ninlil_transaction_summary_t *items;
    uint32_t item_capacity;
    uint32_t item_count;
    uint64_t next_after_transaction_sequence;
    uint32_t has_more;
    uint32_t reserved_zero;
} ninlil_transaction_page_t;

#define NINLIL_CANCEL_FENCED_BEFORE_DISPATCH ((ninlil_cancel_kind_t)1u)
#define NINLIL_CANCEL_PENDING_REMOTE_FENCE  ((ninlil_cancel_kind_t)2u)
#define NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE ((ninlil_cancel_kind_t)3u)
#define NINLIL_CANCEL_ALREADY_TERMINAL      ((ninlil_cancel_kind_t)4u)

typedef struct ninlil_cancel_result {
    NINLIL_STRUCT_HEADER;
    ninlil_cancel_kind_t kind;
    ninlil_reason_t reason;
    ninlil_outcome_t current_outcome;
    uint32_t reserved_zero;
} ninlil_cancel_result_t;

#define NINLIL_EVENT_RESUME_INVALID          ((ninlil_event_resume_kind_t)0u)
#define NINLIL_EVENT_RESUME_RESUMED          ((ninlil_event_resume_kind_t)1u)
#define NINLIL_EVENT_RESUME_ALREADY_RESUMED  ((ninlil_event_resume_kind_t)2u)
#define NINLIL_EVENT_RESUME_NOT_PARKED       ((ninlil_event_resume_kind_t)3u)
#define NINLIL_EVENT_RESUME_ALREADY_RELEASED ((ninlil_event_resume_kind_t)4u)
#define NINLIL_EVENT_RESUME_ALREADY_DISCARDED ((ninlil_event_resume_kind_t)5u)
#define NINLIL_EVENT_RESUME_NOT_EVENT_FACT   ((ninlil_event_resume_kind_t)6u)
#define NINLIL_EVENT_RESUME_CONFLICT         ((ninlil_event_resume_kind_t)7u)
#define NINLIL_EVENT_RESUME_STALE_SPOOL_REVISION ((ninlil_event_resume_kind_t)8u)
#define NINLIL_EVENT_RESUME_LIMIT_EXHAUSTED ((ninlil_event_resume_kind_t)9u)
#define NINLIL_EVENT_RESUME_NOT_RESUMABLE   ((ninlil_event_resume_kind_t)10u)

#define NINLIL_RESUME_CONNECTIVITY_REMEDIATED ((ninlil_event_resume_reason_t)1u)
#define NINLIL_RESUME_CAPACITY_REMEDIATED     ((ninlil_event_resume_reason_t)2u)
#define NINLIL_RESUME_APPLICATION_REMEDIATED  ((ninlil_event_resume_reason_t)3u)
#define NINLIL_RESUME_OPERATOR_OVERRIDE       ((ninlil_event_resume_reason_t)4u)
#define NINLIL_RESUME_TEST                    ((ninlil_event_resume_reason_t)5u)

typedef struct ninlil_event_resume_request {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t operation_id;
    ninlil_id128_t actor_id;
    uint64_t expected_spool_revision;
    ninlil_event_resume_reason_t resume_reason;
    uint32_t reserved_zero;
    ninlil_bytes_view_t audit_metadata;
} ninlil_event_resume_request_t;

typedef struct ninlil_event_resume_result {
    NINLIL_STRUCT_HEADER;
    ninlil_event_resume_kind_t kind;
    ninlil_reason_t reason;
    ninlil_id128_t operation_id;
    uint64_t retry_cycle_id;
    uint64_t spool_revision;
} ninlil_event_resume_result_t;

#define NINLIL_EVENT_DISCARD_INVALID          ((ninlil_event_discard_kind_t)0u)
#define NINLIL_EVENT_DISCARD_DISCARDED        ((ninlil_event_discard_kind_t)1u)
#define NINLIL_EVENT_DISCARD_ALREADY_DISCARDED ((ninlil_event_discard_kind_t)2u)
#define NINLIL_EVENT_DISCARD_ALREADY_RELEASED ((ninlil_event_discard_kind_t)3u)
#define NINLIL_EVENT_DISCARD_NOT_EVENT_FACT   ((ninlil_event_discard_kind_t)4u)
#define NINLIL_EVENT_DISCARD_CONFLICT         ((ninlil_event_discard_kind_t)5u)
#define NINLIL_EVENT_DISCARD_STALE_SPOOL_REVISION ((ninlil_event_discard_kind_t)6u)

#define NINLIL_DISCARD_DEVICE_DECOMMISSIONED ((ninlil_event_discard_reason_t)1u)
#define NINLIL_DISCARD_INVALID_EVENT          ((ninlil_event_discard_reason_t)2u)
#define NINLIL_DISCARD_OPERATOR_OVERRIDE      ((ninlil_event_discard_reason_t)3u)
#define NINLIL_DISCARD_TEST_CLEANUP           ((ninlil_event_discard_reason_t)4u)

typedef struct ninlil_event_discard_request {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t operation_id;
    ninlil_id128_t actor_id;
    ninlil_id128_t expected_event_id;
    ninlil_digest256_t expected_content_digest;
    uint64_t expected_spool_revision;
    ninlil_event_discard_reason_t discard_reason;
    uint32_t acknowledge_required_receipt_absent;
    ninlil_bytes_view_t audit_metadata;
} ninlil_event_discard_request_t;

typedef struct ninlil_event_discard_result {
    NINLIL_STRUCT_HEADER;
    ninlil_event_discard_kind_t kind;
    ninlil_reason_t reason;
    ninlil_id128_t operation_id;
    ninlil_id128_t audit_clock_epoch_id;
    uint64_t audit_committed_at_ms;
    uint64_t spool_revision;
    uint32_t spool_released;
    uint32_t reserved_zero;
} ninlil_event_discard_result_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSACTION_H */
