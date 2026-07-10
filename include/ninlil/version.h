#ifndef NINLIL_VERSION_H
#define NINLIL_VERSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ABI_VERSION              ((uint16_t)0x0001u)
#define NINLIL_STORAGE_SCHEMA_M1A        ((uint32_t)1u)
#define NINLIL_NO_DEADLINE               UINT64_MAX
#define NINLIL_ID_BYTES                  ((uint32_t)16u)
#define NINLIL_SHA256_BYTES              ((uint32_t)32u)
#define NINLIL_MAX_IDEMPOTENCY_BYTES     ((uint32_t)64u)
#define NINLIL_MAX_EVIDENCE_BYTES        ((uint32_t)128u)
#define NINLIL_MAX_AUDIT_METADATA_BYTES  ((uint32_t)128u)
#define NINLIL_MAX_TEXT_ID_BYTES         ((uint32_t)63u)
#define NINLIL_M1A_MAX_STORAGE_VALUE_BYTES ((uint32_t)65536u)
#define NINLIL_DIGEST_SHA256             ((uint16_t)1u)
#define NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE ((uint32_t)8u)
#define NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS ((uint32_t)4u)
#define NINLIL_M1A_MAX_RETRY_DELAY_MS      ((uint64_t)600000u)
#define NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS ((uint64_t)600000u)
#define NINLIL_M1A_MAX_RETRY_BACKOFF_MS    ((uint64_t)60000u)
#define NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS ((uint64_t)60000u)
#define NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS ((uint32_t)8u)
#define NINLIL_M1A_EVENT_RESUME_OPERATION_SLOT_BYTES ((uint64_t)256u)
#define NINLIL_M1A_EVENT_DISCARD_OPERATION_SLOT_BYTES ((uint64_t)512u)
#define NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES ((uint64_t)2560u)
#define NINLIL_M1A_MAX_RETENTION_MS          ((uint64_t)604800000u)

#define NINLIL_STRUCT_HEADER \
    uint16_t abi_version;   \
    uint16_t struct_size

typedef int32_t  ninlil_status_t;
typedef uint32_t ninlil_role_t;
typedef uint32_t ninlil_environment_t;
typedef uint32_t ninlil_family_t;
typedef uint32_t ninlil_direction_t;
typedef uint32_t ninlil_admission_authority_t;
typedef uint32_t ninlil_apply_contract_t;
typedef uint32_t ninlil_custody_policy_t;
typedef uint32_t ninlil_evidence_stage_t;
typedef uint32_t ninlil_submission_kind_t;
typedef uint32_t ninlil_retry_guidance_t;
typedef uint32_t ninlil_reason_t;
typedef uint32_t ninlil_disposition_t;
typedef uint32_t ninlil_effect_certainty_t;
typedef uint32_t ninlil_application_result_kind_t;
typedef uint32_t ninlil_callback_action_t;
typedef uint32_t ninlil_reconcile_action_t;
typedef uint32_t ninlil_transaction_state_t;
typedef uint32_t ninlil_outcome_t;
typedef uint32_t ninlil_deadline_verdict_t;
typedef uint32_t ninlil_cancel_kind_t;
typedef uint32_t ninlil_runtime_health_t;
typedef uint32_t ninlil_resource_kind_t;
typedef uint32_t ninlil_clock_trust_t;
typedef uint32_t ninlil_storage_status_t;
typedef uint32_t ninlil_storage_mode_t;
typedef uint32_t ninlil_durability_t;
typedef uint32_t ninlil_bearer_status_t;
typedef uint32_t ninlil_bearer_message_kind_t;
typedef uint32_t ninlil_bearer_send_kind_t;
typedef uint32_t ninlil_tx_gate_status_t;
typedef uint32_t ninlil_port_status_t;
typedef uint32_t ninlil_origin_auth_status_t;
typedef uint32_t ninlil_assurance_profile_t;
typedef uint32_t ninlil_event_resume_kind_t;
typedef uint32_t ninlil_event_discard_kind_t;
typedef uint32_t ninlil_event_resume_reason_t;
typedef uint32_t ninlil_event_discard_reason_t;
typedef uint32_t ninlil_event_park_cause_t;

typedef struct ninlil_id128 {
    uint8_t bytes[16];
} ninlil_id128_t;

typedef struct ninlil_digest256 {
    uint16_t algorithm;
    uint16_t reserved_zero;
    uint8_t bytes[32];
} ninlil_digest256_t;

typedef struct ninlil_bytes_view {
    const uint8_t *data;
    uint32_t length;
} ninlil_bytes_view_t;

typedef struct ninlil_mut_bytes {
    uint8_t *data;
    uint32_t capacity;
    uint32_t length;
} ninlil_mut_bytes_t;

typedef struct ninlil_text_id {
    uint8_t length;
    uint8_t bytes[63];
} ninlil_text_id_t;

#define NINLIL_LOCAL_IDENTITY_HAS_DEVICE       ((uint32_t)1u << 0)
#define NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION ((uint32_t)1u << 1)
#define NINLIL_LOCAL_IDENTITY_HAS_SITE         ((uint32_t)1u << 2)

typedef struct ninlil_local_identity {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t device_id;
    ninlil_id128_t installation_id;
    ninlil_id128_t site_domain_id;
    uint64_t binding_epoch;
    uint64_t membership_epoch;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_local_identity_t;

#define NINLIL_OK                         ((ninlil_status_t)0)
#define NINLIL_E_INVALID_ARGUMENT         ((ninlil_status_t)1)
#define NINLIL_E_ABI_MISMATCH             ((ninlil_status_t)2)
#define NINLIL_E_UNSUPPORTED              ((ninlil_status_t)3)
#define NINLIL_E_WRONG_THREAD             ((ninlil_status_t)4)
#define NINLIL_E_REENTRANT                 ((ninlil_status_t)5)
#define NINLIL_E_BUFFER_TOO_SMALL          ((ninlil_status_t)6)
#define NINLIL_E_NOT_FOUND                 ((ninlil_status_t)7)
#define NINLIL_E_CONFLICT                  ((ninlil_status_t)8)
#define NINLIL_E_CAPACITY_EXHAUSTED        ((ninlil_status_t)9)
#define NINLIL_E_STORAGE                   ((ninlil_status_t)10)
#define NINLIL_E_STORAGE_CORRUPT           ((ninlil_status_t)11)
#define NINLIL_E_STORAGE_COMMIT_UNKNOWN    ((ninlil_status_t)12)
#define NINLIL_E_CLOCK_UNCERTAIN           ((ninlil_status_t)13)
#define NINLIL_E_ENTROPY                   ((ninlil_status_t)14)
#define NINLIL_E_WOULD_BLOCK               ((ninlil_status_t)15)
#define NINLIL_E_INVALID_STATE             ((ninlil_status_t)16)
#define NINLIL_E_CALLBACK                  ((ninlil_status_t)17) /* M1a reserved; never generated */
#define NINLIL_E_DEGRADED                  ((ninlil_status_t)18)
#define NINLIL_E_INTERNAL                  ((ninlil_status_t)19) /* M1a reserved; never generated */

#define NINLIL_ROLE_CONTROLLER             ((ninlil_role_t)1u)
#define NINLIL_ROLE_ENDPOINT               ((ninlil_role_t)2u)
#define NINLIL_ROLE_CELL_AGENT_RESERVED    ((ninlil_role_t)3u)

#define NINLIL_ENV_TEST                    ((ninlil_environment_t)1u)
#define NINLIL_ENV_LAB_RESERVED            ((ninlil_environment_t)2u)
#define NINLIL_ENV_FIELD_RESERVED          ((ninlil_environment_t)3u)
#define NINLIL_ENV_PRODUCTION_RESERVED     ((ninlil_environment_t)4u)

#define NINLIL_FAMILY_EVENT_FACT           ((ninlil_family_t)1u)
#define NINLIL_FAMILY_DESIRED_STATE        ((ninlil_family_t)2u)
#define NINLIL_FAMILY_LATEST_STATE_RESERVED ((ninlil_family_t)3u)
#define NINLIL_FAMILY_MEASUREMENT_RESERVED  ((ninlil_family_t)4u)
#define NINLIL_FAMILY_TRANSFER_RESERVED     ((ninlil_family_t)5u)
#define NINLIL_FAMILY_CONFIG_RESERVED       ((ninlil_family_t)6u)
#define NINLIL_FAMILY_NETWORK_CONTROL_RESERVED ((ninlil_family_t)0x80000001u)
#define NINLIL_FAMILY_MASK_EVENT_FACT      ((uint32_t)1u << 0)
#define NINLIL_FAMILY_MASK_DESIRED_STATE   ((uint32_t)1u << 1)

#define NINLIL_DIRECTION_UPLINK             ((ninlil_direction_t)1u)
#define NINLIL_DIRECTION_DOWNLINK           ((ninlil_direction_t)2u)
#define NINLIL_DIRECTION_BIDIRECTIONAL_RESERVED ((ninlil_direction_t)3u)

#define NINLIL_AUTHORITY_CONTROLLER_ONLY    ((ninlil_admission_authority_t)1u)
#define NINLIL_AUTHORITY_ORIGIN_WITH_GRANT  ((ninlil_admission_authority_t)2u)

#define NINLIL_APPLY_IDEMPOTENT             ((ninlil_apply_contract_t)1u)
#define NINLIL_APPLY_APPLICATION_DEDUP       ((ninlil_apply_contract_t)2u)
#define NINLIL_APPLY_ATOMIC_PARTICIPANT_RESERVED ((ninlil_apply_contract_t)3u)

#define NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE ((ninlil_custody_policy_t)1u)
#define NINLIL_CUSTODY_RELEASE_ON_TRANSPORT_RESERVED ((ninlil_custody_policy_t)2u)

#define NINLIL_EVIDENCE_NONE                ((ninlil_evidence_stage_t)0u)
#define NINLIL_EVIDENCE_RECEIVED            ((ninlil_evidence_stage_t)1u)
#define NINLIL_EVIDENCE_DURABLY_RECORDED    ((ninlil_evidence_stage_t)2u)
#define NINLIL_EVIDENCE_APPLIED             ((ninlil_evidence_stage_t)3u)
#define NINLIL_EVIDENCE_VERIFIED            ((ninlil_evidence_stage_t)4u)

#define NINLIL_EVIDENCE_MASK(stage)         ((uint32_t)1u << (stage))

#define NINLIL_SUBMISSION_INVALID           ((ninlil_submission_kind_t)0u)
#define NINLIL_SUBMISSION_ADMITTED_READY    ((ninlil_submission_kind_t)1u)
#define NINLIL_SUBMISSION_ALREADY_ADMITTED  ((ninlil_submission_kind_t)2u)
#define NINLIL_SUBMISSION_REJECTED          ((ninlil_submission_kind_t)3u)
#define NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT ((ninlil_submission_kind_t)4u)
#define NINLIL_SUBMISSION_ADMITTED_SCHEDULED_RESERVED ((ninlil_submission_kind_t)5u)
#define NINLIL_SUBMISSION_COUNTER_OFFERED_RESERVED ((ninlil_submission_kind_t)6u)

#define NINLIL_RETRY_NEVER                  ((ninlil_retry_guidance_t)0u)
#define NINLIL_RETRY_SAME_AFTER             ((ninlil_retry_guidance_t)1u)
#define NINLIL_RETRY_MODIFIED               ((ninlil_retry_guidance_t)2u)
#define NINLIL_RETRY_OPERATOR_ACTION        ((ninlil_retry_guidance_t)3u)

#define NINLIL_DISPOSITION_NONE             ((ninlil_disposition_t)0u)
#define NINLIL_DISPOSITION_RETRY_LATER      ((ninlil_disposition_t)1u)
#define NINLIL_DISPOSITION_INVALID_PAYLOAD  ((ninlil_disposition_t)2u)
#define NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA ((ninlil_disposition_t)3u)
#define NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE ((ninlil_disposition_t)4u)
#define NINLIL_DISPOSITION_STALE_NOT_APPLIED ((ninlil_disposition_t)5u)
#define NINLIL_DISPOSITION_APPLICATION_BUSY ((ninlil_disposition_t)6u)
#define NINLIL_DISPOSITION_APPLY_FAILED     ((ninlil_disposition_t)7u)
#define NINLIL_DISPOSITION_VERIFY_FAILED    ((ninlil_disposition_t)8u)
#define NINLIL_DISPOSITION_CAPACITY_EXHAUSTED ((ninlil_disposition_t)9u)
#define NINLIL_DISPOSITION_OUTCOME_UNKNOWN  ((ninlil_disposition_t)10u)

#define NINLIL_EFFECT_CERTAINTY_NONE          ((ninlil_effect_certainty_t)0u)
#define NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN ((ninlil_effect_certainty_t)1u)
#define NINLIL_EFFECT_CERTAINTY_POSSIBLE      ((ninlil_effect_certainty_t)2u)

#define NINLIL_APP_RESULT_POSITIVE_EVIDENCE ((ninlil_application_result_kind_t)1u)
#define NINLIL_APP_RESULT_DISPOSITION       ((ninlil_application_result_kind_t)2u)

#define NINLIL_CALLBACK_COMPLETE            ((ninlil_callback_action_t)1u)
#define NINLIL_CALLBACK_DEFER               ((ninlil_callback_action_t)2u)
#define NINLIL_CALLBACK_FATAL               ((ninlil_callback_action_t)3u)

#define NINLIL_RECONCILE_REDELIVER          ((ninlil_reconcile_action_t)1u)
#define NINLIL_RECONCILE_KNOWN_RESULT       ((ninlil_reconcile_action_t)2u)
#define NINLIL_RECONCILE_RETRY_LATER        ((ninlil_reconcile_action_t)3u)
#define NINLIL_RECONCILE_OUTCOME_UNKNOWN    ((ninlil_reconcile_action_t)4u)

#define NINLIL_TXN_READY                    ((ninlil_transaction_state_t)1u)
#define NINLIL_TXN_DISPATCHING              ((ninlil_transaction_state_t)2u)
#define NINLIL_TXN_AWAITING_EVIDENCE        ((ninlil_transaction_state_t)3u)
#define NINLIL_TXN_PARKED_RETRY             ((ninlil_transaction_state_t)4u)
#define NINLIL_TXN_TERMINAL                 ((ninlil_transaction_state_t)5u)
#define NINLIL_TXN_WAITING_WINDOW           ((ninlil_transaction_state_t)6u)

#define NINLIL_OUTCOME_NONE                 ((ninlil_outcome_t)0u)
#define NINLIL_OUTCOME_SATISFIED            ((ninlil_outcome_t)1u)
#define NINLIL_OUTCOME_EXPIRED              ((ninlil_outcome_t)2u)
#define NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT ((ninlil_outcome_t)3u)
#define NINLIL_OUTCOME_FAILED_DEFINITIVE    ((ninlil_outcome_t)4u)
#define NINLIL_OUTCOME_UNKNOWN              ((ninlil_outcome_t)5u)
#define NINLIL_OUTCOME_SUPERSEDED_RESERVED  ((ninlil_outcome_t)6u)

#define NINLIL_DEADLINE_PENDING             ((ninlil_deadline_verdict_t)0u)
#define NINLIL_DEADLINE_MET                 ((ninlil_deadline_verdict_t)1u)
#define NINLIL_DEADLINE_MISSED              ((ninlil_deadline_verdict_t)2u)
#define NINLIL_DEADLINE_INDETERMINATE       ((ninlil_deadline_verdict_t)3u)
#define NINLIL_DEADLINE_NOT_APPLICABLE      ((ninlil_deadline_verdict_t)4u)

#define NINLIL_EVENT_PARK_CAUSE_NONE         ((ninlil_event_park_cause_t)0u)
#define NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT ((ninlil_event_park_cause_t)1u)
#define NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE ((ninlil_event_park_cause_t)2u)
#define NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLE ((ninlil_event_park_cause_t)3u)
#define NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION ((ninlil_event_park_cause_t)4u)
#define NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED ((ninlil_event_park_cause_t)5u)

#define NINLIL_REASON_NONE                  ((ninlil_reason_t)0u)

/* M1a admission/validation: 1..63 */
#define NINLIL_REASON_UNSUPPORTED_FAMILY    ((ninlil_reason_t)1u)
#define NINLIL_REASON_UNSUPPORTED_SELECTOR  ((ninlil_reason_t)2u)
#define NINLIL_REASON_TARGET_COUNT_UNSUPPORTED ((ninlil_reason_t)3u)
#define NINLIL_REASON_INVALID_SCHEMA        ((ninlil_reason_t)4u)
#define NINLIL_REASON_INVALID_PAYLOAD_LENGTH ((ninlil_reason_t)5u)
#define NINLIL_REASON_INVALID_CONTENT_DIGEST ((ninlil_reason_t)6u)
#define NINLIL_REASON_DEADLINE_INVALID      ((ninlil_reason_t)7u)
#define NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED ((ninlil_reason_t)8u)
#define NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID ((ninlil_reason_t)9u)
#define NINLIL_REASON_EVIDENCE_UNSUPPORTED  ((ninlil_reason_t)10u)
#define NINLIL_REASON_CAPACITY_EXHAUSTED    ((ninlil_reason_t)11u)
#define NINLIL_REASON_MODIFICATION_REQUIRED ((ninlil_reason_t)12u)
#define NINLIL_REASON_IDEMPOTENCY_CONFLICT  ((ninlil_reason_t)13u)
#define NINLIL_REASON_GRANT_INVALID         ((ninlil_reason_t)14u)
#define NINLIL_REASON_GRANT_EXPIRED         ((ninlil_reason_t)15u)
#define NINLIL_REASON_GRANT_LIMIT_EXCEEDED  ((ninlil_reason_t)16u)
#define NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE ((ninlil_reason_t)17u)
#define NINLIL_REASON_STORAGE_IO            ((ninlil_reason_t)18u)
#define NINLIL_REASON_STORAGE_COMMIT_UNKNOWN ((ninlil_reason_t)19u)
#define NINLIL_REASON_CLOCK_UNCERTAIN       ((ninlil_reason_t)20u)
#define NINLIL_REASON_RATE_EXHAUSTED        ((ninlil_reason_t)21u)
#define NINLIL_REASON_TARGET_UNAUTHORIZED   ((ninlil_reason_t)22u)
#define NINLIL_REASON_CALLBACK_CONTRACT     ((ninlil_reason_t)23u)
#define NINLIL_REASON_UNSUPPORTED_DIRECTION ((ninlil_reason_t)24u)

/* M1a outcome/operation: 64..127 */
#define NINLIL_REASON_REQUIRED_EVIDENCE_MET ((ninlil_reason_t)64u)
#define NINLIL_REASON_REQUIRED_EVIDENCE_LATE ((ninlil_reason_t)65u)
#define NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH ((ninlil_reason_t)66u)
/* 67 is reserved. M1a Submission has no caller not-before semantic. */
#define NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING ((ninlil_reason_t)68u)
#define NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING ((ninlil_reason_t)69u)
#define NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT ((ninlil_reason_t)70u)
#define NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED ((ninlil_reason_t)71u)
#define NINLIL_REASON_EVENT_RECEIPT_TIMEOUT ((ninlil_reason_t)72u)
#define NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT ((ninlil_reason_t)73u)
#define NINLIL_REASON_BEARER_UNAVAILABLE    ((ninlil_reason_t)74u)
#define NINLIL_REASON_CAPACITY_UNAVAILABLE  ((ninlil_reason_t)75u)
#define NINLIL_REASON_COUNTER_EXHAUSTED     ((ninlil_reason_t)76u)
#define NINLIL_REASON_STALE_AVAILABILITY_EPOCH ((ninlil_reason_t)77u)
#define NINLIL_REASON_RESUME_CONFLICT       ((ninlil_reason_t)78u)
#define NINLIL_REASON_STALE_SPOOL_REVISION  ((ninlil_reason_t)79u)
#define NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT ((ninlil_reason_t)80u)
#define NINLIL_REASON_DISCARD_CONFLICT      ((ninlil_reason_t)81u)
#define NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH ((ninlil_reason_t)82u)
#define NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE ((ninlil_reason_t)83u)
#define NINLIL_REASON_EVENT_FACT_IMMUTABLE  ((ninlil_reason_t)84u)
#define NINLIL_REASON_TRANSPORT_RETRY       ((ninlil_reason_t)85u)
#define NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE ((ninlil_reason_t)86u)

/* M1a delivery/application: 128..255. Disposition itself is authoritative. */
#define NINLIL_REASON_APPLICATION_FAILED    ((ninlil_reason_t)128u)
#define NINLIL_REASON_OUTCOME_UNKNOWN       ((ninlil_reason_t)129u)
#define NINLIL_REASON_RECEIVER_UNAVAILABLE  ((ninlil_reason_t)130u)
#define NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT ((ninlil_reason_t)131u)
#define NINLIL_REASON_RECONCILE_RETRY_LATER ((ninlil_reason_t)132u)

/* M1b forward-only reservation: 4096.. */
#define NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION ((ninlil_reason_t)4096u)
#define NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT ((ninlil_reason_t)4097u)

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_VERSION_H */
