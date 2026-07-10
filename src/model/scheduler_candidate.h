#ifndef NINLIL_MODEL_SCHEDULER_CANDIDATE_H
#define NINLIL_MODEL_SCHEDULER_CANDIDATE_H

#include <stdint.h>

#include <ninlil/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MODEL_EPOCH_BYTES ((uint32_t)16u)
#define NINLIL_MODEL_TARGET_RECORD_BYTES ((uint32_t)100u)
#define NINLIL_MODEL_TIE_ID_BYTES ((uint32_t)16u)
#define NINLIL_MODEL_CANDIDATE_KEY_BYTES ((uint32_t)146u)
#define NINLIL_MODEL_INTERNAL_SEQUENCE UINT64_MAX

#define NINLIL_MODEL_KEY_TIME_OFFSET ((uint32_t)0u)
#define NINLIL_MODEL_KEY_PRIORITY_OFFSET ((uint32_t)8u)
#define NINLIL_MODEL_KEY_CLASS_OFFSET ((uint32_t)9u)
#define NINLIL_MODEL_KEY_SEQUENCE_OFFSET ((uint32_t)10u)
#define NINLIL_MODEL_KEY_TARGET_OFFSET ((uint32_t)18u)
#define NINLIL_MODEL_KEY_WORK_KIND_OFFSET ((uint32_t)118u)
#define NINLIL_MODEL_KEY_TIE_ID_OFFSET ((uint32_t)122u)
#define NINLIL_MODEL_KEY_TIE_GENERATION_OFFSET ((uint32_t)138u)

typedef enum ninlil_model_input_kind {
    NINLIL_MODEL_INPUT_NONE = 0,
    NINLIL_MODEL_INPUT_RECOVERY_FENCE = 1,
    NINLIL_MODEL_INPUT_STORAGE_COMMIT_FAILED = 2,
    NINLIL_MODEL_INPUT_STORAGE_COMMIT_UNKNOWN = 3,
    NINLIL_MODEL_INPUT_DELIVERY_COMPLETE_REQUEST = 4,
    NINLIL_MODEL_INPUT_APPLICATION_RESULT_COMMITTED = 5,
    NINLIL_MODEL_INPUT_RECONCILE_RESULT = 6,
    NINLIL_MODEL_INPUT_DELIVERY_INGRESS_COMMITTED = 7,
    NINLIL_MODEL_INPUT_VALID_RECEIPT = 8,
    NINLIL_MODEL_INPUT_REMOTE_CANCEL_RESULT = 9,
    NINLIL_MODEL_INPUT_DELIVERY_DISPOSITION = 10,
    NINLIL_MODEL_INPUT_EVENT_DISCARD_REQUEST = 11,
    NINLIL_MODEL_INPUT_LOCAL_CANCEL_REQUEST = 12,
    NINLIL_MODEL_INPUT_REMOTE_CANCEL_REQUEST = 13,
    NINLIL_MODEL_INPUT_DEFER_CONTEXT_TIMEOUT = 14,
    NINLIL_MODEL_INPUT_EFFECT_DEADLINE = 15,
    NINLIL_MODEL_INPUT_EVIDENCE_CLOSE = 16,
    NINLIL_MODEL_INPUT_ATTEMPT_RECEIPT_TIMEOUT = 17,
    NINLIL_MODEL_INPUT_RETRY_BUDGET_EXHAUSTED = 18,
    NINLIL_MODEL_INPUT_EVENT_RESUME_REQUEST = 19,
    NINLIL_MODEL_INPUT_AVAILABILITY_EPOCH_AVAILABLE = 20,
    NINLIL_MODEL_INPUT_RECONCILE_DUE = 21,
    NINLIL_MODEL_INPUT_RETRY_DUE = 22,
    NINLIL_MODEL_INPUT_DISPATCH_DUE = 23,
    NINLIL_MODEL_INPUT_TRANSPORT_OBSERVATION = 24,
    NINLIL_MODEL_INPUT_CUSTODY_ACCEPTED = 25
} ninlil_model_input_kind_t;

typedef enum ninlil_model_work_kind {
    NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT = 1,
    NINLIL_MODEL_WORK_AVAILABILITY_CONSUME = 2,
    NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE = 3,
    NINLIL_MODEL_WORK_COMMAND_EVIDENCE_CLOSE = 4,
    NINLIL_MODEL_WORK_ATTEMPT_RECEIPT_TIMEOUT = 5,
    NINLIL_MODEL_WORK_INTERNAL_RETRY_DUE = 6,
    NINLIL_MODEL_WORK_DELIVERY_TOKEN_TIMEOUT = 7,
    NINLIL_MODEL_WORK_RECONCILE_DUE = 8,
    NINLIL_MODEL_WORK_DELIVERY_CALLBACK = 9,
    NINLIL_MODEL_WORK_RECONCILE_CALLBACK = 10,
    NINLIL_MODEL_WORK_APPLICATION_ATTEMPT_PREPARE = 11,
    NINLIL_MODEL_WORK_APPLICATION_SEND = 12,
    NINLIL_MODEL_WORK_CANCEL_ATTEMPT_PREPARE = 13,
    NINLIL_MODEL_WORK_CANCEL_REQUEST_SEND = 14,
    NINLIL_MODEL_WORK_RECEIPT_REVERSE_SEND = 15,
    NINLIL_MODEL_WORK_DISPOSITION_REVERSE_SEND = 16,
    NINLIL_MODEL_WORK_CUSTODY_ACCEPTED_REVERSE_SEND = 17,
    NINLIL_MODEL_WORK_CANCEL_RESULT_REVERSE_SEND = 18,
    NINLIL_MODEL_WORK_RETENTION_BASIS_UPDATE = 19,
    NINLIL_MODEL_WORK_TERMINAL_RETENTION_CLEANUP = 20,
    NINLIL_MODEL_WORK_RESULT_TOKEN_RETENTION_CLEANUP = 21,
    NINLIL_MODEL_WORK_OBSERVATION_RETENTION_CLEANUP = 22
} ninlil_model_work_kind_t;

typedef enum ninlil_model_tie_contract {
    NINLIL_MODEL_TIE_ZERO_ZERO = 1,
    NINLIL_MODEL_TIE_ZERO_NONZERO_GENERATION = 2,
    NINLIL_MODEL_TIE_OPTIONAL_ID_ATTEMPT_INDEX = 3,
    NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION = 4,
    NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION = 5,
    NINLIL_MODEL_TIE_REQUIRED_ID_EVIDENCE_STAGE = 6,
    NINLIL_MODEL_TIE_REQUIRED_ID_DISPOSITION = 7,
    NINLIL_MODEL_TIE_REQUIRED_ID_CANCEL_RESULT = 8,
    NINLIL_MODEL_TIE_ZERO_RETENTION_KIND = 9,
    NINLIL_MODEL_TIE_ZERO_ATTEMPT_INDEX = 10
} ninlil_model_tie_contract_t;

typedef enum ninlil_model_candidate_disposition {
    NINLIL_MODEL_CANDIDATE_INVALID = 0,
    NINLIL_MODEL_CANDIDATE_CURRENT_READY = 1,
    NINLIL_MODEL_CANDIDATE_RECOVERY_FENCE = 2,
    NINLIL_MODEL_CANDIDATE_SUPPRESSED_OLD_EPOCH = 3
} ninlil_model_candidate_disposition_t;

typedef enum ninlil_model_target_presence {
    NINLIL_MODEL_TARGET_NONE = 0,
    NINLIL_MODEL_TARGET_PRESENT = 1
} ninlil_model_target_presence_t;

typedef enum ninlil_model_target_policy {
    NINLIL_MODEL_TARGET_REQUIRED = 1,
    /* NONE is only for a genuinely runtime-local/no-target cleanup record. */
    NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE = 2
} ninlil_model_target_policy_t;

typedef enum ninlil_model_optional_presence {
    NINLIL_MODEL_CANDIDATE_ABSENT = 0,
    NINLIL_MODEL_CANDIDATE_PRESENT = 1
} ninlil_model_optional_presence_t;

typedef struct ninlil_model_epoch_id {
    uint8_t bytes[16];
} ninlil_model_epoch_id_t;

typedef struct ninlil_model_target_record {
    uint8_t bytes[100];
} ninlil_model_target_record_t;

typedef struct ninlil_model_tie_id {
    uint8_t bytes[16];
} ninlil_model_tie_id_t;

typedef struct ninlil_model_work_contract {
    uint8_t semantic_priority;
    uint8_t work_class;
    uint8_t priority_is_dynamic;
    uint8_t reserved_zero;
    ninlil_model_tie_contract_t tie_contract;
    ninlil_model_target_policy_t target_policy;
} ninlil_model_work_contract_t;

typedef struct ninlil_model_candidate_spec {
    ninlil_model_work_kind_t work_kind;
    ninlil_model_input_kind_t input_kind;
    uint8_t semantic_priority;
    uint8_t work_class;
    ninlil_model_target_presence_t target_presence;
    ninlil_model_epoch_id_t current_epoch;
    ninlil_model_epoch_id_t candidate_epoch;
    uint64_t logical_time_ms;
    uint64_t durable_input_sequence;
    ninlil_model_target_record_t target_identity_record;
    ninlil_model_tie_id_t tie_identity;
    uint64_t tie_generation;
} ninlil_model_candidate_spec_t;

typedef struct ninlil_model_candidate_key {
    uint8_t bytes[146];
} ninlil_model_candidate_key_t;

typedef struct ninlil_model_optional_candidate {
    ninlil_model_optional_presence_t presence;
    ninlil_model_candidate_key_t key;
} ninlil_model_optional_candidate_t;

ninlil_status_t ninlil_model_input_priority(
    ninlil_model_input_kind_t input_kind,
    uint8_t *out_priority);

ninlil_status_t ninlil_model_input_is_durable_ring_candidate(
    ninlil_model_input_kind_t input_kind,
    uint8_t *out_is_eligible);

ninlil_status_t ninlil_model_work_contract(
    ninlil_model_work_kind_t work_kind,
    ninlil_model_work_contract_t *out_contract);

ninlil_status_t ninlil_model_build_candidate(
    const ninlil_model_candidate_spec_t *spec,
    ninlil_model_candidate_disposition_t *out_disposition,
    ninlil_model_candidate_key_t *out_key);

int ninlil_model_candidate_key_compare(
    const ninlil_model_candidate_key_t *left,
    const ninlil_model_candidate_key_t *right);

/* qsort comparator for candidate keys already validated by build_candidate(). */
int ninlil_model_candidate_key_qsort_compare(const void *left, const void *right);

ninlil_status_t ninlil_model_optional_candidate_compare(
    const ninlil_model_optional_candidate_t *left,
    const ninlil_model_optional_candidate_t *right,
    int *out_comparison);

ninlil_status_t ninlil_model_recovery_fence_sequence_compare(
    uint64_t left_sequence,
    uint64_t right_sequence,
    int *out_comparison);

#ifdef __cplusplus
}
#endif

#endif
