#ifndef NINLIL_MODEL_REQUIRED_RECEIPT_TRANSITION_H
#define NINLIL_MODEL_REQUIRED_RECEIPT_TRANSITION_H

#include <stdint.h>

#include "deadline_projection.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_model_desired_target_state {
    NINLIL_MODEL_DESIRED_TARGET_READY = 1,
    NINLIL_MODEL_DESIRED_TARGET_ATTEMPT_PREPARED = 2,
    NINLIL_MODEL_DESIRED_TARGET_AWAITING_EVIDENCE = 3,
    NINLIL_MODEL_DESIRED_TARGET_RETRY_WAIT = 4,
    NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE = 5,
    NINLIL_MODEL_DESIRED_TARGET_SATISFIED = 6,
    NINLIL_MODEL_DESIRED_TARGET_EXPIRED = 7,
    NINLIL_MODEL_DESIRED_TARGET_CANCELLED_BEFORE_EFFECT = 8,
    NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE = 9,
    NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN = 10
} ninlil_model_desired_target_state_t;

typedef enum ninlil_model_receipt_evidence_action {
    NINLIL_MODEL_RECEIPT_EVIDENCE_ACTIVE_REQUIRED = 1,
    NINLIL_MODEL_RECEIPT_EVIDENCE_TERMINAL_LATE = 2
} ninlil_model_receipt_evidence_action_t;

typedef struct ninlil_model_desired_target_snapshot {
    ninlil_model_desired_target_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_deadline_verdict_t deadline_verdict;
    ninlil_effect_certainty_t effect_certainty;
} ninlil_model_desired_target_snapshot_t;

/*
 * The caller has already validated Receipt identity/binding and stage, and
 * classified the Receipt as new material rather than an exact duplicate.
 * Evidence summary, raw detail, revision, counters, and storage are outside
 * this pure transition model.
 */
typedef struct ninlil_model_required_receipt_transition_input {
    ninlil_model_desired_target_snapshot_t current;
    uint32_t required_stage_reached;
    uint32_t receipt_is_new_material;
    ninlil_model_required_receipt_deadline_result_t deadline;
} ninlil_model_required_receipt_transition_input_t;

typedef struct ninlil_model_required_receipt_transition_result {
    ninlil_model_desired_target_snapshot_t next;
    ninlil_model_receipt_evidence_action_t evidence_action;
} ninlil_model_required_receipt_transition_result_t;

ninlil_status_t ninlil_model_reduce_desired_required_receipt(
    const ninlil_model_required_receipt_transition_input_t *input,
    ninlil_model_required_receipt_transition_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
