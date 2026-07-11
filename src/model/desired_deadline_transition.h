#ifndef NINLIL_MODEL_DESIRED_DEADLINE_TRANSITION_H
#define NINLIL_MODEL_DESIRED_DEADLINE_TRANSITION_H

#include "deadline_projection.h"
#include "desired_target_snapshot.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_model_effect_basis {
    NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT = 1,
    NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_APPLICATION_FAILED = 2,
    NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_TARGET_UNAUTHORIZED = 3,
    NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_RETRY_BUDGET_EXHAUSTED = 4,
    NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE = 5
} ninlil_model_effect_basis_t;

typedef enum ninlil_model_deadline_transition_action {
    NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED = 1,
    NINLIL_MODEL_DEADLINE_TERMINAL_ABSORBED = 2,
    NINLIL_MODEL_DEADLINE_CATCH_UP_PRIOR_REDUCER = 3
} ninlil_model_deadline_transition_action_t;

/*
 * effect_basis is a validated summary of attempt/delivery/Disposition facts.
 * These reducers do not inspect attempts or infer a definitive failure reason.
 */
typedef struct ninlil_model_desired_deadline_transition_input {
    ninlil_model_desired_target_snapshot_t current;
    ninlil_model_deadline_evidence_t deadline_evidence;
    ninlil_model_effect_basis_t effect_basis;
} ninlil_model_desired_deadline_transition_input_t;

typedef struct ninlil_model_desired_deadline_transition_result {
    ninlil_model_desired_target_snapshot_t next;
    ninlil_model_deadline_transition_action_t action;
    ninlil_model_effect_basis_t catch_up_basis;
} ninlil_model_desired_deadline_transition_result_t;

ninlil_status_t ninlil_model_reduce_desired_effect_deadline(
    const ninlil_model_desired_deadline_transition_input_t *input,
    ninlil_model_desired_deadline_transition_result_t *out_result);

ninlil_status_t ninlil_model_reduce_desired_evidence_close(
    const ninlil_model_desired_deadline_transition_input_t *input,
    ninlil_model_desired_deadline_transition_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
