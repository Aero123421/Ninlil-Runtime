#include "desired_deadline_transition.h"

#include "desired_target_snapshot_internal.h"

#include <string.h>

static int deadline_evidence_is_known(
    ninlil_model_deadline_evidence_t evidence)
{
    return evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_NONE
        || evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME
        || evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE
        || evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN;
}

static int effect_basis_is_known(ninlil_model_effect_basis_t basis)
{
    return basis >= NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT
        && basis <= NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
}

static int effect_basis_is_definitive(ninlil_model_effect_basis_t basis)
{
    return basis
            >= NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_APPLICATION_FAILED
        && basis
            <= NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_RETRY_BUDGET_EXHAUSTED;
}

static ninlil_reason_t definitive_reason_for_basis(
    ninlil_model_effect_basis_t basis)
{
    switch (basis) {
    case NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_APPLICATION_FAILED:
        return NINLIL_REASON_APPLICATION_FAILED;
    case NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_TARGET_UNAUTHORIZED:
        return NINLIL_REASON_TARGET_UNAUTHORIZED;
    case NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_RETRY_BUDGET_EXHAUSTED:
        return NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT;
    default:
        return NINLIL_REASON_NONE;
    }
}

static int active_basis_is_consistent(
    const ninlil_model_desired_deadline_transition_input_t *input)
{
    if (input->effect_basis
        == NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT) {
        return input->deadline_evidence
                == NINLIL_MODEL_DEADLINE_EVIDENCE_NONE
            && input->current.effect_certainty
                != NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    }

    if (effect_basis_is_definitive(input->effect_basis)) {
        return input->deadline_evidence
                == NINLIL_MODEL_DEADLINE_EVIDENCE_NONE
            && input->current.effect_certainty
                == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    }

    if (input->effect_basis != NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE
        || input->current.effect_certainty
            == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        || input->deadline_evidence
            == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME) {
        return 0;
    }

    return input->deadline_evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_NONE
        || input->current.effect_certainty
            == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
}

static int prepare_input(
    const ninlil_model_desired_deadline_transition_input_t *input)
{
    return input != NULL
        && ninlil_model_desired_target_snapshot_is_valid(&input->current)
        && deadline_evidence_is_known(input->deadline_evidence)
        && effect_basis_is_known(input->effect_basis);
}

static void set_expired_deadline_only(
    ninlil_model_desired_deadline_transition_result_t *result)
{
    result->next.state = NINLIL_MODEL_DESIRED_TARGET_EXPIRED;
    result->next.outcome = NINLIL_OUTCOME_EXPIRED;
    result->next.reason = NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH;
    result->next.deadline_verdict = NINLIL_DEADLINE_MISSED;
    result->next.effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    result->action = NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED;
}

static void set_failed_definitive(
    ninlil_model_desired_deadline_transition_result_t *result,
    ninlil_model_effect_basis_t basis)
{
    result->next.state = NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE;
    result->next.outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
    result->next.reason = definitive_reason_for_basis(basis);
    result->next.deadline_verdict = NINLIL_DEADLINE_PENDING;
    result->next.effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    result->action = NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED;
}

static void set_awaiting_grace(
    ninlil_model_desired_deadline_transition_result_t *result)
{
    result->next.state = NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE;
    result->next.outcome = NINLIL_OUTCOME_NONE;
    result->next.reason = NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING;
    result->next.deadline_verdict = NINLIL_DEADLINE_INDETERMINATE;
    result->next.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    result->action = NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED;
}

static void set_expired_late(
    ninlil_model_desired_deadline_transition_result_t *result)
{
    result->next.state = NINLIL_MODEL_DESIRED_TARGET_EXPIRED;
    result->next.outcome = NINLIL_OUTCOME_EXPIRED;
    result->next.reason = NINLIL_REASON_REQUIRED_EVIDENCE_LATE;
    result->next.deadline_verdict = NINLIL_DEADLINE_MISSED;
    result->next.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    result->action = NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED;
}

static void set_outcome_unknown(
    ninlil_model_desired_deadline_transition_result_t *result)
{
    result->next.state = NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN;
    result->next.outcome = NINLIL_OUTCOME_UNKNOWN;
    result->next.reason = NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING;
    result->next.deadline_verdict = NINLIL_DEADLINE_INDETERMINATE;
    result->next.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    result->action = NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED;
}

static ninlil_status_t absorb_terminal(
    const ninlil_model_desired_deadline_transition_input_t *input,
    ninlil_model_desired_deadline_transition_result_t *out_result)
{
    ninlil_model_desired_target_snapshot_copy(
        &out_result->next,
        &input->current);
    out_result->action = NINLIL_MODEL_DEADLINE_TERMINAL_ABSORBED;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_reduce_desired_effect_deadline(
    const ninlil_model_desired_deadline_transition_input_t *input,
    ninlil_model_desired_deadline_transition_result_t *out_result)
{
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    if (!prepare_input(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ninlil_model_desired_target_state_is_terminal(
            input->current.state)) {
        return absorb_terminal(input, out_result);
    }
    if (!active_basis_is_consistent(input)
        || input->deadline_evidence
            == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (input->effect_basis
        == NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT) {
        set_expired_deadline_only(out_result);
    } else if (effect_basis_is_definitive(input->effect_basis)) {
        set_failed_definitive(out_result, input->effect_basis);
    } else {
        set_awaiting_grace(out_result);
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_reduce_desired_evidence_close(
    const ninlil_model_desired_deadline_transition_input_t *input,
    ninlil_model_desired_deadline_transition_result_t *out_result)
{
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    if (!prepare_input(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ninlil_model_desired_target_state_is_terminal(
            input->current.state)) {
        return absorb_terminal(input, out_result);
    }
    if (!active_basis_is_consistent(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (input->effect_basis
        != NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE) {
        out_result->action =
            NINLIL_MODEL_DEADLINE_CATCH_UP_PRIOR_REDUCER;
        out_result->catch_up_basis = input->effect_basis;
    } else if (input->deadline_evidence
        == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE) {
        set_expired_late(out_result);
    } else {
        set_outcome_unknown(out_result);
    }
    return NINLIL_OK;
}
