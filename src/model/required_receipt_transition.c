#include "required_receipt_transition.h"

#include "desired_target_snapshot_internal.h"

#include <stddef.h>
#include <string.h>

static int deadline_projection_is_valid(
    const ninlil_model_required_receipt_deadline_result_t *deadline)
{
    return (deadline->evidence
                == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME
            && deadline->verdict == NINLIL_DEADLINE_MET)
        || (deadline->evidence
                == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE
            && deadline->verdict == NINLIL_DEADLINE_MISSED)
        || (deadline->evidence
                == NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN
            && deadline->verdict == NINLIL_DEADLINE_INDETERMINATE);
}

ninlil_status_t ninlil_model_reduce_desired_required_receipt(
    const ninlil_model_required_receipt_transition_input_t *input,
    ninlil_model_required_receipt_transition_result_t *out_result)
{
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    if (input == NULL
        || input->required_stage_reached != 1u
        || input->receipt_is_new_material != 1u
        || !ninlil_model_desired_target_snapshot_is_valid(&input->current)
        || !deadline_projection_is_valid(&input->deadline)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (ninlil_model_desired_target_state_is_terminal(
            input->current.state)) {
        ninlil_model_desired_target_snapshot_copy(
            &out_result->next,
            &input->current);
        out_result->evidence_action =
            NINLIL_MODEL_RECEIPT_EVIDENCE_TERMINAL_LATE;
        return NINLIL_OK;
    }

    out_result->next.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    out_result->evidence_action =
        NINLIL_MODEL_RECEIPT_EVIDENCE_ACTIVE_REQUIRED;

    switch (input->deadline.evidence) {
    case NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME:
        out_result->next.state = NINLIL_MODEL_DESIRED_TARGET_SATISFIED;
        out_result->next.outcome = NINLIL_OUTCOME_SATISFIED;
        out_result->next.reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
        out_result->next.deadline_verdict = NINLIL_DEADLINE_MET;
        break;
    case NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE:
        out_result->next.state = NINLIL_MODEL_DESIRED_TARGET_EXPIRED;
        out_result->next.outcome = NINLIL_OUTCOME_EXPIRED;
        out_result->next.reason = NINLIL_REASON_REQUIRED_EVIDENCE_LATE;
        out_result->next.deadline_verdict = NINLIL_DEADLINE_MISSED;
        break;
    case NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN:
        out_result->next.state = NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE;
        out_result->next.outcome = NINLIL_OUTCOME_NONE;
        out_result->next.reason =
            NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING;
        out_result->next.deadline_verdict = NINLIL_DEADLINE_INDETERMINATE;
        break;
    default:
        (void)memset(out_result, 0, sizeof(*out_result));
        return NINLIL_E_INVALID_ARGUMENT;
    }

    return NINLIL_OK;
}
