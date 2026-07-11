#include "desired_target_snapshot_internal.h"

static int reason_is_known(ninlil_reason_t reason)
{
    switch (reason) {
    case NINLIL_REASON_NONE:
    case NINLIL_REASON_UNSUPPORTED_FAMILY:
    case NINLIL_REASON_UNSUPPORTED_SELECTOR:
    case NINLIL_REASON_TARGET_COUNT_UNSUPPORTED:
    case NINLIL_REASON_INVALID_SCHEMA:
    case NINLIL_REASON_INVALID_PAYLOAD_LENGTH:
    case NINLIL_REASON_INVALID_CONTENT_DIGEST:
    case NINLIL_REASON_DEADLINE_INVALID:
    case NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED:
    case NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID:
    case NINLIL_REASON_EVIDENCE_UNSUPPORTED:
    case NINLIL_REASON_CAPACITY_EXHAUSTED:
    case NINLIL_REASON_MODIFICATION_REQUIRED:
    case NINLIL_REASON_IDEMPOTENCY_CONFLICT:
    case NINLIL_REASON_GRANT_INVALID:
    case NINLIL_REASON_GRANT_EXPIRED:
    case NINLIL_REASON_GRANT_LIMIT_EXCEEDED:
    case NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE:
    case NINLIL_REASON_STORAGE_IO:
    case NINLIL_REASON_STORAGE_COMMIT_UNKNOWN:
    case NINLIL_REASON_CLOCK_UNCERTAIN:
    case NINLIL_REASON_RATE_EXHAUSTED:
    case NINLIL_REASON_TARGET_UNAUTHORIZED:
    case NINLIL_REASON_CALLBACK_CONTRACT:
    case NINLIL_REASON_UNSUPPORTED_DIRECTION:
    case NINLIL_REASON_REQUIRED_EVIDENCE_MET:
    case NINLIL_REASON_REQUIRED_EVIDENCE_LATE:
    case NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH:
    case NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING:
    case NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING:
    case NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT:
    case NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED:
    case NINLIL_REASON_EVENT_RECEIPT_TIMEOUT:
    case NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT:
    case NINLIL_REASON_BEARER_UNAVAILABLE:
    case NINLIL_REASON_CAPACITY_UNAVAILABLE:
    case NINLIL_REASON_COUNTER_EXHAUSTED:
    case NINLIL_REASON_STALE_AVAILABILITY_EPOCH:
    case NINLIL_REASON_RESUME_CONFLICT:
    case NINLIL_REASON_STALE_SPOOL_REVISION:
    case NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT:
    case NINLIL_REASON_DISCARD_CONFLICT:
    case NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH:
    case NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE:
    case NINLIL_REASON_EVENT_FACT_IMMUTABLE:
    case NINLIL_REASON_TRANSPORT_RETRY:
    case NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE:
    case NINLIL_REASON_APPLICATION_FAILED:
    case NINLIL_REASON_OUTCOME_UNKNOWN:
    case NINLIL_REASON_RECEIVER_UNAVAILABLE:
    case NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT:
    case NINLIL_REASON_RECONCILE_RETRY_LATER:
        return 1;
    default:
        return 0;
    }
}

static int deadline_verdict_is_valid(ninlil_deadline_verdict_t verdict)
{
    return verdict == NINLIL_DEADLINE_PENDING
        || verdict == NINLIL_DEADLINE_MET
        || verdict == NINLIL_DEADLINE_MISSED
        || verdict == NINLIL_DEADLINE_INDETERMINATE;
}

static int effect_certainty_is_valid(ninlil_effect_certainty_t certainty)
{
    return certainty == NINLIL_EFFECT_CERTAINTY_NONE
        || certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        || certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
}

static ninlil_outcome_t terminal_outcome_for_state(
    ninlil_model_desired_target_state_t state)
{
    switch (state) {
    case NINLIL_MODEL_DESIRED_TARGET_SATISFIED:
        return NINLIL_OUTCOME_SATISFIED;
    case NINLIL_MODEL_DESIRED_TARGET_EXPIRED:
        return NINLIL_OUTCOME_EXPIRED;
    case NINLIL_MODEL_DESIRED_TARGET_CANCELLED_BEFORE_EFFECT:
        return NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
    case NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE:
        return NINLIL_OUTCOME_FAILED_DEFINITIVE;
    case NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN:
        return NINLIL_OUTCOME_UNKNOWN;
    default:
        return NINLIL_OUTCOME_NONE;
    }
}

int ninlil_model_desired_target_state_is_active(
    ninlil_model_desired_target_state_t state)
{
    return state >= NINLIL_MODEL_DESIRED_TARGET_READY
        && state <= NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE;
}

int ninlil_model_desired_target_state_is_terminal(
    ninlil_model_desired_target_state_t state)
{
    return state >= NINLIL_MODEL_DESIRED_TARGET_SATISFIED
        && state <= NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN;
}

int ninlil_model_desired_target_snapshot_is_valid(
    const ninlil_model_desired_target_snapshot_t *current)
{
    if ((!ninlil_model_desired_target_state_is_active(current->state)
            && !ninlil_model_desired_target_state_is_terminal(current->state))
        || !reason_is_known(current->reason)
        || !deadline_verdict_is_valid(current->deadline_verdict)
        || !effect_certainty_is_valid(current->effect_certainty)) {
        return 0;
    }

    if (ninlil_model_desired_target_state_is_active(current->state)) {
        return current->outcome == NINLIL_OUTCOME_NONE;
    }

    if (current->outcome != terminal_outcome_for_state(current->state)) {
        return 0;
    }

    switch (current->state) {
    case NINLIL_MODEL_DESIRED_TARGET_SATISFIED:
        return current->reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET
            && current->deadline_verdict == NINLIL_DEADLINE_MET
            && current->effect_certainty
                == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    case NINLIL_MODEL_DESIRED_TARGET_EXPIRED:
        if (current->reason == NINLIL_REASON_REQUIRED_EVIDENCE_LATE) {
            return current->deadline_verdict == NINLIL_DEADLINE_MISSED
                && current->effect_certainty
                    == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
        }
        if (current->reason
            == NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH) {
            return current->deadline_verdict == NINLIL_DEADLINE_MISSED
                && current->effect_certainty
                    == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
        }
        return current->reason == NINLIL_REASON_CLOCK_UNCERTAIN
            && current->deadline_verdict == NINLIL_DEADLINE_INDETERMINATE
            && current->effect_certainty
                == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    case NINLIL_MODEL_DESIRED_TARGET_CANCELLED_BEFORE_EFFECT:
        return current->reason
                == NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH
            && current->deadline_verdict == NINLIL_DEADLINE_PENDING
            && current->effect_certainty
                == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    case NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE:
        return (current->reason == NINLIL_REASON_APPLICATION_FAILED
                || current->reason == NINLIL_REASON_TARGET_UNAUTHORIZED
                || current->reason
                    == NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT)
            && current->deadline_verdict == NINLIL_DEADLINE_PENDING
            && current->effect_certainty
                == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    case NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN:
        return (current->reason
                    == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING
                || current->reason == NINLIL_REASON_CLOCK_UNCERTAIN)
            && current->deadline_verdict == NINLIL_DEADLINE_INDETERMINATE
            && current->effect_certainty
                == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    default:
        return 0;
    }
}

void ninlil_model_desired_target_snapshot_copy(
    ninlil_model_desired_target_snapshot_t *destination,
    const ninlil_model_desired_target_snapshot_t *source)
{
    destination->state = source->state;
    destination->outcome = source->outcome;
    destination->reason = source->reason;
    destination->deadline_verdict = source->deadline_verdict;
    destination->effect_certainty = source->effect_certainty;
}
