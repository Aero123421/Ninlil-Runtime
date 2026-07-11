#include "desired_deadline_transition.h"
#include "required_receipt_transition.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                        \
                "%s:%d: requirement failed: %s\n",                           \
                __FILE__,                                                      \
                __LINE__,                                                      \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef ninlil_status_t (*deadline_reducer_fn)(
    const ninlil_model_desired_deadline_transition_input_t *,
    ninlil_model_desired_deadline_transition_result_t *);

static ninlil_model_desired_target_snapshot_t make_active_snapshot(
    ninlil_model_desired_target_state_t state,
    ninlil_effect_certainty_t certainty)
{
    ninlil_model_desired_target_snapshot_t snapshot;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = state;
    snapshot.outcome = NINLIL_OUTCOME_NONE;
    snapshot.reason = NINLIL_REASON_NONE;
    snapshot.deadline_verdict = NINLIL_DEADLINE_PENDING;
    snapshot.effect_certainty = certainty;
    return snapshot;
}

static ninlil_model_desired_deadline_transition_input_t make_input(void)
{
    ninlil_model_desired_deadline_transition_input_t input;

    (void)memset(&input, 0, sizeof(input));
    input.current = make_active_snapshot(
        NINLIL_MODEL_DESIRED_TARGET_READY,
        NINLIL_EFFECT_CERTAINTY_NONE);
    input.deadline_evidence = NINLIL_MODEL_DEADLINE_EVIDENCE_NONE;
    input.effect_basis =
        NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT;
    return input;
}

static int snapshot_equals(
    const ninlil_model_desired_target_snapshot_t *left,
    const ninlil_model_desired_target_snapshot_t *right)
{
    return left->state == right->state
        && left->outcome == right->outcome
        && left->reason == right->reason
        && left->deadline_verdict == right->deadline_verdict
        && left->effect_certainty == right->effect_certainty;
}

static int result_is_zero(
    const ninlil_model_desired_deadline_transition_result_t *result)
{
    ninlil_model_desired_deadline_transition_result_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(result, &zero, sizeof(zero)) == 0;
}

static int snapshot_is_zero(
    const ninlil_model_desired_target_snapshot_t *snapshot)
{
    ninlil_model_desired_target_snapshot_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(snapshot, &zero, sizeof(zero)) == 0;
}

static int expect_invalid(
    deadline_reducer_fn reducer,
    const ninlil_model_desired_deadline_transition_input_t *input)
{
    ninlil_model_desired_deadline_transition_result_t result;

    (void)memset(&result, 0xa5, sizeof(result));
    return reducer(input, &result) == NINLIL_E_INVALID_ARGUMENT
        && result_is_zero(&result);
}

static int require_result(
    const ninlil_model_desired_deadline_transition_result_t *result,
    ninlil_model_desired_target_state_t state,
    ninlil_outcome_t outcome,
    ninlil_reason_t reason,
    ninlil_deadline_verdict_t verdict,
    ninlil_effect_certainty_t certainty)
{
    return result->next.state == state
        && result->next.outcome == outcome
        && result->next.reason == reason
        && result->next.deadline_verdict == verdict
        && result->next.effect_certainty == certainty
        && result->action == NINLIL_MODEL_DEADLINE_TRANSITION_APPLIED
        && result->catch_up_basis == (ninlil_model_effect_basis_t)0;
}

static int test_effect_deadline_matrix(void)
{
    static const struct definitive_case {
        ninlil_model_effect_basis_t basis;
        ninlil_reason_t reason;
    } definitive_cases[] = {
        {
            NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_APPLICATION_FAILED,
            NINLIL_REASON_APPLICATION_FAILED
        },
        {
            NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_TARGET_UNAUTHORIZED,
            NINLIL_REASON_TARGET_UNAUTHORIZED
        },
        {
            NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_RETRY_BUDGET_EXHAUSTED,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT
        }
    };
    ninlil_model_desired_deadline_transition_input_t input = make_input();
    ninlil_model_desired_deadline_transition_result_t result;
    size_t index;

    REQUIRE(ninlil_model_reduce_desired_effect_deadline(&input, &result)
        == NINLIL_OK);
    REQUIRE(require_result(
        &result,
        NINLIL_MODEL_DESIRED_TARGET_EXPIRED,
        NINLIL_OUTCOME_EXPIRED,
        NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH,
        NINLIL_DEADLINE_MISSED,
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN));

    for (index = 0u;
         index < sizeof(definitive_cases) / sizeof(definitive_cases[0]);
         ++index) {
        input = make_input();
        input.current = make_active_snapshot(
            NINLIL_MODEL_DESIRED_TARGET_RETRY_WAIT,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN);
        input.effect_basis = definitive_cases[index].basis;
        REQUIRE(ninlil_model_reduce_desired_effect_deadline(&input, &result)
            == NINLIL_OK);
        REQUIRE(require_result(
            &result,
            NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE,
            NINLIL_OUTCOME_FAILED_DEFINITIVE,
            definitive_cases[index].reason,
            NINLIL_DEADLINE_PENDING,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN));
    }

    input = make_input();
    input.current = make_active_snapshot(
        NINLIL_MODEL_DESIRED_TARGET_ATTEMPT_PREPARED,
        NINLIL_EFFECT_CERTAINTY_NONE);
    input.effect_basis = NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
    REQUIRE(ninlil_model_reduce_desired_effect_deadline(&input, &result)
        == NINLIL_OK);
    REQUIRE(require_result(
        &result,
        NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE,
        NINLIL_OUTCOME_NONE,
        NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING,
        NINLIL_DEADLINE_INDETERMINATE,
        NINLIL_EFFECT_CERTAINTY_POSSIBLE));

    input.current = result.next;
    input.deadline_evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN;
    REQUIRE(ninlil_model_reduce_desired_effect_deadline(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.next.state == NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE);
    REQUIRE(result.next.reason
        == NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING);
    return 0;
}

static int test_evidence_close_matrix(void)
{
    static const ninlil_model_effect_basis_t catch_up_bases[] = {
        NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT,
        NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_APPLICATION_FAILED,
        NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_TARGET_UNAUTHORIZED,
        NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_RETRY_BUDGET_EXHAUSTED
    };
    ninlil_model_desired_deadline_transition_input_t input = make_input();
    ninlil_model_desired_deadline_transition_result_t result;
    size_t index;

    input.current = make_active_snapshot(
        NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE,
        NINLIL_EFFECT_CERTAINTY_POSSIBLE);
    input.effect_basis = NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
    input.deadline_evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE;
    REQUIRE(ninlil_model_reduce_desired_evidence_close(&input, &result)
        == NINLIL_OK);
    REQUIRE(require_result(
        &result,
        NINLIL_MODEL_DESIRED_TARGET_EXPIRED,
        NINLIL_OUTCOME_EXPIRED,
        NINLIL_REASON_REQUIRED_EVIDENCE_LATE,
        NINLIL_DEADLINE_MISSED,
        NINLIL_EFFECT_CERTAINTY_POSSIBLE));

    input.deadline_evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN;
    REQUIRE(ninlil_model_reduce_desired_evidence_close(&input, &result)
        == NINLIL_OK);
    REQUIRE(require_result(
        &result,
        NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN,
        NINLIL_OUTCOME_UNKNOWN,
        NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING,
        NINLIL_DEADLINE_INDETERMINATE,
        NINLIL_EFFECT_CERTAINTY_POSSIBLE));

    input.deadline_evidence = NINLIL_MODEL_DEADLINE_EVIDENCE_NONE;
    REQUIRE(ninlil_model_reduce_desired_evidence_close(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.next.state == NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN);

    for (index = 0u;
         index < sizeof(catch_up_bases) / sizeof(catch_up_bases[0]);
         ++index) {
        input = make_input();
        input.effect_basis = catch_up_bases[index];
        if (input.effect_basis
            != NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT) {
            input.current.effect_certainty =
                NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
        }
        (void)memset(&result, 0xa5, sizeof(result));
        REQUIRE(ninlil_model_reduce_desired_evidence_close(&input, &result)
            == NINLIL_OK);
        REQUIRE(snapshot_is_zero(&result.next));
        REQUIRE(result.action
            == NINLIL_MODEL_DEADLINE_CATCH_UP_PRIOR_REDUCER);
        REQUIRE(result.catch_up_basis == input.effect_basis);
    }
    return 0;
}

static int test_terminal_absorbs(void)
{
    static const ninlil_model_desired_target_snapshot_t terminals[] = {
        {
            NINLIL_MODEL_DESIRED_TARGET_SATISFIED,
            NINLIL_OUTCOME_SATISFIED,
            NINLIL_REASON_REQUIRED_EVIDENCE_MET,
            NINLIL_DEADLINE_MET,
            NINLIL_EFFECT_CERTAINTY_POSSIBLE
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_EXPIRED,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_REQUIRED_EVIDENCE_LATE,
            NINLIL_DEADLINE_MISSED,
            NINLIL_EFFECT_CERTAINTY_POSSIBLE
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_CANCELLED_BEFORE_EFFECT,
            NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT,
            NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH,
            NINLIL_DEADLINE_PENDING,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE,
            NINLIL_OUTCOME_FAILED_DEFINITIVE,
            NINLIL_REASON_APPLICATION_FAILED,
            NINLIL_DEADLINE_PENDING,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN,
            NINLIL_OUTCOME_UNKNOWN,
            NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING,
            NINLIL_DEADLINE_INDETERMINATE,
            NINLIL_EFFECT_CERTAINTY_POSSIBLE
        }
    };
    deadline_reducer_fn reducers[] = {
        ninlil_model_reduce_desired_effect_deadline,
        ninlil_model_reduce_desired_evidence_close
    };
    size_t terminal_index;
    size_t reducer_index;

    for (terminal_index = 0u;
         terminal_index < sizeof(terminals) / sizeof(terminals[0]);
         ++terminal_index) {
        for (reducer_index = 0u;
             reducer_index < sizeof(reducers) / sizeof(reducers[0]);
             ++reducer_index) {
            ninlil_model_desired_deadline_transition_input_t input =
                make_input();
            ninlil_model_desired_deadline_transition_result_t result;

            input.current = terminals[terminal_index];
            input.deadline_evidence =
                NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME;
            input.effect_basis =
                NINLIL_MODEL_EFFECT_BASIS_DEADLINE_ONLY_NO_EFFECT;
            REQUIRE(reducers[reducer_index](&input, &result) == NINLIL_OK);
            REQUIRE(snapshot_equals(&result.next, &input.current));
            REQUIRE(result.action
                == NINLIL_MODEL_DEADLINE_TERMINAL_ABSORBED);
            REQUIRE(result.catch_up_basis == (ninlil_model_effect_basis_t)0);
        }
    }
    return 0;
}

static int test_fail_closed(void)
{
    deadline_reducer_fn reducers[] = {
        ninlil_model_reduce_desired_effect_deadline,
        ninlil_model_reduce_desired_evidence_close
    };
    ninlil_model_desired_deadline_transition_input_t input;
    size_t reducer_index;

    for (reducer_index = 0u;
         reducer_index < sizeof(reducers) / sizeof(reducers[0]);
         ++reducer_index) {
        ninlil_model_desired_deadline_transition_result_t result;

        input = make_input();
        REQUIRE(expect_invalid(reducers[reducer_index], NULL));
        REQUIRE(reducers[reducer_index](&input, NULL)
            == NINLIL_E_INVALID_ARGUMENT);

        input.current.state = (ninlil_model_desired_target_state_t)0;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));
        input = make_input();
        input.current.outcome = NINLIL_OUTCOME_EXPIRED;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));

        input = make_input();
        input.deadline_evidence = (ninlil_model_deadline_evidence_t)4u;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));
        input = make_input();
        input.effect_basis = (ninlil_model_effect_basis_t)0;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));
        input.effect_basis = (ninlil_model_effect_basis_t)6;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));

        input = make_input();
        input.deadline_evidence =
            NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));

        input = make_input();
        input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));
        input = make_input();
        input.effect_basis =
            NINLIL_MODEL_EFFECT_BASIS_DEFINITIVE_APPLICATION_FAILED;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));
        input = make_input();
        input.current.effect_certainty =
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
        input.effect_basis = NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));
        input = make_input();
        input.effect_basis = NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
        input.deadline_evidence =
            NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN;
        REQUIRE(expect_invalid(reducers[reducer_index], &input));

        (void)memset(&result, 0xa5, sizeof(result));
        REQUIRE(reducers[reducer_index](NULL, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(result_is_zero(&result));
    }

    input = make_input();
    input.current = make_active_snapshot(
        NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE,
        NINLIL_EFFECT_CERTAINTY_POSSIBLE);
    input.effect_basis = NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
    input.deadline_evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE;
    REQUIRE(expect_invalid(
        ninlil_model_reduce_desired_effect_deadline,
        &input));
    return 0;
}

static int test_same_time_api_chains(void)
{
    ninlil_model_required_receipt_transition_input_t receipt;
    ninlil_model_required_receipt_transition_result_t receipt_result;
    ninlil_model_desired_deadline_transition_input_t deadline;
    ninlil_model_desired_deadline_transition_result_t deadline_result;
    ninlil_model_desired_deadline_transition_result_t close_result;

    (void)memset(&receipt, 0, sizeof(receipt));
    receipt.current = make_active_snapshot(
        NINLIL_MODEL_DESIRED_TARGET_AWAITING_EVIDENCE,
        NINLIL_EFFECT_CERTAINTY_POSSIBLE);
    receipt.required_stage_reached = 1u;
    receipt.receipt_is_new_material = 1u;
    receipt.deadline.evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME;
    receipt.deadline.verdict = NINLIL_DEADLINE_MET;
    REQUIRE(ninlil_model_reduce_desired_required_receipt(
                &receipt,
                &receipt_result)
        == NINLIL_OK);

    deadline.current = receipt_result.next;
    deadline.deadline_evidence = receipt.deadline.evidence;
    deadline.effect_basis = NINLIL_MODEL_EFFECT_BASIS_EFFECT_POSSIBLE;
    REQUIRE(ninlil_model_reduce_desired_effect_deadline(
                &deadline,
                &deadline_result)
        == NINLIL_OK);
    REQUIRE(deadline_result.next.state
        == NINLIL_MODEL_DESIRED_TARGET_SATISFIED);
    deadline.current = deadline_result.next;
    REQUIRE(ninlil_model_reduce_desired_evidence_close(
                &deadline,
                &close_result)
        == NINLIL_OK);
    REQUIRE(close_result.next.state
        == NINLIL_MODEL_DESIRED_TARGET_SATISFIED);

    receipt.deadline.evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN;
    receipt.deadline.verdict = NINLIL_DEADLINE_INDETERMINATE;
    REQUIRE(ninlil_model_reduce_desired_required_receipt(
                &receipt,
                &receipt_result)
        == NINLIL_OK);
    deadline.current = receipt_result.next;
    deadline.deadline_evidence = receipt.deadline.evidence;
    REQUIRE(ninlil_model_reduce_desired_effect_deadline(
                &deadline,
                &deadline_result)
        == NINLIL_OK);
    REQUIRE(deadline_result.next.state
        == NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE);
    deadline.current = deadline_result.next;
    REQUIRE(ninlil_model_reduce_desired_evidence_close(
                &deadline,
                &close_result)
        == NINLIL_OK);
    REQUIRE(close_result.next.state
        == NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN);
    return 0;
}

int main(void)
{
    REQUIRE(test_effect_deadline_matrix() == 0);
    REQUIRE(test_evidence_close_matrix() == 0);
    REQUIRE(test_terminal_absorbs() == 0);
    REQUIRE(test_fail_closed() == 0);
    REQUIRE(test_same_time_api_chains() == 0);
    return 0;
}
