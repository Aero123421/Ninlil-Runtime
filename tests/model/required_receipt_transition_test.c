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

typedef struct expected_transition {
    ninlil_model_deadline_evidence_t evidence;
    ninlil_deadline_verdict_t projected_verdict;
    ninlil_model_desired_target_state_t state;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    ninlil_deadline_verdict_t verdict;
} expected_transition_t;

static const ninlil_model_desired_target_state_t active_states[] = {
    NINLIL_MODEL_DESIRED_TARGET_READY,
    NINLIL_MODEL_DESIRED_TARGET_ATTEMPT_PREPARED,
    NINLIL_MODEL_DESIRED_TARGET_AWAITING_EVIDENCE,
    NINLIL_MODEL_DESIRED_TARGET_RETRY_WAIT,
    NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE
};

static const expected_transition_t active_transitions[] = {
    {
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME,
        NINLIL_DEADLINE_MET,
        NINLIL_MODEL_DESIRED_TARGET_SATISFIED,
        NINLIL_OUTCOME_SATISFIED,
        NINLIL_REASON_REQUIRED_EVIDENCE_MET,
        NINLIL_DEADLINE_MET
    },
    {
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE,
        NINLIL_DEADLINE_MISSED,
        NINLIL_MODEL_DESIRED_TARGET_EXPIRED,
        NINLIL_OUTCOME_EXPIRED,
        NINLIL_REASON_REQUIRED_EVIDENCE_LATE,
        NINLIL_DEADLINE_MISSED
    },
    {
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN,
        NINLIL_DEADLINE_INDETERMINATE,
        NINLIL_MODEL_DESIRED_TARGET_AWAITING_GRACE,
        NINLIL_OUTCOME_NONE,
        NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING,
        NINLIL_DEADLINE_INDETERMINATE
    }
};

static ninlil_model_required_receipt_transition_input_t make_active_input(void)
{
    ninlil_model_required_receipt_transition_input_t input;

    (void)memset(&input, 0, sizeof(input));
    input.current.state = NINLIL_MODEL_DESIRED_TARGET_READY;
    input.current.outcome = NINLIL_OUTCOME_NONE;
    input.current.reason = NINLIL_REASON_TRANSPORT_RETRY;
    input.current.deadline_verdict = NINLIL_DEADLINE_PENDING;
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    input.required_stage_reached = 1u;
    input.receipt_is_new_material = 1u;
    input.deadline.evidence =
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME;
    input.deadline.verdict = NINLIL_DEADLINE_MET;
    return input;
}

static int result_is_zero(
    const ninlil_model_required_receipt_transition_result_t *result)
{
    ninlil_model_required_receipt_transition_result_t zero;

    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(result, &zero, sizeof(zero)) == 0;
}

static int expect_invalid(
    const ninlil_model_required_receipt_transition_input_t *input)
{
    ninlil_model_required_receipt_transition_result_t result;

    (void)memset(&result, 0xa5, sizeof(result));
    return ninlil_model_reduce_desired_required_receipt(input, &result)
            == NINLIL_E_INVALID_ARGUMENT
        && result_is_zero(&result);
}

static int test_active_matrix(void)
{
    size_t state_index;
    size_t transition_index;

    for (state_index = 0u;
         state_index < sizeof(active_states) / sizeof(active_states[0]);
         ++state_index) {
        for (transition_index = 0u;
             transition_index
                < sizeof(active_transitions) / sizeof(active_transitions[0]);
             ++transition_index) {
            ninlil_model_required_receipt_transition_input_t input =
                make_active_input();
            ninlil_model_required_receipt_transition_result_t result;
            const expected_transition_t *expected =
                &active_transitions[transition_index];

            input.current.state = active_states[state_index];
            input.deadline.evidence = expected->evidence;
            input.deadline.verdict = expected->projected_verdict;
            (void)memset(&result, 0xa5, sizeof(result));

            REQUIRE(ninlil_model_reduce_desired_required_receipt(
                        &input,
                        &result)
                == NINLIL_OK);
            REQUIRE(result.next.state == expected->state);
            REQUIRE(result.next.outcome == expected->outcome);
            REQUIRE(result.next.reason == expected->reason);
            REQUIRE(result.next.deadline_verdict == expected->verdict);
            REQUIRE(result.next.effect_certainty
                == NINLIL_EFFECT_CERTAINTY_POSSIBLE);
            REQUIRE(result.evidence_action
                == NINLIL_MODEL_RECEIPT_EVIDENCE_ACTIVE_REQUIRED);
        }
    }
    return 0;
}

static int test_terminal_is_immutable(void)
{
    static const struct terminal_case {
        ninlil_model_desired_target_state_t state;
        ninlil_outcome_t outcome;
        ninlil_reason_t reason;
        ninlil_deadline_verdict_t verdict;
        ninlil_effect_certainty_t certainty;
    } terminal_cases[] = {
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
            NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH,
            NINLIL_DEADLINE_MISSED,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_EXPIRED,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_REQUIRED_EVIDENCE_LATE,
            NINLIL_DEADLINE_MISSED,
            NINLIL_EFFECT_CERTAINTY_POSSIBLE
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_EXPIRED,
            NINLIL_OUTCOME_EXPIRED,
            NINLIL_REASON_CLOCK_UNCERTAIN,
            NINLIL_DEADLINE_INDETERMINATE,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
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
            NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE,
            NINLIL_OUTCOME_FAILED_DEFINITIVE,
            NINLIL_REASON_TARGET_UNAUTHORIZED,
            NINLIL_DEADLINE_PENDING,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE,
            NINLIL_OUTCOME_FAILED_DEFINITIVE,
            NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT,
            NINLIL_DEADLINE_PENDING,
            NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN,
            NINLIL_OUTCOME_UNKNOWN,
            NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING,
            NINLIL_DEADLINE_INDETERMINATE,
            NINLIL_EFFECT_CERTAINTY_POSSIBLE
        },
        {
            NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN,
            NINLIL_OUTCOME_UNKNOWN,
            NINLIL_REASON_CLOCK_UNCERTAIN,
            NINLIL_DEADLINE_INDETERMINATE,
            NINLIL_EFFECT_CERTAINTY_POSSIBLE
        }
    };
    size_t terminal_index;
    size_t projection_index;

    for (terminal_index = 0u;
         terminal_index < sizeof(terminal_cases) / sizeof(terminal_cases[0]);
         ++terminal_index) {
        for (projection_index = 0u;
             projection_index
                < sizeof(active_transitions) / sizeof(active_transitions[0]);
             ++projection_index) {
            ninlil_model_required_receipt_transition_input_t input =
                make_active_input();
            ninlil_model_required_receipt_transition_result_t result;
            const struct terminal_case *terminal =
                &terminal_cases[terminal_index];

            input.current.state = terminal->state;
            input.current.outcome = terminal->outcome;
            input.current.reason = terminal->reason;
            input.current.deadline_verdict = terminal->verdict;
            input.current.effect_certainty = terminal->certainty;
            input.deadline.evidence =
                active_transitions[projection_index].evidence;
            input.deadline.verdict =
                active_transitions[projection_index].projected_verdict;

            REQUIRE(ninlil_model_reduce_desired_required_receipt(
                        &input,
                        &result)
                == NINLIL_OK);
            REQUIRE(result.next.state == input.current.state);
            REQUIRE(result.next.outcome == input.current.outcome);
            REQUIRE(result.next.reason == input.current.reason);
            REQUIRE(result.next.deadline_verdict
                == input.current.deadline_verdict);
            REQUIRE(result.next.effect_certainty
                == input.current.effect_certainty);
            REQUIRE(result.evidence_action
                == NINLIL_MODEL_RECEIPT_EVIDENCE_TERMINAL_LATE);
        }
    }
    return 0;
}

static int test_projection_pairs_fail_closed(void)
{
    ninlil_model_deadline_evidence_t evidence;
    ninlil_deadline_verdict_t verdict;

    for (evidence = NINLIL_MODEL_DEADLINE_EVIDENCE_NONE;
         evidence <= (ninlil_model_deadline_evidence_t)4u;
         ++evidence) {
        for (verdict = NINLIL_DEADLINE_PENDING;
             verdict <= (ninlil_deadline_verdict_t)5u;
             ++verdict) {
            ninlil_model_required_receipt_transition_input_t input =
                make_active_input();
            int valid_pair;

            input.deadline.evidence = evidence;
            input.deadline.verdict = verdict;
            valid_pair =
                (evidence
                        == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME
                    && verdict == NINLIL_DEADLINE_MET)
                || (evidence
                        == NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE
                    && verdict == NINLIL_DEADLINE_MISSED)
                || (evidence
                        == NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN
                    && verdict == NINLIL_DEADLINE_INDETERMINATE);

            if (valid_pair) {
                ninlil_model_required_receipt_transition_result_t result;

                REQUIRE(ninlil_model_reduce_desired_required_receipt(
                            &input,
                            &result)
                    == NINLIL_OK);
            } else {
                REQUIRE(expect_invalid(&input));
            }
        }
    }
    return 0;
}

static int test_current_shape_and_guards_fail_closed(void)
{
    ninlil_model_required_receipt_transition_input_t input =
        make_active_input();
    ninlil_model_required_receipt_transition_result_t result;

    REQUIRE(expect_invalid(NULL));
    REQUIRE(ninlil_model_reduce_desired_required_receipt(&input, NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    input.required_stage_reached = 0u;
    REQUIRE(expect_invalid(&input));
    input.required_stage_reached = 2u;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.receipt_is_new_material = 0u;
    REQUIRE(expect_invalid(&input));
    input.receipt_is_new_material = 2u;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state = (ninlil_model_desired_target_state_t)0u;
    REQUIRE(expect_invalid(&input));
    input.current.state = (ninlil_model_desired_target_state_t)11u;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.outcome = NINLIL_OUTCOME_EXPIRED;
    REQUIRE(expect_invalid(&input));
    input.current.outcome = NINLIL_OUTCOME_SUPERSEDED_RESERVED;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state = NINLIL_MODEL_DESIRED_TARGET_EXPIRED;
    input.current.outcome = NINLIL_OUTCOME_SATISFIED;
    input.current.reason = NINLIL_REASON_REQUIRED_EVIDENCE_LATE;
    REQUIRE(expect_invalid(&input));
    input.current.outcome = NINLIL_OUTCOME_EXPIRED;
    input.current.reason = NINLIL_REASON_NONE;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state = NINLIL_MODEL_DESIRED_TARGET_SATISFIED;
    input.current.outcome = NINLIL_OUTCOME_SATISFIED;
    input.current.reason = NINLIL_REASON_APPLICATION_FAILED;
    input.current.deadline_verdict = NINLIL_DEADLINE_MET;
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_REQUIRED_EVIDENCE_MET;
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_NONE;
    REQUIRE(expect_invalid(&input));
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    input.current.deadline_verdict = NINLIL_DEADLINE_PENDING;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state = NINLIL_MODEL_DESIRED_TARGET_EXPIRED;
    input.current.outcome = NINLIL_OUTCOME_EXPIRED;
    input.current.reason = NINLIL_REASON_INVALID_SCHEMA;
    input.current.deadline_verdict = NINLIL_DEADLINE_MISSED;
    input.current.effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_REQUIRED_EVIDENCE_LATE;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_CLOCK_UNCERTAIN;
    input.current.deadline_verdict = NINLIL_DEADLINE_MISSED;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state =
        NINLIL_MODEL_DESIRED_TARGET_CANCELLED_BEFORE_EFFECT;
    input.current.outcome = NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
    input.current.reason = NINLIL_REASON_APPLICATION_FAILED;
    input.current.deadline_verdict = NINLIL_DEADLINE_PENDING;
    input.current.effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH;
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state = NINLIL_MODEL_DESIRED_TARGET_FAILED_DEFINITIVE;
    input.current.outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
    input.current.reason = NINLIL_REASON_CLOCK_UNCERTAIN;
    input.current.deadline_verdict = NINLIL_DEADLINE_PENDING;
    input.current.effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_APPLICATION_FAILED;
    input.current.deadline_verdict = NINLIL_DEADLINE_MISSED;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.state = NINLIL_MODEL_DESIRED_TARGET_OUTCOME_UNKNOWN;
    input.current.outcome = NINLIL_OUTCOME_UNKNOWN;
    input.current.reason = NINLIL_REASON_OUTCOME_UNKNOWN;
    input.current.deadline_verdict = NINLIL_DEADLINE_INDETERMINATE;
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_POSSIBLE;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING;
    input.current.effect_certainty = NINLIL_EFFECT_CERTAINTY_NONE;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.reason = (ninlil_reason_t)67u;
    REQUIRE(expect_invalid(&input));
    input.current.reason = NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION;
    REQUIRE(expect_invalid(&input));
    input.current.reason = (ninlil_reason_t)UINT32_MAX;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.deadline_verdict = NINLIL_DEADLINE_NOT_APPLICABLE;
    REQUIRE(expect_invalid(&input));
    input.current.deadline_verdict = (ninlil_deadline_verdict_t)5u;
    REQUIRE(expect_invalid(&input));

    input = make_active_input();
    input.current.effect_certainty = (ninlil_effect_certainty_t)3u;
    REQUIRE(expect_invalid(&input));

    (void)memset(&result, 0xa5, sizeof(result));
    REQUIRE(ninlil_model_reduce_desired_required_receipt(NULL, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result_is_zero(&result));
    return 0;
}

int main(void)
{
    REQUIRE(test_active_matrix() == 0);
    REQUIRE(test_terminal_is_immutable() == 0);
    REQUIRE(test_projection_pairs_fail_closed() == 0);
    REQUIRE(test_current_shape_and_guards_fail_closed() == 0);
    return 0;
}
