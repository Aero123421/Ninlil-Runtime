#include "deadline_projection.h"

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

static ninlil_id128_t make_epoch(uint8_t value)
{
    ninlil_id128_t epoch;

    (void)memset(&epoch, 0, sizeof(epoch));
    epoch.bytes[15] = value;
    return epoch;
}

static ninlil_model_semantic_time_t make_time(
    uint8_t epoch,
    uint64_t now_ms,
    ninlil_clock_trust_t trust)
{
    ninlil_model_semantic_time_t time;

    (void)memset(&time, 0, sizeof(time));
    time.clock_epoch_id = make_epoch(epoch);
    time.now_ms = now_ms;
    time.trust = trust;
    return time;
}

static ninlil_model_required_receipt_deadline_input_t make_command_input(void)
{
    ninlil_model_required_receipt_deadline_input_t input;

    (void)memset(&input, 0, sizeof(input));
    input.family = NINLIL_FAMILY_DESIRED_STATE;
    input.deadline_clock_epoch_id = make_epoch(1u);
    input.absolute_effect_deadline_ms = 5000u;
    input.issuer_evidence_time = make_time(1u, 4500u, NINLIL_CLOCK_TRUSTED);
    input.controller_ingress_time =
        make_time(1u, 5200u, NINLIL_CLOCK_TRUSTED);
    return input;
}

static int project_equals(
    const ninlil_model_required_receipt_deadline_input_t *input,
    ninlil_model_deadline_evidence_t expected_evidence,
    ninlil_deadline_verdict_t expected_verdict)
{
    ninlil_model_required_receipt_deadline_result_t result;

    (void)memset(&result, 0xa5, sizeof(result));
    if (ninlil_model_project_required_receipt_deadline(input, &result)
        != NINLIL_OK) {
        return 0;
    }
    return result.evidence == expected_evidence
        && result.verdict == expected_verdict;
}

static int expect_invalid(
    const ninlil_model_required_receipt_deadline_input_t *input)
{
    ninlil_model_required_receipt_deadline_result_t result;

    (void)memset(&result, 0xa5, sizeof(result));
    if (ninlil_model_project_required_receipt_deadline(input, &result)
        != NINLIL_E_INVALID_ARGUMENT) {
        return 0;
    }
    return result.evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_NONE
        && result.verdict == NINLIL_DEADLINE_PENDING;
}

static int test_direct_issuer_proof(void)
{
    ninlil_model_required_receipt_deadline_input_t input = make_command_input();

    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME,
        NINLIL_DEADLINE_MET));

    input.issuer_evidence_time.now_ms = input.absolute_effect_deadline_ms;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME,
        NINLIL_DEADLINE_MET));

    input.issuer_evidence_time.now_ms = input.absolute_effect_deadline_ms + 1u;
    input.controller_ingress_time.now_ms = input.absolute_effect_deadline_ms - 1u;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE,
        NINLIL_DEADLINE_MISSED));

    input.absolute_effect_deadline_ms = UINT64_MAX - 1u;
    input.issuer_evidence_time.now_ms = UINT64_MAX;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE,
        NINLIL_DEADLINE_MISSED));
    return 0;
}

static int test_fallback_ingress_proof(void)
{
    ninlil_model_required_receipt_deadline_input_t input = make_command_input();

    input.issuer_evidence_time.clock_epoch_id = make_epoch(2u);
    input.controller_ingress_time.now_ms = input.absolute_effect_deadline_ms;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME,
        NINLIL_DEADLINE_MET));

    input.controller_ingress_time.now_ms = input.absolute_effect_deadline_ms + 1u;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN,
        NINLIL_DEADLINE_INDETERMINATE));

    input.issuer_evidence_time = make_time(1u, 4500u, NINLIL_CLOCK_UNCERTAIN);
    input.controller_ingress_time.now_ms = input.absolute_effect_deadline_ms;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME,
        NINLIL_DEADLINE_MET));

    input.controller_ingress_time.now_ms = input.absolute_effect_deadline_ms + 1u;
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN,
        NINLIL_DEADLINE_INDETERMINATE));

    input.controller_ingress_time = make_time(2u, 1u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN,
        NINLIL_DEADLINE_INDETERMINATE));

    input.controller_ingress_time =
        make_time(1u, 1u, NINLIL_CLOCK_UNCERTAIN);
    REQUIRE(project_equals(
        &input,
        NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN,
        NINLIL_DEADLINE_INDETERMINATE));
    return 0;
}

static int test_event_fact_is_audit_only(void)
{
    ninlil_model_required_receipt_deadline_input_t input = make_command_input();
    uint32_t variant;

    input.family = NINLIL_FAMILY_EVENT_FACT;
    (void)memset(
        &input.deadline_clock_epoch_id,
        0,
        sizeof(input.deadline_clock_epoch_id));
    input.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;

    for (variant = 0u; variant < 4u; ++variant) {
        input.issuer_evidence_time = make_time(
            (uint8_t)(variant + 1u),
            variant == 0u ? 0u : UINT64_MAX - (uint64_t)variant,
            (variant & 1u) == 0u
                ? NINLIL_CLOCK_TRUSTED
                : NINLIL_CLOCK_UNCERTAIN);
        input.controller_ingress_time = make_time(
            (uint8_t)(4u - variant),
            (uint64_t)variant,
            (variant & 1u) == 0u
                ? NINLIL_CLOCK_UNCERTAIN
                : NINLIL_CLOCK_TRUSTED);
        REQUIRE(project_equals(
            &input,
            NINLIL_MODEL_DEADLINE_EVIDENCE_NONE,
            NINLIL_DEADLINE_NOT_APPLICABLE));
    }
    return 0;
}

static int test_fail_closed_shapes(void)
{
    ninlil_model_required_receipt_deadline_input_t input = make_command_input();
    ninlil_model_required_receipt_deadline_result_t result;

    REQUIRE(expect_invalid(NULL));
    REQUIRE(ninlil_model_project_required_receipt_deadline(&input, NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    input.family = (ninlil_family_t)0u;
    REQUIRE(expect_invalid(&input));
    input.family = NINLIL_FAMILY_LATEST_STATE_RESERVED;
    REQUIRE(expect_invalid(&input));

    input = make_command_input();
    (void)memset(
        &input.deadline_clock_epoch_id,
        0,
        sizeof(input.deadline_clock_epoch_id));
    REQUIRE(expect_invalid(&input));
    input = make_command_input();
    input.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
    REQUIRE(expect_invalid(&input));

    input = make_command_input();
    (void)memset(
        &input.issuer_evidence_time.clock_epoch_id,
        0,
        sizeof(input.issuer_evidence_time.clock_epoch_id));
    REQUIRE(expect_invalid(&input));
    input = make_command_input();
    (void)memset(
        &input.controller_ingress_time.clock_epoch_id,
        0,
        sizeof(input.controller_ingress_time.clock_epoch_id));
    REQUIRE(expect_invalid(&input));
    input = make_command_input();
    input.issuer_evidence_time.trust = (ninlil_clock_trust_t)0u;
    REQUIRE(expect_invalid(&input));
    input = make_command_input();
    input.controller_ingress_time.trust = (ninlil_clock_trust_t)3u;
    REQUIRE(expect_invalid(&input));

    input = make_command_input();
    input.family = NINLIL_FAMILY_EVENT_FACT;
    input.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
    REQUIRE(expect_invalid(&input));
    (void)memset(
        &input.deadline_clock_epoch_id,
        0,
        sizeof(input.deadline_clock_epoch_id));
    input.absolute_effect_deadline_ms = 5000u;
    REQUIRE(expect_invalid(&input));

    (void)memset(&result, 0xa5, sizeof(result));
    REQUIRE(ninlil_model_project_required_receipt_deadline(NULL, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result.evidence == NINLIL_MODEL_DEADLINE_EVIDENCE_NONE);
    REQUIRE(result.verdict == NINLIL_DEADLINE_PENDING);
    return 0;
}

static int test_determinism(void)
{
    ninlil_model_required_receipt_deadline_input_t input = make_command_input();
    ninlil_model_required_receipt_deadline_result_t baseline;
    uint32_t iteration;

    input.issuer_evidence_time = make_time(2u, 1u, NINLIL_CLOCK_TRUSTED);
    input.controller_ingress_time =
        make_time(1u, 5001u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_model_project_required_receipt_deadline(&input, &baseline)
        == NINLIL_OK);
    for (iteration = 0u; iteration < 100u; ++iteration) {
        ninlil_model_required_receipt_deadline_result_t trial;

        (void)memset(&trial, (int)(iteration + 1u), sizeof(trial));
        REQUIRE(ninlil_model_project_required_receipt_deadline(&input, &trial)
            == NINLIL_OK);
        REQUIRE(memcmp(&trial, &baseline, sizeof(trial)) == 0);
    }
    return 0;
}

int main(void)
{
    int failed = 0;

    failed |= test_direct_issuer_proof();
    failed |= test_fallback_ingress_proof();
    failed |= test_event_fact_is_audit_only();
    failed |= test_fail_closed_shapes();
    failed |= test_determinism();

    if (failed == 0) {
        (void)puts("deadline projection model tests passed");
    }
    return failed;
}
