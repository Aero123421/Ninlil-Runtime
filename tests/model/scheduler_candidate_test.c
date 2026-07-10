#include "scheduler_candidate.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

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

typedef struct expected_work_row {
    uint8_t priority;
    uint8_t work_class;
    uint8_t dynamic;
    ninlil_model_tie_contract_t tie_contract;
} expected_work_row_t;

static const uint8_t EXPECTED_INPUT_PRIORITIES[] = {
    0u,
    0u, 0u, 0u,
    1u, 1u, 1u, 1u, 1u,
    2u, 2u,
    3u, 3u, 3u,
    4u,
    5u,
    6u,
    7u, 7u,
    8u, 8u, 8u,
    9u, 9u,
    10u, 10u
};

static const uint8_t EXPECTED_DURABLE_RING_INPUTS[] = {
    0u,
    0u, 0u, 0u,
    0u, 0u, 0u,
    1u, 1u,
    1u, 1u,
    1u, 1u, 1u,
    0u,
    0u,
    0u,
    0u, 0u,
    1u,
    0u, 0u,
    0u, 0u,
    0u, 1u
};

static const expected_work_row_t EXPECTED_WORK[] = {
    {0u, 0u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {0u, 1u, 1u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {8u, 1u, 0u, NINLIL_MODEL_TIE_ZERO_NONZERO_GENERATION},
    {5u, 2u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {6u, 2u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {7u, 2u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION},
    {9u, 2u, 0u, NINLIL_MODEL_TIE_OPTIONAL_ID_ATTEMPT_INDEX},
    {4u, 2u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION},
    {8u, 2u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION},
    {9u, 3u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION},
    {8u, 3u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION},
    {9u, 4u, 0u, NINLIL_MODEL_TIE_ZERO_ATTEMPT_INDEX},
    {9u, 4u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION},
    {3u, 4u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {3u, 4u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_EVIDENCE_STAGE},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_DISPOSITION},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_CANCEL_RESULT},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_RETENTION_KIND},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO}
};

static const ninlil_model_target_policy_t EXPECTED_TARGET_POLICY[] = {
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_REQUIRED,
    NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE,
    NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE,
    NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE,
    NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE
};

static int bytes_are_zero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void make_id_nonzero(ninlil_model_tie_id_t *id, uint8_t value)
{
    (void)memset(id, 0, sizeof(*id));
    id->bytes[15] = value;
}

static ninlil_model_candidate_spec_t make_valid_spec(
    ninlil_model_work_kind_t work_kind)
{
    ninlil_model_candidate_spec_t spec;
    ninlil_model_work_contract_t contract;
    uint8_t priority = 0u;

    (void)memset(&spec, 0, sizeof(spec));
    (void)ninlil_model_work_contract(work_kind, &contract);

    spec.work_kind = work_kind;
    spec.input_kind = NINLIL_MODEL_INPUT_NONE;
    spec.semantic_priority = contract.semantic_priority;
    spec.work_class = contract.work_class;
    spec.target_presence = NINLIL_MODEL_TARGET_NONE;
    spec.current_epoch.bytes[15] = 0xa5u;
    spec.candidate_epoch = spec.current_epoch;
    spec.logical_time_ms = 100u;
    spec.durable_input_sequence = NINLIL_MODEL_INTERNAL_SEQUENCE;

    if (contract.target_policy == NINLIL_MODEL_TARGET_REQUIRED) {
        spec.target_presence = NINLIL_MODEL_TARGET_PRESENT;
        spec.target_identity_record.bytes[0] = 1u;
    }

    if (work_kind == NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT) {
        spec.input_kind = NINLIL_MODEL_INPUT_VALID_RECEIPT;
        (void)ninlil_model_input_priority(spec.input_kind, &priority);
        spec.semantic_priority = priority;
        spec.durable_input_sequence = 1u;
    }

    switch (contract.tie_contract) {
    case NINLIL_MODEL_TIE_ZERO_ZERO:
        break;
    case NINLIL_MODEL_TIE_ZERO_NONZERO_GENERATION:
        spec.tie_generation = 1u;
        break;
    case NINLIL_MODEL_TIE_OPTIONAL_ID_ATTEMPT_INDEX:
        spec.tie_generation = 1u;
        break;
    case NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION:
        make_id_nonzero(&spec.tie_identity, 1u);
        break;
    case NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION:
        make_id_nonzero(&spec.tie_identity, 1u);
        spec.tie_generation = 1u;
        break;
    case NINLIL_MODEL_TIE_REQUIRED_ID_EVIDENCE_STAGE:
        make_id_nonzero(&spec.tie_identity, 1u);
        spec.tie_generation = (uint64_t)NINLIL_EVIDENCE_RECEIVED;
        break;
    case NINLIL_MODEL_TIE_REQUIRED_ID_DISPOSITION:
        make_id_nonzero(&spec.tie_identity, 1u);
        spec.tie_generation = (uint64_t)NINLIL_DISPOSITION_RETRY_LATER;
        break;
    case NINLIL_MODEL_TIE_REQUIRED_ID_CANCEL_RESULT:
        make_id_nonzero(&spec.tie_identity, 1u);
        spec.tie_generation = 1u;
        break;
    case NINLIL_MODEL_TIE_ZERO_RETENTION_KIND:
        spec.tie_generation = 1u;
        break;
    case NINLIL_MODEL_TIE_ZERO_ATTEMPT_INDEX:
        spec.tie_generation = 1u;
        break;
    default:
        break;
    }

    return spec;
}

static int build_ready(
    const ninlil_model_candidate_spec_t *spec,
    ninlil_model_candidate_key_t *out_key)
{
    ninlil_model_candidate_disposition_t disposition;

    if (ninlil_model_build_candidate(spec, &disposition, out_key) != NINLIL_OK) {
        return 0;
    }
    return disposition == NINLIL_MODEL_CANDIDATE_CURRENT_READY;
}

static int expect_invalid(const ninlil_model_candidate_spec_t *spec)
{
    ninlil_model_candidate_disposition_t disposition =
        NINLIL_MODEL_CANDIDATE_CURRENT_READY;
    ninlil_model_candidate_key_t key;

    (void)memset(&key, 0x5a, sizeof(key));
    if (ninlil_model_build_candidate(spec, &disposition, &key)
        != NINLIL_E_INVALID_ARGUMENT) {
        return 0;
    }
    return disposition == NINLIL_MODEL_CANDIDATE_INVALID
        && bytes_are_zero(key.bytes, sizeof(key.bytes));
}

static int test_closed_tables_and_all_work_kinds(void)
{
    uint32_t kind;
    uint8_t priority = 99u;
    uint8_t is_eligible = 99u;
    ninlil_model_work_contract_t contract;

    REQUIRE(ARRAY_COUNT(EXPECTED_INPUT_PRIORITIES) == 26u);
    REQUIRE(ARRAY_COUNT(EXPECTED_DURABLE_RING_INPUTS) == 26u);
    for (kind = 1u; kind <= 25u; ++kind) {
        ninlil_model_candidate_spec_t spec =
            make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
        ninlil_model_candidate_key_t key;

        REQUIRE(ninlil_model_input_priority(
                    (ninlil_model_input_kind_t)kind,
                    &priority) == NINLIL_OK);
        REQUIRE(priority == EXPECTED_INPUT_PRIORITIES[kind]);
        REQUIRE(ninlil_model_input_is_durable_ring_candidate(
                    (ninlil_model_input_kind_t)kind,
                    &is_eligible) == NINLIL_OK);
        REQUIRE(is_eligible == EXPECTED_DURABLE_RING_INPUTS[kind]);
        spec.input_kind = (ninlil_model_input_kind_t)kind;
        spec.semantic_priority = priority;
        spec.durable_input_sequence = (uint64_t)kind;
        if (is_eligible != 0u) {
            REQUIRE(build_ready(&spec, &key));
        } else {
            REQUIRE(expect_invalid(&spec));
        }
    }
    priority = 99u;
    REQUIRE(ninlil_model_input_priority(NINLIL_MODEL_INPUT_NONE, &priority)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(priority == 0u);
    REQUIRE(ninlil_model_input_priority(
                (ninlil_model_input_kind_t)26,
                &priority) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_input_priority(
                NINLIL_MODEL_INPUT_VALID_RECEIPT,
                NULL) == NINLIL_E_INVALID_ARGUMENT);
    is_eligible = 99u;
    REQUIRE(ninlil_model_input_is_durable_ring_candidate(
                NINLIL_MODEL_INPUT_NONE,
                &is_eligible) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(is_eligible == 0u);
    REQUIRE(ninlil_model_input_is_durable_ring_candidate(
                (ninlil_model_input_kind_t)26,
                &is_eligible) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_input_is_durable_ring_candidate(
                NINLIL_MODEL_INPUT_VALID_RECEIPT,
                NULL) == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ARRAY_COUNT(EXPECTED_WORK) == 23u);
    REQUIRE(ARRAY_COUNT(EXPECTED_TARGET_POLICY) == 23u);
    for (kind = 1u; kind <= 22u; ++kind) {
        ninlil_model_candidate_spec_t spec =
            make_valid_spec((ninlil_model_work_kind_t)kind);
        ninlil_model_candidate_key_t key;

        REQUIRE(ninlil_model_work_contract(
                    (ninlil_model_work_kind_t)kind,
                    &contract) == NINLIL_OK);
        REQUIRE(contract.semantic_priority == EXPECTED_WORK[kind].priority);
        REQUIRE(contract.work_class == EXPECTED_WORK[kind].work_class);
        REQUIRE(contract.priority_is_dynamic == EXPECTED_WORK[kind].dynamic);
        REQUIRE(contract.reserved_zero == 0u);
        REQUIRE(contract.tie_contract == EXPECTED_WORK[kind].tie_contract);
        REQUIRE(contract.target_policy == EXPECTED_TARGET_POLICY[kind]);
        REQUIRE(build_ready(&spec, &key));
    }

    (void)memset(&contract, 0x5a, sizeof(contract));
    REQUIRE(ninlil_model_work_contract(
                (ninlil_model_work_kind_t)0,
                &contract) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero((const uint8_t *)&contract, sizeof(contract)));
    REQUIRE(ninlil_model_work_contract(
                (ninlil_model_work_kind_t)23,
                &contract) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_work_contract(
                NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT,
                NULL) == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_exact_key_encoding(void)
{
    ninlil_model_candidate_spec_t spec =
        make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    ninlil_model_candidate_key_t key;
    uint32_t index;
    static const uint8_t expected_time[] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u
    };
    static const uint8_t expected_sequence[] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
    };

    spec.logical_time_ms = UINT64_C(0x0102030405060708);
    spec.target_presence = NINLIL_MODEL_TARGET_PRESENT;
    for (index = 0u; index < NINLIL_MODEL_TARGET_RECORD_BYTES; ++index) {
        spec.target_identity_record.bytes[index] = (uint8_t)(index + 1u);
    }

    REQUIRE(build_ready(&spec, &key));
    REQUIRE(sizeof(key.bytes) == NINLIL_MODEL_CANDIDATE_KEY_BYTES);
    REQUIRE(memcmp(
                &key.bytes[NINLIL_MODEL_KEY_TIME_OFFSET],
                expected_time,
                sizeof(expected_time)) == 0);
    REQUIRE(key.bytes[NINLIL_MODEL_KEY_PRIORITY_OFFSET] == 5u);
    REQUIRE(key.bytes[NINLIL_MODEL_KEY_CLASS_OFFSET] == 2u);
    REQUIRE(memcmp(
                &key.bytes[NINLIL_MODEL_KEY_SEQUENCE_OFFSET],
                expected_sequence,
                sizeof(expected_sequence)) == 0);
    REQUIRE(memcmp(
                &key.bytes[NINLIL_MODEL_KEY_TARGET_OFFSET],
                spec.target_identity_record.bytes,
                sizeof(spec.target_identity_record.bytes)) == 0);
    REQUIRE(key.bytes[NINLIL_MODEL_KEY_WORK_KIND_OFFSET] == 0u);
    REQUIRE(key.bytes[NINLIL_MODEL_KEY_WORK_KIND_OFFSET + 1u] == 0u);
    REQUIRE(key.bytes[NINLIL_MODEL_KEY_WORK_KIND_OFFSET + 2u] == 0u);
    REQUIRE(key.bytes[NINLIL_MODEL_KEY_WORK_KIND_OFFSET + 3u] == 3u);
    REQUIRE(bytes_are_zero(
        &key.bytes[NINLIL_MODEL_KEY_TIE_ID_OFFSET],
        NINLIL_MODEL_TIE_ID_BYTES + sizeof(uint64_t)));
    return 0;
}

static int test_fail_closed_contract_validation(void)
{
    uint32_t kind;
    ninlil_model_candidate_spec_t spec =
        make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    ninlil_model_candidate_disposition_t disposition;
    ninlil_model_candidate_key_t key;

    spec.work_kind = (ninlil_model_work_kind_t)0;
    REQUIRE(expect_invalid(&spec));
    spec.work_kind = (ninlil_model_work_kind_t)23;
    REQUIRE(expect_invalid(&spec));

    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_NONE;
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = (ninlil_model_input_kind_t)26;
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.durable_input_sequence = 0u;
    REQUIRE(expect_invalid(&spec));
    spec.durable_input_sequence = NINLIL_MODEL_INTERNAL_SEQUENCE;
    REQUIRE(expect_invalid(&spec));

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.durable_input_sequence = 0u;
    REQUIRE(expect_invalid(&spec));
    spec.durable_input_sequence = 1u;
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.input_kind = NINLIL_MODEL_INPUT_EFFECT_DEADLINE;
    REQUIRE(expect_invalid(&spec));

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    (void)memset(&spec.current_epoch, 0, sizeof(spec.current_epoch));
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    (void)memset(&spec.candidate_epoch, 0, sizeof(spec.candidate_epoch));
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.target_presence = (ninlil_model_target_presence_t)2;
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.target_presence = NINLIL_MODEL_TARGET_NONE;
    spec.target_identity_record.bytes[0] = 1u;
    REQUIRE(expect_invalid(&spec));
    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.target_presence = NINLIL_MODEL_TARGET_PRESENT;
    (void)memset(
        &spec.target_identity_record,
        0,
        sizeof(spec.target_identity_record));
    REQUIRE(expect_invalid(&spec));

    for (kind = 1u; kind <= 22u; ++kind) {
        ninlil_model_work_contract_t contract;

        spec = make_valid_spec((ninlil_model_work_kind_t)kind);
        spec.semantic_priority = (uint8_t)(spec.semantic_priority == 10u
            ? 9u
            : spec.semantic_priority + 1u);
        REQUIRE(expect_invalid(&spec));

        spec = make_valid_spec((ninlil_model_work_kind_t)kind);
        spec.work_class = (uint8_t)(spec.work_class == 6u
            ? 5u
            : spec.work_class + 1u);
        REQUIRE(expect_invalid(&spec));

        REQUIRE(ninlil_model_work_contract(
                    (ninlil_model_work_kind_t)kind,
                    &contract) == NINLIL_OK);
        spec = make_valid_spec((ninlil_model_work_kind_t)kind);
        switch (contract.tie_contract) {
        case NINLIL_MODEL_TIE_ZERO_ZERO:
            spec.tie_generation = 1u;
            break;
        case NINLIL_MODEL_TIE_ZERO_NONZERO_GENERATION:
        case NINLIL_MODEL_TIE_OPTIONAL_ID_ATTEMPT_INDEX:
        case NINLIL_MODEL_TIE_ZERO_ATTEMPT_INDEX:
            spec.tie_generation = 0u;
            break;
        case NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION:
        case NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION:
            (void)memset(&spec.tie_identity, 0, sizeof(spec.tie_identity));
            break;
        case NINLIL_MODEL_TIE_REQUIRED_ID_EVIDENCE_STAGE:
            spec.tie_generation = 5u;
            break;
        case NINLIL_MODEL_TIE_REQUIRED_ID_DISPOSITION:
            spec.tie_generation = 11u;
            break;
        case NINLIL_MODEL_TIE_REQUIRED_ID_CANCEL_RESULT:
            spec.tie_generation = 5u;
            break;
        case NINLIL_MODEL_TIE_ZERO_RETENTION_KIND:
            spec.tie_generation = 4u;
            break;
        default:
            REQUIRE(0);
        }
        REQUIRE(expect_invalid(&spec));
    }

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    REQUIRE(ninlil_model_build_candidate(NULL, &disposition, &key)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_build_candidate(&spec, NULL, &key)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_build_candidate(&spec, &disposition, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_closed_target_policy(void)
{
    uint32_t kind;

    for (kind = 1u; kind <= 22u; ++kind) {
        ninlil_model_candidate_spec_t spec =
            make_valid_spec((ninlil_model_work_kind_t)kind);
        ninlil_model_candidate_key_t key;

        spec.target_presence = NINLIL_MODEL_TARGET_NONE;
        (void)memset(
            &spec.target_identity_record,
            0,
            sizeof(spec.target_identity_record));
        if (kind <= 18u) {
            REQUIRE(expect_invalid(&spec));
        } else {
            REQUIRE(build_ready(&spec, &key));
        }

        spec.target_presence = NINLIL_MODEL_TARGET_PRESENT;
        spec.target_identity_record.bytes[0] = (uint8_t)kind;
        REQUIRE(build_ready(&spec, &key));

        (void)memset(
            &spec.target_identity_record,
            0,
            sizeof(spec.target_identity_record));
        REQUIRE(expect_invalid(&spec));

        spec.target_presence = NINLIL_MODEL_TARGET_NONE;
        spec.target_identity_record.bytes[0] = (uint8_t)kind;
        REQUIRE(expect_invalid(&spec));
    }
    return 0;
}

static int test_tuple_comparison_fields(void)
{
    ninlil_model_candidate_spec_t left;
    ninlil_model_candidate_spec_t right;
    ninlil_model_candidate_key_t left_key;
    ninlil_model_candidate_key_t right_key;

    left = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    right = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    left.logical_time_ms = 100u;
    right.logical_time_ms = 101u;
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);
    REQUIRE(ninlil_model_candidate_key_compare(&right_key, &left_key) > 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    right = left;
    left.input_kind = NINLIL_MODEL_INPUT_VALID_RECEIPT;
    left.semantic_priority = 1u;
    right.input_kind = NINLIL_MODEL_INPUT_LOCAL_CANCEL_REQUEST;
    right.semantic_priority = 3u;
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_AVAILABILITY_CONSUME);
    right = make_valid_spec(NINLIL_MODEL_WORK_RECONCILE_DUE);
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    right = left;
    left.durable_input_sequence = 7u;
    right.durable_input_sequence = 8u;
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    right = left;
    left.target_presence = NINLIL_MODEL_TARGET_PRESENT;
    right.target_presence = NINLIL_MODEL_TARGET_PRESENT;
    left.target_identity_record.bytes[99] = 0x7fu;
    right.target_identity_record.bytes[99] = 0x80u;
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_APPLICATION_ATTEMPT_PREPARE);
    right = make_valid_spec(NINLIL_MODEL_WORK_APPLICATION_SEND);
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_APPLICATION_SEND);
    right = left;
    make_id_nonzero(&left.tie_identity, 0x7fu);
    make_id_nonzero(&right.tie_identity, 0x80u);
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);

    left = make_valid_spec(NINLIL_MODEL_WORK_DELIVERY_TOKEN_TIMEOUT);
    right = left;
    left.tie_generation = 1u;
    right.tie_generation = 2u;
    REQUIRE(build_ready(&left, &left_key));
    REQUIRE(build_ready(&right, &right_key));
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &right_key) < 0);
    REQUIRE(ninlil_model_candidate_key_compare(&left_key, &left_key) == 0);
    return 0;
}

static int test_same_time_and_chronological_examples(void)
{
    ninlil_model_candidate_spec_t spec;
    ninlil_model_candidate_key_t candidates[7];
    ninlil_model_candidate_key_t expected[7];
    uint32_t index;

    spec = make_valid_spec(NINLIL_MODEL_WORK_INTERNAL_RETRY_DUE);
    REQUIRE(build_ready(&spec, &candidates[0]));
    expected[6] = candidates[0];

    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_EVENT_RESUME_REQUEST;
    spec.semantic_priority = 8u;
    spec.durable_input_sequence = 2u;
    REQUIRE(build_ready(&spec, &candidates[1]));
    expected[5] = candidates[1];

    spec = make_valid_spec(NINLIL_MODEL_WORK_ATTEMPT_RECEIPT_TIMEOUT);
    REQUIRE(build_ready(&spec, &candidates[2]));
    expected[4] = candidates[2];

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    REQUIRE(build_ready(&spec, &candidates[3]));
    expected[3] = candidates[3];

    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_LOCAL_CANCEL_REQUEST;
    spec.semantic_priority = 3u;
    spec.durable_input_sequence = 3u;
    REQUIRE(build_ready(&spec, &candidates[4]));
    expected[2] = candidates[4];

    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_DELIVERY_DISPOSITION;
    spec.semantic_priority = 2u;
    spec.durable_input_sequence = 4u;
    REQUIRE(build_ready(&spec, &candidates[5]));
    expected[1] = candidates[5];

    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_VALID_RECEIPT;
    spec.semantic_priority = 1u;
    spec.durable_input_sequence = 5u;
    REQUIRE(build_ready(&spec, &candidates[6]));
    expected[0] = candidates[6];

    qsort(
        candidates,
        ARRAY_COUNT(candidates),
        sizeof(candidates[0]),
        ninlil_model_candidate_key_qsort_compare);
    for (index = 0u; index < ARRAY_COUNT(candidates); ++index) {
        REQUIRE(ninlil_model_candidate_key_compare(
                    &candidates[index],
                    &expected[index]) == 0);
    }

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.logical_time_ms = 100u;
    REQUIRE(build_ready(&spec, &candidates[0]));
    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_VALID_RECEIPT;
    spec.semantic_priority = 1u;
    spec.logical_time_ms = 101u;
    REQUIRE(build_ready(&spec, &candidates[1]));
    REQUIRE(ninlil_model_candidate_key_compare(&candidates[0], &candidates[1]) < 0);

    spec = make_valid_spec(NINLIL_MODEL_WORK_ATTEMPT_RECEIPT_TIMEOUT);
    spec.logical_time_ms = 100u;
    REQUIRE(build_ready(&spec, &candidates[0]));
    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.input_kind = NINLIL_MODEL_INPUT_EVENT_RESUME_REQUEST;
    spec.semantic_priority = 8u;
    spec.logical_time_ms = 101u;
    REQUIRE(build_ready(&spec, &candidates[1]));
    REQUIRE(ninlil_model_candidate_key_compare(&candidates[0], &candidates[1]) < 0);
    return 0;
}

static uint32_t permutation_index(uint32_t order, uint32_t index)
{
    switch (order) {
    case 0u:
        return index;
    case 1u:
        return 21u - index;
    case 2u:
        return (index + 7u) % 22u;
    default:
        return index < 11u ? index * 2u : ((index - 11u) * 2u) + 1u;
    }
}

static int test_four_insertion_orders_are_stable(void)
{
    ninlil_model_candidate_key_t source[22];
    ninlil_model_candidate_key_t baseline[22];
    ninlil_model_candidate_key_t trial[22];
    uint32_t kind;
    uint32_t order;
    uint32_t index;

    for (kind = 1u; kind <= 22u; ++kind) {
        ninlil_model_candidate_spec_t spec =
            make_valid_spec((ninlil_model_work_kind_t)kind);

        spec.logical_time_ms = 100u + (uint64_t)(kind % 3u);
        spec.target_presence = NINLIL_MODEL_TARGET_PRESENT;
        spec.target_identity_record.bytes[0] = (uint8_t)(23u - kind);
        REQUIRE(build_ready(&spec, &source[kind - 1u]));
    }

    (void)memcpy(baseline, source, sizeof(baseline));
    qsort(
        baseline,
        ARRAY_COUNT(baseline),
        sizeof(baseline[0]),
        ninlil_model_candidate_key_qsort_compare);

    for (order = 0u; order < 4u; ++order) {
        for (index = 0u; index < 22u; ++index) {
            trial[index] = source[permutation_index(order, index)];
        }
        qsort(
            trial,
            ARRAY_COUNT(trial),
            sizeof(trial[0]),
            ninlil_model_candidate_key_qsort_compare);
        REQUIRE(memcmp(trial, baseline, sizeof(trial)) == 0);
    }
    return 0;
}

static int test_epoch_fence_and_recovery_sequence(void)
{
    ninlil_model_candidate_spec_t spec;
    ninlil_model_candidate_disposition_t disposition;
    ninlil_model_candidate_key_t key;
    int comparison = 99;

    spec = make_valid_spec(NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT);
    spec.durable_input_sequence = 7u;
    spec.candidate_epoch.bytes[15] = 0xa6u;
    REQUIRE(ninlil_model_build_candidate(&spec, &disposition, &key) == NINLIL_OK);
    REQUIRE(disposition == NINLIL_MODEL_CANDIDATE_RECOVERY_FENCE);
    REQUIRE(bytes_are_zero(key.bytes, sizeof(key.bytes)));

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    spec.candidate_epoch.bytes[15] = 0xa6u;
    REQUIRE(ninlil_model_build_candidate(&spec, &disposition, &key) == NINLIL_OK);
    REQUIRE(disposition == NINLIL_MODEL_CANDIDATE_SUPPRESSED_OLD_EPOCH);
    REQUIRE(bytes_are_zero(key.bytes, sizeof(key.bytes)));

    spec = make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    (void)memset(&spec.current_epoch, 0, sizeof(spec.current_epoch));
    (void)memset(&spec.candidate_epoch, 0, sizeof(spec.candidate_epoch));
    spec.current_epoch.bytes[0] = 0xffu;
    spec.candidate_epoch.bytes[0] = 0x01u;
    REQUIRE(ninlil_model_build_candidate(&spec, &disposition, &key) == NINLIL_OK);
    REQUIRE(disposition == NINLIL_MODEL_CANDIDATE_SUPPRESSED_OLD_EPOCH);

    spec.semantic_priority = 4u;
    REQUIRE(expect_invalid(&spec));

    REQUIRE(ninlil_model_recovery_fence_sequence_compare(7u, 8u, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison < 0);
    REQUIRE(ninlil_model_recovery_fence_sequence_compare(8u, 7u, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison > 0);
    REQUIRE(ninlil_model_recovery_fence_sequence_compare(7u, 7u, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison == 0);
    REQUIRE(ninlil_model_recovery_fence_sequence_compare(0u, 7u, &comparison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_recovery_fence_sequence_compare(
                NINLIL_MODEL_INTERNAL_SEQUENCE,
                7u,
                &comparison) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_recovery_fence_sequence_compare(7u, 8u, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_absence_sentinel(void)
{
    ninlil_model_candidate_spec_t spec =
        make_valid_spec(NINLIL_MODEL_WORK_COMMAND_EFFECT_DEADLINE);
    ninlil_model_optional_candidate_t absent;
    ninlil_model_optional_candidate_t present;
    int comparison = 99;

    (void)memset(&absent, 0, sizeof(absent));
    (void)memset(&present, 0, sizeof(present));
    absent.presence = NINLIL_MODEL_CANDIDATE_ABSENT;
    present.presence = NINLIL_MODEL_CANDIDATE_PRESENT;
    REQUIRE(build_ready(&spec, &present.key));

    REQUIRE(ninlil_model_optional_candidate_compare(&absent, &absent, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison == 0);
    REQUIRE(ninlil_model_optional_candidate_compare(&present, &absent, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison < 0);
    REQUIRE(ninlil_model_optional_candidate_compare(&absent, &present, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison > 0);
    REQUIRE(ninlil_model_optional_candidate_compare(&present, &present, &comparison)
        == NINLIL_OK);
    REQUIRE(comparison == 0);

    absent.key.bytes[0] = 1u;
    REQUIRE(ninlil_model_optional_candidate_compare(&absent, &present, &comparison)
        == NINLIL_E_INVALID_ARGUMENT);
    absent.key.bytes[0] = 0u;
    absent.presence = (ninlil_model_optional_presence_t)2;
    REQUIRE(ninlil_model_optional_candidate_compare(&absent, &present, &comparison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_optional_candidate_compare(NULL, &present, &comparison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_optional_candidate_compare(&present, &absent, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

int main(void)
{
    int failed = 0;

    failed |= test_closed_tables_and_all_work_kinds();
    failed |= test_exact_key_encoding();
    failed |= test_fail_closed_contract_validation();
    failed |= test_closed_target_policy();
    failed |= test_tuple_comparison_fields();
    failed |= test_same_time_and_chronological_examples();
    failed |= test_four_insertion_orders_are_stable();
    failed |= test_epoch_fence_and_recovery_sequence();
    failed |= test_absence_sentinel();

    if (failed == 0) {
        (void)puts("scheduler candidate model tests passed");
    }
    return failed;
}
