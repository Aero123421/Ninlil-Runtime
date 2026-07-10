#include "scheduler_candidate.h"

#include <stddef.h>
#include <string.h>

typedef struct work_row {
    uint8_t semantic_priority;
    uint8_t work_class;
    uint8_t priority_is_dynamic;
    ninlil_model_tie_contract_t tie_contract;
    ninlil_model_target_policy_t target_policy;
} work_row_t;

static const uint8_t INPUT_PRIORITIES[] = {
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

/*
 * Kind 1 is narrower than the semantic reducer input catalog. It contains only
 * Bearer ingress and public management mutations that consume the namespace
 * ordered-input sequence. Barrier, timer, callback, send-observation, and
 * other inline reducer inputs are represented by their owning work/stage.
 */
static const uint8_t DURABLE_RING_INPUTS[] = {
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

static const work_row_t WORK_ROWS[] = {
    {0u, 0u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_REQUIRED},
    {0u, 1u, 1u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_REQUIRED},
    {8u, 1u, 0u, NINLIL_MODEL_TIE_ZERO_NONZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {5u, 2u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_REQUIRED},
    {6u, 2u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_REQUIRED},
    {7u, 2u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {9u, 2u, 0u, NINLIL_MODEL_TIE_OPTIONAL_ID_ATTEMPT_INDEX, NINLIL_MODEL_TARGET_REQUIRED},
    {4u, 2u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {8u, 2u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {9u, 3u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {8u, 3u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {9u, 4u, 0u, NINLIL_MODEL_TIE_ZERO_ATTEMPT_INDEX, NINLIL_MODEL_TARGET_REQUIRED},
    {9u, 4u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {3u, 4u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_REQUIRED},
    {3u, 4u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_EVIDENCE_STAGE, NINLIL_MODEL_TARGET_REQUIRED},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_DISPOSITION, NINLIL_MODEL_TARGET_REQUIRED},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION, NINLIL_MODEL_TARGET_REQUIRED},
    {10u, 5u, 0u, NINLIL_MODEL_TIE_REQUIRED_ID_CANCEL_RESULT, NINLIL_MODEL_TARGET_REQUIRED},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_RETENTION_KIND, NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE},
    {10u, 6u, 0u, NINLIL_MODEL_TIE_ZERO_ZERO, NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE}
};

_Static_assert(
    sizeof(ninlil_model_epoch_id_t) == NINLIL_MODEL_EPOCH_BYTES,
    "scheduler epoch ID must remain exactly 16 bytes");
_Static_assert(
    sizeof(ninlil_model_target_record_t) == NINLIL_MODEL_TARGET_RECORD_BYTES,
    "scheduler target record must remain exactly 100 bytes");
_Static_assert(
    sizeof(ninlil_model_tie_id_t) == NINLIL_MODEL_TIE_ID_BYTES,
    "scheduler tie ID must remain exactly 16 bytes");
_Static_assert(
    sizeof(ninlil_model_candidate_key_t) == NINLIL_MODEL_CANDIDATE_KEY_BYTES,
    "scheduler candidate key must remain exactly 146 bytes");
_Static_assert(
    sizeof(INPUT_PRIORITIES) / sizeof(INPUT_PRIORITIES[0]) == 26u,
    "input priority table must cover the closed input set");
_Static_assert(
    sizeof(DURABLE_RING_INPUTS) / sizeof(DURABLE_RING_INPUTS[0]) == 26u,
    "durable ring classification must cover the closed input set");
_Static_assert(
    sizeof(WORK_ROWS) / sizeof(WORK_ROWS[0]) == 23u,
    "work contract table must cover the closed work set");

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

static int epoch_is_valid(const ninlil_model_epoch_id_t *epoch)
{
    return !bytes_are_zero(epoch->bytes, sizeof(epoch->bytes));
}

static int tie_id_is_zero(const ninlil_model_tie_id_t *tie_id)
{
    return bytes_are_zero(tie_id->bytes, sizeof(tie_id->bytes));
}

static int tie_is_valid(
    ninlil_model_tie_contract_t contract,
    const ninlil_model_tie_id_t *tie_id,
    uint64_t generation)
{
    const int id_is_zero = tie_id_is_zero(tie_id);

    switch (contract) {
    case NINLIL_MODEL_TIE_ZERO_ZERO:
        return id_is_zero && generation == 0u;
    case NINLIL_MODEL_TIE_ZERO_NONZERO_GENERATION:
        return id_is_zero && generation != 0u;
    case NINLIL_MODEL_TIE_OPTIONAL_ID_ATTEMPT_INDEX:
        return generation >= 1u
            && generation <= (uint64_t)NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    case NINLIL_MODEL_TIE_REQUIRED_ID_ZERO_GENERATION:
        return !id_is_zero && generation == 0u;
    case NINLIL_MODEL_TIE_REQUIRED_ID_NONZERO_GENERATION:
        return !id_is_zero && generation != 0u;
    case NINLIL_MODEL_TIE_REQUIRED_ID_EVIDENCE_STAGE:
        return !id_is_zero
            && generation >= (uint64_t)NINLIL_EVIDENCE_RECEIVED
            && generation <= (uint64_t)NINLIL_EVIDENCE_VERIFIED;
    case NINLIL_MODEL_TIE_REQUIRED_ID_DISPOSITION:
        return !id_is_zero
            && generation >= (uint64_t)NINLIL_DISPOSITION_RETRY_LATER
            && generation <= (uint64_t)NINLIL_DISPOSITION_OUTCOME_UNKNOWN;
    case NINLIL_MODEL_TIE_REQUIRED_ID_CANCEL_RESULT:
        return !id_is_zero && generation >= 1u && generation <= 4u;
    case NINLIL_MODEL_TIE_ZERO_RETENTION_KIND:
        return id_is_zero && generation >= 1u && generation <= 3u;
    case NINLIL_MODEL_TIE_ZERO_ATTEMPT_INDEX:
        return id_is_zero
            && generation >= 1u
            && generation <= (uint64_t)NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    default:
        return 0;
    }
}

static void encode_u32_be(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value >> 24u);
    destination[1] = (uint8_t)(value >> 16u);
    destination[2] = (uint8_t)(value >> 8u);
    destination[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t *destination, uint64_t value)
{
    destination[0] = (uint8_t)(value >> 56u);
    destination[1] = (uint8_t)(value >> 48u);
    destination[2] = (uint8_t)(value >> 40u);
    destination[3] = (uint8_t)(value >> 32u);
    destination[4] = (uint8_t)(value >> 24u);
    destination[5] = (uint8_t)(value >> 16u);
    destination[6] = (uint8_t)(value >> 8u);
    destination[7] = (uint8_t)value;
}

ninlil_status_t ninlil_model_input_priority(
    ninlil_model_input_kind_t input_kind,
    uint8_t *out_priority)
{
    const uint32_t kind = (uint32_t)input_kind;

    if (out_priority == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_priority = 0u;

    if (kind < (uint32_t)NINLIL_MODEL_INPUT_RECOVERY_FENCE
        || kind > (uint32_t)NINLIL_MODEL_INPUT_CUSTODY_ACCEPTED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    *out_priority = INPUT_PRIORITIES[kind];
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_input_is_durable_ring_candidate(
    ninlil_model_input_kind_t input_kind,
    uint8_t *out_is_eligible)
{
    const uint32_t kind = (uint32_t)input_kind;

    if (out_is_eligible == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_is_eligible = 0u;

    if (kind < (uint32_t)NINLIL_MODEL_INPUT_RECOVERY_FENCE
        || kind > (uint32_t)NINLIL_MODEL_INPUT_CUSTODY_ACCEPTED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    *out_is_eligible = DURABLE_RING_INPUTS[kind];
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_work_contract(
    ninlil_model_work_kind_t work_kind,
    ninlil_model_work_contract_t *out_contract)
{
    const uint32_t kind = (uint32_t)work_kind;
    const work_row_t *row;

    if (out_contract == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_contract, 0, sizeof(*out_contract));

    if (kind < (uint32_t)NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT
        || kind > (uint32_t)NINLIL_MODEL_WORK_OBSERVATION_RETENTION_CLEANUP) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    row = &WORK_ROWS[kind];
    out_contract->semantic_priority = row->semantic_priority;
    out_contract->work_class = row->work_class;
    out_contract->priority_is_dynamic = row->priority_is_dynamic;
    out_contract->reserved_zero = 0u;
    out_contract->tie_contract = row->tie_contract;
    out_contract->target_policy = row->target_policy;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_build_candidate(
    const ninlil_model_candidate_spec_t *spec,
    ninlil_model_candidate_disposition_t *out_disposition,
    ninlil_model_candidate_key_t *out_key)
{
    ninlil_model_work_contract_t contract;
    uint8_t expected_priority;
    uint8_t input_is_eligible;
    const int is_input = spec != NULL
        && spec->work_kind == NINLIL_MODEL_WORK_DURABLE_REDUCER_INPUT;

    if (out_disposition == NULL || out_key == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_disposition = NINLIL_MODEL_CANDIDATE_INVALID;
    (void)memset(out_key, 0, sizeof(*out_key));

    if (spec == NULL
        || ninlil_model_work_contract(spec->work_kind, &contract) != NINLIL_OK
        || !epoch_is_valid(&spec->current_epoch)
        || !epoch_is_valid(&spec->candidate_epoch)
        || (spec->target_presence != NINLIL_MODEL_TARGET_NONE
            && spec->target_presence != NINLIL_MODEL_TARGET_PRESENT)
        || (spec->target_presence == NINLIL_MODEL_TARGET_NONE
            && !bytes_are_zero(
                spec->target_identity_record.bytes,
                sizeof(spec->target_identity_record.bytes)))
        || (spec->target_presence == NINLIL_MODEL_TARGET_PRESENT
            && bytes_are_zero(
                spec->target_identity_record.bytes,
                sizeof(spec->target_identity_record.bytes)))
        || (contract.target_policy == NINLIL_MODEL_TARGET_REQUIRED
            && spec->target_presence != NINLIL_MODEL_TARGET_PRESENT)
        || (contract.target_policy != NINLIL_MODEL_TARGET_REQUIRED
            && contract.target_policy
                != NINLIL_MODEL_TARGET_OR_RUNTIME_LOCAL_NONE)
        || spec->work_class != contract.work_class
        || !tie_is_valid(
            contract.tie_contract,
            &spec->tie_identity,
            spec->tie_generation)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (is_input) {
        if (spec->durable_input_sequence == 0u
            || spec->durable_input_sequence == NINLIL_MODEL_INTERNAL_SEQUENCE
            || ninlil_model_input_priority(
                spec->input_kind,
                &expected_priority) != NINLIL_OK
            || ninlil_model_input_is_durable_ring_candidate(
                spec->input_kind,
                &input_is_eligible) != NINLIL_OK
            || input_is_eligible == 0u
            || spec->semantic_priority != expected_priority) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else if (spec->input_kind != NINLIL_MODEL_INPUT_NONE
        || spec->durable_input_sequence != NINLIL_MODEL_INTERNAL_SEQUENCE
        || spec->semantic_priority != contract.semantic_priority) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (memcmp(
            spec->current_epoch.bytes,
            spec->candidate_epoch.bytes,
            sizeof(spec->current_epoch.bytes)) != 0) {
        *out_disposition = is_input
            ? NINLIL_MODEL_CANDIDATE_RECOVERY_FENCE
            : NINLIL_MODEL_CANDIDATE_SUPPRESSED_OLD_EPOCH;
        return NINLIL_OK;
    }

    encode_u64_be(
        &out_key->bytes[NINLIL_MODEL_KEY_TIME_OFFSET],
        spec->logical_time_ms);
    out_key->bytes[NINLIL_MODEL_KEY_PRIORITY_OFFSET] = spec->semantic_priority;
    out_key->bytes[NINLIL_MODEL_KEY_CLASS_OFFSET] = spec->work_class;
    encode_u64_be(
        &out_key->bytes[NINLIL_MODEL_KEY_SEQUENCE_OFFSET],
        spec->durable_input_sequence);
    (void)memcpy(
        &out_key->bytes[NINLIL_MODEL_KEY_TARGET_OFFSET],
        spec->target_identity_record.bytes,
        sizeof(spec->target_identity_record.bytes));
    encode_u32_be(
        &out_key->bytes[NINLIL_MODEL_KEY_WORK_KIND_OFFSET],
        (uint32_t)spec->work_kind);
    (void)memcpy(
        &out_key->bytes[NINLIL_MODEL_KEY_TIE_ID_OFFSET],
        spec->tie_identity.bytes,
        sizeof(spec->tie_identity.bytes));
    encode_u64_be(
        &out_key->bytes[NINLIL_MODEL_KEY_TIE_GENERATION_OFFSET],
        spec->tie_generation);

    *out_disposition = NINLIL_MODEL_CANDIDATE_CURRENT_READY;
    return NINLIL_OK;
}

int ninlil_model_candidate_key_compare(
    const ninlil_model_candidate_key_t *left,
    const ninlil_model_candidate_key_t *right)
{
    const int comparison = memcmp(left->bytes, right->bytes, sizeof(left->bytes));

    if (comparison < 0) {
        return -1;
    }
    if (comparison > 0) {
        return 1;
    }
    return 0;
}

int ninlil_model_candidate_key_qsort_compare(const void *left, const void *right)
{
    return ninlil_model_candidate_key_compare(
        (const ninlil_model_candidate_key_t *)left,
        (const ninlil_model_candidate_key_t *)right);
}

ninlil_status_t ninlil_model_optional_candidate_compare(
    const ninlil_model_optional_candidate_t *left,
    const ninlil_model_optional_candidate_t *right,
    int *out_comparison)
{
    if (out_comparison == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_comparison = 0;

    if (left == NULL || right == NULL
        || (left->presence != NINLIL_MODEL_CANDIDATE_ABSENT
            && left->presence != NINLIL_MODEL_CANDIDATE_PRESENT)
        || (right->presence != NINLIL_MODEL_CANDIDATE_ABSENT
            && right->presence != NINLIL_MODEL_CANDIDATE_PRESENT)
        || (left->presence == NINLIL_MODEL_CANDIDATE_ABSENT
            && !bytes_are_zero(left->key.bytes, sizeof(left->key.bytes)))
        || (right->presence == NINLIL_MODEL_CANDIDATE_ABSENT
            && !bytes_are_zero(right->key.bytes, sizeof(right->key.bytes)))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (left->presence != right->presence) {
        *out_comparison = left->presence == NINLIL_MODEL_CANDIDATE_PRESENT ? -1 : 1;
    } else if (left->presence == NINLIL_MODEL_CANDIDATE_PRESENT) {
        *out_comparison = ninlil_model_candidate_key_compare(&left->key, &right->key);
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_recovery_fence_sequence_compare(
    uint64_t left_sequence,
    uint64_t right_sequence,
    int *out_comparison)
{
    if (out_comparison == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_comparison = 0;

    if (left_sequence == 0u || left_sequence == NINLIL_MODEL_INTERNAL_SEQUENCE
        || right_sequence == 0u
        || right_sequence == NINLIL_MODEL_INTERNAL_SEQUENCE) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (left_sequence < right_sequence) {
        *out_comparison = -1;
    } else if (left_sequence > right_sequence) {
        *out_comparison = 1;
    }
    return NINLIL_OK;
}
