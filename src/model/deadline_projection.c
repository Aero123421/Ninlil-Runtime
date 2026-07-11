#include "deadline_projection.h"

#include <stddef.h>
#include <string.h>

_Static_assert(
    sizeof(ninlil_model_required_receipt_deadline_result_t)
        == sizeof(uint32_t) * 2u,
    "deadline projection result must contain two fixed uint32 values");

static int id_is_zero(const ninlil_id128_t *id)
{
    size_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int semantic_time_is_valid(const ninlil_model_semantic_time_t *time)
{
    return !id_is_zero(&time->clock_epoch_id)
        && (time->trust == NINLIL_CLOCK_TRUSTED
            || time->trust == NINLIL_CLOCK_UNCERTAIN);
}

static int same_epoch(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

ninlil_status_t ninlil_model_project_required_receipt_deadline(
    const ninlil_model_required_receipt_deadline_input_t *input,
    ninlil_model_required_receipt_deadline_result_t *out_result)
{
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    if (input == NULL
        || (input->family != NINLIL_FAMILY_DESIRED_STATE
            && input->family != NINLIL_FAMILY_EVENT_FACT)
        || !semantic_time_is_valid(&input->issuer_evidence_time)
        || !semantic_time_is_valid(&input->controller_ingress_time)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (input->family == NINLIL_FAMILY_EVENT_FACT) {
        if (!id_is_zero(&input->deadline_clock_epoch_id)
            || input->absolute_effect_deadline_ms != NINLIL_NO_DEADLINE) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        out_result->evidence = NINLIL_MODEL_DEADLINE_EVIDENCE_NONE;
        out_result->verdict = NINLIL_DEADLINE_NOT_APPLICABLE;
        return NINLIL_OK;
    }

    if (id_is_zero(&input->deadline_clock_epoch_id)
        || input->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (input->issuer_evidence_time.trust == NINLIL_CLOCK_TRUSTED
        && same_epoch(
            &input->issuer_evidence_time.clock_epoch_id,
            &input->deadline_clock_epoch_id)) {
        if (input->issuer_evidence_time.now_ms
            <= input->absolute_effect_deadline_ms) {
            out_result->evidence =
                NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME;
            out_result->verdict = NINLIL_DEADLINE_MET;
        } else {
            out_result->evidence =
                NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE;
            out_result->verdict = NINLIL_DEADLINE_MISSED;
        }
        return NINLIL_OK;
    }

    if (input->controller_ingress_time.trust == NINLIL_CLOCK_TRUSTED
        && same_epoch(
            &input->controller_ingress_time.clock_epoch_id,
            &input->deadline_clock_epoch_id)
        && input->controller_ingress_time.now_ms
            <= input->absolute_effect_deadline_ms) {
        out_result->evidence =
            NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME;
        out_result->verdict = NINLIL_DEADLINE_MET;
        return NINLIL_OK;
    }

    out_result->evidence = NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN;
    out_result->verdict = NINLIL_DEADLINE_INDETERMINATE;
    return NINLIL_OK;
}
