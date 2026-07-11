#ifndef NINLIL_MODEL_DEADLINE_PROJECTION_H
#define NINLIL_MODEL_DEADLINE_PROJECTION_H

#include <stdint.h>

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ninlil_model_deadline_evidence_t;

#define NINLIL_MODEL_DEADLINE_EVIDENCE_NONE \
    ((ninlil_model_deadline_evidence_t)0u)
#define NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_IN_TIME \
    ((ninlil_model_deadline_evidence_t)1u)
#define NINLIL_MODEL_DEADLINE_EVIDENCE_PROVEN_LATE \
    ((ninlil_model_deadline_evidence_t)2u)
#define NINLIL_MODEL_DEADLINE_EVIDENCE_TIME_UNKNOWN \
    ((ninlil_model_deadline_evidence_t)3u)

/* Validated semantic value: no ABI header and no Port status. */
typedef struct ninlil_model_semantic_time {
    ninlil_id128_t clock_epoch_id;
    uint64_t now_ms;
    ninlil_clock_trust_t trust;
} ninlil_model_semantic_time_t;

/*
 * The caller has already validated Receipt identity/binding and established
 * that its evidence stage reaches the transaction's required stage.
 */
typedef struct ninlil_model_required_receipt_deadline_input {
    ninlil_family_t family;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    ninlil_model_semantic_time_t issuer_evidence_time;
    ninlil_model_semantic_time_t controller_ingress_time;
} ninlil_model_required_receipt_deadline_input_t;

typedef struct ninlil_model_required_receipt_deadline_result {
    ninlil_model_deadline_evidence_t evidence;
    ninlil_deadline_verdict_t verdict;
} ninlil_model_required_receipt_deadline_result_t;

ninlil_status_t ninlil_model_project_required_receipt_deadline(
    const ninlil_model_required_receipt_deadline_input_t *input,
    ninlil_model_required_receipt_deadline_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
