#ifndef NINLIL_RUNTIME_V1_TARGET_RESOLVER_H
#define NINLIL_RUNTIME_V1_TARGET_RESOLVER_H

/*
 * V1-LAB B5: concrete target roster resolution and deterministic aggregate.
 * Not public ABI.
 */

#include "runtime_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_rt_target_resolve_result {
    uint32_t target_count;
    ninlil_rt_target_slot_t targets[NINLIL_RT_V1_MAX_TARGETS_PER_TXN];
    ninlil_reason_t reject_reason;
} ninlil_rt_target_resolve_result_t;

ninlil_status_t ninlil_rt_v1_resolve_submission_targets(
    const ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_submission_t *submission,
    ninlil_rt_target_resolve_result_t *out_result);

void ninlil_rt_v1_aggregate_target_outcomes(
    ninlil_rt_transaction_slot_t *txn,
    ninlil_outcome_t *out_outcome,
    ninlil_reason_t *out_reason);

int ninlil_rt_v1_all_targets_evidence_recorded(
    const ninlil_rt_transaction_slot_t *txn);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_TARGET_RESOLVER_H */
