#ifndef NINLIL_RUNTIME_V1_SPINE_DURABLE_H
#define NINLIL_RUNTIME_V1_SPINE_DURABLE_H

#include "runtime_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

ninlil_status_t ninlil_rt_v1_spine_service_register_commit(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    uint32_t *inout_slot_index);

ninlil_status_t ninlil_rt_v1_spine_submit_admission(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_rt_v1_spine_cancel_admission(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
