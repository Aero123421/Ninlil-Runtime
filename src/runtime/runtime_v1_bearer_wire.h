#ifndef NINLIL_RUNTIME_V1_BEARER_WIRE_H
#define NINLIL_RUNTIME_V1_BEARER_WIRE_H

#include "runtime_internal.h"
#include "runtime_v1_delivery_durable.h"

#ifdef __cplusplus
extern "C" {
#endif

int ninlil_rt_v1_bearer_path_available(ninlil_runtime_t *runtime);

ninlil_status_t ninlil_rt_v1_bearer_ingress_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *inout_ingress_budget,
    uint32_t callback_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result);

ninlil_status_t ninlil_rt_v1_bearer_send_desired_application(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result);

ninlil_status_t ninlil_rt_v1_bearer_send_uplink_application(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_BEARER_WIRE_H */
