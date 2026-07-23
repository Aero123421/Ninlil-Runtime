#ifndef NINLIL_RUNTIME_V1_DELIVERY_DURABLE_H
#define NINLIL_RUNTIME_V1_DELIVERY_DURABLE_H

#include "runtime_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_rt_v1_step_delivery_result {
    uint32_t callbacks_invoked;
    uint32_t transitions_consumed;
    uint32_t work_remaining;
} ninlil_rt_v1_step_delivery_result_t;

#define NINLIL_RT_V1_TX_ADMISSION_MARKER_VALUE_BYTES 46u

void ninlil_rt_v1_encode_tx_admission_marker(
    uint8_t *value,
    ninlil_family_t family,
    const ninlil_id128_t *service_app_id,
    uint64_t effect_deadline_ms,
    uint64_t generation);

ninlil_status_t ninlil_rt_v1_delivery_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    uint32_t transition_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result);

ninlil_status_t ninlil_rt_v1_delivery_restart_scan(
    ninlil_runtime_t *runtime);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_DELIVERY_DURABLE_H */
