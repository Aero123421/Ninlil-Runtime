#ifndef NINLIL_RUNTIME_V1_EVENT_MGMT_H
#define NINLIL_RUNTIME_V1_EVENT_MGMT_H

#include "runtime_internal.h"

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES 40u
#define NINLIL_RT_V1_EVENT_RESUME_PREFIX 0x4552u
#define NINLIL_RT_V1_EVENT_DISCARD_PREFIX 0x4544u

ninlil_status_t ninlil_rt_v1_event_operation_marker_encode(
    uint16_t prefix,
    const ninlil_id128_t *operation_id,
    uint32_t reason,
    uint64_t prior_spool_revision,
    uint8_t out_value[NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES]);

ninlil_status_t ninlil_rt_v1_event_operation_marker_validate(
    uint16_t expected_prefix,
    ninlil_bytes_view_t value);

ninlil_status_t ninlil_rt_v1_event_ledger_boot_validate(
    ninlil_runtime_t *runtime);

ninlil_status_t ninlil_rt_v1_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result);

ninlil_status_t ninlil_rt_v1_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_EVENT_MGMT_H */
