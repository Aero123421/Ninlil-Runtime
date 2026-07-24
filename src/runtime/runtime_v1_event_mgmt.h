#ifndef NINLIL_RUNTIME_V1_EVENT_MGMT_H
#define NINLIL_RUNTIME_V1_EVENT_MGMT_H

#include "runtime_internal.h"

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

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
