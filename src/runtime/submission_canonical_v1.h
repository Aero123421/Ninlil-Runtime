#ifndef NINLIL_RUNTIME_SUBMISSION_CANONICAL_V1_H
#define NINLIL_RUNTIME_SUBMISSION_CANONICAL_V1_H

#include <ninlil/runtime.h>
#include <ninlil/service.h>
#include <ninlil/transaction.h>

#ifdef __cplusplus
extern "C" {
#endif

ninlil_status_t ninlil_rt_canonical_submission_digest_v1(
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_submission_t *submission,
    ninlil_digest256_t *out_digest);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_SUBMISSION_CANONICAL_V1_H */
