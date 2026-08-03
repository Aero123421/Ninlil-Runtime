#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_FABRIC_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_FABRIC_H

/* Private closed ADR-0036 Fabric records for one V1 LAB radio pair. */

#include "v1_lab_binding.h"

#include "ninlil/fabric_v1.h"
#include "ninlil/service.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_FABRIC_PACKET_MAX ((uint32_t)760u)
#define NINLIL_V1_LAB_APPLICATION_MAX ((uint32_t)128u)
#define NINLIL_V1_LAB_ADMISSION_WINDOW_MS ((uint32_t)10000u)
#define NINLIL_V1_LAB_ADMISSIONS_PER_WINDOW ((uint32_t)10u)

typedef uint32_t ninlil_v1_lab_fabric_status_t;
#define NINLIL_V1_LAB_FABRIC_OK ((ninlil_v1_lab_fabric_status_t)0u)
#define NINLIL_V1_LAB_FABRIC_INVALID_ARGUMENT \
    ((ninlil_v1_lab_fabric_status_t)1u)
#define NINLIL_V1_LAB_FABRIC_BINDING ((ninlil_v1_lab_fabric_status_t)2u)
#define NINLIL_V1_LAB_FABRIC_FLOW ((ninlil_v1_lab_fabric_status_t)3u)
#define NINLIL_V1_LAB_FABRIC_CRYPTO ((ninlil_v1_lab_fabric_status_t)4u)

/* One registration/state per distinct binding flow, shared by its Services. */
ninlil_v1_lab_fabric_status_t ninlil_v1_lab_fabric_build_path(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t flow,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state);

/* One policy and one original-forward authority record per Service row. */
ninlil_v1_lab_fabric_status_t ninlil_v1_lab_fabric_build_service(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t row_index,
    ninlil_fabric_path_policy_v1_t *out_policy,
    ninlil_fabric_authority_binding_v1_t *out_authority);

/* Fixed Foundation Service contract for one exact binding row. */
ninlil_v1_lab_fabric_status_t ninlil_v1_lab_fabric_build_descriptor(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t row_index,
    ninlil_service_descriptor_t *out_descriptor);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_FABRIC_H */
