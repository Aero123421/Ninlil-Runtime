/*
 * Ninlil Runtime composition v1.
 *
 * Applications use the borrowed Runtime handle. Reference transport ports use
 * the borrowed Fabric handle. Internal reliability engines remain private.
 */
#ifndef NINLIL_COMPOSITION_V1_H
#define NINLIL_COMPOSITION_V1_H

#include "ninlil/fabric_v1.h"
#include "ninlil/runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_COMPOSITION_API_VERSION ((uint16_t)0x0001u)
#define NINLIL_COMPOSITION_PROFILE_1 ((uint32_t)1u)

typedef struct ninlil_composition_v1 ninlil_composition_v1_t;

typedef struct ninlil_composition_step_budget_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_step_budget_t runtime;
    uint32_t fabric_work;
    uint32_t reliability_work;
} ninlil_composition_step_budget_v1_t;

typedef struct ninlil_composition_step_result_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_step_result_t runtime;
    uint32_t fabric_work_done;
    uint32_t reliability_work_done;
    uint32_t more_work;
    uint32_t reserved_zero;
} ninlil_composition_step_result_v1_t;

ninlil_status_t ninlil_composition_v1_workspace_required(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment);

ninlil_status_t ninlil_composition_v1_create(
    uint32_t profile_id,
    const ninlil_runtime_config_t *runtime_config,
    const ninlil_platform_ops_t *platform_template,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_composition_v1_t **out_composition);

ninlil_status_t ninlil_composition_v1_runtime(
    ninlil_composition_v1_t *composition,
    ninlil_runtime_t **out_runtime);

ninlil_status_t ninlil_composition_v1_fabric(
    ninlil_composition_v1_t *composition,
    ninlil_fabric_v1_t **out_fabric);

ninlil_status_t ninlil_composition_v1_step(
    ninlil_composition_v1_t *composition,
    const ninlil_composition_step_budget_v1_t *budget,
    ninlil_composition_step_result_v1_t *out_result);

ninlil_status_t ninlil_composition_v1_close_begin(
    ninlil_composition_v1_t *composition);

ninlil_status_t ninlil_composition_v1_close_poll(
    ninlil_composition_v1_t *composition,
    uint32_t work_budget,
    uint32_t *out_done);

ninlil_status_t ninlil_composition_v1_destroy(
    ninlil_composition_v1_t *composition);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_COMPOSITION_V1_H */
