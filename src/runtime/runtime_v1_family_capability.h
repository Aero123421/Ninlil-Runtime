#ifndef NINLIL_RUNTIME_V1_FAMILY_CAPABILITY_H
#define NINLIL_RUNTIME_V1_FAMILY_CAPABILITY_H

/*
 * V1-LAB B5: application capability family state machines.
 * Not public ABI.
 */

#include "runtime_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_CONFIG_STAGE_STAGED    1u
#define NINLIL_RT_V1_CONFIG_STAGE_VALIDATE  2u
#define NINLIL_RT_V1_CONFIG_STAGE_COMMIT    3u

#define NINLIL_RT_V1_TRANSFER_STATE_NONE       0u
#define NINLIL_RT_V1_TRANSFER_STATE_RECEIVING   1u
#define NINLIL_RT_V1_TRANSFER_STATE_COMPLETE    2u
#define NINLIL_RT_V1_TRANSFER_STATE_ABORTED     3u

int ninlil_rt_v1_family_is_uplink(ninlil_family_t family);
int ninlil_rt_v1_family_is_downlink(ninlil_family_t family);
int ninlil_rt_v1_family_is_b5_lab(ninlil_family_t family);

int ninlil_rt_v1_family_descriptor_role_valid(
    ninlil_role_t role,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_model_local_submission_side_t *out_side);

int ninlil_rt_v1_family_descriptor_semantics_valid(
    const ninlil_service_descriptor_t *descriptor);

int ninlil_rt_v1_family_submission_identity_valid(
    ninlil_family_t family,
    const ninlil_submission_t *submission);

int ninlil_rt_v1_family_latest_state_apply(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    uint64_t generation,
    ninlil_application_result_t *out_result);

int ninlil_rt_v1_family_measurement_batch_accept(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    uint64_t batch_sequence,
    uint32_t payload_length,
    ninlil_application_result_t *out_result);

int ninlil_rt_v1_family_bounded_transfer_begin(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id,
    uint32_t total_bytes);

int ninlil_rt_v1_family_bounded_transfer_receive(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id,
    uint32_t chunk_bytes,
    int complete);

int ninlil_rt_v1_family_bounded_transfer_abort(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id);

int ninlil_rt_v1_family_bounded_transfer_may_apply(
    const ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *transaction_id);

int ninlil_rt_v1_family_config_revision_advance(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id,
    uint64_t revision,
    uint8_t requested_stage,
    ninlil_application_result_t *out_result);

void ninlil_rt_v1_family_config_revision_rollback(
    ninlil_rt_v1_family_workspace_t *ws,
    const ninlil_id128_t *service_app_id);

ninlil_rt_v1_family_workspace_t *ninlil_rt_v1_family_workspace(
    ninlil_runtime_t *runtime);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_FAMILY_CAPABILITY_H */
