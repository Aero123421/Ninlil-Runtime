#ifndef NINLIL_RUNTIME_V1_BEARER_WIRE_H
#define NINLIL_RUNTIME_V1_BEARER_WIRE_H

#include "runtime_internal.h"
#include "runtime_v1_delivery_durable.h"

#ifdef __cplusplus
extern "C" {
#endif

int ninlil_rt_v1_bearer_path_available(ninlil_runtime_t *runtime);

/*
 * Validates the complete LAB-private Bearer State durable envelope without
 * binding it to one runtime instance.  Restore adds the runtime-id equality
 * check after this format-level validation succeeds.
 */
ninlil_status_t ninlil_rt_v1_bearer_state_marker_validate(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);

ninlil_status_t ninlil_rt_v1_bearer_snapshot_step_state(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t transition_budget,
    uint32_t *out_transitions_consumed,
    uint32_t *out_work_remaining);

int ninlil_rt_v1_bearer_restore_state_marker(
    ninlil_runtime_t *runtime,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);

ninlil_status_t ninlil_rt_v1_bearer_ingress_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *inout_ingress_budget,
    uint32_t callback_budget,
    uint32_t transition_budget,
    uint32_t send_budget,
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

ninlil_status_t ninlil_rt_v1_bearer_reduce_pending_ingress(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    uint32_t transition_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result);

#if defined(NINLIL_MFDT_V1_PRIVATE)
/*
 * Commit/reconcile one receiver-side canonical OPEN as the existing inbound
 * Foundation transaction. The large payload remains sidecar-owned and is
 * represented by logical length plus zero inline bytes.
 */
ninlil_status_t ninlil_rt_v1_bearer_commit_mfdt_ingress(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const uint8_t transfer_id[16],
    uint32_t target_ordinal,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *durable_transition_out);

int ninlil_rt_v1_bearer_mfdt_ingress_matches(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const uint8_t transfer_id[16],
    uint32_t target_ordinal);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_BEARER_WIRE_H */
