#ifndef NINLIL_RUNTIME_V1_DELIVERY_DURABLE_H
#define NINLIL_RUNTIME_V1_DELIVERY_DURABLE_H

#include "runtime_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_rt_v1_step_delivery_result {
    uint32_t ingress_processed;
    uint32_t callbacks_invoked;
    uint32_t transitions_consumed;
    uint32_t bearer_sends;
    uint32_t transactions_terminalized;
    uint32_t events_parked;
    uint32_t work_remaining;
} ninlil_rt_v1_step_delivery_result_t;

ninlil_status_t ninlil_rt_v1_delivery_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t ingress_budget,
    uint32_t callback_budget,
    uint32_t transition_budget,
    uint32_t send_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result);

ninlil_status_t ninlil_rt_v1_prepare_callback_start(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample,
    uint64_t application_completion_timeout_ms,
    ninlil_rt_v1_step_delivery_result_t *out_result);

/*
 * Per-delivery clock boundaries shared by local and Bearer ingress dispatch.
 * Preflight leaves out_may_invoke zero when it durably consumes an expired or
 * unsafe ACTIVE token. COMPLETE callers must capture the result before the
 * postflight Port call and resolve only when out_may_resolve is non-zero.
 */
ninlil_status_t ninlil_rt_v1_callback_preflight(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *step_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_may_invoke);

const ninlil_application_result_t *ninlil_rt_v1_capture_callback_complete_result(
    ninlil_runtime_t *runtime,
    const ninlil_application_result_t *result);

/*
 * LAB-private hook boundaries around the actual application function entry.
 * The role-specific names are part of the conformance hook registry, but the
 * dispatcher remains outside the installed/public ABI.
 */
void ninlil_rt_v1_before_application_callback(
    ninlil_runtime_t *runtime);

void ninlil_rt_v1_after_application_callback(
    ninlil_runtime_t *runtime);

ninlil_status_t ninlil_rt_v1_callback_complete_postflight(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *step_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_may_resolve);

ninlil_status_t ninlil_rt_v1_resolve_callback(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    ninlil_callback_action_t action,
    const ninlil_application_result_t *result,
    ninlil_rt_v1_step_delivery_result_t *out_result);

ninlil_status_t ninlil_rt_v1_complete_deferred_delivery(
    ninlil_runtime_t *runtime,
    const ninlil_delivery_token_t *token,
    const ninlil_application_result_t *result);

ninlil_status_t ninlil_rt_v1_fence_active_tokens_for_destroy(
    ninlil_runtime_t *runtime);

/*
 * LAB-private deterministic destroy ordering seam.  Returns every ACTIVE
 * token index sorted by context_id unsigned-byte lexicographic order and
 * then generation.  No public/runtime ABI surface is added.
 */
ninlil_status_t ninlil_rt_v1_collect_destroy_token_order(
    const ninlil_runtime_t *runtime,
    uint32_t *out_order,
    uint32_t order_capacity,
    uint32_t *out_count);

ninlil_status_t ninlil_rt_v1_delivery_restart_scan(
    ninlil_runtime_t *runtime);

ninlil_status_t ninlil_rt_v1_begin_event_retry_cycle(
    const ninlil_rt_transaction_slot_t *current,
    ninlil_rt_transaction_slot_t *candidate);

/*
 * Private scheduler seam used by the delivery step and its capacity-boundary
 * regression.  Returns the complete sorted work set that fits in out_order.
 */
uint32_t ninlil_rt_v1_delivery_collect_work_order(
    const ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *out_order,
    uint32_t order_capacity);

ninlil_status_t ninlil_rt_v1_commit_delivery_marker(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation,
    uint8_t phase);

ninlil_status_t ninlil_rt_v1_commit_transaction_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_transaction_slot_t *candidate,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation);

/*
 * Commits an ordered-ingress transaction snapshot and the namespace
 * ORDERED_INPUT counter in one FULL storage transaction.  The in-memory
 * counter is published only after the durable commit succeeds.
 */
ninlil_status_t ninlil_rt_v1_commit_ordered_input_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_transaction_slot_t *candidate,
    uint16_t prefix,
    ninlil_v1_durable_operation_t operation);

/*
 * Applies correctness-closing work for one transaction before an Event
 * management mutation is evaluated.  Receipt ingress wins first, followed by
 * delivery-token timeout and the current Event attempt receipt timeout.
 */
ninlil_status_t ninlil_rt_v1_targeted_management_catch_up(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_time_sample_t *clock_sample,
    uint32_t transition_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result,
    uint32_t *out_changed);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_DELIVERY_DURABLE_H */
