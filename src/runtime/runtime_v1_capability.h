#ifndef NINLIL_RUNTIME_V1_CAPABILITY_H
#define NINLIL_RUNTIME_V1_CAPABILITY_H

/*
 * V1-LAB unit 4 (B3): logical capability layer — bearer payload limits,
 * logical payload/fragment descriptors, admission reservation helpers.
 * Not public ABI.
 */

#include "runtime_internal.h"
#include "resource_ledger_batch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_MARKER_RV 0x5256u
#define NINLIL_RT_V1_RESERVATION_MARKER_BYTES 32u

typedef enum ninlil_rt_v1_bearer_route {
    NINLIL_RT_V1_BEARER_ROUTE_SIMULATED = 1,
    NINLIL_RT_V1_BEARER_ROUTE_U6 = 2,
    /* Private ADR-0021 multi-frame: logical ApplicationData up to 32768. */
    NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1 = 3
} ninlil_rt_v1_bearer_route_t;

typedef struct ninlil_rt_v1_bearer_limit_row {
    ninlil_rt_v1_bearer_route_t route;
    uint32_t max_single_frame_payload_bytes;
    const char *name;
} ninlil_rt_v1_bearer_limit_row_t;

typedef struct ninlil_rt_v1_logical_payload_desc {
    uint32_t total_logical_bytes;
    uint32_t fragment_count;
    uint64_t effect_deadline_ms;
    uint8_t semantic_priority;
    uint8_t reserved_zero[3];
} ninlil_rt_v1_logical_payload_desc_t;

typedef struct ninlil_rt_v1_logical_fragment_desc {
    uint32_t fragment_index;
    uint32_t fragment_logical_bytes;
    uint32_t fragment_count;
    uint32_t reserved_zero;
} ninlil_rt_v1_logical_fragment_desc_t;

ninlil_rt_v1_bearer_route_t ninlil_rt_v1_default_bearer_route(void);

uint32_t ninlil_rt_v1_bearer_payload_limit(
    ninlil_rt_v1_bearer_route_t route);

int ninlil_rt_v1_bearer_admits_payload(
    ninlil_rt_v1_bearer_route_t route,
    uint32_t payload_length);

uint8_t ninlil_rt_v1_semantic_priority_for_family(ninlil_family_t family);

ninlil_status_t ninlil_rt_v1_build_logical_payload_desc(
    ninlil_family_t family,
    uint32_t payload_length,
    uint64_t effect_deadline_ms,
    ninlil_rt_v1_logical_payload_desc_t *out_desc);

ninlil_status_t ninlil_rt_v1_build_logical_fragment_desc(
    uint32_t payload_length,
    ninlil_rt_v1_logical_fragment_desc_t *out_desc);

int ninlil_rt_v1_txn_queue_order_less(
    const ninlil_rt_transaction_slot_t *left,
    const ninlil_rt_transaction_slot_t *right);

ninlil_status_t ninlil_rt_v1_reservation_marker_encode(
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route,
    uint8_t out_value[NINLIL_RT_V1_RESERVATION_MARKER_BYTES]);

ninlil_status_t ninlil_rt_v1_reservation_marker_decode(
    ninlil_bytes_view_t value,
    uint32_t *out_payload_length,
    ninlil_rt_v1_bearer_route_t *out_route);

ninlil_status_t ninlil_rt_v1_reservation_marker_validate(
    ninlil_bytes_view_t value);

ninlil_status_t ninlil_rt_v1_check_bearer_payload_admission(
    ninlil_rt_v1_bearer_route_t route,
    uint32_t payload_length,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_rt_v1_commit_reservation_marker(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route);

ninlil_status_t ninlil_rt_v1_stage_reservation_marker(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_v1_durable_operation_t operation,
    const ninlil_id128_t *transaction_id,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route);

ninlil_status_t ninlil_rt_v1_stage_resource_ledger(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_v1_durable_operation_t operation,
    const ninlil_model_resource_ledger_t *ledger);

ninlil_status_t ninlil_rt_v1_stage_resource_ledger_kind(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t storage_txn,
    ninlil_v1_durable_operation_t operation,
    const ninlil_model_resource_ledger_t *ledger,
    ninlil_resource_kind_t kind);

ninlil_status_t ninlil_rt_v1_restore_resource_ledger_row(
    ninlil_runtime_t *runtime,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    uint32_t *out_recognized);

ninlil_status_t ninlil_rt_v1_build_released_resource_ledger(
    const ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn,
    ninlil_model_resource_ledger_t *out_ledger);

ninlil_status_t ninlil_rt_v1_build_released_resource_ledger_from(
    const ninlil_model_resource_ledger_t *current,
    const ninlil_rt_transaction_slot_t *txn,
    ninlil_model_resource_ledger_t *out_ledger);

ninlil_status_t ninlil_rt_v1_build_evidence_committed_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    ninlil_model_resource_ledger_t *out_ledger);

/*
 * Inbound callback ownership is separate from origin submission ownership.
 * The first callback start acquires DELIVERY + RESULT_CACHE and every
 * callback start acquires one DEFERRED_TOKEN.  The transition is pure so the
 * caller can persist the candidate ledger in the same FULL transaction as
 * DELIVERY_STARTED before publishing either projection.
 */
ninlil_status_t ninlil_rt_v1_build_callback_start_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    uint32_t first_callback,
    ninlil_model_capacity_batch_action_t *out_action,
    ninlil_model_resource_ledger_t *out_ledger);

/*
 * A new inbound application delivery owns DELIVERY capacity from the same
 * FULL commit which first makes the canonical transaction durable.  This
 * gate therefore runs before callback scheduling and is independently
 * enforceable when callback budget is zero.
 */
ninlil_status_t ninlil_rt_v1_build_inbound_delivery_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    ninlil_model_capacity_batch_action_t *out_action,
    ninlil_model_resource_ledger_t *out_ledger);

/*
 * Release exact inbound ownership in the transaction which makes the
 * corresponding state transition visible.  Counts may be larger than one
 * for the destroy recovery group, but only the named resource classes move.
 */
ninlil_status_t ninlil_rt_v1_build_inbound_released_resource_ledger(
    const ninlil_model_resource_ledger_t *current,
    uint64_t delivery_count,
    uint64_t deferred_token_count,
    ninlil_model_resource_ledger_t *out_ledger);

/*
 * Recovery publication gate: durable capacity metadata must describe the
 * exact resource ownership reconstructed from the canonical transaction and
 * reservation records.  A mismatch is corruption, never an estimate.
 */
ninlil_status_t ninlil_rt_v1_validate_restored_resource_ledger(
    const ninlil_runtime_t *runtime);

ninlil_status_t ninlil_rt_v1_release_transaction_reservation(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_CAPABILITY_H */
