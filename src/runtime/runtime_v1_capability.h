#ifndef NINLIL_RUNTIME_V1_CAPABILITY_H
#define NINLIL_RUNTIME_V1_CAPABILITY_H

/*
 * V1-LAB unit 4 (B3): logical capability layer — bearer payload limits,
 * logical payload/fragment descriptors, admission reservation helpers.
 * Not public ABI.
 */

#include "runtime_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_TX_ADMISSION_MARKER_V1_BYTES 33u
#define NINLIL_RT_V1_TX_ADMISSION_MARKER_V2_BYTES 46u

#define NINLIL_RT_V1_MARKER_RV 0x5256u

typedef enum ninlil_rt_v1_bearer_route {
    NINLIL_RT_V1_BEARER_ROUTE_SIMULATED = 1,
    NINLIL_RT_V1_BEARER_ROUTE_U6 = 2
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

void ninlil_rt_v1_encode_tx_admission_marker_v2(
    uint8_t *value,
    ninlil_family_t family,
    const ninlil_id128_t *service_app_id,
    uint64_t effect_deadline_ms,
    uint64_t generation,
    uint8_t semantic_priority,
    uint32_t payload_length,
    uint64_t admitted_at_ms);

void ninlil_rt_v1_decode_tx_admission_marker(
    ninlil_bytes_view_t value,
    ninlil_family_t *out_family,
    ninlil_id128_t *out_service_app_id,
    uint64_t *out_effect_deadline_ms,
    uint64_t *out_generation,
    uint8_t *out_semantic_priority,
    uint32_t *out_payload_length,
    uint64_t *out_admitted_at_ms);

ninlil_status_t ninlil_rt_v1_check_bearer_payload_admission(
    ninlil_rt_v1_bearer_route_t route,
    uint32_t payload_length,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_rt_v1_commit_reservation_marker(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    uint32_t payload_length,
    ninlil_rt_v1_bearer_route_t route);

ninlil_status_t ninlil_rt_v1_release_transaction_reservation(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_CAPABILITY_H */
