#ifndef NINLIL_C3_LAB_SECURE_WIRE_H
#define NINLIL_C3_LAB_SECURE_WIRE_H

/*
 * C3-LAB secure wire seal/open (W1/L1 basic; r7_wire_codec + context lifecycle).
 * Production-private. Not public ABI.
 */

#include "c3_lab_context_lifecycle.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_C3_LAB_WIRE_FRAME_MAX ((size_t)255u)

typedef struct ninlil_c3_lab_wire_send_result {
    uint8_t frame[NINLIL_C3_LAB_WIRE_FRAME_MAX];
    size_t frame_len;
    uint64_t hop_counter;
    uint64_t e2e_counter;
} ninlil_c3_lab_wire_send_result_t;

typedef struct ninlil_c3_lab_wire_recv_result {
    uint8_t payload[190];
    size_t payload_len;
    uint64_t hop_counter;
    uint64_t e2e_counter;
    uint32_t hop_context_id;
    uint32_t e2e_context_id;
} ninlil_c3_lab_wire_recv_result_t;

ninlil_c3_lab_status_t ninlil_c3_lab_wire_seal_data(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ack_requested,
    ninlil_c3_lab_wire_send_result_t *out_result);

ninlil_c3_lab_status_t ninlil_c3_lab_wire_open_data(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_c3_lab_wire_recv_result_t *out_result);

ninlil_c3_lab_status_t ninlil_c3_lab_wire_seal_ack(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *payload,
    size_t payload_len,
    ninlil_c3_lab_wire_send_result_t *out_result);

ninlil_c3_lab_status_t ninlil_c3_lab_wire_open_ack(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_c3_lab_wire_recv_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_C3_LAB_SECURE_WIRE_H */
