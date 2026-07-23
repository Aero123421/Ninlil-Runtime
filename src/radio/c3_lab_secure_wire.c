/*
 * C3-LAB secure wire seal/open (W1/L1 basic; r7_wire_codec).
 */

#include "c3_lab_secure_wire.h"

#include "r7_wire_codec.h"

#include <string.h>

static ninlil_c3_lab_status_t c3_wire_status_from_r7(ninlil_r7_wire_status st)
{
    switch (st) {
    case NINLIL_R7_WIRE_OK:
        return NINLIL_C3_LAB_OK;
    case NINLIL_R7_WIRE_AUTH_FAILED:
        return NINLIL_C3_LAB_AUTH_FAILED;
    case NINLIL_R7_WIRE_INVALID_ARGUMENT:
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    default:
        return NINLIL_C3_LAB_REJECTED;
    }
}

static const ninlil_c3_lab_lane_context_t *c3_tx_lane(
    const ninlil_c3_lab_context_store_t *store,
    uint8_t lane)
{
    if (lane == NINLIL_C3_LAB_LANE_DATA) {
        return &store->hop_tx.data;
    }
    if (lane == NINLIL_C3_LAB_LANE_ACK) {
        return &store->hop_tx.ack;
    }
    return NULL;
}

static const ninlil_c3_lab_lane_context_t *c3_rx_lane(
    const ninlil_c3_lab_context_store_t *store,
    uint8_t lane)
{
    if (lane == NINLIL_C3_LAB_LANE_DATA) {
        return &store->hop_rx.data;
    }
    if (lane == NINLIL_C3_LAB_LANE_ACK) {
        return &store->hop_rx.ack;
    }
    return NULL;
}

static ninlil_c3_lab_status_t c3_wire_seal(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ack_requested,
    ninlil_c3_lab_wire_send_result_t *out_result)
{
    ninlil_r7_wire_e2e_single_fields e2e_fields;
    ninlil_r7_wire_outer_data_fields outer_fields;
    uint8_t e2e_blob[220];
    size_t e2e_blob_len = 0u;
    size_t e2e_blob_cap;
    size_t frame_cap;
    ninlil_r7_wire_status wst;
    ninlil_c3_lab_status_t st;
    const ninlil_c3_lab_lane_context_t *hop_lane;

    if (store == NULL || payload == NULL || out_result == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    if (store->state != NINLIL_C3_LAB_STATE_ACTIVE
        || store->hop_tx.installed == 0u
        || store->e2e_tx.installed == 0u) {
        return NINLIL_C3_LAB_FENCED;
    }
    if (payload_len < NINLIL_R7_WIRE_APP_MIN
        || payload_len > NINLIL_R7_WIRE_APP_MAX) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    hop_lane = c3_tx_lane(store, lane);
    if (hop_lane == NULL || hop_lane->active == 0u) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    st = ninlil_c3_lab_tx_burn_counter(store, NINLIL_C3_LAB_LANE_DATA, 1u, &e2e_fields.e2e_counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }
    e2e_fields.e2e_context_id = store->e2e_tx.e2e_context_id;

    e2e_blob_cap =
        NINLIL_R7_WIRE_E2E_AAD_LEN + payload_len + NINLIL_R7_WIRE_TAG_LEN;
    wst = ninlil_r7_wire_seal_e2e_single(
        store->provider,
        store->e2e_tx.key16,
        store->e2e_tx.iv12,
        &e2e_fields,
        payload,
        payload_len,
        e2e_blob,
        e2e_blob_cap,
        &e2e_blob_len);
    if (wst != NINLIL_R7_WIRE_OK) {
        return c3_wire_status_from_r7(wst);
    }

    st = ninlil_c3_lab_tx_burn_counter(store, lane, 0u, &outer_fields.hop_counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }

    outer_fields.ack_requested = ack_requested;
    outer_fields.hop_remaining = 0u;
    outer_fields.hop_context_id = store->hop_tx.hop_context_id;
    outer_fields.route_handle = 0u;
    outer_fields.route_generation = 0u;

    frame_cap = NINLIL_R7_WIRE_OUTER_AAD_LEN + e2e_blob_len + NINLIL_R7_WIRE_TAG_LEN;
    wst = ninlil_r7_wire_seal_outer_single(
        store->provider,
        hop_lane->hop_key16,
        hop_lane->hop_iv12,
        &outer_fields,
        e2e_blob,
        e2e_blob_len,
        out_result->frame,
        frame_cap,
        &out_result->frame_len);
    if (wst != NINLIL_R7_WIRE_OK) {
        return c3_wire_status_from_r7(wst);
    }

    out_result->hop_counter = outer_fields.hop_counter;
    out_result->e2e_counter = e2e_fields.e2e_counter;
    return NINLIL_C3_LAB_OK;
}

static ninlil_c3_lab_status_t c3_wire_open(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_c3_lab_wire_recv_result_t *out_result)
{
    ninlil_r7_wire_outer_data_fields outer_fields;
    ninlil_r7_wire_e2e_single_fields e2e_fields;
    uint8_t e2e_blob[220];
    size_t e2e_blob_len = 0u;
    size_t e2e_blob_cap;
    size_t payload_cap;
    ninlil_r7_wire_status wst;
    ninlil_c3_lab_status_t st;
    const ninlil_c3_lab_lane_context_t *hop_lane;

    if (store == NULL || frame == NULL || out_result == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    if (store->state != NINLIL_C3_LAB_STATE_ACTIVE
        || store->hop_rx.installed == 0u
        || store->e2e_rx.installed == 0u) {
        return NINLIL_C3_LAB_FENCED;
    }

    hop_lane = c3_rx_lane(store, lane);
    if (hop_lane == NULL || hop_lane->active == 0u) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    if (frame_len < NINLIL_R7_WIRE_FRAME_MIN
        || frame_len > NINLIL_R7_WIRE_FRAME_MAX) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }
    e2e_blob_cap = frame_len
        - (NINLIL_R7_WIRE_OUTER_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    if (e2e_blob_cap < NINLIL_R7_WIRE_E2E_BLOB_MIN
        || e2e_blob_cap > NINLIL_R7_WIRE_E2E_BLOB_MAX) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    wst = ninlil_r7_wire_open_outer_single(
        store->provider,
        hop_lane->hop_key16,
        hop_lane->hop_iv12,
        frame,
        frame_len,
        &outer_fields,
        e2e_blob,
        e2e_blob_cap,
        &e2e_blob_len);
    if (wst != NINLIL_R7_WIRE_OK) {
        return c3_wire_status_from_r7(wst);
    }

    if (outer_fields.hop_context_id != store->hop_rx.hop_context_id) {
        return NINLIL_C3_LAB_REJECTED;
    }

    st = ninlil_c3_lab_rx_precheck(store, lane, 0u, outer_fields.hop_counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }

    payload_cap = e2e_blob_len
        - (NINLIL_R7_WIRE_E2E_AAD_LEN + NINLIL_R7_WIRE_TAG_LEN);
    if (payload_cap < NINLIL_R7_WIRE_APP_MIN
        || payload_cap > NINLIL_R7_WIRE_APP_MAX) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    wst = ninlil_r7_wire_open_e2e_single(
        store->provider,
        store->e2e_rx.key16,
        store->e2e_rx.iv12,
        e2e_blob,
        e2e_blob_len,
        &e2e_fields,
        out_result->payload,
        payload_cap,
        &out_result->payload_len);
    if (wst != NINLIL_R7_WIRE_OK) {
        return c3_wire_status_from_r7(wst);
    }

    if (e2e_fields.e2e_context_id != store->e2e_rx.e2e_context_id) {
        return NINLIL_C3_LAB_REJECTED;
    }

    st = ninlil_c3_lab_rx_precheck(store, NINLIL_C3_LAB_LANE_DATA, 1u, e2e_fields.e2e_counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }

    st = ninlil_c3_lab_rx_admit(store, lane, 0u, outer_fields.hop_counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }
    st = ninlil_c3_lab_rx_admit(store, NINLIL_C3_LAB_LANE_DATA, 1u, e2e_fields.e2e_counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }

    out_result->hop_counter = outer_fields.hop_counter;
    out_result->e2e_counter = e2e_fields.e2e_counter;
    out_result->hop_context_id = outer_fields.hop_context_id;
    out_result->e2e_context_id = e2e_fields.e2e_context_id;
    return NINLIL_C3_LAB_OK;
}

ninlil_c3_lab_status_t ninlil_c3_lab_wire_seal_data(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ack_requested,
    ninlil_c3_lab_wire_send_result_t *out_result)
{
    return c3_wire_seal(
        store,
        NINLIL_C3_LAB_LANE_DATA,
        payload,
        payload_len,
        ack_requested,
        out_result);
}

ninlil_c3_lab_status_t ninlil_c3_lab_wire_open_data(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_c3_lab_wire_recv_result_t *out_result)
{
    return c3_wire_open(
        store,
        NINLIL_C3_LAB_LANE_DATA,
        frame,
        frame_len,
        out_result);
}

ninlil_c3_lab_status_t ninlil_c3_lab_wire_seal_ack(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *payload,
    size_t payload_len,
    ninlil_c3_lab_wire_send_result_t *out_result)
{
    return c3_wire_seal(
        store,
        NINLIL_C3_LAB_LANE_ACK,
        payload,
        payload_len,
        0u,
        out_result);
}

ninlil_c3_lab_status_t ninlil_c3_lab_wire_open_ack(
    ninlil_c3_lab_context_store_t *store,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_c3_lab_wire_recv_result_t *out_result)
{
    return c3_wire_open(
        store,
        NINLIL_C3_LAB_LANE_ACK,
        frame,
        frame_len,
        out_result);
}
