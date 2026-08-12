/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_usb_bridge.h"

#include <limits.h>
#include <string.h>

#define SLOT_EMPTY ((uint8_t)0u)
#define SLOT_PENDING ((uint8_t)1u)
#define SLOT_COMPLETE ((uint8_t)2u)

_Static_assert(sizeof(ninlil_v1_usb_bridge_t)
        <= NINLIL_V1_USB_BRIDGE_OBJECT_CEILING_BYTES,
    "V1 USB bridge exceeds its private fixed-memory ceiling");

static int range_end(uintptr_t base, size_t length, uintptr_t *out_end)
{
    if (length > UINTPTR_MAX - base) {
        return 0;
    }
    *out_end = base + length;
    return 1;
}

static int ranges_disjoint(
    const void *a, size_t a_length, const void *b, size_t b_length)
{
    uintptr_t a_base = (uintptr_t)a;
    uintptr_t b_base = (uintptr_t)b;
    uintptr_t a_end;
    uintptr_t b_end;

    if (!range_end(a_base, a_length, &a_end)
        || !range_end(b_base, b_length, &b_end)) {
        return 0;
    }
    return a_end <= b_base || b_end <= a_base;
}

static void bridge_zero(void *memory, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)memory;

    while (length > 0u) {
        *p = 0u;
        ++p;
        --length;
    }
}

static int role_valid(ninlil_v1_usb_bridge_role_t role)
{
    return role == NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER
        || role == NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD;
}

static int bridge_known(const ninlil_v1_usb_bridge_t *bridge)
{
    const ninlil_byte_stream_ops_t *ops;

    if (bridge == NULL || bridge->magic != NINLIL_V1_USB_BRIDGE_MAGIC
        || !role_valid(bridge->role) || bridge->stream == NULL
        || bridge->stream->ops == NULL) {
        return 0;
    }
    ops = bridge->stream->ops;
    return ops->read != NULL && ops->write != NULL && ops->poll != NULL
        && ops->link != NULL && ops->link_generation != NULL;
}

static void clear_tx(ninlil_v1_usb_bridge_t *bridge)
{
    bridge_zero(bridge->tx_payload, sizeof(bridge->tx_payload));
    bridge_zero(bridge->tx_wire, sizeof(bridge->tx_wire));
    bridge->tx_wire_length = 0u;
    bridge->tx_is_local_request = 0u;
    bridge->tx_kind = 0u;
    bridge->tx_operation_id = 0u;
}

static void reset_rx(ninlil_v1_usb_bridge_t *bridge)
{
    bridge_zero(bridge->parser_payload, sizeof(bridge->parser_payload));
    bridge_zero(bridge->rx_chunk, sizeof(bridge->rx_chunk));
    bridge_zero(bridge->rx_residual, sizeof(bridge->rx_residual));
    bridge->rx_residual_length = 0u;
    ninlil_model_control_frame_parser_reset(&bridge->parser);
}

static void complete_slot(
    ninlil_v1_usb_bridge_slot_t *slot,
    ninlil_v1_usb_bridge_completion_reason_t reason,
    uint32_t remote_status_code,
    uint64_t pair_generation)
{
    if (slot->state != SLOT_PENDING) {
        return;
    }
    slot->completion.reason = reason;
    slot->completion.remote_status_code = remote_status_code;
    slot->completion.pair_generation = pair_generation;
    slot->state = SLOT_COMPLETE;
}

static void complete_pending_for_fence(ninlil_v1_usb_bridge_t *bridge)
{
    uint8_t i;

    complete_slot(&bridge->binding_slot,
        NINLIL_V1_USB_BRIDGE_COMPLETION_LINK_FENCED, 0u, 0u);
    for (i = 0u; i < NINLIL_V1_USB_BRIDGE_PACKET_SLOTS; ++i) {
        complete_slot(&bridge->packet_slots[i],
            NINLIL_V1_USB_BRIDGE_COMPLETION_LINK_FENCED, 0u, 0u);
    }
}

static void fence_generation(ninlil_v1_usb_bridge_t *bridge)
{
    if (bridge->active_generation != 0u) {
        complete_pending_for_fence(bridge);
        bridge->generation_fenced = 1u;
    }
    clear_tx(bridge);
    reset_rx(bridge);
}

static void fence_observed_generation(ninlil_v1_usb_bridge_t *bridge)
{
    uint64_t observed_generation =
        bridge->stream->ops->link_generation(bridge->stream);

    fence_generation(bridge);
    if (observed_generation != 0u) {
        bridge->active_generation = observed_generation;
        bridge->generation_fenced = 1u;
    }
}

static void start_generation(
    ninlil_v1_usb_bridge_t *bridge, uint64_t generation)
{
    if (bridge->active_generation != 0u
        && bridge->active_generation != generation) {
        complete_pending_for_fence(bridge);
    }
    clear_tx(bridge);
    reset_rx(bridge);
    bridge->active_generation = generation;
    bridge->next_local_operation_id = 1u;
    bridge->next_remote_operation_id = 1u;
    bridge->tx_sequence = 0u;
    bridge->rx_sequence = 0u;
    bridge->generation_fenced = 0u;
    bridge->tx_sequence_exhausted = 0u;
    bridge->rx_sequence_exhausted = 0u;
    bridge->remote_operation_exhausted = 0u;
    bridge->board_info_sent = 0u;
    bridge->board_info_received = 0u;
}

static ninlil_v1_usb_bridge_slot_t *find_slot(
    ninlil_v1_usb_bridge_t *bridge,
    uint64_t generation,
    uint64_t operation_id)
{
    uint8_t i;

    if (bridge->binding_slot.state != SLOT_EMPTY
        && bridge->binding_slot.link_generation == generation
        && bridge->binding_slot.operation_id == operation_id) {
        return &bridge->binding_slot;
    }
    for (i = 0u; i < NINLIL_V1_USB_BRIDGE_PACKET_SLOTS; ++i) {
        if (bridge->packet_slots[i].state != SLOT_EMPTY
            && bridge->packet_slots[i].link_generation == generation
            && bridge->packet_slots[i].operation_id == operation_id) {
            return &bridge->packet_slots[i];
        }
    }
    return NULL;
}

static ninlil_v1_usb_bridge_slot_t *empty_packet_slot(
    ninlil_v1_usb_bridge_t *bridge)
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_USB_BRIDGE_PACKET_SLOTS; ++i) {
        if (bridge->packet_slots[i].state == SLOT_EMPTY) {
            return &bridge->packet_slots[i];
        }
    }
    return NULL;
}

static uint64_t get_u64_be(const uint8_t *bytes)
{
    return ((uint64_t)bytes[0] << 56u)
        | ((uint64_t)bytes[1] << 48u)
        | ((uint64_t)bytes[2] << 40u)
        | ((uint64_t)bytes[3] << 32u)
        | ((uint64_t)bytes[4] << 24u)
        | ((uint64_t)bytes[5] << 16u)
        | ((uint64_t)bytes[6] << 8u)
        | (uint64_t)bytes[7];
}

static ninlil_v1_usb_bridge_status_t build_tx(
    ninlil_v1_usb_bridge_t *bridge,
    uint8_t kind,
    uint64_t operation_id,
    const uint8_t *payload,
    size_t payload_length,
    uint8_t is_local_request)
{
    ninlil_nvb1_envelope_t envelope;
    ninlil_model_control_frame_fields_t fields;
    size_t nvb_length = 0u;
    uint32_t wire_length = 0u;

    if (bridge->tx_wire_length != 0u) {
        return NINLIL_V1_USB_BRIDGE_BUSY;
    }
    if (bridge->tx_sequence_exhausted != 0u
        || bridge->tx_sequence == UINT32_MAX) {
        return NINLIL_V1_USB_BRIDGE_SEQUENCE_EXHAUSTED;
    }
    (void)memset(&envelope, 0, sizeof(envelope));
    envelope.kind = kind;
    envelope.operation_id = operation_id;
    envelope.payload = payload;
    envelope.payload_length = payload_length;
    if (ninlil_nvb1_encode(&envelope, bridge->tx_payload,
            sizeof(bridge->tx_payload), &nvb_length)
        != NINLIL_NVB1_OK) {
        clear_tx(bridge);
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = bridge->tx_sequence;
    fields.payload.data = bridge->tx_payload;
    fields.payload.length = (uint32_t)nvb_length;
    if (ninlil_model_control_frame_encode(&fields, bridge->tx_wire,
            sizeof(bridge->tx_wire), &wire_length)
        != NINLIL_OK) {
        clear_tx(bridge);
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    bridge_zero(bridge->tx_payload, sizeof(bridge->tx_payload));
    bridge->tx_wire_length = wire_length;
    bridge->tx_is_local_request = is_local_request;
    bridge->tx_kind = kind;
    bridge->tx_operation_id = operation_id;
    return NINLIL_V1_USB_BRIDGE_OK;
}

static ninlil_v1_usb_bridge_status_t queue_status(
    ninlil_v1_usb_bridge_t *bridge,
    uint64_t operation_id,
    uint32_t code,
    uint64_t pair_generation)
{
    ninlil_nvb1_local_status_t status;
    uint8_t encoded[NINLIL_NVB1_STATUS_BYTES];
    ninlil_v1_usb_bridge_status_t result;

    status.code = code;
    status.pair_generation = pair_generation;
    if (ninlil_nvb1_status_encode(&status, encoded) != NINLIL_NVB1_OK) {
        bridge_zero(encoded, sizeof(encoded));
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    result = build_tx(bridge, NINLIL_NVB1_KIND_STATUS, operation_id,
        encoded, sizeof(encoded), 0u);
    bridge_zero(encoded, sizeof(encoded));
    return result;
}

static int fabric_status_valid(uint32_t code)
{
    return code == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL
        || code == NINLIL_NVB1_STATUS_REJECTED
        || code == NINLIL_NVB1_STATUS_BUSY
        || code == NINLIL_NVB1_STATUS_UNSUPPORTED;
}

static int status_matches_slot(
    const ninlil_v1_usb_bridge_slot_t *slot,
    const ninlil_nvb1_local_status_t *status)
{
    if (status->code == NINLIL_NVB1_STATUS_INSTALLED) {
        return slot->kind == NINLIL_NVB1_KIND_BINDING_SET
            && status->pair_generation != 0u
            && status->pair_generation == slot->expected_pair_generation;
    }
    if (status->pair_generation != 0u) {
        return 0;
    }
    if (slot->kind == NINLIL_NVB1_KIND_BINDING_SET) {
        return status->code == NINLIL_NVB1_STATUS_REJECTED
            || status->code == NINLIL_NVB1_STATUS_BUSY
            || status->code == NINLIL_NVB1_STATUS_STORAGE_UNKNOWN
            || status->code == NINLIL_NVB1_STATUS_UNSUPPORTED
            || status->code == NINLIL_NVB1_STATUS_REPROVISION_REQUIRED;
    }
    return slot->kind == NINLIL_NVB1_KIND_FABRIC_PACKET
        && fabric_status_valid(status->code);
}

static uint32_t map_provision_status(
    ninlil_v1_lab_provision_status_t status)
{
    switch (status) {
    case NINLIL_V1_LAB_PROVISION_OK:
        return NINLIL_NVB1_STATUS_INSTALLED;
    case NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN:
        return NINLIL_NVB1_STATUS_STORAGE_UNKNOWN;
    case NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED:
    case NINLIL_V1_LAB_PROVISION_FENCED:
    case NINLIL_V1_LAB_PROVISION_STORAGE:
    case NINLIL_V1_LAB_PROVISION_CORRUPT:
    case NINLIL_V1_LAB_PROVISION_CRYPTO:
        return NINLIL_NVB1_STATUS_REPROVISION_REQUIRED;
    case NINLIL_V1_LAB_PROVISION_CAPACITY:
    case NINLIL_V1_LAB_PROVISION_INVALID_STATE:
        return NINLIL_NVB1_STATUS_BUSY;
    case NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT:
    default:
        return NINLIL_NVB1_STATUS_REJECTED;
    }
}

static ninlil_v1_usb_bridge_status_t handle_status(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_nvb1_envelope_t *envelope)
{
    ninlil_nvb1_local_status_t status;
    ninlil_v1_usb_bridge_slot_t *slot;

    if (ninlil_nvb1_status_decode(envelope->payload, &status)
        != NINLIL_NVB1_OK) {
        return NINLIL_V1_USB_BRIDGE_OK;
    }
    slot = find_slot(bridge, bridge->active_generation,
        envelope->operation_id);
    if (slot == NULL || slot->state != SLOT_PENDING || slot->sent == 0u
        || !status_matches_slot(slot, &status)) {
        return NINLIL_V1_USB_BRIDGE_OK;
    }
    complete_slot(slot, NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS,
        status.code, status.pair_generation);
    return NINLIL_V1_USB_BRIDGE_OK;
}

static ninlil_v1_usb_bridge_status_t handle_binding_request(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_nvb1_envelope_t *envelope)
{
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_v1_lab_provision_status_t provision_status;
    uint32_t code;
    uint64_t pair_generation = 0u;

    (void)memset(&handles, 0, sizeof(handles));
    if (bridge->role != NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD) {
        code = NINLIL_NVB1_STATUS_REJECTED;
    } else if (bridge->board_info_sent == 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    } else if (bridge->provisioner == NULL
        || bridge->pair_installed == NULL) {
        code = NINLIL_NVB1_STATUS_UNSUPPORTED;
    } else {
        provision_status = ninlil_v1_lab_provisioner_install_pair(
            bridge->provisioner, envelope->payload,
            envelope->payload_length, &handles);
        if (provision_status != NINLIL_V1_LAB_PROVISION_OK
            && provision_status != NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN
            && ninlil_v1_lab_provisioner_is_fenced(bridge->provisioner)) {
            code = NINLIL_NVB1_STATUS_REPROVISION_REQUIRED;
        } else {
            code = map_provision_status(provision_status);
        }
        if (provision_status == NINLIL_V1_LAB_PROVISION_OK) {
            pair_generation = get_u64_be(envelope->payload + 4u);
            bridge->pair_installed(bridge->callback_user,
                envelope->payload, envelope->payload_length, &handles);
        }
    }
    bridge_zero(&handles, sizeof(handles));
    return queue_status(bridge, envelope->operation_id,
        code, pair_generation);
}

static ninlil_v1_usb_bridge_status_t handle_fabric_request(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_nvb1_envelope_t *envelope)
{
    uint32_t code = NINLIL_NVB1_STATUS_UNSUPPORTED;

    if (bridge->fabric_handoff != NULL) {
        code = bridge->fabric_handoff(bridge->callback_user,
            envelope->payload, envelope->payload_length);
        if (!fabric_status_valid(code)) {
            code = NINLIL_NVB1_STATUS_REJECTED;
        }
    }
    return queue_status(bridge, envelope->operation_id, code, 0u);
}

static ninlil_v1_usb_bridge_status_t handle_board_info(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_nvb1_envelope_t *envelope)
{
    ninlil_nvb1_board_info_t info;

    if (bridge->role != NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER
        || bridge->board_info == NULL
        || bridge->board_info_received != 0u
        || ninlil_nvb1_board_info_decode(envelope->payload, &info)
            != NINLIL_NVB1_OK) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    if (bridge->board_info(bridge->callback_user, &info)
        != NINLIL_V1_USB_BRIDGE_OK) {
        bridge_zero(&info, sizeof(info));
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    bridge->board_info_received = 1u;
    bridge_zero(&info, sizeof(info));
    return NINLIL_V1_USB_BRIDGE_OK;
}

static ninlil_v1_usb_bridge_status_t handle_frame(
    ninlil_v1_usb_bridge_t *bridge)
{
    const ninlil_model_control_frame_view_t *frame =
        &bridge->parser.last_frame;
    ninlil_nvb1_envelope_t envelope;
    ninlil_v1_usb_bridge_status_t result = NINLIL_V1_USB_BRIDGE_OK;

    if (bridge->rx_sequence_exhausted != 0u
        || frame->sequence == UINT32_MAX
        || frame->sequence != bridge->rx_sequence) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (frame->sequence == UINT32_MAX - 1u) {
        bridge->rx_sequence_exhausted = 1u;
    } else {
        bridge->rx_sequence += 1u;
    }

    if (frame->version != NINLIL_MODEL_CONTROL_FRAME_VERSION
        || frame->type != NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA
        || frame->flags != 0u || frame->stream_or_cell_id != 0u) {
        return NINLIL_V1_USB_BRIDGE_OK;
    }
    (void)memset(&envelope, 0, sizeof(envelope));
    if (ninlil_nvb1_decode(frame->payload, frame->payload_length, &envelope)
        != NINLIL_NVB1_OK) {
        return NINLIL_V1_USB_BRIDGE_OK;
    }
    if (envelope.kind == NINLIL_NVB1_KIND_STATUS) {
        return handle_status(bridge, &envelope);
    }

    if (bridge->tx_sequence_exhausted != 0u
        || bridge->remote_operation_exhausted != 0u
        || envelope.operation_id == UINT64_MAX
        || envelope.operation_id != bridge->next_remote_operation_id) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (envelope.operation_id == UINT64_MAX - 1u) {
        bridge->remote_operation_exhausted = 1u;
    } else {
        bridge->next_remote_operation_id += 1u;
    }

    if (envelope.kind == NINLIL_NVB1_KIND_BINDING_SET) {
        result = handle_binding_request(bridge, &envelope);
    } else if (envelope.kind == NINLIL_NVB1_KIND_FABRIC_PACKET) {
        result = handle_fabric_request(bridge, &envelope);
    } else if (envelope.kind == NINLIL_NVB1_KIND_BOARD_INFO) {
        result = handle_board_info(bridge, &envelope);
    } else {
        result = NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    if (result != NINLIL_V1_USB_BRIDGE_OK) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    return NINLIL_V1_USB_BRIDGE_OK;
}

static void release_frame_payload(ninlil_v1_usb_bridge_t *bridge)
{
    ninlil_model_control_frame_parser_reset(&bridge->parser);
    bridge_zero(bridge->parser_payload, sizeof(bridge->parser_payload));
}

static ninlil_v1_usb_bridge_status_t feed_bytes(
    ninlil_v1_usb_bridge_t *bridge,
    const uint8_t *bytes,
    uint32_t length,
    uint32_t *out_consumed)
{
    ninlil_model_control_frame_result_t frame_result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    ninlil_v1_usb_bridge_status_t result;

    if (ninlil_model_control_frame_parser_feed(&bridge->parser,
            bytes, length, out_consumed, &frame_result)
        != NINLIL_OK) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (bridge->parser.window_length > sizeof(bridge->parser.window)) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    bridge_zero(bridge->parser.window + bridge->parser.window_length,
        sizeof(bridge->parser.window) - bridge->parser.window_length);
    if (bridge->parser.frame_ready == 0u) {
        return NINLIL_V1_USB_BRIDGE_OK;
    }
    result = handle_frame(bridge);
    release_frame_payload(bridge);
    return result;
}

static int stream_ticket_valid(const ninlil_v1_usb_bridge_t *bridge)
{
    return bridge->stream->ops->link(bridge->stream)
            == NINLIL_BYTE_STREAM_LINK_UP
        && bridge->stream->ops->link_generation(bridge->stream)
            == bridge->active_generation;
}

static void expire_slot(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_v1_usb_bridge_slot_t *slot,
    uint64_t now_ms)
{
    int untransmitted;

    if (slot->state != SLOT_PENDING || now_ms < slot->deadline_ms) {
        return;
    }
    untransmitted = bridge->tx_wire_length != 0u
        && bridge->tx_is_local_request != 0u
        && bridge->tx_operation_id == slot->operation_id
        && slot->link_generation == bridge->active_generation
        && slot->sent == 0u;
    if (untransmitted) {
        clear_tx(bridge);
    }
    complete_slot(slot, NINLIL_V1_USB_BRIDGE_COMPLETION_TIMEOUT, 0u, 0u);
    if (untransmitted) {
        /* This allocated request ID never reached the peer; do not create a gap. */
        fence_generation(bridge);
    }
}

static void expire_slots(ninlil_v1_usb_bridge_t *bridge, uint64_t now_ms)
{
    uint8_t i;

    expire_slot(bridge, &bridge->binding_slot, now_ms);
    for (i = 0u; i < NINLIL_V1_USB_BRIDGE_PACKET_SLOTS; ++i) {
        expire_slot(bridge, &bridge->packet_slots[i], now_ms);
    }
}

static ninlil_v1_usb_bridge_status_t flush_tx(
    ninlil_v1_usb_bridge_t *bridge)
{
    ninlil_byte_stream_error_t error;
    ninlil_byte_stream_status_t stream_status;
    uint32_t accepted = 0u;
    uint32_t wire_length = bridge->tx_wire_length;
    uint64_t operation_id = bridge->tx_operation_id;
    uint8_t is_local_request = bridge->tx_is_local_request;
    uint8_t tx_kind = bridge->tx_kind;

    (void)memset(&error, 0, sizeof(error));
    stream_status = bridge->stream->ops->write(bridge->stream,
        bridge->tx_wire, wire_length, &accepted, &error);
    if (stream_status == NINLIL_BYTE_STREAM_WRONG_OWNER) {
        return NINLIL_V1_USB_BRIDGE_WRONG_OWNER;
    }
    if (!stream_ticket_valid(bridge)) {
        fence_observed_generation(bridge);
        return stream_status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
                || stream_status == NINLIL_BYTE_STREAM_CLOSED
            ? NINLIL_V1_USB_BRIDGE_LINK_DOWN
            : NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (stream_status == NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        if (accepted != 0u) {
            fence_observed_generation(bridge);
            return NINLIL_V1_USB_BRIDGE_FENCED;
        }
        return NINLIL_V1_USB_BRIDGE_WOULD_BLOCK;
    }
    if (stream_status != NINLIL_BYTE_STREAM_OK
        || accepted != wire_length) {
        fence_observed_generation(bridge);
        return stream_status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
                || stream_status == NINLIL_BYTE_STREAM_CLOSED
            ? NINLIL_V1_USB_BRIDGE_LINK_DOWN
            : NINLIL_V1_USB_BRIDGE_IO_ERROR;
    }
    if (is_local_request != 0u) {
        ninlil_v1_usb_bridge_slot_t *slot = find_slot(bridge,
            bridge->active_generation, operation_id);
        if (slot == NULL || slot->state != SLOT_PENDING) {
            fence_observed_generation(bridge);
            return NINLIL_V1_USB_BRIDGE_FENCED;
        }
        slot->sent = 1u;
    } else if (tx_kind == NINLIL_NVB1_KIND_BOARD_INFO) {
        bridge->board_info_sent = 1u;
    }
    clear_tx(bridge);
    if (bridge->tx_sequence == UINT32_MAX - 1u) {
        bridge->tx_sequence_exhausted = 1u;
    } else {
        bridge->tx_sequence += 1u;
    }
    return NINLIL_V1_USB_BRIDGE_OK;
}

static ninlil_v1_usb_bridge_status_t map_poll_failure(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_byte_stream_status_t status)
{
    if (status == NINLIL_BYTE_STREAM_WRONG_OWNER) {
        return NINLIL_V1_USB_BRIDGE_WRONG_OWNER;
    }
    if (status == NINLIL_BYTE_STREAM_RX_OVERFLOW) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
        || status == NINLIL_BYTE_STREAM_CLOSED) {
        fence_generation(bridge);
        return NINLIL_V1_USB_BRIDGE_LINK_DOWN;
    }
    fence_generation(bridge);
    return NINLIL_V1_USB_BRIDGE_IO_ERROR;
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_init(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_v1_usb_bridge_config_t *config)
{
    if (bridge == NULL || config == NULL || !role_valid(config->role)
        || config->stream == NULL || config->stream->ops == NULL
        || config->stream->ops->read == NULL
        || config->stream->ops->write == NULL
        || config->stream->ops->poll == NULL
        || config->stream->ops->link == NULL
        || config->stream->ops->link_generation == NULL
        || !ranges_disjoint(bridge, sizeof(*bridge), config, sizeof(*config))
        || !ranges_disjoint(bridge, sizeof(*bridge),
            config->stream, sizeof(*config->stream))) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    (void)memset(bridge, 0, sizeof(*bridge));
    bridge->magic = NINLIL_V1_USB_BRIDGE_MAGIC;
    bridge->role = config->role;
    bridge->stream = config->stream;
    bridge->provisioner = config->provisioner;
    bridge->pair_installed = config->pair_installed;
    bridge->fabric_handoff = config->fabric_handoff;
    bridge->board_info = config->board_info;
    bridge->callback_user = config->callback_user;
    if (ninlil_model_control_frame_parser_init(&bridge->parser,
            bridge->parser_payload, sizeof(bridge->parser_payload))
        != NINLIL_OK) {
        bridge_zero(bridge, sizeof(*bridge));
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    return NINLIL_V1_USB_BRIDGE_OK;
}

static ninlil_v1_usb_bridge_status_t submit_request(
    ninlil_v1_usb_bridge_t *bridge,
    uint8_t kind,
    const uint8_t *payload,
    size_t payload_length,
    uint64_t deadline_ms,
    ninlil_v1_usb_bridge_handle_t *out_handle)
{
    ninlil_v1_usb_bridge_slot_t *slot;
    ninlil_v1_usb_bridge_status_t result;
    uint64_t operation_id;

    if (!bridge_known(bridge) || out_handle == NULL || payload == NULL
        || deadline_ms == 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    if (!ranges_disjoint(bridge, sizeof(*bridge),
            out_handle, sizeof(*out_handle))
        || !ranges_disjoint(payload, payload_length,
            out_handle, sizeof(*out_handle))
        || !ranges_disjoint(bridge, sizeof(*bridge),
            payload, payload_length)) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    (void)memset(out_handle, 0, sizeof(*out_handle));
    if (bridge->in_step != 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    if (bridge->active_generation == 0u) {
        return NINLIL_V1_USB_BRIDGE_LINK_DOWN;
    }
    if (bridge->generation_fenced != 0u) {
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (bridge->tx_wire_length != 0u) {
        return NINLIL_V1_USB_BRIDGE_BUSY;
    }
    if (bridge->tx_sequence_exhausted != 0u
        || bridge->next_local_operation_id == UINT64_MAX) {
        return NINLIL_V1_USB_BRIDGE_SEQUENCE_EXHAUSTED;
    }
    if (kind == NINLIL_NVB1_KIND_BINDING_SET) {
        if (bridge->role != NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER) {
            return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
        }
        if (bridge->board_info_received == 0u) {
            return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
        }
        slot = &bridge->binding_slot;
        if (slot->state != SLOT_EMPTY) {
            return NINLIL_V1_USB_BRIDGE_BUSY;
        }
    } else {
        slot = empty_packet_slot(bridge);
        if (slot == NULL) {
            return NINLIL_V1_USB_BRIDGE_BUSY;
        }
    }

    operation_id = bridge->next_local_operation_id;
    result = build_tx(bridge, kind, operation_id,
        payload, payload_length, 1u);
    if (result != NINLIL_V1_USB_BRIDGE_OK) {
        return result;
    }
    (void)memset(slot, 0, sizeof(*slot));
    slot->state = SLOT_PENDING;
    slot->kind = kind;
    slot->link_generation = bridge->active_generation;
    slot->operation_id = operation_id;
    slot->deadline_ms = deadline_ms;
    if (kind == NINLIL_NVB1_KIND_BINDING_SET) {
        slot->expected_pair_generation = get_u64_be(payload + 4u);
    }
    bridge->next_local_operation_id += 1u;
    out_handle->link_generation = bridge->active_generation;
    out_handle->operation_id = operation_id;
    return NINLIL_V1_USB_BRIDGE_OK;
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_submit_binding(
    ninlil_v1_usb_bridge_t *bridge,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint64_t deadline_ms,
    ninlil_v1_usb_bridge_handle_t *out_handle)
{
    return submit_request(bridge, NINLIL_NVB1_KIND_BINDING_SET,
        encoded_binding, encoded_length, deadline_ms, out_handle);
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_submit_fabric(
    ninlil_v1_usb_bridge_t *bridge,
    const uint8_t *encoded_packet,
    size_t encoded_length,
    uint64_t deadline_ms,
    ninlil_v1_usb_bridge_handle_t *out_handle)
{
    return submit_request(bridge, NINLIL_NVB1_KIND_FABRIC_PACKET,
        encoded_packet, encoded_length, deadline_ms, out_handle);
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_submit_board_info(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_nvb1_board_info_t *info)
{
    uint8_t payload[NINLIL_NVB1_BOARD_INFO_BYTES];
    ninlil_v1_usb_bridge_status_t result;
    uint64_t operation_id;

    if (!bridge_known(bridge) || info == NULL
        || bridge->role != NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD
        || !ranges_disjoint(bridge, sizeof(*bridge), info, sizeof(*info))) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    if (bridge->in_step != 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    if (bridge->active_generation == 0u) {
        return NINLIL_V1_USB_BRIDGE_LINK_DOWN;
    }
    if (bridge->generation_fenced != 0u) {
        return NINLIL_V1_USB_BRIDGE_FENCED;
    }
    if (bridge->tx_wire_length != 0u) {
        return NINLIL_V1_USB_BRIDGE_BUSY;
    }
    if (bridge->board_info_sent != 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    if (bridge->tx_sequence_exhausted != 0u
        || bridge->next_local_operation_id == UINT64_MAX) {
        return NINLIL_V1_USB_BRIDGE_SEQUENCE_EXHAUSTED;
    }
    if (ninlil_nvb1_board_info_encode(info, payload) != NINLIL_NVB1_OK) {
        bridge_zero(payload, sizeof(payload));
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    operation_id = bridge->next_local_operation_id;
    result = build_tx(bridge, NINLIL_NVB1_KIND_BOARD_INFO, operation_id,
        payload, sizeof(payload), 0u);
    bridge_zero(payload, sizeof(payload));
    if (result != NINLIL_V1_USB_BRIDGE_OK) {
        return result;
    }
    bridge->next_local_operation_id += 1u;
    return NINLIL_V1_USB_BRIDGE_OK;
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_step(
    ninlil_v1_usb_bridge_t *bridge,
    uint64_t now_ms,
    uint32_t poll_timeout_ms)
{
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    ninlil_byte_stream_error_t error;
    ninlil_byte_stream_status_t stream_status;
    ninlil_byte_stream_link_t link;
    uint64_t generation;
    ninlil_v1_usb_bridge_status_t result = NINLIL_V1_USB_BRIDGE_OK;
    uint32_t length = 0u;
    uint32_t consumed = 0u;

    if (!bridge_known(bridge)) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    if (bridge->in_step != 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    bridge->in_step = 1u;
    (void)memset(&error, 0, sizeof(error));
    stream_status = bridge->stream->ops->poll(bridge->stream,
        poll_timeout_ms, &events, &error);
    if (stream_status != NINLIL_BYTE_STREAM_OK
        && stream_status != NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        result = map_poll_failure(bridge, stream_status);
        goto done;
    }
    link = bridge->stream->ops->link(bridge->stream);
    generation = bridge->stream->ops->link_generation(bridge->stream);
    if (link != NINLIL_BYTE_STREAM_LINK_UP || generation == 0u) {
        fence_generation(bridge);
        result = NINLIL_V1_USB_BRIDGE_LINK_DOWN;
        goto done;
    }
    if (generation != bridge->active_generation) {
        start_generation(bridge, generation);
    } else if (bridge->generation_fenced != 0u) {
        result = NINLIL_V1_USB_BRIDGE_FENCED;
        goto done;
    }
    if ((events & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) != 0u) {
        fence_generation(bridge);
        result = NINLIL_V1_USB_BRIDGE_FENCED;
        goto done;
    }

    expire_slots(bridge, now_ms);
    if (bridge->generation_fenced != 0u) {
        result = NINLIL_V1_USB_BRIDGE_FENCED;
        goto done;
    }
    if (bridge->tx_wire_length != 0u) {
        result = flush_tx(bridge);
        if (result != NINLIL_V1_USB_BRIDGE_OK) {
            goto done;
        }
    }

    if (bridge->rx_residual_length != 0u) {
        uint32_t residual_length = bridge->rx_residual_length;
        result = feed_bytes(bridge, bridge->rx_residual,
            residual_length, &consumed);
        if (result == NINLIL_V1_USB_BRIDGE_OK) {
            uint32_t remaining = residual_length - consumed;

            if (consumed < residual_length) {
                (void)memmove(bridge->rx_residual,
                    bridge->rx_residual + consumed,
                    remaining);
            }
            bridge_zero(bridge->rx_residual + remaining,
                sizeof(bridge->rx_residual) - remaining);
            bridge->rx_residual_length = remaining;
        }
        goto done;
    }

    (void)memset(&error, 0, sizeof(error));
    bridge_zero(bridge->rx_chunk, sizeof(bridge->rx_chunk));
    stream_status = bridge->stream->ops->read(bridge->stream,
        bridge->rx_chunk, sizeof(bridge->rx_chunk), &length, &error);
    if (stream_status == NINLIL_BYTE_STREAM_WRONG_OWNER) {
        result = NINLIL_V1_USB_BRIDGE_WRONG_OWNER;
        goto done;
    }
    if (!stream_ticket_valid(bridge)) {
        fence_observed_generation(bridge);
        result = stream_status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
                || stream_status == NINLIL_BYTE_STREAM_CLOSED
            ? NINLIL_V1_USB_BRIDGE_LINK_DOWN
            : NINLIL_V1_USB_BRIDGE_FENCED;
        goto done;
    }
    if (stream_status == NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        if (length != 0u) {
            fence_generation(bridge);
            result = NINLIL_V1_USB_BRIDGE_FENCED;
        } else {
            result = NINLIL_V1_USB_BRIDGE_OK;
        }
        goto done;
    }
    if (stream_status != NINLIL_BYTE_STREAM_OK) {
        fence_observed_generation(bridge);
        result = stream_status == NINLIL_BYTE_STREAM_RX_OVERFLOW
            ? NINLIL_V1_USB_BRIDGE_FENCED
            : (stream_status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
                    || stream_status == NINLIL_BYTE_STREAM_CLOSED
                ? NINLIL_V1_USB_BRIDGE_LINK_DOWN
                : NINLIL_V1_USB_BRIDGE_IO_ERROR);
        goto done;
    }
    if (length > sizeof(bridge->rx_chunk)) {
        fence_observed_generation(bridge);
        result = NINLIL_V1_USB_BRIDGE_FENCED;
        goto done;
    }
    if (length == 0u) {
        result = NINLIL_V1_USB_BRIDGE_OK;
        goto done;
    }
    result = feed_bytes(bridge, bridge->rx_chunk, length, &consumed);
    if (result == NINLIL_V1_USB_BRIDGE_OK && consumed < length) {
        bridge_zero(bridge->rx_residual, sizeof(bridge->rx_residual));
        (void)memcpy(bridge->rx_residual,
            bridge->rx_chunk + consumed, length - consumed);
        bridge->rx_residual_length = length - consumed;
    }

done:
    bridge_zero(bridge->rx_chunk, sizeof(bridge->rx_chunk));
    bridge->in_step = 0u;
    return result;
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_take_completion(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_v1_usb_bridge_handle_t handle,
    ninlil_v1_usb_bridge_completion_t *out_completion)
{
    ninlil_v1_usb_bridge_slot_t *slot;

    if (!bridge_known(bridge) || out_completion == NULL
        || handle.link_generation == 0u || handle.operation_id == 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    if (!ranges_disjoint(bridge, sizeof(*bridge),
            out_completion, sizeof(*out_completion))) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    (void)memset(out_completion, 0, sizeof(*out_completion));
    if (bridge->in_step != 0u) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    slot = find_slot(bridge, handle.link_generation, handle.operation_id);
    if (slot == NULL) {
        return NINLIL_V1_USB_BRIDGE_NOT_FOUND;
    }
    if (slot->state == SLOT_PENDING) {
        return NINLIL_V1_USB_BRIDGE_WOULD_BLOCK;
    }
    if (slot->state != SLOT_COMPLETE) {
        return NINLIL_V1_USB_BRIDGE_NOT_FOUND;
    }
    *out_completion = slot->completion;
    bridge_zero(slot, sizeof(*slot));
    return NINLIL_V1_USB_BRIDGE_OK;
}

int ninlil_v1_usb_bridge_is_fenced(
    const ninlil_v1_usb_bridge_t *bridge)
{
    return bridge_known(bridge) && bridge->generation_fenced != 0u ? 1 : 0;
}

void ninlil_v1_usb_bridge_clear(ninlil_v1_usb_bridge_t *bridge)
{
    if (bridge != NULL) {
        bridge_zero(bridge, sizeof(*bridge));
    }
}
