/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_usb_bridge.h"
#include "fake_byte_stream.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 0;                                                          \
        }                                                                      \
    } while (0)

typedef struct callback_state {
    uint32_t fabric_calls;
    uint32_t fabric_status;
    size_t last_length;
    uint8_t last_first;
    ninlil_v1_usb_bridge_status_t board_info_status;
} callback_state_t;

static int all_zero(const void *memory, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)memory;
    size_t i;

    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static uint32_t fabric_handoff(
    void *user, const uint8_t *packet, size_t length)
{
    callback_state_t *state = (callback_state_t *)user;

    state->fabric_calls += 1u;
    state->last_length = length;
    state->last_first = packet[0];
    return state->fabric_status;
}

static ninlil_v1_usb_bridge_status_t board_info_handoff(
    void *user, const ninlil_nvb1_board_info_t *info)
{
    callback_state_t *state = (callback_state_t *)user;

    (void)info;
    return state->board_info_status;
}

static int setup_bridge(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_fake_byte_stream_t *fake,
    ninlil_v1_usb_bridge_role_t role,
    callback_state_t *callbacks)
{
    ninlil_v1_usb_bridge_config_t config;

    ninlil_fake_byte_stream_init(fake);
    ninlil_fake_byte_stream_open_up(fake, 1u);
    (void)memset(&config, 0, sizeof(config));
    config.role = role;
    config.stream = &fake->view;
    config.fabric_handoff = callbacks == NULL ? NULL : fabric_handoff;
    config.board_info = role == NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER
            && callbacks != NULL
        ? board_info_handoff
        : NULL;
    config.callback_user = callbacks;
    REQUIRE(ninlil_v1_usb_bridge_init(bridge, &config)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(bridge, 1u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(bridge->active_generation == 1u);
    return 1;
}

static int encode_wire(
    uint8_t kind,
    uint64_t operation_id,
    uint32_t sequence,
    uint8_t frame_type,
    uint32_t stream_id,
    const uint8_t *payload,
    size_t payload_length,
    uint8_t out[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES],
    uint32_t *out_length)
{
    uint8_t nvb[NINLIL_NVB1_ENVELOPE_MAX];
    size_t nvb_length = 0u;
    ninlil_nvb1_envelope_t envelope;
    ninlil_model_control_frame_fields_t fields;

    (void)memset(&envelope, 0, sizeof(envelope));
    envelope.kind = kind;
    envelope.operation_id = operation_id;
    envelope.payload = payload;
    envelope.payload_length = payload_length;
    REQUIRE(ninlil_nvb1_encode(&envelope, nvb, sizeof(nvb), &nvb_length)
        == NINLIL_NVB1_OK);
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = frame_type;
    fields.stream_or_cell_id = stream_id;
    fields.sequence = sequence;
    fields.payload.data = nvb;
    fields.payload.length = (uint32_t)nvb_length;
    REQUIRE(ninlil_model_control_frame_encode(&fields, out,
        NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES, out_length) == NINLIL_OK);
    return 1;
}

static int encode_status_wire(
    uint64_t operation_id,
    uint32_t sequence,
    uint32_t code,
    uint64_t pair_generation,
    uint8_t out[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES],
    uint32_t *out_length)
{
    ninlil_nvb1_local_status_t status;
    uint8_t payload[NINLIL_NVB1_STATUS_BYTES];

    status.code = code;
    status.pair_generation = pair_generation;
    REQUIRE(ninlil_nvb1_status_encode(&status, payload) == NINLIL_NVB1_OK);
    return encode_wire(NINLIL_NVB1_KIND_STATUS, operation_id, sequence,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u,
        payload, sizeof(payload), out, out_length);
}

static int inject_frame(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_fake_byte_stream_t *fake,
    const uint8_t *wire,
    uint32_t wire_length,
    ninlil_v1_usb_bridge_status_t expected)
{
    unsigned int i;
    ninlil_v1_usb_bridge_status_t status = NINLIL_V1_USB_BRIDGE_OK;

    REQUIRE(ninlil_fake_byte_stream_inject_rx(fake, wire, wire_length));
    for (i = 0u; i < 12u && fake->rx_len != 0u; ++i) {
        status = ninlil_v1_usb_bridge_step(bridge, 2u + i, 0u);
        if (status == NINLIL_V1_USB_BRIDGE_FENCED) {
            break;
        }
        REQUIRE(status == NINLIL_V1_USB_BRIDGE_OK);
    }
    REQUIRE(status == expected);
    return 1;
}

static int inject_board_info(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_fake_byte_stream_t *fake,
    uint64_t operation_id,
    uint32_t sequence,
    ninlil_v1_usb_bridge_status_t expected)
{
    ninlil_nvb1_board_info_t info;
    uint8_t payload[NINLIL_NVB1_BOARD_INFO_BYTES];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    (void)memset(&info, 0, sizeof(info));
    (void)memset(info.clock_epoch_id, 0x42, sizeof(info.clock_epoch_id));
    info.clock_now_ms = 41u;
    info.clock_trust = 1u;
    REQUIRE(ninlil_nvb1_board_info_encode(&info, payload)
        == NINLIL_NVB1_OK);
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_BOARD_INFO, operation_id, sequence,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u,
        payload, sizeof(payload), wire, &wire_length));
    REQUIRE(inject_frame(bridge, fake, wire, wire_length, expected));
    return 1;
}

static int decode_status_tx(
    ninlil_fake_byte_stream_t *fake,
    uint64_t expected_operation_id,
    uint32_t expected_code)
{
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length;
    ninlil_model_control_frame_view_t frame;
    ninlil_model_control_frame_result_t frame_result;
    ninlil_nvb1_envelope_t envelope;
    ninlil_nvb1_local_status_t status;

    wire_length = ninlil_fake_byte_stream_take_tx(fake, wire, sizeof(wire));
    REQUIRE(wire_length != 0u);
    REQUIRE(ninlil_model_control_frame_decode(
        (ninlil_bytes_view_t){wire, wire_length}, &frame, &frame_result)
        == NINLIL_OK);
    REQUIRE(frame_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
    REQUIRE(ninlil_nvb1_decode(frame.payload, frame.payload_length, &envelope)
        == NINLIL_NVB1_OK);
    REQUIRE(envelope.kind == NINLIL_NVB1_KIND_STATUS);
    REQUIRE(envelope.operation_id == expected_operation_id);
    REQUIRE(ninlil_nvb1_status_decode(envelope.payload, &status)
        == NINLIL_NVB1_OK);
    REQUIRE(status.code == expected_code);
    return 1;
}

static int test_bidirectional_fabric_and_status(void)
{
    ninlil_v1_usb_bridge_t host;
    ninlil_v1_usb_bridge_t board;
    ninlil_fake_byte_stream_t host_stream;
    ninlil_fake_byte_stream_t board_stream;
    callback_state_t host_callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    callback_state_t board_callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    ninlil_v1_usb_bridge_handle_t handle;
    ninlil_v1_usb_bridge_completion_t completion;
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length;
    unsigned int i;

    (void)memset(packet, 0x31, sizeof(packet));
    REQUIRE(setup_bridge(&host, &host_stream,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &host_callbacks));
    REQUIRE(setup_bridge(&board, &board_stream,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &board_callbacks));
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&host, packet,
        sizeof(packet), 100u, &handle) == NINLIL_V1_USB_BRIDGE_OK);

    for (i = 0u; i < 24u; ++i) {
        REQUIRE(ninlil_v1_usb_bridge_step(&host, 2u + i, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        wire_length = ninlil_fake_byte_stream_take_tx(
            &host_stream, wire, sizeof(wire));
        if (wire_length != 0u) {
            REQUIRE(ninlil_fake_byte_stream_inject_rx(
                &board_stream, wire, wire_length));
        }
        REQUIRE(ninlil_v1_usb_bridge_step(&board, 2u + i, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        wire_length = ninlil_fake_byte_stream_take_tx(
            &board_stream, wire, sizeof(wire));
        if (wire_length != 0u) {
            REQUIRE(ninlil_fake_byte_stream_inject_rx(
                &host_stream, wire, wire_length));
        }
        if (ninlil_v1_usb_bridge_take_completion(&host, handle, &completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            REQUIRE(completion.reason
                == NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS);
            REQUIRE(completion.remote_status_code
                == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);
            break;
        }
    }
    REQUIRE(i < 24u);
    REQUIRE(board_callbacks.fabric_calls == 1u);
    REQUIRE(board_callbacks.last_length == sizeof(packet));
    REQUIRE(board_callbacks.last_first == 0x31u);

    packet[0] = 0x62u;
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&board, packet,
        sizeof(packet), 200u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < 24u; ++i) {
        REQUIRE(ninlil_v1_usb_bridge_step(&board, 30u + i, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        wire_length = ninlil_fake_byte_stream_take_tx(
            &board_stream, wire, sizeof(wire));
        if (wire_length != 0u) {
            REQUIRE(ninlil_fake_byte_stream_inject_rx(
                &host_stream, wire, wire_length));
        }
        REQUIRE(ninlil_v1_usb_bridge_step(&host, 30u + i, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        wire_length = ninlil_fake_byte_stream_take_tx(
            &host_stream, wire, sizeof(wire));
        if (wire_length != 0u) {
            REQUIRE(ninlil_fake_byte_stream_inject_rx(
                &board_stream, wire, wire_length));
        }
        if (ninlil_v1_usb_bridge_take_completion(&board, handle, &completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            REQUIRE(completion.remote_status_code
                == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);
            break;
        }
    }
    REQUIRE(i < 24u);
    REQUIRE(host_callbacks.fabric_calls == 1u);
    REQUIRE(host_callbacks.last_first == 0x62u);
    return 1;
}

static int test_sequence_and_operation_fences(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    callback_state_t callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    (void)memset(packet, 0x44, sizeof(packet));
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 1u, 1u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, packet, sizeof(packet),
        wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_FENCED));
    REQUIRE(callbacks.fabric_calls == 0u);

    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 2u, 0u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, packet, sizeof(packet),
        wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_FENCED));
    REQUIRE(callbacks.fabric_calls == 0u);

    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 1u, UINT32_MAX,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, packet, sizeof(packet),
        wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_FENCED));
    return 1;
}

static int test_fixed_field_consumes_sequence(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    callback_state_t callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    (void)memset(packet, 0x55, sizeof(packet));
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 1u, 0u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_PING, 0u, packet, sizeof(packet),
        wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(callbacks.fabric_calls == 0u);
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 1u, 1u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, packet, sizeof(packet),
        wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(callbacks.fabric_calls == 1u);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 20u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(decode_status_tx(&fake, 1u,
        NINLIL_NVB1_STATUS_ACCEPTED_LOCAL));
    return 1;
}

static int test_status_completion_duplicate_and_wrong_direction(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    callback_state_t callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    ninlil_v1_usb_bridge_handle_t handle;
    ninlil_v1_usb_bridge_completion_t completion;
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t binding[NINLIL_NVB1_BINDING_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length;

    (void)memset(packet, 0x61, sizeof(packet));
    (void)memset(binding, 0x71, sizeof(binding));
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &callbacks));
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 100u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_fake_byte_stream_take_tx(&fake, wire, sizeof(wire)) != 0u);
    REQUIRE(encode_status_wire(handle.operation_id, 0u,
        NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, handle, &completion)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(completion.remote_status_code
        == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL);

    REQUIRE(encode_status_wire(handle.operation_id, 1u,
        NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(!ninlil_v1_usb_bridge_is_fenced(&bridge));

    REQUIRE(encode_wire(NINLIL_NVB1_KIND_BINDING_SET, 1u, 2u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, binding, sizeof(binding),
        wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(all_zero(bridge.parser_payload, sizeof(bridge.parser_payload)));
    REQUIRE(all_zero(bridge.parser.window, sizeof(bridge.parser.window)));
    REQUIRE(all_zero(bridge.rx_chunk, sizeof(bridge.rx_chunk)));
    REQUIRE(all_zero(bridge.rx_residual, sizeof(bridge.rx_residual)));
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 30u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(decode_status_tx(&fake, 1u, NINLIL_NVB1_STATUS_REJECTED));
    return 1;
}

static int test_mid_io_generation_fence(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    callback_state_t callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    ninlil_v1_usb_bridge_handle_t handle;
    ninlil_v1_usb_bridge_completion_t completion;
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    (void)memset(packet, 0xa1, sizeof(packet));
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &callbacks));
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 100u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    ninlil_fake_byte_stream_bump_gen_on_next_write(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    REQUIRE(bridge.active_generation == fake.link_generation);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, handle, &completion)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(completion.reason
        == NINLIL_V1_USB_BRIDGE_COMPLETION_LINK_FENCED);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 3u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    ninlil_fake_byte_stream_link_up_again(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 4u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(!ninlil_v1_usb_bridge_is_fenced(&bridge));
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 200u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(handle.operation_id == 1u);

    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &callbacks));
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 100u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    ninlil_fake_byte_stream_bump_gen_on_next_write(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    REQUIRE(bridge.active_generation == fake.link_generation);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));

    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    ninlil_fake_byte_stream_bump_gen_on_next_read(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    REQUIRE(bridge.active_generation == fake.link_generation);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));

    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    callbacks.fabric_calls = 0u;
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 1u, 0u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, packet, sizeof(packet),
        wire, &wire_length));
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&fake, wire, wire_length));
    ninlil_fake_byte_stream_bump_gen_on_next_read(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    REQUIRE(bridge.active_generation == fake.link_generation);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));
    REQUIRE(callbacks.fabric_calls == 0u);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 3u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    ninlil_fake_byte_stream_link_up_again(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 4u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(callbacks.fabric_calls == 1u);

    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, &callbacks));
    ninlil_fake_byte_stream_force_read_would_block_nonzero_once(&fake);
    ninlil_fake_byte_stream_bump_gen_on_next_read(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    REQUIRE(bridge.active_generation == fake.link_generation);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));
    return 1;
}

static int test_corrupt_frame_tail_zeroization(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    uint8_t binding[NINLIL_NVB1_BINDING_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    (void)memset(binding, 0xd1, sizeof(binding));
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD, NULL));
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_BINDING_SET, 1u, 0u,
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA, 0u, binding, sizeof(binding),
        wire, &wire_length));
    wire[wire_length - 1u] ^= 1u;
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(bridge.parser.window_length <= sizeof(bridge.parser.window));
    REQUIRE(all_zero(bridge.parser.window + bridge.parser.window_length,
        sizeof(bridge.parser.window) - bridge.parser.window_length));
    REQUIRE(all_zero(bridge.parser_payload, sizeof(bridge.parser_payload)));
    REQUIRE(all_zero(bridge.rx_chunk, sizeof(bridge.rx_chunk)));
    REQUIRE(all_zero(bridge.rx_residual, sizeof(bridge.rx_residual)));
    REQUIRE(bridge.rx_sequence == 0u);
    return 1;
}

static int test_capacity_timeout_and_reconnect(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    callback_state_t callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    ninlil_v1_usb_bridge_handle_t handles[5];
    ninlil_v1_usb_bridge_completion_t completion;
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint64_t first_generation;
    uint8_t i;

    (void)memset(packet, 0x81, sizeof(packet));
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &callbacks));
    first_generation = bridge.active_generation;
    for (i = 0u; i < NINLIL_V1_USB_BRIDGE_PACKET_SLOTS; ++i) {
        REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
            sizeof(packet), 100u, &handles[i]) == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u + i, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(ninlil_fake_byte_stream_take_tx(&fake, wire, sizeof(wire))
            != 0u);
    }
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 100u, &handles[4]) == NINLIL_V1_USB_BRIDGE_BUSY);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 100u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < NINLIL_V1_USB_BRIDGE_PACKET_SLOTS; ++i) {
        REQUIRE(ninlil_v1_usb_bridge_take_completion(
            &bridge, handles[i], &completion) == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(completion.reason == NINLIL_V1_USB_BRIDGE_COMPLETION_TIMEOUT);
    }

    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 200u, &handles[0]) == NINLIL_V1_USB_BRIDGE_OK);
    ninlil_fake_byte_stream_link_down(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 101u, 0u)
        == NINLIL_V1_USB_BRIDGE_LINK_DOWN);
    REQUIRE(ninlil_v1_usb_bridge_take_completion(
        &bridge, handles[0], &completion) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(completion.reason
        == NINLIL_V1_USB_BRIDGE_COMPLETION_LINK_FENCED);
    ninlil_fake_byte_stream_link_up_again(&fake);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 102u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(bridge.active_generation != first_generation);
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 300u, &handles[0]) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(handles[0].operation_id == 1u);
    return 1;
}

static int test_binding_generation_and_unsent_timeout(void)
{
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t fake;
    callback_state_t callbacks = {
        0u, NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 0u, 0u};
    ninlil_v1_usb_bridge_handle_t handle;
    ninlil_v1_usb_bridge_completion_t completion;
    uint8_t binding[NINLIL_NVB1_BINDING_MIN];
    uint8_t packet[NINLIL_NVB1_FABRIC_MIN];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length;

    (void)memset(binding, 0, sizeof(binding));
    binding[11] = 1u;
    (void)memset(packet, 0x91, sizeof(packet));
    callbacks.board_info_status = NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &callbacks));
    REQUIRE(inject_board_info(&bridge, &fake, 1u, 0u,
        NINLIL_V1_USB_BRIDGE_FENCED));
    REQUIRE(bridge.board_info_received == 0u);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));

    callbacks.board_info_status = NINLIL_V1_USB_BRIDGE_OK;
    REQUIRE(setup_bridge(&bridge, &fake,
        NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER, &callbacks));
    REQUIRE(sizeof(bridge) <= NINLIL_V1_USB_BRIDGE_OBJECT_CEILING_BYTES);
    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&bridge, binding,
        sizeof(binding), 100u, &handle)
        == NINLIL_V1_USB_BRIDGE_INVALID_STATE);
    REQUIRE(inject_board_info(&bridge, &fake, 1u, 0u,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(bridge.board_info_received != 0u);
    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&bridge, binding,
        sizeof(binding), 100u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 2u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_fake_byte_stream_take_tx(&fake, wire, sizeof(wire)) != 0u);
    REQUIRE(encode_status_wire(handle.operation_id, 1u,
        NINLIL_NVB1_STATUS_INSTALLED, 2u, wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, handle, &completion)
        == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK);
    REQUIRE(encode_status_wire(handle.operation_id, 2u,
        NINLIL_NVB1_STATUS_INSTALLED, 1u, wire, &wire_length));
    REQUIRE(inject_frame(&bridge, &fake, wire, wire_length,
        NINLIL_V1_USB_BRIDGE_OK));
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, handle, &completion)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(completion.pair_generation == 1u);

    ninlil_fake_byte_stream_set_force_write_would_block(&fake, 1);
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&bridge, packet,
        sizeof(packet), 20u, &handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 20u, 0u)
        == NINLIL_V1_USB_BRIDGE_FENCED);
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, handle, &completion)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(completion.reason == NINLIL_V1_USB_BRIDGE_COMPLETION_TIMEOUT);
    REQUIRE(ninlil_v1_usb_bridge_is_fenced(&bridge));
    return 1;
}

int main(void)
{
    if (!test_bidirectional_fabric_and_status()
        || !test_sequence_and_operation_fences()
        || !test_fixed_field_consumes_sequence()
        || !test_status_completion_duplicate_and_wrong_direction()
        || !test_mid_io_generation_fence()
        || !test_corrupt_frame_tail_zeroization()
        || !test_capacity_timeout_and_reconnect()
        || !test_binding_generation_and_unsent_timeout()) {
        return 1;
    }
    (void)printf("v1_usb_bridge_test OK\n");
    return 0;
}
