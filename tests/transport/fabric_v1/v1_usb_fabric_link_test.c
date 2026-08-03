#include "v1_usb_fabric_link.h"

#include "fake_byte_stream.h"
#include "nfl1_codec.h"
#include "r7_crypto_openssl3.h"

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

typedef struct test_clock {
    ninlil_clock_ops_t ops;
    ninlil_time_sample_t now;
} test_clock_t;

static ninlil_port_status_t clock_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    test_clock_t *clock = (test_clock_t *)user;

    if (clock == NULL || out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    *out_sample = clock->now;
    return NINLIL_PORT_OK;
}

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;

    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_epoch(uint8_t out[16])
{
    (void)memset(out, 0, 16u);
    out[0] = 0xa0u;
    out[15] = 0x01u;
}

static void init_clock(test_clock_t *clock)
{
    (void)memset(clock, 0, sizeof(*clock));
    clock->ops.abi_version = NINLIL_ABI_VERSION;
    clock->ops.struct_size = (uint16_t)sizeof(clock->ops);
    clock->ops.user = clock;
    clock->ops.now = clock_now;
    clock->now.abi_version = NINLIL_ABI_VERSION;
    clock->now.struct_size = (uint16_t)sizeof(clock->now);
    fill_epoch(clock->now.clock_epoch_id.bytes);
    clock->now.now_ms = 1000u;
    clock->now.trust = NINLIL_CLOCK_TRUSTED;
}

static void fill_endpoint(ninlil_v1_lab_endpoint_t *endpoint, uint8_t seed)
{
    (void)memset(endpoint, 0, sizeof(*endpoint));
    fill_bytes(endpoint->runtime_id, 16u, seed);
    fill_bytes(endpoint->application_id, 16u, (uint8_t)(seed + 0x10u));
    fill_bytes(endpoint->device_id, 16u, (uint8_t)(seed + 0x20u));
    fill_bytes(endpoint->installation_id, 16u, (uint8_t)(seed + 0x30u));
    fill_bytes(endpoint->site_id, 16u, (uint8_t)(seed + 0x40u));
    endpoint->binding_epoch = 4u;
    endpoint->membership_epoch = 9u;
    endpoint->identity_flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    fill_epoch(endpoint->clock_epoch_id);
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static int make_binding(
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *binding,
    uint8_t encoded[NINLIL_V1_LAB_BINDING_MAX_BYTES],
    size_t *encoded_length,
    uint8_t peer_seed,
    uint64_t pair_generation)
{
    ninlil_v1_lab_service_row_t *row;

    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = 2u;
    binding->pair_generation = pair_generation;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, peer_seed);
    fill_bytes(binding->radio_site_domain_id, 16u, 0x90u);
    binding->radio_membership_epoch = 11u;
    binding->a_to_b_hop_context_id = 1u;
    binding->a_to_b_e2e_context_id = 1u;
    binding->b_to_a_hop_context_id = 1u;
    binding->b_to_a_e2e_context_id = 1u;
    fill_bytes(binding->a_to_b_hop_secret, 32u, 0xa0u);
    fill_bytes(binding->a_to_b_e2e_secret, 32u, 0xb0u);
    fill_bytes(binding->b_to_a_hop_secret, 32u, 0xc0u);
    fill_bytes(binding->b_to_a_e2e_secret, 32u, 0xd0u);
    row = &binding->services[0];
    row->slot = 1u;
    row->flow = NINLIL_V1_LAB_FLOW_A_TO_B;
    row->namespace_length = 3u;
    row->service_length = 4u;
    row->schema_length = 3u;
    row->descriptor_revision = 21u;
    fill_bytes(row->descriptor_digest, 32u, (uint8_t)(peer_seed + 0x40u));
    row->schema_major = 1u;
    row->family = NINLIL_FAMILY_DESIRED_STATE;
    row->direction = NINLIL_DIRECTION_DOWNLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    row->evidence_grace_ms = 500u;
    (void)memcpy(row->namespace_id, "lab", 3u);
    (void)memcpy(row->service_id, "text", 4u);
    (void)memcpy(row->schema_id, "bin", 3u);
    row = &binding->services[1];
    row->slot = 2u;
    row->flow = NINLIL_V1_LAB_FLOW_B_TO_A;
    row->namespace_length = 3u;
    row->service_length = 5u;
    row->schema_length = 3u;
    row->descriptor_revision = 22u;
    fill_bytes(row->descriptor_digest, 32u, (uint8_t)(peer_seed + 0x60u));
    row->schema_major = 1u;
    row->family = NINLIL_FAMILY_EVENT_FACT;
    row->direction = NINLIL_DIRECTION_UPLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    (void)memcpy(row->namespace_id, "lab", 3u);
    (void)memcpy(row->service_id, "event", 5u);
    (void)memcpy(row->schema_id, "bin", 3u);
    return ninlil_v1_lab_binding_finalize(crypto, binding)
                == NINLIL_V1_LAB_BINDING_OK
            && ninlil_v1_lab_binding_encode(crypto, binding, encoded,
                   NINLIL_V1_LAB_BINDING_MAX_BYTES, encoded_length)
                == NINLIL_V1_LAB_BINDING_OK;
}

static void set_source(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->source_runtime_id.bytes,
        endpoint->runtime_id, 16u);
    (void)memcpy(envelope->source_application_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(envelope->source_device_id.bytes,
        endpoint->device_id, 16u);
    (void)memcpy(envelope->source_installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(envelope->source_site_id.bytes, endpoint->site_id, 16u);
    envelope->source_binding_epoch = endpoint->binding_epoch;
    envelope->source_membership_epoch = endpoint->membership_epoch;
    envelope->source_flags = endpoint->identity_flags;
}

static void set_target(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->target_runtime_id.bytes,
        endpoint->runtime_id, 16u);
    (void)memcpy(envelope->target_application_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(envelope->target_device_id.bytes,
        endpoint->device_id, 16u);
    (void)memcpy(envelope->target_installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(envelope->target_site_id.bytes, endpoint->site_id, 16u);
    envelope->target_binding_epoch = endpoint->binding_epoch;
    envelope->target_membership_epoch = endpoint->membership_epoch;
    envelope->target_flags = endpoint->identity_flags;
}

static int make_application(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t *out,
    uint32_t *out_length)
{
    const ninlil_v1_lab_service_row_t *row = &binding->services[0];
    ninlil_fabric_private_nfl1_envelope_t envelope;
    static const uint8_t payload[] = "display:occupied";
    uint8_t digest[32];

    (void)memset(&envelope, 0, sizeof(envelope));
    envelope.api_version = NINLIL_ABI_VERSION;
    envelope.struct_size = (uint16_t)sizeof(envelope);
    envelope.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    fill_bytes(envelope.transaction_id.bytes, 16u, 0x01u);
    fill_bytes(envelope.attempt_id.bytes, 16u, 0x21u);
    set_source(&envelope, &binding->endpoint_a);
    set_target(&envelope, &binding->endpoint_b);
    (void)memcpy(envelope.authority_id.bytes,
        binding->endpoint_a.runtime_id, 16u);
    envelope.authority_term = binding->pair_generation;
    envelope.assignment_epoch = (uint32_t)binding->pair_generation;
    envelope.descriptor_revision = row->descriptor_revision;
    envelope.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(envelope.descriptor_digest.bytes,
        row->descriptor_digest, 32u);
    envelope.schema_major = row->schema_major;
    envelope.schema_minor = row->schema_minor;
    envelope.family = row->family;
    envelope.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    if (ninlil_r7_crypto_sha256(crypto, payload, sizeof(payload) - 1u,
            digest) != NINLIL_R7_CRYPTO_OK) {
        return 0;
    }
    (void)memcpy(envelope.content_digest.bytes, digest, 32u);
    envelope.generation = 42u;
    (void)memcpy(envelope.deadline_clock_epoch_id.bytes,
        binding->endpoint_a.clock_epoch_id, 16u);
    envelope.absolute_effect_deadline_ms = 90000u;
    envelope.evidence_grace_ms = row->evidence_grace_ms;
    envelope.required_evidence = NINLIL_EVIDENCE_APPLIED;
    (void)memcpy(envelope.route_policy_id.bytes, row->policy_id, 16u);
    envelope.route_policy_revision = binding->pair_generation;
    envelope.route_policy_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(envelope.route_policy_digest.bytes,
        row->path_policy_digest, 32u);
    (void)memcpy(envelope.selected_path_id.bytes,
        row->selected_path_id, 16u);
    envelope.path_selection_epoch = 77u;
    envelope.namespace_id.bytes = row->namespace_id;
    envelope.namespace_id.length = row->namespace_length;
    envelope.service_id.bytes = row->service_id;
    envelope.service_id.length = row->service_length;
    envelope.schema_id.bytes = row->schema_id;
    envelope.schema_id.length = row->schema_length;
    envelope.payload.bytes = payload;
    envelope.payload.length = (uint32_t)(sizeof(payload) - 1u);
    return ninlil_fabric_private_nfl1_encode(&envelope, out,
               NINLIL_V1_LAB_FABRIC_PACKET_MAX, out_length)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK;
}

static int make_receipt(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *application,
    uint32_t application_length,
    uint8_t *out,
    uint32_t *out_length,
    int wrong_path)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    if (ninlil_fabric_private_nfl1_decode(application, application_length,
            &workspace, &envelope, &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return 0;
    }
    envelope.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    set_source(&envelope, &binding->endpoint_b);
    set_target(&envelope, &binding->endpoint_a);
    envelope.receipt_stage = NINLIL_EVIDENCE_APPLIED;
    envelope.payload.bytes = NULL;
    envelope.payload.length = 0u;
    (void)memcpy(envelope.evidence_time_clock_epoch_id.bytes,
        binding->endpoint_b.clock_epoch_id, 16u);
    envelope.evidence_time_now_ms = 1600u;
    envelope.evidence_time_trust = NINLIL_CLOCK_TRUSTED;
    envelope.path_selection_epoch = 91u;
    if (wrong_path) {
        envelope.selected_path_id.bytes[0] ^= 0x80u;
    }
    return ninlil_fabric_private_nfl1_encode(&envelope, out,
               NINLIL_V1_LAB_FABRIC_PACKET_MAX, out_length)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK;
}

static int encode_wire(
    uint8_t kind,
    uint64_t operation_id,
    uint32_t sequence,
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
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = sequence;
    fields.payload.data = nvb;
    fields.payload.length = (uint32_t)nvb_length;
    REQUIRE(ninlil_model_control_frame_encode(&fields, out,
        NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES, out_length) == NINLIL_OK);
    return 1;
}

static int inject_wire(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_fake_byte_stream_t *stream,
    const uint8_t *wire,
    uint32_t wire_length,
    uint64_t now_ms)
{
    unsigned int i;

    REQUIRE(ninlil_fake_byte_stream_inject_rx(stream, wire, wire_length));
    for (i = 0u; i < 12u && stream->rx_len != 0u; ++i) {
        REQUIRE(ninlil_v1_usb_bridge_step(bridge, now_ms + i, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
    }
    REQUIRE(stream->rx_len == 0u);
    return 1;
}

static int inject_board_info(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_fake_byte_stream_t *stream)
{
    ninlil_nvb1_board_info_t info;
    uint8_t payload[NINLIL_NVB1_BOARD_INFO_BYTES];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    (void)memset(&info, 0, sizeof(info));
    fill_epoch(info.clock_epoch_id);
    info.clock_now_ms = 1000u;
    info.clock_trust = NINLIL_CLOCK_TRUSTED;
    REQUIRE(ninlil_nvb1_board_info_encode(&info, payload)
        == NINLIL_NVB1_OK);
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_BOARD_INFO, 1u, 0u,
        payload, sizeof(payload), wire, &wire_length));
    return inject_wire(bridge, stream, wire, wire_length, 1000u);
}

static int inject_status(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_fake_byte_stream_t *stream,
    uint64_t operation_id,
    uint32_t sequence,
    uint32_t code,
    uint64_t pair_generation,
    uint64_t now_ms)
{
    ninlil_nvb1_local_status_t status;
    uint8_t payload[NINLIL_NVB1_STATUS_BYTES];
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;

    status.code = code;
    status.pair_generation = pair_generation;
    REQUIRE(ninlil_nvb1_status_encode(&status, payload) == NINLIL_NVB1_OK);
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_STATUS, operation_id, sequence,
        payload, sizeof(payload), wire, &wire_length));
    return inject_wire(bridge, stream, wire, wire_length, now_ms);
}

static int test_controller_adapter(void)
{
    ninlil_r7_crypto_provider crypto;
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_binding_t second_binding;
    uint8_t encoded_binding[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    uint8_t second_encoded_binding[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t encoded_binding_length = 0u;
    size_t second_encoded_binding_length = 0u;
    test_clock_t clock;
    ninlil_v1_usb_fabric_link_t link;
    ninlil_v1_usb_bridge_t bridge;
    ninlil_fake_byte_stream_t stream;
    ninlil_v1_usb_bridge_config_t bridge_config;
    ninlil_v1_usb_bridge_handle_t binding_handle;
    ninlil_v1_usb_bridge_completion_t binding_completion;
    const ninlil_fabric_link_descriptor_v1_t *descriptor = NULL;
    const ninlil_fabric_link_descriptor_v1_t *second_descriptor = NULL;
    const ninlil_fabric_link_descriptor_v1_t *reverse_descriptor = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *ops = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *second_ops = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *reverse_ops = NULL;
    ninlil_fabric_packet_link_handle_t link_handle = NULL;
    ninlil_fabric_packet_view_v1_t packet;
    ninlil_tx_permit_t permit;
    ninlil_tx_permit_t second_permit;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    uint8_t application[NINLIL_V1_LAB_FABRIC_PACKET_MAX];
    uint32_t application_length = 0u;
    uint8_t receipt[NINLIL_V1_LAB_FABRIC_PACKET_MAX];
    uint32_t receipt_length = 0u;
    uint8_t wrong_path[NINLIL_V1_LAB_FABRIC_PACKET_MAX];
    uint32_t wrong_path_length = 0u;
    uint8_t wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t wire_length = 0u;
    const uint8_t *received = NULL;
    uint32_t received_length = 0u;
    void *receive_token = NULL;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(make_binding(&crypto, &binding, encoded_binding,
        &encoded_binding_length, 0x30u, 7u));
    REQUIRE(make_binding(&crypto, &second_binding, second_encoded_binding,
        &second_encoded_binding_length, 0x50u, 8u));
    REQUIRE(make_application(&crypto, &binding,
        application, &application_length));
    REQUIRE(make_receipt(&binding, application, application_length,
        receipt, &receipt_length, 0));
    REQUIRE(make_receipt(&binding, application, application_length,
        wrong_path, &wrong_path_length, 1));
    init_clock(&clock);

    REQUIRE(ninlil_v1_usb_fabric_link_prepare(&link)
        == NINLIL_V1_USB_FABRIC_LINK_OK);
    ninlil_fake_byte_stream_init(&stream);
    ninlil_fake_byte_stream_open_up(&stream, 1u);
    (void)memset(&bridge_config, 0, sizeof(bridge_config));
    bridge_config.role = NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER;
    bridge_config.stream = &stream.view;
    bridge_config.fabric_handoff = ninlil_v1_usb_fabric_link_handoff;
    bridge_config.board_info = ninlil_v1_usb_fabric_link_board_info_handoff;
    bridge_config.callback_user = &link;
    REQUIRE(ninlil_v1_usb_bridge_init(&bridge, &bridge_config)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 999u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(inject_board_info(&bridge, &stream));

    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&bridge, encoded_binding,
        encoded_binding_length, 5000u, &binding_handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 1001u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_fake_byte_stream_take_tx(&stream, wire, sizeof(wire)) != 0u);
    REQUIRE(inject_status(&bridge, &stream, binding_handle.operation_id, 1u,
        NINLIL_NVB1_STATUS_INSTALLED, binding.pair_generation, 1002u));
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, binding_handle,
        &binding_completion) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_fabric_link_activate(&link, &bridge, &crypto,
        &clock.ops, binding.endpoint_b.runtime_id, encoded_binding,
        encoded_binding_length, binding_completion.pair_generation)
        == NINLIL_V1_USB_FABRIC_LINK_BINDING);
    REQUIRE(ninlil_v1_usb_fabric_link_activate(&link, &bridge, &crypto,
        &clock.ops, binding.endpoint_a.runtime_id, encoded_binding,
        encoded_binding_length, binding_completion.pair_generation)
        == NINLIL_V1_USB_FABRIC_LINK_OK);

    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&bridge,
        second_encoded_binding, second_encoded_binding_length, 5000u,
        &binding_handle) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 1003u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_fake_byte_stream_take_tx(&stream, wire, sizeof(wire)) != 0u);
    REQUIRE(inject_status(&bridge, &stream, binding_handle.operation_id, 2u,
        NINLIL_NVB1_STATUS_INSTALLED, second_binding.pair_generation, 1004u));
    REQUIRE(ninlil_v1_usb_bridge_take_completion(&bridge, binding_handle,
        &binding_completion) == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_fabric_link_activate(&link, &bridge, &crypto,
        &clock.ops, second_binding.endpoint_a.runtime_id,
        second_encoded_binding, second_encoded_binding_length,
        binding_completion.pair_generation)
        == NINLIL_V1_USB_FABRIC_LINK_OK);
    REQUIRE(link.pair_count == 2u && link.port_count == 4u);
    REQUIRE(ninlil_v1_usb_fabric_link_path(&link,
        binding.services[0].selected_path_id, &descriptor, &ops)
        == NINLIL_V1_USB_FABRIC_LINK_OK);
    REQUIRE(ninlil_v1_usb_fabric_link_path(&link,
        second_binding.services[0].selected_path_id,
        &second_descriptor, &second_ops) == NINLIL_V1_USB_FABRIC_LINK_OK);
    REQUIRE(ninlil_v1_usb_fabric_link_path(&link,
        binding.services[1].selected_path_id,
        &reverse_descriptor, &reverse_ops) == NINLIL_V1_USB_FABRIC_LINK_OK);
    REQUIRE(descriptor != NULL && ops != NULL);
    REQUIRE(second_descriptor != NULL && second_ops != NULL);
    REQUIRE(reverse_descriptor != NULL && reverse_ops != NULL);
    REQUIRE(memcmp(descriptor->instance_id.bytes,
        second_descriptor->instance_id.bytes, 16u) != 0);
    REQUIRE(ops->open(ops->user, &link_handle) == NINLIL_FABRIC_LINK_OK);

    (void)memset(&permit, 0, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fill_bytes(permit.permit_id.bytes, 16u, 0xe0u);
    fill_bytes(permit.attempt_id.bytes, 16u, 0x21u);
    fill_epoch(permit.clock_epoch_id.bytes);
    permit.expires_at_ms = 5000u;
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = NINLIL_FABRIC_API_VERSION;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = application;
    packet.length = application_length;
    fill_bytes(packet.transaction_id.bytes, 16u, 0x01u);
    fill_bytes(packet.attempt_id.bytes, 16u, 0x21u);
    (void)memcpy(packet.selected_path_id.bytes,
        binding.services[0].selected_path_id, 16u);
    packet.path_selection_epoch = 77u;
    packet.permit = &permit;
    REQUIRE(ops->start_send(ops->user, link_handle, &packet, &token)
        == NINLIL_FABRIC_LINK_RETAINED);
    REQUIRE(token != NULL);
    {
        ninlil_fabric_packet_token_t duplicate = (void *)1;
        REQUIRE(ops->start_send(ops->user, link_handle, &packet, &duplicate)
            == NINLIL_FABRIC_LINK_DENIED);
        REQUIRE(duplicate == NULL);
    }
    second_permit = permit;
    fill_bytes(second_permit.permit_id.bytes, 16u, 0xf0u);
    packet.permit = &second_permit;
    {
        ninlil_fabric_packet_token_t blocked = (void *)1;
        REQUIRE(ops->start_send(ops->user, link_handle, &packet, &blocked)
            == NINLIL_FABRIC_LINK_WOULD_BLOCK);
        REQUIRE(blocked == NULL);
    }
    packet.permit = &permit;
    REQUIRE(ninlil_v1_usb_fabric_link_step(&link, 1005u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_fake_byte_stream_take_tx(&stream, wire, sizeof(wire)) != 0u);
    REQUIRE(inject_status(&bridge, &stream, 3u, 3u,
        NINLIL_NVB1_STATUS_ACCEPTED_LOCAL, 0u, 1006u));
    (void)memset(&completion, 0, sizeof(completion));
    REQUIRE(ops->poll_send(ops->user, link_handle, token, &completion)
        == NINLIL_FABRIC_LINK_OK);
    REQUIRE(completion.kind
        == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
    ops->release_send(ops->user, link_handle, token);

    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 2u, 4u,
        receipt, receipt_length, wire, &wire_length));
    REQUIRE(inject_wire(&bridge, &stream, wire, wire_length, 1007u));
    REQUIRE(ops->receive_next(ops->user, link_handle, &received,
        &received_length, &receive_token) == NINLIL_FABRIC_LINK_OK);
    REQUIRE(received_length == receipt_length);
    REQUIRE(memcmp(received, receipt, receipt_length) == 0);
    REQUIRE(encode_wire(NINLIL_NVB1_KIND_FABRIC_PACKET, 3u, 5u,
        receipt, receipt_length, wire, &wire_length));
    REQUIRE(inject_wire(&bridge, &stream, wire, wire_length, 1008u));
    ops->release_received(ops->user, link_handle, receive_token);
    REQUIRE(ninlil_v1_usb_fabric_link_handoff(&link,
        wrong_path, wrong_path_length) == NINLIL_NVB1_STATUS_REJECTED);

    REQUIRE(ninlil_v1_usb_bridge_step(&bridge, 1009u, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_fake_byte_stream_take_tx(&stream, wire, sizeof(wire)) != 0u);
    packet.permit = &second_permit;
    token = NULL;
    REQUIRE(ops->start_send(ops->user, link_handle, &packet, &token)
        == NINLIL_FABRIC_LINK_RETAINED);
    ninlil_fake_byte_stream_link_down(&stream);
    REQUIRE(ninlil_v1_usb_fabric_link_step(&link, 1010u, 0u)
        == NINLIL_V1_USB_BRIDGE_LINK_DOWN);
    (void)memset(&completion, 0, sizeof(completion));
    REQUIRE(ops->poll_send(ops->user, link_handle, token, &completion)
        == NINLIL_FABRIC_LINK_OK);
    REQUIRE(completion.kind
        == NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN);
    ops->release_send(ops->user, link_handle, token);
    ops->close(ops->user, link_handle);
    ninlil_v1_usb_fabric_link_clear(&link);
    REQUIRE(link.magic == 0u);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_v1_lab_binding_clear(&second_binding);
    return 1;
}

int main(void)
{
    if (!test_controller_adapter()) {
        return 1;
    }
    (void)printf("v1_usb_fabric_link_test OK\n");
    return 0;
}
