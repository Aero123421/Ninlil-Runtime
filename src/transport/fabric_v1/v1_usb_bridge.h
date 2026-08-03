#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_USB_BRIDGE_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_USB_BRIDGE_H

/*
 * Private ADR-0036 NCG1/NVB1 USB bridge.
 *
 * This is one bounded V1 adapter, not an installed API or transport
 * framework. The caller owns the byte stream, provisioner and outer loop.
 */

#include "byte_stream.h"
#include "control_frame_codec.h"
#include "nvb1_codec.h"
#include "v1_lab_provisioner.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_USB_BRIDGE_MAGIC ((uint32_t)0x31b6a9c4u)
#define NINLIL_V1_USB_BRIDGE_PACKET_SLOTS ((uint8_t)4u)
#define NINLIL_V1_USB_BRIDGE_RX_CHUNK_BYTES ((uint32_t)256u)
#define NINLIL_V1_USB_BRIDGE_OBJECT_CEILING_BYTES ((size_t)6144u)

typedef uint32_t ninlil_v1_usb_bridge_role_t;
#define NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER \
    ((ninlil_v1_usb_bridge_role_t)1u)
#define NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD \
    ((ninlil_v1_usb_bridge_role_t)2u)

typedef uint32_t ninlil_v1_usb_bridge_status_t;
#define NINLIL_V1_USB_BRIDGE_OK ((ninlil_v1_usb_bridge_status_t)0u)
#define NINLIL_V1_USB_BRIDGE_WOULD_BLOCK ((ninlil_v1_usb_bridge_status_t)1u)
#define NINLIL_V1_USB_BRIDGE_LINK_DOWN ((ninlil_v1_usb_bridge_status_t)2u)
#define NINLIL_V1_USB_BRIDGE_FENCED ((ninlil_v1_usb_bridge_status_t)3u)
#define NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT \
    ((ninlil_v1_usb_bridge_status_t)4u)
#define NINLIL_V1_USB_BRIDGE_INVALID_STATE \
    ((ninlil_v1_usb_bridge_status_t)5u)
#define NINLIL_V1_USB_BRIDGE_BUSY ((ninlil_v1_usb_bridge_status_t)6u)
#define NINLIL_V1_USB_BRIDGE_NOT_FOUND ((ninlil_v1_usb_bridge_status_t)7u)
#define NINLIL_V1_USB_BRIDGE_IO_ERROR ((ninlil_v1_usb_bridge_status_t)8u)
#define NINLIL_V1_USB_BRIDGE_WRONG_OWNER ((ninlil_v1_usb_bridge_status_t)9u)
#define NINLIL_V1_USB_BRIDGE_SEQUENCE_EXHAUSTED \
    ((ninlil_v1_usb_bridge_status_t)10u)

typedef uint32_t ninlil_v1_usb_bridge_completion_reason_t;
#define NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS \
    ((ninlil_v1_usb_bridge_completion_reason_t)1u)
#define NINLIL_V1_USB_BRIDGE_COMPLETION_TIMEOUT \
    ((ninlil_v1_usb_bridge_completion_reason_t)2u)
#define NINLIL_V1_USB_BRIDGE_COMPLETION_LINK_FENCED \
    ((ninlil_v1_usb_bridge_completion_reason_t)3u)

typedef struct ninlil_v1_usb_bridge_handle {
    uint64_t link_generation;
    uint64_t operation_id;
} ninlil_v1_usb_bridge_handle_t;

typedef struct ninlil_v1_usb_bridge_completion {
    ninlil_v1_usb_bridge_completion_reason_t reason;
    uint32_t remote_status_code;
    uint64_t pair_generation;
} ninlil_v1_usb_bridge_completion_t;

/*
 * Fixed composition handoffs. Pointers are borrowed only for the callback.
 * Callbacks execute synchronously from step and must not re-enter the bridge.
 */
typedef void (*ninlil_v1_usb_bridge_pair_installed_fn)(
    void *user,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    const ninlil_v1_lab_n6_handles_t *handles);

typedef uint32_t (*ninlil_v1_usb_bridge_fabric_handoff_fn)(
    void *user,
    const uint8_t *encoded_packet,
    size_t encoded_length);

typedef struct ninlil_v1_usb_bridge_config {
    ninlil_v1_usb_bridge_role_t role;
    ninlil_byte_stream_t *stream;
    ninlil_v1_lab_provisioner_t *provisioner;
    ninlil_v1_usb_bridge_pair_installed_fn pair_installed;
    ninlil_v1_usb_bridge_fabric_handoff_fn fabric_handoff;
    void *callback_user;
} ninlil_v1_usb_bridge_config_t;

/* Private layout is exposed only so ESP/Host can use caller-owned storage. */
typedef struct ninlil_v1_usb_bridge_slot {
    uint8_t state;
    uint8_t kind;
    uint8_t sent;
    uint8_t reserved_zero;
    uint64_t link_generation;
    uint64_t operation_id;
    uint64_t deadline_ms;
    uint64_t expected_pair_generation;
    ninlil_v1_usb_bridge_completion_t completion;
} ninlil_v1_usb_bridge_slot_t;

typedef struct ninlil_v1_usb_bridge {
    uint32_t magic;
    ninlil_v1_usb_bridge_role_t role;
    ninlil_byte_stream_t *stream;
    ninlil_v1_lab_provisioner_t *provisioner;
    ninlil_v1_usb_bridge_pair_installed_fn pair_installed;
    ninlil_v1_usb_bridge_fabric_handoff_fn fabric_handoff;
    void *callback_user;
    uint64_t active_generation;
    uint64_t next_local_operation_id;
    uint64_t next_remote_operation_id;
    uint32_t tx_sequence;
    uint32_t rx_sequence;
    uint8_t generation_fenced;
    uint8_t tx_sequence_exhausted;
    uint8_t rx_sequence_exhausted;
    uint8_t remote_operation_exhausted;
    uint8_t tx_is_local_request;
    uint8_t in_step;
    uint8_t reserved_state[2];
    uint64_t tx_operation_id;
    uint32_t tx_wire_length;
    uint32_t rx_residual_length;
    ninlil_v1_usb_bridge_slot_t binding_slot;
    ninlil_v1_usb_bridge_slot_t
        packet_slots[NINLIL_V1_USB_BRIDGE_PACKET_SLOTS];
    ninlil_model_control_frame_parser_t parser;
    uint8_t parser_payload[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    uint8_t tx_payload[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    uint8_t tx_wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t rx_chunk[NINLIL_V1_USB_BRIDGE_RX_CHUNK_BYTES];
    uint8_t rx_residual[NINLIL_V1_USB_BRIDGE_RX_CHUNK_BYTES];
} ninlil_v1_usb_bridge_t;

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_init(
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_v1_usb_bridge_config_t *config);

/* Absolute monotonic deadline; the bridge never reads a clock implicitly. */
ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_submit_binding(
    ninlil_v1_usb_bridge_t *bridge,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint64_t deadline_ms,
    ninlil_v1_usb_bridge_handle_t *out_handle);

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_submit_fabric(
    ninlil_v1_usb_bridge_t *bridge,
    const uint8_t *encoded_packet,
    size_t encoded_length,
    uint64_t deadline_ms,
    ninlil_v1_usb_bridge_handle_t *out_handle);

/* Performs bounded poll, at most one raw write and at most one frame handoff. */
ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_step(
    ninlil_v1_usb_bridge_t *bridge,
    uint64_t now_ms,
    uint32_t poll_timeout_ms);

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_bridge_take_completion(
    ninlil_v1_usb_bridge_t *bridge,
    ninlil_v1_usb_bridge_handle_t handle,
    ninlil_v1_usb_bridge_completion_t *out_completion);

int ninlil_v1_usb_bridge_is_fenced(
    const ninlil_v1_usb_bridge_t *bridge);

void ninlil_v1_usb_bridge_clear(ninlil_v1_usb_bridge_t *bridge);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_USB_BRIDGE_H */
