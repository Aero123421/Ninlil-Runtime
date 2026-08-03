#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_USB_FABRIC_LINK_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_USB_FABRIC_LINK_H

/*
 * Private ADR-0036 Host USB bridge -> Fabric packet-link adapter.
 *
 * This is a bounded V1 LAB composition seam, not an installed API.  One
 * prepared object owns the BOARD_INFO handoff before activation, then exposes
 * at most one packet-link port for each binding flow.
 */

#include "v1_lab_fabric.h"
#include "v1_usb_bridge.h"

#include "ninlil/fabric_v1.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_USB_FABRIC_LINK_MAGIC ((uint32_t)0x8cb4e731u)
#define NINLIL_V1_USB_FABRIC_LINK_PAIR_MAX ((uint8_t)2u)
#define NINLIL_V1_USB_FABRIC_LINK_PATH_MAX ((uint8_t)4u)
#define NINLIL_V1_USB_FABRIC_LINK_TX_MAX \
    NINLIL_V1_USB_BRIDGE_PACKET_SLOTS

typedef uint32_t ninlil_v1_usb_fabric_link_status_t;
#define NINLIL_V1_USB_FABRIC_LINK_OK \
    ((ninlil_v1_usb_fabric_link_status_t)0u)
#define NINLIL_V1_USB_FABRIC_LINK_INVALID_ARGUMENT \
    ((ninlil_v1_usb_fabric_link_status_t)1u)
#define NINLIL_V1_USB_FABRIC_LINK_INVALID_STATE \
    ((ninlil_v1_usb_fabric_link_status_t)2u)
#define NINLIL_V1_USB_FABRIC_LINK_BINDING \
    ((ninlil_v1_usb_fabric_link_status_t)3u)
#define NINLIL_V1_USB_FABRIC_LINK_FENCED \
    ((ninlil_v1_usb_fabric_link_status_t)4u)
#define NINLIL_V1_USB_FABRIC_LINK_NOT_FOUND \
    ((ninlil_v1_usb_fabric_link_status_t)5u)

struct ninlil_v1_usb_fabric_link;

typedef struct ninlil_v1_usb_fabric_rx {
    uint8_t active;
    uint8_t loaned;
    uint16_t reserved_zero;
    uint32_t generation;
    uint32_t length;
    uint8_t bytes[NINLIL_V1_LAB_FABRIC_PACKET_MAX];
} ninlil_v1_usb_fabric_rx_t;

typedef struct ninlil_v1_usb_fabric_port {
    uint8_t active;
    uint8_t open;
    uint8_t flow;
    uint8_t reserved_zero;
    uint8_t path_id[16];
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_state_v1_t state;
    ninlil_v1_usb_fabric_rx_t rx;
    struct ninlil_v1_usb_fabric_link *owner;
    ninlil_fabric_packet_link_ops_v1_t ops;
} ninlil_v1_usb_fabric_port_t;

typedef struct ninlil_v1_usb_fabric_tx {
    uint8_t active;
    uint8_t terminal;
    uint8_t released;
    uint8_t bridge_live;
    uint8_t port_index;
    uint8_t completion_kind;
    uint16_t reserved_zero;
    uint32_t generation;
    uint8_t permit_id[16];
    ninlil_v1_usb_bridge_handle_t bridge_handle;
} ninlil_v1_usb_fabric_tx_t;

typedef struct ninlil_v1_usb_fabric_link {
    uint32_t magic;
    uint8_t prepared;
    uint8_t active;
    uint8_t board_info_received;
    uint8_t port_count;
    uint8_t pair_count;
    uint8_t reserved_state[3];
    uint32_t next_tx_generation;
    uint32_t next_rx_generation;
    uint64_t bridge_generation;
    ninlil_nvb1_board_info_t board_info;
    ninlil_v1_usb_bridge_t *bridge;
    ninlil_clock_ops_t clock;
    uint8_t local_runtime_id[16];
    uint8_t pair_ids[NINLIL_V1_USB_FABRIC_LINK_PAIR_MAX][32];
    uint8_t pair_binding_digests[NINLIL_V1_USB_FABRIC_LINK_PAIR_MAX][32];
    ninlil_v1_usb_fabric_port_t
        ports[NINLIL_V1_USB_FABRIC_LINK_PATH_MAX];
    ninlil_v1_usb_fabric_tx_t
        tx[NINLIL_V1_USB_FABRIC_LINK_TX_MAX];
} ninlil_v1_usb_fabric_link_t;

/* Call before bridge_init; callback_user may then point at this object. */
ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_prepare(
    ninlil_v1_usb_fabric_link_t *link);

/* Exact v1_usb_bridge_config callback functions. */
ninlil_v1_usb_bridge_status_t ninlil_v1_usb_fabric_link_board_info_handoff(
    void *user,
    const ninlil_nvb1_board_info_t *info);
uint32_t ninlil_v1_usb_fabric_link_handoff(
    void *user,
    const uint8_t *encoded_packet,
    size_t encoded_length);

ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_board_info(
    const ninlil_v1_usb_fabric_link_t *link,
    ninlil_nvb1_board_info_t *out_info);

/*
 * Add one pair only after its exact binding request completed as INSTALLED.
 * The first call activates the adapter; a second call may add the other V1
 * direct peer. installed_pair_generation is the completion's pair generation.
 */
ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_activate(
    ninlil_v1_usb_fabric_link_t *link,
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_clock_ops_t *clock,
    const uint8_t local_runtime_id[16],
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint64_t installed_pair_generation);

ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_path(
    ninlil_v1_usb_fabric_link_t *link,
    const uint8_t selected_path_id[16],
    const ninlil_fabric_link_descriptor_v1_t **out_descriptor,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops);

/* One bounded bridge step plus reclamation of cancelled USB operations. */
ninlil_v1_usb_bridge_status_t ninlil_v1_usb_fabric_link_step(
    ninlil_v1_usb_fabric_link_t *link,
    uint64_t now_ms,
    uint32_t poll_timeout_ms);

/* Clears only a quiescent object; open ports or retained work are preserved. */
void ninlil_v1_usb_fabric_link_clear(ninlil_v1_usb_fabric_link_t *link);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_USB_FABRIC_LINK_H */
