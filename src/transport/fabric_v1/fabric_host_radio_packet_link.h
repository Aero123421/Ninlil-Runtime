/*
 * Private host radio packet-link seam (no public ABI).
 * Deterministic loopback for Fabric host acceptance; not ESP/RF HIL.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_HOST_RADIO_PACKET_LINK_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_HOST_RADIO_PACKET_LINK_H

#include "fabric_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_FABRIC_HOST_RADIO_TX_SLOTS 4u
#define NINLIL_FABRIC_HOST_RADIO_RX_SLOTS 4u
#define NINLIL_FABRIC_HOST_RADIO_MAX_BYTES 1925u

typedef struct ninlil_fabric_host_radio_tx_slot {
    uint8_t used;
    uint8_t terminal;
    uint8_t reserved[2];
    uint32_t generation;
    uint32_t length;
    uint8_t bytes[NINLIL_FABRIC_HOST_RADIO_MAX_BYTES];
} ninlil_fabric_host_radio_tx_slot_t;

typedef struct ninlil_fabric_host_radio_user {
    uint32_t open;
    uint32_t next_gen;
    uint32_t availability_epoch;
    uint32_t available;
    uint32_t start_calls;
    uint32_t retain_bytes;
    ninlil_fabric_host_radio_tx_slot_t tx[NINLIL_FABRIC_HOST_RADIO_TX_SLOTS];
    uint8_t rx_loan;
    uint32_t rx_len;
    uint8_t rx_bytes[NINLIL_FABRIC_HOST_RADIO_MAX_BYTES];
    /* Injected next start_send status (0 = RETAINED). */
    ninlil_fabric_link_status_t next_start_status;
} ninlil_fabric_host_radio_user_t;

void ninlil_fabric_host_radio_user_init(ninlil_fabric_host_radio_user_t *u);
void ninlil_fabric_host_radio_packet_link_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_host_radio_user_t *user);

/* Host test: queue one RX NFL1 for receive_next. */
int ninlil_fabric_host_radio_push_rx(
    ninlil_fabric_host_radio_user_t *u,
    const uint8_t *bytes,
    uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_FABRIC_HOST_RADIO_PACKET_LINK_H */
