#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_BOARD_OWNER_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_BOARD_OWNER_H

/* Private fixed USB-board owner from ADR-0036. Not installed ABI. */

#include "v1_lab_radio_packet_link.h"
#include "v1_usb_bridge.h"

#include "radio_hal.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_BOARD_OWNER_USB_DEADLINE_MS ((uint64_t)5000u)

typedef uint32_t ninlil_v1_lab_board_owner_status_t;
#define NINLIL_V1_LAB_BOARD_OWNER_OK \
    ((ninlil_v1_lab_board_owner_status_t)0u)
#define NINLIL_V1_LAB_BOARD_OWNER_INVALID_ARGUMENT \
    ((ninlil_v1_lab_board_owner_status_t)1u)
#define NINLIL_V1_LAB_BOARD_OWNER_LINK_DOWN \
    ((ninlil_v1_lab_board_owner_status_t)2u)
#define NINLIL_V1_LAB_BOARD_OWNER_BUSY \
    ((ninlil_v1_lab_board_owner_status_t)3u)
#define NINLIL_V1_LAB_BOARD_OWNER_FENCED \
    ((ninlil_v1_lab_board_owner_status_t)4u)
#define NINLIL_V1_LAB_BOARD_OWNER_RADIO \
    ((ninlil_v1_lab_board_owner_status_t)5u)
#define NINLIL_V1_LAB_BOARD_OWNER_USB \
    ((ninlil_v1_lab_board_owner_status_t)6u)

typedef struct ninlil_v1_lab_board_owner_config {
    ninlil_byte_stream_t *usb_stream;
    ninlil_v1_lab_provisioner_t *provisioner;
    const ninlil_r7_crypto_provider *crypto;
    const uint8_t *local_runtime_id;
    const ninlil_clock_ops_t *clock;
    ninlil_sx1262_phy_t *phy;
    ninlil_pcp_t *pcp;
    ninlil_radio_hal_t *hal;
    const ninlil_pcp_live_profile_t *live;
} ninlil_v1_lab_board_owner_config_t;

typedef struct ninlil_v1_lab_board_owner_pair {
    ninlil_r7_frag_prod_bind_t a_to_b;
    ninlil_r7_frag_prod_bind_t b_to_a;
} ninlil_v1_lab_board_owner_pair_t;

typedef struct ninlil_v1_lab_board_owner {
    uint32_t magic;
    uint8_t active;
    uint8_t fenced;
    uint8_t pair_count;
    uint8_t usb_receive_pending;
    ninlil_v1_lab_provisioner_t *provisioner;
    ninlil_pcp_t *pcp;
    ninlil_radio_hal_t *hal;
    ninlil_pcp_live_profile_t live;
    ninlil_v1_usb_bridge_handle_t usb_receive_handle;
    void *radio_receive_token;
    ninlil_v1_usb_bridge_t bridge;
    ninlil_v1_lab_radio_packet_link_t radio;
    ninlil_v1_lab_board_owner_pair_t
        pairs[NINLIL_V1_LAB_RADIO_PAIR_MAX];
} ninlil_v1_lab_board_owner_t;

ninlil_v1_lab_board_owner_status_t ninlil_v1_lab_board_owner_init(
    ninlil_v1_lab_board_owner_t *owner,
    const ninlil_v1_lab_board_owner_config_t *config);

/*
 * One bounded USB completion, bridge step, radio step and RF->USB handoff.
 * LINK_DOWN and BUSY are retryable on a later step; FENCED/RADIO/USB are not.
 */
ninlil_v1_lab_board_owner_status_t ninlil_v1_lab_board_owner_step(
    ninlil_v1_lab_board_owner_t *owner,
    uint64_t now_ms,
    uint32_t usb_poll_timeout_ms);

int ninlil_v1_lab_board_owner_is_fenced(
    const ninlil_v1_lab_board_owner_t *owner);

/* Clear is allowed only after retained radio/USB receive work has drained. */
ninlil_v1_lab_board_owner_status_t ninlil_v1_lab_board_owner_clear(
    ninlil_v1_lab_board_owner_t *owner);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_BOARD_OWNER_H */
