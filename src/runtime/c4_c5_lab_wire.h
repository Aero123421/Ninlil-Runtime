#ifndef NINLIL_RUNTIME_C4_C5_LAB_WIRE_H
#define NINLIL_RUNTIME_C4_C5_LAB_WIRE_H

/*
 * C4/C5-LAB delivery wire seam (V1 item 9).
 *
 * Connects Runtime delivery (item 2) to USB Cell Agent software path (C4)
 * or SX1262 radio software path (C5) after secure wire seal.
 *
 * Not public ABI. Host simulation only.
 */

#include "c4_lab_usb_path.h"
#include "c5_lab_radio_path.h"
#include "runtime_internal.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_c4_c5_lab_route {
    NINLIL_C4_C5_LAB_ROUTE_USB = 1,
    NINLIL_C4_C5_LAB_ROUTE_RADIO = 2
} ninlil_c4_c5_lab_route_t;

typedef struct ninlil_c4_c5_lab_dispatch_result {
    ninlil_c4_c5_lab_route_t route;
    uint32_t payload_len;
    uint32_t spi_tx_count;
    uint32_t usb_custody_ok;
    uint32_t radio_tx_ok;
} ninlil_c4_c5_lab_dispatch_result_t;

/*
 * Dispatch admitted runtime payload over USB custody (U6) or radio TX (R9).
 * Secure wire seal occurs inside radio path; USB path carries application bytes
 * after runtime admission marker commit.
 */
ninlil_status_t ninlil_c4_c5_lab_dispatch_delivery(
    ninlil_rt_v1_bearer_route_t bearer_route,
    ninlil_c4_lab_usb_t *usb_path,
    ninlil_c5_lab_radio_t *radio_path,
    ninlil_c5_lab_radio_channel_t *peer_channel,
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t ownership_token,
    ninlil_c4_c5_lab_dispatch_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_C4_C5_LAB_WIRE_H */
