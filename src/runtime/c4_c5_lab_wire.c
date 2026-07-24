#include "c4_c5_lab_wire.h"

#include <string.h>

ninlil_status_t ninlil_c4_c5_lab_dispatch_delivery(
    ninlil_rt_v1_bearer_route_t bearer_route,
    ninlil_c4_lab_usb_t *usb_path,
    ninlil_c5_lab_radio_t *radio_path,
    ninlil_c5_lab_radio_channel_t *peer_channel,
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t ownership_token,
    ninlil_c4_c5_lab_dispatch_result_t *out_result)
{
    ninlil_c4_lab_usb_status_t usb_st;
    ninlil_c5_lab_radio_status_t radio_st;

    if (payload == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (!ninlil_rt_v1_bearer_admits_payload(bearer_route, payload_len)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (bearer_route == NINLIL_RT_V1_BEARER_ROUTE_U6) {
        if (usb_path == NULL) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        out_result->route = NINLIL_C4_C5_LAB_ROUTE_USB;
        out_result->payload_len = payload_len;
        usb_st = ninlil_c4_lab_usb_custody_offer(
            usb_path, ownership_token, payload, payload_len);
        if (usb_st != NINLIL_C4_LAB_USB_OK) {
            return NINLIL_E_INVALID_STATE;
        }
        out_result->usb_custody_ok = 1u;
        return NINLIL_OK;
    }
    if (radio_path == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    out_result->route = NINLIL_C4_C5_LAB_ROUTE_RADIO;
    out_result->payload_len = payload_len;
    radio_st = ninlil_c5_lab_radio_tx_data(
        radio_path, payload, payload_len, peer_channel);
    if (radio_st == NINLIL_C5_LAB_RADIO_PERMIT_DENIED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (radio_st != NINLIL_C5_LAB_RADIO_OK) {
        return NINLIL_E_DEGRADED;
    }
    {
        ninlil_c5_lab_radio_stats_t stats;
        ninlil_c5_lab_radio_stats_snapshot(radio_path, &stats);
        out_result->spi_tx_count = (uint32_t)stats.spi_tx_count;
    }
    out_result->radio_tx_ok = 1u;
    return NINLIL_OK;
}
