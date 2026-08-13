/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_fabric_adapter.h"

#include <string.h>

void ninlil_wifi_fabric_link_init(
    ninlil_wifi_fabric_link_t *link,
    ninlil_wifi_session_t *session)
{
    if (link == NULL) {
        return;
    }
    link->session = session;
    /* Fabric packet-link maximum is NFL1 structural max (1925), not NWB1 total. */
    link->maximum_packet_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    link->link_kind = 2u; /* WIFI */
}

#if !defined(ESP_PLATFORM)

ninlil_wifi_status_t ninlil_wifi_fabric_link_send(
    ninlil_wifi_fabric_link_t *link,
    const uint8_t *nfl1,
    uint32_t nfl1_len)
{
    if (link == NULL || link->session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    return ninlil_wifi_session_send_payload(link->session, nfl1, nfl1_len);
}

ninlil_wifi_status_t ninlil_wifi_fabric_link_recv(
    ninlil_wifi_fabric_link_t *link,
    uint8_t *record_out,
    size_t record_cap,
    size_t *record_len_out)
{
    if (link == NULL || link->session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    return ninlil_wifi_session_recv_record(
        link->session, record_out, record_cap, record_len_out, NULL);
}

#endif /* !ESP_PLATFORM */
