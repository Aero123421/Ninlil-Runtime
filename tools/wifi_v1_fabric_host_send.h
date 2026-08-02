#ifndef NINLIL_TOOLS_WIFI_V1_FABRIC_HOST_SEND_H
#define NINLIL_TOOLS_WIFI_V1_FABRIC_HOST_SEND_H

#include "wifi_session.h"

#include <stdint.h>

/*
 * Host acceptance helper: every frame enters through the real Fabric outer
 * bearer and leaves through Wi-Fi TLS/TCP.  Returns 0 only after Fabric has
 * observed transport terminal completion and released every provider token.
 */
int ninlil_wifi_host_fabric_send_frames(
    ninlil_wifi_session_t *session,
    uint32_t frames,
    uint32_t slow_ms,
    uint32_t start_id,
    int require_peer_response_each);

/*
 * Two-process acceptance seam:
 * public Runtime API -> private Fabric -> real Wi-Fi TLS/TCP -> peer Runtime
 * -> reverse Receipt.  Each process calls this once after ATTACHED with its
 * local TLS role.  This remains a test/tool API and is never installed.
 */
int ninlil_wifi_host_public_runtime_e2e(
    ninlil_wifi_session_t *session,
    int is_server);

#endif /* NINLIL_TOOLS_WIFI_V1_FABRIC_HOST_SEND_H */
