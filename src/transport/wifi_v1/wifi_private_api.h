/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private Wi-Fi packet-link candidate v1 (ADR-0018).
 * Default-OFF. Not installed. Not public ABI.
 * Symbol prefix: ninlil_wifi_
 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_PRIVATE_API_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_PRIVATE_API_H

#include "wifi_budget.h"
#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1
#include "wifi_adapter_v1.h"
#endif
#include "wifi_credentials.h"
#include "wifi_esp_seam.h"
#include "wifi_fabric_adapter.h"
#include "wifi_nwb1.h"
#include "wifi_private_types.h"
#include "wifi_queues.h"
#include "wifi_session.h"
#include "wifi_stream.h"
#include "wifi_tcp_posix.h"
#include "wifi_tls_host.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Umbrella include for private Host candidate. */

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_PRIVATE_API_H */
