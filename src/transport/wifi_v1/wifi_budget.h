/*
 * Private Wi-Fi v1 resource budgets (ADR-0018).
 * Default-OFF candidate. Not installed. Not public ABI.
 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_BUDGET_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_BUDGET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Host profile (Proposed resource vectors). */
#define NINLIL_WIFI_HOST_ADAPTER_MAX 64u
#define NINLIL_WIFI_HOST_SESSION_MAX 64u
#define NINLIL_WIFI_HOST_CONNECT_ATTEMPT_MAX 8u
#define NINLIL_WIFI_HOST_TX_TOKEN_PER_SESSION 8u
#define NINLIL_WIFI_HOST_RX_RECORD_PER_SESSION 8u
#define NINLIL_WIFI_HOST_EVENT_QUEUE_MAX 64u

/* ESP profile (Proposed resource vectors). */
#define NINLIL_WIFI_ESP_ADAPTER_MAX 1u
#define NINLIL_WIFI_ESP_SESSION_MAX 2u
#define NINLIL_WIFI_ESP_CONNECT_ATTEMPT_MAX 1u
/* Owner-internal TX/RX slots sized for 12 KiB workspace contract. */
#define NINLIL_WIFI_ESP_TX_TOKEN_MAX 1u
#define NINLIL_WIFI_ESP_RX_RECORD_MAX 1u
#define NINLIL_WIFI_ESP_RX_LOAN_MAX 1u
#define NINLIL_WIFI_ESP_EVENT_QUEUE_MAX 8u

/* Shared framing / storage (ADR-0018). */
#define NINLIL_WIFI_NWB1_HEADER_BYTES 40u
#define NINLIL_WIFI_NWB1_PAYLOAD_MIN 587u
#define NINLIL_WIFI_NWB1_PAYLOAD_MAX 1925u
#define NINLIL_WIFI_NWB1_TOTAL_MIN 627u
#define NINLIL_WIFI_NWB1_TOTAL_MAX 1965u
#define NINLIL_WIFI_NFL1_HEADER_BYTES 584u
#define NINLIL_WIFI_RECORD_BYTES_FIXED 1965u
#define NINLIL_WIFI_NWD1_RECORD_BYTES 160u
#define NINLIL_WIFI_NWD1_KEYS_MAX 8u
#define NINLIL_WIFI_NWD1_COMMITTED_CU 1280u
#define NINLIL_WIFI_NWD1_STAGING_CU 2560u

/*
 * Approximate static RAM budgets for workspace (bytes). These are design
 * ceilings for private candidate sizing — not production .su gates.
 */
#define NINLIL_WIFI_HOST_SESSION_WORKSPACE_BYTES (48u * 1024u)
/*
 * ESP owner control+record workspace (TLS object is external pointer).
 * Contract: sizeof(ninlil_wifi_esp_owner_t) <= 12 KiB (measured gate).
 * TX/RX depth 1 each + one partial buffer = 3 × 1965 + control.
 */
#define NINLIL_WIFI_ESP_SESSION_WORKSPACE_BYTES (12u * 1024u)
#define NINLIL_WIFI_HOST_STACK_BUDGET_BYTES (24u * 1024u)
#define NINLIL_WIFI_ESP_STACK_BUDGET_BYTES (8u * 1024u)

/* Liveness (ADR-0018). */
#define NINLIL_WIFI_KEEPALIVE_INTERVAL_MS 15000u
#define NINLIL_WIFI_KEEPALIVE_EXCLUSIVE_DEADLINE_MS 15000u
#define NINLIL_WIFI_MISSED_RESPONSE_THRESHOLD 3u
#define NINLIL_WIFI_BLACKHOLE_DETECT_MS 45000u

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_BUDGET_H */
