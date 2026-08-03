#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_SEAM_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_SEAM_H

/*
 * ESP seam index (ADR-0018). Real implementation lives in:
 *   wifi_esp_sta.*          — WIFI_STORAGE_RAM STA owner
 *   wifi_esp_tcp.*          — lwIP nonblocking sockets
 *   wifi_esp_tls_mbedtls.*  — direct mbedTLS TLS1.3 mutual-auth
 *   wifi_esp_owner.*        — FreeRTOS event/task state machine
 *
 * Host does not call these. Budgets: wifi_budget.h.
 */
#include "wifi_budget.h"
#include "wifi_esp_owner.h"
#include "wifi_esp_sta.h"
#include "wifi_esp_tcp.h"
#include "wifi_esp_tls_mbedtls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Budget summary pins for design review / resource gate. */
enum {
    NINLIL_WIFI_ESP_SEAM_SESSION_WS = NINLIL_WIFI_ESP_SESSION_WORKSPACE_BYTES,
    NINLIL_WIFI_ESP_SEAM_STACK = NINLIL_WIFI_ESP_STACK_BUDGET_BYTES,
    NINLIL_WIFI_ESP_SEAM_ADAPTER_MAX = NINLIL_WIFI_ESP_ADAPTER_MAX,
    NINLIL_WIFI_ESP_SEAM_SESSION_MAX = NINLIL_WIFI_ESP_SESSION_MAX,
    NINLIL_WIFI_ESP_SEAM_EVENT_MAX = NINLIL_WIFI_ESP_EVENT_QUEUE_MAX
};

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_SEAM_H */
