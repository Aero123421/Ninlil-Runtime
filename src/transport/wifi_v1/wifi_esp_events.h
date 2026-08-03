#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_EVENTS_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_EVENTS_H

/*
 * Fixed ESP Wi-Fi/IP event kinds for sole-owner queue (ADR-0018).
 * Callbacks enqueue these; owner step alone mutates session state.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_wifi_esp_event_kind {
    NINLIL_WIFI_ESP_EV_NONE = 0,
    NINLIL_WIFI_ESP_EV_STA_START = 1,
    NINLIL_WIFI_ESP_EV_STA_CONNECTED = 2,
    NINLIL_WIFI_ESP_EV_STA_DISCONNECTED = 3,
    NINLIL_WIFI_ESP_EV_GOT_IP = 4,
    NINLIL_WIFI_ESP_EV_LOST_IP = 5,
    NINLIL_WIFI_ESP_EV_STEP = 6,
    NINLIL_WIFI_ESP_EV_FENCE = 7
} ninlil_wifi_esp_event_kind_t;

typedef struct ninlil_wifi_esp_event_record {
    uint64_t generation;
    uint8_t kind;
    uint8_t disconnect_reason;
    uint8_t ip_change;
    uint8_t has_ip4;
    uint8_t ip4[4]; /* GOT_IP payload copy (callback never mutates owner/sta) */
} ninlil_wifi_esp_event_record_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_EVENTS_H */
