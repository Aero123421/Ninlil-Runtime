#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_STA_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_STA_H

/*
 * ESP32-S3 STA owner (ADR-0018). WIFI_STORAGE_RAM only.
 * Private / default-OFF.
 *
 * Callbacks only enqueue bounded records via event sink — never mutate owner
 * phase/TLS/socket state and never update got_ip/last_ip mirrors. Owner step
 * alone drives connect/lifecycle and applies observational STA mirrors.
 */
#include "wifi_adapter_v1.h"
#include "wifi_private_types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_esp_sta_config {
    ninlil_id128_t network_profile_id;
    uint64_t network_profile_revision;
    uint8_t network_profile_digest[32];
    const wifi_network_credential_provider_ops_v1_t *credential_provider;
    /*
     * Must be 0 for the sole-owner asynchronous path: start Wi-Fi and return;
     * GOT_IP arrives via the event sink. A blocking value is rejected because
     * it would prevent owner_step from consuming STA_START and connecting.
     */
    uint32_t connect_timeout_ms;
} ninlil_wifi_esp_sta_config_t;

typedef struct ninlil_wifi_esp_sta ninlil_wifi_esp_sta_t;

/*
 * Callback-safe sink: copy-only enqueue.
 * ip4 may be non-NULL for GOT_IP (4 bytes). Implementation must not call
 * Wi-Fi/TLS/Fabric or mutate owner phase/TLS/TCP.
 */
typedef ninlil_wifi_status_t (*ninlil_wifi_esp_event_sink_fn)(
    void *user,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change,
    const uint8_t *ip4);

/* Opaque control block size for stack/static allocation (ESP + host tests). */
#define NINLIL_WIFI_ESP_STA_STORAGE_BYTES 128u

size_t ninlil_wifi_esp_sta_sizeof(void);

ninlil_wifi_status_t ninlil_wifi_esp_sta_init(ninlil_wifi_esp_sta_t *sta);

void ninlil_wifi_esp_sta_bind_event_sink(
    ninlil_wifi_esp_sta_t *sta,
    ninlil_wifi_esp_event_sink_fn sink,
    void *user);

/*
 * Start STA with WIFI_STORAGE_RAM. Does not claim physical AP association.
 * Nonblocking; connect_timeout_ms must be 0.
 */
ninlil_wifi_status_t ninlil_wifi_esp_sta_start(
    ninlil_wifi_esp_sta_t *sta,
    const ninlil_wifi_esp_sta_config_t *cfg);

/* Owner-step only: drive esp_wifi_connect after STA_START event. */
ninlil_wifi_status_t ninlil_wifi_esp_sta_request_connect(
    ninlil_wifi_esp_sta_t *sta);

void ninlil_wifi_esp_sta_stop(ninlil_wifi_esp_sta_t *sta);

/*
 * Owner-task only APIs: apply observational mirrors after event consume.
 * Never called from Wi-Fi/IP callbacks.
 */
void ninlil_wifi_esp_sta_owner_note_got_ip(
    ninlil_wifi_esp_sta_t *sta,
    const uint8_t ip4[4]);
void ninlil_wifi_esp_sta_owner_note_lost_ip(ninlil_wifi_esp_sta_t *sta);
void ninlil_wifi_esp_sta_owner_note_fail(ninlil_wifi_esp_sta_t *sta);

/* Observational only — not authority for owner got_ip (owner events are). */
int ninlil_wifi_esp_sta_is_got_ip(const ninlil_wifi_esp_sta_t *sta);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_STA_H */
