/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TCP_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TCP_H

/* lwIP nonblocking TCP for ESP wifi_v1 (ADR-0018). */
#include "wifi_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_esp_tcp {
    int fd;
    int listen_fd;
    int connected;
    int is_server;
} ninlil_wifi_esp_tcp_t;

void ninlil_wifi_esp_tcp_init(ninlil_wifi_esp_tcp_t *tcp);

void ninlil_wifi_esp_tcp_close(ninlil_wifi_esp_tcp_t *tcp);

ninlil_wifi_status_t ninlil_wifi_esp_tcp_connect(
    ninlil_wifi_esp_tcp_t *tcp,
    const ninlil_wifi_endpoint_t *endpoint);

/* Nonblocking one-session listener. poll_accepted installs the accepted fd. */
ninlil_wifi_status_t ninlil_wifi_esp_tcp_listen(
    ninlil_wifi_esp_tcp_t *tcp,
    const ninlil_wifi_endpoint_t *endpoint);

ninlil_wifi_status_t ninlil_wifi_esp_tcp_poll_accepted(
    ninlil_wifi_esp_tcp_t *tcp);

ninlil_wifi_status_t ninlil_wifi_esp_tcp_poll_connected(
    ninlil_wifi_esp_tcp_t *tcp);

ninlil_wifi_status_t ninlil_wifi_esp_tcp_send(
    ninlil_wifi_esp_tcp_t *tcp,
    const uint8_t *data,
    size_t len,
    size_t *sent_out);

ninlil_wifi_status_t ninlil_wifi_esp_tcp_recv(
    ninlil_wifi_esp_tcp_t *tcp,
    uint8_t *data,
    size_t cap,
    size_t *got_out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TCP_H */
