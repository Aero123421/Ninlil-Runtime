/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TCP_POSIX_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TCP_POSIX_H

#include "wifi_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_tcp {
    int fd;
    int is_listener;
    int connected;
} ninlil_wifi_tcp_t;

void ninlil_wifi_tcp_init(ninlil_wifi_tcp_t *tcp);
void ninlil_wifi_tcp_close(ninlil_wifi_tcp_t *tcp);

/* Nonblocking connect to IPv4/IPv6 endpoint. */
ninlil_wifi_status_t ninlil_wifi_tcp_connect(
    ninlil_wifi_tcp_t *tcp,
    const ninlil_wifi_endpoint_t *endpoint);

/* Listen on 127.0.0.1 / ::1 for tests (IPv4). port 0 => ephemeral. */
ninlil_wifi_status_t ninlil_wifi_tcp_listen_loopback(
    ninlil_wifi_tcp_t *listener,
    uint16_t port,
    uint16_t *bound_port_out);

/* Nonblocking bind/listen on the exact IPv4/IPv6 endpoint. Port 0 is valid. */
ninlil_wifi_status_t ninlil_wifi_tcp_listen(
    ninlil_wifi_tcp_t *listener,
    const ninlil_wifi_endpoint_t *endpoint,
    uint16_t *bound_port_out);

ninlil_wifi_status_t ninlil_wifi_tcp_accept(
    ninlil_wifi_tcp_t *listener,
    ninlil_wifi_tcp_t *client);

/* Poll connect completion. */
ninlil_wifi_status_t ninlil_wifi_tcp_poll_connected(ninlil_wifi_tcp_t *tcp);

ninlil_wifi_status_t ninlil_wifi_tcp_send(
    ninlil_wifi_tcp_t *tcp,
    const uint8_t *data,
    size_t len,
    size_t *sent_out);

ninlil_wifi_status_t ninlil_wifi_tcp_recv(
    ninlil_wifi_tcp_t *tcp,
    uint8_t *data,
    size_t cap,
    size_t *got_out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TCP_POSIX_H */
