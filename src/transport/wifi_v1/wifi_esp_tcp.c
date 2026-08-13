/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_esp_tcp.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#if defined(ESP_PLATFORM)
/* lwIP BSD sockets under IDF component build. */
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/errno.h"
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

void ninlil_wifi_esp_tcp_init(ninlil_wifi_esp_tcp_t *tcp)
{
    if (tcp == NULL) {
        return;
    }
    tcp->fd = -1;
    tcp->listen_fd = -1;
    tcp->connected = 0;
    tcp->is_server = 0;
}

void ninlil_wifi_esp_tcp_close(ninlil_wifi_esp_tcp_t *tcp)
{
    if (tcp == NULL) {
        return;
    }
    if (tcp->fd >= 0) {
        (void)close(tcp->fd);
        tcp->fd = -1;
    }
    if (tcp->listen_fd >= 0) {
        (void)close(tcp->listen_fd);
        tcp->listen_fd = -1;
    }
    tcp->connected = 0;
    tcp->is_server = 0;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

ninlil_wifi_status_t ninlil_wifi_esp_tcp_connect(
    ninlil_wifi_esp_tcp_t *tcp,
    const ninlil_wifi_endpoint_t *endpoint)
{
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    int rc;
    if (tcp == NULL || endpoint == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_esp_tcp_close(tcp);
    if (endpoint->address_kind == 1u) {
        tcp->fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tcp->fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        if (set_nonblock(tcp->fd) != 0) {
            ninlil_wifi_esp_tcp_close(tcp);
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(endpoint->port);
        (void)memcpy(&addr4.sin_addr, endpoint->address, 4u);
        rc = connect(tcp->fd, (struct sockaddr *)&addr4, sizeof(addr4));
    } else if (endpoint->address_kind == 2u) {
        tcp->fd = (int)socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (tcp->fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        if (set_nonblock(tcp->fd) != 0) {
            ninlil_wifi_esp_tcp_close(tcp);
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(endpoint->port);
        addr6.sin6_scope_id = endpoint->scope_id_u32;
        (void)memcpy(&addr6.sin6_addr, endpoint->address, 16u);
        rc = connect(tcp->fd, (struct sockaddr *)&addr6, sizeof(addr6));
    } else {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (rc == 0) {
        tcp->connected = 1;
        return NINLIL_WIFI_OK;
    }
    if (errno == EINPROGRESS || errno == EALREADY) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    ninlil_wifi_esp_tcp_close(tcp);
    return NINLIL_WIFI_IO_ERROR;
}

ninlil_wifi_status_t ninlil_wifi_esp_tcp_listen(
    ninlil_wifi_esp_tcp_t *tcp,
    const ninlil_wifi_endpoint_t *endpoint)
{
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    int reuse = 1;
    int rc;
    if (tcp == NULL || endpoint == NULL || endpoint->port == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_esp_tcp_close(tcp);
    if (endpoint->address_kind == 1u) {
        tcp->listen_fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (tcp->listen_fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)setsockopt(
            tcp->listen_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            (socklen_t)sizeof(reuse));
        (void)memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(endpoint->port);
        (void)memcpy(&addr4.sin_addr, endpoint->address, 4u);
        rc = bind(
            tcp->listen_fd,
            (const struct sockaddr *)&addr4,
            (socklen_t)sizeof(addr4));
    } else if (endpoint->address_kind == 2u) {
        tcp->listen_fd = (int)socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (tcp->listen_fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)setsockopt(
            tcp->listen_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            (socklen_t)sizeof(reuse));
        (void)memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(endpoint->port);
        addr6.sin6_scope_id = endpoint->scope_id_u32;
        (void)memcpy(&addr6.sin6_addr, endpoint->address, 16u);
        rc = bind(
            tcp->listen_fd,
            (const struct sockaddr *)&addr6,
            (socklen_t)sizeof(addr6));
    } else {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (rc != 0 || set_nonblock(tcp->listen_fd) != 0
        || listen(tcp->listen_fd, 1) != 0) {
        ninlil_wifi_esp_tcp_close(tcp);
        return NINLIL_WIFI_IO_ERROR;
    }
    tcp->is_server = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tcp_poll_accepted(
    ninlil_wifi_esp_tcp_t *tcp)
{
    int accepted;
    if (tcp == NULL || tcp->listen_fd < 0 || !tcp->is_server) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    accepted = (int)accept(tcp->listen_fd, NULL, NULL);
    if (accepted < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NINLIL_WIFI_WOULD_BLOCK;
        }
        return NINLIL_WIFI_IO_ERROR;
    }
    if (set_nonblock(accepted) != 0) {
        (void)close(accepted);
        return NINLIL_WIFI_IO_ERROR;
    }
    (void)close(tcp->listen_fd);
    tcp->listen_fd = -1;
    tcp->fd = accepted;
    tcp->connected = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tcp_poll_connected(
    ninlil_wifi_esp_tcp_t *tcp)
{
    int err = 0;
    socklen_t len = (socklen_t)sizeof(err);
    fd_set wfds;
    struct timeval tv;
    int rc;
    if (tcp == NULL || tcp->fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tcp->connected) {
        return NINLIL_WIFI_OK;
    }
    FD_ZERO(&wfds);
    FD_SET(tcp->fd, &wfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select(tcp->fd + 1, NULL, &wfds, NULL, &tv);
    if (rc == 0) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    if (rc < 0) {
        return NINLIL_WIFI_IO_ERROR;
    }
    if (getsockopt(tcp->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        return NINLIL_WIFI_IO_ERROR;
    }
    if (err != 0) {
        return NINLIL_WIFI_IO_ERROR;
    }
    tcp->connected = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tcp_send(
    ninlil_wifi_esp_tcp_t *tcp,
    const uint8_t *data,
    size_t len,
    size_t *sent_out)
{
    ssize_t n;
    if (tcp == NULL || data == NULL || sent_out == NULL || tcp->fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *sent_out = 0u;
    n = send(tcp->fd, data, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NINLIL_WIFI_WOULD_BLOCK;
        }
        return NINLIL_WIFI_IO_ERROR;
    }
    *sent_out = (size_t)n;
    return (*sent_out < len) ? NINLIL_WIFI_WOULD_BLOCK : NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tcp_recv(
    ninlil_wifi_esp_tcp_t *tcp,
    uint8_t *data,
    size_t cap,
    size_t *got_out)
{
    ssize_t n;
    if (tcp == NULL || data == NULL || got_out == NULL || tcp->fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *got_out = 0u;
    n = recv(tcp->fd, data, cap, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NINLIL_WIFI_WOULD_BLOCK;
        }
        return NINLIL_WIFI_IO_ERROR;
    }
    if (n == 0) {
        return NINLIL_WIFI_CLOSED;
    }
    *got_out = (size_t)n;
    return NINLIL_WIFI_OK;
}
