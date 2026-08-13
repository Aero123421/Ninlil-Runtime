/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_tcp_posix.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void ninlil_wifi_tcp_init(ninlil_wifi_tcp_t *tcp)
{
    if (tcp == NULL) {
        return;
    }
    tcp->fd = -1;
    tcp->is_listener = 0;
    tcp->connected = 0;
}

void ninlil_wifi_tcp_close(ninlil_wifi_tcp_t *tcp)
{
    if (tcp == NULL) {
        return;
    }
    if (tcp->fd >= 0) {
        (void)close(tcp->fd);
    }
    tcp->fd = -1;
    tcp->is_listener = 0;
    tcp->connected = 0;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

ninlil_wifi_status_t ninlil_wifi_tcp_connect(
    ninlil_wifi_tcp_t *tcp,
    const ninlil_wifi_endpoint_t *endpoint)
{
    int fd;
    int rc;
    if (tcp == NULL || endpoint == NULL || endpoint->port == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_tcp_close(tcp);
    if (endpoint->address_kind == 1u) {
        struct sockaddr_in addr;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        if (set_nonblock(fd) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
#if defined(SO_NOSIGPIPE)
        {
            int one = 1;
            (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        }
#endif
        (void)memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(endpoint->port);
        (void)memcpy(&addr.sin_addr, endpoint->address, 4u);
        rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (rc != 0 && errno != EINPROGRESS) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        tcp->fd = fd;
        tcp->connected = (rc == 0) ? 1 : 0;
        return (rc == 0) ? NINLIL_WIFI_OK : NINLIL_WIFI_WOULD_BLOCK;
    }
    if (endpoint->address_kind == 2u) {
        struct sockaddr_in6 addr6;
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        if (set_nonblock(fd) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(endpoint->port);
        addr6.sin6_scope_id = endpoint->scope_id_u32;
        (void)memcpy(&addr6.sin6_addr, endpoint->address, 16u);
        rc = connect(fd, (struct sockaddr *)&addr6, sizeof(addr6));
        if (rc != 0 && errno != EINPROGRESS) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        tcp->fd = fd;
        tcp->connected = (rc == 0) ? 1 : 0;
        return (rc == 0) ? NINLIL_WIFI_OK : NINLIL_WIFI_WOULD_BLOCK;
    }
    return NINLIL_WIFI_UNSUPPORTED;
}

ninlil_wifi_status_t ninlil_wifi_tcp_listen_loopback(
    ninlil_wifi_tcp_t *listener,
    uint16_t port,
    uint16_t *bound_port_out)
{
    int fd;
    int one = 1;
    struct sockaddr_in addr;
    socklen_t alen;
    if (listener == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_tcp_close(listener);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NINLIL_WIFI_IO_ERROR;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (set_nonblock(fd) != 0) {
        (void)close(fd);
        return NINLIL_WIFI_IO_ERROR;
    }
    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        (void)close(fd);
        return NINLIL_WIFI_IO_ERROR;
    }
    if (listen(fd, 8) != 0) {
        (void)close(fd);
        return NINLIL_WIFI_IO_ERROR;
    }
    alen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        (void)close(fd);
        return NINLIL_WIFI_IO_ERROR;
    }
    listener->fd = fd;
    listener->is_listener = 1;
    listener->connected = 1;
    if (bound_port_out != NULL) {
        *bound_port_out = ntohs(addr.sin_port);
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tcp_listen(
    ninlil_wifi_tcp_t *listener,
    const ninlil_wifi_endpoint_t *endpoint,
    uint16_t *bound_port_out)
{
    int fd;
    int one = 1;
    socklen_t alen;
    if (listener == NULL || endpoint == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_tcp_close(listener);
    if (endpoint->address_kind == 1u) {
        struct sockaddr_in addr;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (set_nonblock(fd) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(endpoint->port);
        (void)memcpy(&addr.sin_addr, endpoint->address, 4u);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0
            || listen(fd, 8) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        alen = (socklen_t)sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        if (bound_port_out != NULL) {
            *bound_port_out = ntohs(addr.sin_port);
        }
    } else if (endpoint->address_kind == 2u) {
        struct sockaddr_in6 addr6;
        fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) {
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (set_nonblock(fd) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        (void)memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(endpoint->port);
        addr6.sin6_scope_id = endpoint->scope_id_u32;
        (void)memcpy(&addr6.sin6_addr, endpoint->address, 16u);
        if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0
            || listen(fd, 8) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        alen = (socklen_t)sizeof(addr6);
        if (getsockname(fd, (struct sockaddr *)&addr6, &alen) != 0) {
            (void)close(fd);
            return NINLIL_WIFI_IO_ERROR;
        }
        if (bound_port_out != NULL) {
            *bound_port_out = ntohs(addr6.sin6_port);
        }
    } else {
        return NINLIL_WIFI_UNSUPPORTED;
    }
    listener->fd = fd;
    listener->is_listener = 1;
    listener->connected = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tcp_accept(
    ninlil_wifi_tcp_t *listener,
    ninlil_wifi_tcp_t *client)
{
    int fd;
    if (listener == NULL || client == NULL || listener->fd < 0
        || !listener->is_listener) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    fd = accept(listener->fd, NULL, NULL);
    if (fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NINLIL_WIFI_WOULD_BLOCK;
        }
        return NINLIL_WIFI_IO_ERROR;
    }
    if (set_nonblock(fd) != 0) {
        (void)close(fd);
        return NINLIL_WIFI_IO_ERROR;
    }
    ninlil_wifi_tcp_close(client);
    client->fd = fd;
    client->connected = 1;
    client->is_listener = 0;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tcp_poll_connected(ninlil_wifi_tcp_t *tcp)
{
    int err = 0;
    socklen_t elen = sizeof(err);
    if (tcp == NULL || tcp->fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tcp->connected) {
        return NINLIL_WIFI_OK;
    }
    if (getsockopt(tcp->fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0) {
        return NINLIL_WIFI_IO_ERROR;
    }
    if (err == EINPROGRESS) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    if (err != 0) {
        return NINLIL_WIFI_IO_ERROR;
    }
    tcp->connected = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tcp_send(
    ninlil_wifi_tcp_t *tcp,
    const uint8_t *data,
    size_t len,
    size_t *sent_out)
{
    ssize_t n;
    if (tcp == NULL || data == NULL || sent_out == NULL || tcp->fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *sent_out = 0u;
#if defined(MSG_NOSIGNAL)
    n = send(tcp->fd, data, len, MSG_NOSIGNAL);
#else
    n = send(tcp->fd, data, len, 0);
#endif
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NINLIL_WIFI_WOULD_BLOCK;
        }
        return NINLIL_WIFI_IO_ERROR;
    }
    *sent_out = (size_t)n;
    return (*sent_out < len) ? NINLIL_WIFI_WOULD_BLOCK : NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tcp_recv(
    ninlil_wifi_tcp_t *tcp,
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
