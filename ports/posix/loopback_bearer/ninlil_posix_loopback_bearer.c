#include "ninlil_posix_loopback_bearer.h"

#include "ninlil_posix_loopback_bearer_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct loopback_loan {
    ninlil_bearer_message_t message;
    uint8_t *payload;
    uint8_t *evidence;
    uint8_t *namespace_id;
    uint8_t *service_id;
    uint8_t *schema_id;
    struct loopback_loan *next;
} loopback_loan_t;

typedef enum permit_state {
    PERMIT_LIVE = 0,
    PERMIT_CONSUMED = 1,
    PERMIT_RELEASED = 2
} permit_state_t;

typedef struct permit_record {
    ninlil_tx_permit_t permit;
    ninlil_id128_t transaction_id;
    ninlil_bearer_message_kind_t message_kind;
    uint32_t logical_bytes;
    ninlil_digest256_t content_digest;
    permit_state_t state;
} permit_record_t;

typedef struct loopback_handle {
    uint64_t id;
    struct ninlil_posix_loopback_bearer *owner;
    int live;
    loopback_loan_t *loan;
} loopback_handle_t;

struct ninlil_posix_loopback_bearer {
    ninlil_posix_loopback_bearer_config_t config;
    char owned_socket_path[512];
    int socket_fd;
    int peer_fd;
    int connected;
    ninlil_bearer_ops_t bearer_ops;
    ninlil_tx_gate_ops_t tx_gate_ops;
    loopback_handle_t *handle;
    loopback_loan_t *recv_queue;
    loopback_loan_t *orphan_loans;
    permit_record_t *permits;
    ninlil_id128_t current_clock_epoch_id;
    uint64_t current_time_ms;
    uint64_t availability_epoch;
    uint64_t next_permit_sequence;
    uint64_t queued_entries;
    uint64_t queued_bytes;
};

static int id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int id_equal(const ninlil_id128_t *a, const ninlil_id128_t *b)
{
    return memcmp(a->bytes, b->bytes, 16u) == 0;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0u;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        if (n == 0) {
            return 0;
        }
        off += (size_t)n;
    }
    return 1;
}

static void write_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
        | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

static int read_all(int fd, void *buf, size_t len, int *out_would_block)
{
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0u;

    if (out_would_block != NULL) {
        *out_would_block = 0;
    }
    while (off < len) {
        ssize_t n = read(fd, p + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (out_would_block != NULL
                && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                *out_would_block = 1;
            }
            return 0;
        }
        if (n == 0) {
            return 0;
        }
        off += (size_t)n;
    }
    return 1;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return 0;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return 0;
    }
    return 1;
}

static int disable_sigpipe(int fd)
{
#ifdef SO_NOSIGPIPE
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) == 0;
#else
    (void)fd;
    return 1;
#endif
}

static void free_loan(loopback_loan_t *loan)
{
    if (loan != NULL) {
        free(loan->payload);
        free(loan->evidence);
        free(loan->namespace_id);
        free(loan->service_id);
        free(loan->schema_id);
        free(loan);
    }
}

static loopback_loan_t *loan_from_wire(
    ninlil_posix_loopback_wire_message_t *wire)
{
    loopback_loan_t *loan;

    loan = (loopback_loan_t *)calloc(1u, sizeof(*loan));
    if (loan == NULL) {
        return NULL;
    }
    loan->message = wire->message;
    if (wire->owned_payload != NULL) {
        loan->payload = wire->owned_payload;
        wire->owned_payload = NULL;
        loan->message.payload.data = loan->payload;
    }
    if (wire->owned_evidence != NULL) {
        loan->evidence = wire->owned_evidence;
        wire->owned_evidence = NULL;
        loan->message.evidence.data = loan->evidence;
    }
    if (wire->owned_namespace_id != NULL) {
        loan->namespace_id = wire->owned_namespace_id;
        wire->owned_namespace_id = NULL;
        (void)memcpy(
            loan->message.service.namespace_id.bytes,
            loan->namespace_id,
            loan->message.service.namespace_id.length);
    }
    if (wire->owned_service_id != NULL) {
        loan->service_id = wire->owned_service_id;
        wire->owned_service_id = NULL;
        (void)memcpy(
            loan->message.service.service_id.bytes,
            loan->service_id,
            loan->message.service.service_id.length);
    }
    if (wire->owned_schema_id != NULL) {
        loan->schema_id = wire->owned_schema_id;
        wire->owned_schema_id = NULL;
        (void)memcpy(
            loan->message.service.schema_id.bytes,
            loan->schema_id,
            loan->message.service.schema_id.length);
    }
    return loan;
}

static int socket_send_frame(
    ninlil_posix_loopback_bearer_t *bearer,
    const ninlil_bearer_message_t *message)
{
    uint8_t header[12];
    uint8_t *body = NULL;
    size_t body_len = 0u;
    int ok;

    if (!ninlil_posix_loopback_wire_encode(message, &body, &body_len)) {
        return 0;
    }
    write_u32_be(header, NINLIL_POSIX_LOOPBACK_WIRE_MAGIC);
    header[4] = (uint8_t)NINLIL_POSIX_LOOPBACK_WIRE_VERSION;
    header[5] = 0u;
    write_u32_be(&header[8], (uint32_t)body_len);
    ok = write_all(bearer->peer_fd, header, sizeof(header))
        && write_all(bearer->peer_fd, body, body_len);
    free(body);
    if (!ok) {
        bearer->connected = 0;
        bearer->availability_epoch += 1u;
    }
    return ok;
}

static int socket_poll_receive(ninlil_posix_loopback_bearer_t *bearer)
{
    uint8_t header[12];
    uint32_t magic;
    uint32_t body_len;
    uint8_t *body;
    ninlil_posix_loopback_wire_message_t wire;
    loopback_loan_t *loan;
    int would_block = 0;

    if (!bearer->connected || bearer->peer_fd < 0) {
        return 0;
    }
    if (!read_all(bearer->peer_fd, header, sizeof(header), &would_block)) {
        if (would_block != 0) {
            return 0;
        }
        bearer->connected = 0;
        bearer->availability_epoch += 1u;
        return 0;
    }
    magic = read_u32_be(header);
    if (magic != NINLIL_POSIX_LOOPBACK_WIRE_MAGIC
        || header[4] != (uint8_t)NINLIL_POSIX_LOOPBACK_WIRE_VERSION) {
        bearer->connected = 0;
        bearer->availability_epoch += 1u;
        return 0;
    }
    body_len = read_u32_be(&header[8]);
    if (body_len == 0u || body_len > 1048576u) {
        return 0;
    }
    body = (uint8_t *)malloc(body_len);
    if (body == NULL) {
        return 0;
    }
    if (!read_all(bearer->peer_fd, body, body_len, &would_block)) {
        free(body);
        if (would_block != 0) {
            return 0;
        }
        bearer->connected = 0;
        bearer->availability_epoch += 1u;
        return 0;
    }
    ninlil_posix_loopback_wire_message_init(&wire);
    if (!ninlil_posix_loopback_wire_decode(body, body_len, &wire)) {
        free(body);
        ninlil_posix_loopback_wire_message_clear(&wire);
        return 0;
    }
    free(body);
    loan = loan_from_wire(&wire);
    ninlil_posix_loopback_wire_message_clear(&wire);
    if (loan == NULL) {
        return 0;
    }
    loan->next = bearer->recv_queue;
    bearer->recv_queue = loan;
    bearer->queued_entries += 1u;
    bearer->queued_bytes += loan->message.payload.length + loan->message.evidence.length;
    return 1;
}

static int server_accept_peer(ninlil_posix_loopback_bearer_t *bearer)
{
    if (bearer->config.role != NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER) {
        return bearer->connected;
    }
    if (bearer->connected != 0) {
        return 1;
    }
    if (bearer->socket_fd < 0) {
        return 0;
    }
    if (bearer->peer_fd >= 0) {
        (void)close(bearer->peer_fd);
        bearer->peer_fd = -1;
    }
    bearer->peer_fd = accept(bearer->socket_fd, NULL, NULL);
    if (bearer->peer_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        bearer->connected = 0;
        bearer->availability_epoch += 1u;
        return 0;
    }
    if (!set_nonblocking(bearer->peer_fd)) {
        (void)close(bearer->peer_fd);
        bearer->peer_fd = -1;
        return 0;
    }
    (void)disable_sigpipe(bearer->peer_fd);
    bearer->connected = 1;
    bearer->availability_epoch += 1u;
    return 1;
}

static int connect_socket(ninlil_posix_loopback_bearer_t *bearer)
{
    struct sockaddr_un addr;
    int fd;

    if (bearer->config.socket_path == NULL || bearer->config.socket_path[0] == '\0') {
        return 0;
    }
    (void)memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
        bearer->config.socket_path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }
    if (bearer->config.role == NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER) {
        if (bearer->socket_fd >= 0) {
            return 1;
        }
        (void)unlink(bearer->config.socket_path);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            (void)close(fd);
            return 0;
        }
        if (listen(fd, 1) != 0) {
            (void)close(fd);
            return 0;
        }
        bearer->socket_fd = fd;
        bearer->peer_fd = accept(fd, NULL, NULL);
        if (bearer->peer_fd < 0) {
            (void)close(fd);
            bearer->socket_fd = -1;
            return 0;
        }
        if (!set_nonblocking(bearer->peer_fd)) {
            (void)close(bearer->peer_fd);
            bearer->peer_fd = -1;
            (void)close(fd);
            bearer->socket_fd = -1;
            return 0;
        }
        (void)disable_sigpipe(bearer->peer_fd);
        if (!set_nonblocking(fd)) {
            (void)close(bearer->peer_fd);
            bearer->peer_fd = -1;
            (void)close(fd);
            bearer->socket_fd = -1;
            return 0;
        }
    } else {
        uint32_t attempt;
        for (attempt = 0u; attempt < 400u; ++attempt) {
            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                break;
            }
            (void)usleep(25000);
        }
        if (attempt >= 400u) {
            (void)close(fd);
            return 0;
        }
        bearer->socket_fd = -1;
        bearer->peer_fd = fd;
        if (!set_nonblocking(bearer->peer_fd)) {
            (void)close(bearer->peer_fd);
            bearer->peer_fd = -1;
            return 0;
        }
        (void)disable_sigpipe(bearer->peer_fd);
    }
    bearer->connected = 1;
    bearer->availability_epoch += 1u;
    return 1;
}

static ninlil_bearer_status_t lb_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    loopback_handle_t *handle;

    (void)runtime_id;
    (void)role;
    if (bearer == NULL || out_handle == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    if (bearer->handle != NULL && bearer->handle->live) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    if (!bearer->connected && bearer->socket_fd < 0 && !connect_socket(bearer)) {
        return NINLIL_BEARER_UNAVAILABLE;
    }
    handle = (loopback_handle_t *)calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    handle->id = 1u;
    handle->owner = bearer;
    handle->live = 1;
    bearer->handle = handle;
    *out_handle = (ninlil_bearer_handle_t)handle;
    return NINLIL_BEARER_OK;
}

static void lb_close(void *user, ninlil_bearer_handle_t opaque)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    loopback_handle_t *handle = (loopback_handle_t *)opaque;

    if (bearer == NULL || handle == NULL || handle->owner != bearer) {
        return;
    }
    if (handle->loan != NULL) {
        handle->loan->next = bearer->orphan_loans;
        bearer->orphan_loans = handle->loan;
        handle->loan = NULL;
    }
    handle->live = 0;
    bearer->handle = NULL;
    free(handle);
}

static uint64_t logical_bytes(const ninlil_bearer_message_t *message)
{
    return 455u + message->service.namespace_id.length
        + message->service.service_id.length + message->service.schema_id.length
        + message->payload.length + message->evidence.length;
}

static ninlil_bearer_status_t lb_send(
    void *user,
    ninlil_bearer_handle_t opaque,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    loopback_handle_t *handle = (loopback_handle_t *)opaque;
    permit_record_t *record = NULL;
    uint32_t index;

    if (bearer == NULL || handle == NULL || handle->owner != bearer
        || !handle->live || permit == NULL || message == NULL
        || out_result == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    if (!bearer->connected && !server_accept_peer(bearer)) {
        return NINLIL_BEARER_UNAVAILABLE;
    }
    for (index = 0u; index < bearer->config.max_permits; ++index) {
        record = &bearer->permits[index];
        if (!id_is_zero(&record->permit.permit_id)
            && id_equal(&record->permit.permit_id, &permit->permit_id)
            && record->state == PERMIT_LIVE) {
            break;
        }
        record = NULL;
    }
    if (record == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    record->state = PERMIT_CONSUMED;
    if (!socket_send_frame(bearer, message)) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);
    out_result->kind = NINLIL_BEARER_SEND_ACCEPTED;
    out_result->availability_epoch = bearer->availability_epoch;
    (void)logical_bytes;
    return NINLIL_BEARER_OK;
}

static ninlil_bearer_status_t lb_receive(
    void *user,
    ninlil_bearer_handle_t opaque,
    ninlil_bearer_message_t *out_message)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    loopback_handle_t *handle = (loopback_handle_t *)opaque;
    loopback_loan_t *loan;

    if (bearer == NULL || handle == NULL || handle->owner != bearer
        || !handle->live || out_message == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    if (handle->loan != NULL) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    if (!bearer->connected && !server_accept_peer(bearer)) {
        return NINLIL_BEARER_EMPTY;
    }
    while (bearer->recv_queue == NULL) {
        if (!bearer->connected) {
            return NINLIL_BEARER_UNAVAILABLE;
        }
        if (!socket_poll_receive(bearer)) {
            return NINLIL_BEARER_EMPTY;
        }
    }
    loan = bearer->recv_queue;
    bearer->recv_queue = loan->next;
    if (bearer->queued_entries > 0u) {
        bearer->queued_entries -= 1u;
    }
    handle->loan = loan;
    *out_message = loan->message;
    return NINLIL_BEARER_OK;
}

static void lb_release(void *user, ninlil_bearer_handle_t opaque, ninlil_bearer_message_t *message)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    loopback_handle_t *handle = (loopback_handle_t *)opaque;

    (void)message;
    if (bearer == NULL || handle == NULL || handle->owner != bearer) {
        return;
    }
    if (handle->loan != NULL) {
        free_loan(handle->loan);
        handle->loan = NULL;
    }
}

static ninlil_bearer_status_t lb_state(
    void *user,
    ninlil_bearer_handle_t opaque,
    ninlil_bearer_state_t *out_state)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    loopback_handle_t *handle = (loopback_handle_t *)opaque;

    if (out_state == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    out_state->abi_version = NINLIL_ABI_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    if (bearer == NULL || handle == NULL || handle->owner != bearer || !handle->live) {
        return NINLIL_BEARER_DENIED;
    }
    if (!bearer->connected) {
        (void)server_accept_peer(bearer);
    }
    out_state->availability_epoch = bearer->availability_epoch;
    out_state->available = bearer->connected ? 1u : 0u;
    return NINLIL_BEARER_OK;
}

static ninlil_tx_gate_status_t lb_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    uint32_t index;
    permit_record_t *slot = NULL;

    if (bearer == NULL || request == NULL || now == NULL || out_permit == NULL) {
        return NINLIL_TX_GATE_DENIED;
    }
    for (index = 0u; index < bearer->config.max_permits; ++index) {
        if (id_is_zero(&bearer->permits[index].permit.permit_id)) {
            slot = &bearer->permits[index];
            break;
        }
    }
    if (slot == NULL) {
        return NINLIL_TX_GATE_TEMPORARY;
    }
    (void)memset(slot, 0, sizeof(*slot));
    (void)memset(out_permit, 0, sizeof(*out_permit));
    out_permit->abi_version = NINLIL_ABI_VERSION;
    out_permit->struct_size = (uint16_t)sizeof(*out_permit);
    bearer->next_permit_sequence += 1u;
    out_permit->permit_id.bytes[0] = (uint8_t)(bearer->next_permit_sequence & 0xffu);
    out_permit->permit_id.bytes[15] = 0x7fu;
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms = now->now_ms + 60000u;
    slot->permit = *out_permit;
    slot->transaction_id = request->transaction_id;
    slot->message_kind = request->message_kind;
    slot->logical_bytes = request->logical_bytes;
    slot->content_digest = request->content_digest;
    slot->state = PERMIT_LIVE;
    return NINLIL_TX_GATE_OK;
}

static void lb_tx_release(void *user, const ninlil_tx_permit_t *permit)
{
    ninlil_posix_loopback_bearer_t *bearer = (ninlil_posix_loopback_bearer_t *)user;
    uint32_t index;

    if (bearer == NULL || permit == NULL) {
        return;
    }
    for (index = 0u; index < bearer->config.max_permits; ++index) {
        if (!id_is_zero(&bearer->permits[index].permit.permit_id)
            && id_equal(&bearer->permits[index].permit.permit_id, &permit->permit_id)) {
            (void)memset(&bearer->permits[index], 0, sizeof(bearer->permits[index]));
            return;
        }
    }
}

void ninlil_posix_loopback_bearer_config_defaults(
    ninlil_posix_loopback_bearer_config_t *config)
{
    if (config == NULL) {
        return;
    }
    (void)memset(config, 0, sizeof(*config));
    config->role = NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER;
    config->max_entries_per_direction = 64u;
    config->max_bytes_per_direction = 131072u;
    config->max_permits = 128u;
    config->permit_issuer_id.bytes[0] = 0x80u;
    config->permit_issuer_id.bytes[15] = 0x02u;
    config->initial_clock_epoch_id.bytes[0] = 0xa0u;
    config->initial_clock_epoch_id.bytes[15] = 0x02u;
    config->initial_time_ms = 1000u;
}

ninlil_posix_loopback_bearer_t *ninlil_posix_loopback_bearer_create(
    const ninlil_posix_loopback_bearer_config_t *config)
{
    ninlil_posix_loopback_bearer_t *bearer;

    if (config == NULL || config->socket_path == NULL) {
        return NULL;
    }
    bearer = (ninlil_posix_loopback_bearer_t *)calloc(1u, sizeof(*bearer));
    if (bearer == NULL) {
        return NULL;
    }
    bearer->config = *config;
    (void)snprintf(bearer->owned_socket_path, sizeof(bearer->owned_socket_path),
        "%s", config->socket_path);
    bearer->config.socket_path = bearer->owned_socket_path;
    bearer->socket_fd = -1;
    bearer->peer_fd = -1;
    bearer->current_clock_epoch_id = config->initial_clock_epoch_id;
    bearer->current_time_ms = config->initial_time_ms;
    bearer->permits = (permit_record_t *)calloc(
        config->max_permits, sizeof(permit_record_t));
    if (bearer->permits == NULL) {
        free(bearer);
        return NULL;
    }
    bearer->bearer_ops.abi_version = NINLIL_ABI_VERSION;
    bearer->bearer_ops.struct_size = (uint16_t)sizeof(bearer->bearer_ops);
    bearer->bearer_ops.user = bearer;
    bearer->bearer_ops.open = lb_open;
    bearer->bearer_ops.close = lb_close;
    bearer->bearer_ops.send = lb_send;
    bearer->bearer_ops.receive_next = lb_receive;
    bearer->bearer_ops.release_received = lb_release;
    bearer->bearer_ops.state = lb_state;
    bearer->tx_gate_ops.abi_version = NINLIL_ABI_VERSION;
    bearer->tx_gate_ops.struct_size = (uint16_t)sizeof(bearer->tx_gate_ops);
    bearer->tx_gate_ops.user = bearer;
    bearer->tx_gate_ops.acquire = lb_tx_acquire;
    bearer->tx_gate_ops.release_unused = lb_tx_release;
    return bearer;
}

void ninlil_posix_loopback_bearer_destroy(ninlil_posix_loopback_bearer_t *bearer)
{
    loopback_loan_t *loan;

    if (bearer == NULL) {
        return;
    }
    if (bearer->handle != NULL) {
        lb_close(bearer, (ninlil_bearer_handle_t)bearer->handle);
    }
    while (bearer->recv_queue != NULL) {
        loan = bearer->recv_queue;
        bearer->recv_queue = loan->next;
        free_loan(loan);
    }
    while (bearer->orphan_loans != NULL) {
        loan = bearer->orphan_loans;
        bearer->orphan_loans = loan->next;
        free_loan(loan);
    }
    if (bearer->peer_fd >= 0) {
        (void)close(bearer->peer_fd);
    }
    if (bearer->socket_fd >= 0) {
        (void)close(bearer->socket_fd);
    }
    if (bearer->owned_socket_path[0] != '\0'
        && bearer->config.role == NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER) {
        (void)unlink(bearer->owned_socket_path);
    }
    free(bearer->permits);
    free(bearer);
}

const ninlil_bearer_ops_t *ninlil_posix_loopback_bearer_ops(
    ninlil_posix_loopback_bearer_t *bearer)
{
    return bearer == NULL ? NULL : &bearer->bearer_ops;
}

const ninlil_tx_gate_ops_t *ninlil_posix_loopback_bearer_tx_gate_ops(
    ninlil_posix_loopback_bearer_t *bearer)
{
    return bearer == NULL ? NULL : &bearer->tx_gate_ops;
}

int ninlil_posix_loopback_bearer_set_time(
    ninlil_posix_loopback_bearer_t *bearer,
    ninlil_id128_t clock_epoch_id,
    uint64_t now_ms)
{
    if (bearer == NULL) {
        return 0;
    }
    bearer->current_clock_epoch_id = clock_epoch_id;
    bearer->current_time_ms = now_ms;
    return 1;
}

int ninlil_posix_loopback_bearer_connected(
    const ninlil_posix_loopback_bearer_t *bearer)
{
    return bearer != NULL && bearer->connected != 0;
}
