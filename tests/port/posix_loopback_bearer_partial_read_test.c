/*
 * Regression: a nonblocking SOCK_STREAM receiver must preserve a partially
 * consumed frame across EAGAIN boundaries.
 */

#include "ninlil_posix_loopback_bearer.h"
#include "ninlil_posix_loopback_bearer_wire.h"

#include <ninlil/platform.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void write_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

static int write_exact(int fd, const void *bytes, size_t length)
{
    const uint8_t *cursor = (const uint8_t *)bytes;
    size_t offset = 0u;

    while (offset < length) {
        ssize_t written = write(fd, cursor + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int exchange_byte(int write_fd, int read_fd, char value)
{
    char received = 0;
    return write_exact(write_fd, &value, 1u)
        && read(read_fd, &received, 1u) == 1
        && received == value;
}

static int raw_sender(
    const char *socket_path,
    int notify_fd,
    int continue_fd)
{
    struct sockaddr_un address;
    ninlil_bearer_message_t message;
    uint8_t payload[] = {0x10u, 0x20u, 0x30u, 0x40u};
    uint8_t header[12];
    uint8_t *body = NULL;
    size_t body_length = 0u;
    size_t first_body_fragment;
    int socket_fd;
    uint32_t attempt;

    (void)memset(&message, 0, sizeof(message));
    message.abi_version = NINLIL_ABI_VERSION;
    message.struct_size = (uint16_t)sizeof(message);
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message.payload.data = payload;
    message.payload.length = sizeof(payload);
    if (!ninlil_posix_loopback_wire_encode(&message, &body, &body_length)
        || body_length > UINT32_MAX) {
        free(body);
        return 2;
    }
    (void)memset(header, 0, sizeof(header));
    write_u32_be(header, NINLIL_POSIX_LOOPBACK_WIRE_MAGIC);
    header[4] = (uint8_t)NINLIL_POSIX_LOOPBACK_WIRE_VERSION;
    write_u32_be(&header[8], (uint32_t)body_length);

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        free(body);
        return 3;
    }
    (void)memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    for (attempt = 0u; attempt < 2000u; ++attempt) {
        if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
            break;
        }
        (void)usleep(1000);
    }
    if (attempt == 2000u) {
        (void)close(socket_fd);
        free(body);
        return 4;
    }

    first_body_fragment = body_length < 7u ? body_length : 7u;
    if (!write_exact(socket_fd, header, 3u)
        || !exchange_byte(notify_fd, continue_fd, '1')
        || !write_exact(socket_fd, &header[3], sizeof(header) - 3u)
        || !write_exact(socket_fd, body, first_body_fragment)
        || !exchange_byte(notify_fd, continue_fd, '2')
        || !write_exact(
            socket_fd,
            body + first_body_fragment,
            body_length - first_body_fragment)
        || !exchange_byte(notify_fd, continue_fd, '3')) {
        (void)close(socket_fd);
        free(body);
        return 5;
    }
    (void)close(socket_fd);
    free(body);
    return 0;
}

static int await_fragment(int read_fd, char expected)
{
    char value = 0;
    return read(read_fd, &value, 1u) == 1 && value == expected;
}

int main(void)
{
    char socket_path[96];
    ninlil_posix_loopback_bearer_config_t config;
    ninlil_posix_loopback_bearer_t *bearer;
    const ninlil_bearer_ops_t *ops;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t received;
    ninlil_id128_t runtime_id;
    int child_to_parent[2];
    int parent_to_child[2];
    pid_t child;
    int status;
    uint32_t attempt;

    REQUIRE(snprintf(socket_path, sizeof(socket_path),
        "/tmp/ninlil-loopback-partial-%ld.sock", (long)getpid()) > 0);
    (void)unlink(socket_path);
    ninlil_posix_loopback_bearer_config_defaults(&config);
    config.socket_path = socket_path;
    config.role = NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER;
    bearer = ninlil_posix_loopback_bearer_create(&config);
    REQUIRE(bearer != NULL);
    ops = ninlil_posix_loopback_bearer_ops(bearer);
    REQUIRE(ops != NULL);
    REQUIRE(pipe(child_to_parent) == 0);
    REQUIRE(pipe(parent_to_child) == 0);

    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        int result;
        (void)close(child_to_parent[0]);
        (void)close(parent_to_child[1]);
        result = raw_sender(
            socket_path, child_to_parent[1], parent_to_child[0]);
        (void)close(child_to_parent[1]);
        (void)close(parent_to_child[0]);
        _exit(result);
    }
    (void)close(child_to_parent[1]);
    (void)close(parent_to_child[0]);
    (void)memset(&runtime_id, 0, sizeof(runtime_id));
    REQUIRE(ops->open(ops->user, &runtime_id, NINLIL_ROLE_CONTROLLER, &handle)
        == NINLIL_BEARER_OK);

    REQUIRE(await_fragment(child_to_parent[0], '1'));
    (void)memset(&received, 0, sizeof(received));
    REQUIRE(ops->receive_next(ops->user, handle, &received)
        == NINLIL_BEARER_EMPTY);
    REQUIRE(write_exact(parent_to_child[1], "1", 1u));

    REQUIRE(await_fragment(child_to_parent[0], '2'));
    REQUIRE(ops->receive_next(ops->user, handle, &received)
        == NINLIL_BEARER_EMPTY);
    REQUIRE(write_exact(parent_to_child[1], "2", 1u));

    REQUIRE(await_fragment(child_to_parent[0], '3'));
    for (attempt = 0u; attempt < 2000u; ++attempt) {
        ninlil_bearer_status_t receive_status =
            ops->receive_next(ops->user, handle, &received);
        if (receive_status == NINLIL_BEARER_OK) {
            break;
        }
        REQUIRE(receive_status == NINLIL_BEARER_EMPTY);
        (void)usleep(1000);
    }
    REQUIRE(attempt < 2000u);
    REQUIRE(received.kind == NINLIL_BEARER_MESSAGE_APPLICATION);
    REQUIRE(received.payload.length == 4u);
    REQUIRE(received.payload.data[0] == 0x10u);
    REQUIRE(received.payload.data[3] == 0x40u);
    REQUIRE(write_exact(parent_to_child[1], "3", 1u));
    ops->release_received(ops->user, handle, &received);
    ops->close(ops->user, handle);
    ninlil_posix_loopback_bearer_destroy(bearer);

    (void)close(child_to_parent[0]);
    (void)close(parent_to_child[1]);
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    (void)unlink(socket_path);
    return 0;
}
