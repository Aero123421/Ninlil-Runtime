#include <ninlil/posix_usb_serial_v1.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#else
#error "POSIX USB serial reference port supports Linux and macOS only"
#endif

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",          \
                __FILE__, __LINE__, #condition);                               \
            return 0;                                                          \
        }                                                                      \
    } while (0)

typedef struct pty_pair {
    int master;
    char slave_path[256];
} pty_pair_t;

static int pty_pair_open(pty_pair_t *pair)
{
    int slave = -1;
    int flags;

    pair->master = -1;
    pair->slave_path[0] = '\0';
    if (openpty(&pair->master, &slave, pair->slave_path, NULL, NULL) != 0) {
        return 0;
    }
    if (pair->slave_path[0] != '/' || close(slave) != 0) {
        (void)close(pair->master);
        pair->master = -1;
        return 0;
    }
    flags = fcntl(pair->master, F_GETFL, 0);
    if (flags < 0 || fcntl(pair->master, F_SETFL, flags | O_NONBLOCK) != 0) {
        (void)close(pair->master);
        pair->master = -1;
        return 0;
    }
    return 1;
}

static void pty_pair_close(pty_pair_t *pair)
{
    if (pair->master >= 0) {
        (void)close(pair->master);
        pair->master = -1;
    }
}

static int fd_write_all(int fd, const uint8_t *data, size_t length)
{
    size_t offset = 0u;
    unsigned int attempts;

    for (attempts = 0u; offset < length && attempts < 256u; ++attempts) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno != EINTR && errno != EAGAIN
            && errno != EWOULDBLOCK) {
            return 0;
        }
        {
            struct pollfd wait_fd;
            wait_fd.fd = fd;
            wait_fd.events = POLLOUT;
            wait_fd.revents = 0;
            (void)poll(&wait_fd, 1, 5);
        }
    }
    return offset == length;
}

static int host_to_adapter(
    int master,
    ninlil_byte_stream_t *stream,
    const uint8_t *expected,
    uint32_t length)
{
    uint8_t received[64];
    uint32_t offset = 0u;
    unsigned int attempts;

    REQUIRE(length <= (uint32_t)sizeof(received));
    REQUIRE(fd_write_all(master, expected, length));
    for (attempts = 0u; offset < length && attempts < 256u; ++attempts) {
        ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
        ninlil_byte_stream_error_t error;
        uint32_t got = 0u;
        ninlil_byte_stream_status_t status =
            ninlil_posix_usb_serial_poll(stream, 5u, &events, &error);
        REQUIRE(status == NINLIL_BYTE_STREAM_OK);
        status = ninlil_posix_usb_serial_read(
            stream, received + offset, length - offset, &got, &error);
        REQUIRE(status == NINLIL_BYTE_STREAM_OK);
        offset += got;
    }
    REQUIRE(offset == length);
    REQUIRE(memcmp(received, expected, length) == 0);
    return 1;
}

static int adapter_to_host(
    ninlil_byte_stream_t *stream,
    int master,
    const uint8_t *expected,
    uint32_t length)
{
    uint8_t received[64];
    uint32_t accepted = 0u;
    size_t offset = 0u;
    unsigned int attempts;
    ninlil_byte_stream_error_t error;

    REQUIRE(length <= (uint32_t)sizeof(received));
    REQUIRE(ninlil_posix_usb_serial_write(
        stream, expected, length, &accepted, &error) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(accepted == length);
    for (attempts = 0u; offset < length && attempts < 256u; ++attempts) {
        ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
        ssize_t got;
        REQUIRE(ninlil_posix_usb_serial_poll(stream, 5u, &events, &error)
            == NINLIL_BYTE_STREAM_OK);
        got = read(master, received + offset, length - offset);
        if (got > 0) {
            offset += (size_t)got;
        } else if (got < 0 && errno != EINTR && errno != EAGAIN
            && errno != EWOULDBLOCK) {
            return 0;
        }
    }
    REQUIRE(offset == length);
    REQUIRE(memcmp(received, expected, length) == 0);
    return 1;
}

static int run_consumer(void)
{
    static const uint8_t host_message[] = {0x48u, 0x6fu, 0x73u, 0x74u};
    static const uint8_t adapter_message[] = {0x4eu, 0x69u, 0x6eu, 0x6cu, 0x69u, 0x6cu};
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t error;
    pty_pair_t first;
    pty_pair_t second;
    uint64_t generation_one;
    uint64_t generation_two;

    first.master = -1;
    second.master = -1;
    REQUIRE(ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(pty_pair_open(&first));
    REQUIRE(ninlil_posix_usb_serial_open(&stream, first.slave_path, &error)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_posix_usb_serial_link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    generation_one = ninlil_posix_usb_serial_link_generation(&stream);
    REQUIRE(generation_one != 0u);
    REQUIRE(host_to_adapter(first.master, &stream,
        host_message, (uint32_t)sizeof(host_message)));
    REQUIRE(adapter_to_host(&stream, first.master,
        adapter_message, (uint32_t)sizeof(adapter_message)));
    REQUIRE(ninlil_posix_usb_serial_close(&stream, &error)
        == NINLIL_BYTE_STREAM_OK);
    pty_pair_close(&first);

    REQUIRE(pty_pair_open(&second));
    REQUIRE(ninlil_posix_usb_serial_open(&stream, second.slave_path, &error)
        == NINLIL_BYTE_STREAM_OK);
    generation_two = ninlil_posix_usb_serial_link_generation(&stream);
    REQUIRE(generation_two > generation_one);
    REQUIRE(ninlil_posix_usb_serial_close(&stream, &error)
        == NINLIL_BYTE_STREAM_OK);
    pty_pair_close(&second);
    return 1;
}

int main(void)
{
    if (!run_consumer()) {
        return 1;
    }
    (void)printf(
        "posix_usb_serial_v1_installed_consumer: PASS bidirectional=1 reopen=1 generation=1\n");
    return 0;
}
