/*
 * Host-test-only: fcntl FD_CLOEXEC fallback path coverage.
 *
 * Built only against ninlil_posix_usb_serial_cloexec_fallback with
 * NINLIL_POSIX_USB_SERIAL_FORCE_FCNTL_CLOEXEC_FALLBACK so modern Linux/macOS
 * compile the fallback that production omits when O_CLOEXEC is available.
 * Not Required HIL; not U1 complete; not install/public ABI/ESP packaging.
 */

#include "ninlil_posix_usb_serial.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct fake_serial {
    int open_calls;
    int last_open_flags;
    int close_calls;
    int set_cloexec_calls;
    int tcsetattr_calls;
    int fd_token;
    int is_open;
} fake_serial_t;

static int fake_open(const char *path, int flags, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)path;
    f->open_calls += 1;
    f->last_open_flags = flags;
    f->is_open = 1;
    f->fd_token = 77;
    return f->fd_token;
}

static int fake_close(int fd, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->close_calls += 1;
    f->is_open = 0;
    return 0;
}

static int fake_read(int fd, void *buf, size_t n, void *user)
{
    (void)fd;
    (void)buf;
    (void)n;
    (void)user;
    errno = EAGAIN;
    return -1;
}

static int fake_write(int fd, const void *buf, size_t n, void *user)
{
    (void)fd;
    (void)buf;
    (void)user;
    return (int)n;
}

static int fake_poll(
    int fd,
    int want_events,
    int *got_events,
    int timeout_ms,
    void *user)
{
    (void)fd;
    (void)want_events;
    (void)timeout_ms;
    (void)user;
    if (got_events != NULL) {
        *got_events = 0;
    }
    return 0;
}

static int fake_tcgetattr(int fd, void *termios_out, void *user)
{
    struct termios *tio = (struct termios *)termios_out;

    (void)fd;
    (void)user;
    (void)memset(tio, 0, sizeof(*tio));
    return 0;
}

static int fake_tcsetattr(int fd, int actions, const void *termios_in, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    (void)actions;
    (void)termios_in;
    f->tcsetattr_calls += 1;
    return 0;
}

static int fake_ioctl(int fd, unsigned long request, void *arg, void *user)
{
    (void)fd;
    (void)request;
    (void)arg;
    (void)user;
    return 0;
}

static int fake_set_cloexec_ok(int fd, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->set_cloexec_calls += 1;
    return 0;
}

static int fake_set_cloexec_fail(int fd, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->set_cloexec_calls += 1;
    errno = EINVAL;
    return -1;
}

static void fake_ops_init(ninlil_posix_usb_serial_sys_ops_t *ops, fake_serial_t *f)
{
    (void)memset(ops, 0, sizeof(*ops));
    (void)memset(f, 0, sizeof(*f));
    ops->open_fn = fake_open;
    ops->close_fn = fake_close;
    ops->read_fn = fake_read;
    ops->write_fn = fake_write;
    ops->poll_fn = fake_poll;
    ops->tcgetattr_fn = fake_tcgetattr;
    ops->tcsetattr_fn = fake_tcsetattr;
    ops->ioctl_fn = fake_ioctl;
    ops->user = f;
}

/*
 * Fallback open flags are exactly the three non-CLOEXEC bits (no O_CLOEXEC).
 * set_cloexec runs exactly once; open/close succeed.
 */
static int test_fcntl_cloexec_fallback_ok(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    const int expected = O_RDWR | O_NOCTTY | O_NONBLOCK;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.set_cloexec_fn = fake_set_cloexec_ok;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.last_open_flags == expected);
    REQUIRE(fake.set_cloexec_calls == 1);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.set_cloexec_calls == 1);
    return 0;
}

/*
 * Fallback set_cloexec failure: OPEN stage + original errno, fence/close
 * exactly once, link not UP; later close must not re-close (delta 0).
 */
static int test_fcntl_cloexec_fallback_fail_fences(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    int closes_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.set_cloexec_fn = fake_set_cloexec_fail;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_OPEN);
    REQUIRE(err.sys_errno == (int32_t)EINVAL);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(fake.set_cloexec_calls == 1);
    REQUIRE(fake.close_calls == 1);
    REQUIRE(stream.ops->link(&stream) != NINLIL_BYTE_STREAM_LINK_UP);
    closes_before = fake.close_calls;
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.close_calls == closes_before);
    return 0;
}

int main(void)
{
#if !defined(NINLIL_POSIX_USB_SERIAL_FORCE_FCNTL_CLOEXEC_FALLBACK)
#error "cloexec fallback test must be built with FORCE_FCNTL_CLOEXEC_FALLBACK"
#endif
    REQUIRE(test_fcntl_cloexec_fallback_ok() == 0);
    REQUIRE(test_fcntl_cloexec_fallback_fail_fences() == 0);
    (void)printf("posix_usb_serial_cloexec_fallback_test ok (%d cases)\n", 2);
    return 0;
}
