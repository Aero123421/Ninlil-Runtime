/*
 * U1 host tests: POSIX USB/serial byte-stream adapter.
 * Deterministic PTY + syscall seam. No timing-flaky sleeps.
 * Does not claim physical USB HIL or U1 complete.
 */

#include "ninlil_posix_usb_serial.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <util.h>
#elif defined(__linux__)
#include <pty.h>
#else
#error "posix_usb_serial tests target Linux/macOS only"
#endif

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

/* ---------- PTY helpers -------------------------------------------------- */

typedef struct pty_pair {
    int master;
    int slave;
    char slave_path[128];
} pty_pair_t;

static int open_pty_pair(pty_pair_t *pair)
{
    int master = -1;
    int slave = -1;
    char name[128];

    (void)memset(pair, 0, sizeof(*pair));
    pair->master = -1;
    pair->slave = -1;

    if (openpty(&master, &slave, name, NULL, NULL) != 0) {
        return 0;
    }
    if (name[0] != '/') {
        (void)close(master);
        (void)close(slave);
        return 0;
    }
    pair->master = master;
    pair->slave = slave;
    (void)snprintf(pair->slave_path, sizeof(pair->slave_path), "%s", name);
    (void)close(pair->slave);
    pair->slave = -1;
    return 1;
}

static void close_pty_pair(pty_pair_t *pair)
{
    if (pair->master >= 0) {
        (void)close(pair->master);
        pair->master = -1;
    }
    if (pair->slave >= 0) {
        (void)close(pair->slave);
        pair->slave = -1;
    }
}

/* Exact full write: EINTR retry, EAGAIN poll, partial advance. Returns 1 iff all. */
static int write_fd_all(int fd, const uint8_t *data, size_t len)
{
    size_t off = 0u;
    int spins = 0;
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    while (off < len && spins < 256) {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                (void)poll(&pfd, 1, 20);
                ++spins;
                continue;
            }
            return 0;
        }
        if (n == 0) {
            ++spins;
            continue;
        }
        off += (size_t)n;
        spins = 0;
    }
    return off == len;
}

static int write_master_all(int master, const uint8_t *data, size_t len)
{
    return write_fd_all(master, data, len);
}

/* Best-effort write for overflow injection: contracts EINTR/EAGAIN/partial. */
static size_t write_fd_best_effort(int fd, const uint8_t *data, size_t len)
{
    size_t off = 0u;
    int spins = 0;

    while (off < len && spins < 64) {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                if (poll(&pfd, 1, 5) <= 0) {
                    break;
                }
                ++spins;
                continue;
            }
            break;
        }
        if (n == 0) {
            ++spins;
            continue;
        }
        off += (size_t)n;
        spins = 0;
    }
    return off;
}

/* Best-effort read (drain): EINTR retry; EAGAIN → 0; hard error → -1. */
static ssize_t read_fd_best_effort(int fd, void *buf, size_t len)
{
    for (;;) {
        ssize_t n = read(fd, buf, len);
        if (n >= 0) {
            return n;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

/* Exact full read: EINTR retry, partial advance. Returns 1 iff all. */
static int read_fd_all(int fd, void *buf, size_t len)
{
    size_t off = 0u;
    while (off < len) {
        ssize_t n = read(fd, (uint8_t *)buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        if (n == 0) {
            return 0; /* EOF before complete */
        }
        off += (size_t)n;
    }
    return 1;
}

static int push_to_adapter(
    ninlil_byte_stream_t *stream,
    int master,
    const uint8_t *data,
    size_t len)
{
    size_t off = 0u;
    int spins = 0;
    int flags = fcntl(master, F_GETFL, 0);

    if (flags >= 0) {
        (void)fcntl(master, F_SETFL, flags | O_NONBLOCK);
    }
    while (off < len && spins < 512) {
        ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
        ninlil_byte_stream_error_t err;
        ssize_t n;

        if (off < len) {
            n = write(master, data + off, len - off);
            if (n > 0) {
                off += (size_t)n;
                spins = 0;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK
                && errno != EINTR) {
                return 0;
            }
        }
        if (stream->ops->poll(stream, 5u, &events, &err) != NINLIL_BYTE_STREAM_OK
            && err.status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN) {
            return 0;
        }
        ++spins;
    }
    return off == len;
}

/* ---------- Full fake serial seam ---------------------------------------- */

typedef struct fake_serial {
    int open_calls;
    int last_open_flags;
    int open_errno; /* if non-zero, open fails */
    int busy_tiocexcl;
    int dtr_get_fail;
    int dtr_set_fail;
    int tiocmget_calls;
    int tiocmset_calls;
    int last_tiocmget_bits;
    int last_tiocmset_bits;
    int close_errno; /* if non-zero, close fails once */
    int close_calls;
    int set_cloexec_calls;
    int poll_eintr_left;
    int poll_io_errno; /* main (any-timeout) poll path: return -1 with errno */
    int poll_calls;
    int write_calls;
    int read_calls;
    int write_io_error;
    int read_io_error;
    int write_eintr_left;
    int read_eintr_left;
    /* Deliver synthetic RX until fill_rx_total (for exact 4KiB ring fill). */
    uint32_t fill_rx_total;
    uint32_t fill_rx_delivered;
    /*
     * Zero-timeout poll (RX-full probe) controls. Main poll uses timeout_ms>0
     * or non-zero timeout path; probe uses timeout_ms==0.
     */
    int probe_eintr_left;
    int probe_io_errno;
    int probe_revents;
    int probe_revents_set;
    int zero_timeout_polls;
    int tcsetattr_calls;
    int last_tcsetattr_actions;
    struct termios last_termios;
    int has_termios;
    int64_t now_ms;
    int advance_ms_on_write;
    int last_poll_timeout_ms;
    int poll_timeout_samples;
    int max_poll_timeout_ms;
    int min_poll_timeout_ms;
    uint8_t rx_seed[64];
    uint32_t rx_seed_len;
    uint32_t rx_seed_off;
    int fd_token;
    int is_open;
} fake_serial_t;

static int fake_open(const char *path, int flags, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)path;
    f->open_calls += 1;
    f->last_open_flags = flags;
    if (f->open_errno != 0) {
        errno = f->open_errno;
        return -1;
    }
    f->is_open = 1;
    f->fd_token = 77;
    return f->fd_token;
}

static int fake_close(int fd, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->close_calls += 1;
    if (f->close_errno != 0) {
        int err = f->close_errno;
        f->close_errno = 0; /* one-shot */
        errno = err;
        f->is_open = 0;
        return -1;
    }
    f->is_open = 0;
    return 0;
}

static int fake_read(int fd, void *buf, size_t n, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;
    uint32_t remain;
    uint32_t take;

    (void)fd;
    f->read_calls += 1;
    if (f->read_eintr_left > 0) {
        f->read_eintr_left -= 1;
        errno = EINTR;
        return -1;
    }
    if (f->read_io_error) {
        errno = EIO;
        return -1;
    }
    if (f->fill_rx_total > f->fill_rx_delivered) {
        remain = f->fill_rx_total - f->fill_rx_delivered;
        take = remain;
        if ((size_t)take > n) {
            take = (uint32_t)n;
        }
        (void)memset(buf, 0xA5, take);
        f->fill_rx_delivered += take;
        return (int)take;
    }
    if (f->rx_seed_off >= f->rx_seed_len) {
        errno = EAGAIN;
        return -1;
    }
    remain = f->rx_seed_len - f->rx_seed_off;
    take = remain;
    if ((size_t)take > n) {
        take = (uint32_t)n;
    }
    (void)memcpy(buf, f->rx_seed + f->rx_seed_off, take);
    f->rx_seed_off += take;
    return (int)take;
}

static int fake_write(int fd, const void *buf, size_t n, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    (void)buf;
    f->write_calls += 1;
    if (f->advance_ms_on_write > 0) {
        f->now_ms += f->advance_ms_on_write;
    }
    if (f->write_eintr_left > 0) {
        f->write_eintr_left -= 1;
        errno = EINTR;
        return -1;
    }
    if (f->write_io_error) {
        /* Non-link-down IO error so pump returns IO_ERROR not ERR_LINK_DOWN. */
        errno = ENOSPC;
        return -1;
    }
    return (int)n;
}

static int64_t fake_now_ms(void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    return f->now_ms;
}

static int fake_poll(
    int fd,
    int want_events,
    int *got_events,
    int timeout_ms,
    void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    (void)want_events;
    f->poll_calls += 1;
    f->last_poll_timeout_ms = timeout_ms;
    f->poll_timeout_samples += 1;
    if (f->poll_timeout_samples == 1) {
        f->max_poll_timeout_ms = timeout_ms;
        f->min_poll_timeout_ms = timeout_ms;
    } else {
        if (timeout_ms > f->max_poll_timeout_ms) {
            f->max_poll_timeout_ms = timeout_ms;
        }
        if (timeout_ms < f->min_poll_timeout_ms) {
            f->min_poll_timeout_ms = timeout_ms;
        }
    }
    /* RX-full probe path uses non-blocking poll (timeout_ms == 0). */
    if (timeout_ms == 0) {
        f->zero_timeout_polls += 1;
        if (f->probe_eintr_left > 0) {
            f->probe_eintr_left -= 1;
            errno = EINTR;
            return -1;
        }
        if (f->probe_io_errno != 0) {
            errno = f->probe_io_errno;
            return -1;
        }
        if (f->probe_revents_set) {
            if (got_events != NULL) {
                *got_events = f->probe_revents;
            }
            return (f->probe_revents != 0) ? 1 : 0;
        }
    }
    if (f->poll_eintr_left > 0) {
        f->poll_eintr_left -= 1;
        errno = EINTR;
        return -1;
    }
    if (f->poll_io_errno != 0) {
        errno = f->poll_io_errno;
        return -1;
    }
    if (got_events != NULL) {
        *got_events = 0;
        if (f->fill_rx_delivered < f->fill_rx_total
            || f->rx_seed_off < f->rx_seed_len) {
            *got_events |= POLLIN;
        }
        *got_events |= POLLOUT;
    }
    return 1;
}

static int fake_tcgetattr(int fd, void *termios_out, void *user)
{
    struct termios *tio = (struct termios *)termios_out;

    (void)fd;
    (void)user;
    /* Start with non-raw bits so tcsetattr result proves reconfiguration. */
    (void)memset(tio, 0, sizeof(*tio));
    tio->c_iflag = (tcflag_t)(ICRNL | IXON);
    tio->c_oflag = (tcflag_t)OPOST;
    tio->c_lflag = (tcflag_t)(ICANON | ECHO | ISIG);
    tio->c_cflag = (tcflag_t)(CS7 | PARENB | CSTOPB);
    tio->c_cc[VMIN] = 1;
    tio->c_cc[VTIME] = 5;
    return 0;
}

static int fake_tcsetattr(int fd, int actions, const void *termios_in, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->tcsetattr_calls += 1;
    f->last_tcsetattr_actions = actions;
    if (termios_in != NULL) {
        (void)memcpy(&f->last_termios, termios_in, sizeof(f->last_termios));
        f->has_termios = 1;
    }
    return 0;
}

static int fake_ioctl(int fd, unsigned long request, void *arg, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
#if defined(TIOCEXCL)
    if (request == (unsigned long)TIOCEXCL) {
        if (f->busy_tiocexcl) {
            errno = EBUSY;
            return -1;
        }
        return 0;
    }
#endif
#if defined(TIOCMGET) && defined(TIOCM_DTR)
    if (request == (unsigned long)TIOCMGET) {
        f->tiocmget_calls += 1;
        if (f->dtr_get_fail) {
            errno = ENOTTY;
            return -1;
        }
        if (arg != NULL) {
            /* Pre-assert modem bits without DTR so OR is observable. */
            *(int *)arg = 0;
            f->last_tiocmget_bits = 0;
        }
        return 0;
    }
#endif
#if defined(TIOCMSET) && defined(TIOCM_DTR)
    if (request == (unsigned long)TIOCMSET) {
        f->tiocmset_calls += 1;
        if (arg != NULL) {
            f->last_tiocmset_bits = *(const int *)arg;
        }
        if (f->dtr_set_fail) {
            errno = EIO;
            return -1;
        }
        return 0;
    }
#endif
#ifdef TIOCNXCL
    if (request == (unsigned long)TIOCNXCL) {
        return 0;
    }
#endif
    (void)arg;
    (void)f;
    errno = ENOTTY;
    return -1;
}

static int fake_write_eio(int fd, const void *buf, size_t n, void *user)
{
    (void)fd;
    (void)buf;
    (void)n;
    (void)user;
    errno = EIO;
    return -1;
}

/* Platform-safe raw termios assertions against the last tcsetattr snapshot. */
static int require_raw_termios_profile(const struct termios *tio)
{
    REQUIRE(tio != NULL);
    REQUIRE((tio->c_lflag & (tcflag_t)ICANON) == 0);
    REQUIRE((tio->c_lflag & (tcflag_t)ECHO) == 0);
    REQUIRE((tio->c_lflag & (tcflag_t)ISIG) == 0);
    REQUIRE((tio->c_iflag & (tcflag_t)ICRNL) == 0);
    REQUIRE((tio->c_iflag & (tcflag_t)IXON) == 0);
    REQUIRE((tio->c_iflag & (tcflag_t)IXOFF) == 0);
    REQUIRE((tio->c_iflag & (tcflag_t)IXANY) == 0);
    /* Output raw: OPOST off (cfmakeraw); docs/07 claims input+output raw. */
    REQUIRE((tio->c_oflag & (tcflag_t)OPOST) == 0);
    REQUIRE((tio->c_cflag & (tcflag_t)CSIZE) == (tcflag_t)CS8);
    REQUIRE((tio->c_cflag & (tcflag_t)PARENB) == 0);
    REQUIRE((tio->c_cflag & (tcflag_t)CSTOPB) == 0);
    REQUIRE((tio->c_cflag & (tcflag_t)CLOCAL) != 0);
    REQUIRE((tio->c_cflag & (tcflag_t)CREAD) != 0);
    REQUIRE(tio->c_cc[VMIN] == 0);
    REQUIRE(tio->c_cc[VTIME] == 0);
    REQUIRE(cfgetispeed(tio) == B115200);
    REQUIRE(cfgetospeed(tio) == B115200);
    return 0;
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
    ops->now_ms_fn = fake_now_ms;
    ops->user = f;
    f->now_ms = 1000;
    f->max_poll_timeout_ms = -1;
    f->min_poll_timeout_ms = -1;
}

static int open_fake(
    ninlil_byte_stream_t *stream,
    fake_serial_t *f,
    ninlil_posix_usb_serial_sys_ops_t *ops)
{
    ninlil_byte_stream_error_t err;

    fake_ops_init(ops, f);
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(stream, ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream->ops->open(stream, "/dev/cu.fake-ninlil", &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(stream->ops->link(stream) == NINLIL_BYTE_STREAM_LINK_UP);
    return 0;
}

/* ---------- Basic / prior tests ------------------------------------------ */

static int test_sat_add(void)
{
    REQUIRE(ninlil_byte_stream_sat_add_u64(1u, 2u) == 3u);
    REQUIRE(ninlil_byte_stream_sat_add_u64(UINT64_MAX, 1u) == UINT64_MAX);
    REQUIRE(ninlil_byte_stream_sat_add_u64(UINT64_MAX - 1u, 5u) == UINT64_MAX);
    REQUIRE(ninlil_byte_stream_sat_hwm_u32(3u, 10u) == 10u);
    REQUIRE(ninlil_byte_stream_sat_hwm_u32(10u, 3u) == 10u);
    return 0;
}

static int test_object_size_align_api(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;

    REQUIRE(ninlil_posix_usb_serial_object_size() > 0u);
    REQUIRE(
        ninlil_posix_usb_serial_object_size()
        <= NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES);
    REQUIRE(ninlil_posix_usb_serial_object_align() == 8u);
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(stream.ops != NULL);
    REQUIRE(stream.self != NULL);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_CLOSED);
    REQUIRE(stream.ops->link_generation(&stream) == 0u);
    return 0;
}

static int test_non_absolute_path(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "relative/tty", &err)
        == NINLIL_BYTE_STREAM_INVALID_ARGUMENT);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_PATH);
    REQUIRE(
        stream.ops->open(&stream, "", &err)
        == NINLIL_BYTE_STREAM_INVALID_ARGUMENT);
    REQUIRE(
        stream.ops->open(&stream, NULL, &err)
        == NINLIL_BYTE_STREAM_INVALID_ARGUMENT);
    return 0;
}

static int test_short_path_no_ub(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    /*
     * Short absolute paths must not cause prefix over-read (ASan). Open fails
     * via seam ENOENT; path_is_macos_tty_dev must length-check first.
     */
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    fake.open_errno = ENOENT;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/x", &err) == NINLIL_BYTE_STREAM_NOT_FOUND);
    REQUIRE(
        stream.ops->open(&stream, "/dev", &err) == NINLIL_BYTE_STREAM_NOT_FOUND);
    REQUIRE(
        stream.ops->open(&stream, "/dev/tty", &err)
        == NINLIL_BYTE_STREAM_NOT_FOUND);
    REQUIRE(
        stream.ops->open(&stream, "/dev/tt", &err)
        == NINLIL_BYTE_STREAM_NOT_FOUND);
    return 0;
}

static int test_open_failure_mapping(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/no/such/ninlil/usb/device", &err)
        == NINLIL_BYTE_STREAM_NOT_FOUND);
    REQUIRE(err.path[0] == '/');
    REQUIRE(err.hint[0] != '\0');
    return 0;
}

static int test_open_eacces_diagnostics(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    fake.open_errno = EACCES;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/ttyACM0", &err)
        == NINLIL_BYTE_STREAM_PERMISSION);
    REQUIRE(err.sys_errno == EACCES);
    REQUIRE(strstr(err.hint, "dialout") != NULL
        || strstr(err.hint, "udev") != NULL
        || strstr(err.hint, "EACCES") != NULL);
    return 0;
}

static int test_macos_tty_path_diagnostic_metadata(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    fake.open_errno = ENOENT;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/tty.usbmodemTEST", &err)
        != NINLIL_BYTE_STREAM_OK);
    REQUIRE(strstr(err.hint, "cu.") != NULL || strstr(err.hint, "tty.") != NULL);
    return 0;
}

/*
 * Open-flags seam matches production compile path:
 * - O_CLOEXEC defined: atomic 4 flags; optional setter must not run (0).
 * - O_CLOEXEC absent: open 3 flags then fcntl setter exactly once / success.
 * (Forced modern fallback coverage is a separate host-test twin binary.)
 */
#if defined(O_CLOEXEC)
static int fake_set_cloexec_must_not_run(int fd, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->set_cloexec_calls += 1;
    return 0;
}

static int test_exact_open_flags_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    const int expected = O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.set_cloexec_fn = fake_set_cloexec_must_not_run;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    {
        ninlil_byte_stream_error_t err;
        REQUIRE(
            stream.ops->open(&stream, "/dev/cu.fake-ninlil", &err)
            == NINLIL_BYTE_STREAM_OK);
    }
    REQUIRE(fake.last_open_flags == expected);
    REQUIRE(fake.set_cloexec_calls == 0);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.set_cloexec_calls == 0);
    return 0;
}
#else /* !defined(O_CLOEXEC) — native production fcntl fallback */
static int fake_set_cloexec_ok(int fd, void *user)
{
    fake_serial_t *f = (fake_serial_t *)user;

    (void)fd;
    f->set_cloexec_calls += 1;
    return 0;
}

static int test_exact_open_flags_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
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
    {
        ninlil_byte_stream_error_t err;
        REQUIRE(
            stream.ops->open(&stream, "/dev/cu.fake-ninlil", &err)
            == NINLIL_BYTE_STREAM_OK);
    }
    REQUIRE(fake.last_open_flags == expected);
    REQUIRE(fake.set_cloexec_calls == 1);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.set_cloexec_calls == 1);
    return 0;
}
#endif /* defined(O_CLOEXEC) */

static int test_raw_termios_via_tcsetattr_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(fake.tcsetattr_calls == 1);
    REQUIRE(fake.has_termios == 1);
    REQUIRE(fake.last_tcsetattr_actions == TCSANOW);
    REQUIRE(require_raw_termios_profile(&fake.last_termios) == 0);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_tiocexcl_busy_seam(void)
{
#if !defined(TIOCEXCL)
    return 0;
#else
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    fake.busy_tiocexcl = 1;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err)
        == NINLIL_BYTE_STREAM_BUSY);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE);
    REQUIRE(err.sys_errno == EBUSY);
    REQUIRE(stream.ops->link(&stream) != NINLIL_BYTE_STREAM_LINK_UP);
    return 0;
#endif
}

static int test_dtr_assert_success_path_seam(void)
{
#if !defined(TIOCMGET) || !defined(TIOCMSET) || !defined(TIOCM_DTR)
    /* Platform build without modem control: success path not available. */
    return 0;
#else
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    /* Open-time modem ioctls only (close may issue TIOCNXCL separately). */
    REQUIRE(fake.tiocmget_calls == 1);
    REQUIRE(fake.tiocmset_calls == 1);
    REQUIRE(fake.tcsetattr_calls == 1);
    /* TIOCMGET returned 0; TIOCMSET must include DTR after OR. */
    REQUIRE((fake.last_tiocmset_bits & TIOCM_DTR) == TIOCM_DTR);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
#endif
}

static int test_dtr_get_failure_evidence_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    fake.dtr_get_fail = 1;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err) == NINLIL_BYTE_STREAM_OK);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_DTR);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_UNSUPPORTED);
    REQUIRE(err.sys_errno == ENOTTY);
    REQUIRE(fake.tiocmget_calls == 1);
    REQUIRE(fake.tiocmset_calls == 0);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_open_clears_stale_last_error_keeps_warning(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    fake.open_errno = EACCES;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.stale", &err)
        == NINLIL_BYTE_STREAM_PERMISSION);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_PERMISSION);

    /* Next attempt: clear stale; forced DTR GET fail leaves exact evidence. */
    fake.open_errno = 0;
    fake.dtr_get_fail = 1;
    fake.tiocmget_calls = 0;
    fake.tiocmset_calls = 0;
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fresh", &err) == NINLIL_BYTE_STREAM_OK);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_DTR);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_UNSUPPORTED);
    REQUIRE(err.sys_errno == ENOTTY);
    REQUIRE(fake.tiocmget_calls == 1);
    REQUIRE(fake.tiocmset_calls == 0);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_eintr_storm_poll_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.poll_eintr_left = (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX + 8;
    REQUIRE(
        stream.ops->poll(&stream, 1000u, &events, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == EINTR);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.eintr_count
        >= (uint64_t)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_eintr_storm_pump_tx_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t payload[16];
    uint32_t accepted = 0u;
    size_t i;
    int writes_before;

    for (i = 0u; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(
        stream.ops->write(
            &stream, payload, (uint32_t)sizeof(payload), &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    fake.write_eintr_left = (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX + 8;
    writes_before = fake.write_calls;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_WRITE);
    REQUIRE(err.sys_errno == EINTR);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.eintr_count
        >= (uint64_t)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX);
    REQUIRE(
        (fake.write_calls - writes_before)
        <= (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX + 1);
    REQUIRE(
        (fake.write_calls - writes_before)
        >= (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_eintr_storm_pump_rx_seam(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    int reads_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    /* Seed so fake_poll reports POLLIN and pump_rx issues read calls. */
    fake.rx_seed[0] = 0x55u;
    fake.rx_seed_len = 1u;
    fake.rx_seed_off = 0u;
    fake.read_eintr_left = (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX + 8;
    reads_before = fake.read_calls;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_READ);
    REQUIRE(err.sys_errno == EINTR);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.eintr_count
        >= (uint64_t)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX);
    REQUIRE(
        (fake.read_calls - reads_before)
        <= (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX + 1);
    REQUIRE(
        (fake.read_calls - reads_before)
        >= (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_read_capacity_zero_invalid(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t dummy = 0u;
    uint32_t got = 99u;
    uint8_t b = 1u;
    uint32_t acc = 0u;
    ninlil_byte_stream_event_t events;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    /* UP + capacity 0 */
    REQUIRE(
        stream.ops->read(&stream, &dummy, 0u, &got, &err)
        == NINLIL_BYTE_STREAM_INVALID_ARGUMENT);
    REQUIRE(got == 0u);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_READ);

    /* Drive LINK_DOWN with residual RX, then capacity 0 must still be invalid. */
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.write_fn = fake_write_eio;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err) == NINLIL_BYTE_STREAM_OK);
    fake.rx_seed[0] = 0xAAu;
    fake.rx_seed_len = 1u;
    fake.rx_seed_off = 0u;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(&stream, &b, 1u, &acc, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    got = 99u;
    REQUIRE(
        stream.ops->read(&stream, &dummy, 0u, &got, &err)
        == NINLIL_BYTE_STREAM_INVALID_ARGUMENT);
    REQUIRE(got == 0u);
    /* Non-zero capacity still drains buffered RX. */
    REQUIRE(
        stream.ops->read(&stream, &dummy, 1u, &got, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(got == 1u);
    REQUIRE(dummy == 0xAAu);
    REQUIRE(
        stream.ops->read(&stream, &dummy, 1u, &got, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    return 0;
}

static int test_write_io_error_propagates(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t payload[8];
    uint32_t accepted = 0u;
    size_t i;

    for (i = 0u; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(
        stream.ops->write(
            &stream, payload, (uint32_t)sizeof(payload), &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    fake.write_io_error = 1;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_WRITE);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int fake_read_enospc(int fd, void *buf, size_t n, void *user)
{
    (void)fd;
    (void)buf;
    (void)n;
    (void)user;
    errno = ENOSPC;
    return -1;
}

static int test_read_io_error_non_linkdown(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.read_fn = fake_read_enospc;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err) == NINLIL_BYTE_STREAM_OK);
    /* Inject POLLIN via seed off/len so pump_rx runs; poll_fn sets POLLIN if seed */
    fake.rx_seed_len = 1u;
    fake.rx_seed_off = 0u;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_READ);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.sys_errno == ENOSPC);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_generation_fail_closed_at_max(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint64_t gen;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    gen = stream.ops->link_generation(&stream);
    REQUIRE(gen != 0u);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);

    ninlil_posix_usb_serial_test_force_generation(&stream, UINT64_MAX);
    REQUIRE(stream.ops->link_generation(&stream) == UINT64_MAX);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_OPEN);
    REQUIRE(stream.ops->link_generation(&stream) == UINT64_MAX);
    REQUIRE(stream.ops->link(&stream) != NINLIL_BYTE_STREAM_LINK_UP);
    return 0;
}

static int test_close_eintr_fences_no_reclose(void)
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
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    closes_before = fake.close_calls;
    fake.close_errno = EINTR;
    REQUIRE(
        stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_CLOSE);
    REQUIRE(err.sys_errno == EINTR);
    REQUIRE(fake.close_calls == closes_before + 1);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_CLOSED);
    /* Second close is idempotent; must not call close again on fenced fd. */
    closes_before = fake.close_calls;
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.close_calls == closes_before);
    return 0;
}

typedef struct close_arg {
    ninlil_byte_stream_t *stream;
    ninlil_byte_stream_status_t st;
} close_arg_t;

static void *close_on_other_thread(void *p)
{
    close_arg_t *a = (close_arg_t *)p;
    ninlil_byte_stream_error_t e;

    a->st = a->stream->ops->close(a->stream, &e);
    return NULL;
}

static int test_close_wrong_owner_after_closed(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    pthread_t thr;
    close_arg_t arg;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);

    arg.stream = &stream;
    arg.st = NINLIL_BYTE_STREAM_OK;
    REQUIRE(pthread_create(&thr, NULL, close_on_other_thread, &arg) == 0);
    REQUIRE(pthread_join(thr, NULL) == 0);
    REQUIRE(arg.st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    return 0;
}

static int test_link_down_buffered_rx_then_err_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t out[8];
    uint32_t got = 0u;
    uint8_t b = 9u;
    uint32_t acc = 0u;

    /*
     * Single path: open with write→EIO, load RX, TX accept then pump to
     * LINK_DOWN, drain buffered RX (OK+len), then ERR_LINK_DOWN.
     */
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.write_fn = fake_write_eio;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err) == NINLIL_BYTE_STREAM_OK);
    fake.rx_seed[0] = 0xAAu;
    fake.rx_seed[1] = 0xBBu;
    fake.rx_seed_len = 2u;
    fake.rx_seed_off = 0u;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(&stream, &b, 1u, &acc, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(
        stream.ops->read(&stream, out, sizeof(out), &got, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(got == 2u);
    REQUIRE(out[0] == 0xAAu && out[1] == 0xBBu);
    REQUIRE(
        stream.ops->read(&stream, out, sizeof(out), &got, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(got == 0u);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    return 0;
}

/*
 * Drive poll → pump_rx until the RX ring is exactly full, then the next
 * zero-timeout sys_poll is the RX-full probe under test.
 */
static int poll_until_rx_full_probe(
    ninlil_byte_stream_t *stream,
    fake_serial_t *fake,
    ninlil_byte_stream_status_t *out_st,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_err)
{
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_status_t st;
    ninlil_byte_stream_stats_t stats;

    fake->fill_rx_total = NINLIL_BYTE_STREAM_RING_BYTES;
    fake->fill_rx_delivered = 0u;
    fake->zero_timeout_polls = 0;
    st = stream->ops->poll(stream, 50u, &events, &err);
    stream->ops->stats(stream, &stats);
    REQUIRE(stats.rx_high_watermark == NINLIL_BYTE_STREAM_RING_BYTES
        || stats.rx_ring_bytes == NINLIL_BYTE_STREAM_RING_BYTES
        || fake->fill_rx_delivered == NINLIL_BYTE_STREAM_RING_BYTES);
    REQUIRE(fake->zero_timeout_polls >= 1);
    if (out_st != NULL) {
        *out_st = st;
    }
    if (out_events != NULL) {
        *out_events = events;
    }
    if (out_err != NULL) {
        *out_err = err;
    }
    return 0;
}

static int test_rx_full_probe_eintr_ceiling(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.probe_eintr_left = (int)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX + 8;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == EINTR);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.eintr_count
        >= (uint64_t)NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_generic_io_error(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.probe_io_errno = ENOSPC;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == ENOSPC);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_main_poll_eio_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    int closes_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    closes_before = fake.close_calls;
    fake.poll_io_errno = EIO;
    REQUIRE(
        stream.ops->poll(&stream, 20u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(fake.close_calls == closes_before + 1);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.status == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == EIO);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_main_poll_enodev_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.poll_io_errno = ENODEV;
    REQUIRE(
        stream.ops->poll(&stream, 20u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    stream.ops->last_error(&stream, &err);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == ENODEV);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_eio_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;
    int closes_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    closes_before = fake.close_calls;
    fake.probe_io_errno = EIO;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(fake.close_calls == closes_before + 1);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == EIO);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_enxio_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.probe_io_errno = ENXIO;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_POLL);
    REQUIRE(err.sys_errno == ENXIO);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_pollnval_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.probe_revents_set = 1;
    fake.probe_revents = POLLNVAL;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_pollerr_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.probe_revents_set = 1;
    fake.probe_revents = POLLERR;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_pollhup_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.probe_revents_set = 1;
    fake.probe_revents = POLLHUP;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_rx_full_probe_pollin_overflow(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    ninlil_byte_stream_status_t st;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    /* After exact fill, probe sees POLLIN → continuity overflow, not link down. */
    fake.probe_revents_set = 1;
    fake.probe_revents = POLLIN;
    REQUIRE(
        poll_until_rx_full_probe(&stream, &fake, &st, &events, &err) == 0);
    REQUIRE(st == NINLIL_BYTE_STREAM_OK);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) != 0u);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) == 0u);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.rx_overflow_count >= 1u);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_explicit_close_after_link_down_clears_rx(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t out[8];
    uint32_t got = 0u;
    uint8_t b = 1u;
    uint32_t acc = 0u;
    uint64_t gen1;
    uint64_t gen2;
    int closes_at_link_down;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    fake_ops_init(&ops, &fake);
    ops.write_fn = fake_write_eio;
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake", &err) == NINLIL_BYTE_STREAM_OK);
    gen1 = stream.ops->link_generation(&stream);
    fake.rx_seed[0] = 0xCCu;
    fake.rx_seed[1] = 0xDDu;
    fake.rx_seed_len = 2u;
    fake.rx_seed_off = 0u;
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(&stream, &b, 1u, &acc, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->poll(&stream, 10u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    closes_at_link_down = fake.close_calls;

    /* Explicit close: CLOSED, rings cleared, no re-sys-close. */
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_CLOSED);
    REQUIRE(fake.close_calls == closes_at_link_down);
    got = 99u;
    out[0] = 0xFFu;
    REQUIRE(
        stream.ops->read(&stream, out, sizeof(out), &got, &err)
        == NINLIL_BYTE_STREAM_CLOSED);
    REQUIRE(got == 0u);
    REQUIRE(out[0] == 0xFFu);
    REQUIRE(
        stream.ops->write(&stream, &b, 1u, &acc, &err)
        == NINLIL_BYTE_STREAM_CLOSED);
    REQUIRE(
        stream.ops->poll(&stream, 0u, &events, &err)
        == NINLIL_BYTE_STREAM_CLOSED);
    /* Idempotent close still OK. */
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);

    /* Reopen: old RX must not reappear. */
    fake_ops_init(&ops, &fake);
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops)
        == NINLIL_BYTE_STREAM_OK);
    /* Preserve generation counter across re-init of ops only. */
    ninlil_posix_usb_serial_test_force_generation(&stream, gen1);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake2", &err) == NINLIL_BYTE_STREAM_OK);
    gen2 = stream.ops->link_generation(&stream);
    REQUIRE(gen2 == gen1 + 1u);
    got = 99u;
    REQUIRE(
        stream.ops->read(&stream, out, sizeof(out), &got, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(got == 0u);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_poll_deadline_covers_prepump(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t payload[32];
    uint32_t accepted = 0u;
    size_t i;

    for (i = 0u; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(
        stream.ops->write(
            &stream, payload, (uint32_t)sizeof(payload), &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);

    /* Each write advances 40ms; pre-pump should shrink sys_poll wait. */
    fake.now_ms = 5000;
    fake.advance_ms_on_write = 40;
    fake.poll_calls = 0;
    fake.poll_timeout_samples = 0;
    REQUIRE(
        stream.ops->poll(&stream, 100u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.poll_calls >= 1);
    REQUIRE(fake.last_poll_timeout_ms < 100);
    REQUIRE(fake.last_poll_timeout_ms >= 0);

    /* Budget fully consumed in pre-pump → no *blocking* poll (wait exact 0). */
    REQUIRE(
        stream.ops->write(
            &stream, payload, (uint32_t)sizeof(payload), &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    fake.now_ms = 8000;
    fake.advance_ms_on_write = 200;
    fake.poll_calls = 0;
    REQUIRE(
        stream.ops->poll(&stream, 50u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.poll_calls == 1);
    REQUIRE(fake.last_poll_timeout_ms == 0);

    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

/* (a)(c) TX enqueue + poll(0): nonblocking write progress; wait timeout exact 0. */
static int test_poll_zero_tx_progress(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t payload[24];
    uint32_t accepted = 0u;
    size_t i;
    int writes_before;

    for (i = 0u; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)(0x40u + i);
    }
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(
        stream.ops->write(
            &stream, payload, (uint32_t)sizeof(payload), &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.tx_ring_bytes == (uint32_t)sizeof(payload));
    writes_before = fake.write_calls;
    fake.poll_calls = 0;
    REQUIRE(
        stream.ops->poll(&stream, 0u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.poll_calls == 1);
    REQUIRE(fake.last_poll_timeout_ms == 0);
    REQUIRE(fake.write_calls > writes_before);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.bytes_written >= (uint64_t)sizeof(payload));
    REQUIRE(stats.tx_ring_bytes == 0u);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

/* (b)(c) POLLIN + poll(0): nonblocking read progress; wait timeout exact 0. */
static int test_poll_zero_rx_progress(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t out[8];
    uint32_t got = 0u;
    int reads_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.rx_seed[0] = 0x11u;
    fake.rx_seed[1] = 0x22u;
    fake.rx_seed[2] = 0x33u;
    fake.rx_seed_len = 3u;
    fake.rx_seed_off = 0u;
    reads_before = fake.read_calls;
    fake.poll_calls = 0;
    REQUIRE(
        stream.ops->poll(&stream, 0u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.poll_calls == 1);
    REQUIRE(fake.last_poll_timeout_ms == 0);
    REQUIRE(fake.read_calls > reads_before);
    REQUIRE(
        stream.ops->read(&stream, out, sizeof(out), &got, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(got == 3u);
    REQUIRE(out[0] == 0x11u && out[1] == 0x22u && out[2] == 0x33u);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_set_sys_ops_forbidden_when_active(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_posix_usb_serial_sys_ops_t ops;
    ninlil_posix_usb_serial_sys_ops_t ops2;
    fake_serial_t fake;
    fake_serial_t fake2;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake_ops_init(&ops2, &fake2);
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, &ops2)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, NULL)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(stream.ops->close(&stream, NULL) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_posix_usb_serial_set_sys_ops(&stream, NULL)
        == NINLIL_BYTE_STREAM_OK);
    return 0;
}

/* PTY integration evidence only; raw termios profile is seam-tested above. */
static int test_pty_bidirectional_integration(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    pty_pair_t pty;
    uint8_t tx_payload[16];
    uint8_t rx_from_master[16];
    uint8_t rx_from_stream[16];
    uint32_t accepted = 0u;
    uint32_t got = 0u;
    size_t i;
    size_t total = 0u;
    int tries;

    REQUIRE(open_pty_pair(&pty));
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, pty.slave_path, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(stream.ops->link_generation(&stream) != 0u);

    for (i = 0u; i < sizeof(tx_payload); ++i) {
        tx_payload[i] = (uint8_t)(0xA0u + i);
    }
    REQUIRE(
        stream.ops->write(
            &stream, tx_payload, (uint32_t)sizeof(tx_payload), &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(accepted == (uint32_t)sizeof(tx_payload));
    for (tries = 0; tries < 64 && total < sizeof(tx_payload); ++tries) {
        struct pollfd pfd;
        ssize_t n;
        REQUIRE(
            stream.ops->poll(&stream, 20u, &events, &err)
            == NINLIL_BYTE_STREAM_OK);
        pfd.fd = pty.master;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 20) > 0) {
            n = read(pty.master, rx_from_master + total, sizeof(tx_payload) - total);
            if (n > 0) {
                total += (size_t)n;
            }
        }
    }
    REQUIRE(total == sizeof(tx_payload));
    REQUIRE(memcmp(rx_from_master, tx_payload, sizeof(tx_payload)) == 0);

    for (i = 0u; i < sizeof(rx_from_stream); ++i) {
        rx_from_stream[i] = (uint8_t)(0x10u + i);
    }
    REQUIRE(write_master_all(pty.master, rx_from_stream, sizeof(rx_from_stream)));
    REQUIRE(
        stream.ops->poll(&stream, 100u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->read(
            &stream, rx_from_master, (uint32_t)sizeof(rx_from_master), &got, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(got == (uint32_t)sizeof(rx_from_stream));
    REQUIRE(memcmp(rx_from_master, rx_from_stream, sizeof(rx_from_stream)) == 0);

    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.bytes_read >= sizeof(rx_from_stream));
    REQUIRE(stats.open_count >= 1u);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    close_pty_pair(&pty);
    return 0;
}

static int test_poll_timeout(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    pty_pair_t pty;

    REQUIRE(open_pty_pair(&pty));
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, pty.slave_path, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->poll(&stream, 0u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_TIMEOUT) != 0u);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.poll_timeout_count >= 1u);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    close_pty_pair(&pty);
    return 0;
}

static int test_tx_backpressure_4k_and_recovery(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    pty_pair_t pty;
    uint8_t block[NINLIL_BYTE_STREAM_RING_BYTES];
    uint8_t one = 0x5Au;
    uint8_t drain_buf[NINLIL_BYTE_STREAM_RING_BYTES];
    uint32_t accepted = 0u;
    size_t i;
    size_t total = 0u;
    int tries;

    for (i = 0u; i < sizeof(block); ++i) {
        block[i] = (uint8_t)(i & 0xffu);
    }
    REQUIRE(open_pty_pair(&pty));
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, pty.slave_path, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(
            &stream, block, NINLIL_BYTE_STREAM_RING_BYTES, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(&stream, &one, 1u, &accepted, &err)
        == NINLIL_BYTE_STREAM_WOULD_BLOCK);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.would_block_count >= 1u);
    REQUIRE(stats.tx_high_watermark == NINLIL_BYTE_STREAM_RING_BYTES);

    for (tries = 0; tries < 256 && total < sizeof(block); ++tries) {
        struct pollfd pfd;
        ssize_t n;
        REQUIRE(
            stream.ops->poll(&stream, 20u, &events, &err)
            == NINLIL_BYTE_STREAM_OK);
        pfd.fd = pty.master;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 20) > 0) {
            n = read(pty.master, drain_buf + total, sizeof(block) - total);
            if (n > 0) {
                total += (size_t)n;
            }
        }
    }
    REQUIRE(total == sizeof(block));

    {
        int recovered = 0;
        for (tries = 0; tries < 64; ++tries) {
            if (stream.ops->write(&stream, &one, 1u, &accepted, &err)
                == NINLIL_BYTE_STREAM_OK) {
                recovered = 1;
                break;
            }
            REQUIRE(err.status == NINLIL_BYTE_STREAM_WOULD_BLOCK);
            REQUIRE(
                stream.ops->poll(&stream, 10u, &events, &err)
                == NINLIL_BYTE_STREAM_OK);
            {
                uint8_t tmp[64];
                ssize_t dn = read_fd_best_effort(pty.master, tmp, sizeof(tmp));
                REQUIRE(dn >= 0); /* EINTR handled; EAGAIN → 0; hard I/O fails test */
            }
        }
        REQUIRE(recovered);
    }
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    close_pty_pair(&pty);
    return 0;
}

static int test_rx_overflow_continuity(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    pty_pair_t pty;
    uint8_t block[NINLIL_BYTE_STREAM_RING_BYTES];
    uint8_t extra[64];
    uint8_t out[NINLIL_BYTE_STREAM_RING_BYTES];
    uint32_t got = 0u;
    size_t i;
    int saw_overflow = 0;
    int tries;

    for (i = 0u; i < sizeof(block); ++i) {
        block[i] = (uint8_t)(i & 0xffu);
    }
    for (i = 0u; i < sizeof(extra); ++i) {
        extra[i] = (uint8_t)(0xE0u + (i & 0x0fu));
    }
    REQUIRE(open_pty_pair(&pty));
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, pty.slave_path, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(push_to_adapter(&stream, pty.master, block, sizeof(block)));
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.rx_ring_bytes == NINLIL_BYTE_STREAM_RING_BYTES);

    {
        int flags = fcntl(pty.master, F_GETFL, 0);
        size_t injected = 0u;
        if (flags >= 0) {
            (void)fcntl(pty.master, F_SETFL, flags | O_NONBLOCK);
        }
        /* Best-effort inject past full ring; EINTR/EAGAIN/partial handled. */
        injected += write_fd_best_effort(pty.master, extra, sizeof(extra));
        for (tries = 0; tries < 32; ++tries) {
            events = NINLIL_BYTE_STREAM_EVENT_NONE;
            (void)stream.ops->poll(&stream, 10u, &events, &err);
            if ((events & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) != 0u
                || err.status == NINLIL_BYTE_STREAM_RX_OVERFLOW) {
                saw_overflow = 1;
                break;
            }
            injected += write_fd_best_effort(pty.master, extra, 8u);
        }
        REQUIRE(saw_overflow);
        REQUIRE(injected > 0u); /* overflow path must have accepted host I/O */
    }
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_UP);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.rx_overflow_count >= 1u);
    REQUIRE(
        stream.ops->read(
            &stream, out, NINLIL_BYTE_STREAM_RING_BYTES, &got, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(got == NINLIL_BYTE_STREAM_RING_BYTES);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    close_pty_pair(&pty);
    return 0;
}

static int test_hangup_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    pty_pair_t pty;
    int tries;
    int down = 0;

    REQUIRE(open_pty_pair(&pty));
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, pty.slave_path, &err) == NINLIL_BYTE_STREAM_OK);
    (void)close(pty.master);
    pty.master = -1;
    for (tries = 0; tries < 32; ++tries) {
        ninlil_byte_stream_status_t st =
            stream.ops->poll(&stream, 20u, &events, &err);
        if (st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
            || (events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u
            || stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN) {
            down = 1;
            break;
        }
    }
    REQUIRE(down);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.link_down_count >= 1u);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    close_pty_pair(&pty);
    return 0;
}

static int test_close_reopen_generation(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint64_t gen1;
    uint64_t gen2;
    uint8_t b = 1u;
    uint32_t accepted = 0u;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    gen1 = stream.ops->link_generation(&stream);
    REQUIRE(gen1 != 0u);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(&stream, &b, 1u, &accepted, &err)
        != NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake2", &err) == NINLIL_BYTE_STREAM_OK);
    gen2 = stream.ops->link_generation(&stream);
    REQUIRE(gen2 != 0u);
    REQUIRE(gen2 > gen1);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

typedef struct owner_matrix_arg {
    ninlil_byte_stream_t *stream;
    ninlil_byte_stream_status_t open_valid_st;
    ninlil_byte_stream_status_t open_invalid_st;
    ninlil_byte_stream_status_t write_st;
    ninlil_byte_stream_status_t read_null_st;
    ninlil_byte_stream_status_t read_cap0_st;
    ninlil_byte_stream_status_t poll_st;
    ninlil_byte_stream_status_t close_st;
    /* Distinct out-payload sentinels per operation (mutation isolation). */
    uint32_t write_accepted;
    uint32_t read_null_length;
    uint32_t read_cap0_length;
    ninlil_byte_stream_event_t poll_events;
} owner_matrix_arg_t;

/* Fake syscall counters that wrong-owner calls must not advance. */
typedef struct fake_syscall_snap {
    int open_calls;
    int close_calls;
    int read_calls;
    int write_calls;
    int poll_calls;
    int zero_timeout_polls;
    int set_cloexec_calls;
    int tcsetattr_calls;
    int tiocmget_calls;
    int tiocmset_calls;
} fake_syscall_snap_t;

static void fake_syscall_snap_capture(
    const fake_serial_t *f,
    fake_syscall_snap_t *out)
{
    out->open_calls = f->open_calls;
    out->close_calls = f->close_calls;
    out->read_calls = f->read_calls;
    out->write_calls = f->write_calls;
    out->poll_calls = f->poll_calls;
    out->zero_timeout_polls = f->zero_timeout_polls;
    out->set_cloexec_calls = f->set_cloexec_calls;
    out->tcsetattr_calls = f->tcsetattr_calls;
    out->tiocmget_calls = f->tiocmget_calls;
    out->tiocmset_calls = f->tiocmset_calls;
}

static int require_fake_syscall_snap_eq(
    const fake_serial_t *f,
    const fake_syscall_snap_t *before)
{
    REQUIRE(f->open_calls == before->open_calls);
    REQUIRE(f->close_calls == before->close_calls);
    REQUIRE(f->read_calls == before->read_calls);
    REQUIRE(f->write_calls == before->write_calls);
    REQUIRE(f->poll_calls == before->poll_calls);
    REQUIRE(f->zero_timeout_polls == before->zero_timeout_polls);
    REQUIRE(f->set_cloexec_calls == before->set_cloexec_calls);
    REQUIRE(f->tcsetattr_calls == before->tcsetattr_calls);
    REQUIRE(f->tiocmget_calls == before->tiocmget_calls);
    REQUIRE(f->tiocmset_calls == before->tiocmset_calls);
    return 0;
}

static int require_stats_eq(
    const ninlil_byte_stream_stats_t *a,
    const ninlil_byte_stream_stats_t *b)
{
    REQUIRE(a->bytes_read == b->bytes_read);
    REQUIRE(a->bytes_written == b->bytes_written);
    REQUIRE(a->would_block_count == b->would_block_count);
    REQUIRE(a->poll_timeout_count == b->poll_timeout_count);
    REQUIRE(a->eintr_count == b->eintr_count);
    REQUIRE(a->rx_overflow_count == b->rx_overflow_count);
    REQUIRE(a->link_down_count == b->link_down_count);
    REQUIRE(a->open_count == b->open_count);
    REQUIRE(a->close_count == b->close_count);
    REQUIRE(a->rx_high_watermark == b->rx_high_watermark);
    REQUIRE(a->tx_high_watermark == b->tx_high_watermark);
    REQUIRE(a->rx_ring_bytes == b->rx_ring_bytes);
    REQUIRE(a->tx_ring_bytes == b->tx_ring_bytes);
    return 0;
}

static int require_error_eq(
    const ninlil_byte_stream_error_t *a,
    const ninlil_byte_stream_error_t *b)
{
    REQUIRE(a->status == b->status);
    REQUIRE(a->stage == b->stage);
    REQUIRE(a->sys_errno == b->sys_errno);
    REQUIRE(a->reserved_zero == b->reserved_zero);
    REQUIRE(strcmp(a->path, b->path) == 0);
    REQUIRE(strcmp(a->hint, b->hint) == 0);
    return 0;
}

/*
 * Non-owner thread: open(valid+invalid path)/write(invalid)/read(NULL+cap0)/
 * poll/close — all WRONG_OWNER; leave distinct out sentinels unchanged.
 */
static void *owner_matrix_on_other_thread(void *p)
{
    owner_matrix_arg_t *a = (owner_matrix_arg_t *)p;
    ninlil_byte_stream_error_t err;
    uint8_t scratch = 0u;

    a->write_accepted = 0xA5A5A5A5u;
    a->read_null_length = 0xB6B6B6B6u;
    a->read_cap0_length = 0xC7C7C7C7u;
    a->poll_events = (ninlil_byte_stream_event_t)0xD8u;

    a->open_valid_st =
        a->stream->ops->open(a->stream, "/dev/cu.fake-ninlil", &err);
    a->open_invalid_st = a->stream->ops->open(a->stream, "relative", &err);
    a->write_st =
        a->stream->ops->write(a->stream, NULL, 4u, &a->write_accepted, &err);
    a->read_null_st = a->stream->ops->read(
        a->stream, NULL, 8u, &a->read_null_length, &err);
    a->read_cap0_st = a->stream->ops->read(
        a->stream, &scratch, 0u, &a->read_cap0_length, &err);
    a->poll_st =
        a->stream->ops->poll(a->stream, 10u, &a->poll_events, &err);
    a->close_st = a->stream->ops->close(a->stream, &err);
    return NULL;
}

typedef struct open_owner_arg {
    ninlil_byte_stream_t *stream;
    ninlil_byte_stream_status_t open_st;
    ninlil_byte_stream_status_t write_st;
    ninlil_byte_stream_status_t close_st;
    /*
     * Plain values captured by the (would-be) owner thread only.
     * Sentinels: gen 0 / link 0xFF must not survive a successful path.
     */
    uint64_t gen_after_open;
    ninlil_byte_stream_link_t link_after_close;
} open_owner_arg_t;

static void *open_on_other_thread(void *p)
{
    open_owner_arg_t *a = (open_owner_arg_t *)p;
    ninlil_byte_stream_error_t err;

    a->open_st = a->stream->ops->open(a->stream, "/dev/cu.fake-ninlil", &err);
    return NULL;
}

/*
 * New-owner thread: open → capture generation → write → close → capture link.
 * After successful open, only this thread may touch the stream.
 */
static void *open_write_close_on_other_thread(void *p)
{
    open_owner_arg_t *a = (open_owner_arg_t *)p;
    ninlil_byte_stream_error_t err;
    uint8_t b = 0x5Au;
    uint32_t accepted = 0u;

    a->open_st = a->stream->ops->open(a->stream, "/dev/cu.fake-ninlil", &err);
    if (a->open_st != NINLIL_BYTE_STREAM_OK) {
        a->write_st = a->open_st;
        a->close_st = a->open_st;
        return NULL;
    }
    /* Successful open established this thread as owner: capture gen here. */
    a->gen_after_open = a->stream->ops->link_generation(a->stream);
    a->write_st =
        a->stream->ops->write(a->stream, &b, 1u, &accepted, &err);
    a->close_st = a->stream->ops->close(a->stream, &err);
    if (a->close_st == NINLIL_BYTE_STREAM_OK) {
        a->link_after_close = a->stream->ops->link(a->stream);
    }
    return NULL;
}

/*
 * UP single-owner matrix: non-owner open/write/read/poll/close all
 * WRONG_OWNER; distinct out sentinels + complete last_error/stats/link/
 * generation invariant; all relevant fake syscall counters delta 0.
 */
static int test_wrong_owner_matrix_while_up(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_error_t err_before;
    ninlil_byte_stream_error_t err_after;
    ninlil_byte_stream_stats_t stats_before;
    ninlil_byte_stream_stats_t stats_after;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    fake_syscall_snap_t sys_before;
    pthread_t thr;
    owner_matrix_arg_t arg;
    uint64_t gen_before;
    ninlil_byte_stream_link_t link_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    /* Seed a structured last_error on the owner path for invariance. */
    REQUIRE(
        stream.ops->write(&stream, NULL, 1u, NULL, &err)
        == NINLIL_BYTE_STREAM_INVALID_ARGUMENT);
    stream.ops->last_error(&stream, &err_before);
    stream.ops->stats(&stream, &stats_before);
    gen_before = stream.ops->link_generation(&stream);
    link_before = stream.ops->link(&stream);
    fake_syscall_snap_capture(&fake, &sys_before);

    arg.stream = &stream;
    REQUIRE(
        pthread_create(&thr, NULL, owner_matrix_on_other_thread, &arg) == 0);
    REQUIRE(pthread_join(thr, NULL) == 0);

    REQUIRE(arg.open_valid_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.open_invalid_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.write_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.read_null_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.read_cap0_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.poll_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.close_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(arg.write_accepted == 0xA5A5A5A5u);
    REQUIRE(arg.read_null_length == 0xB6B6B6B6u);
    REQUIRE(arg.read_cap0_length == 0xC7C7C7C7u);
    REQUIRE(arg.poll_events == (ninlil_byte_stream_event_t)0xD8u);
    REQUIRE(require_fake_syscall_snap_eq(&fake, &sys_before) == 0);

    stream.ops->last_error(&stream, &err_after);
    stream.ops->stats(&stream, &stats_after);
    REQUIRE(require_error_eq(&err_after, &err_before) == 0);
    REQUIRE(require_stats_eq(&stats_after, &stats_before) == 0);
    REQUIRE(stream.ops->link(&stream) == link_before);
    REQUIRE(stream.ops->link_generation(&stream) == gen_before);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

/*
 * LINK_DOWN wrong-owner open → WRONG_OWNER; no reopen; generation preserved.
 */
static int test_open_wrong_owner_after_link_down(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_error_t err_before;
    ninlil_byte_stream_error_t err_after;
    ninlil_byte_stream_stats_t stats_before;
    ninlil_byte_stream_stats_t stats_after;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    fake_syscall_snap_t sys_before;
    pthread_t thr;
    open_owner_arg_t arg;
    uint64_t gen_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.poll_io_errno = EIO;
    REQUIRE(
        stream.ops->poll(&stream, 20u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    stream.ops->last_error(&stream, &err_before);
    stream.ops->stats(&stream, &stats_before);
    gen_before = stream.ops->link_generation(&stream);
    fake_syscall_snap_capture(&fake, &sys_before);
    arg.stream = &stream;
    arg.open_st = NINLIL_BYTE_STREAM_OK;
    REQUIRE(pthread_create(&thr, NULL, open_on_other_thread, &arg) == 0);
    REQUIRE(pthread_join(thr, NULL) == 0);
    REQUIRE(arg.open_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(require_fake_syscall_snap_eq(&fake, &sys_before) == 0);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(stream.ops->link_generation(&stream) == gen_before);
    stream.ops->last_error(&stream, &err_after);
    stream.ops->stats(&stream, &stats_after);
    REQUIRE(require_error_eq(&err_after, &err_before) == 0);
    REQUIRE(require_stats_eq(&stats_after, &stats_before) == 0);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

/*
 * LINK_DOWN same owner: open is INVALID_STATE (must explicit close first);
 * open call delta 0 so residual RX is not dropped by open.
 */
static int test_open_same_owner_link_down_requires_close(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint64_t gen_before;
    int opens_before;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    fake.poll_io_errno = EIO;
    REQUIRE(
        stream.ops->poll(&stream, 20u, &events, &err)
        == NINLIL_BYTE_STREAM_ERR_LINK_DOWN);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    gen_before = stream.ops->link_generation(&stream);
    opens_before = fake.open_calls;
    REQUIRE(
        stream.ops->open(&stream, "/dev/cu.fake-ninlil", &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(err.stage == NINLIL_BYTE_STREAM_STAGE_OPEN);
    REQUIRE(fake.open_calls == opens_before);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_DOWN);
    REQUIRE(stream.ops->link_generation(&stream) == gen_before);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_CLOSED);
    return 0;
}

/*
 * Explicit close → CLOSED: different thread may open as new owner and then
 * operate/close successfully (owner transfer).
 *
 * After the child open succeeds, the old main thread must not call any stream
 * API (observers remain owner-only while owner_set tracks the new owner even
 * after the child's close). Assert only plain values captured by the child.
 */
static int test_open_new_owner_after_explicit_close(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    pthread_t thr;
    open_owner_arg_t arg;
    uint64_t gen_after_first;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    gen_after_first = stream.ops->link_generation(&stream);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    /* Still the original owner until a later open transfers ownership. */
    REQUIRE(stream.ops->link(&stream) == NINLIL_BYTE_STREAM_LINK_CLOSED);

    arg.stream = &stream;
    arg.open_st = NINLIL_BYTE_STREAM_IO_ERROR;
    arg.write_st = NINLIL_BYTE_STREAM_IO_ERROR;
    arg.close_st = NINLIL_BYTE_STREAM_IO_ERROR;
    arg.gen_after_open = 0u; /* sentinel: successful open is nonzero gen */
    arg.link_after_close = (ninlil_byte_stream_link_t)0xFFu; /* invalid */
    REQUIRE(
        pthread_create(&thr, NULL, open_write_close_on_other_thread, &arg)
        == 0);
    REQUIRE(pthread_join(thr, NULL) == 0);
    /* Main: only child-captured plain values (no stream API after transfer). */
    REQUIRE(arg.open_st == NINLIL_BYTE_STREAM_OK);
    REQUIRE(arg.write_st == NINLIL_BYTE_STREAM_OK);
    REQUIRE(arg.close_st == NINLIL_BYTE_STREAM_OK);
    REQUIRE(arg.gen_after_open != 0u);
    REQUIRE(arg.gen_after_open == gen_after_first + 1u);
    REQUIRE(arg.link_after_close == NINLIL_BYTE_STREAM_LINK_CLOSED);
    return 0;
}

static int test_wrong_owner_process(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    pid_t child;
    int status = 0;
    int pipefd[2];
    ninlil_byte_stream_status_t child_st = NINLIL_BYTE_STREAM_OK;

    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(pipe(pipefd) == 0);
    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        uint8_t b = 2u;
        uint32_t accepted = 0u;
        ninlil_byte_stream_status_t st =
            stream.ops->write(&stream, &b, 1u, &accepted, &err);
        (void)close(pipefd[0]);
        /* Exact sizeof status to parent; EINTR/partial handled; fail → exit 2. */
        if (!write_fd_all(pipefd[1], (const uint8_t *)&st, sizeof(st))) {
            (void)close(pipefd[1]);
            _exit(2);
        }
        (void)close(pipefd[1]);
        _exit(0);
    }
    (void)close(pipefd[1]);
    REQUIRE(read_fd_all(pipefd[0], &child_st, sizeof(child_st)));
    (void)close(pipefd[0]);
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0); /* exact pipe write succeeded in child */
    REQUIRE(child_st == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_stats_hwm(void)
{
    ninlil_posix_usb_serial_object_t object;
    ninlil_byte_stream_t stream;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events;
    ninlil_byte_stream_stats_t stats;
    ninlil_posix_usb_serial_sys_ops_t ops;
    fake_serial_t fake;
    uint8_t buf[128];
    uint32_t accepted = 0u;
    size_t i;

    for (i = 0u; i < sizeof(buf); ++i) {
        buf[i] = (uint8_t)i;
    }
    REQUIRE(
        ninlil_posix_usb_serial_init_object(&object, &stream)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(open_fake(&stream, &fake, &ops) == 0);
    REQUIRE(
        stream.ops->write(&stream, buf, 64u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        stream.ops->write(&stream, buf, 32u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.tx_high_watermark >= 96u);
    REQUIRE(
        stream.ops->poll(&stream, 50u, &events, &err) == NINLIL_BYTE_STREAM_OK);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.bytes_written >= 96u);
    REQUIRE(stream.ops->close(&stream, &err) == NINLIL_BYTE_STREAM_OK);
    stream.ops->stats(&stream, &stats);
    REQUIRE(stats.close_count >= 1u);
    return 0;
}

int main(void)
{
    REQUIRE(test_sat_add() == 0);
    REQUIRE(test_object_size_align_api() == 0);
    REQUIRE(test_non_absolute_path() == 0);
    REQUIRE(test_short_path_no_ub() == 0);
    REQUIRE(test_open_failure_mapping() == 0);
    REQUIRE(test_open_eacces_diagnostics() == 0);
    REQUIRE(test_macos_tty_path_diagnostic_metadata() == 0);
    REQUIRE(test_exact_open_flags_seam() == 0);
    REQUIRE(test_raw_termios_via_tcsetattr_seam() == 0);
    REQUIRE(test_tiocexcl_busy_seam() == 0);
    REQUIRE(test_dtr_assert_success_path_seam() == 0);
    REQUIRE(test_dtr_get_failure_evidence_seam() == 0);
    REQUIRE(test_open_clears_stale_last_error_keeps_warning() == 0);
    REQUIRE(test_eintr_storm_poll_seam() == 0);
    REQUIRE(test_eintr_storm_pump_tx_seam() == 0);
    REQUIRE(test_eintr_storm_pump_rx_seam() == 0);
    REQUIRE(test_read_capacity_zero_invalid() == 0);
    REQUIRE(test_write_io_error_propagates() == 0);
    REQUIRE(test_read_io_error_non_linkdown() == 0);
    REQUIRE(test_generation_fail_closed_at_max() == 0);
    REQUIRE(test_close_eintr_fences_no_reclose() == 0);
    REQUIRE(test_close_wrong_owner_after_closed() == 0);
    REQUIRE(test_link_down_buffered_rx_then_err_link_down() == 0);
    REQUIRE(test_explicit_close_after_link_down_clears_rx() == 0);
    REQUIRE(test_rx_full_probe_eintr_ceiling() == 0);
    REQUIRE(test_rx_full_probe_generic_io_error() == 0);
    REQUIRE(test_main_poll_eio_link_down() == 0);
    REQUIRE(test_main_poll_enodev_link_down() == 0);
    REQUIRE(test_rx_full_probe_eio_link_down() == 0);
    REQUIRE(test_rx_full_probe_enxio_link_down() == 0);
    REQUIRE(test_rx_full_probe_pollnval_link_down() == 0);
    REQUIRE(test_rx_full_probe_pollerr_link_down() == 0);
    REQUIRE(test_rx_full_probe_pollhup_link_down() == 0);
    REQUIRE(test_rx_full_probe_pollin_overflow() == 0);
    REQUIRE(test_poll_deadline_covers_prepump() == 0);
    REQUIRE(test_poll_zero_tx_progress() == 0);
    REQUIRE(test_poll_zero_rx_progress() == 0);
    REQUIRE(test_set_sys_ops_forbidden_when_active() == 0);
    REQUIRE(test_pty_bidirectional_integration() == 0);
    REQUIRE(test_poll_timeout() == 0);
    REQUIRE(test_tx_backpressure_4k_and_recovery() == 0);
    REQUIRE(test_rx_overflow_continuity() == 0);
    REQUIRE(test_hangup_link_down() == 0);
    REQUIRE(test_close_reopen_generation() == 0);
    REQUIRE(test_wrong_owner_matrix_while_up() == 0);
    REQUIRE(test_wrong_owner_process() == 0);
    REQUIRE(test_open_wrong_owner_after_link_down() == 0);
    REQUIRE(test_open_same_owner_link_down_requires_close() == 0);
    REQUIRE(test_open_new_owner_after_explicit_close() == 0);
    REQUIRE(test_stats_hwm() == 0);
    (void)printf("posix_usb_serial_test ok (%d cases)\n", 50);
    return 0;
}
