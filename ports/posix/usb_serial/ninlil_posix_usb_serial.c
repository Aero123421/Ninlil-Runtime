/*
 * A1 POSIX USB/serial adapter — production-private host implementation.
 * See ninlil_posix_usb_serial.h and docs/23 §3.2 / §4 / §6 / §10.1.
 */

#include "ninlil_posix_usb_serial.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define NINLIL_POSIX_USB_SERIAL_MAGIC ((uint32_t)0x4e505553u) /* 'NPUS' */

typedef struct ninlil_posix_usb_serial {
    uint32_t magic;
    int fd;
    ninlil_byte_stream_link_t link;
    uint64_t link_generation;
    pid_t owner_pid;
    pthread_t owner_thread;
    int owner_set;
    int saw_hup;
    int rx_overflow_latched;
    int dtr_status; /* 1 asserted, 0 unsupported, -1 error */
    int32_t dtr_errno;

    uint8_t rx_ring[NINLIL_BYTE_STREAM_RING_BYTES];
    uint32_t rx_head;
    uint32_t rx_tail;
    uint32_t rx_len;

    uint8_t tx_ring[NINLIL_BYTE_STREAM_RING_BYTES];
    uint32_t tx_head;
    uint32_t tx_tail;
    uint32_t tx_len;

    char path[NINLIL_BYTE_STREAM_PATH_BYTES];
    ninlil_byte_stream_stats_t stats;
    ninlil_byte_stream_error_t last_error;
    ninlil_posix_usb_serial_sys_ops_t sys;
    int sys_active;
} ninlil_posix_usb_serial_t;

_Static_assert(
    sizeof(ninlil_posix_usb_serial_t) <= NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES,
    "posix usb serial object exceeds storage size ceiling");
_Static_assert(
    _Alignof(ninlil_posix_usb_serial_t) <= NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN,
    "posix usb serial object align insufficient for concrete state");
_Static_assert(
    (NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN % _Alignof(ninlil_posix_usb_serial_t))
        == 0u,
    "object storage align must be a multiple of concrete align");
_Static_assert(
    sizeof(ninlil_posix_usb_serial_object_t)
        >= sizeof(ninlil_posix_usb_serial_t),
    "opaque object bytes smaller than concrete state");
_Static_assert(
    _Alignof(ninlil_posix_usb_serial_object_t)
        >= _Alignof(ninlil_posix_usb_serial_t),
    "opaque object align weaker than concrete state");

static void error_clear(ninlil_byte_stream_error_t *err)
{
    if (err == NULL) {
        return;
    }
    (void)memset(err, 0, sizeof(*err));
}

static void error_set(
    ninlil_posix_usb_serial_t *self,
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    int sys_errno,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    error_clear(&local);
    local.status = status;
    local.stage = stage;
    local.sys_errno = (int32_t)sys_errno;
    if (self != NULL && self->path[0] != '\0') {
        (void)memcpy(local.path, self->path, sizeof(local.path));
        local.path[sizeof(local.path) - 1u] = '\0';
    }
    if (hint != NULL) {
        size_t n = strlen(hint);
        if (n >= sizeof(local.hint)) {
            n = sizeof(local.hint) - 1u;
        }
        (void)memcpy(local.hint, hint, n);
        local.hint[n] = '\0';
    }
    if (self != NULL) {
        self->last_error = local;
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static void copy_path(ninlil_posix_usb_serial_t *self, const char *path)
{
    size_t n;

    (void)memset(self->path, 0, sizeof(self->path));
    if (path == NULL) {
        return;
    }
    n = strlen(path);
    if (n >= sizeof(self->path)) {
        n = sizeof(self->path) - 1u;
    }
    (void)memcpy(self->path, path, n);
}

static int path_is_absolute(const char *path)
{
    return path != NULL && path[0] == '/' && path[1] != '\0';
}

/*
 * Length-checked prefix match. MUST NOT walk past the path length (short
 * strings must not read past the terminating NUL as if they were longer).
 */
static int path_is_macos_tty_dev(const char *path)
{
    static const char prefix[] = "/dev/tty.";
    const size_t prefix_len = sizeof(prefix) - 1u;
    size_t path_len;

    if (path == NULL) {
        return 0;
    }
    path_len = strlen(path);
    if (path_len < prefix_len) {
        return 0;
    }
    return memcmp(path, prefix, prefix_len) == 0;
}

static ninlil_posix_usb_serial_t *self_from(ninlil_byte_stream_t *stream)
{
    ninlil_posix_usb_serial_t *self;

    if (stream == NULL || stream->self == NULL) {
        return NULL;
    }
    self = (ninlil_posix_usb_serial_t *)stream->self;
    if (self->magic != NINLIL_POSIX_USB_SERIAL_MAGIC) {
        return NULL;
    }
    return self;
}

static const ninlil_posix_usb_serial_t *self_from_const(
    const ninlil_byte_stream_t *stream)
{
    const ninlil_posix_usb_serial_t *self;

    if (stream == NULL || stream->self == NULL) {
        return NULL;
    }
    self = (const ninlil_posix_usb_serial_t *)stream->self;
    if (self->magic != NINLIL_POSIX_USB_SERIAL_MAGIC) {
        return NULL;
    }
    return self;
}

/*
 * WRONG_OWNER is out-only: never write stream last_error/stats/rings/link/
 * generation/path. Caller-owned out_error gets structured facts only.
 */
static void wrong_owner_error_out(
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    if (out_error == NULL) {
        return;
    }
    error_clear(&local);
    local.status = NINLIL_BYTE_STREAM_WRONG_OWNER;
    local.stage = NINLIL_BYTE_STREAM_STAGE_OWNER;
    local.sys_errno = 0;
    if (hint != NULL) {
        size_t n = strlen(hint);
        if (n >= sizeof(local.hint)) {
            n = sizeof(local.hint) - 1u;
        }
        (void)memcpy(local.hint, hint, n);
        local.hint[n] = '\0';
    }
    *out_error = local;
}

static int check_owner(
    const ninlil_posix_usb_serial_t *self,
    ninlil_byte_stream_error_t *out_error)
{
    if (!self->owner_set) {
        return 1;
    }
    if (self->owner_pid != getpid()) {
        wrong_owner_error_out(
            "owner process mismatch; fork fd share is forbidden", out_error);
        return 0;
    }
    if (!pthread_equal(self->owner_thread, pthread_self())) {
        wrong_owner_error_out(
            "owner thread mismatch; close/use only on owner thread",
            out_error);
        return 0;
    }
    return 1;
}

static void ring_reset_rx(ninlil_posix_usb_serial_t *self)
{
    self->rx_head = 0u;
    self->rx_tail = 0u;
    self->rx_len = 0u;
}

static void ring_reset_tx(ninlil_posix_usb_serial_t *self)
{
    self->tx_head = 0u;
    self->tx_tail = 0u;
    self->tx_len = 0u;
}

static uint32_t ring_free_rx(const ninlil_posix_usb_serial_t *self)
{
    return NINLIL_BYTE_STREAM_RING_BYTES - self->rx_len;
}

static uint32_t ring_free_tx(const ninlil_posix_usb_serial_t *self)
{
    return NINLIL_BYTE_STREAM_RING_BYTES - self->tx_len;
}

static void ring_push_rx(
    ninlil_posix_usb_serial_t *self,
    const uint8_t *data,
    uint32_t n)
{
    uint32_t i;

    for (i = 0u; i < n; ++i) {
        self->rx_ring[self->rx_tail] = data[i];
        self->rx_tail = (self->rx_tail + 1u) % NINLIL_BYTE_STREAM_RING_BYTES;
    }
    self->rx_len += n;
    self->stats.rx_high_watermark = ninlil_byte_stream_sat_hwm_u32(
        self->stats.rx_high_watermark, self->rx_len);
    self->stats.rx_ring_bytes = self->rx_len;
}

static void ring_push_tx(
    ninlil_posix_usb_serial_t *self,
    const uint8_t *data,
    uint32_t n)
{
    uint32_t i;

    for (i = 0u; i < n; ++i) {
        self->tx_ring[self->tx_tail] = data[i];
        self->tx_tail = (self->tx_tail + 1u) % NINLIL_BYTE_STREAM_RING_BYTES;
    }
    self->tx_len += n;
    self->stats.tx_high_watermark = ninlil_byte_stream_sat_hwm_u32(
        self->stats.tx_high_watermark, self->tx_len);
    self->stats.tx_ring_bytes = self->tx_len;
}

static uint32_t ring_pop_rx(
    ninlil_posix_usb_serial_t *self,
    uint8_t *out,
    uint32_t cap)
{
    uint32_t n = self->rx_len;
    uint32_t i;

    if (n > cap) {
        n = cap;
    }
    for (i = 0u; i < n; ++i) {
        out[i] = self->rx_ring[self->rx_head];
        self->rx_head = (self->rx_head + 1u) % NINLIL_BYTE_STREAM_RING_BYTES;
    }
    self->rx_len -= n;
    self->stats.rx_ring_bytes = self->rx_len;
    return n;
}

static uint32_t ring_peek_tx(
    const ninlil_posix_usb_serial_t *self,
    uint8_t *out,
    uint32_t cap)
{
    uint32_t n = self->tx_len;
    uint32_t i;
    uint32_t head;

    if (n > cap) {
        n = cap;
    }
    head = self->tx_head;
    for (i = 0u; i < n; ++i) {
        out[i] = self->tx_ring[head];
        head = (head + 1u) % NINLIL_BYTE_STREAM_RING_BYTES;
    }
    return n;
}

static void ring_consume_tx(ninlil_posix_usb_serial_t *self, uint32_t n)
{
    if (n > self->tx_len) {
        n = self->tx_len;
    }
    self->tx_head = (self->tx_head + n) % NINLIL_BYTE_STREAM_RING_BYTES;
    self->tx_len -= n;
    self->stats.tx_ring_bytes = self->tx_len;
}

/*
 * Monotonic milliseconds for the whole poll() call budget.
 * Prefer test seam now_ms_fn when active; else CLOCK_MONOTONIC.
 * Returns -1 if unavailable (EINTR ceiling still bounds the call).
 */
static int64_t mono_now_ms(const ninlil_posix_usb_serial_t *self)
{
    struct timespec ts;

    if (self != NULL && self->sys_active && self->sys.now_ms_fn != NULL) {
        return self->sys.now_ms_fn(self->sys.user);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return (int64_t)-1;
    }
    return ((int64_t)ts.tv_sec * (int64_t)1000)
        + ((int64_t)ts.tv_nsec / (int64_t)1000000);
}

static int remaining_timeout_ms(int64_t deadline_ms, int64_t now_ms)
{
    int64_t left;

    if (deadline_ms < 0 || now_ms < 0) {
        /* No reliable clock: caller must use non-blocking or full fallback. */
        return 0;
    }
    left = deadline_ms - now_ms;
    if (left <= 0) {
        return 0;
    }
    if (left > (int64_t)0x7fffffff) {
        return 0x7fffffff;
    }
    return (int)left;
}

static int budget_expired(
    const ninlil_posix_usb_serial_t *self,
    int64_t deadline_ms)
{
    int64_t now;

    if (deadline_ms < 0) {
        return 0;
    }
    now = mono_now_ms(self);
    if (now < 0) {
        return 0;
    }
    return now >= deadline_ms;
}

static int sys_open(ninlil_posix_usb_serial_t *self, const char *path, int flags)
{
    if (self->sys_active && self->sys.open_fn != NULL) {
        return self->sys.open_fn(path, flags, self->sys.user);
    }
    return open(path, flags);
}

static int sys_close(ninlil_posix_usb_serial_t *self, int fd)
{
    if (self->sys_active && self->sys.close_fn != NULL) {
        return self->sys.close_fn(fd, self->sys.user);
    }
    return close(fd);
}

static int sys_read(ninlil_posix_usb_serial_t *self, int fd, void *buf, size_t n)
{
    ssize_t rc;

    if (self->sys_active && self->sys.read_fn != NULL) {
        return self->sys.read_fn(fd, buf, n, self->sys.user);
    }
    rc = read(fd, buf, n);
    if (rc < 0) {
        return -1;
    }
    return (int)rc;
}

static int sys_write(
    ninlil_posix_usb_serial_t *self,
    int fd,
    const void *buf,
    size_t n)
{
    ssize_t rc;

    if (self->sys_active && self->sys.write_fn != NULL) {
        return self->sys.write_fn(fd, buf, n, self->sys.user);
    }
    rc = write(fd, buf, n);
    if (rc < 0) {
        return -1;
    }
    return (int)rc;
}

static int sys_poll(
    ninlil_posix_usb_serial_t *self,
    int fd,
    int want_events,
    int *got_events,
    int timeout_ms)
{
    struct pollfd pfd;
    int rc;

    if (self->sys_active && self->sys.poll_fn != NULL) {
        return self->sys.poll_fn(
            fd, want_events, got_events, timeout_ms, self->sys.user);
    }
    pfd.fd = fd;
    pfd.events = (short)want_events;
    pfd.revents = 0;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc > 0 && got_events != NULL) {
        *got_events = (int)pfd.revents;
    } else if (got_events != NULL) {
        *got_events = 0;
    }
    return rc;
}

static int sys_tcgetattr(
    ninlil_posix_usb_serial_t *self,
    int fd,
    struct termios *tio)
{
    if (self->sys_active && self->sys.tcgetattr_fn != NULL) {
        return self->sys.tcgetattr_fn(fd, tio, self->sys.user);
    }
    return tcgetattr(fd, tio);
}

static int sys_tcsetattr(
    ninlil_posix_usb_serial_t *self,
    int fd,
    int actions,
    const struct termios *tio)
{
    if (self->sys_active && self->sys.tcsetattr_fn != NULL) {
        return self->sys.tcsetattr_fn(fd, actions, tio, self->sys.user);
    }
    return tcsetattr(fd, actions, tio);
}

static int sys_ioctl(
    ninlil_posix_usb_serial_t *self,
    int fd,
    unsigned long request,
    void *arg)
{
    if (self->sys_active && self->sys.ioctl_fn != NULL) {
        return self->sys.ioctl_fn(fd, request, arg, self->sys.user);
    }
    return ioctl(fd, request, arg);
}

/*
 * Host-test-only FORCE compiles the fcntl fallback even when O_CLOEXEC exists
 * (modern Linux/macOS otherwise never build that path). Production never
 * defines the FORCE macro.
 */
#if defined(NINLIL_POSIX_USB_SERIAL_FORCE_FCNTL_CLOEXEC_FALLBACK) \
    || !defined(O_CLOEXEC)
#define NINLIL_POSIX_USB_SERIAL_FCNTL_CLOEXEC_FALLBACK 1
#endif

#if defined(NINLIL_POSIX_USB_SERIAL_FCNTL_CLOEXEC_FALLBACK)
/*
 * Fallback when atomic O_CLOEXEC on open(2) is unavailable (or FORCE host-test).
 * Failure must fence the fd (caller); no silent continue.
 */
static int sys_set_cloexec(ninlil_posix_usb_serial_t *self, int fd)
{
    int flags;

    if (self->sys_active && self->sys.set_cloexec_fn != NULL) {
        return self->sys.set_cloexec_fn(fd, self->sys.user);
    }
    flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
        return -1;
    }
    return 0;
}
#endif

static void map_open_errno(
    ninlil_posix_usb_serial_t *self,
    int err,
    ninlil_byte_stream_error_t *out_error)
{
    const char *hint = "open failed";
    ninlil_byte_stream_status_t status = NINLIL_BYTE_STREAM_IO_ERROR;
    ninlil_byte_stream_stage_t stage = NINLIL_BYTE_STREAM_STAGE_OPEN;

    if (err == EACCES || err == EPERM) {
        status = NINLIL_BYTE_STREAM_PERMISSION;
        hint =
            "EACCES/EPERM: check dialout/uucp group membership or udev rules "
            "(Linux); macOS TCC/serial entitlement not required for /dev/cu.*";
    } else if (err == ENOENT || err == ENOTDIR) {
        status = NINLIL_BYTE_STREAM_NOT_FOUND;
        if (path_is_macos_tty_dev(self->path)) {
            hint =
                "path not found; on macOS prefer /dev/cu.* (not /dev/tty.*) for "
                "Controller USB CDC";
        } else {
            hint = "device path not found; pass explicit absolute path only";
        }
    } else if (err == EBUSY || err == EAGAIN) {
        status = NINLIL_BYTE_STREAM_BUSY;
        stage = NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE;
        hint = "device busy or exclusive open denied (TIOCEXCL/peer open)";
    } else if (err == ENXIO || err == ENODEV) {
        status = NINLIL_BYTE_STREAM_NOT_FOUND;
        hint = "ENODEV/ENXIO: device node present but not ready / unplugged";
    }

    if (path_is_macos_tty_dev(self->path)
        && status != NINLIL_BYTE_STREAM_PERMISSION) {
        hint =
            "open failed; macOS path looks like /dev/tty.* — Controller default "
            "is /dev/cu.* (avoid DCD wait on tty.*)";
    }

    error_set(self, status, stage, err, hint, out_error);
}

static int configure_termios_raw(
    ninlil_posix_usb_serial_t *self,
    ninlil_byte_stream_error_t *out_error)
{
    struct termios tio;

    if (sys_tcgetattr(self, self->fd, &tio) != 0) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_TERMIOS,
            errno,
            "tcgetattr failed",
            out_error);
        return 0;
    }

    cfmakeraw(&tio);
    tio.c_cflag |= (tcflag_t)(CLOCAL | CREAD);
    tio.c_cflag &= (tcflag_t) ~(CSIZE | PARENB | CSTOPB);
#if defined(CRTSCTS)
    tio.c_cflag &= (tcflag_t)~CRTSCTS;
#endif
    tio.c_cflag |= (tcflag_t)CS8;
    tio.c_iflag &= (tcflag_t) ~(IXON | IXOFF | IXANY);
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 0;

    if (cfsetispeed(&tio, B115200) != 0 || cfsetospeed(&tio, B115200) != 0) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_TERMIOS,
            errno,
            "cfsetispeed/cfsetospeed 115200 failed",
            out_error);
        return 0;
    }

    if (sys_tcsetattr(self, self->fd, TCSANOW, &tio) != 0) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_TERMIOS,
            errno,
            "tcsetattr raw 8N1 failed",
            out_error);
        return 0;
    }
    return 1;
}

static void try_assert_dtr(ninlil_posix_usb_serial_t *self)
{
#if defined(TIOCMGET) && defined(TIOCMSET) && defined(TIOCM_DTR)
    int status = 0;

    if (sys_ioctl(self, self->fd, (unsigned long)TIOCMGET, &status) != 0) {
        self->dtr_status = 0;
        self->dtr_errno = (int32_t)errno;
        error_set(
            self,
            NINLIL_BYTE_STREAM_UNSUPPORTED,
            NINLIL_BYTE_STREAM_STAGE_DTR,
            errno,
            "DTR assert unsupported (TIOCMGET failed); open continues",
            NULL);
        return;
    }
    status |= TIOCM_DTR;
    if (sys_ioctl(self, self->fd, (unsigned long)TIOCMSET, &status) != 0) {
        self->dtr_status = -1;
        self->dtr_errno = (int32_t)errno;
        error_set(
            self,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_DTR,
            errno,
            "DTR assert failed (TIOCMSET); open continues with evidence",
            NULL);
        return;
    }
    self->dtr_status = 1;
    self->dtr_errno = 0;
#else
    self->dtr_status = 0;
    self->dtr_errno = 0;
    error_set(
        self,
        NINLIL_BYTE_STREAM_UNSUPPORTED,
        NINLIL_BYTE_STREAM_STAGE_DTR,
        0,
        "DTR macros unavailable on this platform build; open continues",
        NULL);
#endif
}

/*
 * Fence fd without re-close. On EINTR, POSIX does not allow a safe second
 * close of the same descriptor in portable code; the descriptor is fenced.
 */
static ninlil_byte_stream_status_t fence_close_fd(
    ninlil_posix_usb_serial_t *self,
    ninlil_byte_stream_stage_t stage,
    ninlil_byte_stream_error_t *out_error)
{
    int fd;
    int rc;
    int err;

    if (self->fd < 0) {
        return NINLIL_BYTE_STREAM_OK;
    }
    fd = self->fd;
    self->fd = -1;
#ifdef TIOCNXCL
    (void)sys_ioctl(self, fd, (unsigned long)TIOCNXCL, NULL);
#endif
    rc = sys_close(self, fd);
    if (rc != 0) {
        err = errno;
        error_set(
            self,
            NINLIL_BYTE_STREAM_IO_ERROR,
            stage,
            err,
            (err == EINTR)
                ? "close returned EINTR; fd fenced without re-close"
                : "close failed; fd fenced",
            out_error);
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    return NINLIL_BYTE_STREAM_OK;
}

static void mark_link_down(
    ninlil_posix_usb_serial_t *self,
    ninlil_byte_stream_stage_t stage,
    int sys_errno,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    if (self->link == NINLIL_BYTE_STREAM_LINK_UP) {
        self->stats.link_down_count =
            ninlil_byte_stream_sat_add_u64(self->stats.link_down_count, 1u);
    }
    self->link = NINLIL_BYTE_STREAM_LINK_DOWN;
    if (self->fd >= 0) {
        /* Best-effort fence; link-down status dominates. */
        (void)fence_close_fd(self, stage, NULL);
    }
    error_set(
        self,
        NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
        stage,
        sys_errno,
        hint,
        out_error);
}

static int errno_is_link_down(int err)
{
    return err == EIO || err == ENODEV || err == ENXIO
#if defined(ECONNRESET)
        || err == ECONNRESET
#endif
        ;
}

/*
 * Shared poll-call budget: deadline from poll() entry bounds *blocking* wait
 * and additional I/O/retry loops. timeout_ms is a blocking-wait budget only.
 * Even when the deadline is already reached (e.g. timeout_ms=0), each pump
 * still permits at least one nonblocking syscall when work is queued/ready so
 * poll(0) iteration can make finite progress.
 */
static ninlil_byte_stream_status_t pump_tx(
    ninlil_posix_usb_serial_t *self,
    ninlil_byte_stream_event_t *events,
    ninlil_byte_stream_error_t *out_error,
    int64_t deadline_ms,
    uint32_t *eintr_retries)
{
    uint8_t chunk[512];
    uint32_t available;
    int wrote;
    int attempts = 0;

    while (self->tx_len > 0u && self->link == NINLIL_BYTE_STREAM_LINK_UP) {
        /*
         * First nonblocking write is always allowed for liveness when TX is
         * queued. Further iterations require remaining wait budget.
         */
        if (attempts > 0 && budget_expired(self, deadline_ms)) {
            break;
        }
        available = ring_peek_tx(self, chunk, (uint32_t)sizeof(chunk));
        if (available == 0u) {
            break;
        }
        wrote = sys_write(self, self->fd, chunk, (size_t)available);
        attempts += 1;
        if (wrote < 0) {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK) {
                break;
            }
            if (err == EINTR) {
                *eintr_retries += 1u;
                self->stats.eintr_count = ninlil_byte_stream_sat_add_u64(
                    self->stats.eintr_count, 1u);
                if (*eintr_retries >= NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX) {
                    error_set(
                        self,
                        NINLIL_BYTE_STREAM_IO_ERROR,
                        NINLIL_BYTE_STREAM_STAGE_WRITE,
                        EINTR,
                        "write EINTR retry ceiling exhausted",
                        out_error);
                    return NINLIL_BYTE_STREAM_IO_ERROR;
                }
                /* Retries after the first attempt still respect deadline. */
                continue;
            }
            if (errno_is_link_down(err)) {
                mark_link_down(
                    self,
                    NINLIL_BYTE_STREAM_STAGE_WRITE,
                    err,
                    "write link-down errno (EIO/ENODEV/ENXIO)",
                    out_error);
                if (events != NULL) {
                    *events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                }
                return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
            }
            error_set(
                self,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_WRITE,
                err,
                "write failed",
                out_error);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        if (wrote == 0) {
            break;
        }
        ring_consume_tx(self, (uint32_t)wrote);
        self->stats.bytes_written = ninlil_byte_stream_sat_add_u64(
            self->stats.bytes_written, (uint64_t)wrote);
    }
    if (self->tx_len == 0u && events != NULL) {
        *events |= NINLIL_BYTE_STREAM_EVENT_TX_DRAINED;
    }
    if (ring_free_tx(self) > 0u && events != NULL) {
        *events |= NINLIL_BYTE_STREAM_EVENT_WRITABLE;
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t pump_rx(
    ninlil_posix_usb_serial_t *self,
    int revents,
    ninlil_byte_stream_event_t *events,
    ninlil_byte_stream_error_t *out_error,
    int64_t deadline_ms,
    uint32_t *eintr_retries)
{
    uint8_t chunk[512];
    int nread;
    uint32_t free_space;
    int rx_attempts = 0;

    if (self->link != NINLIL_BYTE_STREAM_LINK_UP) {
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }

    free_space = ring_free_rx(self);
    if (free_space == 0u) {
        if ((revents & POLLIN) != 0) {
            if (!self->rx_overflow_latched) {
                self->rx_overflow_latched = 1;
                self->stats.rx_overflow_count = ninlil_byte_stream_sat_add_u64(
                    self->stats.rx_overflow_count, 1u);
            }
            if (events != NULL) {
                *events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
            }
            error_set(
                self,
                NINLIL_BYTE_STREAM_RX_OVERFLOW,
                NINLIL_BYTE_STREAM_STAGE_RX_RING,
                0,
                "RX ring full with pending readable data; continuity signal "
                "(not physical link down); U3 may fence parser/session",
                out_error);
            return NINLIL_BYTE_STREAM_OK;
        }
        return NINLIL_BYTE_STREAM_OK;
    }

    for (;;) {
        /*
         * At least one nonblocking read (or full-ring probe) when ready.
         * Additional iterations stop once the blocking-wait deadline expires.
         */
        if (rx_attempts > 0 && budget_expired(self, deadline_ms)) {
            break;
        }
        free_space = ring_free_rx(self);
        if (free_space == 0u) {
            /*
             * Ring exactly full: non-blocking probe for pending readable data.
             * Errors/EINTR/HUP must not fall through as silent OK.
             */
            int probe_want = POLLIN | POLLERR | POLLHUP | POLLNVAL;
            int probe_attempts = 0;
            for (;;) {
                int got = 0;
                int prc;

                if (probe_attempts > 0 && budget_expired(self, deadline_ms)) {
                    return NINLIL_BYTE_STREAM_OK;
                }
                prc = sys_poll(self, self->fd, probe_want, &got, 0);
                probe_attempts += 1;
                if (prc < 0) {
                    int err = errno;
                    if (err == EINTR) {
                        *eintr_retries += 1u;
                        self->stats.eintr_count =
                            ninlil_byte_stream_sat_add_u64(
                                self->stats.eintr_count, 1u);
                        if (*eintr_retries
                            >= NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX) {
                            error_set(
                                self,
                                NINLIL_BYTE_STREAM_IO_ERROR,
                                NINLIL_BYTE_STREAM_STAGE_POLL,
                                EINTR,
                                "RX-full probe poll EINTR retry ceiling "
                                "exhausted",
                                out_error);
                            return NINLIL_BYTE_STREAM_IO_ERROR;
                        }
                        continue;
                    }
                    /* docs/23 §3.2.2: EIO/ENODEV/ENXIO (unplug) → link down. */
                    if (errno_is_link_down(err)) {
                        mark_link_down(
                            self,
                            NINLIL_BYTE_STREAM_STAGE_POLL,
                            err,
                            "RX-full probe poll link-down errno "
                            "(EIO/ENODEV/ENXIO)",
                            out_error);
                        if (events != NULL) {
                            *events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                        }
                        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
                    }
                    error_set(
                        self,
                        NINLIL_BYTE_STREAM_IO_ERROR,
                        NINLIL_BYTE_STREAM_STAGE_POLL,
                        err,
                        "RX-full probe poll failed",
                        out_error);
                    return NINLIL_BYTE_STREAM_IO_ERROR;
                }
                if (prc == 0) {
                    /* No pending kernel data; not an overflow. */
                    return NINLIL_BYTE_STREAM_OK;
                }
                if ((got & (POLLNVAL | POLLERR)) != 0) {
                    mark_link_down(
                        self,
                        NINLIL_BYTE_STREAM_STAGE_POLL,
                        0,
                        (got & POLLNVAL) != 0
                            ? "RX-full probe POLLNVAL maps to link down"
                            : "RX-full probe POLLERR maps to link down",
                        out_error);
                    if (events != NULL) {
                        *events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                    }
                    return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
                }
                if ((got & POLLHUP) != 0) {
                    mark_link_down(
                        self,
                        NINLIL_BYTE_STREAM_STAGE_POLL,
                        0,
                        "RX-full probe POLLHUP maps to link down",
                        out_error);
                    if (events != NULL) {
                        *events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                    }
                    return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
                }
                if ((got & POLLIN) != 0) {
                    if (!self->rx_overflow_latched) {
                        self->rx_overflow_latched = 1;
                        self->stats.rx_overflow_count =
                            ninlil_byte_stream_sat_add_u64(
                                self->stats.rx_overflow_count, 1u);
                    }
                    if (events != NULL) {
                        *events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
                    }
                    error_set(
                        self,
                        NINLIL_BYTE_STREAM_RX_OVERFLOW,
                        NINLIL_BYTE_STREAM_STAGE_RX_RING,
                        0,
                        "RX ring full with pending readable data; continuity "
                        "signal (not physical link down)",
                        out_error);
                    return NINLIL_BYTE_STREAM_OK;
                }
                /* Unexpected revents bits only: treat as no overflow. */
                return NINLIL_BYTE_STREAM_OK;
            }
        }

        {
            size_t want = (size_t)free_space;
            if (want > sizeof(chunk)) {
                want = sizeof(chunk);
            }
            nread = sys_read(self, self->fd, chunk, want);
        }
        rx_attempts += 1;
        if (nread < 0) {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK) {
                break;
            }
            if (err == EINTR) {
                *eintr_retries += 1u;
                self->stats.eintr_count = ninlil_byte_stream_sat_add_u64(
                    self->stats.eintr_count, 1u);
                if (*eintr_retries >= NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX) {
                    error_set(
                        self,
                        NINLIL_BYTE_STREAM_IO_ERROR,
                        NINLIL_BYTE_STREAM_STAGE_READ,
                        EINTR,
                        "read EINTR retry ceiling exhausted",
                        out_error);
                    return NINLIL_BYTE_STREAM_IO_ERROR;
                }
                continue;
            }
            if (errno_is_link_down(err)) {
                mark_link_down(
                    self,
                    NINLIL_BYTE_STREAM_STAGE_READ,
                    err,
                    "read link-down errno (EIO/ENODEV/ENXIO)",
                    out_error);
                if (events != NULL) {
                    *events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                }
                return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
            }
            error_set(
                self,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_READ,
                err,
                "read failed",
                out_error);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        if (nread == 0) {
            if (self->saw_hup || (revents & (POLLHUP | POLLERR)) != 0) {
                mark_link_down(
                    self,
                    NINLIL_BYTE_STREAM_STAGE_READ,
                    0,
                    "zero-length read after HUP/ERR maps to link down",
                    out_error);
                if (events != NULL) {
                    *events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                }
                return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
            }
            break;
        }
        ring_push_rx(self, chunk, (uint32_t)nread);
        self->stats.bytes_read = ninlil_byte_stream_sat_add_u64(
            self->stats.bytes_read, (uint64_t)nread);
        if (events != NULL) {
            *events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
        }
    }
    return NINLIL_BYTE_STREAM_OK;
}

/* ---- public entry points ------------------------------------------------ */

size_t ninlil_posix_usb_serial_object_size(void)
{
    return sizeof(ninlil_posix_usb_serial_t);
}

size_t ninlil_posix_usb_serial_object_align(void)
{
    return NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN;
}

static const ninlil_byte_stream_ops_t *posix_usb_serial_ops(void);

ninlil_byte_stream_status_t ninlil_posix_usb_serial_init(
    void *storage,
    size_t storage_bytes,
    ninlil_byte_stream_t *out_stream)
{
    ninlil_posix_usb_serial_t *self;
    uintptr_t addr;

    if (storage == NULL || out_stream == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (storage_bytes < sizeof(ninlil_posix_usb_serial_t)) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    addr = (uintptr_t)storage;
    if ((addr % NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN) != 0u) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    self = (ninlil_posix_usb_serial_t *)storage;
    (void)memset(self, 0, sizeof(*self));
    self->magic = NINLIL_POSIX_USB_SERIAL_MAGIC;
    self->fd = -1;
    self->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
    self->link_generation = 0u;

    out_stream->ops = posix_usb_serial_ops();
    out_stream->self = self;
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_init_object(
    ninlil_posix_usb_serial_object_t *object,
    ninlil_byte_stream_t *out_stream)
{
    if (object == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    return ninlil_posix_usb_serial_init(
        object->bytes, sizeof(object->bytes), out_stream);
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_set_sys_ops(
    ninlil_byte_stream_t *stream,
    const ninlil_posix_usb_serial_sys_ops_t *ops)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);

    if (self == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (self->link == NINLIL_BYTE_STREAM_LINK_UP || self->fd >= 0) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "set_sys_ops forbidden while link is active",
            NULL);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (ops == NULL) {
        (void)memset(&self->sys, 0, sizeof(self->sys));
        self->sys_active = 0;
        return NINLIL_BYTE_STREAM_OK;
    }
    self->sys = *ops;
    self->sys_active = 1;
    return NINLIL_BYTE_STREAM_OK;
}

void ninlil_posix_usb_serial_test_force_generation(
    ninlil_byte_stream_t *stream,
    uint64_t generation)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);

    if (self == NULL) {
        return;
    }
    self->link_generation = generation;
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_open(
    ninlil_byte_stream_t *stream,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);
    int fd;
    int flags;
    int have_warning = 0;

    if (self == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "null or uninitialized stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    /*
     * Active generation (UP or LINK_DOWN): open is single-owner first.
     * Wrong process/thread → WRONG_OWNER with zero stream mutation (out_error
     * only). Open is allowed only from LINK_CLOSED with fd already fenced
     * (initial or after the owner's explicit close). LINK_DOWN does not
     * permit reopen even for the same owner — must close first so residual
     * RX is not silently dropped by a new open. A1 never uses LISTENING.
     */
    if (self->owner_set
        && self->link != NINLIL_BYTE_STREAM_LINK_CLOSED) {
        if (!check_owner(self, out_error)) {
            return NINLIL_BYTE_STREAM_WRONG_OWNER;
        }
    }

    if (self->link != NINLIL_BYTE_STREAM_LINK_CLOSED || self->fd >= 0) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "close before reopen (open only from CLOSED with fd fenced)",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    /*
     * Fail closed before open when generation cannot advance to a new value.
     * UINT64_MAX is the last issued generation; reuse is forbidden.
     */
    if (self->link_generation == UINT64_MAX) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "link generation exhausted; cannot open without generation reuse",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    /* Clear stale last_error from a previous session/attempt. */
    error_clear(&self->last_error);

    /* A1: C1 endpoint_token must be an absolute device path. */
    if (!path_is_absolute(endpoint_token)) {
        copy_path(self, endpoint_token != NULL ? endpoint_token : "");
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_PATH,
            0,
            "explicit absolute device path required (no relative / empty / "
            "auto-picker)",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    copy_path(self, endpoint_token);

    if (path_is_macos_tty_dev(endpoint_token)) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_OK,
            NINLIL_BYTE_STREAM_STAGE_PATH,
            0,
            "macOS path is /dev/tty.*; Controller default prefers /dev/cu.* "
            "(tty may wait on DCD)",
            NULL);
        have_warning = 1;
    }

#if defined(NINLIL_POSIX_USB_SERIAL_FCNTL_CLOEXEC_FALLBACK)
    /* No atomic O_CLOEXEC (or host-test FORCE): open then fcntl FD_CLOEXEC. */
    flags = O_RDWR | O_NOCTTY | O_NONBLOCK;
#else
    /* Linux/macOS modern path: atomic close-on-exec (docs/23 §3.2.2). */
    flags = O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC;
#endif
    fd = sys_open(self, endpoint_token, flags);
    if (fd < 0) {
        map_open_errno(self, errno, out_error);
        return self->last_error.status;
    }
    self->fd = fd;

#if defined(NINLIL_POSIX_USB_SERIAL_FCNTL_CLOEXEC_FALLBACK)
    if (sys_set_cloexec(self, self->fd) != 0) {
        int err = errno;
        (void)fence_close_fd(self, NINLIL_BYTE_STREAM_STAGE_OPEN, NULL);
        error_set(
            self,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            err,
            "fcntl FD_CLOEXEC failed after open; fd fenced",
            out_error);
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
#endif

#if defined(TIOCEXCL)
    if (sys_ioctl(self, self->fd, (unsigned long)TIOCEXCL, NULL) != 0) {
        int err = errno;
        if (err == EBUSY
#if defined(EAGAIN)
            || err == EAGAIN
#endif
        ) {
            (void)fence_close_fd(self, NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE, NULL);
            error_set(
                self,
                NINLIL_BYTE_STREAM_BUSY,
                NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE,
                err,
                "TIOCEXCL exclusive open denied (device busy)",
                out_error);
            return NINLIL_BYTE_STREAM_BUSY;
        }
        error_set(
            self,
            NINLIL_BYTE_STREAM_UNSUPPORTED,
            NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE,
            err,
            "TIOCEXCL unsupported; open continues without exclusive claim",
            NULL);
        have_warning = 1;
    }
#endif

    if (!configure_termios_raw(self, out_error)) {
        (void)fence_close_fd(self, NINLIL_BYTE_STREAM_STAGE_TERMIOS, NULL);
        return self->last_error.status != 0u
            ? self->last_error.status
            : NINLIL_BYTE_STREAM_IO_ERROR;
    }

    try_assert_dtr(self);
    if (self->last_error.stage == NINLIL_BYTE_STREAM_STAGE_DTR
        || self->last_error.stage == NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE
        || self->last_error.stage == NINLIL_BYTE_STREAM_STAGE_PATH) {
        have_warning = 1;
    }

    ring_reset_rx(self);
    ring_reset_tx(self);
    self->saw_hup = 0;
    self->rx_overflow_latched = 0;
    self->owner_pid = getpid();
    self->owner_thread = pthread_self();
    self->owner_set = 1;
    self->link = NINLIL_BYTE_STREAM_LINK_UP;
    /* Non-saturating increment: reuse of UINT64_MAX is fail-closed above. */
    self->link_generation += 1u;
    if (self->link_generation == 0u) {
        self->link_generation = 1u;
    }
    self->stats.link_up_count = ninlil_byte_stream_sat_add_u64(
        self->stats.link_up_count, 1u);
    self->stats.open_count =
        ninlil_byte_stream_sat_add_u64(self->stats.open_count, 1u);

    if (out_error != NULL) {
        if (have_warning && self->last_error.status != NINLIL_BYTE_STREAM_OK
            && self->last_error.stage != NINLIL_BYTE_STREAM_STAGE_NONE) {
            *out_error = self->last_error;
        } else if (have_warning
            && self->last_error.stage != NINLIL_BYTE_STREAM_STAGE_NONE) {
            *out_error = self->last_error;
        } else {
            error_clear(out_error);
        }
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_close(
    ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);
    ninlil_byte_stream_status_t close_st;

    if (self == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            0,
            "null or uninitialized stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    /* Owner check before any state change / idempotent branch. */
    if (self->owner_set && !check_owner(self, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }

    /* Already fully closed: pure idempotent OK. */
    if (self->link == NINLIL_BYTE_STREAM_LINK_CLOSED && self->fd < 0) {
        if (out_error != NULL) {
            error_clear(out_error);
        }
        return NINLIL_BYTE_STREAM_OK;
    }

    close_st = NINLIL_BYTE_STREAM_OK;
    if (self->fd >= 0) {
        /* LINK_UP (or unexpected open fd): fence-close once. */
        close_st = fence_close_fd(
            self, NINLIL_BYTE_STREAM_STAGE_CLOSE, out_error);
        self->stats.close_count =
            ninlil_byte_stream_sat_add_u64(self->stats.close_count, 1u);
    } else {
        /*
         * LINK_DOWN path: fd already fenced by mark_link_down. Explicit close
         * still transitions to CLOSED and clears rings; never re-sys-close.
         */
        self->stats.close_count =
            ninlil_byte_stream_sat_add_u64(self->stats.close_count, 1u);
    }

    self->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
    ring_reset_rx(self);
    ring_reset_tx(self);
    self->saw_hup = 0;
    self->rx_overflow_latched = 0;
    /* Keep owner_set and generation so post-close use is fenced. */

    if (close_st != NINLIL_BYTE_STREAM_OK) {
        return close_st;
    }
    if (out_error != NULL) {
        error_clear(out_error);
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);

    if (self == NULL) {
        if (out_accepted != NULL) {
            *out_accepted = 0u;
        }
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "invalid write arguments",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    /* Owner before out-payload init / arg validation; wrong-owner leaves
     * out_accepted unchanged and does not touch stream state. */
    if (self->owner_set && !check_owner(self, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (out_accepted != NULL) {
        *out_accepted = 0u;
    }
    if (data == NULL && length != 0u) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "invalid write arguments",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (self->link != NINLIL_BYTE_STREAM_LINK_UP || self->fd < 0) {
        error_set(
            self,
            self->link == NINLIL_BYTE_STREAM_LINK_DOWN
                ? NINLIL_BYTE_STREAM_ERR_LINK_DOWN
                : NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "write rejected: link not up (old generation fenced)",
            out_error);
        return self->last_error.status;
    }
    if (length == 0u) {
        if (out_error != NULL) {
            error_clear(out_error);
        }
        return NINLIL_BYTE_STREAM_OK;
    }
    if (length > NINLIL_BYTE_STREAM_RING_BYTES) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_TX_RING,
            0,
            "write length exceeds fixed TX ring capacity (4096)",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (length > ring_free_tx(self)) {
        self->stats.would_block_count =
            ninlil_byte_stream_sat_add_u64(self->stats.would_block_count, 1u);
        error_set(
            self,
            NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_TX_RING,
            0,
            "TX ring full: all-or-none WOULD_BLOCK (not custody)",
            out_error);
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }

    ring_push_tx(self, data, length);
    if (out_accepted != NULL) {
        *out_accepted = length;
    }
    if (out_error != NULL) {
        error_clear(out_error);
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);
    uint32_t n;

    if (self == NULL) {
        if (out_length != NULL) {
            *out_length = 0u;
        }
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "invalid read arguments",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    /* Owner first: wrong-owner leaves out_length/payload unchanged. */
    if (self->owner_set && !check_owner(self, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_data == NULL || out_length == NULL) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "invalid read arguments",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    /*
     * capacity == 0 is always INVALID_ARGUMENT (UP or DOWN). Returning OK+0
     * would hide LINK_DOWN forever when the ring is empty or non-empty.
     */
    if (capacity == 0u) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "read capacity must be non-zero",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    /* Explicit close fences all residual RX; never expose post-close bytes. */
    if (self->link == NINLIL_BYTE_STREAM_LINK_CLOSED) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "read rejected: closed",
            out_error);
        return NINLIL_BYTE_STREAM_CLOSED;
    }

    /*
     * LINK_DOWN (not yet explicitly closed): drain buffered RX first
     * (OK + length > 0 only). Empty ring → ERR_LINK_DOWN.
     */
    if (self->link == NINLIL_BYTE_STREAM_LINK_DOWN && self->rx_len == 0u) {
        error_set(
            self,
            NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "read after link down with empty RX ring",
            out_error);
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }

    n = ring_pop_rx(self, out_data, capacity);
    *out_length = n;
    if (n > 0u && self->rx_overflow_latched && ring_free_rx(self) > 0u) {
        self->rx_overflow_latched = 0;
    }
    if (out_error != NULL) {
        error_clear(out_error);
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_posix_usb_serial_poll(
    ninlil_byte_stream_t *stream,
    uint32_t timeout_ms,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_posix_usb_serial_t *self = self_from(stream);
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    int want;
    int got = 0;
    int rc;
    int timeout_left;
    int64_t start_ms;
    int64_t deadline_ms;
    uint32_t eintr_retries = 0u;
    ninlil_byte_stream_status_t st;

    if (self == NULL) {
        if (out_events != NULL) {
            *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
        }
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            0,
            "null stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    /* Owner before out_events init; wrong-owner leaves sentinel unchanged. */
    if (self->owner_set && !check_owner(self, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (out_events != NULL) {
        *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
    }
    if (self->link != NINLIL_BYTE_STREAM_LINK_UP || self->fd < 0) {
        error_set(
            self,
            self->link == NINLIL_BYTE_STREAM_LINK_DOWN
                ? NINLIL_BYTE_STREAM_ERR_LINK_DOWN
                : NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            0,
            "poll rejected: link not up",
            out_error);
        if (out_events != NULL && self->link == NINLIL_BYTE_STREAM_LINK_DOWN) {
            *out_events = NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
        }
        return self->last_error.status;
    }

    /*
     * timeout_ms = blocking wait budget only. Deadline from call entry stops
     * additional loops/blocking wait; pumps still allow one nonblocking try.
     */
    timeout_left = (timeout_ms > 0x7fffffffu) ? 0x7fffffff : (int)timeout_ms;
    start_ms = mono_now_ms(self);
    if (start_ms >= 0) {
        deadline_ms = start_ms + (int64_t)timeout_left;
    } else {
        deadline_ms = (int64_t)-1;
    }

    /* Pre-pump TX if queued (including timeout_ms=0: one nonblocking write). */
    st = pump_tx(self, &events, out_error, deadline_ms, &eintr_retries);
    if (st != NINLIL_BYTE_STREAM_OK) {
        if (out_events != NULL) {
            *out_events = events;
        }
        return st;
    }

    want = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    if (self->tx_len > 0u) {
        want |= POLLOUT;
    }

    for (;;) {
        int wait_ms;

        if (deadline_ms >= 0) {
            wait_ms = remaining_timeout_ms(deadline_ms, mono_now_ms(self));
        } else {
            /* No clock: timeout_ms=0 stays non-blocking; else best-effort. */
            wait_ms = timeout_left;
        }

        /*
         * Blocking poll is forbidden once the call budget is exhausted.
         * wait_ms==0 is non-blocking and always allowed (including timeout_ms=0).
         * If budget expired after pre-pump and wait would be 0, still issue
         * one non-blocking poll unless we already know we should just timeout
         * without I/O wait — for timeout_ms>0 with expired budget, poll(0).
         */
        got = 0;
        rc = sys_poll(self, self->fd, want, &got, wait_ms);
        if (rc < 0) {
            int err = errno;
            if (err == EINTR) {
                eintr_retries += 1u;
                self->stats.eintr_count = ninlil_byte_stream_sat_add_u64(
                    self->stats.eintr_count, 1u);
                if (eintr_retries >= NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX) {
                    error_set(
                        self,
                        NINLIL_BYTE_STREAM_IO_ERROR,
                        NINLIL_BYTE_STREAM_STAGE_POLL,
                        EINTR,
                        "poll EINTR retry ceiling exhausted",
                        out_error);
                    if (out_events != NULL) {
                        *out_events = events;
                    }
                    return NINLIL_BYTE_STREAM_IO_ERROR;
                }
                if (budget_expired(self, deadline_ms) && wait_ms > 0) {
                    /* Do not re-enter blocking wait after budget expiry. */
                    self->stats.poll_timeout_count =
                        ninlil_byte_stream_sat_add_u64(
                            self->stats.poll_timeout_count, 1u);
                    events |= NINLIL_BYTE_STREAM_EVENT_TIMEOUT;
                    if (out_events != NULL) {
                        *out_events = events;
                    }
                    if (out_error != NULL) {
                        error_clear(out_error);
                    }
                    return NINLIL_BYTE_STREAM_OK;
                }
                continue;
            }
            /* docs/23 §3.2.2: EIO/ENODEV/ENXIO (unplug) → link down. */
            if (errno_is_link_down(err)) {
                mark_link_down(
                    self,
                    NINLIL_BYTE_STREAM_STAGE_POLL,
                    err,
                    "poll link-down errno (EIO/ENODEV/ENXIO)",
                    out_error);
                events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
                if (out_events != NULL) {
                    *out_events = events;
                }
                return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
            }
            error_set(
                self,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_POLL,
                err,
                "poll failed",
                out_error);
            if (out_events != NULL) {
                *out_events = events;
            }
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        if (rc == 0) {
            self->stats.poll_timeout_count = ninlil_byte_stream_sat_add_u64(
                self->stats.poll_timeout_count, 1u);
            events |= NINLIL_BYTE_STREAM_EVENT_TIMEOUT;
            if (self->rx_len > 0u) {
                events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
            }
            if (ring_free_tx(self) > 0u) {
                events |= NINLIL_BYTE_STREAM_EVENT_WRITABLE;
            }
            if (out_events != NULL) {
                *out_events = events;
            }
            if (out_error != NULL) {
                error_clear(out_error);
            }
            return NINLIL_BYTE_STREAM_OK;
        }
        break;
    }

    if ((got & POLLNVAL) != 0) {
        mark_link_down(
            self,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            0,
            "POLLNVAL maps to link down",
            out_error);
        events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
        if (out_events != NULL) {
            *out_events = events;
        }
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if ((got & POLLERR) != 0) {
        mark_link_down(
            self,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            0,
            "POLLERR maps to link down",
            out_error);
        events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
        if (out_events != NULL) {
            *out_events = events;
        }
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if ((got & POLLHUP) != 0) {
        self->saw_hup = 1;
    }

    if ((got & POLLOUT) != 0 || self->tx_len > 0u) {
        st = pump_tx(
            self, &events, out_error, deadline_ms, &eintr_retries);
        if (st != NINLIL_BYTE_STREAM_OK) {
            if (out_events != NULL) {
                *out_events = events;
            }
            return st;
        }
    }

    if ((got & (POLLIN | POLLHUP)) != 0) {
        st = pump_rx(
            self, got, &events, out_error, deadline_ms, &eintr_retries);
        if (st != NINLIL_BYTE_STREAM_OK) {
            if (out_events != NULL) {
                *out_events = events;
            }
            return st;
        }
    } else if (self->saw_hup) {
        st = pump_rx(
            self,
            got | POLLHUP,
            &events,
            out_error,
            deadline_ms,
            &eintr_retries);
        if (st != NINLIL_BYTE_STREAM_OK) {
            if (out_events != NULL) {
                *out_events = events;
            }
            return st;
        }
    }

    if (self->rx_len > 0u) {
        events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
    }
    if (ring_free_tx(self) > 0u) {
        events |= NINLIL_BYTE_STREAM_EVENT_WRITABLE;
    }
    if (self->rx_overflow_latched) {
        events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
    }

    if (out_events != NULL) {
        *out_events = events;
    }
    if (out_error != NULL
        && (events & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) == 0u) {
        error_clear(out_error);
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_link_t ninlil_posix_usb_serial_link(
    const ninlil_byte_stream_t *stream)
{
    const ninlil_posix_usb_serial_t *self = self_from_const(stream);

    if (self == NULL) {
        return NINLIL_BYTE_STREAM_LINK_CLOSED;
    }
    return self->link;
}

uint64_t ninlil_posix_usb_serial_link_generation(
    const ninlil_byte_stream_t *stream)
{
    const ninlil_posix_usb_serial_t *self = self_from_const(stream);

    if (self == NULL) {
        return 0u;
    }
    return self->link_generation;
}

void ninlil_posix_usb_serial_stats(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_stats_t *out_stats)
{
    const ninlil_posix_usb_serial_t *self = self_from_const(stream);

    if (out_stats == NULL) {
        return;
    }
    if (self == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = self->stats;
    out_stats->rx_ring_bytes = self->rx_len;
    out_stats->tx_ring_bytes = self->tx_len;
}

void ninlil_posix_usb_serial_last_error(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error)
{
    const ninlil_posix_usb_serial_t *self = self_from_const(stream);

    if (out_error == NULL) {
        return;
    }
    if (self == NULL) {
        error_clear(out_error);
        return;
    }
    *out_error = self->last_error;
}

static const ninlil_byte_stream_ops_t g_ops = {
    ninlil_posix_usb_serial_open,
    ninlil_posix_usb_serial_close,
    ninlil_posix_usb_serial_write,
    ninlil_posix_usb_serial_read,
    ninlil_posix_usb_serial_poll,
    ninlil_posix_usb_serial_link,
    ninlil_posix_usb_serial_link_generation,
    ninlil_posix_usb_serial_stats,
    ninlil_posix_usb_serial_last_error,
};

static const ninlil_byte_stream_ops_t *posix_usb_serial_ops(void)
{
    return &g_ops;
}
