#ifndef NINLIL_POSIX_USB_SERIAL_H
#define NINLIL_POSIX_USB_SERIAL_H

/*
 * A1: POSIX controller USB/serial byte-stream adapter (production-private).
 *
 * Host Linux/macOS only. Implements C1 (src/transport/byte_stream.h) with
 * raw termios + poll, fixed 4 KiB RX/TX rings, explicit absolute path open.
 *
 * Placement: ports/posix (not public include/ninlil; not installed package).
 * Normative UX: docs/23 §3.2, ownership/rings §4, backpressure §6, U1 §10.1.
 *
 * Owner: successful open records owner process+thread for that link
 * generation. After open, every API on the stream (open/close/read/write/poll
 * *and* link/generation/stats/last_error) is single-owner-only; concurrent or
 * cross-thread calls are forbidden. There is no internal mutex and no atomic
 * multi-reader claim. open/close/read/write/poll enforce WRONG_OWNER while the
 * generation is active (LINK_UP or LINK_DOWN), including vs invalid args:
 * WRONG_OWNER fills only caller-owned out_error (STAGE_OWNER) and does not
 * write stream last_error/stats/rings/link/generation/path. Out payload
 * counts/events are left unchanged on WRONG_OWNER.
 * link/generation/stats/last_error keep observer signatures but are still not
 * safe cross-thread monitors — snapshot on the owner thread and hand off.
 * Reopen: open only from LINK_CLOSED with fd fenced. LINK_DOWN (even same
 * owner) is INVALID_STATE until explicit close clears residual RX. Explicit
 * close then a later successful open may establish a new owner (same or
 * different thread). Initial CLOSED open also establishes owner.
 *
 * Open flags (Linux/macOS): O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC when the
 * platform defines O_CLOEXEC (atomic close-on-exec). If O_CLOEXEC is absent at
 * compile time, open then fcntl(F_SETFD, FD_CLOEXEC); failure fences the fd
 * and returns structured open error (no silent continue).
 * Host-test-only: NINLIL_POSIX_USB_SERIAL_FORCE_FCNTL_CLOEXEC_FALLBACK forces
 * the fcntl path on modern platforms (separate private CMake target; not
 * installed / not public ABI / not ESP packaging).
 *
 * Nonclaims:
 * - Not U1 complete (Required HIL Linux+macOS physical USB CDC pending).
 * - Not USB series complete; not ESP CDC (A2); not NCG1/NCL1 session.
 * - Write accept is not Transport Custody / Application Receipt.
 * - No auto reconnect / no hidden pump thread.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Caller-owned fixed storage (allocation-free). Size/align are ABI for this
 * port only; not a public Ninlil ABI guarantee.
 *
 * Layout: 2×4096 rings + path + stats/error + platform state. Ceiling is
 * intentionally generous for LP64 padding; exact sizeof is not part of C1.
 */
#define NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES ((size_t)9216u)
#define NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN ((size_t)8u)

/* Poll/pump EINTR bound (deadline + explicit ceiling). */
#define NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX ((uint32_t)64u)

typedef struct ninlil_posix_usb_serial_object {
    _Alignas(8) unsigned char bytes[NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES];
} ninlil_posix_usb_serial_object_t;

/* Explicit size/align API (alternative to the fixed object typedef). */
size_t ninlil_posix_usb_serial_object_size(void);
size_t ninlil_posix_usb_serial_object_align(void);

/*
 * Initialize caller storage and fill a portable C1 stream view.
 * Does not open a device. Returns INVALID_ARGUMENT if storage is too small
 * or pointers are NULL / misaligned.
 */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_init(
    void *storage,
    size_t storage_bytes,
    ninlil_byte_stream_t *out_stream);

/*
 * Convenience: init using ninlil_posix_usb_serial_object_t.
 */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_init_object(
    ninlil_posix_usb_serial_object_t *object,
    ninlil_byte_stream_t *out_stream);

/*
 * Direct typed entry points (same contract as ops vtable). Prefer the C1
 * stream view for portable code.
 */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_open(
    ninlil_byte_stream_t *stream,
    const char *absolute_path,
    ninlil_byte_stream_error_t *out_error);

/*
 * Explicit close (owner thread). Owner check runs before any state change.
 * - Already CLOSED + fd fenced: idempotent OK.
 * - LINK_DOWN (fd already fenced after unplug): still transitions to CLOSED,
 *   clears RX/TX rings and latched overflow; does not re-sys-close. Required
 *   before any reopen so residual RX is not silently dropped by open.
 * - LINK_UP: fence-close fd then CLOSED + clear rings.
 * Subsequent read/write/poll return CLOSED (not residual RX / ERR_LINK_DOWN).
 *
 * close() system-call errors: fd is fenced without re-close on EINTR.
 */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_close(
    ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_posix_usb_serial_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error);

/*
 * Dequeue from the RX raw ring.
 * capacity == 0 → INVALID_ARGUMENT (UP or DOWN); never OK+0.
 * After LINK_DOWN: buffered RX first when capacity > 0 and ring non-empty
 * (OK + length > 0); empty ring → ERR_LINK_DOWN (not OK+0).
 */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error);

/*
 * Deterministic poll/pump. timeout_ms is the *blocking wait* budget only
 * (not a claim that the whole call finishes in that wall time). Call-entry
 * deadline stops further blocking wait and additional I/O/retry loops, but
 * ready/queued directions still get at least one nonblocking syscall for
 * finite progress (poll(0) must advance TX/RX). After deadline: wait_ms is 0
 * only (no blocking poll). Work is finite via rings/chunks/EINTR ceiling.
 */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_poll(
    ninlil_byte_stream_t *stream,
    uint32_t timeout_ms,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_link_t ninlil_posix_usb_serial_link(
    const ninlil_byte_stream_t *stream);

uint64_t ninlil_posix_usb_serial_link_generation(
    const ninlil_byte_stream_t *stream);

void ninlil_posix_usb_serial_stats(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_stats_t *out_stats);

void ninlil_posix_usb_serial_last_error(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error);

/*
 * Deterministic host-test syscall seam (platform types avoided).
 * poll want/got use POLLIN/POLLOUT/POLLERR/POLLHUP/POLLNVAL bit values as
 * host integers. Production leaves ops NULL (real POSIX). Not packaged.
 *
 * MUST NOT replace the seam while link is UP (active fd). Returns
 * INVALID_STATE and leaves ops unchanged if called on an active link.
 */
typedef struct ninlil_posix_usb_serial_sys_ops {
    int (*open_fn)(const char *path, int flags, void *user);
    int (*close_fn)(int fd, void *user);
    int (*read_fn)(int fd, void *buf, size_t n, void *user);
    int (*write_fn)(int fd, const void *buf, size_t n, void *user);
    int (*poll_fn)(
        int fd,
        int want_events,
        int *got_events,
        int timeout_ms,
        void *user);
    int (*tcgetattr_fn)(int fd, void *termios_out, void *user);
    int (*tcsetattr_fn)(int fd, int actions, const void *termios_in, void *user);
    int (*ioctl_fn)(int fd, unsigned long request, void *arg, void *user);
    /*
     * Optional: set FD_CLOEXEC on fd (return 0 / -1+errno). Used only on the
     * fcntl fallback path (no O_CLOEXEC, or host-test FORCE macro). Production
     * atomic O_CLOEXEC builds never call this setter.
     */
    int (*set_cloexec_fn)(int fd, void *user);
    /*
     * Optional deterministic clock for host tests (monotonic ms).
     * When NULL, production uses CLOCK_MONOTONIC. Injected clocks prove
     * poll() call-entry deadline covers pre/post pump work without sleeps.
     */
    int64_t (*now_ms_fn)(void *user);
    void *user;
} ninlil_posix_usb_serial_sys_ops_t;

ninlil_byte_stream_status_t ninlil_posix_usb_serial_set_sys_ops(
    ninlil_byte_stream_t *stream,
    const ninlil_posix_usb_serial_sys_ops_t *ops);

/*
 * Host-test hook only (not package surface): force link_generation for
 * fail-closed max-generation tests. Not a public ABI.
 */
void ninlil_posix_usb_serial_test_force_generation(
    ninlil_byte_stream_t *stream,
    uint64_t generation);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_USB_SERIAL_H */
