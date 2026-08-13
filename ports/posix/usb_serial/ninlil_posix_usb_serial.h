/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_POSIX_USB_SERIAL_PRIVATE_H
#define NINLIL_POSIX_USB_SERIAL_PRIVATE_H

/*
 * Private host-test additions for the public ADR-0031 adapter. Production
 * users include <ninlil/posix_usb_serial_v1.h>; this header is not installed.
 */
#include "ninlil/posix_usb_serial_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    int (*set_cloexec_fn)(int fd, void *user);
    int64_t (*now_ms_fn)(void *user);
    void *user;
} ninlil_posix_usb_serial_sys_ops_t;

ninlil_byte_stream_status_t ninlil_posix_usb_serial_set_sys_ops(
    ninlil_byte_stream_t *stream,
    const ninlil_posix_usb_serial_sys_ops_t *ops);

void ninlil_posix_usb_serial_test_force_generation(
    ninlil_byte_stream_t *stream,
    uint64_t generation);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_USB_SERIAL_PRIVATE_H */
