/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Ninlil POSIX USB/serial byte-stream reference port.
 *
 * Experimental 0.x Linux/macOS surface fixed by ADR-0031. The caller owns
 * the object and drives all progress; there is no hidden thread or automatic
 * reconnect. A successful raw write is not Transport Custody or an
 * Application Receipt.
 */
#ifndef NINLIL_POSIX_USB_SERIAL_V1_H
#define NINLIL_POSIX_USB_SERIAL_V1_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/byte_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES ((size_t)9216u)
#define NINLIL_POSIX_USB_SERIAL_OBJECT_ALIGN ((size_t)8u)
#define NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX ((uint32_t)64u)

#if defined(__cplusplus)
#define NINLIL_POSIX_USB_SERIAL_ALIGNAS(bytes_) alignas(bytes_)
#else
#define NINLIL_POSIX_USB_SERIAL_ALIGNAS(bytes_) _Alignas(bytes_)
#endif
typedef struct ninlil_posix_usb_serial_object {
    NINLIL_POSIX_USB_SERIAL_ALIGNAS(8)
    unsigned char bytes[NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES];
} ninlil_posix_usb_serial_object_t;
#undef NINLIL_POSIX_USB_SERIAL_ALIGNAS

size_t ninlil_posix_usb_serial_object_size(void);
size_t ninlil_posix_usb_serial_object_align(void);

/* Initialize caller storage and return a portable byte-stream view. */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_init(
    void *storage,
    size_t storage_bytes,
    ninlil_byte_stream_t *out_stream);

ninlil_byte_stream_status_t ninlil_posix_usb_serial_init_object(
    ninlil_posix_usb_serial_object_t *object,
    ninlil_byte_stream_t *out_stream);

/* endpoint_token must be an explicit absolute device path. */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_open(
    ninlil_byte_stream_t *stream,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error);

/* LINK_DOWN must be explicitly closed before a later open. */
ninlil_byte_stream_status_t ninlil_posix_usb_serial_close(
    ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_posix_usb_serial_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_posix_usb_serial_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error);

/* timeout_ms bounds blocking wait; all work remains caller-driven and finite. */
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

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_USB_SERIAL_V1_H */
