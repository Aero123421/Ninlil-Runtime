#ifndef NINLIL_TRANSPORT_C4_LAB_USB_PATH_H
#define NINLIL_TRANSPORT_C4_LAB_USB_PATH_H

/*
 * C4-LAB USB Controller/Cell Agent software path (V1 item 9).
 *
 * Composes U1–U4 (byte_stream + control_session + logical_session) with
 * V1-LAB U5 assignment state, U6 transport custody ownership, U7 diagnostics.
 * Host simulation only — physical USB HAL / HIL are out of scope.
 *
 * Normative: docs/23-usb-radio-boundary.md, docs/25 (U5), docs/26 (U6)
 * Not public include/ninlil. Not USB series complete / not HIL.
 *
 * SEMANTIC: C4_LAB_HOST_SIM_ONLY
 * SEMANTIC: U6_MAX_PAYLOAD_926
 */

#include "byte_stream.h"
#include "logical_session.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_C4_LAB_USB_OBJECT_BYTES ((size_t)32768u)
#define NINLIL_C4_LAB_USB_MAX_PAYLOAD_BYTES ((uint32_t)926u)
#define NINLIL_C4_LAB_USB_WIRE_MAGIC0 ((uint8_t)'C')
#define NINLIL_C4_LAB_USB_WIRE_MAGIC1 ((uint8_t)'4')
#define NINLIL_C4_LAB_USB_WIRE_MAGIC2 ((uint8_t)'L')
#define NINLIL_C4_LAB_USB_WIRE_MAGIC3 ((uint8_t)'B')

typedef uint32_t ninlil_c4_lab_usb_status_t;

#define NINLIL_C4_LAB_USB_OK ((ninlil_c4_lab_usb_status_t)0u)
#define NINLIL_C4_LAB_USB_INVALID_ARGUMENT ((ninlil_c4_lab_usb_status_t)1u)
#define NINLIL_C4_LAB_USB_INVALID_STATE ((ninlil_c4_lab_usb_status_t)2u)
#define NINLIL_C4_LAB_USB_WOULD_BLOCK ((ninlil_c4_lab_usb_status_t)3u)
#define NINLIL_C4_LAB_USB_IO_ERROR ((ninlil_c4_lab_usb_status_t)4u)
#define NINLIL_C4_LAB_USB_BAD_FRAME ((ninlil_c4_lab_usb_status_t)5u)
#define NINLIL_C4_LAB_USB_OWNERSHIP ((ninlil_c4_lab_usb_status_t)6u)
#define NINLIL_C4_LAB_USB_CAPACITY ((ninlil_c4_lab_usb_status_t)7u)

typedef enum ninlil_c4_lab_usb_link_state {
    NINLIL_C4_LAB_USB_LINK_DISCONNECTED = 0,
    NINLIL_C4_LAB_USB_LINK_UP = 1,
    NINLIL_C4_LAB_USB_SESSION_ACTIVE = 2,
    NINLIL_C4_LAB_USB_CUSTODY_READY = 3
} ninlil_c4_lab_usb_link_state_t;

typedef struct ninlil_c4_lab_usb_diag {
    uint64_t hello_sent;
    uint64_t hello_ack_ok;
    uint64_t hello_recovery;
    uint64_t custody_offer;
    uint64_t custody_accept;
    uint64_t custody_payload;
    uint64_t bad_frame;
    uint64_t ownership_violation;
    uint32_t assignment_epoch;
    uint16_t control_version;
    uint16_t reserved_zero;
} ninlil_c4_lab_usb_diag_t;

typedef struct ninlil_c4_lab_usb_config {
    ninlil_logical_session_role_t role;
    ninlil_logical_session_cookie_rng_fn cookie_rng;
    void *cookie_rng_ctx;
    ninlil_logical_session_jitter_fn jitter_fn;
    void *jitter_ctx;
    uint32_t owner_token;
} ninlil_c4_lab_usb_config_t;

#if defined(__cplusplus)
#define NINLIL_C4_LAB_USB_ALIGNAS(value) alignas(value)
#else
#define NINLIL_C4_LAB_USB_ALIGNAS(value) _Alignas(value)
#endif

typedef struct ninlil_c4_lab_usb_object {
    NINLIL_C4_LAB_USB_ALIGNAS(NINLIL_LOGICAL_SESSION_OBJECT_ALIGN)
    uint8_t storage[NINLIL_C4_LAB_USB_OBJECT_BYTES];
} ninlil_c4_lab_usb_object_t;

typedef struct ninlil_c4_lab_usb ninlil_c4_lab_usb_t;

#define NINLIL_C4_LAB_USB_OBJECT_INIT {{0}}

#undef NINLIL_C4_LAB_USB_ALIGNAS

size_t ninlil_c4_lab_usb_object_size(void);

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_init_object(
    ninlil_c4_lab_usb_object_t *object,
    const ninlil_c4_lab_usb_config_t *config,
    ninlil_c4_lab_usb_t **out_path);

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_bind(
    ninlil_c4_lab_usb_t *path,
    ninlil_byte_stream_t *stream);

/*
 * Host-simulation peer link for U6 custody (does not share NCL1 byte stream).
 */
ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_bind_peer(
    ninlil_c4_lab_usb_t *path,
    ninlil_c4_lab_usb_t *peer);

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_step(
    ninlil_c4_lab_usb_t *path,
    uint64_t now_monotonic_ms,
    uint32_t timeout_ms);

ninlil_c4_lab_usb_link_state_t ninlil_c4_lab_usb_link_state(
    const ninlil_c4_lab_usb_t *path);

int ninlil_c4_lab_usb_session_active(const ninlil_c4_lab_usb_t *path);

/*
 * U6 custody: sender offers payload ownership. Receiver must accept before
 * payload bytes are released to the peer. Max 926 bytes (V1 admission).
 */
ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_custody_offer(
    ninlil_c4_lab_usb_t *path,
    uint32_t ownership_token,
    const uint8_t *payload,
    uint32_t payload_len);

ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_custody_accept(
    ninlil_c4_lab_usb_t *path,
    uint32_t ownership_token,
    uint8_t *out_payload,
    uint32_t out_capacity,
    uint32_t *out_payload_len);

/*
 * HELLO recovery: force controller re-HELLO after session fence (host sim).
 */
ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_recover_hello(
    ninlil_c4_lab_usb_t *path);

void ninlil_c4_lab_usb_diag_snapshot(
    const ninlil_c4_lab_usb_t *path,
    ninlil_c4_lab_usb_diag_t *out_diag);

/*
 * Host-simulation RX inject for bad-frame tests (bypasses NCL1 byte stream).
 */
ninlil_c4_lab_usb_status_t ninlil_c4_lab_usb_inject_wire_rx(
    ninlil_c4_lab_usb_t *path,
    const uint8_t *data,
    uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_C4_LAB_USB_PATH_H */
