#ifndef NINLIL_ESP_IDF_USB_CDC_H
#define NINLIL_ESP_IDF_USB_CDC_H

/*
 * A2: ESP32-S3 USB OTG Device CDC-ACM byte-stream adapter (production-private).
 *
 * Implements C1 (src/transport/byte_stream.h) under ports/esp-idf.
 * Uses pinned esp_tinyusb managed component. No public include/ninlil ABI.
 * No product-specific vocabulary. No TinyUSB types in the C1 header.
 *
 * Lifecycle (docs/23 §3.1 / §3.4 / C1):
 *   open(endpoint_token) → LINK_LISTENING (stack installed; generation sticky)
 *   host attach + DTR assert → LINK_UP (generation++; residual discard counted)
 *   host detach or DTR deassert → LINK_DOWN (residual RX drainable)
 *   host reconnect attach+DTR → LINK_UP (generation++; residual RX discarded
 *     with generation_rx_discard_bytes accounting — not silent)
 *   close (V1 logical park) → s_mux fence admit/epoch + s_live unpublish first
 *     → core inflight drain → s_io software FIFO clear → logical FREE park.
 *     Does NOT call tinyusb_cdcacm_deinit / tinyusb_driver_uninstall
 *     (esp_tinyusb 2.1.1 persistent service; upstream free/UAF risk).
 *     Success → CLOSED; USB service remains READY for reopen/bind.
 *     Failure → TEARDOWN_PENDING/POISONED; s_live stays NULL; same-owner retry.
 *
 * Persistent USB service (esp_tinyusb==2.1.1):
 *   Once READY, stack+CDC-ACM stay for firmware lifetime. Control CDC is sole
 *   owner; service is not transferred to other USB roles. Full USB shutdown
 *   / handoff is V1-unsupported. Service POISONED after partial init requires
 *   reboot (no safe uninstall path claimed).
 *   Unbound windows still bump physical_event_seq (ATTACH/DETACH/DTR).
 *   Post-bind reconcile: capture seq under lock → hardware snapshot outside →
 *   apply only if seq unchanged. Unbound/fenced RX: bounded TinyUSB FIFO
 *   drain/drop (never residual into next logical generation).
 *
 * init / reinit contract (caller-owned storage):
 *   - init does not install USB; prepares storage + C1 stream view only.
 *   - Wipe rejected (BUSY) if storage or out_stream half-open range overlaps
 *     live/reserved object range (overflow-safe). No raw content read.
 *   - After successful logical close, same storage may reinit; reopen binds
 *     to existing READY service.
 *
 * endpoint_token: empty/NULL or exact "control-cdc". Not a filesystem path.
 *
 * Ownership: successful open records owner FreeRTOS task. All C1 APIs are
 * single-owner. WRONG_OWNER is checked before out_accepted/out_length/out_events
 * mutation. Observers (link/generation/stats/last_error): wrong-owner fail-closed
 * sentinel (CLOSED/0) or leave caller out buffers unchanged (no stream mutation).
 *
 * Callback context (esp_tinyusb 2.1.1): CDC ACM and device-event callbacks run
 * in the TinyUSB service *task* context, not hard-ISR. Global portMUX serializes
 * s_live + callback admission; epoch is captured at try_enter (stale exclusion).
 * Never hold spinlock across driver APIs or vTaskDelay.
 *
 * Sticky/one-shot poll events: LINK_UP/LINK_DOWN/RX_OVERFLOW are latched once
 * and cleared when owner poll observes them (no permanent hot loop).
 * WRITABLE only while LINK_UP.
 *
 * Control CDC isolation: this adapter never installs esp_tusb_init_console
 * and never routes printf/ESP_LOG to the control CDC interface. Console stays
 * on the distinct UART path configured by the application.
 *
 * TinyUSB FIFO contract (esp_tinyusb 2.1.1 / device CDC):
 *   tud_cdc_n_write_clear / tud_cdc_n_read_flush clear software stream FIFOs
 *   only. They do not retract endpoint/hardware buffers already queued for
 *   USB transfer or already physically transmitted. U2 guarantees Ninlil ring
 *   generation isolation + best-effort software FIFO clear on DOWN; bytes
 *   already accepted by TinyUSB are non-custody. U3 MUST reject stale frames.
 *
 * Nonclaims:
 * - Not U2 complete (Required HIL flash + host CDC roundtrip + DTR old-gen
 *   negative pending).
 * - compile/link ≠ HIL. Not USB series complete. Not U3 session.
 * - Write accept is not Transport Custody / Application Receipt.
 * - Raw USB cannot recall bytes already physically transmitted.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Caller-owned fixed storage (allocation-free). Port-only ceiling; not public
 * Ninlil ABI. Holds 2×4096 rings + core state + small backend flags.
 */
#define NINLIL_ESP_IDF_USB_CDC_OBJECT_BYTES ((size_t)10240u)
#define NINLIL_ESP_IDF_USB_CDC_OBJECT_ALIGN ((size_t)8u)

/* Bounded nonblocking TX drain chunk per poll iteration. */
#define NINLIL_ESP_IDF_USB_CDC_TX_DRAIN_CHUNK ((uint32_t)512u)

typedef struct ninlil_esp_idf_usb_cdc_object {
    _Alignas(8) unsigned char bytes[NINLIL_ESP_IDF_USB_CDC_OBJECT_BYTES];
} ninlil_esp_idf_usb_cdc_object_t;

size_t ninlil_esp_idf_usb_cdc_object_size(void);
size_t ninlil_esp_idf_usb_cdc_object_align(void);

/*
 * Initialize caller storage and fill a portable C1 stream view.
 * Does not install USB.
 * Returns INVALID_ARGUMENT on null/misaligned/small.
 * Returns BUSY if this storage address currently holds the global CDC
 * reservation or is the live callback object (reinit would wipe live state).
 * On BUSY, storage and out_stream are left unmodified.
 * After successful logical close (bind released; USB service remains READY),
 * reinit of the same storage is OK.
 */
ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_init(
    void *storage,
    size_t storage_bytes,
    ninlil_byte_stream_t *out_stream);

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_init_object(
    ninlil_esp_idf_usb_cdc_object_t *object,
    ninlil_byte_stream_t *out_stream);

/* Typed C1 entry points (same contract as ops vtable). */
ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_open(
    ninlil_byte_stream_t *stream,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_close(
    ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_poll(
    ninlil_byte_stream_t *stream,
    uint32_t timeout_ms,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_link_t ninlil_esp_idf_usb_cdc_link(
    const ninlil_byte_stream_t *stream);

uint64_t ninlil_esp_idf_usb_cdc_link_generation(
    const ninlil_byte_stream_t *stream);

void ninlil_esp_idf_usb_cdc_stats(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_stats_t *out_stats);

void ninlil_esp_idf_usb_cdc_last_error(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error);

/*
 * Host-test-only pure core force helpers live under state_logic and are not
 * exposed here on target. No test-only macros in production target builds.
 */

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_USB_CDC_H */
