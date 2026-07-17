/*
 * Pure A2 CDC adapter state machine (host-testable).
 *
 * No FreeRTOS / TinyUSB / ESP types. Deterministic physical attach/DTR,
 * callback admission/epoch capture, teardown-pending fail-closed lifecycle.
 *
 * Physical link-up (generation advances) requires BOTH:
 *   usb_attached && dtr_asserted
 * Loss of either from UP → DOWN (residual RX drainable until generation UP).
 * RX overflow is continuity loss (latched), not physical DOWN.
 * Reconnect UP clears residual RX with generation_rx_discard_bytes accounting
 * (never silent).
 */

#ifndef NINLIL_ESP_IDF_USB_CDC_STATE_LOGIC_H
#define NINLIL_ESP_IDF_USB_CDC_STATE_LOGIC_H

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"
#include "usb_cdc_ring_logic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_CDC_ENDPOINT_TOKEN "control-cdc"
#define NINLIL_ESP_CDC_ENDPOINT_TOKEN_LEN ((size_t)11u)

/* Bounded wait quanta for pure/host models of inflight drain (backend maps). */
#define NINLIL_ESP_CDC_INFLIGHT_WAIT_SLICES_MAX ((uint32_t)64u)

/*
 * Driver ownership / teardown lifecycle (orthogonal to C1 link).
 * TEARDOWN_PENDING: fail-closed poison; reopen rejected; same owner may retry
 * close; storage not reusable until CLOSED with driver fully released.
 */
typedef uint32_t ninlil_usb_cdc_lifecycle_t;
#define NINLIL_USB_CDC_LC_CLOSED ((ninlil_usb_cdc_lifecycle_t)0u)
#define NINLIL_USB_CDC_LC_LIVE ((ninlil_usb_cdc_lifecycle_t)1u)
#define NINLIL_USB_CDC_LC_TEARDOWN_PENDING ((ninlil_usb_cdc_lifecycle_t)2u)

typedef struct ninlil_usb_cdc_core {
    ninlil_byte_stream_link_t link;
    ninlil_usb_cdc_lifecycle_t lifecycle;
    uint64_t link_generation;
    uint32_t callback_epoch;
    int owner_set;
    uint64_t owner_id;
    int usb_attached;
    int dtr_asserted;
    int rx_overflow_latched;
    /* One-shot event latches: set on transition, cleared when poll observes. */
    int rx_overflow_event_pending;
    int link_down_event_pending;
    int link_up_event_pending;

    /* Callback admission fence (pure model of shared lock discipline). */
    int callback_admit; /* 1 = new callbacks may enter */
    uint32_t callback_inflight;

    int stack_installed; /* driver still owns USB stack/PHY */
    int cdc_inited; /* CDC class still inited */
    int partial_init_stage; /* 0=none, 1=stack, 2=cdc, 3=ready */

    uint8_t rx_storage[NINLIL_BYTE_STREAM_RING_BYTES];
    uint8_t tx_storage[NINLIL_BYTE_STREAM_RING_BYTES];
    ninlil_usb_cdc_ring_t rx;
    ninlil_usb_cdc_ring_t tx;

    ninlil_byte_stream_stats_t stats;
    ninlil_byte_stream_error_t last_error;
    ninlil_byte_stream_error_t first_teardown_error; /* sticky first failure */
    int has_first_teardown_error;
    char endpoint[NINLIL_BYTE_STREAM_ENDPOINT_BYTES];
} ninlil_usb_cdc_core_t;

void ninlil_usb_cdc_core_init(ninlil_usb_cdc_core_t *core);

int ninlil_usb_cdc_endpoint_token_ok(const char *endpoint_token);

int ninlil_usb_cdc_core_check_owner(
    const ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    ninlil_byte_stream_error_t *out_error);

/*
 * Open only from lifecycle CLOSED (not TEARDOWN_PENDING).
 * Success → LISTENING + LIVE, owner set, admit=1, epoch advanced.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_core_open(
    ninlil_usb_cdc_core_t *core,
    const char *endpoint_token,
    uint64_t owner_id,
    ninlil_byte_stream_error_t *out_error);

/*
 * Begin close fence (owner only): stop callback admission, advance epoch
 * (fail-closed on wrap), set TEARDOWN_PENDING if driver still owned.
 * Does NOT release owner or clear driver flags.
 * Already CLOSED + no driver → OK idempotent.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_core_begin_close_fence(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    ninlil_byte_stream_error_t *out_error);

/* 1 if inflight == 0 (safe to call driver deinit/uninstall). */
int ninlil_usb_cdc_core_callbacks_drained(const ninlil_usb_cdc_core_t *core);

/*
 * Apply teardown driver results. Only clears cdc/stack ownership bits on
 * confirmed success of that step. Full success → CLOSED + owner released.
 * Any failure → remains TEARDOWN_PENDING, preserves first error, no reopen.
 *
 * cdc_deinit_status: 0=ok/skipped, non-zero=fail
 * uninstall_status: 0=ok/skipped, non-zero=fail
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_core_apply_teardown_result(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    int had_cdc,
    int cdc_deinit_status,
    int had_driver,
    int uninstall_status,
    ninlil_byte_stream_error_t *out_error);

/* Partial-init: mark stack/cdc installed flags (backend after successful steps). */
void ninlil_usb_cdc_core_set_partial_stage(ninlil_usb_cdc_core_t *core, int stage);
void ninlil_usb_cdc_core_mark_stack_installed(ninlil_usb_cdc_core_t *core, int on);
void ninlil_usb_cdc_core_mark_cdc_inited(ninlil_usb_cdc_core_t *core, int on);

/*
 * Callback admission under shared discipline:
 * Returns 1 and captures epoch at admission if admit allowed.
 * Caller must later call release (even if work dropped).
 */
int ninlil_usb_cdc_core_callback_try_enter(
    ninlil_usb_cdc_core_t *core,
    uint32_t *out_captured_epoch);

void ninlil_usb_cdc_core_callback_leave(ninlil_usb_cdc_core_t *core);

/*
 * Physical attach/DTR with *captured* epoch from try_enter (not re-read).
 * Gen exhaustion → safe non-UP fault (DOWN + facts cleared for UP path).
 */
ninlil_byte_stream_event_t ninlil_usb_cdc_core_apply_physical(
    ninlil_usb_cdc_core_t *core,
    uint32_t captured_epoch,
    int usb_attached,
    int dtr_asserted);

/*
 * RX ingress with captured epoch. Stale epoch → drop.
 * Full ring → latch overflow (not link down).
 */
uint32_t ninlil_usb_cdc_core_rx_ingress(
    ninlil_usb_cdc_core_t *core,
    uint32_t captured_epoch,
    const uint8_t *data,
    uint32_t length,
    ninlil_byte_stream_event_t *out_events);

/*
 * write/read: WRONG_OWNER checked before any out_* mutation.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_core_write(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error);

ninlil_byte_stream_status_t ninlil_usb_cdc_core_read(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error);

/*
 * Collect one-shot pending events + current ring/link facts for poll.
 * Clears one-shot latches (RX_OVERFLOW/LINK_DOWN/LINK_UP event pending).
 * WRITABLE only when UP and TX free > 0.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_core_poll_snapshot(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error);

/* Legacy peek (no ticket). Prefer orch tx_drain_begin/finish. */
uint32_t ninlil_usb_cdc_core_tx_drain_peek(
    ninlil_usb_cdc_core_t *core,
    uint8_t *out,
    uint32_t max_bytes);

void ninlil_usb_cdc_core_tx_drain_commit(
    ninlil_usb_cdc_core_t *core,
    uint32_t accepted_by_driver);

/*
 * Observers (pure): wrong owner → *out_ok=0, no mutation of out buffers
 * when pointers provided; caller applies sentinel policy.
 */
int ninlil_usb_cdc_core_observer_allowed(
    const ninlil_usb_cdc_core_t *core,
    uint64_t caller_id);

ninlil_byte_stream_link_t ninlil_usb_cdc_core_link_get(
    const ninlil_usb_cdc_core_t *core);

uint64_t ninlil_usb_cdc_core_generation_get(
    const ninlil_usb_cdc_core_t *core);

void ninlil_usb_cdc_core_stats_copy(
    const ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_stats_t *out_stats);

void ninlil_usb_cdc_core_last_error_copy(
    const ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_error_t *out_error);

int ninlil_usb_cdc_core_generation_can_advance(
    const ninlil_usb_cdc_core_t *core);

/* Host-test hooks. */
void ninlil_usb_cdc_core_test_force_generation(
    ninlil_usb_cdc_core_t *core,
    uint64_t generation);

void ninlil_usb_cdc_core_test_force_epoch(
    ninlil_usb_cdc_core_t *core,
    uint32_t epoch);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_USB_CDC_STATE_LOGIC_H */
