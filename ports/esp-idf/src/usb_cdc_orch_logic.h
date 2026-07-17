/*
 * Pure A2 USB CDC orchestration (host-testable; no ESP/FreeRTOS/TinyUSB headers).
 *
 * Design (esp_tinyusb ==2.1.1 evidence-based):
 * - USB stack + CDC-ACM object are a *firmware-lifetime service* once READY.
 * - V1 close is logical park only (never cdc_deinit / driver_uninstall while
 *   callbacks may still be pre-dispatched by upstream get_acm).
 * - Device event callback arg is storage-free; production loads s_live under lock.
 * - Logical bind is sole Control-CDC owner; service is not transferred to others.
 *
 * Service: ABSENT → STARTING → READY (persistent) | POISONED (no V1 recovery)
 * Logical: FREE → CLAIMING → BOUND → PARKING → FREE | POISONED
 */

#ifndef NINLIL_ESP_IDF_USB_CDC_ORCH_LOGIC_H
#define NINLIL_ESP_IDF_USB_CDC_ORCH_LOGIC_H

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"
#include "usb_cdc_state_logic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Address ranges (overflow-safe half-open [base, base+bytes)) -------- */

typedef struct ninlil_usb_cdc_addr_range {
    uint64_t base;
    uint64_t bytes;
} ninlil_usb_cdc_addr_range_t;

/* 1 if range is non-empty and base+bytes does not wrap in u64. */
int ninlil_usb_cdc_range_valid(const ninlil_usb_cdc_addr_range_t *r);

/*
 * 1 if range is valid in u64 and lies in address space [0, addr_max]
 * as half-open [base, base+bytes) with last byte <= addr_max.
 * Use addr_max=UINTPTR_MAX on production targets; UINT32_MAX for 32-bit models.
 */
int ninlil_usb_cdc_range_valid_in_space(
    const ninlil_usb_cdc_addr_range_t *r,
    uint64_t addr_max);

/* 1 if half-open intervals overlap. Invalid ranges → treat as overlap (fail-closed). */
int ninlil_usb_cdc_ranges_overlap(
    const ninlil_usb_cdc_addr_range_t *a,
    const ninlil_usb_cdc_addr_range_t *b);

/* ---- Global service + logical bind ------------------------------------ */

typedef uint32_t ninlil_usb_cdc_service_state_t;
#define NINLIL_USB_CDC_SVC_ABSENT ((ninlil_usb_cdc_service_state_t)0u)
#define NINLIL_USB_CDC_SVC_STARTING ((ninlil_usb_cdc_service_state_t)1u)
#define NINLIL_USB_CDC_SVC_READY ((ninlil_usb_cdc_service_state_t)2u)
#define NINLIL_USB_CDC_SVC_POISONED ((ninlil_usb_cdc_service_state_t)3u)

typedef uint32_t ninlil_usb_cdc_bind_state_t;
#define NINLIL_USB_CDC_BIND_FREE ((ninlil_usb_cdc_bind_state_t)0u)
#define NINLIL_USB_CDC_BIND_CLAIMING ((ninlil_usb_cdc_bind_state_t)1u)
#define NINLIL_USB_CDC_BIND_BOUND ((ninlil_usb_cdc_bind_state_t)2u)
#define NINLIL_USB_CDC_BIND_PARKING ((ninlil_usb_cdc_bind_state_t)3u)
#define NINLIL_USB_CDC_BIND_POISONED ((ninlil_usb_cdc_bind_state_t)4u)

/* Legacy aliases used by older tests (map to bind states). */
typedef uint32_t ninlil_usb_cdc_global_state_t;
#define NINLIL_USB_CDC_G_FREE NINLIL_USB_CDC_BIND_FREE
#define NINLIL_USB_CDC_G_INSTALLING NINLIL_USB_CDC_BIND_CLAIMING
#define NINLIL_USB_CDC_G_ACTIVE NINLIL_USB_CDC_BIND_BOUND
#define NINLIL_USB_CDC_G_TEARING NINLIL_USB_CDC_BIND_PARKING
#define NINLIL_USB_CDC_G_POISONED NINLIL_USB_CDC_BIND_POISONED

typedef struct ninlil_usb_cdc_global_res {
    ninlil_usb_cdc_service_state_t service;
    ninlil_usb_cdc_bind_state_t state; /* logical bind */
    uint64_t reserved_id;
    /* Live bound object storage range (0 bytes if unbound). */
    ninlil_usb_cdc_addr_range_t live_storage;
    /* Monotonic physical event sequence under production s_mux. */
    uint64_t physical_event_seq;
} ninlil_usb_cdc_global_res_t;

void ninlil_usb_cdc_global_init(ninlil_usb_cdc_global_res_t *g);

int ninlil_usb_cdc_global_try_begin_install(
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id);

void ninlil_usb_cdc_global_mark_active(
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id);

int ninlil_usb_cdc_global_try_begin_teardown(
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id);

void ninlil_usb_cdc_global_teardown_success(ninlil_usb_cdc_global_res_t *g);

void ninlil_usb_cdc_global_teardown_fail(ninlil_usb_cdc_global_res_t *g);

void ninlil_usb_cdc_global_install_abort(ninlil_usb_cdc_global_res_t *g);

void ninlil_usb_cdc_global_set_live_storage(
    ninlil_usb_cdc_global_res_t *g,
    const ninlil_usb_cdc_addr_range_t *storage);

void ninlil_usb_cdc_global_clear_live_storage(ninlil_usb_cdc_global_res_t *g);

uint64_t ninlil_usb_cdc_global_bump_physical_seq(ninlil_usb_cdc_global_res_t *g);

/*
 * Snapshot reconcile: apply only if seq still matches (no intervening callback).
 * Production order: capture seq under lock → unlock → hardware snapshot →
 * relock → apply iff seq unchanged. Returns 1 if applied, 0 if stale.
 */
int ninlil_usb_cdc_reconcile_physical_if_seq(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_global_res_t *g,
    uint64_t captured_seq,
    uint32_t captured_epoch,
    int usb_attached,
    int dtr_asserted);

/*
 * Host-test model for RX path decision (persistent service):
 * Returns 1 if bytes should enter Ninlil ring; 0 if drop (unbound or fenced).
 */
int ninlil_usb_cdc_rx_should_ingress(int live_bound, int admit_entered);

/*
 * Host-test model for unbound physical events:
 * Always bump seq when a physical ATTACH/DETACH/DTR event is observed,
 * even if no logical adapter is bound (live_bound==0).
 * Returns new seq (0 if g NULL).
 */
uint64_t ninlil_usb_cdc_note_physical_event(
    ninlil_usb_cdc_global_res_t *g,
    int live_bound);

/*
 * Host pure bind/I-O protocol model (P0 close/rebind/unbound interleave).
 *
 * Production invariants modeled here (not a substitute for HIL):
 * - Firmware-lifetime I/O mutex serializes TinyUSB software FIFO ops.
 * - Never hold state_lock (s_mux model) while taking I/O or calling FIFO ops.
 * - Open: service ensure without live publish; I/O lock → flush → state
 *   publish s_live (flush-before-publish).
 * - Close: state fence + unpublish first; then inflight drain; then I/O
 *   quiesce/soft flush; then FREE.
 * - RX callback: I/O lock first → state admit → FIFO read under I/O only →
 *   state apply/leave → I/O unlock. Unbound/fenced → drop, no ring ingress.
 */
typedef struct ninlil_usb_cdc_bind_io_protocol {
    int live_published; /* abstract s_live == current owner */
    int service_ready;
    int callback_admit;
    int io_locked;
    int state_locked;
    uint32_t fifo_bytes; /* TinyUSB software RX FIFO abstract */
    uint32_t ring_bytes; /* Ninlil RX ring abstract */
    uint32_t generation; /* increments on each successful publish */
    uint32_t inflight; /* abstract callback_inflight */
    /* Violation / outcome counters for host tests */
    uint32_t io_ops_while_state_held; /* must remain 0 */
    uint32_t rx_ingress_count;
    uint32_t rx_drop_count;
    uint32_t soft_flush_count;
    uint32_t publish_count;
    uint32_t unpublish_count;
    int last_rx_ingressed_gen; /* generation that received last ingress, or -1 */
    int fault; /* sticky protocol fault */
} ninlil_usb_cdc_bind_io_protocol_t;

void ninlil_usb_cdc_bind_io_protocol_init(ninlil_usb_cdc_bind_io_protocol_t *p);

/* Returns 0 on success, -1 on protocol fault. */
int ninlil_usb_cdc_proto_state_enter(ninlil_usb_cdc_bind_io_protocol_t *p);
int ninlil_usb_cdc_proto_state_leave(ninlil_usb_cdc_bind_io_protocol_t *p);
int ninlil_usb_cdc_proto_io_enter(ninlil_usb_cdc_bind_io_protocol_t *p);
int ninlil_usb_cdc_proto_io_leave(ninlil_usb_cdc_bind_io_protocol_t *p);

/* Soft FIFO clear/flush; requires io_locked; forbids state_locked. */
int ninlil_usb_cdc_proto_soft_flush_fifo(ninlil_usb_cdc_bind_io_protocol_t *p);

/* Host injects bytes into abstract TinyUSB RX FIFO (no locks required). */
void ninlil_usb_cdc_proto_fifo_inject(
    ninlil_usb_cdc_bind_io_protocol_t *p,
    uint32_t n);

/*
 * Open path (after claim/core LIVE abstract):
 * service ready may already be true; does NOT publish live.
 */
int ninlil_usb_cdc_proto_open_service_ready(
    ninlil_usb_cdc_bind_io_protocol_t *p);

/*
 * Flush-before-publish: must hold neither lock on entry.
 * Takes I/O → flush → state publish live+admit → leave both.
 */
int ninlil_usb_cdc_proto_open_flush_and_publish(
    ninlil_usb_cdc_bind_io_protocol_t *p);

/*
 * Close: fence+unpublish under state first (no I/O while state held).
 * Does not soft-flush yet.
 */
int ninlil_usb_cdc_proto_close_fence_unpublish(
    ninlil_usb_cdc_bind_io_protocol_t *p);

/*
 * After unpublish + inflight==0: I/O soft flush then abstract FREE.
 */
int ninlil_usb_cdc_proto_close_quiesce_flush_free(
    ninlil_usb_cdc_bind_io_protocol_t *p);

/*
 * RX callback protocol. On entry holds no locks.
 * I/O first → state admit decision → read/drop under I/O → apply under state.
 * Returns 1 if ingressed, 0 if dropped, -1 on fault.
 */
int ninlil_usb_cdc_proto_rx_callback(ninlil_usb_cdc_bind_io_protocol_t *p);

/* Abstract TX software-FIFO op (queue/flush): I/O only, never under state. */
int ninlil_usb_cdc_proto_tx_fifo_op(ninlil_usb_cdc_bind_io_protocol_t *p);

/* ---- Driver ops ------------------------------------------------------- */

/*
 * Driver ops. state_lock/unlock protect core/global only (depth 1).
 * Driver APIs must run at lock depth 0.
 * V1 persistent service: cdc_deinit/driver_uninstall unused on success close.
 */
typedef struct ninlil_usb_cdc_driver_ops {
    int (*driver_install)(void *user);
    int (*cdc_init)(void *user);
    int (*cdc_deinit)(void *user); /* unused on V1 park success path */
    int (*driver_uninstall)(void *user); /* unused on V1 park success path */
    uint32_t (*tx_queue)(void *user, const uint8_t *data, uint32_t n);
    void (*tx_fifo_soft_clear)(void *user);
    void (*rx_fifo_soft_flush)(void *user);
    void (*state_lock)(void *user);
    void (*state_unlock)(void *user);
    int (*wait_callbacks_drained)(void *user);
    /* Optional: snapshot tud_mounted/dtr into out_* (production). */
    void (*physical_snapshot)(void *user, int *out_attached, int *out_dtr);
    void *user;
} ninlil_usb_cdc_driver_ops_t;

/* ---- TX ticket -------------------------------------------------------- */

typedef struct ninlil_usb_cdc_tx_ticket {
    uint32_t n;
    uint64_t link_generation;
    uint32_t callback_epoch;
    int valid;
} ninlil_usb_cdc_tx_ticket_t;

uint32_t ninlil_usb_cdc_core_tx_drain_begin(
    ninlil_usb_cdc_core_t *core,
    uint8_t *out,
    uint32_t max_bytes,
    ninlil_usb_cdc_tx_ticket_t *ticket);

int ninlil_usb_cdc_core_tx_drain_finish(
    ninlil_usb_cdc_core_t *core,
    const ninlil_usb_cdc_tx_ticket_t *ticket,
    uint32_t queued_by_driver);

/* ---- Open preflight (nonmutating) ------------------------------------ */

/*
 * Nonmutating open preflight under caller's lock.
 * WRONG_OWNER / INVALID_STATE / OK. Does not claim global or mutate core.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_open_preflight(
    const ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error);

/* ---- Install / park --------------------------------------------------- */

/*
 * Ensure service READY + bind this id.
 * - ABSENT: driver_install + cdc_init (partial fail may poison service)
 * - READY: bind only
 * Never deinit/uninstall on success path.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_orch_install(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id,
    uint64_t owner_id,
    const ninlil_usb_cdc_driver_ops_t *ops,
    ninlil_byte_stream_error_t *out_error);

/*
 * Logical park (V1 close success path). NO cdc_deinit / driver_uninstall.
 * Hard gate: reserved_id==id && PARKING. Soft-clear FIFOs if ops provide.
 * Success → core CLOSED via apply, bind FREE, service remains READY.
 */
ninlil_byte_stream_status_t ninlil_usb_cdc_orch_teardown(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id,
    uint64_t owner_id,
    int callbacks_drained,
    const ninlil_usb_cdc_driver_ops_t *ops,
    ninlil_byte_stream_error_t *out_error);

/* ---- Init wipe / closed-idle ------------------------------------------ */

int ninlil_usb_cdc_closed_idle_close_policy(
    const ninlil_usb_cdc_core_t *core,
    const ninlil_usb_cdc_global_res_t *g,
    uint64_t id);

/*
 * Init claim: reject if storage or out_stream overlaps live/reserved object
 * range. Address math only; never reads storage contents.
 * Returns 1 allow wipe+write, 0 reject.
 */
int ninlil_usb_cdc_init_storage_may_wipe(
    uint64_t storage_id,
    const ninlil_usb_cdc_global_res_t *g,
    uint64_t live_id);

int ninlil_usb_cdc_init_ranges_may_claim(
    const ninlil_usb_cdc_addr_range_t *storage,
    const ninlil_usb_cdc_addr_range_t *out_stream,
    const ninlil_usb_cdc_global_res_t *g,
    const ninlil_usb_cdc_addr_range_t *live_storage);

/* Same as init_ranges_may_claim but with explicit address-space ceiling. */
int ninlil_usb_cdc_init_ranges_may_claim_in_space(
    const ninlil_usb_cdc_addr_range_t *storage,
    const ninlil_usb_cdc_addr_range_t *out_stream,
    const ninlil_usb_cdc_global_res_t *g,
    const ninlil_usb_cdc_addr_range_t *live_storage,
    uint64_t addr_max);

/* ---- Once-init -------------------------------------------------------- */

typedef uint32_t ninlil_usb_cdc_once_state_t;
#define NINLIL_USB_CDC_ONCE_FREE ((ninlil_usb_cdc_once_state_t)0u)
#define NINLIL_USB_CDC_ONCE_CREATING ((ninlil_usb_cdc_once_state_t)1u)
#define NINLIL_USB_CDC_ONCE_READY ((ninlil_usb_cdc_once_state_t)2u)

typedef struct ninlil_usb_cdc_once {
    ninlil_usb_cdc_once_state_t state;
    void *handle;
} ninlil_usb_cdc_once_t;

void ninlil_usb_cdc_once_init(ninlil_usb_cdc_once_t *o);
int ninlil_usb_cdc_once_claim_create(ninlil_usb_cdc_once_t *o);
void ninlil_usb_cdc_once_mark_ready(ninlil_usb_cdc_once_t *o, void *handle);
void ninlil_usb_cdc_once_mark_failed(ninlil_usb_cdc_once_t *o);

/* ---- Callback soft-clear ordering ------------------------------------- */

typedef struct ninlil_usb_cdc_cb_soft_work {
    int active;
    int need_soft_clear;
    int soft_clear_done;
    int left;
} ninlil_usb_cdc_cb_soft_work_t;

void ninlil_usb_cdc_cb_soft_work_reset(ninlil_usb_cdc_cb_soft_work_t *w);
void ninlil_usb_cdc_cb_soft_work_enter(
    ninlil_usb_cdc_cb_soft_work_t *w,
    int need_soft_clear);
void ninlil_usb_cdc_cb_soft_work_mark_soft_clear_done(
    ninlil_usb_cdc_cb_soft_work_t *w);
int ninlil_usb_cdc_cb_soft_work_may_leave(
    const ninlil_usb_cdc_cb_soft_work_t *w);
int ninlil_usb_cdc_cb_soft_work_leave(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_cb_soft_work_t *w);

/* ---- Poll helpers ----------------------------------------------------- */

ninlil_byte_stream_status_t ninlil_usb_cdc_poll_owner_before_tx(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    uint32_t (*tx_queue)(void *user, const uint8_t *data, uint32_t n),
    void *tx_user,
    const uint8_t *peek_data,
    uint32_t peek_n,
    uint32_t *out_queued,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error);

/*
 * Overflow-safe required tick budget for timeout_ms.
 * timeout_ms==0 → 0 (nonblocking).
 * ms_per_tick==0 treated as 1. Ceil division; min 1 tick if timeout_ms>0.
 * Prefer poll_required_ticks_hz for FreeRTOS (arbitrary configTICK_RATE_HZ).
 */
uint64_t ninlil_usb_cdc_poll_required_ticks(
    uint32_t timeout_ms,
    uint32_t ms_per_tick);

/*
 * Overflow-safe ceil ticks: ceil(timeout_ms * tick_rate_hz / 1000).
 * timeout_ms==0 → 0. tick_rate_hz==0 treated as 1. Min 1 tick if timeout_ms>0.
 * Matches FreeRTOS configTICK_RATE_HZ (not portTICK_PERIOD_MS integer divide).
 */
uint64_t ninlil_usb_cdc_poll_required_ticks_hz(
    uint32_t timeout_ms,
    uint32_t tick_rate_hz);

/*
 * Unsigned elapsed accumulation: add (now-last) as uint32 modular delta into
 * *inout_elapsed_u64. Returns 1 if elapsed >= budget.
 */
int ninlil_usb_cdc_poll_elapsed_reached(
    uint64_t *inout_elapsed_u64,
    uint32_t last_tick,
    uint32_t now_tick,
    uint64_t budget_ticks);

/*
 * Pure poll deadline decision model (C1-aligned):
 * - call-entry tick is the deadline baseline (includes initial pump time)
 * - initial nonblocking I/O is always allowed once
 * - after a blocking wait, extra I/O is allowed only if elapsed < budget
 */
typedef struct ninlil_usb_cdc_poll_deadline {
    uint64_t budget_ticks;
    uint64_t elapsed;
    uint32_t last_tick;
    uint32_t io_ops; /* nonblocking TX drain / pump count */
    int entry_captured;
} ninlil_usb_cdc_poll_deadline_t;

void ninlil_usb_cdc_poll_deadline_init(
    ninlil_usb_cdc_poll_deadline_t *d,
    uint64_t budget_ticks,
    uint32_t entry_tick);

/* Always allowed (C1 first nonblocking progress). Charges entry→now. */
int ninlil_usb_cdc_poll_deadline_initial_io(
    ninlil_usb_cdc_poll_deadline_t *d,
    uint32_t now_tick);

/*
 * After a delay slice ending at now_tick: charge elapsed; return 1 if more
 * nonblocking I/O is still allowed, 0 if deadline hit (no extra I/O).
 */
int ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(
    ninlil_usb_cdc_poll_deadline_t *d,
    uint32_t now_tick);

/* Record one extra I/O only after may_extra returned 1. */
void ninlil_usb_cdc_poll_deadline_note_extra_io(
    ninlil_usb_cdc_poll_deadline_t *d);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_USB_CDC_ORCH_LOGIC_H */
