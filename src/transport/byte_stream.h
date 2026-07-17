#ifndef NINLIL_TRANSPORT_BYTE_STREAM_H
#define NINLIL_TRANSPORT_BYTE_STREAM_H

/*
 * C1: Portable byte-stream contract (production-private; not public ABI).
 *
 * Abstract open/read/write/close/poll surface for USB control transport
 * adapters (A1 POSIX, A2 ESP CDC). Platform types (fd, termios, pthread,
 * TinyUSB handles) MUST NOT appear in this header.
 *
 * Normative ownership / rings / backpressure / reconnect:
 *   docs/23-usb-radio-boundary.md §2, §3.1–§3.2, §4, §6, §10.1
 *   docs/adr/0003-radio-usb-dependency-direction.md
 *
 * Endpoint token (open argument):
 *   Adapter-neutral opaque UTF-8 selector — NOT a portable filesystem claim.
 *   A1 interprets it as an absolute device path (required form for A1).
 *   A2 interprets it as a fixed control-CDC endpoint id (or sole default).
 *   Do NOT invent a fake /dev path for device-side USB.
 *
 * Link lifecycle (portable):
 *   CLOSED  --open ok-->  LISTENING | UP
 *     A1: open success is immediately physical link-up (UP, generation++).
 *     A2: open success installs the stack and parks LISTENING until the host
 *         physical link is observed; generation does NOT advance yet.
 *   LISTENING --physical link-up--> UP (generation++, rings cleared)
 *   UP --physical link loss--> DOWN (generation sticky; residual RX drainable)
 *   DOWN --A2 host reconnect physical up--> UP (generation++, rings cleared)
 *   DOWN --A1--> must explicit close before any open (no silent residual drop)
 *   * --close--> CLOSED (idempotent-safe; generation sticky until next UP)
 *
 * link_generation advances ONLY on physical link-up transitions (never on
 * open alone for async adapters; never on close/down).
 *
 * Nonclaims:
 * - Not public include/ninlil ABI / not installed.
 * - Raw write acceptance is not Transport Custody or Application Receipt.
 * - RX overflow is a continuity signal, not physical link down.
 * - Does not claim U1/U2 complete, USB series complete, or physical HIL.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default raw ring capacity (docs/23 §4.4 profile default). */
#define NINLIL_BYTE_STREAM_RING_BYTES ((uint32_t)4096u)

/*
 * Bounded diagnostic endpoint / hint capacities (no heap).
 * error.endpoint holds the last endpoint token or path diagnostic (not a
 * portable filesystem guarantee).
 */
#define NINLIL_BYTE_STREAM_ENDPOINT_BYTES ((size_t)256u)
/* Backward-compatible alias used by existing A1 diagnostics. */
#define NINLIL_BYTE_STREAM_PATH_BYTES NINLIL_BYTE_STREAM_ENDPOINT_BYTES
#define NINLIL_BYTE_STREAM_HINT_BYTES ((size_t)160u)

typedef uint32_t ninlil_byte_stream_status_t;

#define NINLIL_BYTE_STREAM_OK ((ninlil_byte_stream_status_t)0u)
#define NINLIL_BYTE_STREAM_WOULD_BLOCK ((ninlil_byte_stream_status_t)1u)
#define NINLIL_BYTE_STREAM_ERR_LINK_DOWN ((ninlil_byte_stream_status_t)2u)
#define NINLIL_BYTE_STREAM_INVALID_ARGUMENT ((ninlil_byte_stream_status_t)3u)
#define NINLIL_BYTE_STREAM_INVALID_STATE ((ninlil_byte_stream_status_t)4u)
#define NINLIL_BYTE_STREAM_BUSY ((ninlil_byte_stream_status_t)5u)
#define NINLIL_BYTE_STREAM_NOT_FOUND ((ninlil_byte_stream_status_t)6u)
#define NINLIL_BYTE_STREAM_PERMISSION ((ninlil_byte_stream_status_t)7u)
#define NINLIL_BYTE_STREAM_UNSUPPORTED ((ninlil_byte_stream_status_t)8u)
#define NINLIL_BYTE_STREAM_IO_ERROR ((ninlil_byte_stream_status_t)9u)
#define NINLIL_BYTE_STREAM_WRONG_OWNER ((ninlil_byte_stream_status_t)10u)
#define NINLIL_BYTE_STREAM_RX_OVERFLOW ((ninlil_byte_stream_status_t)11u)
#define NINLIL_BYTE_STREAM_CLOSED ((ninlil_byte_stream_status_t)12u)

typedef uint32_t ninlil_byte_stream_link_t;

#define NINLIL_BYTE_STREAM_LINK_CLOSED ((ninlil_byte_stream_link_t)0u)
#define NINLIL_BYTE_STREAM_LINK_UP ((ninlil_byte_stream_link_t)1u)
#define NINLIL_BYTE_STREAM_LINK_DOWN ((ninlil_byte_stream_link_t)2u)
/*
 * Open accepted; physical host link not yet established (async adapters).
 * A1 never parks here on successful open (POSIX open is link-up).
 */
#define NINLIL_BYTE_STREAM_LINK_LISTENING ((ninlil_byte_stream_link_t)3u)

/*
 * Operation stage for structured error facts (adapter-private mapping).
 * Portable enum; concrete adapters may set additional stages.
 */
typedef uint32_t ninlil_byte_stream_stage_t;

#define NINLIL_BYTE_STREAM_STAGE_NONE ((ninlil_byte_stream_stage_t)0u)
/* Endpoint token validation (A1 absolute path; A2 endpoint id). */
#define NINLIL_BYTE_STREAM_STAGE_ENDPOINT ((ninlil_byte_stream_stage_t)1u)
/* Alias for A1 path diagnostics (same numeric value as STAGE_ENDPOINT). */
#define NINLIL_BYTE_STREAM_STAGE_PATH NINLIL_BYTE_STREAM_STAGE_ENDPOINT
#define NINLIL_BYTE_STREAM_STAGE_OPEN ((ninlil_byte_stream_stage_t)2u)
#define NINLIL_BYTE_STREAM_STAGE_EXCLUSIVE ((ninlil_byte_stream_stage_t)3u)
#define NINLIL_BYTE_STREAM_STAGE_TERMIOS ((ninlil_byte_stream_stage_t)4u)
#define NINLIL_BYTE_STREAM_STAGE_DTR ((ninlil_byte_stream_stage_t)5u)
#define NINLIL_BYTE_STREAM_STAGE_POLL ((ninlil_byte_stream_stage_t)6u)
#define NINLIL_BYTE_STREAM_STAGE_READ ((ninlil_byte_stream_stage_t)7u)
#define NINLIL_BYTE_STREAM_STAGE_WRITE ((ninlil_byte_stream_stage_t)8u)
#define NINLIL_BYTE_STREAM_STAGE_CLOSE ((ninlil_byte_stream_stage_t)9u)
#define NINLIL_BYTE_STREAM_STAGE_OWNER ((ninlil_byte_stream_stage_t)10u)
#define NINLIL_BYTE_STREAM_STAGE_RX_RING ((ninlil_byte_stream_stage_t)11u)
#define NINLIL_BYTE_STREAM_STAGE_TX_RING ((ninlil_byte_stream_stage_t)12u)
/* USB stack install / uninstall (A2). */
#define NINLIL_BYTE_STREAM_STAGE_USB_STACK ((ninlil_byte_stream_stage_t)13u)
/* USB mount / unmount / line-state physical transitions (A2). */
#define NINLIL_BYTE_STREAM_STAGE_USB_LINK ((ninlil_byte_stream_stage_t)14u)

typedef uint32_t ninlil_byte_stream_event_t;

#define NINLIL_BYTE_STREAM_EVENT_NONE ((ninlil_byte_stream_event_t)0u)
#define NINLIL_BYTE_STREAM_EVENT_READABLE ((ninlil_byte_stream_event_t)1u)
#define NINLIL_BYTE_STREAM_EVENT_WRITABLE ((ninlil_byte_stream_event_t)2u)
#define NINLIL_BYTE_STREAM_EVENT_LINK_DOWN ((ninlil_byte_stream_event_t)4u)
/* Continuity/overflow: NOT physical link down (docs/23 §4.5 / §5.2). */
#define NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW ((ninlil_byte_stream_event_t)8u)
#define NINLIL_BYTE_STREAM_EVENT_TIMEOUT ((ninlil_byte_stream_event_t)16u)
#define NINLIL_BYTE_STREAM_EVENT_TX_DRAINED ((ninlil_byte_stream_event_t)32u)
/* Physical link-up (generation advanced). */
#define NINLIL_BYTE_STREAM_EVENT_LINK_UP ((ninlil_byte_stream_event_t)64u)

/*
 * Structured private error: stage/status/errno/endpoint facts + bounded hint.
 * sys_errno is a portable int32 snapshot of platform errno (0 if n/a).
 * path[] is the diagnostic endpoint token slot (absolute path for A1;
 * control-CDC endpoint id for A2). Field name is historical; not a portable
 * filesystem claim.
 */
typedef struct ninlil_byte_stream_error {
    ninlil_byte_stream_status_t status;
    ninlil_byte_stream_stage_t stage;
    int32_t sys_errno;
    uint32_t reserved_zero;
    char path[NINLIL_BYTE_STREAM_ENDPOINT_BYTES];
    char hint[NINLIL_BYTE_STREAM_HINT_BYTES];
} ninlil_byte_stream_error_t;

/*
 * Fixed measurement snapshot (docs/23 §4.4 measurement hooks / U1/U2).
 * Counters are saturating (see ninlil_byte_stream_sat_add_u64).
 */
typedef struct ninlil_byte_stream_stats {
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t would_block_count;
    uint64_t poll_timeout_count;
    /*
     * Aggregated EINTR / interruptible-retry observations across poll and
     * pump read/write paths (not poll-only). Saturating.
     */
    uint64_t eintr_count;
    uint64_t rx_overflow_count;
    uint64_t link_down_count;
    uint64_t link_up_count;
    uint64_t open_count;
    uint64_t close_count;
    /*
     * Residual RX bytes discarded at a physical generation boundary
     * (reconnect UP clears prior-generation residual; never silent).
     */
    uint64_t generation_rx_discard_bytes;
    /*
     * Bytes accepted by the underlying driver TX path after a concurrent
     * generation/link change made Ninlil ring commit impossible. Those
     * bytes are non-custody / non-recallable; U3 must reject stale frames.
     */
    uint64_t tx_driver_stale_accepted;
    uint32_t rx_high_watermark;
    uint32_t tx_high_watermark;
    uint32_t rx_ring_bytes;
    uint32_t tx_ring_bytes;
} ninlil_byte_stream_stats_t;

typedef struct ninlil_byte_stream ninlil_byte_stream_t;

/*
 * Owner concurrency contract (C1 portable):
 * - Successful open establishes the owner process/thread/task for that open
 *   lifetime (LISTENING, UP, or DOWN until close). After open, *all* stream
 *   API calls — including link/generation/stats/last_error observers — are
 *   single-owner-only; concurrent or cross-owner calls are forbidden (no
 *   internal locks for multi-reader telemetry; no atomic snapshot claim).
 *   Data races are undefined behavior.
 * - open/close/read/write/poll may fail-closed with WRONG_OWNER when the
 *   adapter implements owner checks. WRONG_OWNER must not mutate owned stream
 *   state (last_error/stats/rings/link/generation); only caller-owned
 *   out_error is filled. link/generation/stats/last_error may keep pure
 *   observer signatures (no status return) but are still not cross-owner
 *   telemetry APIs: upper layers must snapshot on the owner and hand off.
 * - Reopen: open is allowed only from LINK_CLOSED. LINK_DOWN requires the
 *   owner's explicit close first for A1 (no silent residual-RX drop). A2 may
 *   observe host reconnect physical UP while still open (DOWN→UP) without
 *   close; that is not "open()", it is a physical generation transition.
 *   Explicit close, then a later successful open, may establish a new owner
 *   for the new open lifetime (same or different thread/task).
 */
typedef struct ninlil_byte_stream_ops {
    /*
     * Open with adapter-neutral endpoint_token.
     * Only from LINK_CLOSED. Successful open establishes stream owner.
     *   A1: token is absolute device path; success → LINK_UP + generation++.
     *   A2: token is control-CDC endpoint id (or sole default); success →
     *       LINK_LISTENING (generation unchanged until physical UP).
     * Platform state stays private. No fake /dev path for device USB.
     */
    ninlil_byte_stream_status_t (*open)(
        ninlil_byte_stream_t *stream,
        const char *endpoint_token,
        ninlil_byte_stream_error_t *out_error);

    /*
     * Idempotent-safe close. Owner only. Fences subsequent use of the closed
     * generation; does not auto-reconnect.
     */
    ninlil_byte_stream_status_t (*close)(
        ninlil_byte_stream_t *stream,
        ninlil_byte_stream_error_t *out_error);

    /*
     * All-or-none enqueue into the TX raw ring. On WOULD_BLOCK nothing is
     * accepted (accepted=0). Acceptance never implies Transport Custody or
     * Application Receipt (docs/23 §6). While not LINK_UP, adapters return
     * WOULD_BLOCK or ERR_LINK_DOWN without accepting bytes.
     */
    ninlil_byte_stream_status_t (*write)(
        ninlil_byte_stream_t *stream,
        const uint8_t *data,
        uint32_t length,
        uint32_t *out_accepted,
        ninlil_byte_stream_error_t *out_error);

    /*
     * Dequeue from the RX raw ring into caller storage (bounded by capacity).
     * - capacity == 0 is always INVALID_ARGUMENT (UP or DOWN); never OK+0.
     * - While link is UP or LISTENING: length 0 with OK means no bytes available.
     * - After physical LINK_DOWN: buffered RX is returned first only when
     *   capacity > 0 and ring non-empty (OK + length > 0). Once the ring is
     *   empty, read MUST return ERR_LINK_DOWN (not OK+0 that hides link loss).
     */
    ninlil_byte_stream_status_t (*read)(
        ninlil_byte_stream_t *stream,
        uint8_t *out_data,
        uint32_t capacity,
        uint32_t *out_length,
        ninlil_byte_stream_error_t *out_error);

    /*
     * Deterministic poll/pump. timeout_ms bounds *blocking wait* only (not
     * whole-call wall-time). Call-entry deadline stops further blocking wait
     * and extra I/O/retry loops, but ready/queued work MUST still get at least
     * one nonblocking progress attempt (so poll(0) can drain/fill rings).
     * After deadline: no blocking poll (wait_ms may be 0 only). EINTR retries
     * finite via shared ceiling. Work finite via rings/chunks/ceilings.
     * Non-OK pump results MUST propagate. No hidden adapter pump thread;
     * reconnect explicit (A1) or physical host-driven (A2). Driver stack
     * service tasks (e.g. esp_tinyusb) are not C1 ownership pumps.
     */
    ninlil_byte_stream_status_t (*poll)(
        ninlil_byte_stream_t *stream,
        uint32_t timeout_ms,
        ninlil_byte_stream_event_t *out_events,
        ninlil_byte_stream_error_t *out_error);

    /* Owner only; not a concurrent cross-owner monitor. */
    ninlil_byte_stream_link_t (*link)(const ninlil_byte_stream_t *stream);

    /*
     * Owner only. Nonzero after physical link-up; advances on each physical
     * link-up (including A2 host reconnect). Zero while never-up this process
     * or still LISTENING after open.
     */
    uint64_t (*link_generation)(const ninlil_byte_stream_t *stream);

    /* Owner only snapshot out; not lock-free multi-reader telemetry. */
    void (*stats)(
        const ninlil_byte_stream_t *stream,
        ninlil_byte_stream_stats_t *out_stats);

    /* Owner only snapshot out; not cross-owner last-error watch. */
    void (*last_error)(
        const ninlil_byte_stream_t *stream,
        ninlil_byte_stream_error_t *out_error);
} ninlil_byte_stream_ops_t;

/*
 * Portable stream view: ops vtable + opaque implementor self.
 * Concrete adapters fill this from caller-owned storage.
 */
struct ninlil_byte_stream {
    const ninlil_byte_stream_ops_t *ops;
    void *self;
};

/* Saturating u64 add for measurement counters. */
static inline uint64_t ninlil_byte_stream_sat_add_u64(uint64_t a, uint64_t b)
{
    uint64_t sum;

    if (a == UINT64_MAX || b == UINT64_MAX) {
        return UINT64_MAX;
    }
    sum = a + b;
    if (sum < a) {
        return UINT64_MAX;
    }
    return sum;
}

/* Saturating u32 high-watermark update. */
static inline uint32_t ninlil_byte_stream_sat_hwm_u32(uint32_t current, uint32_t sample)
{
    return (sample > current) ? sample : current;
}

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_BYTE_STREAM_H */
