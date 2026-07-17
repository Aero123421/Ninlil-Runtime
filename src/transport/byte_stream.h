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
 *   docs/23-usb-radio-boundary.md §2, §3.2, §4, §6, §10.1
 *   docs/adr/0003-radio-usb-dependency-direction.md
 *
 * Nonclaims:
 * - Not public include/ninlil ABI / not installed.
 * - Raw write acceptance is not Transport Custody or Application Receipt.
 * - RX overflow is a continuity signal, not physical link down.
 * - Does not claim U1 complete, USB series complete, or physical HIL.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default raw ring capacity (docs/23 §4.4 profile default). */
#define NINLIL_BYTE_STREAM_RING_BYTES ((uint32_t)4096u)

/* Bounded diagnostic path / hint capacities (no heap). */
#define NINLIL_BYTE_STREAM_PATH_BYTES ((size_t)256u)
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
 * Operation stage for structured error facts (adapter-private mapping).
 * Portable enum; concrete adapters may set additional stages.
 */
typedef uint32_t ninlil_byte_stream_stage_t;

#define NINLIL_BYTE_STREAM_STAGE_NONE ((ninlil_byte_stream_stage_t)0u)
#define NINLIL_BYTE_STREAM_STAGE_PATH ((ninlil_byte_stream_stage_t)1u)
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

typedef uint32_t ninlil_byte_stream_event_t;

#define NINLIL_BYTE_STREAM_EVENT_NONE ((ninlil_byte_stream_event_t)0u)
#define NINLIL_BYTE_STREAM_EVENT_READABLE ((ninlil_byte_stream_event_t)1u)
#define NINLIL_BYTE_STREAM_EVENT_WRITABLE ((ninlil_byte_stream_event_t)2u)
#define NINLIL_BYTE_STREAM_EVENT_LINK_DOWN ((ninlil_byte_stream_event_t)4u)
/* Continuity/overflow: NOT physical link down (docs/23 §4.5 / §5.2). */
#define NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW ((ninlil_byte_stream_event_t)8u)
#define NINLIL_BYTE_STREAM_EVENT_TIMEOUT ((ninlil_byte_stream_event_t)16u)
#define NINLIL_BYTE_STREAM_EVENT_TX_DRAINED ((ninlil_byte_stream_event_t)32u)

/*
 * Structured private error: stage/status/errno/path facts + bounded hint.
 * sys_errno is a portable int32 snapshot of platform errno (0 if n/a).
 */
typedef struct ninlil_byte_stream_error {
    ninlil_byte_stream_status_t status;
    ninlil_byte_stream_stage_t stage;
    int32_t sys_errno;
    uint32_t reserved_zero;
    char path[NINLIL_BYTE_STREAM_PATH_BYTES];
    char hint[NINLIL_BYTE_STREAM_HINT_BYTES];
} ninlil_byte_stream_error_t;

/*
 * Fixed measurement snapshot (docs/23 §4.4 measurement hooks / U1).
 * Counters are saturating (see ninlil_byte_stream_sat_add_u64).
 */
typedef struct ninlil_byte_stream_stats {
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t would_block_count;
    uint64_t poll_timeout_count;
    /*
     * Aggregated EINTR observations across poll and pump read/write paths
     * (not poll-only). Saturating.
     */
    uint64_t eintr_count;
    uint64_t rx_overflow_count;
    uint64_t link_down_count;
    uint64_t open_count;
    uint64_t close_count;
    uint32_t rx_high_watermark;
    uint32_t tx_high_watermark;
    uint32_t rx_ring_bytes;
    uint32_t tx_ring_bytes;
} ninlil_byte_stream_stats_t;

typedef struct ninlil_byte_stream ninlil_byte_stream_t;

/*
 * Owner concurrency contract (C1 portable):
 * - Successful open establishes the owner process/thread for that
 *   link_generation. After open, *all* stream API calls — including
 *   link/generation/stats/last_error observers — are single-owner-only;
 *   concurrent or cross-thread calls are forbidden (no internal locks;
 *   no atomic snapshot claim). Data races are undefined behavior.
 * - open/close/read/write/poll may fail-closed with WRONG_OWNER when the
 *   adapter implements owner checks. WRONG_OWNER must not mutate owned stream
 *   state (last_error/stats/rings/link/generation); only caller-owned
 *   out_error is filled. link/generation/stats/last_error may keep pure
 *   observer signatures (no status return) but are still not cross-thread
 *   telemetry APIs: upper layers must snapshot on the owner thread and hand
 *   off copies if other threads need the facts.
 * - Reopen: open is allowed only from LINK_CLOSED (fd fenced). LINK_DOWN
 *   requires the owner's explicit close first (no silent residual-RX drop).
 *   Explicit close, then a later successful open, may establish a new owner
 *   for the new generation (same or different thread).
 */
typedef struct ninlil_byte_stream_ops {
    /*
     * Open explicit absolute device path. Only from LINK_CLOSED with fd
     * fenced. Successful open yields link UP and a new nonzero
     * link_generation, and establishes stream owner. Path/fd platform state
     * stay private.
     */
    ninlil_byte_stream_status_t (*open)(
        ninlil_byte_stream_t *stream,
        const char *absolute_path,
        ninlil_byte_stream_error_t *out_error);

    /*
     * Idempotent-safe close. Owner thread/process only. Fences subsequent
     * use of the closed generation; does not auto-reconnect.
     */
    ninlil_byte_stream_status_t (*close)(
        ninlil_byte_stream_t *stream,
        ninlil_byte_stream_error_t *out_error);

    /*
     * All-or-none enqueue into the TX raw ring. On WOULD_BLOCK nothing is
     * accepted. Acceptance never implies Transport Custody or Application
     * Receipt (docs/23 §6).
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
     * - While link is UP: length 0 with OK means no bytes available.
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
     * Non-OK pump results MUST propagate. No hidden thread; reconnect explicit.
     */
    ninlil_byte_stream_status_t (*poll)(
        ninlil_byte_stream_t *stream,
        uint32_t timeout_ms,
        ninlil_byte_stream_event_t *out_events,
        ninlil_byte_stream_error_t *out_error);

    /* Owner-thread only; not a concurrent cross-thread monitor. */
    ninlil_byte_stream_link_t (*link)(const ninlil_byte_stream_t *stream);

    /* Owner-thread only. Nonzero after successful open; advances on reopen. */
    uint64_t (*link_generation)(const ninlil_byte_stream_t *stream);

    /* Owner-thread only snapshot out; not lock-free multi-reader telemetry. */
    void (*stats)(
        const ninlil_byte_stream_t *stream,
        ninlil_byte_stream_stats_t *out_stats);

    /* Owner-thread only snapshot out; not cross-thread last-error watch. */
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
