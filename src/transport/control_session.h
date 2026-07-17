#ifndef NINLIL_TRANSPORT_CONTROL_SESSION_H
#define NINLIL_TRANSPORT_CONTROL_SESSION_H

/*
 * U3: Private C3 control-session object + C4 pump (production-private).
 *
 * Connects NCG1 framing (C2 / docs/19) to C1 byte-stream ops (U1/U2 or fake)
 * with explicit payload ownership, bounded ingress/TX intent queues, and
 * fail-closed continuity fencing on link-generation change, RX overflow,
 * close/reopen, and wrong-owner stream results.
 *
 * Normative ownership / queues / non-custody:
 *   docs/23-usb-radio-boundary.md §2, §4.1–4.5, §5 (continuity fence subset),
 *   §6, §10.1 U3
 *   docs/19-m3-control-byte-stream-framing.md
 *
 * Handoff mode (fixed for U3): (b) copy-out
 *   Accepted NCG1 payloads live in C3-owned ingress storage until take_rx
 *   copies them into caller storage and releases the slot. Summary-only
 *   external pointers into the raw CDC ring are forbidden.
 *
 * Nonclaims (must not be asserted by this slice):
 * - Not U3 "USB series complete"; optional device framing only.
 * - Not HELLO / NCL1 / session_cookie / custody / assignment / security.
 * - Not U4 sequence/gap policy (codec remains transparent; U3 does not
 *   enforce stream_or_cell_id=0 or exact +1 sequence).
 * - Not public include/ninlil ABI / not installed.
 * - Framing or write accept is not Transport Custody or Application Receipt.
 * - Does not claim U1/U2 Required HIL or physical USB roundtrip.
 *
 * WRONG_OWNER (C1 single-owner contract, mirrored for C3/C4):
 * - Fills only caller-owned out_error (STAGE_OWNER). Must not mutate any
 *   session-owned state: last_error, stats (including pump_calls), queues,
 *   TX wire residual, parser, bound generation, or state.
 * - C4 pump MUST NOT call C1 link/generation/stats/last_error observers
 *   before a status-returning stream op (poll/read/write). Observers cannot
 *   report WRONG_OWNER and must not drive fencing on a wrong-owner call.
 * - pump_calls increments only after a non-WRONG_OWNER poll. Bind probes
 *   owner with poll(0) before observers.
 *
 * Generation ticket (post-C1-I/O TOCTOU closure):
 * - After every poll/read/write that is not WRONG_OWNER, re-validate
 *   link_generation + link against the bound ticket before parsing/enqueue
 *   RX or accepting TX progress. Mismatch → fence + discard parser/queues.
 *
 * C1 write contract used by C4:
 * - Normative all-or-none enqueue (docs/23 / C1): OK ⇒ accepted == length
 *   requested for that call; WOULD_BLOCK ⇒ accepted == 0 and no bytes kept.
 * - Partial OK (0 < accepted < length) is a protocol violation: fail-closed
 *   continuity fence; never treat partial accept as Transport Custody.
 * - Session may retain a full encoded frame across pumps while WOULD_BLOCK
 *   (TX ownership handoff of the whole frame), not partial-byte residual.
 *
 * Framing stats: saturating and retained across fence/rebind (parser cold
 * reset must not zero cumulative session snapshot counters).
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"
#include "control_frame_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* docs/23 §4.4 profile defaults for C3 logical ingress / host write intent. */
#define NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES ((uint32_t)16u)
#define NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP ((uint32_t)8192u)
#define NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES ((uint32_t)16u)
#define NINLIL_CTRL_SESSION_TX_INTENT_BYTE_CAP ((uint32_t)8192u)

/*
 * Caller-owned fixed storage ceiling (LP64/ILP32). Exact sizeof is internal;
 * oversized storage is accepted. No heap.
 */
#define NINLIL_CTRL_SESSION_OBJECT_BYTES ((size_t)24576u)
#define NINLIL_CTRL_SESSION_OBJECT_ALIGN ((size_t)8u)

typedef uint32_t ninlil_ctrl_session_status_t;

#define NINLIL_CTRL_SESSION_OK ((ninlil_ctrl_session_status_t)0u)
#define NINLIL_CTRL_SESSION_WOULD_BLOCK ((ninlil_ctrl_session_status_t)1u)
#define NINLIL_CTRL_SESSION_NEED_MORE ((ninlil_ctrl_session_status_t)2u)
#define NINLIL_CTRL_SESSION_ERR_LINK_DOWN ((ninlil_ctrl_session_status_t)3u)
#define NINLIL_CTRL_SESSION_INVALID_ARGUMENT ((ninlil_ctrl_session_status_t)4u)
#define NINLIL_CTRL_SESSION_INVALID_STATE ((ninlil_ctrl_session_status_t)5u)
#define NINLIL_CTRL_SESSION_WRONG_OWNER ((ninlil_ctrl_session_status_t)6u)
#define NINLIL_CTRL_SESSION_RX_OVERFLOW ((ninlil_ctrl_session_status_t)7u)
#define NINLIL_CTRL_SESSION_CONTINUITY_LOST ((ninlil_ctrl_session_status_t)8u)
#define NINLIL_CTRL_SESSION_GENERATION_MISMATCH ((ninlil_ctrl_session_status_t)9u)
#define NINLIL_CTRL_SESSION_INGRESS_FULL ((ninlil_ctrl_session_status_t)10u)
#define NINLIL_CTRL_SESSION_TX_BUSY ((ninlil_ctrl_session_status_t)11u)
#define NINLIL_CTRL_SESSION_CLOSED ((ninlil_ctrl_session_status_t)12u)
#define NINLIL_CTRL_SESSION_IO_ERROR ((ninlil_ctrl_session_status_t)13u)
#define NINLIL_CTRL_SESSION_UNSUPPORTED ((ninlil_ctrl_session_status_t)14u)

typedef uint32_t ninlil_ctrl_session_state_t;

/* Unbound / never successfully bound this object lifetime. */
#define NINLIL_CTRL_SESSION_STATE_IDLE ((ninlil_ctrl_session_state_t)0u)
/* Bound to a C1 stream generation; framing continuity active. */
#define NINLIL_CTRL_SESSION_STATE_BOUND ((ninlil_ctrl_session_state_t)1u)
/*
 * Continuity fence (not necessarily physical link down): generation change,
 * RX overflow, stream CLOSED, fatal I/O, or explicit unbind. No new TX submit
 * or RX accept until rebind. Owned queues discarded at fence time.
 */
#define NINLIL_CTRL_SESSION_STATE_FENCED ((ninlil_ctrl_session_state_t)2u)

typedef uint32_t ninlil_ctrl_session_stage_t;

#define NINLIL_CTRL_SESSION_STAGE_NONE ((ninlil_ctrl_session_stage_t)0u)
#define NINLIL_CTRL_SESSION_STAGE_INIT ((ninlil_ctrl_session_stage_t)1u)
#define NINLIL_CTRL_SESSION_STAGE_BIND ((ninlil_ctrl_session_stage_t)2u)
#define NINLIL_CTRL_SESSION_STAGE_PUMP ((ninlil_ctrl_session_stage_t)3u)
#define NINLIL_CTRL_SESSION_STAGE_RX ((ninlil_ctrl_session_stage_t)4u)
#define NINLIL_CTRL_SESSION_STAGE_TX ((ninlil_ctrl_session_stage_t)5u)
#define NINLIL_CTRL_SESSION_STAGE_TAKE ((ninlil_ctrl_session_stage_t)6u)
#define NINLIL_CTRL_SESSION_STAGE_UNBIND ((ninlil_ctrl_session_stage_t)7u)
#define NINLIL_CTRL_SESSION_STAGE_OWNER ((ninlil_ctrl_session_stage_t)8u)

#define NINLIL_CTRL_SESSION_HINT_BYTES ((size_t)160u)

typedef struct ninlil_ctrl_session_error {
    ninlil_ctrl_session_status_t status;
    ninlil_ctrl_session_stage_t stage;
    ninlil_byte_stream_status_t stream_status;
    uint32_t framing_result;
    char hint[NINLIL_CTRL_SESSION_HINT_BYTES];
} ninlil_ctrl_session_error_t;

/*
 * Saturating private snapshot (uint64_t; no wrap). Includes framing parser
 * counters (promoted) and session-layer continuity counters.
 */
typedef struct ninlil_ctrl_session_stats {
    /* Framing parser (docs/19 units; promoted from u32 with saturation). */
    uint64_t frames_accepted;
    uint64_t framing_bytes_consumed;
    uint64_t resync_skips;
    uint64_t rejects_bad_header;
    uint64_t rejects_bad_frame_crc;
    uint64_t rejects_bad_type;
    uint64_t rejects_bad_version;
    uint64_t rejects_bad_flags;
    uint64_t rejects_bad_length;
    /* Session / pump */
    uint64_t pump_calls;
    uint64_t rx_bytes_read;
    uint64_t tx_bytes_written;
    uint64_t frames_enqueued;
    uint64_t frames_taken;
    uint64_t frames_dropped_ingress_full;
    uint64_t tx_submits;
    uint64_t tx_accepts;
    uint64_t tx_would_block;
    uint64_t rx_overflow_fences;
    uint64_t generation_fences;
    uint64_t link_down_fences;
    /*
     * Reserved diagnostic lane (not incremented on WRONG_OWNER — that path
     * is zero-mutation). Kept for snapshot layout stability.
     */
    uint64_t wrong_owner_count;
    uint64_t continuity_fence_total;
    /* Fail-closed reactions to C1 partial-OK protocol violations. */
    uint64_t tx_partial_ok_fences;
    uint64_t bind_count;
    uint64_t unbind_count;
    uint64_t rebind_count;
    uint32_t ingress_entries;
    uint32_t ingress_bytes;
    uint32_t tx_intent_entries;
    uint32_t tx_intent_bytes;
    uint32_t tx_wire_residual;
    uint32_t ingress_hwm_entries;
    uint32_t ingress_hwm_bytes;
    uint32_t tx_intent_hwm_entries;
    uint32_t tx_intent_hwm_bytes;
} ninlil_ctrl_session_stats_t;

/*
 * Accepted NCG1 frame observation after take_rx copy-out.
 * payload points at caller-owned storage supplied to take_rx.
 */
typedef struct ninlil_ctrl_session_frame {
    uint8_t type;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    uint16_t payload_length;
    const uint8_t *payload;
} ninlil_ctrl_session_frame_t;

typedef struct ninlil_ctrl_session ninlil_ctrl_session_t;

typedef struct ninlil_ctrl_session_object {
    _Alignas(8) unsigned char bytes[NINLIL_CTRL_SESSION_OBJECT_BYTES];
} ninlil_ctrl_session_object_t;

size_t ninlil_ctrl_session_object_size(void);
size_t ninlil_ctrl_session_object_align(void);

/*
 * Initialize caller storage. Does not bind a stream.
 * storage must be >= object_size and correctly aligned.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_init(
    void *storage,
    size_t storage_bytes,
    ninlil_ctrl_session_t **out_session);

ninlil_ctrl_session_status_t ninlil_ctrl_session_init_object(
    ninlil_ctrl_session_object_t *object,
    ninlil_ctrl_session_t **out_session);

/*
 * Bind to a C1 stream that is already LINK_UP with nonzero generation.
 * Owner-validated via status-returning poll(0) before link/generation
 * observers. Captures link_generation as the session fence key.
 * IDLE or FENCED only. On success: STATE_BOUND, parser cold, queues empty,
 * cumulative stats retained (bind_count++ / rebind_count++ when prior fence).
 * WRONG_OWNER: only out_error; no bind / no session mutation.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_bind(
    ninlil_ctrl_session_t *session,
    ninlil_byte_stream_t *stream,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Explicit unbind: STATE_FENCED, discard owned queues, reset parser, drop
 * stream pointer. Idempotent from FENCED. Does not close the stream.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_unbind(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error);

ninlil_ctrl_session_state_t ninlil_ctrl_session_state(
    const ninlil_ctrl_session_t *session);

uint64_t ninlil_ctrl_session_bound_generation(
    const ninlil_ctrl_session_t *session);

/*
 * C4 pump: deterministic progress on bound session.
 * - Owner check first via status-returning poll (never observers first)
 * - Detects generation change / RX_OVERFLOW / link down / CLOSED → fence
 * - Drains RX (prefer) then TX: encode intent head; all-or-none C1 write
 * - Feeds NCG1 parser in bounded chunks; enqueues owned frames (copy)
 * - Full-frame TX ownership: while WOULD_BLOCK, entire encoded frame stays
 *   session-owned (accepted==0). OK requires accepted == remaining length.
 *
 * timeout_ms is passed to C1 poll (blocking-wait budget only).
 * Returns OK on progress or idle-success; WOULD_BLOCK when TX cannot move;
 * CONTINUITY_LOST / GENERATION_MISMATCH / RX_OVERFLOW after a new fence;
 * WRONG_OWNER with zero session mutation (only out_error).
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_pump(
    ninlil_ctrl_session_t *session,
    uint32_t timeout_ms,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Queue one NCG1 frame for TX (copy payload into session intent storage).
 * On OK: caller may free fields->payload immediately (ownership transferred
 * into session intent). On WOULD_BLOCK: nothing accepted, caller retains
 * payload. Encoded frame stays session-owned until C1 write accepts the
 * whole frame (all-or-none).
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_submit_tx(
    ninlil_ctrl_session_t *session,
    const ninlil_model_control_frame_fields_t *fields,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Copy-out handoff of the oldest enqueued RX frame into caller storage.
 * On OK: frame is removed from ingress; out_frame->payload points at
 * out_payload for payload_length bytes (0-length ⇒ payload NULL).
 * NEED_MORE if ingress empty while BOUND; CONTINUITY_LOST if FENCED.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_take_rx(
    ninlil_ctrl_session_t *session,
    uint8_t *out_payload,
    uint32_t payload_capacity,
    ninlil_ctrl_session_frame_t *out_frame,
    ninlil_ctrl_session_error_t *out_error);

/* Owner-only snapshot; not a concurrent multi-reader telemetry API. */
void ninlil_ctrl_session_stats(
    const ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_stats_t *out_stats);

void ninlil_ctrl_session_last_error(
    const ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error);

/* Ingress occupancy (BOUND); 0 when not bound. */
uint32_t ninlil_ctrl_session_ingress_count(const ninlil_ctrl_session_t *session);
uint32_t ninlil_ctrl_session_tx_intent_count(const ninlil_ctrl_session_t *session);
uint32_t ninlil_ctrl_session_tx_wire_residual(const ninlil_ctrl_session_t *session);

/*
 * Host-test-only seam (not public ABI). Enabled only when the test target
 * compiles with NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM. Forces committed
 * framing counters so saturation/retention can be proven without a public
 * diagnostic API. Production builds must not define the macro.
 */
#if defined(NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM)
void ninlil_ctrl_session_test_force_committed_framing_stats(
    ninlil_ctrl_session_t *session,
    uint64_t frames_accepted,
    uint64_t resync_skips);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_CONTROL_SESSION_H */
