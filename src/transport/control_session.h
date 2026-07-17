#ifndef NINLIL_TRANSPORT_CONTROL_SESSION_H
#define NINLIL_TRANSPORT_CONTROL_SESSION_H

/*
 * U3: Private C3 control-session object + C4 pump (production-private).
 * U3↔U4 production-private boundary (same object): logical epoch claim,
 * tracked TX (raw outstanding max 1), RX-only cold under claim.
 *
 * Connects NCG1 framing (C2 / docs/19) to C1 byte-stream ops (U1/U2 or fake)
 * with explicit payload ownership, bounded ingress/TX intent queues, and
 * fail-closed continuity fencing on link-generation change, RX overflow
 * (legacy non-claim path), close/reopen, and wrong-owner stream results.
 *
 * Normative ownership / queues / non-custody:
 *   docs/23-usb-radio-boundary.md §2, §4.1–4.5, §5 (continuity fence subset),
 *   §5.5.2 / §5.6.1 RX-only cold semantics (local framing subset only),
 *   §6, §8.3 (session fence vocabulary; NCL1 RESET not implemented here),
 *   §10.1 U3 + U3↔U4 boundary
 *   docs/19-m3-control-byte-stream-framing.md
 *
 * Handoff mode (fixed for U3): (b) copy-out
 *   Accepted NCG1 payloads live in C3-owned ingress storage until take_rx
 *   copies them into caller storage and releases the slot. Summary-only
 *   external pointers into the raw CDC ring are forbidden.
 *
 * Logical epoch claim (U4-prereq production-private):
 *   - Claim binds a nonzero monotonic epoch_id to the current stream
 *     generation while STATE_BOUND, dirty TX empty, and no unresolved
 *     tracked token. Begin performs RX parser/ingress cold only.
 *   - While claimed: legacy submit_tx is rejected; tracked_submit_tx,
 *     take_rx, and pump remain available. Epoch wrap is fail-closed.
 *   - Stale epoch arguments reject with zero session mutation.
 *   - Full link/generation fence invalidates the claim; RX overflow under
 *     claim is RX-only cold (BOUND preserved). Non-claim overflow still
 *     full-fences as classic U3.
 *
 * Tracked TX (U4 raw outstanding max 1):
 *   - tracked_submit_tx issues a process-local nonzero token held from
 *     intent through tx_wire until tx_resolve consumes a terminal result.
 *   - tx_resolve is the sole authority for resolution (no stats-delta
 *     inference). Exact enum includes PENDING_UNACCEPTED, raw accept in
 *     current epoch, cancel, fenced-unaccepted, accept-then-fenced, and
 *     indeterminate partial. Cancel removes unaccepted intent/wire only.
 *
 * Nonclaims (must not be asserted by this slice):
 * - Not U3 "USB series complete"; optional device framing only.
 * - Not HELLO / NCL1 / session_cookie / custody / assignment / security.
 * - Not U4 complete (no NCL1 logical_control, no HELLO state machine,
 *   no §8.9 vector bridge). This is the U3↔U4 production-private
 *   tracked-TX / logical-epoch / RX-cold boundary only.
 * - Not U4 sequence/gap policy (codec remains transparent; U3 does not
 *   enforce stream_or_cell_id=0 or exact +1 sequence).
 * - Not public include/ninlil ABI / not installed.
 * - Framing or write accept is not Transport Custody or Application Receipt.
 * - Does not claim U1/U2 Required HIL or physical USB roundtrip.
 *
 * WRONG_OWNER (C1 single-owner contract, mirrored for C3/C4):
 * - Fills only caller-owned out_error (STAGE_OWNER). Must not mutate any
 *   session-owned state: last_error, stats (including pump_calls), queues,
 *   TX wire residual, parser, bound generation, epoch claim, tracked token,
 *   or state.
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
 * - Tracked full C1 accept followed by post-I/O ticket mismatch is reported
 *   as RAW_ACCEPTED_THEN_FENCED (accept fact saved before queue clear).
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
 *
 * Object size ceiling:
 *   24576 bytes covers two 8192-byte pools, NCG1 max frame wire, parser
 *   payload, ingress/intent metadata, tracked-token/epoch state, and
 *   alignment padding on LP64/ILP32. Oversized caller storage is accepted.
 *   _Static_assert enforces sizeof(session) <= ceiling.
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
 *
 * Budget (bytes, order-of-magnitude): ingress pool 8192 + intent pool 8192 +
 * tx_wire MAX_FRAME (~1050) + parser payload 1024 + rx_chunk 256 +
 * entry tables + stats/error + epoch/tracked (~64) + padding < 24576.
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
/* Stale or mismatched logical epoch; guaranteed zero session mutation. */
#define NINLIL_CTRL_SESSION_STALE_EPOCH ((ninlil_ctrl_session_status_t)15u)
/* Monotonic epoch id space exhausted (wrap fail-closed). */
#define NINLIL_CTRL_SESSION_EPOCH_EXHAUSTED ((ninlil_ctrl_session_status_t)16u)
/*
 * Tracked TX token id space exhausted (object-lifetime non-reuse wrap
 * fail-closed). Distinct from TX_BUSY (outstanding max 1).
 */
#define NINLIL_CTRL_SESSION_TOKEN_EXHAUSTED ((ninlil_ctrl_session_status_t)17u)

typedef uint32_t ninlil_ctrl_session_state_t;

/* Unbound / never successfully bound this object lifetime. */
#define NINLIL_CTRL_SESSION_STATE_IDLE ((ninlil_ctrl_session_state_t)0u)
/* Bound to a C1 stream generation; framing continuity active. */
#define NINLIL_CTRL_SESSION_STATE_BOUND ((ninlil_ctrl_session_state_t)1u)
/*
 * Continuity fence (not necessarily physical link down): generation change,
 * RX overflow (legacy non-claim), stream CLOSED, fatal I/O, or explicit
 * unbind. No new TX submit or RX accept until rebind. Owned queues discarded
 * at fence time (tracked terminal resolution is retained until resolve).
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
#define NINLIL_CTRL_SESSION_STAGE_EPOCH ((ninlil_ctrl_session_stage_t)9u)
#define NINLIL_CTRL_SESSION_STAGE_TRACKED ((ninlil_ctrl_session_stage_t)10u)
#define NINLIL_CTRL_SESSION_STAGE_RX_COLD ((ninlil_ctrl_session_stage_t)11u)

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
    /*
     * Legacy full continuity fence on RX_OVERFLOW only (STATE_FENCED).
     * Claim-path RX-only cold must not increment this; use logical_rx_colds.
     */
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
    /* U3↔U4 boundary diagnostics (not a substitute for tx_resolve). */
    uint64_t logical_epoch_begins;
    uint64_t logical_epoch_ends;
    /* RX-only cold applications (claim overflow / explicit cold); not fences. */
    uint64_t logical_rx_colds;
    uint64_t tracked_submits;
    uint64_t tracked_resolves;
    uint64_t tracked_cancels;
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

/*
 * Logical epoch claim handle (caller-owned copy of authority fields).
 * epoch_id is nonzero and monotonic for a live claim reference.
 * bound_stream_generation is the C1 generation captured at begin.
 */
typedef struct ninlil_ctrl_session_logical_epoch {
    uint64_t epoch_id;
    uint64_t bound_stream_generation;
} ninlil_ctrl_session_logical_epoch_t;

/* Process-local tracked TX token; nonzero; not reused within the object life. */
typedef uint64_t ninlil_ctrl_session_tx_token_t;

typedef uint32_t ninlil_ctrl_session_tx_resolution_t;

/* Exact tracked TX resolution (tx_resolve is sole authority). */
#define NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED \
    ((ninlil_ctrl_session_tx_resolution_t)0u)
#define NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH \
    ((ninlil_ctrl_session_tx_resolution_t)1u)
#define NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED \
    ((ninlil_ctrl_session_tx_resolution_t)2u)
#define NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED \
    ((ninlil_ctrl_session_tx_resolution_t)3u)
#define NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED \
    ((ninlil_ctrl_session_tx_resolution_t)4u)
#define NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL \
    ((ninlil_ctrl_session_tx_resolution_t)5u)

/*
 * Closed reason catalog for logical_rx_cold (not a free status_t).
 *
 * Values use a tagged range 0x52430001.. ("RC" + ordinal) so they are
 * disjoint from ninlil_ctrl_session_status_t small integers (OK=0,
 * WOULD_BLOCK=1, NEED_MORE=2, …). Passing a status value as reason must
 * fail closed (INVALID_ARGUMENT, zero session mutation) and must not be
 * accepted as EXPLICIT/overflow/etc.
 *
 * Sticky last_error.status is derived from this catalog only — never a
 * copy of an arbitrary status_t masquerading as reason.
 */
typedef uint32_t ninlil_ctrl_session_rx_cold_reason_t;

/* Tagged base: ASCII 'R','C' << 16 | 0x0000. */
#define NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG \
    ((ninlil_ctrl_session_rx_cold_reason_t)0x52430000u)

#define NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT \
    ((ninlil_ctrl_session_rx_cold_reason_t)0x52430001u)
#define NINLIL_CTRL_SESSION_RX_COLD_REASON_RX_OVERFLOW \
    ((ninlil_ctrl_session_rx_cold_reason_t)0x52430002u)
#define NINLIL_CTRL_SESSION_RX_COLD_REASON_PARSER_CONTINUITY \
    ((ninlil_ctrl_session_rx_cold_reason_t)0x52430003u)
#define NINLIL_CTRL_SESSION_RX_COLD_REASON_FEED_GUARD \
    ((ninlil_ctrl_session_rx_cold_reason_t)0x52430004u)

typedef struct ninlil_ctrl_session ninlil_ctrl_session_t;

/*
 * Complete private layout (production-private header surface only).
 * Object embeds the typed session member — never unsigned-char storage
 * with struct cast (C11 effective type / strict aliasing).
 */
#define NINLIL_CTRL_SESSION_LAYOUT_ALLOW 1
#include "control_session_layout.h"
/* Keep ALLOW defined so nested re-includes of the layout guard pass. */

typedef struct ninlil_ctrl_session_object {
    struct ninlil_ctrl_session session;
} ninlil_ctrl_session_object_t;

#define NINLIL_CTRL_SESSION_OBJECT_INIT \
    {                                   \
        .session = { 0 }                \
    }

_Static_assert(
    sizeof(ninlil_ctrl_session_object_t) <= NINLIL_CTRL_SESSION_OBJECT_BYTES,
    "typed ctrl_session object must fit portable ceiling");
_Static_assert(
    _Alignof(ninlil_ctrl_session_object_t) >= NINLIL_CTRL_SESSION_OBJECT_ALIGN,
    "typed ctrl_session object align must meet OBJECT_ALIGN");
_Static_assert(
    sizeof(ninlil_ctrl_session_object_t) == sizeof(struct ninlil_ctrl_session),
    "object is exactly the typed session (no char-array padding shell)");
_Static_assert(
    _Alignof(ninlil_ctrl_session_object_t)
        == _Alignof(struct ninlil_ctrl_session),
    "object align must equal complete session align");

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
 * Invalidates any logical epoch claim; pending tracked becomes
 * FENCED_UNACCEPTED (or retains a prior terminal).
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
 *   (RX_OVERFLOW under active logical epoch claim → RX-only cold, stay BOUND)
 * - Drains RX (prefer) then TX: encode intent head; all-or-none C1 write
 * - Feeds NCG1 parser in bounded chunks; enqueues owned frames (copy)
 * - Full-frame TX ownership: while WOULD_BLOCK, entire encoded frame stays
 *   session-owned (accepted==0). OK requires accepted == remaining length.
 *
 * timeout_ms is passed to C1 poll (blocking-wait budget only).
 * Returns OK on progress or idle-success; WOULD_BLOCK when TX cannot move;
 * CONTINUITY_LOST / GENERATION_MISMATCH / RX_OVERFLOW after a new fence
 * (or RX-only cold under claim for overflow);
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
 *
 * Rejected while a logical epoch claim is active (use tracked_submit_tx).
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_submit_tx(
    ninlil_ctrl_session_t *session,
    const ninlil_model_control_frame_fields_t *fields,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Begin a logical epoch claim. Requires STATE_BOUND, empty dirty TX
 * (intent + wire residual), and no unresolved tracked token. On success:
 * RX parser cumulative commit+reset and ingress discard (RX cold); TX path
 * and bound generation unchanged. Fail-closed on epoch id wrap exhaustion.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_logical_epoch_begin(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_logical_epoch_t *out_epoch,
    ninlil_ctrl_session_error_t *out_error);

/*
 * End a logical epoch claim. Epoch must match the active claim. Requires the
 * tracked slot fully resolved: tracked_token == 0 and phase NONE (pending
 * intent/wire and unconsumed terminal results all block end — resolve first).
 * Zero mutation on stale epoch.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_logical_epoch_end(
    ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Tracked TX submit under an active logical epoch (raw outstanding max 1).
 * On OK: returns a nonzero object-lifetime non-reuse token; payload ownership
 * same as submit_tx. Token wrap → TOKEN_EXHAUSTED fail-closed (not TX_BUSY).
 * Stale epoch: zero mutation.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_tracked_submit_tx(
    ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch,
    const ninlil_model_control_frame_fields_t *fields,
    ninlil_ctrl_session_tx_token_t *out_token,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Resolve a tracked TX token. Terminal results are retained until the first
 * successful resolve that observes them; that call consumes the token slot.
 * cancel_if_pending != 0: if still unaccepted (intent or encoded wire),
 * atomically delete residual and return CANCELLED_UNACCEPTED (no later wire
 * send). Already-accepted terminals cannot be cancelled.
 * Double resolve after consumption: STALE/invalid, zero mutation.
 * out_resolution receives the exact enum; never infer from stats deltas.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_tx_resolve(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_tx_token_t token,
    int cancel_if_pending,
    ninlil_ctrl_session_tx_resolution_t *out_resolution,
    ninlil_ctrl_session_error_t *out_error);

/*
 * Explicit RX-only cold under an active matching epoch: parser cumulative
 * commit+reset and full ingress discard only. Preserves STATE_BOUND, stream,
 * generation, TX intent, tx_wire, and tracked token/terminal completely.
 * reason must be a closed RX_COLD_REASON_* value; sticky last_error.status is
 * derived from that catalog (never copies free status_t such as OK/STALE).
 * Invalid reason → INVALID_ARGUMENT, zero session mutation. Stale epoch:
 * zero mutation.
 */
ninlil_ctrl_session_status_t ninlil_ctrl_session_logical_rx_cold(
    ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch,
    ninlil_ctrl_session_rx_cold_reason_t reason,
    uint32_t *out_dropped_frames,
    uint32_t *out_dropped_bytes,
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

/* Nonzero when a logical epoch claim is active on a BOUND session. */
int ninlil_ctrl_session_logical_epoch_is_claimed(
    const ninlil_ctrl_session_t *session);

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

/* Test-only: force next epoch id allocation (0 = exhausted; UINT64_MAX wrap). */
void ninlil_ctrl_session_test_force_epoch_next(
    ninlil_ctrl_session_t *session,
    uint64_t epoch_next);

/*
 * Test-only: force next tracked TX token allocation (0 = exhausted;
 * UINT64_MAX exercises final mint then exhaustion). Object-lifetime non-reuse.
 */
void ninlil_ctrl_session_test_force_token_next(
    ninlil_ctrl_session_t *session,
    uint64_t token_next);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_CONTROL_SESSION_H */
