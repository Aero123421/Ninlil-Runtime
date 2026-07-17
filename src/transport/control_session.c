#include "control_session.h"

#include <string.h>

/*
 * U3 C3 session + C4 pump implementation, plus U3↔U4 production-private
 * logical epoch / tracked TX / RX-only cold boundary.
 * Portable C11. No heap / no VLA / no platform headers.
 */

#define MAGIC ((uint32_t)0x43335355u) /* 'C3SU' */
#define RX_CHUNK_BYTES ((uint32_t)256u)

#define TRACKED_PHASE_NONE ((uint8_t)0u)
#define TRACKED_PHASE_INTENT ((uint8_t)1u)
#define TRACKED_PHASE_WIRE ((uint8_t)2u)
#define TRACKED_PHASE_TERMINAL ((uint8_t)3u)

typedef struct ingress_entry {
    uint8_t type;
    uint8_t reserved0;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    uint16_t payload_length;
    uint16_t payload_off;
} ingress_entry_t;

typedef struct intent_entry {
    uint8_t type;
    uint8_t reserved0;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    uint16_t payload_length;
    uint16_t payload_off;
    uint64_t tracked_token; /* 0 = legacy untracked intent */
} intent_entry_t;

struct ninlil_ctrl_session {
    uint32_t magic;
    ninlil_ctrl_session_state_t state;
    uint32_t reserved_pad;
    ninlil_byte_stream_t *stream;
    uint64_t bound_generation;

    ninlil_model_control_frame_parser_t parser;
    uint8_t parser_payload[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];

    ingress_entry_t ingress[NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES];
    uint8_t ingress_pool[NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP];
    uint32_t ingress_head;
    uint32_t ingress_count;
    uint32_t ingress_bytes;

    intent_entry_t intent[NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES];
    uint8_t intent_pool[NINLIL_CTRL_SESSION_TX_INTENT_BYTE_CAP];
    uint32_t intent_head;
    uint32_t intent_count;
    uint32_t intent_bytes;

    /* Full encoded frame owned until all-or-none C1 write accepts it. */
    uint8_t tx_wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t tx_wire_len;
    uint32_t tx_wire_off;
    uint64_t tx_wire_tracked_token; /* nonzero if wire holds tracked frame */

    uint8_t rx_chunk[RX_CHUNK_BYTES];

    /* Logical epoch claim (0 epoch_active / claimed=0 ⇒ no claim). */
    uint8_t epoch_claimed;
    uint8_t reserved_epoch[7];
    uint64_t epoch_active;
    uint64_t epoch_bound_gen;
    uint64_t epoch_next; /* next id to mint; 0 ⇒ exhausted */

    /* Tracked TX slot (raw outstanding max 1). */
    uint8_t tracked_phase;
    uint8_t reserved_tracked[3];
    ninlil_ctrl_session_tx_resolution_t tracked_resolution;
    uint64_t tracked_token;
    uint64_t token_next; /* next token to mint; 0 ⇒ exhausted */

    ninlil_ctrl_session_stats_t stats;
    ninlil_ctrl_session_error_t last_error;
    uint8_t had_prior_fence;
    uint8_t reserved_tail[7];
};

_Static_assert(
    sizeof(struct ninlil_ctrl_session) <= NINLIL_CTRL_SESSION_OBJECT_BYTES,
    "ctrl session object exceeds portable ceiling");
_Static_assert(
    NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP == 8192u,
    "ingress byte cap drift vs docs/23 §4.4");
_Static_assert(
    NINLIL_CTRL_SESSION_TX_INTENT_BYTE_CAP == 8192u,
    "tx intent byte cap drift vs docs/23 §4.4");
_Static_assert(
    sizeof(struct ninlil_ctrl_session) >= 16384u,
    "ctrl session unexpectedly small vs dual 8KiB pool budget");
/* RX_COLD_REASON tagged range must not collide with status_t small ints. */
_Static_assert(
    NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT
        != NINLIL_CTRL_SESSION_WOULD_BLOCK
        && NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT
            > (ninlil_ctrl_session_rx_cold_reason_t)0x100u,
    "RX_COLD_REASON must be disjoint from status small range");
_Static_assert(
    (NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT
        & NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG)
        == NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG
        && (NINLIL_CTRL_SESSION_RX_COLD_REASON_FEED_GUARD
            & NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG)
            == NINLIL_CTRL_SESSION_RX_COLD_REASON_TAG,
    "RX_COLD_REASON values must carry RC tag");

static uint64_t sat_add_u64(uint64_t a, uint64_t b)
{
    return ninlil_byte_stream_sat_add_u64(a, b);
}

static uint64_t sat_add_u64_u32(uint64_t a, uint32_t b)
{
    return sat_add_u64(a, (uint64_t)b);
}

static void clear_error(ninlil_ctrl_session_error_t *err)
{
    if (err == NULL) {
        return;
    }
    (void)memset(err, 0, sizeof(*err));
}

/* Sticky session last_error + optional out_error. */
static void set_error_sticky(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error,
    ninlil_ctrl_session_status_t status,
    ninlil_ctrl_session_stage_t stage,
    ninlil_byte_stream_status_t stream_status,
    uint32_t framing_result,
    const char *hint)
{
    ninlil_ctrl_session_error_t local;

    (void)memset(&local, 0, sizeof(local));
    local.status = status;
    local.stage = stage;
    local.stream_status = stream_status;
    local.framing_result = framing_result;
    if (hint != NULL) {
        size_t i;
        for (i = 0u; i + 1u < NINLIL_CTRL_SESSION_HINT_BYTES && hint[i] != '\0';
             ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (session != NULL) {
        session->last_error = local;
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

/*
 * WRONG_OWNER path: fill only caller-owned out_error. Never touch
 * session->last_error / stats / queues / residual / state / epoch / tracked.
 */
static void set_error_out_only(
    ninlil_ctrl_session_error_t *out_error,
    ninlil_ctrl_session_status_t status,
    ninlil_ctrl_session_stage_t stage,
    ninlil_byte_stream_status_t stream_status,
    const char *hint)
{
    ninlil_ctrl_session_error_t local;

    (void)memset(&local, 0, sizeof(local));
    local.status = status;
    local.stage = stage;
    local.stream_status = stream_status;
    if (hint != NULL) {
        size_t i;
        for (i = 0u; i + 1u < NINLIL_CTRL_SESSION_HINT_BYTES && hint[i] != '\0';
             ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static ninlil_ctrl_session_t *as_session(void *storage)
{
    return (ninlil_ctrl_session_t *)storage;
}

static int is_live(const ninlil_ctrl_session_t *session)
{
    return session != NULL && session->magic == MAGIC;
}

static void invalidate_epoch_claim(ninlil_ctrl_session_t *session)
{
    session->epoch_claimed = 0u;
    session->epoch_active = 0u;
    session->epoch_bound_gen = 0u;
}

/*
 * Mark pending tracked as terminal on full fence. Never downgrade an already
 * terminal accept-then-fenced / indeterminate result.
 */
static void tracked_terminal_if_pending(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_tx_resolution_t resolution)
{
    if (session->tracked_phase == TRACKED_PHASE_INTENT
        || session->tracked_phase == TRACKED_PHASE_WIRE) {
        session->tracked_phase = TRACKED_PHASE_TERMINAL;
        session->tracked_resolution = resolution;
        session->tx_wire_tracked_token = 0u;
    }
}

/*
 * Commit live parser counters into session cumulative, then cold-reset parser.
 * Guarantees framing stats never decrease across fence/rebind.
 */
static void commit_parser_stats_and_reset(ninlil_ctrl_session_t *session)
{
    const ninlil_model_control_frame_parser_stats_t *ps = &session->parser.stats;

    session->stats.frames_accepted =
        sat_add_u64_u32(session->stats.frames_accepted, ps->frames_accepted);
    session->stats.framing_bytes_consumed =
        sat_add_u64_u32(session->stats.framing_bytes_consumed, ps->bytes_consumed);
    session->stats.resync_skips =
        sat_add_u64_u32(session->stats.resync_skips, ps->resync_skips);
    session->stats.rejects_bad_header =
        sat_add_u64_u32(session->stats.rejects_bad_header, ps->rejects_bad_header);
    session->stats.rejects_bad_frame_crc = sat_add_u64_u32(
        session->stats.rejects_bad_frame_crc, ps->rejects_bad_frame_crc);
    session->stats.rejects_bad_type =
        sat_add_u64_u32(session->stats.rejects_bad_type, ps->rejects_bad_type);
    session->stats.rejects_bad_version =
        sat_add_u64_u32(session->stats.rejects_bad_version, ps->rejects_bad_version);
    session->stats.rejects_bad_flags =
        sat_add_u64_u32(session->stats.rejects_bad_flags, ps->rejects_bad_flags);
    session->stats.rejects_bad_length =
        sat_add_u64_u32(session->stats.rejects_bad_length, ps->rejects_bad_length);
    ninlil_model_control_frame_parser_reset(&session->parser);
}

/* Snapshot = committed cumulative + live parser epoch (no write-back that zeros). */
static void fill_stats_snapshot(
    const ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_stats_t *out)
{
    const ninlil_model_control_frame_parser_stats_t *ps = &session->parser.stats;

    *out = session->stats;
    out->frames_accepted =
        sat_add_u64_u32(session->stats.frames_accepted, ps->frames_accepted);
    out->framing_bytes_consumed =
        sat_add_u64_u32(session->stats.framing_bytes_consumed, ps->bytes_consumed);
    out->resync_skips =
        sat_add_u64_u32(session->stats.resync_skips, ps->resync_skips);
    out->rejects_bad_header =
        sat_add_u64_u32(session->stats.rejects_bad_header, ps->rejects_bad_header);
    out->rejects_bad_frame_crc = sat_add_u64_u32(
        session->stats.rejects_bad_frame_crc, ps->rejects_bad_frame_crc);
    out->rejects_bad_type =
        sat_add_u64_u32(session->stats.rejects_bad_type, ps->rejects_bad_type);
    out->rejects_bad_version =
        sat_add_u64_u32(session->stats.rejects_bad_version, ps->rejects_bad_version);
    out->rejects_bad_flags =
        sat_add_u64_u32(session->stats.rejects_bad_flags, ps->rejects_bad_flags);
    out->rejects_bad_length =
        sat_add_u64_u32(session->stats.rejects_bad_length, ps->rejects_bad_length);
}

static void update_hwm(ninlil_ctrl_session_t *session)
{
    session->stats.ingress_entries = session->ingress_count;
    session->stats.ingress_bytes = session->ingress_bytes;
    session->stats.tx_intent_entries = session->intent_count;
    session->stats.tx_intent_bytes = session->intent_bytes;
    session->stats.tx_wire_residual =
        (session->tx_wire_len > session->tx_wire_off)
            ? (session->tx_wire_len - session->tx_wire_off)
            : 0u;
    session->stats.ingress_hwm_entries = ninlil_byte_stream_sat_hwm_u32(
        session->stats.ingress_hwm_entries, session->ingress_count);
    session->stats.ingress_hwm_bytes = ninlil_byte_stream_sat_hwm_u32(
        session->stats.ingress_hwm_bytes, session->ingress_bytes);
    session->stats.tx_intent_hwm_entries = ninlil_byte_stream_sat_hwm_u32(
        session->stats.tx_intent_hwm_entries, session->intent_count);
    session->stats.tx_intent_hwm_bytes = ninlil_byte_stream_sat_hwm_u32(
        session->stats.tx_intent_hwm_bytes, session->intent_bytes);
}

static void discard_ingress_only(ninlil_ctrl_session_t *session)
{
    session->ingress_head = 0u;
    session->ingress_count = 0u;
    session->ingress_bytes = 0u;
    (void)memset(session->ingress, 0, sizeof(session->ingress));
    update_hwm(session);
}

static void discard_queues(ninlil_ctrl_session_t *session)
{
    session->ingress_head = 0u;
    session->ingress_count = 0u;
    session->ingress_bytes = 0u;
    session->intent_head = 0u;
    session->intent_count = 0u;
    session->intent_bytes = 0u;
    session->tx_wire_len = 0u;
    session->tx_wire_off = 0u;
    session->tx_wire_tracked_token = 0u;
    (void)memset(session->ingress, 0, sizeof(session->ingress));
    (void)memset(session->intent, 0, sizeof(session->intent));
    (void)memset(session->tx_wire, 0, sizeof(session->tx_wire));
    update_hwm(session);
}

/*
 * Full continuity fence. pending_tracked_res applied only if tracked is still
 * non-terminal (INTENT/WIRE). Existing terminal resolutions are preserved.
 */
static void fence_session(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_status_t reason_status,
    ninlil_ctrl_session_stage_t stage,
    ninlil_byte_stream_status_t stream_status,
    const char *hint,
    ninlil_ctrl_session_error_t *out_error,
    ninlil_ctrl_session_tx_resolution_t pending_tracked_res)
{
    tracked_terminal_if_pending(session, pending_tracked_res);
    invalidate_epoch_claim(session);
    session->state = NINLIL_CTRL_SESSION_STATE_FENCED;
    session->had_prior_fence = 1u;
    session->stream = NULL;
    session->bound_generation = 0u;
    discard_queues(session);
    commit_parser_stats_and_reset(session);
    session->stats.continuity_fence_total =
        sat_add_u64(session->stats.continuity_fence_total, 1u);
    set_error_sticky(
        session, out_error, reason_status, stage, stream_status, 0u, hint);
}

/* RX-only cold: parser commit+reset + ingress discard; TX/epoch/state kept. */
static void rx_only_cold_apply(
    ninlil_ctrl_session_t *session,
    uint32_t *out_dropped_frames,
    uint32_t *out_dropped_bytes)
{
    uint32_t frames = session->ingress_count;
    uint32_t bytes = session->ingress_bytes;

    commit_parser_stats_and_reset(session);
    discard_ingress_only(session);
    session->stats.logical_rx_colds =
        sat_add_u64(session->stats.logical_rx_colds, 1u);
    if (out_dropped_frames != NULL) {
        *out_dropped_frames = frames;
    }
    if (out_dropped_bytes != NULL) {
        *out_dropped_bytes = bytes;
    }
}

static ninlil_ctrl_session_status_t map_stream_status(
    ninlil_byte_stream_status_t st)
{
    switch (st) {
    case NINLIL_BYTE_STREAM_OK:
        return NINLIL_CTRL_SESSION_OK;
    case NINLIL_BYTE_STREAM_WOULD_BLOCK:
        return NINLIL_CTRL_SESSION_WOULD_BLOCK;
    case NINLIL_BYTE_STREAM_ERR_LINK_DOWN:
        return NINLIL_CTRL_SESSION_ERR_LINK_DOWN;
    case NINLIL_BYTE_STREAM_INVALID_ARGUMENT:
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    case NINLIL_BYTE_STREAM_INVALID_STATE:
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    case NINLIL_BYTE_STREAM_WRONG_OWNER:
        return NINLIL_CTRL_SESSION_WRONG_OWNER;
    case NINLIL_BYTE_STREAM_RX_OVERFLOW:
        return NINLIL_CTRL_SESSION_RX_OVERFLOW;
    case NINLIL_BYTE_STREAM_CLOSED:
        return NINLIL_CTRL_SESSION_CLOSED;
    case NINLIL_BYTE_STREAM_IO_ERROR:
        return NINLIL_CTRL_SESSION_IO_ERROR;
    default:
        return NINLIL_CTRL_SESSION_IO_ERROR;
    }
}

/*
 * Central post-C1-I/O ticket: after every poll/read/write (and only after a
 * non-WRONG_OWNER status path), re-validate link + generation before using
 * any I/O result (RX parse/enqueue or TX accept). Closes A2 DOWN→UP TOCTOU.
 *
 * Double generation snapshot: g1, link, g2 — both generations must equal
 * bound_generation (rejects a gen advance that races between samples).
 *
 * pending_tracked_res: resolution applied to pending tracked on fence.
 */
static ninlil_ctrl_session_status_t validate_link_generation_ticket(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_stage_t stage,
    ninlil_ctrl_session_error_t *out_error,
    ninlil_ctrl_session_tx_resolution_t pending_tracked_res)
{
    ninlil_byte_stream_link_t link;
    uint64_t g1;
    uint64_t g2;
    uint64_t bound;

    if (session->stream == NULL
        || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return NINLIL_CTRL_SESSION_CONTINUITY_LOST;
    }
    bound = session->bound_generation;
    g1 = session->stream->ops->link_generation(session->stream);
    link = session->stream->ops->link(session->stream);
    g2 = session->stream->ops->link_generation(session->stream);
    if (g1 != bound || g2 != bound || g1 != g2) {
        session->stats.generation_fences =
            sat_add_u64(session->stats.generation_fences, 1u);
        fence_session(
            session,
            NINLIL_CTRL_SESSION_GENERATION_MISMATCH,
            stage,
            NINLIL_BYTE_STREAM_OK,
            "link generation ticket mismatch (g1/link/g2)",
            out_error,
            pending_tracked_res);
        return NINLIL_CTRL_SESSION_GENERATION_MISMATCH;
    }
    if (link == NINLIL_BYTE_STREAM_LINK_CLOSED) {
        session->stats.link_down_fences =
            sat_add_u64(session->stats.link_down_fences, 1u);
        fence_session(
            session,
            NINLIL_CTRL_SESSION_CLOSED,
            stage,
            NINLIL_BYTE_STREAM_CLOSED,
            "stream closed after I/O",
            out_error,
            pending_tracked_res);
        return NINLIL_CTRL_SESSION_CLOSED;
    }
    if (link != NINLIL_BYTE_STREAM_LINK_UP) {
        session->stats.link_down_fences =
            sat_add_u64(session->stats.link_down_fences, 1u);
        fence_session(
            session,
            NINLIL_CTRL_SESSION_ERR_LINK_DOWN,
            stage,
            NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
            "stream not UP after I/O",
            out_error,
            pending_tracked_res);
        return NINLIL_CTRL_SESSION_ERR_LINK_DOWN;
    }
    return NINLIL_CTRL_SESSION_OK;
}

static int epoch_is_active_match(
    const ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch)
{
    if (session == NULL || epoch == NULL) {
        return 0;
    }
    if (session->epoch_claimed == 0u
        || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return 0;
    }
    if (epoch->epoch_id == 0u || session->epoch_active == 0u) {
        return 0;
    }
    if (epoch->epoch_id != session->epoch_active) {
        return 0;
    }
    if (epoch->bound_stream_generation != session->epoch_bound_gen) {
        return 0;
    }
    if (session->bound_generation != session->epoch_bound_gen) {
        return 0;
    }
    return 1;
}

/* Stale-epoch reject: only out_error (+ optional sticky only when session live
 * and caller path is allowed to set sticky — we use out-only for true zero
 * mutation of session including last_error when required). */
static ninlil_ctrl_session_status_t reject_stale_epoch(
    ninlil_ctrl_session_error_t *out_error,
    ninlil_ctrl_session_stage_t stage,
    const char *hint)
{
    set_error_out_only(
        out_error,
        NINLIL_CTRL_SESSION_STALE_EPOCH,
        stage,
        NINLIL_BYTE_STREAM_OK,
        hint);
    return NINLIL_CTRL_SESSION_STALE_EPOCH;
}

static void ingress_compact(ninlil_ctrl_session_t *session)
{
    ingress_entry_t order[NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES];
    uint32_t write = 0u;
    uint32_t i;

    if (session->ingress_count == 0u) {
        session->ingress_head = 0u;
        session->ingress_bytes = 0u;
        return;
    }
    for (i = 0u; i < session->ingress_count; ++i) {
        uint32_t from = (session->ingress_head + i)
            % NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES;
        order[i] = session->ingress[from];
    }
    (void)memset(session->ingress, 0, sizeof(session->ingress));
    for (i = 0u; i < session->ingress_count; ++i) {
        session->ingress[i] = order[i];
    }
    session->ingress_head = 0u;
    for (i = 0u; i < session->ingress_count; ++i) {
        ingress_entry_t *e = &session->ingress[i];
        if (e->payload_length > 0u) {
            if (e->payload_off != write) {
                (void)memmove(
                    session->ingress_pool + write,
                    session->ingress_pool + e->payload_off,
                    e->payload_length);
            }
            e->payload_off = (uint16_t)write;
            write += e->payload_length;
        } else {
            e->payload_off = 0u;
        }
    }
    session->ingress_bytes = write;
}

static void intent_compact(ninlil_ctrl_session_t *session)
{
    intent_entry_t order[NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES];
    uint32_t write = 0u;
    uint32_t i;

    if (session->intent_count == 0u) {
        session->intent_head = 0u;
        session->intent_bytes = 0u;
        return;
    }
    if (session->intent_head != 0u) {
        for (i = 0u; i < session->intent_count; ++i) {
            uint32_t from = (session->intent_head + i)
                % NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES;
            order[i] = session->intent[from];
        }
        (void)memset(session->intent, 0, sizeof(session->intent));
        for (i = 0u; i < session->intent_count; ++i) {
            session->intent[i] = order[i];
        }
        session->intent_head = 0u;
    }
    for (i = 0u; i < session->intent_count; ++i) {
        intent_entry_t *e = &session->intent[i];
        if (e->payload_length > 0u) {
            if (e->payload_off != write) {
                (void)memmove(
                    session->intent_pool + write,
                    session->intent_pool + e->payload_off,
                    e->payload_length);
            }
            e->payload_off = (uint16_t)write;
            write += e->payload_length;
        } else {
            e->payload_off = 0u;
        }
    }
    session->intent_bytes = write;
}

static int ingress_try_enqueue(
    ninlil_ctrl_session_t *session,
    const ninlil_model_control_frame_view_t *view)
{
    uint32_t slot;
    ingress_entry_t *e;
    uint16_t plen;

    if (view == NULL) {
        return 0;
    }
    plen = view->payload_length;
    if (session->ingress_count >= NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES) {
        return 0;
    }
    if ((uint32_t)plen > NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP - session->ingress_bytes) {
        return 0;
    }
    if (plen > 0u && view->payload == NULL) {
        return 0;
    }
    slot = (session->ingress_head + session->ingress_count)
        % NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES;
    e = &session->ingress[slot];
    e->type = view->type;
    e->reserved0 = 0u;
    e->flags = view->flags;
    e->stream_or_cell_id = view->stream_or_cell_id;
    e->sequence = view->sequence;
    e->payload_length = plen;
    e->payload_off = (uint16_t)session->ingress_bytes;
    if (plen > 0u) {
        (void)memcpy(session->ingress_pool + session->ingress_bytes, view->payload, plen);
        session->ingress_bytes += plen;
    }
    session->ingress_count += 1u;
    session->stats.frames_enqueued =
        sat_add_u64(session->stats.frames_enqueued, 1u);
    update_hwm(session);
    return 1;
}

static int intent_try_enqueue(
    ninlil_ctrl_session_t *session,
    const ninlil_model_control_frame_fields_t *fields,
    uint64_t tracked_token)
{
    uint32_t slot;
    intent_entry_t *e;
    uint32_t plen;

    if (fields == NULL) {
        return 0;
    }
    plen = fields->payload.length;
    if (plen > NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES) {
        return 0;
    }
    if (session->intent_count >= NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES) {
        return 0;
    }
    if (plen > NINLIL_CTRL_SESSION_TX_INTENT_BYTE_CAP - session->intent_bytes) {
        return 0;
    }
    if (plen > 0u && fields->payload.data == NULL) {
        return 0;
    }
    if (plen == 0u && fields->payload.data != NULL) {
        return 0;
    }
    slot = (session->intent_head + session->intent_count)
        % NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES;
    e = &session->intent[slot];
    e->type = fields->type;
    e->reserved0 = 0u;
    e->flags = fields->flags;
    e->stream_or_cell_id = fields->stream_or_cell_id;
    e->sequence = fields->sequence;
    e->payload_length = (uint16_t)plen;
    e->payload_off = (uint16_t)session->intent_bytes;
    e->tracked_token = tracked_token;
    if (plen > 0u) {
        (void)memcpy(
            session->intent_pool + session->intent_bytes, fields->payload.data, plen);
        session->intent_bytes += plen;
    }
    session->intent_count += 1u;
    update_hwm(session);
    return 1;
}

static void intent_pop_head(ninlil_ctrl_session_t *session)
{
    if (session->intent_count == 0u) {
        return;
    }
    session->intent_head =
        (session->intent_head + 1u) % NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES;
    session->intent_count -= 1u;
    intent_compact(session);
    update_hwm(session);
}

/* Remove intent entry matching tracked token (at most one). */
static int intent_remove_tracked_token(
    ninlil_ctrl_session_t *session,
    uint64_t token)
{
    uint32_t i;
    uint32_t found = NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES;
    intent_entry_t order[NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES];
    uint32_t n = 0u;
    uint32_t write = 0u;

    if (token == 0u || session->intent_count == 0u) {
        return 0;
    }
    for (i = 0u; i < session->intent_count; ++i) {
        uint32_t from = (session->intent_head + i)
            % NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES;
        if (session->intent[from].tracked_token == token) {
            found = i;
        } else {
            order[n] = session->intent[from];
            n += 1u;
        }
    }
    if (found == NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES) {
        return 0;
    }
    (void)memset(session->intent, 0, sizeof(session->intent));
    session->intent_head = 0u;
    session->intent_count = n;
    for (i = 0u; i < n; ++i) {
        session->intent[i] = order[i];
    }
    for (i = 0u; i < n; ++i) {
        intent_entry_t *e = &session->intent[i];
        if (e->payload_length > 0u) {
            if (e->payload_off != write) {
                (void)memmove(
                    session->intent_pool + write,
                    session->intent_pool + e->payload_off,
                    e->payload_length);
            }
            e->payload_off = (uint16_t)write;
            write += e->payload_length;
        } else {
            e->payload_off = 0u;
        }
    }
    session->intent_bytes = write;
    update_hwm(session);
    return 1;
}

static ninlil_ctrl_session_status_t encode_intent_head_to_wire(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error)
{
    intent_entry_t *e;
    ninlil_model_control_frame_fields_t fields;
    uint32_t length = 0u;
    ninlil_status_t st;
    uint64_t tok;

    if (session->tx_wire_len != session->tx_wire_off) {
        return NINLIL_CTRL_SESSION_OK;
    }
    if (session->intent_count == 0u) {
        return NINLIL_CTRL_SESSION_OK;
    }
    e = &session->intent[session->intent_head];
    tok = e->tracked_token;
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = e->type;
    fields.flags = e->flags;
    fields.stream_or_cell_id = e->stream_or_cell_id;
    fields.sequence = e->sequence;
    if (e->payload_length == 0u) {
        fields.payload.data = NULL;
        fields.payload.length = 0u;
    } else {
        fields.payload.data = session->intent_pool + e->payload_off;
        fields.payload.length = e->payload_length;
    }
    st = ninlil_model_control_frame_encode(
        &fields, session->tx_wire, (uint32_t)sizeof(session->tx_wire), &length);
    if (st != NINLIL_OK) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "encode failed");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    session->tx_wire_len = length;
    session->tx_wire_off = 0u;
    session->tx_wire_tracked_token = tok;
    if (tok != 0u && session->tracked_token == tok
        && session->tracked_phase == TRACKED_PHASE_INTENT) {
        session->tracked_phase = TRACKED_PHASE_WIRE;
    }
    intent_pop_head(session);
    update_hwm(session);
    return NINLIL_CTRL_SESSION_OK;
}

static void mark_tracked_raw_accepted_current(ninlil_ctrl_session_t *session)
{
    if (session->tx_wire_tracked_token != 0u
        && session->tracked_token == session->tx_wire_tracked_token
        && (session->tracked_phase == TRACKED_PHASE_WIRE
            || session->tracked_phase == TRACKED_PHASE_INTENT)) {
        session->tracked_phase = TRACKED_PHASE_TERMINAL;
        session->tracked_resolution =
            NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH;
    }
    session->tx_wire_tracked_token = 0u;
}

static ninlil_ctrl_session_status_t flush_tx_wire(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error)
{
    ninlil_byte_stream_status_t st;
    ninlil_byte_stream_error_t serr;
    uint32_t accepted = 0u;
    uint32_t remain;
    ninlil_ctrl_session_status_t ticket;
    int full_ok;
    int partial_shape;

    if (session->tx_wire_off >= session->tx_wire_len) {
        session->tx_wire_len = 0u;
        session->tx_wire_off = 0u;
        session->tx_wire_tracked_token = 0u;
        return NINLIL_CTRL_SESSION_OK;
    }
    remain = session->tx_wire_len - session->tx_wire_off;
    (void)memset(&serr, 0, sizeof(serr));
    accepted = 0u;
    st = session->stream->ops->write(
        session->stream,
        session->tx_wire + session->tx_wire_off,
        remain,
        &accepted,
        &serr);
    if (st == NINLIL_BYTE_STREAM_WRONG_OWNER) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_WRONG_OWNER,
            NINLIL_CTRL_SESSION_STAGE_OWNER,
            st,
            "stream wrong owner on write");
        return NINLIL_CTRL_SESSION_WRONG_OWNER;
    }

    /* Exact all-or-none only: OK with accepted == remain. */
    full_ok = (st == NINLIL_BYTE_STREAM_OK && accepted == remain) ? 1 : 0;
    /*
     * Any accepted>0 that is not exact full all-or-none OK is indeterminate:
     * partial OK (accepted < remain), OK with accepted > remain (illegal
     * over-report), WOULD_BLOCK accepted!=0, and non-OK / CLOSED /
     * LINK_DOWN / IO_ERROR with accepted>0. Never FENCED_UNACCEPTED.
     */
    partial_shape = (accepted > 0u && full_ok == 0) ? 1 : 0;

    /*
     * Full C1 accept + post ticket mismatch: save accept fact before any
     * queue clear / fence so resolution is RAW_ACCEPTED_THEN_FENCED (never
     * misreported as FENCED_UNACCEPTED).
     */
    if (full_ok) {
        /* Pre-save accept fact while phase/wire token still intact. */
        if (session->tx_wire_tracked_token != 0u
            && session->tracked_token == session->tx_wire_tracked_token
            && (session->tracked_phase == TRACKED_PHASE_WIRE
                || session->tracked_phase == TRACKED_PHASE_INTENT)) {
            session->tracked_phase = TRACKED_PHASE_TERMINAL;
            session->tracked_resolution =
                NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED;
        }
        ticket = validate_link_generation_ticket(
            session,
            NINLIL_CTRL_SESSION_STAGE_TX,
            out_error,
            NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED);
        if (ticket != NINLIL_CTRL_SESSION_OK) {
            /* Terminal already RAW_ACCEPTED_THEN_FENCED if tracked; keep it. */
            return ticket;
        }
        /* Ticket matched current epoch: upgrade to RAW_ACCEPTED_CURRENT. */
        session->tx_wire_len = 0u;
        session->tx_wire_off = 0u;
        if (session->tracked_phase == TRACKED_PHASE_TERMINAL
            && session->tracked_resolution
                == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED) {
            session->tracked_resolution =
                NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH;
            session->tx_wire_tracked_token = 0u;
        } else {
            mark_tracked_raw_accepted_current(session);
        }
        session->stats.tx_bytes_written =
            sat_add_u64_u32(session->stats.tx_bytes_written, accepted);
        session->stats.tx_accepts = sat_add_u64(session->stats.tx_accepts, 1u);
        update_hwm(session);
        clear_error(&session->last_error);
        if (out_error != NULL) {
            clear_error(out_error);
        }
        return NINLIL_CTRL_SESSION_OK;
    }

    if (partial_shape) {
        const char *phint;

        session->stats.tx_partial_ok_fences =
            sat_add_u64(session->stats.tx_partial_ok_fences, 1u);
        if (st == NINLIL_BYTE_STREAM_WOULD_BLOCK) {
            phint = "WOULD_BLOCK with accepted!=0";
        } else if (st == NINLIL_BYTE_STREAM_OK && accepted > remain) {
            phint = "C1 OK accepted>requested protocol violation";
        } else if (st == NINLIL_BYTE_STREAM_OK) {
            phint = "C1 partial OK protocol violation";
        } else {
            phint = "non-OK write with accepted>0 (indeterminate)";
        }
        fence_session(
            session,
            NINLIL_CTRL_SESSION_IO_ERROR,
            NINLIL_CTRL_SESSION_STAGE_TX,
            st,
            phint,
            out_error,
            NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL);
        return NINLIL_CTRL_SESSION_IO_ERROR;
    }

    /* accepted == 0 path: ticket before treating residual / fence. */
    ticket = validate_link_generation_ticket(
        session,
        NINLIL_CTRL_SESSION_STAGE_TX,
        out_error,
        NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    if (ticket != NINLIL_CTRL_SESSION_OK) {
        return ticket;
    }

    if (st == NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        session->stats.tx_would_block =
            sat_add_u64(session->stats.tx_would_block, 1u);
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_WOULD_BLOCK,
            NINLIL_CTRL_SESSION_STAGE_TX,
            st,
            0u,
            "tx would block");
        return NINLIL_CTRL_SESSION_WOULD_BLOCK;
    }
    if (st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN || st == NINLIL_BYTE_STREAM_CLOSED) {
        session->stats.link_down_fences =
            sat_add_u64(session->stats.link_down_fences, 1u);
        fence_session(
            session,
            map_stream_status(st),
            NINLIL_CTRL_SESSION_STAGE_TX,
            st,
            "link down during tx",
            out_error,
            NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
        return map_stream_status(st);
    }
    fence_session(
        session,
        NINLIL_CTRL_SESSION_IO_ERROR,
        NINLIL_CTRL_SESSION_STAGE_TX,
        st,
        "tx io error",
        out_error,
        NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    return NINLIL_CTRL_SESSION_IO_ERROR;
}

static ninlil_ctrl_session_status_t feed_and_enqueue(
    ninlil_ctrl_session_t *session,
    const uint8_t *data,
    uint32_t length,
    ninlil_ctrl_session_error_t *out_error)
{
    uint32_t offset = 0u;
    uint32_t guard = 0u;

    while (offset < length && guard < 64u) {
        uint32_t consumed = 0u;
        ninlil_model_control_frame_result_t result =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        ninlil_status_t st;

        ++guard;
        st = ninlil_model_control_frame_parser_feed(
            &session->parser,
            data + offset,
            length - offset,
            &consumed,
            &result);
        if (st != NINLIL_OK) {
            set_error_sticky(
                session,
                out_error,
                NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
                NINLIL_CTRL_SESSION_STAGE_RX,
                NINLIL_BYTE_STREAM_OK,
                (uint32_t)result,
                "parser feed invalid");
            return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
        }
        if (consumed == 0u && !session->parser.frame_ready) {
            break;
        }
        offset += consumed;
        if (session->parser.frame_ready) {
            if (!ingress_try_enqueue(session, &session->parser.last_frame)) {
                session->stats.frames_dropped_ingress_full = sat_add_u64(
                    session->stats.frames_dropped_ingress_full, 1u);
            }
            session->parser.frame_ready = 0u;
        }
    }
    /*
     * Guard exhausted with residual input: must not silent-drop bytes.
     * Under claim: RX-only cold + structured status, stay BOUND.
     * Legacy: fail-closed continuity fence.
     */
    if (offset < length) {
        if (session->epoch_claimed != 0u) {
            rx_only_cold_apply(session, NULL, NULL);
            set_error_sticky(
                session,
                out_error,
                NINLIL_CTRL_SESSION_IO_ERROR,
                NINLIL_CTRL_SESSION_STAGE_RX,
                NINLIL_BYTE_STREAM_OK,
                0u,
                "feed guard residual not consumed (rx cold under claim)");
            return NINLIL_CTRL_SESSION_IO_ERROR;
        }
        fence_session(
            session,
            NINLIL_CTRL_SESSION_IO_ERROR,
            NINLIL_CTRL_SESSION_STAGE_RX,
            NINLIL_BYTE_STREAM_OK,
            "feed guard residual not consumed",
            out_error,
            NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
        return NINLIL_CTRL_SESSION_IO_ERROR;
    }
    return NINLIL_CTRL_SESSION_OK;
}

static ninlil_ctrl_session_status_t handle_rx_overflow(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_stage_t stage,
    ninlil_byte_stream_status_t stream_status,
    const char *hint,
    ninlil_ctrl_session_error_t *out_error)
{
    if (session->epoch_claimed != 0u
        && session->state == NINLIL_CTRL_SESSION_STATE_BOUND) {
        /*
         * Claimed: RX-only cold, stay BOUND, TX/token preserved.
         * Do NOT increment rx_overflow_fences — that counter means legacy
         * full continuity fence only (separated from logical_rx_colds).
         */
        rx_only_cold_apply(session, NULL, NULL);
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_RX_OVERFLOW,
            stage,
            stream_status,
            0u,
            hint);
        return NINLIL_CTRL_SESSION_RX_OVERFLOW;
    }
    session->stats.rx_overflow_fences =
        sat_add_u64(session->stats.rx_overflow_fences, 1u);
    fence_session(
        session,
        NINLIL_CTRL_SESSION_RX_OVERFLOW,
        stage,
        stream_status,
        hint,
        out_error,
        NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    return NINLIL_CTRL_SESSION_RX_OVERFLOW;
}

static ninlil_ctrl_session_status_t pump_rx(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error)
{
    uint32_t spins;
    const uint32_t cap = (uint32_t)sizeof(session->rx_chunk);

    for (spins = 0u; spins < 32u; ++spins) {
        ninlil_byte_stream_status_t st;
        ninlil_byte_stream_error_t serr;
        uint32_t n = 0u;
        ninlil_ctrl_session_status_t ticket;

        (void)memset(&serr, 0, sizeof(serr));
        st = session->stream->ops->read(
            session->stream,
            session->rx_chunk,
            cap,
            &n,
            &serr);
        if (st == NINLIL_BYTE_STREAM_WRONG_OWNER) {
            set_error_out_only(
                out_error,
                NINLIL_CTRL_SESSION_WRONG_OWNER,
                NINLIL_CTRL_SESSION_STAGE_OWNER,
                st,
                "stream wrong owner on read");
            return NINLIL_CTRL_SESSION_WRONG_OWNER;
        }

        /* Ticket before parse/enqueue of any read bytes. */
        ticket = validate_link_generation_ticket(
            session,
            NINLIL_CTRL_SESSION_STAGE_RX,
            out_error,
            NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
        if (ticket != NINLIL_CTRL_SESSION_OK) {
            return ticket;
        }

        /* Malformed C1 shapes: fail-closed before using n. */
        if (st == NINLIL_BYTE_STREAM_OK && n > cap) {
            if (session->epoch_claimed != 0u) {
                rx_only_cold_apply(session, NULL, NULL);
                set_error_sticky(
                    session,
                    out_error,
                    NINLIL_CTRL_SESSION_IO_ERROR,
                    NINLIL_CTRL_SESSION_STAGE_RX,
                    st,
                    0u,
                    "read OK length > capacity (rx cold under claim)");
                return NINLIL_CTRL_SESSION_IO_ERROR;
            }
            fence_session(
                session,
                NINLIL_CTRL_SESSION_IO_ERROR,
                NINLIL_CTRL_SESSION_STAGE_RX,
                st,
                "read OK length > capacity",
                out_error,
                NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
            return NINLIL_CTRL_SESSION_IO_ERROR;
        }
        if (st == NINLIL_BYTE_STREAM_WOULD_BLOCK && n != 0u) {
            if (session->epoch_claimed != 0u) {
                rx_only_cold_apply(session, NULL, NULL);
                set_error_sticky(
                    session,
                    out_error,
                    NINLIL_CTRL_SESSION_IO_ERROR,
                    NINLIL_CTRL_SESSION_STAGE_RX,
                    st,
                    0u,
                    "read WOULD_BLOCK with length!=0 (rx cold under claim)");
                return NINLIL_CTRL_SESSION_IO_ERROR;
            }
            fence_session(
                session,
                NINLIL_CTRL_SESSION_IO_ERROR,
                NINLIL_CTRL_SESSION_STAGE_RX,
                st,
                "read WOULD_BLOCK with length!=0",
                out_error,
                NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
            return NINLIL_CTRL_SESSION_IO_ERROR;
        }

        if (st == NINLIL_BYTE_STREAM_RX_OVERFLOW) {
            return handle_rx_overflow(
                session,
                NINLIL_CTRL_SESSION_STAGE_RX,
                st,
                "rx overflow continuity fence",
                out_error);
        }
        if (st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN || st == NINLIL_BYTE_STREAM_CLOSED) {
            session->stats.link_down_fences =
                sat_add_u64(session->stats.link_down_fences, 1u);
            fence_session(
                session,
                map_stream_status(st),
                NINLIL_CTRL_SESSION_STAGE_RX,
                st,
                "link down during rx",
                out_error,
                NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
            return map_stream_status(st);
        }
        if (st == NINLIL_BYTE_STREAM_WOULD_BLOCK) {
            /* n==0 already enforced; no bytes available. */
            return NINLIL_CTRL_SESSION_OK;
        }
        if (st != NINLIL_BYTE_STREAM_OK) {
            fence_session(
                session,
                NINLIL_CTRL_SESSION_IO_ERROR,
                NINLIL_CTRL_SESSION_STAGE_RX,
                st,
                "rx io error",
                out_error,
                NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
            return NINLIL_CTRL_SESSION_IO_ERROR;
        }
        if (n == 0u) {
            return NINLIL_CTRL_SESSION_OK;
        }
        session->stats.rx_bytes_read =
            sat_add_u64_u32(session->stats.rx_bytes_read, n);
        if (feed_and_enqueue(session, session->rx_chunk, n, out_error)
            != NINLIL_CTRL_SESSION_OK) {
            if (session->state == NINLIL_CTRL_SESSION_STATE_FENCED) {
                return NINLIL_CTRL_SESSION_IO_ERROR;
            }
            /* Under claim, feed may RX-cold and stay BOUND. */
            if (session->epoch_claimed != 0u
                && session->state == NINLIL_CTRL_SESSION_STATE_BOUND) {
                return NINLIL_CTRL_SESSION_IO_ERROR;
            }
            return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
        }
        if (session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
            return NINLIL_CTRL_SESSION_IO_ERROR;
        }
    }
    return NINLIL_CTRL_SESSION_OK;
}

size_t ninlil_ctrl_session_object_size(void)
{
    return sizeof(struct ninlil_ctrl_session);
}

size_t ninlil_ctrl_session_object_align(void)
{
    return NINLIL_CTRL_SESSION_OBJECT_ALIGN;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_init(
    void *storage,
    size_t storage_bytes,
    ninlil_ctrl_session_t **out_session)
{
    ninlil_ctrl_session_t *session;
    uintptr_t addr;

    if (out_session == NULL) {
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    *out_session = NULL;
    if (storage == NULL || storage_bytes < sizeof(struct ninlil_ctrl_session)) {
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    addr = (uintptr_t)storage;
    if ((addr % NINLIL_CTRL_SESSION_OBJECT_ALIGN) != 0u) {
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    session = as_session(storage);
    (void)memset(session, 0, sizeof(*session));
    session->magic = MAGIC;
    session->state = NINLIL_CTRL_SESSION_STATE_IDLE;
    session->epoch_next = 1u;
    session->token_next = 1u;
    session->tracked_phase = TRACKED_PHASE_NONE;
    if (ninlil_model_control_frame_parser_init(
            &session->parser,
            session->parser_payload,
            (uint32_t)sizeof(session->parser_payload))
        != NINLIL_OK) {
        session->magic = 0u;
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    *out_session = session;
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_init_object(
    ninlil_ctrl_session_object_t *object,
    ninlil_ctrl_session_t **out_session)
{
    if (object == NULL) {
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    return ninlil_ctrl_session_init(object->bytes, sizeof(object->bytes), out_session);
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_bind(
    ninlil_ctrl_session_t *session,
    ninlil_byte_stream_t *stream,
    ninlil_ctrl_session_error_t *out_error)
{
    ninlil_byte_stream_link_t link;
    uint64_t gen;
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    ninlil_byte_stream_error_t serr;
    ninlil_byte_stream_status_t st;

    clear_error(out_error);
    if (!is_live(session) || stream == NULL || stream->ops == NULL
        || stream->ops->link == NULL || stream->ops->link_generation == NULL
        || stream->ops->read == NULL || stream->ops->write == NULL
        || stream->ops->poll == NULL) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_BIND,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "null session or stream ops");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->state == NINLIL_CTRL_SESSION_STATE_BOUND) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_BIND,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "already bound");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->state != NINLIL_CTRL_SESSION_STATE_IDLE
        && session->state != NINLIL_CTRL_SESSION_STATE_FENCED) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_BIND,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "bad state");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }

    /*
     * Owner probe first: zero-time poll before owner-only link/generation
     * observers. WRONG_OWNER: no bind, no session mutation.
     */
    (void)memset(&serr, 0, sizeof(serr));
    st = stream->ops->poll(stream, 0u, &events, &serr);
    if (st == NINLIL_BYTE_STREAM_WRONG_OWNER) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_WRONG_OWNER,
            NINLIL_CTRL_SESSION_STAGE_OWNER,
            st,
            "wrong owner on bind poll");
        return NINLIL_CTRL_SESSION_WRONG_OWNER;
    }
    if (st != NINLIL_BYTE_STREAM_OK && st != NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        set_error_sticky(
            session,
            out_error,
            map_stream_status(st),
            NINLIL_CTRL_SESSION_STAGE_BIND,
            st,
            0u,
            "bind poll failed");
        return map_stream_status(st);
    }

    link = stream->ops->link(stream);
    gen = stream->ops->link_generation(stream);
    if (link != NINLIL_BYTE_STREAM_LINK_UP || gen == 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_BIND,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "stream not UP with generation");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }

    session->stream = stream;
    session->bound_generation = gen;
    session->state = NINLIL_CTRL_SESSION_STATE_BOUND;
    invalidate_epoch_claim(session);
    discard_queues(session);
    commit_parser_stats_and_reset(session);
    if (session->had_prior_fence != 0u) {
        session->stats.rebind_count =
            sat_add_u64(session->stats.rebind_count, 1u);
    }
    session->stats.bind_count = sat_add_u64(session->stats.bind_count, 1u);
    clear_error(&session->last_error);
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_unbind(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error)
{
    clear_error(out_error);
    if (!is_live(session)) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_UNBIND,
            NINLIL_BYTE_STREAM_OK,
            "null session");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->state == NINLIL_CTRL_SESSION_STATE_IDLE) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_UNBIND,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "idle");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->state == NINLIL_CTRL_SESSION_STATE_FENCED
        && session->stream == NULL) {
        if (out_error != NULL) {
            clear_error(out_error);
        }
        return NINLIL_CTRL_SESSION_OK;
    }
    session->stats.unbind_count = sat_add_u64(session->stats.unbind_count, 1u);
    fence_session(
        session,
        NINLIL_CTRL_SESSION_CONTINUITY_LOST,
        NINLIL_CTRL_SESSION_STAGE_UNBIND,
        NINLIL_BYTE_STREAM_OK,
        "explicit unbind",
        out_error,
        NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_state_t ninlil_ctrl_session_state(
    const ninlil_ctrl_session_t *session)
{
    if (!is_live(session)) {
        return NINLIL_CTRL_SESSION_STATE_IDLE;
    }
    return session->state;
}

uint64_t ninlil_ctrl_session_bound_generation(
    const ninlil_ctrl_session_t *session)
{
    if (!is_live(session) || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return 0u;
    }
    return session->bound_generation;
}

int ninlil_ctrl_session_logical_epoch_is_claimed(
    const ninlil_ctrl_session_t *session)
{
    if (!is_live(session) || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return 0;
    }
    return session->epoch_claimed != 0u ? 1 : 0;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_pump(
    ninlil_ctrl_session_t *session,
    uint32_t timeout_ms,
    ninlil_ctrl_session_error_t *out_error)
{
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    ninlil_byte_stream_error_t serr;
    ninlil_byte_stream_status_t st;
    ninlil_ctrl_session_status_t rs;
    ninlil_ctrl_session_status_t ticket;
    int saw_would_block = 0;

    clear_error(out_error);
    if (!is_live(session)) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_PUMP,
            NINLIL_BYTE_STREAM_OK,
            "null session");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_CTRL_SESSION_STATE_BOUND || session->stream == NULL) {
        set_error_sticky(
            session,
            out_error,
            (session->state == NINLIL_CTRL_SESSION_STATE_FENCED)
                ? NINLIL_CTRL_SESSION_CONTINUITY_LOST
                : NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_PUMP,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "not bound");
        return (session->state == NINLIL_CTRL_SESSION_STATE_FENCED)
            ? NINLIL_CTRL_SESSION_CONTINUITY_LOST
            : NINLIL_CTRL_SESSION_INVALID_STATE;
    }

    /*
     * Owner check first via status-returning poll. Do not call link/generation
     * observers before this, and do not increment pump_calls on WRONG_OWNER.
     */
    (void)memset(&serr, 0, sizeof(serr));
    st = session->stream->ops->poll(session->stream, timeout_ms, &events, &serr);
    if (st == NINLIL_BYTE_STREAM_WRONG_OWNER) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_WRONG_OWNER,
            NINLIL_CTRL_SESSION_STAGE_OWNER,
            st,
            "stream wrong owner on poll");
        return NINLIL_CTRL_SESSION_WRONG_OWNER;
    }

    session->stats.pump_calls = sat_add_u64(session->stats.pump_calls, 1u);

    ticket = validate_link_generation_ticket(
        session,
        NINLIL_CTRL_SESSION_STAGE_PUMP,
        out_error,
        NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
    if (ticket != NINLIL_CTRL_SESSION_OK) {
        return ticket;
    }

    if (st == NINLIL_BYTE_STREAM_RX_OVERFLOW
        || (events & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) != 0u) {
        return handle_rx_overflow(
            session,
            NINLIL_CTRL_SESSION_STAGE_PUMP,
            NINLIL_BYTE_STREAM_RX_OVERFLOW,
            "rx overflow event",
            out_error);
    }
    if (st == NINLIL_BYTE_STREAM_ERR_LINK_DOWN
        || (events & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u) {
        session->stats.link_down_fences =
            sat_add_u64(session->stats.link_down_fences, 1u);
        fence_session(
            session,
            NINLIL_CTRL_SESSION_ERR_LINK_DOWN,
            NINLIL_CTRL_SESSION_STAGE_PUMP,
            NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
            "link down event",
            out_error,
            NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
        return NINLIL_CTRL_SESSION_ERR_LINK_DOWN;
    }
    if (st != NINLIL_BYTE_STREAM_OK && st != NINLIL_BYTE_STREAM_WOULD_BLOCK) {
        if (st == NINLIL_BYTE_STREAM_CLOSED) {
            session->stats.link_down_fences =
                sat_add_u64(session->stats.link_down_fences, 1u);
            fence_session(
                session,
                NINLIL_CTRL_SESSION_CLOSED,
                NINLIL_CTRL_SESSION_STAGE_PUMP,
                st,
                "poll closed",
                out_error,
                NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
            return NINLIL_CTRL_SESSION_CLOSED;
        }
        fence_session(
            session,
            NINLIL_CTRL_SESSION_IO_ERROR,
            NINLIL_CTRL_SESSION_STAGE_PUMP,
            st,
            "poll io error",
            out_error,
            NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED);
        return NINLIL_CTRL_SESSION_IO_ERROR;
    }

    rs = pump_rx(session, out_error);
    if (rs != NINLIL_CTRL_SESSION_OK) {
        return rs;
    }
    if (session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return NINLIL_CTRL_SESSION_CONTINUITY_LOST;
    }

    rs = encode_intent_head_to_wire(session, out_error);
    if (rs != NINLIL_CTRL_SESSION_OK) {
        return rs;
    }
    if (session->tx_wire_len > session->tx_wire_off
        || session->intent_count > 0u) {
        rs = flush_tx_wire(session, out_error);
        if (rs == NINLIL_CTRL_SESSION_WOULD_BLOCK) {
            saw_would_block = 1;
        } else if (rs != NINLIL_CTRL_SESSION_OK) {
            return rs;
        } else if (session->state == NINLIL_CTRL_SESSION_STATE_BOUND
            && session->tx_wire_len == 0u
            && session->intent_count > 0u) {
            rs = encode_intent_head_to_wire(session, out_error);
            if (rs != NINLIL_CTRL_SESSION_OK) {
                return rs;
            }
            if (session->tx_wire_len > 0u) {
                rs = flush_tx_wire(session, out_error);
                if (rs == NINLIL_CTRL_SESSION_WOULD_BLOCK) {
                    saw_would_block = 1;
                } else if (rs != NINLIL_CTRL_SESSION_OK) {
                    return rs;
                }
            }
        }
    }

    update_hwm(session);
    if (saw_would_block) {
        return NINLIL_CTRL_SESSION_WOULD_BLOCK;
    }
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_submit_tx(
    ninlil_ctrl_session_t *session,
    const ninlil_model_control_frame_fields_t *fields,
    ninlil_ctrl_session_error_t *out_error)
{
    clear_error(out_error);
    if (!is_live(session) || fields == NULL) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "null");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->state == NINLIL_CTRL_SESSION_STATE_FENCED) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_CONTINUITY_LOST,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "fenced");
        return NINLIL_CTRL_SESSION_CONTINUITY_LOST;
    }
    if (session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "not bound");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->epoch_claimed != 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "logical epoch claimed; use tracked_submit_tx");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (!ninlil_model_control_frame_type_is_known(fields->type)
        || fields->flags != 0u
        || fields->payload.length > NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES
        || (fields->payload.length == 0u && fields->payload.data != NULL)
        || (fields->payload.length > 0u && fields->payload.data == NULL)) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "bad fields");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (!intent_try_enqueue(session, fields, 0u)) {
        session->stats.tx_would_block =
            sat_add_u64(session->stats.tx_would_block, 1u);
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_WOULD_BLOCK,
            NINLIL_CTRL_SESSION_STAGE_TX,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "tx intent full");
        return NINLIL_CTRL_SESSION_WOULD_BLOCK;
    }
    session->stats.tx_submits = sat_add_u64(session->stats.tx_submits, 1u);
    update_hwm(session);
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_logical_epoch_begin(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_logical_epoch_t *out_epoch,
    ninlil_ctrl_session_error_t *out_error)
{
    uint64_t id;

    clear_error(out_error);
    if (out_epoch != NULL) {
        out_epoch->epoch_id = 0u;
        out_epoch->bound_stream_generation = 0u;
    }
    if (!is_live(session) || out_epoch == NULL) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            "null");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        set_error_sticky(
            session,
            out_error,
            (session->state == NINLIL_CTRL_SESSION_STATE_FENCED)
                ? NINLIL_CTRL_SESSION_CONTINUITY_LOST
                : NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "not bound for epoch begin");
        return (session->state == NINLIL_CTRL_SESSION_STATE_FENCED)
            ? NINLIL_CTRL_SESSION_CONTINUITY_LOST
            : NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->epoch_claimed != 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "epoch already claimed");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->intent_count != 0u || session->tx_wire_len != 0u
        || session->tx_wire_off != 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "dirty TX blocks epoch begin");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->tracked_phase != TRACKED_PHASE_NONE
        || session->tracked_token != 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "unresolved tracked token (incl. terminal) blocks epoch begin");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->epoch_next == 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_EPOCH_EXHAUSTED,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "epoch wrap fail-closed");
        return NINLIL_CTRL_SESSION_EPOCH_EXHAUSTED;
    }

    id = session->epoch_next;
    if (session->epoch_next == UINT64_MAX) {
        session->epoch_next = 0u; /* exhausted after this mint */
    } else {
        session->epoch_next += 1u;
    }
    session->epoch_claimed = 1u;
    session->epoch_active = id;
    session->epoch_bound_gen = session->bound_generation;
    out_epoch->epoch_id = id;
    out_epoch->bound_stream_generation = session->bound_generation;

    /* Begin RX cold: parser + ingress only. */
    rx_only_cold_apply(session, NULL, NULL);
    session->stats.logical_epoch_begins =
        sat_add_u64(session->stats.logical_epoch_begins, 1u);
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_logical_epoch_end(
    ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch,
    ninlil_ctrl_session_error_t *out_error)
{
    clear_error(out_error);
    if (!is_live(session) || epoch == NULL) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            "null");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (!epoch_is_active_match(session, epoch)) {
        return reject_stale_epoch(
            out_error,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            "stale epoch on end");
    }
    /*
     * Full resolution required: no pending intent/wire and no unconsumed
     * terminal (token must be zero and phase NONE).
     */
    if (session->tracked_phase != TRACKED_PHASE_NONE
        || session->tracked_token != 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_EPOCH,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "unresolved tracked token (incl. terminal) blocks epoch end");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    invalidate_epoch_claim(session);
    session->stats.logical_epoch_ends =
        sat_add_u64(session->stats.logical_epoch_ends, 1u);
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_tracked_submit_tx(
    ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch,
    const ninlil_model_control_frame_fields_t *fields,
    ninlil_ctrl_session_tx_token_t *out_token,
    ninlil_ctrl_session_error_t *out_error)
{
    uint64_t tok;

    clear_error(out_error);
    if (out_token != NULL) {
        *out_token = 0u;
    }
    if (!is_live(session) || epoch == NULL || fields == NULL || out_token == NULL) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            "null");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (!epoch_is_active_match(session, epoch)) {
        return reject_stale_epoch(
            out_error,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            "stale epoch on tracked submit");
    }
    if (session->tracked_phase != TRACKED_PHASE_NONE) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_TX_BUSY,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "tracked raw outstanding max 1");
        return NINLIL_CTRL_SESSION_TX_BUSY;
    }
    if (session->token_next == 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_TOKEN_EXHAUSTED,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "token wrap fail-closed");
        return NINLIL_CTRL_SESSION_TOKEN_EXHAUSTED;
    }
    if (!ninlil_model_control_frame_type_is_known(fields->type)
        || fields->flags != 0u
        || fields->payload.length > NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES
        || (fields->payload.length == 0u && fields->payload.data != NULL)
        || (fields->payload.length > 0u && fields->payload.data == NULL)) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "bad fields");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }

    tok = session->token_next;
    if (session->token_next == UINT64_MAX) {
        session->token_next = 0u;
    } else {
        session->token_next += 1u;
    }
    if (!intent_try_enqueue(session, fields, tok)) {
        /* Roll back token mint: keep monotonic non-reuse (do not recycle). */
        session->stats.tx_would_block =
            sat_add_u64(session->stats.tx_would_block, 1u);
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_WOULD_BLOCK,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "tx intent full");
        return NINLIL_CTRL_SESSION_WOULD_BLOCK;
    }
    session->tracked_phase = TRACKED_PHASE_INTENT;
    session->tracked_token = tok;
    session->tracked_resolution = NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    *out_token = tok;
    session->stats.tx_submits = sat_add_u64(session->stats.tx_submits, 1u);
    session->stats.tracked_submits =
        sat_add_u64(session->stats.tracked_submits, 1u);
    update_hwm(session);
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_tx_resolve(
    ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_tx_token_t token,
    int cancel_if_pending,
    ninlil_ctrl_session_tx_resolution_t *out_resolution,
    ninlil_ctrl_session_error_t *out_error)
{
    ninlil_ctrl_session_tx_resolution_t res;

    clear_error(out_error);
    if (out_resolution != NULL) {
        *out_resolution = NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    }
    if (!is_live(session) || out_resolution == NULL || token == 0u) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            "null or zero token");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->tracked_phase == TRACKED_PHASE_NONE
        || session->tracked_token != token) {
        /* Stale / already consumed / wrong token: zero mutation. */
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_STALE_EPOCH,
            NINLIL_CTRL_SESSION_STAGE_TRACKED,
            NINLIL_BYTE_STREAM_OK,
            "unknown or already resolved token");
        return NINLIL_CTRL_SESSION_STALE_EPOCH;
    }

    if (session->tracked_phase == TRACKED_PHASE_TERMINAL) {
        res = session->tracked_resolution;
        *out_resolution = res;
        /* Consume terminal token slot. */
        session->tracked_phase = TRACKED_PHASE_NONE;
        session->tracked_token = 0u;
        session->tracked_resolution = NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
        session->stats.tracked_resolves =
            sat_add_u64(session->stats.tracked_resolves, 1u);
        if (out_error != NULL) {
            clear_error(out_error);
        }
        return NINLIL_CTRL_SESSION_OK;
    }

    /* Pending INTENT or WIRE. */
    if (cancel_if_pending != 0) {
        if (session->tracked_phase == TRACKED_PHASE_INTENT) {
            (void)intent_remove_tracked_token(session, token);
        } else if (session->tracked_phase == TRACKED_PHASE_WIRE) {
            session->tx_wire_len = 0u;
            session->tx_wire_off = 0u;
            session->tx_wire_tracked_token = 0u;
            (void)memset(session->tx_wire, 0, sizeof(session->tx_wire));
        }
        update_hwm(session);
        res = NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED;
        *out_resolution = res;
        session->tracked_phase = TRACKED_PHASE_NONE;
        session->tracked_token = 0u;
        session->tracked_resolution = NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
        session->stats.tracked_cancels =
            sat_add_u64(session->stats.tracked_cancels, 1u);
        session->stats.tracked_resolves =
            sat_add_u64(session->stats.tracked_resolves, 1u);
        if (out_error != NULL) {
            clear_error(out_error);
        }
        return NINLIL_CTRL_SESSION_OK;
    }

    *out_resolution = NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

/*
 * Map closed RX-cold reason → sticky status. Never accepts free status_t
 * values (OK / STALE_EPOCH / …) as a reason.
 */
static int rx_cold_reason_to_status(
    ninlil_ctrl_session_rx_cold_reason_t reason,
    ninlil_ctrl_session_status_t *out_status,
    const char **out_hint)
{
    if (out_status == NULL || out_hint == NULL) {
        return 0;
    }
    switch (reason) {
    case NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT:
        *out_status = NINLIL_CTRL_SESSION_CONTINUITY_LOST;
        *out_hint = "logical_rx_cold explicit";
        return 1;
    case NINLIL_CTRL_SESSION_RX_COLD_REASON_RX_OVERFLOW:
        *out_status = NINLIL_CTRL_SESSION_RX_OVERFLOW;
        *out_hint = "logical_rx_cold rx_overflow";
        return 1;
    case NINLIL_CTRL_SESSION_RX_COLD_REASON_PARSER_CONTINUITY:
        *out_status = NINLIL_CTRL_SESSION_IO_ERROR;
        *out_hint = "logical_rx_cold parser continuity";
        return 1;
    case NINLIL_CTRL_SESSION_RX_COLD_REASON_FEED_GUARD:
        *out_status = NINLIL_CTRL_SESSION_IO_ERROR;
        *out_hint = "logical_rx_cold feed guard";
        return 1;
    default:
        return 0;
    }
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_logical_rx_cold(
    ninlil_ctrl_session_t *session,
    const ninlil_ctrl_session_logical_epoch_t *epoch,
    ninlil_ctrl_session_rx_cold_reason_t reason,
    uint32_t *out_dropped_frames,
    uint32_t *out_dropped_bytes,
    ninlil_ctrl_session_error_t *out_error)
{
    uint32_t df = 0u;
    uint32_t db = 0u;
    ninlil_ctrl_session_status_t sticky_status =
        NINLIL_CTRL_SESSION_CONTINUITY_LOST;
    const char *hint = "logical_rx_cold";

    clear_error(out_error);
    if (out_dropped_frames != NULL) {
        *out_dropped_frames = 0u;
    }
    if (out_dropped_bytes != NULL) {
        *out_dropped_bytes = 0u;
    }
    if (!is_live(session) || epoch == NULL) {
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_RX_COLD,
            NINLIL_BYTE_STREAM_OK,
            "null");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (!rx_cold_reason_to_status(reason, &sticky_status, &hint)) {
        /* Closed catalog only; do not apply cold or write free status. */
        set_error_out_only(
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_RX_COLD,
            NINLIL_BYTE_STREAM_OK,
            "rx_cold reason not in closed catalog");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (!epoch_is_active_match(session, epoch)) {
        return reject_stale_epoch(
            out_error,
            NINLIL_CTRL_SESSION_STAGE_RX_COLD,
            "stale epoch on rx cold");
    }

    rx_only_cold_apply(session, &df, &db);
    if (out_dropped_frames != NULL) {
        *out_dropped_frames = df;
    }
    if (out_dropped_bytes != NULL) {
        *out_dropped_bytes = db;
    }
    set_error_sticky(
        session,
        out_error,
        sticky_status,
        NINLIL_CTRL_SESSION_STAGE_RX_COLD,
        NINLIL_BYTE_STREAM_OK,
        (uint32_t)reason,
        hint);
    return NINLIL_CTRL_SESSION_OK;
}

ninlil_ctrl_session_status_t ninlil_ctrl_session_take_rx(
    ninlil_ctrl_session_t *session,
    uint8_t *out_payload,
    uint32_t payload_capacity,
    ninlil_ctrl_session_frame_t *out_frame,
    ninlil_ctrl_session_error_t *out_error)
{
    ingress_entry_t *e;

    clear_error(out_error);
    if (!is_live(session) || out_frame == NULL) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
            NINLIL_CTRL_SESSION_STAGE_TAKE,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "null");
        return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
    }
    if (session->state == NINLIL_CTRL_SESSION_STATE_FENCED) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_CONTINUITY_LOST,
            NINLIL_CTRL_SESSION_STAGE_TAKE,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "fenced");
        return NINLIL_CTRL_SESSION_CONTINUITY_LOST;
    }
    if (session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_INVALID_STATE,
            NINLIL_CTRL_SESSION_STAGE_TAKE,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "not bound");
        return NINLIL_CTRL_SESSION_INVALID_STATE;
    }
    if (session->ingress_count == 0u) {
        set_error_sticky(
            session,
            out_error,
            NINLIL_CTRL_SESSION_NEED_MORE,
            NINLIL_CTRL_SESSION_STAGE_TAKE,
            NINLIL_BYTE_STREAM_OK,
            0u,
            "ingress empty");
        return NINLIL_CTRL_SESSION_NEED_MORE;
    }
    e = &session->ingress[session->ingress_head];
    if (e->payload_length > 0u) {
        if (out_payload == NULL || payload_capacity < e->payload_length) {
            set_error_sticky(
                session,
                out_error,
                NINLIL_CTRL_SESSION_INVALID_ARGUMENT,
                NINLIL_CTRL_SESSION_STAGE_TAKE,
                NINLIL_BYTE_STREAM_OK,
                0u,
                "payload capacity");
            return NINLIL_CTRL_SESSION_INVALID_ARGUMENT;
        }
        (void)memcpy(
            out_payload,
            session->ingress_pool + e->payload_off,
            e->payload_length);
        out_frame->payload = out_payload;
    } else {
        out_frame->payload = NULL;
    }
    out_frame->type = e->type;
    out_frame->flags = e->flags;
    out_frame->stream_or_cell_id = e->stream_or_cell_id;
    out_frame->sequence = e->sequence;
    out_frame->payload_length = e->payload_length;

    session->ingress_head =
        (session->ingress_head + 1u) % NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES;
    session->ingress_count -= 1u;
    ingress_compact(session);
    session->stats.frames_taken = sat_add_u64(session->stats.frames_taken, 1u);
    update_hwm(session);
    if (out_error != NULL) {
        clear_error(out_error);
    }
    return NINLIL_CTRL_SESSION_OK;
}

void ninlil_ctrl_session_stats(
    const ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    (void)memset(out_stats, 0, sizeof(*out_stats));
    if (!is_live(session)) {
        return;
    }
    fill_stats_snapshot(session, out_stats);
}

void ninlil_ctrl_session_last_error(
    const ninlil_ctrl_session_t *session,
    ninlil_ctrl_session_error_t *out_error)
{
    if (out_error == NULL) {
        return;
    }
    (void)memset(out_error, 0, sizeof(*out_error));
    if (!is_live(session)) {
        return;
    }
    *out_error = session->last_error;
}

uint32_t ninlil_ctrl_session_ingress_count(const ninlil_ctrl_session_t *session)
{
    if (!is_live(session) || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return 0u;
    }
    return session->ingress_count;
}

uint32_t ninlil_ctrl_session_tx_intent_count(const ninlil_ctrl_session_t *session)
{
    if (!is_live(session) || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return 0u;
    }
    return session->intent_count;
}

uint32_t ninlil_ctrl_session_tx_wire_residual(const ninlil_ctrl_session_t *session)
{
    if (!is_live(session) || session->state != NINLIL_CTRL_SESSION_STATE_BOUND) {
        return 0u;
    }
    if (session->tx_wire_len <= session->tx_wire_off) {
        return 0u;
    }
    return session->tx_wire_len - session->tx_wire_off;
}

#if defined(NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM)
/*
 * Host-test seam only. Compiled only when NINLIL_BUILD_TESTS=ON defines
 * NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM on ninlil_runtime_private.
 * Absent from tests-OFF / ESP production component archives.
 */
void ninlil_ctrl_session_test_force_committed_framing_stats(
    ninlil_ctrl_session_t *session,
    uint64_t frames_accepted,
    uint64_t resync_skips)
{
    if (!is_live(session)) {
        return;
    }
    session->stats.frames_accepted = frames_accepted;
    session->stats.resync_skips = resync_skips;
}

void ninlil_ctrl_session_test_force_epoch_next(
    ninlil_ctrl_session_t *session,
    uint64_t epoch_next)
{
    if (!is_live(session)) {
        return;
    }
    session->epoch_next = epoch_next;
}

void ninlil_ctrl_session_test_force_token_next(
    ninlil_ctrl_session_t *session,
    uint64_t token_next)
{
    if (!is_live(session)) {
        return;
    }
    session->token_next = token_next;
}
#endif
