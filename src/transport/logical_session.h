#ifndef NINLIL_TRANSPORT_LOGICAL_SESSION_H
#define NINLIL_TRANSPORT_LOGICAL_SESSION_H

/*
 * U4: Production-private logical control session host candidate.
 *
 * Sole owner of embedded U3 control_session (logical epoch claim, tracked TX
 * token, pump, take_rx, tracked_submit, tx_resolve) and NCL1 encode/decode.
 * External hosts MUST NOT orchestrate U3 order; external surface is
 * init / bind / step / snapshot / unbind only.
 *
 * Normative authority:
 *   docs/23-usb-radio-boundary.md §4.3.1, §5.5–§5.6.2, §7, §8, §10.1 U4
 *   Accepted ADR-0003 (compile/runtime dependency direction)
 *
 * Time (docs/23 §8.11):
 *   Liveness/retry use a host-supplied virtual monotonic clock only.
 *   Wall clock is forbidden. step() is the sole time+I/O entry: the host
 *   passes now_monotonic_ms each call. Time regression (now < last_now) or
 *   deadline arithmetic overflow → explicit status only; the entire step is
 *   exact zero mutation of state / sequences / TX actions / wire residual /
 *   counters / commit meta (not silent ignore; not partial timer-path hold).
 *   Observation of these failures is the return status — never a counter
 *   bump (a counter increment would violate zero mutation). This does not
 *   contradict §8.11 (monotonic-only; wall-clock steps must not fence).
 *
 * Cookie vs jitter entropy:
 *   cookie_rng is CSPRNG/approved random for session_cookie only.
 *   jitter_fn is a separate non-crypto source for HELLO retry ±20% only.
 *   Engine never falls back from jitter to cookie_rng (or the reverse).
 *
 * Object size:
 *   Ceiling = NINLIL_CTRL_SESSION_OBJECT_BYTES (embedded U3 storage)
 *           + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES (U4-only fixed budget).
 *   object_size() returns actual sizeof(session). _Static_assert and gate pin
 *   the composition; oversized opaque constants are not used to hide bloat.
 *
 * Nonclaims: not USB series complete / HIL / assignment / security / public ABI.
 * Constraints: fixed RAM, C11, no heap/VLA, no KGuard/platform types here.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"
#include "control_session.h"
#include "ncl1_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * U4-exclusive fixed budget (bytes), not including embedded U3 object.
 * Components (order-of-magnitude, LP64): role/state/clock ~64; sequence+session
 * ids ~48; request allocator + inflight[8] ~200; continuity notice slot ~48;
 * TX action queue meta[8] + one NCL1 encode scratch 1024 + RX take buffer 1024;
 * counters (~40×u64) ~320; tracked commit meta ~64; padding/align ~256.
 * Keep explicit; raise only with docs+gate in the same change.
 */
#define NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES ((size_t)8192u)

/* Ceiling for caller storage: embedded U3 object + U4 exclusive budget. */
#define NINLIL_LOGICAL_SESSION_OBJECT_BYTES \
    (NINLIL_CTRL_SESSION_OBJECT_BYTES + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES)
#define NINLIL_LOGICAL_SESSION_OBJECT_ALIGN ((size_t)8u)

_Static_assert(
    NINLIL_LOGICAL_SESSION_OBJECT_BYTES
        == (NINLIL_CTRL_SESSION_OBJECT_BYTES
            + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES),
    "logical session object ceiling must equal U3 embed + U4 exclusive");
_Static_assert(
    NINLIL_LOGICAL_SESSION_OBJECT_BYTES >= NINLIL_CTRL_SESSION_OBJECT_BYTES,
    "logical session ceiling must cover embedded U3 object");

/* Session inflight map (HELLO/PING only); docs/23 §4.4 / §5.5.1. */
#define NINLIL_LOGICAL_SESSION_INFLIGHT_MAX ((uint32_t)8u)
/* Fixed bounded ordinary TX action queue (continuity notice is a separate slot). */
#define NINLIL_LOGICAL_SESSION_TX_ACTION_MAX ((uint32_t)8u)
/* Cookie CSPRNG zero-redraw budget (§5.2.1). */
#define NINLIL_LOGICAL_SESSION_COOKIE_REDRAW_MAX ((uint32_t)8u)

/* Liveness / HELLO retry profile defaults (§8.11). */
#define NINLIL_LOGICAL_SESSION_PING_CADENCE_MS ((uint32_t)5000u)
#define NINLIL_LOGICAL_SESSION_PING_DISPATCH_SLACK_MS ((uint32_t)1000u)
#define NINLIL_LOGICAL_SESSION_PONG_TIMEOUT_MS ((uint32_t)2000u)
#define NINLIL_LOGICAL_SESSION_PONG_MISS_THRESHOLD ((uint32_t)3u)
#define NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS ((uint32_t)200u)
#define NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS ((uint32_t)5000u)
#define NINLIL_LOGICAL_SESSION_HELLO_BACKOFF_MULT ((uint32_t)2u)
#define NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS \
    NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS
#define NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_WINDOW_MS ((uint32_t)1000u)
#define NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_MAX ((uint32_t)8u)
#define NINLIL_LOGICAL_SESSION_LOGICAL_REJECT_FENCE_THRESHOLD ((uint32_t)32u)

typedef uint32_t ninlil_logical_session_status_t;

#define NINLIL_LOGICAL_SESSION_OK ((ninlil_logical_session_status_t)0u)
#define NINLIL_LOGICAL_SESSION_WOULD_BLOCK ((ninlil_logical_session_status_t)1u)
#define NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT \
    ((ninlil_logical_session_status_t)2u)
#define NINLIL_LOGICAL_SESSION_INVALID_STATE ((ninlil_logical_session_status_t)3u)
#define NINLIL_LOGICAL_SESSION_CAPACITY ((ninlil_logical_session_status_t)4u)
#define NINLIL_LOGICAL_SESSION_CONTINUITY_LOST \
    ((ninlil_logical_session_status_t)5u)
#define NINLIL_LOGICAL_SESSION_IO_ERROR ((ninlil_logical_session_status_t)6u)
#define NINLIL_LOGICAL_SESSION_RNG_FAIL ((ninlil_logical_session_status_t)7u)
#define NINLIL_LOGICAL_SESSION_EPOCH_EXHAUSTED \
    ((ninlil_logical_session_status_t)8u)
/*
 * now_monotonic_ms < last accepted now. step returns this with exact
 * zero mutation of the entire session object authority surface (state,
 * sequences, TX actions, wire residual, counters, commit meta). Detect
 * via return status only — no counter is incremented.
 */
#define NINLIL_LOGICAL_SESSION_TIME_REGRESSED \
    ((ninlil_logical_session_status_t)9u)
/*
 * Monotonic deadline arithmetic would overflow u64 (e.g. eligible_at + slack).
 * Fail-closed for the entire step: exact zero mutation of state / sequences /
 * TX actions / wire residual / counters / commit meta (same bar as
 * TIME_REGRESSED; not limited to a timer sub-path). Detect via return
 * status only — no counter is incremented.
 */
#define NINLIL_LOGICAL_SESSION_DEADLINE_OVERFLOW \
    ((ninlil_logical_session_status_t)10u)

typedef uint32_t ninlil_logical_session_role_t;

#define NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER \
    ((ninlil_logical_session_role_t)1u)
#define NINLIL_LOGICAL_SESSION_ROLE_CELL ((ninlil_logical_session_role_t)2u)

typedef uint32_t ninlil_logical_session_state_t;

#define NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED \
    ((ninlil_logical_session_state_t)0u)
#define NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION \
    ((ninlil_logical_session_state_t)1u)
#define NINLIL_LOGICAL_SESSION_STATE_HELLO_SENT \
    ((ninlil_logical_session_state_t)2u)
#define NINLIL_LOGICAL_SESSION_STATE_HELLO_RECEIVED \
    ((ninlil_logical_session_state_t)3u)
#define NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE \
    ((ninlil_logical_session_state_t)4u)

/* Last tracked TX resolution observed by the engine (U3 six-way enum mirror). */
typedef uint32_t ninlil_logical_session_tx_commit_t;

#define NINLIL_LOGICAL_SESSION_TX_COMMIT_NONE \
    ((ninlil_logical_session_tx_commit_t)0u)
#define NINLIL_LOGICAL_SESSION_TX_COMMIT_PENDING_UNACCEPTED \
    ((ninlil_logical_session_tx_commit_t)1u)
#define NINLIL_LOGICAL_SESSION_TX_COMMIT_RAW_ACCEPTED_CURRENT_EPOCH \
    ((ninlil_logical_session_tx_commit_t)2u)
#define NINLIL_LOGICAL_SESSION_TX_COMMIT_CANCELLED_UNACCEPTED \
    ((ninlil_logical_session_tx_commit_t)3u)
#define NINLIL_LOGICAL_SESSION_TX_COMMIT_FENCED_UNACCEPTED \
    ((ninlil_logical_session_tx_commit_t)4u)
#define NINLIL_LOGICAL_SESSION_TX_COMMIT_RAW_ACCEPTED_THEN_FENCED \
    ((ninlil_logical_session_tx_commit_t)5u)
#define NINLIL_LOGICAL_SESSION_TX_COMMIT_INDETERMINATE_PARTIAL \
    ((ninlil_logical_session_tx_commit_t)6u)

/* Pending ordinary TX action kind (0 = empty). Continuity notice is separate. */
typedef uint32_t ninlil_logical_session_tx_kind_t;

#define NINLIL_LOGICAL_SESSION_TX_KIND_NONE ((ninlil_logical_session_tx_kind_t)0u)
#define NINLIL_LOGICAL_SESSION_TX_KIND_HELLO ((ninlil_logical_session_tx_kind_t)1u)
#define NINLIL_LOGICAL_SESSION_TX_KIND_HELLO_ACK \
    ((ninlil_logical_session_tx_kind_t)2u)
#define NINLIL_LOGICAL_SESSION_TX_KIND_PING ((ninlil_logical_session_tx_kind_t)3u)
#define NINLIL_LOGICAL_SESSION_TX_KIND_PONG ((ninlil_logical_session_tx_kind_t)4u)
#define NINLIL_LOGICAL_SESSION_TX_KIND_RESET ((ninlil_logical_session_tx_kind_t)5u)
#define NINLIL_LOGICAL_SESSION_TX_KIND_CTRL_ERROR \
    ((ninlil_logical_session_tx_kind_t)6u)

/*
 * Cookie CSPRNG / approved random. Return 0 and write raw bits to *out_cookie.
 * Engine redraws when *out_cookie==0 up to COOKIE_REDRAW_MAX draws total.
 * Nonzero return or all-zero after redraw budget → HELLO_OK forbidden.
 * Must not be used for HELLO retry jitter.
 */
typedef int (*ninlil_logical_session_cookie_rng_fn)(
    void *ctx,
    uint64_t *out_cookie);

/*
 * Independent non-crypto jitter source for HELLO retry ±20% only.
 * On call, write a value in [0, span_inclusive] into *out_unit and return 0.
 * Nonzero return → engine uses zero jitter (fail-closed for entropy, not cookie).
 * MUST be independent of cookie_rng; engine never calls cookie_rng for jitter
 * and never falls back to cookie_rng when this fails or is NULL.
 * NULL jitter_fn ⇒ deterministic zero jitter (span ignored).
 */
typedef int (*ninlil_logical_session_jitter_fn)(
    void *ctx,
    uint32_t span_inclusive,
    uint32_t *out_unit);

/*
 * Saturating private counter catalog (§8.10). Snapshot only; no public ABI.
 * Not reset on session fence / HELLO success.
 */
typedef struct ninlil_logical_session_counters {
    uint64_t rx_overflow;
    uint64_t ncg1_reject_stream_id;
    uint64_t ncg1_reject_seq_gap;
    uint64_t ncg1_reject_seq_dup;
    uint64_t ncg1_reject_seq_regress;
    uint64_t ncg1_reject_seq_reserved;
    uint64_t ncg1_reject_baseline;
    uint64_t ncl1_reject_short;
    uint64_t ncl1_reject_magic;
    uint64_t ncl1_reject_version;
    uint64_t ncl1_reject_flags;
    uint64_t ncl1_reject_body_len;
    uint64_t ncl1_reject_unknown_message_type;
    uint64_t ncl1_reject_type_binding;
    uint64_t ncl1_reject_body_layout;
    uint64_t ncl1_reject_session_mismatch;
    uint64_t ncl1_reject_request;
    uint64_t ncl1_reject_state;
    uint64_t ncl1_reject_reserved;
    uint64_t hello_invalid_role;
    uint64_t hello_invalid_bootstrap;
    uint64_t hello_halfopen_fence;
    uint64_t hello_bootstrap_epoch_restart;
    uint64_t hello_baseline_resync;
    uint64_t hello_ack_baseline_resync;
    uint64_t hello_retry;
    uint64_t session_fence_inflight_dropped;
    uint64_t continuity_reset_notice_cancelled;
    uint64_t ctrl_error_rate_drop;
    uint64_t pong_miss;
    uint64_t ping_dispatch_miss;
    uint64_t liveness_fail;
    /* Engine diagnostics (saturating; not §8.10 names). */
    uint64_t logical_rejects;
    uint64_t raw_accepts;
    uint64_t tx_actions_submitted;
    uint64_t continuity_notice_created;
    uint64_t continuity_notice_accepted;
    uint64_t generation_burns;
} ninlil_logical_session_counters_t;

/*
 * Consistent observation of engine authority fields (single-reader snapshot).
 * Does not expose U3 handles, tokens, or allow external commit.
 */
typedef struct ninlil_logical_session_snapshot {
    ninlil_logical_session_role_t role;
    ninlil_logical_session_state_t state;
    uint64_t now_monotonic_ms;
    uint32_t active_generation;
    uint64_t active_cookie;
    uint32_t last_issued_generation;
    /* Generations reserved/burned (includes cancelled unaccepted HELLO_ACK). */
    uint32_t burned_generation_count;
    uint32_t next_tx_seq;
    int have_rx_seq;
    uint32_t last_rx_seq;
    uint32_t inflight_count;
    uint32_t tx_action_count;
    ninlil_logical_session_tx_kind_t head_tx_kind;
    int continuity_notice_pending; /* not-yet raw-accepted */
    int continuity_notice_raw_accepted; /* accepted; FIFO obligation */
    int tracked_outstanding; /* engine-owned U3 token present */
    ninlil_logical_session_tx_commit_t last_tx_commit;
    ninlil_logical_session_tx_kind_t last_tx_kind;
    uint32_t last_tx_sequence; /* NCG1 seq used on last raw-accept commit */
    uint32_t sole_hello_request_id; /* 0 if no HELLO inflight */
    uint32_t sole_ping_request_id; /* 0 if no PING inflight */
    ninlil_logical_session_counters_t counters;
} ninlil_logical_session_snapshot_t;

typedef struct ninlil_logical_session ninlil_logical_session_t;

/*
 * Complete private layout (production-private header surface only).
 * Object embeds the typed session member — never unsigned-char storage
 * with struct cast (C11 effective type / strict aliasing).
 */
#define NINLIL_LOGICAL_SESSION_LAYOUT_ALLOW 1
#include "logical_session_layout.h"
/* Keep ALLOW defined so nested re-includes of the layout guard pass. */

typedef struct ninlil_logical_session_object {
    struct ninlil_logical_session session;
} ninlil_logical_session_object_t;

#define NINLIL_LOGICAL_SESSION_OBJECT_INIT \
    {                                      \
        .session = { 0 }                   \
    }

_Static_assert(
    sizeof(ninlil_logical_session_object_t) <= NINLIL_LOGICAL_SESSION_OBJECT_BYTES,
    "typed logical_session object must fit U3+U4 exclusive ceiling");
_Static_assert(
    _Alignof(ninlil_logical_session_object_t) >= NINLIL_LOGICAL_SESSION_OBJECT_ALIGN,
    "typed logical_session object align must meet OBJECT_ALIGN");
_Static_assert(
    sizeof(ninlil_logical_session_object_t) == sizeof(struct ninlil_logical_session),
    "object is exactly the typed session (no char-array padding shell)");
_Static_assert(
    _Alignof(ninlil_logical_session_object_t)
        == _Alignof(struct ninlil_logical_session),
    "object align must equal complete session align");

typedef struct ninlil_logical_session_config {
    ninlil_logical_session_role_t role;
    /* Required for ROLE_CELL HELLO_OK path; Controller may pass NULL. */
    ninlil_logical_session_cookie_rng_fn cookie_rng;
    void *cookie_rng_ctx;
    /*
     * Optional independent jitter source (HELLO retry only).
     * NULL ⇒ zero jitter. Never substituted with cookie_rng.
     */
    ninlil_logical_session_jitter_fn jitter_fn;
    void *jitter_ctx;
} ninlil_logical_session_config_t;

/* Actual sizeof(session); always <= OBJECT_BYTES. */
size_t ninlil_logical_session_object_size(void);
size_t ninlil_logical_session_object_align(void);

/*
 * Initialize caller storage. Does not bind a stream.
 * storage_bytes >= object_size(), correctly aligned. No U3 activity yet.
 */
ninlil_logical_session_status_t ninlil_logical_session_init(
    void *storage,
    size_t storage_bytes,
    const ninlil_logical_session_config_t *config,
    ninlil_logical_session_t **out_session);

ninlil_logical_session_status_t ninlil_logical_session_init_object(
    ninlil_logical_session_object_t *object,
    const ninlil_logical_session_config_t *config,
    ninlil_logical_session_t **out_session);

/*
 * Bind to a C1 stream that is already LINK_UP. Engine solely: U3 bind,
 * logical epoch begin, TX+RX sequence cold, state LINK_UP_NO_SESSION.
 * Controller arms initial HELLO at the next step's clock.
 * Requires STATE_DISCONNECTED; any other state → INVALID_STATE and exact
 * zero mutation (double-bind / rebind without unbind is forbidden).
 */
ninlil_logical_session_status_t ninlil_logical_session_bind(
    ninlil_logical_session_t *session,
    ninlil_byte_stream_t *stream);

/*
 * Explicit unbind: sole-owner resolve (cancel if unaccepted) → epoch end →
 * U3 unbind → DISCONNECTED. Idempotent from DISCONNECTED (OK, zero mutation).
 *
 * Fail-closed: returns OK only when every U3 step succeeds and the tracked
 * terminal is not INDETERMINATE_PARTIAL. Terminal resolution is always
 * reflected in snapshot.last_tx_commit (never discarded). On non-OK, local
 * session authority is fenced and state is DISCONNECTED only when U3 unbind
 * completed; otherwise state may remain non-DISCONNECTED with accurate
 * commit meta (caller must not treat non-OK as clean idle).
 */
ninlil_logical_session_status_t ninlil_logical_session_unbind(
    ninlil_logical_session_t *session);

/*
 * Sole drive entry: advance virtual monotonic clock, then engine-owned
 * liveness timers → TX action drain (tracked submit) → U3 pump →
 * tx_resolve (commit authority) → take_rx + NCL1 RX pipeline.
 *
 * Fail-closed prechecks (before any authority mutation, including clock):
 *   - state DISCONNECTED → INVALID_STATE (zero mutation)
 *   - now_monotonic_ms < last accepted now → TIME_REGRESSED
 *   - any deadline arithmetic for this step would overflow u64 →
 *     DEADLINE_OVERFLOW (pure candidate-time check; no temporary live write)
 * These return with exact zero mutation of the entire session authority
 * surface (state, sequences, TX actions, wire residual, counters, commit
 * meta, clock). Callers compare snapshot before/after bit-exact equality;
 * the return status is the sole failure signal (no diagnostic counter).
 *
 * U3 pump statuses are not ignored: CONTINUITY_LOST / RX_OVERFLOW /
 * GENERATION_MISMATCH / IO map into logical fence/recovery and non-OK
 * step results where appropriate (never OK-disguise of a U3 fence/IO fault).
 * Tracked token is never cleared before tx_resolve harvests the 6-way
 * terminal (FENCED / RAW_ACCEPTED_THEN_FENCED / INDETERMINATE included).
 *
 * Step progress budget (fixed; not an open multi-pump loop):
 *   (1) timers once
 *   (2) tracked submit at most once if token free (raw outstanding max 1)
 *   (3) U3 pump at most once
 *   (4) tx_resolve at most once (sole commit authority)
 *   (5) take_rx drain once (bounded by U3 ingress caps)
 * Multi-frame progress requires repeated host step() calls. Strict FIFO of
 * ordinary TX actions is preserved; no second pump/submit inside one step.
 *
 * timeout_ms is passed only to C1 poll inside engine-owned U3 pump.
 *
 * Raw sequence / ACTIVE commit occurs only when engine observes
 * RAW_ACCEPTED_CURRENT_EPOCH from U3 tx_resolve — never on submit/enqueue.
 */
ninlil_logical_session_status_t ninlil_logical_session_step(
    ninlil_logical_session_t *session,
    uint64_t now_monotonic_ms,
    uint32_t timeout_ms);

/* Single-reader consistent snapshot (no U3 handle escape). */
void ninlil_logical_session_snapshot(
    const ninlil_logical_session_t *session,
    ninlil_logical_session_snapshot_t *out_snapshot);

/* Convenience observers (equivalent to snapshot fields; no U3 escape). */
ninlil_logical_session_role_t ninlil_logical_session_role(
    const ninlil_logical_session_t *session);
ninlil_logical_session_state_t ninlil_logical_session_state(
    const ninlil_logical_session_t *session);
uint64_t ninlil_logical_session_now_ms(const ninlil_logical_session_t *session);

/*
 * Host-test inject helpers — TEST SEAM ONLY (not public ABI, not a runtime
 * product path). Enabled only when the test target defines
 * NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM. Production must not define the
 * macro. Helpers must not return U3 pointers or call U3 APIs from outside
 * the engine — they only mutate engine-owned fields or invoke engine-internal
 * paths.
 *
 * force_state / force_rx_baseline / force_next_tx_seq may be used only as
 * post-handshake restart/precondition setup for machine scenarios (never to
 * invent the transition under test). Scenario gates enforce that real
 * protocol steps establish SESSION_ACTIVE before these seams appear.
 */
#if defined(NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM)
void ninlil_logical_session_test_force_request_next(
    ninlil_logical_session_t *session,
    uint32_t request_next);

void ninlil_logical_session_test_force_last_issued_gen(
    ninlil_logical_session_t *session,
    uint32_t last_issued_gen);

void ninlil_logical_session_test_force_next_tx_seq(
    ninlil_logical_session_t *session,
    uint32_t next_tx_seq);

void ninlil_logical_session_test_force_rx_baseline(
    ninlil_logical_session_t *session,
    int have_rx_seq,
    uint32_t last_rx_seq);

void ninlil_logical_session_test_force_active(
    ninlil_logical_session_t *session,
    uint32_t generation,
    uint64_t cookie);

void ninlil_logical_session_test_force_state(
    ninlil_logical_session_t *session,
    ninlil_logical_session_state_t state);

ninlil_logical_session_status_t ninlil_logical_session_test_enqueue_ctrl_error(
    ninlil_logical_session_t *session,
    uint16_t error_code,
    uint32_t related_request_id);

/* Cell ACTIVE continuity-loss path (notice lifecycle tests). */
ninlil_logical_session_status_t ninlil_logical_session_test_cell_continuity_loss(
    ninlil_logical_session_t *session);

void ninlil_logical_session_test_controller_request_hello_now(
    ninlil_logical_session_t *session);

/* Force eligible_at near UINT64_MAX to exercise DEADLINE_OVERFLOW. */
void ninlil_logical_session_test_force_ping_eligible_at(
    ninlil_logical_session_t *session,
    uint64_t eligible_at_ms);

/* Fill ordinary TX action queue to capacity (for transactional enqueue tests). */
void ninlil_logical_session_test_fill_tx_action_queue(
    ninlil_logical_session_t *session);

/* Force burned_generation_count (saturating diagnostic). */
void ninlil_logical_session_test_force_burned_generation_count(
    ninlil_logical_session_t *session,
    uint32_t count);

/*
 * Attempt Cell HELLO_ACK plan (transactional). Returns CAPACITY when action
 * queue is full (no gen burn / no HELLO_RECEIVED). OK on success.
 */
ninlil_logical_session_status_t ninlil_logical_session_test_cell_try_prepare_ack(
    ninlil_logical_session_t *session,
    uint32_t request_id);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_LOGICAL_SESSION_H */
