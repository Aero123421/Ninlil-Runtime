#include "logical_session.h"

#include <string.h>

/*
 * U4 logical session host. Sole owner of embedded U3 control_session and
 * NCL1 codec use. Portable C11. No heap / VLA / platform headers.
 *
 * Storage model: ninlil_logical_session_object_t embeds a typed
 * struct ninlil_logical_session session member. init_object initializes
 * that member in place — no unsigned-char array type punning.
 */

#define MAGIC ((uint32_t)0x4c533455u) /* 'LS4U' */

_Static_assert(
    sizeof(struct ninlil_logical_session) <= NINLIL_LOGICAL_SESSION_OBJECT_BYTES,
    "logical session sizeof exceeds U3 embed + U4 exclusive ceiling");
_Static_assert(
    sizeof(struct ninlil_logical_session) > NINLIL_CTRL_SESSION_OBJECT_BYTES,
    "logical session must embed U3 object storage");
_Static_assert(
    NINLIL_LOGICAL_SESSION_OBJECT_BYTES
        == NINLIL_CTRL_SESSION_OBJECT_BYTES
            + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES,
    "ceiling composition drift");

static void sat_inc(uint64_t *c)
{
    if (*c < UINT64_MAX) {
        *c += 1u;
    }
}

static int add_u64_overflow(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) {
        return 1;
    }
    *out = a + b;
    return 0;
}

static struct ninlil_logical_session *as_session(void *storage)
{
    return (struct ninlil_logical_session *)storage;
}

static const struct ninlil_logical_session *as_session_c(const void *storage)
{
    return (const struct ninlil_logical_session *)storage;
}

static int session_ok(const struct ninlil_logical_session *s)
{
    return s != NULL && s->magic == MAGIC;
}

static void clear_active(struct ninlil_logical_session *s)
{
    s->active_generation = 0u;
    s->active_cookie = 0u;
}

static void drop_all_inflight(struct ninlil_logical_session *s)
{
    uint32_t n = s->inflight_count;
    uint32_t i;
    for (i = 0u; i < NINLIL_LOGICAL_SESSION_INFLIGHT_MAX; ++i) {
        if (s->inflight[i].kind != NINLIL_LS_INFLIGHT_NONE) {
            sat_inc(&s->counters.session_fence_inflight_dropped);
        }
        s->inflight[i].kind = NINLIL_LS_INFLIGHT_NONE;
        s->inflight[i].request_id = 0u;
        s->inflight[i].deadline_ms = 0u;
        s->inflight[i].opaque = 0u;
    }
    s->inflight_count = 0u;
    s->ping_inflight = 0;
    (void)n;
}

static void clear_ordinary_actions(struct ninlil_logical_session *s)
{
    (void)memset(s->actions, 0, sizeof(s->actions));
    s->action_head = 0u;
    s->action_count = 0u;
}

static void clear_notice(struct ninlil_logical_session *s)
{
    (void)memset(&s->notice, 0, sizeof(s->notice));
}

static void rx_only_cold(struct ninlil_logical_session *s)
{
    s->have_rx_seq = 0;
    s->last_rx_seq = 0u;
    if (s->epoch_claimed && s->u3 != NULL) {
        ninlil_ctrl_session_error_t err;
        uint32_t df = 0u;
        uint32_t db = 0u;
        (void)ninlil_ctrl_session_logical_rx_cold(
            s->u3,
            &s->epoch,
            NINLIL_CTRL_SESSION_RX_COLD_REASON_EXPLICIT,
            &df,
            &db,
            &err);
    }
}

static void session_to_link_up_no_session(struct ninlil_logical_session *s)
{
    drop_all_inflight(s);
    /* Cancel not-yet-accepted ordinary HELLO/ACK plans; notice lifecycle separate. */
    clear_ordinary_actions(s);
    clear_active(s);
    s->state = NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION;
    s->ping_inflight = 0;
    s->first_ping_armed = 0;
    s->pong_miss_streak = 0u;
    s->logical_reject_streak = 0u;
}

static void fence_session_keep_tx_seq(struct ninlil_logical_session *s)
{
    session_to_link_up_no_session(s);
}

/*
 * docs/23 §5.5.2 wrap / TX 上限:
 *   next_tx_seq == UINT32_MAX → cannot assign a legal wire sequence
 *   (legal max is UINT32_MAX-1; UINT32_MAX is reserved terminal, never sent).
 * Atomic recovery: session INVALID + local TX epoch cold + local RX cold +
 * Controller re-HELLO arm. Silent wrap-to-0 continuation is forbidden.
 * Returns CONTINUITY_LOST (non-OK terminal for this step).
 */
static ninlil_logical_session_status_t apply_tx_seq_terminal_exhaust(
    struct ninlil_logical_session *s)
{
    drop_all_inflight(s);
    clear_ordinary_actions(s);
    clear_notice(s);
    clear_active(s);
    s->state = NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION;
    s->ping_inflight = 0;
    s->first_ping_armed = 0;
    s->pong_miss_streak = 0u;
    s->logical_reject_streak = 0u;
    s->hello_timer_armed = 0;
    /* TX sequence epoch cold — first post-recovery TX is seq 0 (HELLO only). */
    s->next_tx_seq = 0u;
    /* Matching RX cold (both directions; no half-reset). */
    rx_only_cold(s);
    if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
        s->rehello_armed = 1;
        s->rehello_deadline_ms = s->now_ms; /* immediate re-HELLO */
    } else {
        s->rehello_armed = 0;
    }
    return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
}

/* Max single-path add to now, including HELLO ±20% jitter upper bound. */
static uint64_t max_deadline_add_ms(void)
{
    uint64_t hello_j =
        (uint64_t)NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS
        + ((uint64_t)NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS * 20u) / 100u;
    uint64_t m = hello_j;
    if ((uint64_t)NINLIL_LOGICAL_SESSION_PING_CADENCE_MS > m) {
        m = (uint64_t)NINLIL_LOGICAL_SESSION_PING_CADENCE_MS;
    }
    if ((uint64_t)NINLIL_LOGICAL_SESSION_PONG_TIMEOUT_MS > m) {
        m = (uint64_t)NINLIL_LOGICAL_SESSION_PONG_TIMEOUT_MS;
    }
    if ((uint64_t)NINLIL_LOGICAL_SESSION_PING_DISPATCH_SLACK_MS > m) {
        m = (uint64_t)NINLIL_LOGICAL_SESSION_PING_DISPATCH_SLACK_MS;
    }
    if ((uint64_t)NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS > m) {
        m = (uint64_t)NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS;
    }
    return m;
}

static uint32_t alloc_request_id(struct ninlil_logical_session *s)
{
    uint32_t id;
    uint32_t guard = 0u;
    do {
        id = s->request_next;
        if (s->request_next == UINT32_MAX) {
            s->request_next = 1u;
        } else {
            s->request_next += 1u;
            if (s->request_next == 0u) {
                s->request_next = 1u;
            }
        }
        if (id != 0u) {
            return id;
        }
        guard += 1u;
    } while (guard < 4u);
    return 1u;
}

static int inflight_find_kind(const struct ninlil_logical_session *s, uint8_t kind)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_LOGICAL_SESSION_INFLIGHT_MAX; ++i) {
        if (s->inflight[i].kind == kind) {
            return (int)i;
        }
    }
    return -1;
}

static int inflight_add(
    struct ninlil_logical_session *s,
    uint8_t kind,
    uint32_t request_id,
    uint64_t deadline_ms,
    uint64_t opaque)
{
    uint32_t i;
    if (s->inflight_count >= NINLIL_LOGICAL_SESSION_INFLIGHT_MAX) {
        return -1;
    }
    for (i = 0u; i < NINLIL_LOGICAL_SESSION_INFLIGHT_MAX; ++i) {
        if (s->inflight[i].kind == NINLIL_LS_INFLIGHT_NONE) {
            s->inflight[i].kind = kind;
            s->inflight[i].request_id = request_id;
            s->inflight[i].deadline_ms = deadline_ms;
            s->inflight[i].opaque = opaque;
            s->inflight_count += 1u;
            return (int)i;
        }
    }
    return -1;
}

static void inflight_remove_index(struct ninlil_logical_session *s, int idx)
{
    if (idx < 0 || (uint32_t)idx >= NINLIL_LOGICAL_SESSION_INFLIGHT_MAX) {
        return;
    }
    if (s->inflight[idx].kind == NINLIL_LS_INFLIGHT_NONE) {
        return;
    }
    s->inflight[idx].kind = NINLIL_LS_INFLIGHT_NONE;
    s->inflight[idx].request_id = 0u;
    s->inflight[idx].deadline_ms = 0u;
    s->inflight[idx].opaque = 0u;
    if (s->inflight_count > 0u) {
        s->inflight_count -= 1u;
    }
}

/* Peek next generation without committing (0 = exhausted). */
static uint32_t peek_next_generation(const struct ninlil_logical_session *s)
{
    if (s->last_issued_generation == UINT32_MAX) {
        return 0u;
    }
    return s->last_issued_generation + 1u;
}

/* Commit a generation that was already placed on a durable plan (enqueue OK). */
static void commit_generation_burn(struct ninlil_logical_session *s, uint32_t gen)
{
    if (gen == 0u || gen != s->last_issued_generation + 1u) {
        return;
    }
    s->last_issued_generation = gen;
    sat_inc(&s->counters.generation_burns);
    /* Diagnostic count is saturating (never wrap). */
    if (s->burned_generation_count < UINT32_MAX) {
        s->burned_generation_count += 1u;
    }
}

static int draw_cookie(struct ninlil_logical_session *s, uint64_t *out)
{
    uint32_t draws = 0u;
    if (s->cookie_rng == NULL || out == NULL) {
        return -1;
    }
    while (draws < NINLIL_LOGICAL_SESSION_COOKIE_REDRAW_MAX) {
        uint64_t v = 0u;
        if (s->cookie_rng(s->cookie_rng_ctx, &v) != 0) {
            return -1;
        }
        draws += 1u;
        if (v != 0u) {
            *out = v;
            return 0;
        }
    }
    return -1;
}

/* HELLO retry jitter: independent source only; never cookie_rng. */
static uint32_t apply_hello_jitter(struct ninlil_logical_session *s, uint32_t base_ms)
{
    uint32_t span;
    uint32_t unit = 0u;
    uint32_t delta;
    /* ±20% of base: span = floor(base * 0.4) for full range mapped from unit. */
    span = (base_ms * 40u) / 100u;
    if (span == 0u) {
        return base_ms;
    }
    if (s->jitter_fn == NULL) {
        return base_ms;
    }
    if (s->jitter_fn(s->jitter_ctx, span, &unit) != 0) {
        return base_ms;
    }
    if (unit > span) {
        unit = span;
    }
    /* Map unit in [0,span] to signed offset in [-span/2, +span/2] approx. */
    delta = unit;
    if (delta <= span / 2u) {
        return base_ms - (span / 2u - delta);
    }
    return base_ms + (delta - span / 2u);
}

static int action_enqueue(struct ninlil_logical_session *s, const ninlil_ls_tx_action_t *a)
{
    uint32_t idx;
    if (s->action_count >= NINLIL_LOGICAL_SESSION_TX_ACTION_MAX) {
        return -1;
    }
    idx = (s->action_head + s->action_count) % NINLIL_LOGICAL_SESSION_TX_ACTION_MAX;
    s->actions[idx] = *a;
    s->action_count += 1u;
    return 0;
}

static int action_peek(const struct ninlil_logical_session *s, ninlil_ls_tx_action_t *out)
{
    if (s->action_count == 0u) {
        return -1;
    }
    *out = s->actions[s->action_head];
    return 0;
}

static void action_pop(struct ninlil_logical_session *s)
{
    if (s->action_count == 0u) {
        return;
    }
    (void)memset(&s->actions[s->action_head], 0, sizeof(s->actions[0]));
    s->action_head = (s->action_head + 1u) % NINLIL_LOGICAL_SESSION_TX_ACTION_MAX;
    s->action_count -= 1u;
}

static void cancel_pending_hello_ack_actions(struct ninlil_logical_session *s)
{
    /* Drop HELLO_ACK actions not yet submitted; generation already burned. */
    uint32_t kept = 0u;
    uint32_t i;
    ninlil_ls_tx_action_t tmp[NINLIL_LOGICAL_SESSION_TX_ACTION_MAX];
    for (i = 0u; i < s->action_count; ++i) {
        uint32_t idx =
            (s->action_head + i) % NINLIL_LOGICAL_SESSION_TX_ACTION_MAX;
        if (s->actions[idx].kind != NINLIL_LOGICAL_SESSION_TX_KIND_HELLO_ACK) {
            tmp[kept] = s->actions[idx];
            kept += 1u;
        }
    }
    (void)memset(s->actions, 0, sizeof(s->actions));
    s->action_head = 0u;
    s->action_count = 0u;
    for (i = 0u; i < kept; ++i) {
        (void)action_enqueue(s, &tmp[i]);
    }
}

static void note_logical_reject(struct ninlil_logical_session *s)
{
    sat_inc(&s->counters.logical_rejects);
    if (s->logical_reject_streak < UINT32_MAX) {
        s->logical_reject_streak += 1u;
    }
    if (s->logical_reject_streak
        >= NINLIL_LOGICAL_SESSION_LOGICAL_REJECT_FENCE_THRESHOLD) {
        s->logical_reject_streak = 0u;
        if (s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE
            || s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_SENT
            || s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_RECEIVED) {
            fence_session_keep_tx_seq(s);
            if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
                s->rehello_armed = 1;
                s->rehello_deadline_ms = s->now_ms;
            }
        }
    }
}

static void map_ncl1_status_counter(
    struct ninlil_logical_session *s,
    ninlil_ncl1_status_t st)
{
    switch (st) {
    case NINLIL_NCL1_REJECT_SHORT:
        sat_inc(&s->counters.ncl1_reject_short);
        break;
    case NINLIL_NCL1_REJECT_MAGIC:
        sat_inc(&s->counters.ncl1_reject_magic);
        break;
    case NINLIL_NCL1_REJECT_VERSION:
        sat_inc(&s->counters.ncl1_reject_version);
        break;
    case NINLIL_NCL1_REJECT_FLAGS:
        sat_inc(&s->counters.ncl1_reject_flags);
        break;
    case NINLIL_NCL1_REJECT_BODY_LEN:
        sat_inc(&s->counters.ncl1_reject_body_len);
        break;
    case NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE:
        sat_inc(&s->counters.ncl1_reject_unknown_message_type);
        break;
    case NINLIL_NCL1_REJECT_TYPE_BINDING:
        sat_inc(&s->counters.ncl1_reject_type_binding);
        break;
    case NINLIL_NCL1_REJECT_BODY_LAYOUT:
        sat_inc(&s->counters.ncl1_reject_body_layout);
        break;
    case NINLIL_NCL1_REJECT_RESERVED:
        sat_inc(&s->counters.ncl1_reject_reserved);
        break;
    default:
        break;
    }
}

/* Semantic HELLO bootstrap without reserved (normal step6). */
static int semantic_hello_bootstrap(const ninlil_ncl1_message_t *msg)
{
    if (msg->header.message_type != NINLIL_NCL1_MSG_HELLO) {
        return 0;
    }
    if (msg->header.session_generation != 0u || msg->header.session_cookie != 0u) {
        return 0;
    }
    if (msg->header.request_id == 0u) {
        return 0;
    }
    if (msg->body.hello.min_control_version != NINLIL_NCL1_CONTROL_VERSION_V1
        || msg->body.hello.max_control_version != NINLIL_NCL1_CONTROL_VERSION_V1
        || msg->body.hello.flags_supported != 0u) {
        return 0;
    }
    return 1;
}

/* Semantic HELLO_ACK without reserved (normal step6). */
static int semantic_hello_ack(const ninlil_ncl1_message_t *msg)
{
    if (msg->header.message_type != NINLIL_NCL1_MSG_HELLO_ACK) {
        return 0;
    }
    if (msg->header.request_id == 0u) {
        return 0;
    }
    if (msg->body.hello_ack.flags_selected != 0u) {
        return 0;
    }
    if (msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_OK) {
        if (msg->header.session_generation == 0u
            || msg->header.session_cookie == 0u) {
            return 0;
        }
        if (msg->body.hello_ack.selected_control_version
            != NINLIL_NCL1_CONTROL_VERSION_V1) {
            return 0;
        }
        return 1;
    }
    if (msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_VERSION_MISMATCH
        || msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_BUSY
        || msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_DENIED) {
        return msg->header.session_generation == 0u
            && msg->header.session_cookie == 0u;
    }
    return 0;
}

static int ctrl_error_rate_allow(struct ninlil_logical_session *s)
{
    uint32_t i;
    uint32_t kept = 0u;
    uint64_t window_start;
    uint64_t times[NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_MAX];

    if (s->now_ms >= NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_WINDOW_MS) {
        window_start = s->now_ms - NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_WINDOW_MS;
    } else {
        window_start = 0u;
    }
    for (i = 0u; i < s->ctrl_error_count; ++i) {
        if (s->ctrl_error_times[i] >= window_start) {
            times[kept] = s->ctrl_error_times[i];
            kept += 1u;
        }
    }
    s->ctrl_error_count = kept;
    for (i = 0u; i < kept; ++i) {
        s->ctrl_error_times[i] = times[i];
    }
    if (s->ctrl_error_count >= NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_MAX) {
        sat_inc(&s->counters.ctrl_error_rate_drop);
        return 0;
    }
    s->ctrl_error_times[s->ctrl_error_count] = s->now_ms;
    s->ctrl_error_count += 1u;
    return 1;
}

static void maybe_enqueue_ctrl_error(
    struct ninlil_logical_session *s,
    uint16_t code,
    uint32_t related_req)
{
    ninlil_ls_tx_action_t a;
    if (!ctrl_error_rate_allow(s)) {
        return;
    }
    (void)memset(&a, 0, sizeof(a));
    a.kind = NINLIL_LOGICAL_SESSION_TX_KIND_CTRL_ERROR;
    a.ncg1_type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    a.message_type = NINLIL_NCL1_MSG_CTRL_ERROR;
    a.request_id = related_req;
    if (s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
        a.session_generation = s->active_generation;
        a.session_cookie = s->active_cookie;
    } else {
        a.session_generation = 0u;
        a.session_cookie = 0u;
    }
    a.body_length = NINLIL_NCL1_BODY_CTRL_ERROR_BYTES;
    a.body[0] = (uint8_t)((code >> 8) & 0xffu);
    a.body[1] = (uint8_t)(code & 0xffu);
    a.body[2] = 0u;
    a.body[3] = 0u;
    a.body[4] = (uint8_t)((related_req >> 24) & 0xffu);
    a.body[5] = (uint8_t)((related_req >> 16) & 0xffu);
    a.body[6] = (uint8_t)((related_req >> 8) & 0xffu);
    a.body[7] = (uint8_t)(related_req & 0xffu);
    (void)action_enqueue(s, &a);
}

/*
 * Arm HELLO retry timer. Returns 0 on success.
 * On overflow: exact zero mutation of timer fields (caller / pure precheck
 * must ensure this is unreachable after a passing DEADLINE_OVERFLOW precheck).
 */
static int arm_hello_timer(struct ninlil_logical_session *s, uint32_t delay_ms)
{
    uint64_t dl;
    uint32_t j = apply_hello_jitter(s, delay_ms);
    if (add_u64_overflow(s->now_ms, (uint64_t)j, &dl) != 0) {
        return 1;
    }
    s->hello_timer_armed = 1;
    s->hello_deadline_ms = dl;
    s->hello_retry_delay_ms = delay_ms;
    return 0;
}

/*
 * Atomic HELLO replace: preflight capacity against post-replace occupancy
 * (existing HELLO queue/inflight freed only after candidate succeeds).
 * On failure: zero mutation of prior HELLO plan.
 */
static int schedule_controller_hello(struct ninlil_logical_session *s, int is_retry)
{
    ninlil_ls_tx_action_t cand;
    ninlil_ls_tx_action_t kept[NINLIL_LOGICAL_SESSION_TX_ACTION_MAX];
    uint32_t kept_n = 0u;
    uint32_t i;
    uint32_t non_hello_actions = 0u;
    uint32_t non_hello_inflight = 0u;
    uint32_t req;
    int hi;

    for (i = 0u; i < s->action_count; ++i) {
        uint32_t idx =
            (s->action_head + i) % NINLIL_LOGICAL_SESSION_TX_ACTION_MAX;
        if (s->actions[idx].kind != NINLIL_LOGICAL_SESSION_TX_KIND_HELLO) {
            if (kept_n >= NINLIL_LOGICAL_SESSION_TX_ACTION_MAX) {
                return -1;
            }
            kept[kept_n] = s->actions[idx];
            kept_n += 1u;
            non_hello_actions += 1u;
        }
    }
    /* Post-replace need room for 1 HELLO + non-HELLO actions. */
    if (non_hello_actions + 1u > NINLIL_LOGICAL_SESSION_TX_ACTION_MAX) {
        return -1;
    }

    for (i = 0u; i < NINLIL_LOGICAL_SESSION_INFLIGHT_MAX; ++i) {
        if (s->inflight[i].kind != NINLIL_LS_INFLIGHT_NONE
            && s->inflight[i].kind != NINLIL_LS_INFLIGHT_HELLO) {
            non_hello_inflight += 1u;
        }
    }
    if (non_hello_inflight + 1u > NINLIL_LOGICAL_SESSION_INFLIGHT_MAX) {
        return -1;
    }

    req = alloc_request_id(s);
    (void)memset(&cand, 0, sizeof(cand));
    cand.kind = NINLIL_LOGICAL_SESSION_TX_KIND_HELLO;
    cand.ncg1_type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    cand.message_type = NINLIL_NCL1_MSG_HELLO;
    cand.request_id = req;
    cand.session_generation = 0u;
    cand.session_cookie = 0u;
    cand.body_length = NINLIL_NCL1_BODY_HELLO_BYTES;
    cand.body[0] = 0u;
    cand.body[1] = 1u;
    cand.body[2] = 0u;
    cand.body[3] = 1u;

    /* Atomic replace: rebuild queue = kept non-HELLO + new HELLO. */
    (void)memset(s->actions, 0, sizeof(s->actions));
    s->action_head = 0u;
    s->action_count = 0u;
    for (i = 0u; i < kept_n; ++i) {
        if (action_enqueue(s, &kept[i]) != 0) {
            /* Restore is complex; kept_n fitted preflight — should not fail. */
            return -1;
        }
    }
    if (action_enqueue(s, &cand) != 0) {
        /* Preflight guaranteed capacity; treat as internal fail-closed. */
        return -1;
    }

    hi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_HELLO);
    if (hi >= 0) {
        inflight_remove_index(s, hi);
    }
    /* Preflight guaranteed a free inflight slot after HELLO removal. */
    if (inflight_add(s, NINLIL_LS_INFLIGHT_HELLO, req, 0u, 0u) < 0) {
        return -1;
    }

    s->state = NINLIL_LOGICAL_SESSION_STATE_HELLO_SENT;
    if (is_retry) {
        sat_inc(&s->counters.hello_retry);
        {
            uint32_t next = s->hello_retry_delay_ms;
            if (next == 0u) {
                next = NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS;
            } else {
                if (next
                    > NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS
                        / NINLIL_LOGICAL_SESSION_HELLO_BACKOFF_MULT) {
                    next = NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS;
                } else {
                    next = next * NINLIL_LOGICAL_SESSION_HELLO_BACKOFF_MULT;
                    if (next > NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS) {
                        next = NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS;
                    }
                }
            }
            if (arm_hello_timer(s, next) != 0) {
                return -1;
            }
        }
    } else {
        s->hello_retry_delay_ms = NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS;
        if (arm_hello_timer(s, NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS)
            != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Transactional HELLO_ACK plan: generation is committed only after enqueue
 * succeeds. Capacity / enqueue failure leaves state/gen/queue unchanged
 * (except prior unsent ACK cancel). Returns 0 on success, -1 on fail-closed.
 */
static int cell_prepare_hello_ack(
    struct ninlil_logical_session *s,
    uint32_t request_id,
    int ok)
{
    ninlil_ls_tx_action_t a;
    uint32_t pending_gen = 0u;

    cancel_pending_hello_ack_actions(s);
    if (s->action_count >= NINLIL_LOGICAL_SESSION_TX_ACTION_MAX) {
        return -1;
    }

    (void)memset(&a, 0, sizeof(a));
    a.kind = NINLIL_LOGICAL_SESSION_TX_KIND_HELLO_ACK;
    a.ncg1_type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    a.message_type = NINLIL_NCL1_MSG_HELLO_ACK;
    a.request_id = request_id;
    a.body_length = NINLIL_NCL1_BODY_HELLO_ACK_BYTES;
    if (ok) {
        uint64_t cookie = 0u;
        if (draw_cookie(s, &cookie) != 0) {
            a.session_generation = 0u;
            a.session_cookie = 0u;
            a.hello_result = NINLIL_NCL1_HELLO_BUSY;
            a.body[0] = 0u;
            a.body[1] = 0u;
            a.body[4] = 0u;
            a.body[5] = (uint8_t)NINLIL_NCL1_HELLO_BUSY;
        } else {
            pending_gen = peek_next_generation(s);
            if (pending_gen == 0u) {
                a.session_generation = 0u;
                a.session_cookie = 0u;
                a.hello_result = NINLIL_NCL1_HELLO_BUSY;
                a.body[5] = (uint8_t)NINLIL_NCL1_HELLO_BUSY;
            } else {
                a.session_generation = pending_gen;
                a.session_cookie = cookie;
                a.hello_result = NINLIL_NCL1_HELLO_OK;
                a.gen_burned = 1u;
                a.body[0] = 0u;
                a.body[1] = 1u;
                a.body[4] = 0u;
                a.body[5] = 0u;
            }
        }
    } else {
        a.session_generation = 0u;
        a.session_cookie = 0u;
        a.hello_result = NINLIL_NCL1_HELLO_DENIED;
        a.body[5] = (uint8_t)NINLIL_NCL1_HELLO_DENIED;
    }

    if (action_enqueue(s, &a) != 0) {
        return -1;
    }
    if (a.hello_result == NINLIL_NCL1_HELLO_OK && pending_gen != 0u) {
        commit_generation_burn(s, pending_gen);
    }
    s->state = NINLIL_LOGICAL_SESSION_STATE_HELLO_RECEIVED;
    return 0;
}

static void cell_continuity_loss(struct ninlil_logical_session *s, int overflow)
{
    uint32_t snap_gen;
    uint64_t snap_cookie;
    if (s->role != NINLIL_LOGICAL_SESSION_ROLE_CELL) {
        return;
    }
    if (s->state != NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
        rx_only_cold(s);
        fence_session_keep_tx_seq(s);
        return;
    }
    /* pre-fence snapshot */
    snap_gen = s->active_generation;
    snap_cookie = s->active_cookie;
    /* atomic fence + RX cold; TX continues */
    if (overflow == 1) {
        sat_inc(&s->counters.rx_overflow);
    } else if (overflow == 0) {
        sat_inc(&s->counters.ncg1_reject_seq_gap);
    }
    /* overflow==2: reserved/other — counter already applied by caller */
    rx_only_cold(s);
    fence_session_keep_tx_seq(s);
    /* notice max 1 */
    if (s->notice.phase == NINLIL_LS_NOTICE_EMPTY) {
        s->notice.phase = NINLIL_LS_NOTICE_PENDING;
        s->notice.reset_code = NINLIL_NCL1_RESET_SESSION;
        s->notice.request_id = alloc_request_id(s);
        s->notice.session_generation = snap_gen;
        s->notice.session_cookie = snap_cookie;
        sat_inc(&s->counters.continuity_notice_created);
    }
}

static void controller_continuity_loss(struct ninlil_logical_session *s, int reserved)
{
    if (reserved) {
        sat_inc(&s->counters.ncg1_reject_seq_reserved);
    } else {
        sat_inc(&s->counters.ncg1_reject_seq_gap);
    }
    rx_only_cold(s);
    fence_session_keep_tx_seq(s);
    if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
        s->rehello_armed = 1;
        s->rehello_deadline_ms = s->now_ms; /* immediate */
    }
}

static int accept_rx_sequence(struct ninlil_logical_session *s, uint32_t seq)
{
    s->have_rx_seq = 1;
    s->last_rx_seq = seq;
    return 0;
}

/*
 * Limited peek path for SBR / BOOTSTRAP only — helpers may include reserved.
 */
static int peek_valid_hello_bootstrap(
    const uint8_t *payload,
    uint16_t plen,
    ninlil_ncl1_message_t *out)
{
    ninlil_ncl1_status_t st =
        ninlil_ncl1_decode(payload, (size_t)plen, NINLIL_NCL1_NCG1_TYPE_DATA, out);
    if (st != NINLIL_NCL1_OK) {
        return 0;
    }
    return ninlil_ncl1_is_valid_hello_bootstrap(out);
}

static int peek_valid_hello_ack(
    const uint8_t *payload,
    uint16_t plen,
    ninlil_ncl1_message_t *out)
{
    ninlil_ncl1_status_t st =
        ninlil_ncl1_decode(payload, (size_t)plen, NINLIL_NCL1_NCG1_TYPE_DATA, out);
    if (st != NINLIL_NCL1_OK) {
        return 0;
    }
    return ninlil_ncl1_is_structurally_valid_hello_ack(out);
}

static void on_valid_hello_cell(
    struct ninlil_logical_session *s,
    const ninlil_ncl1_message_t *msg,
    int halfopen,
    int bootstrap_restart,
    int sbr)
{
    if (halfopen || bootstrap_restart) {
        sat_inc(&s->counters.hello_halfopen_fence);
        if (bootstrap_restart) {
            sat_inc(&s->counters.hello_bootstrap_epoch_restart);
        }
        /* cancel pending continuity notice not yet accepted */
        if (s->notice.phase == NINLIL_LS_NOTICE_PENDING) {
            clear_notice(s);
            sat_inc(&s->counters.continuity_reset_notice_cancelled);
        }
        fence_session_keep_tx_seq(s);
        /* RX seq already accepted by caller */
    } else if (sbr) {
        /* Counter already incremented at SBR accept site in process_rx. */
        if (s->notice.phase == NINLIL_LS_NOTICE_PENDING) {
            clear_notice(s);
            sat_inc(&s->counters.continuity_reset_notice_cancelled);
        }
    } else {
        if (s->notice.phase == NINLIL_LS_NOTICE_PENDING) {
            clear_notice(s);
            sat_inc(&s->counters.continuity_reset_notice_cancelled);
        }
    }
    if (s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_RECEIVED) {
        /* duplicate HELLO: replace ACK plan; burned gen stays burned */
        cancel_pending_hello_ack_actions(s);
    }
    /* Transactional: capacity failure leaves no HELLO_RECEIVED/gen burn. */
    if (cell_prepare_hello_ack(s, msg->header.request_id, 1) != 0) {
        sat_inc(&s->counters.ncl1_reject_state);
        note_logical_reject(s);
    }
}

static void handle_reset_accepted(
    struct ninlil_logical_session *s,
    const ninlil_ncl1_message_t *msg)
{
    uint8_t code = msg->body.reset.reset_code;
    if (code == NINLIL_NCL1_RESET_SESSION) {
        uint64_t dl;
        fence_session_keep_tx_seq(s);
        /* sequences continue both sides */
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
            if (add_u64_overflow(
                    s->now_ms,
                    NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS,
                    &dl)
                != 0) {
                /* Pure precheck must reject the step before this path. */
                return;
            }
            s->rehello_armed = 1;
            s->rehello_deadline_ms = dl;
        }
    } else if (code == NINLIL_NCL1_RESET_PARSER) {
        rx_only_cold(s);
        fence_session_keep_tx_seq(s);
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
            s->rehello_armed = 1;
            s->rehello_deadline_ms = s->now_ms;
        }
    } else if (code == NINLIL_NCL1_RESET_LINK) {
        fence_session_keep_tx_seq(s);
        /* sequence cold deferred to observed reopen (bind) */
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
            s->rehello_armed = 1;
            s->rehello_deadline_ms = s->now_ms;
        }
    }
}

static void process_ncl1_after_seq(
    struct ninlil_logical_session *s,
    uint8_t ncg1_type,
    const uint8_t *payload,
    uint16_t plen)
{
    ninlil_ncl1_message_t msg;
    ninlil_ncl1_status_t st;
    ninlil_ncl1_status_t rs;

    /* Empty NCG1 PING (payload 0) → session reject. */
    if (ncg1_type == NINLIL_MODEL_CONTROL_FRAME_TYPE_PING && plen == 0u) {
        sat_inc(&s->counters.ncl1_reject_body_len);
        note_logical_reject(s);
        return;
    }

    (void)memset(&msg, 0, sizeof(msg));
    st = ninlil_ncl1_decode(payload, (size_t)plen, ncg1_type, &msg);
    if (st != NINLIL_NCL1_OK) {
        map_ncl1_status_counter(s, st);
        note_logical_reject(s);
        /* Type binding / unknown: no CTRL_ERROR response to CTRL_ERROR loop.
         * May send CTRL_ERROR for some rejects except when msg is CTRL_ERROR
         * (cannot know if decode failed early). */
        if (st == NINLIL_NCL1_REJECT_TYPE_BINDING) {
            maybe_enqueue_ctrl_error(
                s, NINLIL_NCL1_ERR_TYPE_BINDING, 0u);
        } else if (st == NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE) {
            maybe_enqueue_ctrl_error(
                s, NINLIL_NCL1_ERR_UNKNOWN_MESSAGE, 0u);
        }
        return;
    }

    /* Step 6 semantic (reserved excluded). */
    if (msg.header.message_type == NINLIL_NCL1_MSG_CTRL_ERROR) {
        /* Never respond to CTRL_ERROR with CTRL_ERROR. */
        note_logical_reject(s);
        return;
    }

    if (msg.header.message_type == NINLIL_NCL1_MSG_HELLO) {
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
            sat_inc(&s->counters.hello_invalid_role);
            note_logical_reject(s);
            return;
        }
        if (!semantic_hello_bootstrap(&msg)) {
            if (msg.header.session_generation != 0u
                || msg.header.session_cookie != 0u) {
                sat_inc(&s->counters.hello_invalid_bootstrap);
            } else {
                sat_inc(&s->counters.ncl1_reject_request);
            }
            note_logical_reject(s);
            return;
        }
        /* step 7 reserved */
        rs = ninlil_ncl1_check_reserved(&msg);
        if (rs != NINLIL_NCL1_OK) {
            map_ncl1_status_counter(s, rs);
            note_logical_reject(s);
            return;
        }
        on_valid_hello_cell(s, &msg, 0, 0, 0);
        return;
    }

    if (msg.header.message_type == NINLIL_NCL1_MSG_HELLO_ACK) {
        int hi;
        if (s->role != NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
            sat_inc(&s->counters.ncl1_reject_state);
            note_logical_reject(s);
            return;
        }
        if (!semantic_hello_ack(&msg)) {
            if (msg.body.hello_ack.result_code == NINLIL_NCL1_HELLO_OK
                && msg.header.session_cookie == 0u) {
                sat_inc(&s->counters.ncl1_reject_session_mismatch);
            } else {
                sat_inc(&s->counters.ncl1_reject_request);
            }
            note_logical_reject(s);
            return;
        }
        rs = ninlil_ncl1_check_reserved(&msg);
        if (rs != NINLIL_NCL1_OK) {
            map_ncl1_status_counter(s, rs);
            note_logical_reject(s);
            return;
        }
        hi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_HELLO);
        if (hi < 0
            || s->inflight[hi].request_id != msg.header.request_id) {
            sat_inc(&s->counters.ncl1_reject_request);
            note_logical_reject(s);
            return;
        }
        inflight_remove_index(s, hi);
        s->hello_timer_armed = 0;
        if (msg.body.hello_ack.result_code == NINLIL_NCL1_HELLO_OK) {
            s->active_generation = msg.header.session_generation;
            s->active_cookie = msg.header.session_cookie;
            s->state = NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE;
            s->first_ping_armed = 1;
            s->ping_eligible_at_ms = s->now_ms;
            s->pong_miss_streak = 0u;
        } else {
            s->state = NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION;
            /* Overflow is pure-prechecked; non-zero return leaves timer disarmed. */
            (void)arm_hello_timer(
                s, NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS);
        }
        return;
    }

    if (msg.header.message_type == NINLIL_NCL1_MSG_PING_BODY) {
        if (s->state != NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            sat_inc(&s->counters.ncl1_reject_state);
            note_logical_reject(s);
            return;
        }
        if (msg.header.request_id == 0u) {
            sat_inc(&s->counters.ncl1_reject_request);
            note_logical_reject(s);
            return;
        }
        if (msg.header.session_generation == 0u
            || msg.header.session_cookie == 0u) {
            sat_inc(&s->counters.ncl1_reject_session_mismatch);
            note_logical_reject(s);
            return;
        }
        if (msg.header.session_generation != s->active_generation
            || msg.header.session_cookie != s->active_cookie) {
            sat_inc(&s->counters.ncl1_reject_session_mismatch);
            note_logical_reject(s);
            return;
        }
        rs = ninlil_ncl1_check_reserved(&msg);
        if (rs != NINLIL_NCL1_OK) {
            map_ncl1_status_counter(s, rs);
            note_logical_reject(s);
            return;
        }
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL) {
            ninlil_ls_tx_action_t a;
            (void)memset(&a, 0, sizeof(a));
            a.kind = NINLIL_LOGICAL_SESSION_TX_KIND_PONG;
            a.ncg1_type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PONG;
            a.message_type = NINLIL_NCL1_MSG_PONG_BODY;
            a.request_id = msg.header.request_id;
            a.session_generation = s->active_generation;
            a.session_cookie = s->active_cookie;
            a.body_length = NINLIL_NCL1_BODY_PONG_BYTES;
            a.opaque = msg.body.ping.opaque_echo_token;
            {
                uint64_t t = msg.body.ping.opaque_echo_token;
                a.body[0] = (uint8_t)((t >> 56) & 0xffu);
                a.body[1] = (uint8_t)((t >> 48) & 0xffu);
                a.body[2] = (uint8_t)((t >> 40) & 0xffu);
                a.body[3] = (uint8_t)((t >> 32) & 0xffu);
                a.body[4] = (uint8_t)((t >> 24) & 0xffu);
                a.body[5] = (uint8_t)((t >> 16) & 0xffu);
                a.body[6] = (uint8_t)((t >> 8) & 0xffu);
                a.body[7] = (uint8_t)(t & 0xffu);
            }
            (void)action_enqueue(s, &a);
        } else {
            sat_inc(&s->counters.ncl1_reject_state);
            note_logical_reject(s);
        }
        return;
    }

    if (msg.header.message_type == NINLIL_NCL1_MSG_PONG_BODY) {
        int pi;
        if (s->role != NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER
            || s->state != NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            sat_inc(&s->counters.ncl1_reject_state);
            note_logical_reject(s);
            return;
        }
        if (msg.header.session_generation != s->active_generation
            || msg.header.session_cookie != s->active_cookie) {
            sat_inc(&s->counters.ncl1_reject_session_mismatch);
            note_logical_reject(s);
            return;
        }
        rs = ninlil_ncl1_check_reserved(&msg);
        if (rs != NINLIL_NCL1_OK) {
            map_ncl1_status_counter(s, rs);
            note_logical_reject(s);
            return;
        }
        pi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING);
        if (pi < 0
            || s->inflight[pi].request_id != msg.header.request_id
            || s->inflight[pi].opaque != msg.body.pong.opaque_echo_token) {
            sat_inc(&s->counters.ncl1_reject_request);
            note_logical_reject(s);
            return;
        }
        inflight_remove_index(s, pi);
        s->ping_inflight = 0;
        s->pong_miss_streak = 0u;
        {
            uint64_t next_el;
            if (add_u64_overflow(
                    s->now_ms,
                    NINLIL_LOGICAL_SESSION_PING_CADENCE_MS,
                    &next_el)
                != 0) {
                /* Pure precheck must reject; leave eligible unchanged. */
                return;
            }
            s->ping_eligible_at_ms = next_el;
        }
        return;
    }

    if (msg.header.message_type == NINLIL_NCL1_MSG_RESET_BODY) {
        if (msg.header.request_id == 0u) {
            sat_inc(&s->counters.ncl1_reject_request);
            note_logical_reject(s);
            return;
        }
        if (!ninlil_ncl1_reset_code_is_closed(msg.body.reset.reset_code)) {
            sat_inc(&s->counters.ncl1_reject_body_layout);
            note_logical_reject(s);
            return;
        }
        /* Active mismatch / non-active: semantic after sequence already accepted. */
        if (s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            if (msg.header.session_generation != s->active_generation
                || msg.header.session_cookie != s->active_cookie) {
                sat_inc(&s->counters.ncl1_reject_session_mismatch);
                note_logical_reject(s);
                /* stale: no fence, sequence already advanced */
                return;
            }
            rs = ninlil_ncl1_check_reserved(&msg);
            if (rs != NINLIL_NCL1_OK) {
                /* multi-fault: stale checked first; if match then reserved */
                map_ncl1_status_counter(s, rs);
                note_logical_reject(s);
                return;
            }
            handle_reset_accepted(s, &msg);
            return;
        }
        /* non-active drop (idempotent); sequence already advanced if continuous */
        sat_inc(&s->counters.ncl1_reject_state);
        note_logical_reject(s);
        return;
    }

    sat_inc(&s->counters.ncl1_reject_unknown_message_type);
    note_logical_reject(s);
}

static void process_rx_frame(
    struct ninlil_logical_session *s,
    const ninlil_ctrl_session_frame_t *fr)
{
    uint32_t seq = fr->sequence;
    uint8_t type = fr->type;
    const uint8_t *payload = fr->payload;
    uint16_t plen = fr->payload_length;
    ninlil_ncl1_message_t peek_msg;
    int hi;

    /* stream_or_cell_id exact 0 */
    if (fr->stream_or_cell_id != 0u) {
        sat_inc(&s->counters.ncg1_reject_stream_id);
        note_logical_reject(s);
        return;
    }

    /* UINT32_MAX reserved terminal — before SBR/BOOTSTRAP/baseline */
    if (seq == UINT32_MAX) {
        sat_inc(&s->counters.ncg1_reject_seq_reserved);
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            cell_continuity_loss(s, 2);
        } else if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL) {
            rx_only_cold(s);
            fence_session_keep_tx_seq(s);
        } else {
            rx_only_cold(s);
            fence_session_keep_tx_seq(s);
            if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
                s->rehello_armed = 1;
                s->rehello_deadline_ms = s->now_ms;
            }
        }
        return;
    }

    /* Sequence policy with limited peek for SBR / BOOTSTRAP only. */
    if (!s->have_rx_seq) {
        /* SBR-HELLO: Cell, baseline unset, DATA + valid HELLO bootstrap helper */
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA
            && (s->state == NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION
                || s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_RECEIVED)
            && peek_valid_hello_bootstrap(payload, plen, &peek_msg)) {
            (void)accept_rx_sequence(s, seq);
            sat_inc(&s->counters.hello_baseline_resync);
            on_valid_hello_cell(s, &peek_msg, 0, 0, 1);
            return;
        }
        /* SBR-ACK: Controller HELLO_SENT, matching sole HELLO inflight */
        hi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_HELLO);
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER
            && s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_SENT
            && hi >= 0
            && type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA
            && peek_valid_hello_ack(payload, plen, &peek_msg)
            && peek_msg.header.request_id == s->inflight[hi].request_id) {
            (void)accept_rx_sequence(s, seq);
            sat_inc(&s->counters.hello_ack_baseline_resync);
            process_ncl1_after_seq(s, type, payload, plen);
            return;
        }
        /* Normal baseline: exact seq 0 only */
        if (seq != 0u) {
            sat_inc(&s->counters.ncg1_reject_baseline);
            note_logical_reject(s);
            return;
        }
        (void)accept_rx_sequence(s, seq);
        process_ncl1_after_seq(s, type, payload, plen);
        return;
    }

    /* have_rx_seq */
    if (seq == s->last_rx_seq) {
        /* duplicate — BOOTSTRAP_EPOCH_RESTART for Cell valid HELLO */
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA
            && peek_valid_hello_bootstrap(payload, plen, &peek_msg)) {
            clear_active(s);
            drop_all_inflight(s);
            clear_ordinary_actions(s);
            if (s->notice.phase == NINLIL_LS_NOTICE_PENDING) {
                clear_notice(s);
                sat_inc(&s->counters.continuity_reset_notice_cancelled);
            }
            rx_only_cold(s);
            (void)accept_rx_sequence(s, seq);
            on_valid_hello_cell(s, &peek_msg, 0, 1, 0);
            return;
        }
        sat_inc(&s->counters.ncg1_reject_seq_dup);
        note_logical_reject(s);
        return;
    }

    if (seq < s->last_rx_seq) {
        /* regress — BOOTSTRAP for Cell HELLO */
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA
            && peek_valid_hello_bootstrap(payload, plen, &peek_msg)) {
            clear_active(s);
            drop_all_inflight(s);
            clear_ordinary_actions(s);
            if (s->notice.phase == NINLIL_LS_NOTICE_PENDING) {
                clear_notice(s);
                sat_inc(&s->counters.continuity_reset_notice_cancelled);
            }
            rx_only_cold(s);
            (void)accept_rx_sequence(s, seq);
            on_valid_hello_cell(s, &peek_msg, 0, 1, 0);
            return;
        }
        sat_inc(&s->counters.ncg1_reject_seq_regress);
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            cell_continuity_loss(s, 0);
        } else {
            controller_continuity_loss(s, 0);
        }
        return;
    }

    /* seq > last */
    if (seq != s->last_rx_seq + 1u) {
        /* gap — do NOT NCL1 peek */
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            cell_continuity_loss(s, 0);
        } else {
            controller_continuity_loss(s, 0);
        }
        return;
    }

    /* continuous accept */
    (void)accept_rx_sequence(s, seq);

    /* half-open continuous HELLO on ACTIVE Cell */
    if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
        && s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE
        && type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA) {
        ninlil_ncl1_status_t st =
            ninlil_ncl1_decode(
                payload, (size_t)plen, NINLIL_NCL1_NCG1_TYPE_DATA, &peek_msg);
        if (st == NINLIL_NCL1_OK && semantic_hello_bootstrap(&peek_msg)
            && ninlil_ncl1_check_reserved(&peek_msg) == NINLIL_NCL1_OK) {
            on_valid_hello_cell(s, &peek_msg, 1, 0, 0);
            return;
        }
    }

    process_ncl1_after_seq(s, type, payload, plen);
}

static ninlil_logical_session_status_t encode_action_payload(
    const ninlil_ls_tx_action_t *a,
    uint8_t *out,
    size_t cap,
    size_t *out_len)
{
    ninlil_ncl1_message_t msg;
    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = NINLIL_NCL1_LOGICAL_VERSION;
    msg.header.message_type = a->message_type;
    msg.header.flags = 0u;
    msg.header.request_id = a->request_id;
    msg.header.session_generation = a->session_generation;
    msg.header.session_cookie = a->session_cookie;
    msg.header.body_length = a->body_length;
    if (a->message_type == NINLIL_NCL1_MSG_HELLO) {
        msg.body.hello.min_control_version = 1u;
        msg.body.hello.max_control_version = 1u;
    } else if (a->message_type == NINLIL_NCL1_MSG_HELLO_ACK) {
        msg.body.hello_ack.selected_control_version =
            (a->hello_result == NINLIL_NCL1_HELLO_OK) ? 1u : 0u;
        msg.body.hello_ack.flags_selected = 0u;
        msg.body.hello_ack.result_code = a->hello_result;
    } else if (a->message_type == NINLIL_NCL1_MSG_PING_BODY
        || a->message_type == NINLIL_NCL1_MSG_PONG_BODY) {
        msg.body.ping.opaque_echo_token = a->opaque;
    } else if (a->message_type == NINLIL_NCL1_MSG_RESET_BODY) {
        msg.body.reset.reset_code = a->reset_code;
    } else if (a->message_type == NINLIL_NCL1_MSG_CTRL_ERROR) {
        msg.body.ctrl_error.error_code =
            (uint16_t)(((uint16_t)a->body[0] << 8) | a->body[1]);
        msg.body.ctrl_error.related_request_id = a->request_id;
    }
    if (ninlil_ncl1_encode(&msg, out, cap, out_len) != NINLIL_NCL1_OK) {
        return NINLIL_LOGICAL_SESSION_INVALID_STATE;
    }
    return NINLIL_LOGICAL_SESSION_OK;
}

static ninlil_logical_session_status_t try_submit_tracked(
    struct ninlil_logical_session *s)
{
    ninlil_model_control_frame_fields_t fields;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_tx_token_t token = 0u;
    ninlil_ctrl_session_status_t st;
    size_t ncl1_len = 0u;
    ninlil_ls_tx_action_t act;
    uint8_t ncg1_type;
    uint32_t seq;

    if (s->tracked_kind != NINLIL_LS_TRACKED_NONE) {
        return NINLIL_LOGICAL_SESSION_OK;
    }
    if (!s->epoch_claimed || s->u3 == NULL) {
        return NINLIL_LOGICAL_SESSION_INVALID_STATE;
    }
    if (s->next_tx_seq == UINT32_MAX) {
        /* Cannot assign reserved terminal or wrap; both-direction cold. */
        return apply_tx_seq_terminal_exhaust(s);
    }

    /* Continuity notice has priority over ordinary queue. */
    if (s->notice.phase == NINLIL_LS_NOTICE_PENDING) {
        ninlil_ncl1_message_t msg;
        (void)memset(&msg, 0, sizeof(msg));
        msg.header.logical_version = NINLIL_NCL1_LOGICAL_VERSION;
        msg.header.message_type = NINLIL_NCL1_MSG_RESET_BODY;
        msg.header.request_id = s->notice.request_id;
        msg.header.session_generation = s->notice.session_generation;
        msg.header.session_cookie = s->notice.session_cookie;
        msg.header.body_length = NINLIL_NCL1_BODY_RESET_BYTES;
        msg.body.reset.reset_code = s->notice.reset_code;
        if (ninlil_ncl1_encode(
                &msg, s->ncl1_scratch, sizeof(s->ncl1_scratch), &ncl1_len)
            != NINLIL_NCL1_OK) {
            return NINLIL_LOGICAL_SESSION_INVALID_STATE;
        }
        seq = s->next_tx_seq;
        s->notice.sequence = seq;
        (void)memset(&fields, 0, sizeof(fields));
        fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_RESET;
        fields.flags = 0u;
        fields.stream_or_cell_id = 0u;
        fields.sequence = seq;
        fields.payload.data = s->ncl1_scratch;
        fields.payload.length = (uint32_t)ncl1_len;
        st = ninlil_ctrl_session_tracked_submit_tx(
            s->u3, &s->epoch, &fields, &token, &err);
        if (st == NINLIL_CTRL_SESSION_OK) {
            s->tracked_kind = NINLIL_LS_TRACKED_NOTICE;
            s->tracked_token = token;
            s->tracked_sequence = seq;
            s->tracked_tx_kind = NINLIL_LOGICAL_SESSION_TX_KIND_RESET;
            sat_inc(&s->counters.tx_actions_submitted);
        }
        return NINLIL_LOGICAL_SESSION_OK;
    }

    if (action_peek(s, &act) != 0) {
        return NINLIL_LOGICAL_SESSION_OK;
    }
    /* After continuity notice accepted FIFO: HELLO_ACK may follow. */
    if (encode_action_payload(
            &act, s->ncl1_scratch, sizeof(s->ncl1_scratch), &ncl1_len)
        != NINLIL_LOGICAL_SESSION_OK) {
        action_pop(s);
        return NINLIL_LOGICAL_SESSION_OK;
    }
    ncg1_type = act.ncg1_type;
    seq = s->next_tx_seq;
    act.sequence = seq;
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = ncg1_type;
    fields.flags = 0u;
    fields.stream_or_cell_id = 0u;
    fields.sequence = seq;
    fields.payload.data = s->ncl1_scratch;
    fields.payload.length = (uint32_t)ncl1_len;
    st = ninlil_ctrl_session_tracked_submit_tx(
        s->u3, &s->epoch, &fields, &token, &err);
    if (st == NINLIL_CTRL_SESSION_OK) {
        s->tracked_kind = NINLIL_LS_TRACKED_ORDINARY;
        s->tracked_token = token;
        s->tracked_sequence = seq;
        s->tracked_tx_kind = act.kind;
        s->tracked_request_id = act.request_id;
        s->tracked_generation = act.session_generation;
        s->tracked_cookie = act.session_cookie;
        s->tracked_hello_result = act.hello_result;
        s->tracked_gen_burned = act.gen_burned;
        s->tracked_reset_code = act.reset_code;
        s->tracked_opaque = act.opaque;
        action_pop(s);
        sat_inc(&s->counters.tx_actions_submitted);
    }
    return NINLIL_LOGICAL_SESSION_OK;
}

static void on_raw_accepted(struct ninlil_logical_session *s)
{
    sat_inc(&s->counters.raw_accepts);
    s->last_tx_commit =
        NINLIL_LOGICAL_SESSION_TX_COMMIT_RAW_ACCEPTED_CURRENT_EPOCH;
    s->last_tx_kind = (ninlil_logical_session_tx_kind_t)s->tracked_tx_kind;
    s->last_tx_sequence = s->tracked_sequence;

    /* Sequence consume only on raw accept. */
    if (s->next_tx_seq < UINT32_MAX) {
        s->next_tx_seq += 1u;
    }

    if (s->tracked_kind == NINLIL_LS_TRACKED_NOTICE) {
        s->notice.phase = NINLIL_LS_NOTICE_ACCEPTED;
        sat_inc(&s->counters.continuity_notice_accepted);
        /* fence once already done at creation; do not re-fence */
        clear_notice(s); /* slot free after accept for further notices */
        return;
    }

    if (s->tracked_tx_kind == NINLIL_LOGICAL_SESSION_TX_KIND_HELLO_ACK) {
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && s->tracked_hello_result == NINLIL_NCL1_HELLO_OK
            && s->tracked_generation != 0u && s->tracked_cookie != 0u) {
            s->active_generation = s->tracked_generation;
            s->active_cookie = s->tracked_cookie;
            s->state = NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE;
            s->first_ping_armed = 0; /* Cell is not PING initiator */
        } else if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL) {
            s->state = NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION;
        }
    } else if (s->tracked_tx_kind == NINLIL_LOGICAL_SESSION_TX_KIND_HELLO) {
        /* HELLO sent: arm/refresh ACK timer already set at schedule. */
        int hi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_HELLO);
        if (hi >= 0) {
            uint64_t dl;
            if (add_u64_overflow(
                    s->now_ms,
                    (uint64_t)s->hello_retry_delay_ms,
                    &dl)
                == 0) {
                s->inflight[hi].deadline_ms = dl;
            }
        }
    } else if (s->tracked_tx_kind == NINLIL_LOGICAL_SESSION_TX_KIND_PING) {
        int pi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING);
        uint64_t dl;
        s->ping_inflight = 1;
        if (add_u64_overflow(
                s->now_ms,
                NINLIL_LOGICAL_SESSION_PONG_TIMEOUT_MS,
                &dl)
            == 0) {
            s->ping_deadline_ms = dl;
            if (pi >= 0) {
                s->inflight[pi].deadline_ms = dl;
            }
        }
    } else if (s->tracked_tx_kind == NINLIL_LOGICAL_SESSION_TX_KIND_RESET) {
        /* Ordinary RESET_SESSION sender fence (not continuity notice). */
        if (s->tracked_reset_code == NINLIL_NCL1_RESET_SESSION) {
            uint64_t dl;
            fence_session_keep_tx_seq(s);
            if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
                if (add_u64_overflow(
                        s->now_ms,
                        NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS,
                        &dl)
                    == 0) {
                    s->rehello_armed = 1;
                    s->rehello_deadline_ms = dl;
                }
                /* Overflow: pure precheck rejects the step; do not wrap. */
            }
        } else if (s->tracked_reset_code == NINLIL_NCL1_RESET_PARSER) {
            rx_only_cold(s);
            fence_session_keep_tx_seq(s);
        }
    }
}

/*
 * Sole harvest of U3 6-way terminal. On tx_resolve API failure: keep token
 * and return IO_ERROR (never OK-disguise). PENDING keeps token.
 */
static ninlil_logical_session_status_t resolve_tracked(
    struct ninlil_logical_session *s)
{
    ninlil_ctrl_session_tx_resolution_t res =
        NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_status_t st;

    if (s->tracked_kind == NINLIL_LS_TRACKED_NONE || s->u3 == NULL) {
        return NINLIL_LOGICAL_SESSION_OK;
    }
    st = ninlil_ctrl_session_tx_resolve(
        s->u3, s->tracked_token, 0, &res, &err);
    if (st != NINLIL_CTRL_SESSION_OK) {
        /* Token retained for retry; do not invent a terminal. */
        return NINLIL_LOGICAL_SESSION_IO_ERROR;
    }
    switch (res) {
    case NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED:
        s->last_tx_commit =
            NINLIL_LOGICAL_SESSION_TX_COMMIT_PENDING_UNACCEPTED;
        return NINLIL_LOGICAL_SESSION_OK;
    case NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH:
        on_raw_accepted(s);
        s->tracked_kind = NINLIL_LS_TRACKED_NONE;
        s->tracked_token = 0u;
        return NINLIL_LOGICAL_SESSION_OK;
    case NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED:
        s->last_tx_commit =
            NINLIL_LOGICAL_SESSION_TX_COMMIT_CANCELLED_UNACCEPTED;
        s->last_tx_kind =
            (ninlil_logical_session_tx_kind_t)s->tracked_tx_kind;
        s->last_tx_sequence = s->tracked_sequence;
        s->tracked_kind = NINLIL_LS_TRACKED_NONE;
        s->tracked_token = 0u;
        return NINLIL_LOGICAL_SESSION_OK;
    case NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED:
        s->last_tx_commit =
            NINLIL_LOGICAL_SESSION_TX_COMMIT_FENCED_UNACCEPTED;
        s->last_tx_kind =
            (ninlil_logical_session_tx_kind_t)s->tracked_tx_kind;
        s->last_tx_sequence = s->tracked_sequence;
        s->tracked_kind = NINLIL_LS_TRACKED_NONE;
        s->tracked_token = 0u;
        s->epoch_claimed = 0;
        return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
    case NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED:
        s->last_tx_commit =
            NINLIL_LOGICAL_SESSION_TX_COMMIT_RAW_ACCEPTED_THEN_FENCED;
        s->last_tx_kind =
            (ninlil_logical_session_tx_kind_t)s->tracked_tx_kind;
        s->last_tx_sequence = s->tracked_sequence;
        /* Accept fact: sequence consumed, epoch fenced. */
        if (s->next_tx_seq < UINT32_MAX) {
            s->next_tx_seq += 1u;
        }
        sat_inc(&s->counters.raw_accepts);
        s->tracked_kind = NINLIL_LS_TRACKED_NONE;
        s->tracked_token = 0u;
        s->epoch_claimed = 0;
        return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
    case NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL:
        s->last_tx_commit =
            NINLIL_LOGICAL_SESSION_TX_COMMIT_INDETERMINATE_PARTIAL;
        s->last_tx_kind =
            (ninlil_logical_session_tx_kind_t)s->tracked_tx_kind;
        s->last_tx_sequence = s->tracked_sequence;
        s->tracked_kind = NINLIL_LS_TRACKED_NONE;
        s->tracked_token = 0u;
        s->epoch_claimed = 0;
        fence_session_keep_tx_seq(s);
        return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
    default:
        return NINLIL_LOGICAL_SESSION_IO_ERROR;
    }
}

/*
 * Pure deadline overflow precheck (no live object writes). Covers every
 * now+duration / eligible+slack path the step may take (HELLO arm, RESET
 * rehello, PONG cadence, PING timeout/slack). Overflow → step returns
 * DEADLINE_OVERFLOW with exact zero mutation (docs/23 §8.11 / docs/07 U4).
 */
static int deadline_overflow_pure(
    ninlil_logical_session_state_t state,
    ninlil_logical_session_role_t role,
    int ping_inflight,
    int first_ping_armed,
    uint64_t candidate_now_ms,
    uint64_t ping_eligible_at_ms)
{
    uint64_t tmp;
    uint64_t eligible;
    uint64_t max_add = max_deadline_add_ms();

    /* Universal ceiling for any now + duration used in this step. */
    if (add_u64_overflow(candidate_now_ms, max_add, &tmp) != 0) {
        return 1;
    }

    /* Controller ACTIVE PING path: eligible_at + slack (may bind to now). */
    if (state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE
        && role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER
        && ping_inflight == 0) {
        eligible = first_ping_armed ? candidate_now_ms : ping_eligible_at_ms;
        if (add_u64_overflow(
                eligible,
                NINLIL_LOGICAL_SESSION_PING_DISPATCH_SLACK_MS,
                &tmp)
            != 0) {
            return 1;
        }
        if (add_u64_overflow(
                candidate_now_ms,
                NINLIL_LOGICAL_SESSION_PONG_TIMEOUT_MS,
                &tmp)
            != 0) {
            return 1;
        }
        if (add_u64_overflow(
                candidate_now_ms,
                NINLIL_LOGICAL_SESSION_PING_CADENCE_MS,
                &tmp)
            != 0) {
            return 1;
        }
    }

    /* PONG RX (controller ACTIVE) sets eligible = now + cadence. */
    if (state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE
        && role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER
        && ping_inflight != 0) {
        if (add_u64_overflow(
                candidate_now_ms,
                NINLIL_LOGICAL_SESSION_PING_CADENCE_MS,
                &tmp)
            != 0) {
            return 1;
        }
        if (add_u64_overflow(
                candidate_now_ms,
                NINLIL_LOGICAL_SESSION_PONG_TIMEOUT_MS,
                &tmp)
            != 0) {
            return 1;
        }
    }

    /* HELLO arm / RESET rehello (controller). */
    if (role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
        if (add_u64_overflow(
                candidate_now_ms,
                NINLIL_LOGICAL_SESSION_REHELLO_AFTER_RESET_MS,
                &tmp)
            != 0) {
            return 1;
        }
        if (add_u64_overflow(
                candidate_now_ms,
                (uint64_t)NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS
                    + ((uint64_t)NINLIL_LOGICAL_SESSION_HELLO_RETRY_MAX_MS * 20u)
                        / 100u,
                &tmp)
            != 0) {
            return 1;
        }
    }

    (void)state;
    return 0;
}

static ninlil_logical_session_tx_commit_t map_u3_resolution(
    ninlil_ctrl_session_tx_resolution_t res)
{
    switch (res) {
    case NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_PENDING_UNACCEPTED;
    case NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_RAW_ACCEPTED_CURRENT_EPOCH;
    case NINLIL_CTRL_SESSION_TX_CANCELLED_UNACCEPTED:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_CANCELLED_UNACCEPTED;
    case NINLIL_CTRL_SESSION_TX_FENCED_UNACCEPTED:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_FENCED_UNACCEPTED;
    case NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_RAW_ACCEPTED_THEN_FENCED;
    case NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_INDETERMINATE_PARTIAL;
    default:
        return NINLIL_LOGICAL_SESSION_TX_COMMIT_NONE;
    }
}

/*
 * Map U3 pump status into logical recovery. Never clears tracked token —
 * caller must resolve_tracked first so 6-way terminals are harvested.
 * Never treats fence/IO as OK.
 */
static ninlil_logical_session_status_t apply_u3_pump_status(
    struct ninlil_logical_session *s,
    ninlil_ctrl_session_status_t st)
{
    switch (st) {
    case NINLIL_CTRL_SESSION_OK:
    case NINLIL_CTRL_SESSION_WOULD_BLOCK:
    case NINLIL_CTRL_SESSION_NEED_MORE:
        return NINLIL_LOGICAL_SESSION_OK;
    case NINLIL_CTRL_SESSION_RX_OVERFLOW:
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
            && s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            cell_continuity_loss(s, 1);
        } else {
            controller_continuity_loss(s, 0);
            sat_inc(&s->counters.rx_overflow);
        }
        return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
    case NINLIL_CTRL_SESSION_CONTINUITY_LOST:
    case NINLIL_CTRL_SESSION_GENERATION_MISMATCH:
        /* Session fence only; token/terminal already resolved by caller. */
        if (s->tracked_kind == NINLIL_LS_TRACKED_NONE) {
            s->epoch_claimed = 0;
        }
        fence_session_keep_tx_seq(s);
        if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
            s->rehello_armed = 1;
            s->rehello_deadline_ms = s->now_ms;
        }
        return NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
    case NINLIL_CTRL_SESSION_ERR_LINK_DOWN:
    case NINLIL_CTRL_SESSION_CLOSED:
    case NINLIL_CTRL_SESSION_IO_ERROR:
        /* Token already resolved when possible; do not drop unresolved token. */
        if (s->tracked_kind == NINLIL_LS_TRACKED_NONE) {
            s->epoch_claimed = 0;
        }
        drop_all_inflight(s);
        clear_ordinary_actions(s);
        clear_notice(s);
        clear_active(s);
        if (s->tracked_kind == NINLIL_LS_TRACKED_NONE) {
            s->state = NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED;
            s->have_rx_seq = 0;
        } else {
            /* Unresolved token: stay non-DISCONNECTED with accurate meta. */
            fence_session_keep_tx_seq(s);
        }
        return NINLIL_LOGICAL_SESSION_IO_ERROR;
    case NINLIL_CTRL_SESSION_WRONG_OWNER:
        return NINLIL_LOGICAL_SESSION_IO_ERROR;
    default:
        return NINLIL_LOGICAL_SESSION_IO_ERROR;
    }
}

static void run_timers(struct ninlil_logical_session *s)
{
    int hi;

    if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
        if (s->rehello_armed && s->now_ms >= s->rehello_deadline_ms) {
            if (s->state == NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION
                || s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_SENT) {
                if (schedule_controller_hello(s, 0) == 0) {
                    s->rehello_armed = 0;
                }
                /* Failure: keep rehello_armed so next step retries (no silent loss). */
            } else {
                s->rehello_armed = 0;
            }
        }
        if (s->hello_timer_armed
            && s->state == NINLIL_LOGICAL_SESSION_STATE_HELLO_SENT
            && s->now_ms >= s->hello_deadline_ms) {
            /* HELLO retry: do not cold sequences; next_tx_seq continues */
            if (schedule_controller_hello(s, 1) != 0) {
                /* Keep timer armed for retry; no silent plan loss. */
                (void)arm_hello_timer(
                    s,
                    s->hello_retry_delay_ms != 0u
                        ? s->hello_retry_delay_ms
                        : NINLIL_LOGICAL_SESSION_HELLO_RETRY_INITIAL_MS);
            }
        }
        /* PING liveness */
        if (s->state == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
            if (s->ping_inflight && s->now_ms >= s->ping_deadline_ms) {
                uint64_t next_el;
                sat_inc(&s->counters.pong_miss);
                s->pong_miss_streak += 1u;
                hi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING);
                if (hi >= 0) {
                    inflight_remove_index(s, hi);
                }
                s->ping_inflight = 0;
                if (add_u64_overflow(
                        s->now_ms,
                        NINLIL_LOGICAL_SESSION_PING_CADENCE_MS,
                        &next_el)
                    == 0) {
                    s->ping_eligible_at_ms = next_el;
                }
                /* Overflow: pure precheck rejects; leave eligible unchanged. */
                if (s->pong_miss_streak
                    >= NINLIL_LOGICAL_SESSION_PONG_MISS_THRESHOLD) {
                    sat_inc(&s->counters.liveness_fail);
                    fence_session_keep_tx_seq(s);
                    s->rehello_armed = 1;
                    s->rehello_deadline_ms = s->now_ms;
                }
            }
            if (!s->ping_inflight) {
                uint64_t slack_deadline;
                int eligible = s->first_ping_armed
                    || s->now_ms >= s->ping_eligible_at_ms;
                if (s->first_ping_armed) {
                    s->ping_eligible_at_ms = s->now_ms;
                    s->first_ping_armed = 0;
                    eligible = 1;
                }
                if (eligible) {
                    if (add_u64_overflow(
                            s->ping_eligible_at_ms,
                            NINLIL_LOGICAL_SESSION_PING_DISPATCH_SLACK_MS,
                            &slack_deadline)
                        != 0) {
                        /* Should have been caught precheck. */
                        return;
                    }
                    if (s->now_ms > slack_deadline && s->tracked_kind == NINLIL_LS_TRACKED_NONE
                        && inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING) < 0) {
                        ninlil_ls_tx_action_t peek_act;
                        int has_ping_action = 0;
                        uint32_t ai;
                        for (ai = 0u; ai < s->action_count; ++ai) {
                            uint32_t aidx =
                                (s->action_head + ai)
                                % NINLIL_LOGICAL_SESSION_TX_ACTION_MAX;
                            if (s->actions[aidx].kind
                                == NINLIL_LOGICAL_SESSION_TX_KIND_PING) {
                                has_ping_action = 1;
                                break;
                            }
                        }
                        (void)peek_act;
                        if (!has_ping_action) {
                            sat_inc(&s->counters.ping_dispatch_miss);
                            sat_inc(&s->counters.liveness_fail);
                            fence_session_keep_tx_seq(s);
                            s->rehello_armed = 1;
                            s->rehello_deadline_ms = s->now_ms;
                        }
                    } else if (
                        inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING) < 0
                        && s->action_count < NINLIL_LOGICAL_SESSION_TX_ACTION_MAX
                        && s->now_ms
                            <= s->ping_eligible_at_ms
                                + NINLIL_LOGICAL_SESSION_PING_DISPATCH_SLACK_MS) {
                        ninlil_ls_tx_action_t a;
                        uint32_t req = alloc_request_id(s);
                        uint64_t token =
                            ((uint64_t)req << 32) ^ s->now_ms ^ 0xA5A5A5A5u;
                        (void)memset(&a, 0, sizeof(a));
                        a.kind = NINLIL_LOGICAL_SESSION_TX_KIND_PING;
                        a.ncg1_type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
                        a.message_type = NINLIL_NCL1_MSG_PING_BODY;
                        a.request_id = req;
                        a.session_generation = s->active_generation;
                        a.session_cookie = s->active_cookie;
                        a.body_length = NINLIL_NCL1_BODY_PING_BYTES;
                        a.opaque = token == 0u ? 1u : token;
                        (void)action_enqueue(s, &a);
                        (void)inflight_add(
                            s, NINLIL_LS_INFLIGHT_PING, req, 0u, a.opaque);
                    }
                }
            }
        }
    }
}

static void drain_rx(struct ninlil_logical_session *s)
{
    ninlil_ctrl_session_frame_t fr;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_status_t st;

    if (s->u3 == NULL) {
        return;
    }
    for (;;) {
        (void)memset(&fr, 0, sizeof(fr));
        st = ninlil_ctrl_session_take_rx(
            s->u3,
            s->rx_payload,
            (uint32_t)sizeof(s->rx_payload),
            &fr,
            &err);
        if (st == NINLIL_CTRL_SESSION_NEED_MORE) {
            break;
        }
        if (st != NINLIL_CTRL_SESSION_OK) {
            if (st == NINLIL_CTRL_SESSION_CONTINUITY_LOST
                || st == NINLIL_CTRL_SESSION_RX_OVERFLOW) {
                if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
                    && s->state
                        == NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE) {
                    cell_continuity_loss(s, 1);
                } else {
                    controller_continuity_loss(s, 0);
                    sat_inc(&s->counters.rx_overflow);
                }
            }
            break;
        }
        process_rx_frame(s, &fr);
    }
}

/* ---- public API ---- */

size_t ninlil_logical_session_object_size(void)
{
    return sizeof(struct ninlil_logical_session);
}

size_t ninlil_logical_session_object_align(void)
{
    /* Actual complete-type alignment — not a floor constant alone. */
    return _Alignof(struct ninlil_logical_session);
}

ninlil_logical_session_status_t ninlil_logical_session_init(
    void *storage,
    size_t storage_bytes,
    const ninlil_logical_session_config_t *config,
    ninlil_logical_session_t **out_session)
{
    struct ninlil_logical_session *s;
    ninlil_ctrl_session_t *u3 = NULL;
    uintptr_t addr;

    if (out_session == NULL) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    *out_session = NULL;
    if (storage == NULL || config == NULL
        || storage_bytes < sizeof(struct ninlil_logical_session)) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    if (config->role != NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER
        && config->role != NINLIL_LOGICAL_SESSION_ROLE_CELL) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    if (config->role == NINLIL_LOGICAL_SESSION_ROLE_CELL
        && config->cookie_rng == NULL) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    addr = (uintptr_t)storage;
    if ((addr % _Alignof(struct ninlil_logical_session)) != 0u) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }

    s = as_session(storage);
    (void)memset(s, 0, sizeof(*s));
    if (ninlil_ctrl_session_init_object(&s->u3_obj, &u3)
        != NINLIL_CTRL_SESSION_OK) {
        return NINLIL_LOGICAL_SESSION_INVALID_STATE;
    }
    s->magic = MAGIC;
    s->role = config->role;
    s->state = NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED;
    s->cookie_rng = config->cookie_rng;
    s->cookie_rng_ctx = config->cookie_rng_ctx;
    s->jitter_fn = config->jitter_fn;
    s->jitter_ctx = config->jitter_ctx;
    s->u3 = u3;
    s->request_next = 1u;
    s->last_tx_commit = NINLIL_LOGICAL_SESSION_TX_COMMIT_NONE;
    *out_session = (ninlil_logical_session_t *)s;
    return NINLIL_LOGICAL_SESSION_OK;
}

ninlil_logical_session_status_t ninlil_logical_session_init_object(
    ninlil_logical_session_object_t *object,
    const ninlil_logical_session_config_t *config,
    ninlil_logical_session_t **out_session)
{
    if (object == NULL) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    /* Typed member address — not char-array storage cast. */
    return ninlil_logical_session_init(
        &object->session, sizeof(object->session), config, out_session);
}

ninlil_logical_session_status_t ninlil_logical_session_bind(
    ninlil_logical_session_t *session,
    ninlil_byte_stream_t *stream)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_status_t st;

    if (!session_ok(s) || stream == NULL) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    /* Double-bind / bind without unbind: exact zero mutation. */
    if (s->state != NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED) {
        return NINLIL_LOGICAL_SESSION_INVALID_STATE;
    }
    st = ninlil_ctrl_session_bind(s->u3, stream, &err);
    if (st != NINLIL_CTRL_SESSION_OK) {
        return NINLIL_LOGICAL_SESSION_IO_ERROR;
    }
    st = ninlil_ctrl_session_logical_epoch_begin(s->u3, &s->epoch, &err);
    if (st != NINLIL_CTRL_SESSION_OK) {
        (void)ninlil_ctrl_session_unbind(s->u3, &err);
        if (st == NINLIL_CTRL_SESSION_EPOCH_EXHAUSTED) {
            return NINLIL_LOGICAL_SESSION_EPOCH_EXHAUSTED;
        }
        return NINLIL_LOGICAL_SESSION_INVALID_STATE;
    }
    s->epoch_claimed = 1;
    s->next_tx_seq = 0u;
    s->have_rx_seq = 0;
    s->last_rx_seq = 0u;
    clear_active(s);
    drop_all_inflight(s);
    clear_ordinary_actions(s);
    clear_notice(s);
    s->tracked_kind = NINLIL_LS_TRACKED_NONE;
    s->tracked_token = 0u;
    s->state = NINLIL_LOGICAL_SESSION_STATE_LINK_UP_NO_SESSION;
    s->hello_timer_armed = 0;
    s->rehello_armed = 0;
    s->ping_inflight = 0;
    s->first_ping_armed = 0;
    s->pong_miss_streak = 0u;
    if (s->role == NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER) {
        s->rehello_armed = 1;
        s->rehello_deadline_ms = s->have_now ? s->now_ms : 0u;
    }
    return NINLIL_LOGICAL_SESSION_OK;
}

ninlil_logical_session_status_t ninlil_logical_session_unbind(
    ninlil_logical_session_t *session)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_status_t st;
    ninlil_logical_session_status_t out = NINLIL_LOGICAL_SESSION_OK;
    int u3_unbound = 0;

    if (!session_ok(s)) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    if (s->state == NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED) {
        return NINLIL_LOGICAL_SESSION_OK;
    }

    /* Resolve tracked token with accurate terminal reflection. */
    if (s->tracked_kind != NINLIL_LS_TRACKED_NONE && s->u3 != NULL) {
        ninlil_ctrl_session_tx_resolution_t res =
            NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED;
        st = ninlil_ctrl_session_tx_resolve(
            s->u3, s->tracked_token, 1, &res, &err);
        if (st != NINLIL_CTRL_SESSION_OK) {
            out = NINLIL_LOGICAL_SESSION_IO_ERROR;
        } else {
            s->last_tx_commit = map_u3_resolution(res);
            s->last_tx_kind =
                (ninlil_logical_session_tx_kind_t)s->tracked_tx_kind;
            s->last_tx_sequence = s->tracked_sequence;
            if (res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_CURRENT_EPOCH) {
                /* Accept fact before unbind: sequence already committed path. */
                if (s->next_tx_seq < UINT32_MAX) {
                    s->next_tx_seq += 1u;
                }
                sat_inc(&s->counters.raw_accepts);
            } else if (
                res == NINLIL_CTRL_SESSION_TX_RAW_ACCEPTED_THEN_FENCED) {
                if (s->next_tx_seq < UINT32_MAX) {
                    s->next_tx_seq += 1u;
                }
                sat_inc(&s->counters.raw_accepts);
                out = NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
            } else if (res == NINLIL_CTRL_SESSION_TX_INDETERMINATE_PARTIAL) {
                out = NINLIL_LOGICAL_SESSION_CONTINUITY_LOST;
            } else if (res == NINLIL_CTRL_SESSION_TX_PENDING_UNACCEPTED) {
                /* cancel_if_pending=1 should not leave pending */
                out = NINLIL_LOGICAL_SESSION_IO_ERROR;
            }
            s->tracked_kind = NINLIL_LS_TRACKED_NONE;
            s->tracked_token = 0u;
        }
    }

    if (s->epoch_claimed && s->u3 != NULL) {
        st = ninlil_ctrl_session_logical_epoch_end(s->u3, &s->epoch, &err);
        if (st != NINLIL_CTRL_SESSION_OK) {
            /* Tracked must be clear; if end fails, do not fake clean unbind. */
            if (out == NINLIL_LOGICAL_SESSION_OK) {
                out = NINLIL_LOGICAL_SESSION_INVALID_STATE;
            }
        } else {
            s->epoch_claimed = 0;
        }
    }

    if (s->u3 != NULL) {
        st = ninlil_ctrl_session_unbind(s->u3, &err);
        if (st != NINLIL_CTRL_SESSION_OK) {
            if (out == NINLIL_LOGICAL_SESSION_OK) {
                out = NINLIL_LOGICAL_SESSION_IO_ERROR;
            }
        } else {
            u3_unbound = 1;
        }
    } else {
        u3_unbound = 1;
    }

    drop_all_inflight(s);
    clear_ordinary_actions(s);
    clear_notice(s);
    clear_active(s);
    s->have_rx_seq = 0;
    s->hello_timer_armed = 0;
    s->rehello_armed = 0;
    s->ping_inflight = 0;
    /*
     * DISCONNECTED only when U3 unbind completed. Otherwise leave
     * non-DISCONNECTED with accurate commit meta (fail-closed).
     */
    if (u3_unbound) {
        s->state = NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED;
        s->next_tx_seq = 0u;
        s->epoch_claimed = 0;
        s->tracked_kind = NINLIL_LS_TRACKED_NONE;
        s->tracked_token = 0u;
    }
    return out;
}

ninlil_logical_session_status_t ninlil_logical_session_step(
    ninlil_logical_session_t *session,
    uint64_t now_monotonic_ms,
    uint32_t timeout_ms)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    ninlil_ctrl_session_error_t err;
    ninlil_ctrl_session_status_t st;
    ninlil_logical_session_status_t pump_st = NINLIL_LOGICAL_SESSION_OK;
    ninlil_logical_session_status_t step_st = NINLIL_LOGICAL_SESSION_OK;

    if (!session_ok(s)) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }

    /* All invalid/prechecks before any clock or authority mutation. */
    if (s->state == NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED) {
        return NINLIL_LOGICAL_SESSION_INVALID_STATE;
    }
    if (s->have_now && now_monotonic_ms < s->now_ms) {
        return NINLIL_LOGICAL_SESSION_TIME_REGRESSED;
    }
    if (deadline_overflow_pure(
            s->state,
            s->role,
            s->ping_inflight,
            s->first_ping_armed,
            now_monotonic_ms,
            s->ping_eligible_at_ms)
        != 0) {
        return NINLIL_LOGICAL_SESSION_DEADLINE_OVERFLOW;
    }

    /* Commit clock only after prechecks pass. */
    s->now_ms = now_monotonic_ms;
    s->have_now = 1;

    /*
     * Fixed one-step progress budget (exactly-once stages, max 1 tracked):
     * timers → submit(if idle) → pump×1 → resolve×1 → take_rx drain.
     * Host re-steps for further frames. No multi-pump inside one step.
     */
    run_timers(s);
    {
        ninlil_logical_session_status_t sub_st = try_submit_tracked(s);
        if (sub_st != NINLIL_LOGICAL_SESSION_OK) {
            step_st = sub_st;
        }
    }

    if (s->u3 != NULL) {
        st = ninlil_ctrl_session_pump(s->u3, timeout_ms, &err);
        /*
         * Resolve before pump-status recovery so 6-way terminals are
         * harvested while token is still known.
         */
        {
            ninlil_logical_session_status_t rst = resolve_tracked(s);
            if (rst != NINLIL_LOGICAL_SESSION_OK) {
                step_st = rst;
            }
        }
        pump_st = apply_u3_pump_status(s, st);
        if (pump_st != NINLIL_LOGICAL_SESSION_OK
            && step_st == NINLIL_LOGICAL_SESSION_OK) {
            step_st = pump_st;
        }
    } else {
        {
            ninlil_logical_session_status_t rst = resolve_tracked(s);
            if (rst != NINLIL_LOGICAL_SESSION_OK) {
                step_st = rst;
            }
        }
    }

    if (s->state != NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED) {
        drain_rx(s);
    }

    return step_st;
}

void ninlil_logical_session_snapshot(
    const ninlil_logical_session_t *session,
    ninlil_logical_session_snapshot_t *out)
{
    const struct ninlil_logical_session *s = as_session_c(session);
    int hi;
    int pi;

    if (out == NULL) {
        return;
    }
    (void)memset(out, 0, sizeof(*out));
    if (!session_ok(s)) {
        return;
    }
    out->role = s->role;
    out->state = s->state;
    out->now_monotonic_ms = s->now_ms;
    out->active_generation = s->active_generation;
    out->active_cookie = s->active_cookie;
    out->last_issued_generation = s->last_issued_generation;
    out->burned_generation_count = s->burned_generation_count;
    out->next_tx_seq = s->next_tx_seq;
    out->have_rx_seq = s->have_rx_seq;
    out->last_rx_seq = s->last_rx_seq;
    out->inflight_count = s->inflight_count;
    out->tx_action_count = s->action_count;
    if (s->action_count > 0u) {
        out->head_tx_kind = s->actions[s->action_head].kind;
    }
    out->continuity_notice_pending =
        (s->notice.phase == NINLIL_LS_NOTICE_PENDING) ? 1 : 0;
    out->continuity_notice_raw_accepted =
        (s->notice.phase == NINLIL_LS_NOTICE_ACCEPTED) ? 1 : 0;
    out->tracked_outstanding = (s->tracked_kind != NINLIL_LS_TRACKED_NONE) ? 1 : 0;
    out->last_tx_commit = s->last_tx_commit;
    out->last_tx_kind = s->last_tx_kind;
    out->last_tx_sequence = s->last_tx_sequence;
    hi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_HELLO);
    out->sole_hello_request_id =
        (hi >= 0) ? s->inflight[hi].request_id : 0u;
    pi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING);
    out->sole_ping_request_id =
        (pi >= 0) ? s->inflight[pi].request_id : 0u;
    out->counters = s->counters;
}

ninlil_logical_session_role_t ninlil_logical_session_role(
    const ninlil_logical_session_t *session)
{
    const struct ninlil_logical_session *s = as_session_c(session);
    return session_ok(s) ? s->role : 0u;
}

ninlil_logical_session_state_t ninlil_logical_session_state(
    const ninlil_logical_session_t *session)
{
    const struct ninlil_logical_session *s = as_session_c(session);
    return session_ok(s) ? s->state
                         : NINLIL_LOGICAL_SESSION_STATE_DISCONNECTED;
}

uint64_t ninlil_logical_session_now_ms(const ninlil_logical_session_t *session)
{
    const struct ninlil_logical_session *s = as_session_c(session);
    return session_ok(s) ? s->now_ms : 0u;
}

#if defined(NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM)
void ninlil_logical_session_test_force_request_next(
    ninlil_logical_session_t *session,
    uint32_t request_next)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->request_next = (request_next == 0u) ? 1u : request_next;
}

void ninlil_logical_session_test_force_last_issued_gen(
    ninlil_logical_session_t *session,
    uint32_t last_issued_gen)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->last_issued_generation = last_issued_gen;
}

void ninlil_logical_session_test_force_next_tx_seq(
    ninlil_logical_session_t *session,
    uint32_t next_tx_seq)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->next_tx_seq = next_tx_seq;
}

void ninlil_logical_session_test_force_rx_baseline(
    ninlil_logical_session_t *session,
    int have_rx_seq,
    uint32_t last_rx_seq)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->have_rx_seq = have_rx_seq ? 1 : 0;
    s->last_rx_seq = last_rx_seq;
}

void ninlil_logical_session_test_force_active(
    ninlil_logical_session_t *session,
    uint32_t generation,
    uint64_t cookie)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->active_generation = generation;
    s->active_cookie = cookie;
    s->state = NINLIL_LOGICAL_SESSION_STATE_SESSION_ACTIVE;
}

void ninlil_logical_session_test_force_state(
    ninlil_logical_session_t *session,
    ninlil_logical_session_state_t state)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->state = state;
}

ninlil_logical_session_status_t ninlil_logical_session_test_enqueue_ctrl_error(
    ninlil_logical_session_t *session,
    uint16_t error_code,
    uint32_t related_request_id)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    maybe_enqueue_ctrl_error(s, error_code, related_request_id);
    return NINLIL_LOGICAL_SESSION_OK;
}

ninlil_logical_session_status_t ninlil_logical_session_test_cell_continuity_loss(
    ninlil_logical_session_t *session)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    cell_continuity_loss(s, 0);
    return NINLIL_LOGICAL_SESSION_OK;
}

void ninlil_logical_session_test_controller_request_hello_now(
    ninlil_logical_session_t *session)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->rehello_armed = 1;
    s->rehello_deadline_ms = s->now_ms;
    s->hello_timer_armed = 0;
}

void ninlil_logical_session_test_force_ping_eligible_at(
    ninlil_logical_session_t *session,
    uint64_t eligible_at_ms)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    int pi;
    if (!session_ok(s)) {
        return;
    }
    s->ping_eligible_at_ms = eligible_at_ms;
    s->first_ping_armed = 0;
    /* Clear PING inflight bookkeeping so a fresh liveness cycle can start. */
    s->ping_inflight = 0;
    pi = inflight_find_kind(s, NINLIL_LS_INFLIGHT_PING);
    if (pi >= 0) {
        inflight_remove_index(s, pi);
    }
}

void ninlil_logical_session_test_fill_tx_action_queue(
    ninlil_logical_session_t *session)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    ninlil_ls_tx_action_t a;
    if (!session_ok(s)) {
        return;
    }
    (void)memset(&a, 0, sizeof(a));
    a.kind = NINLIL_LOGICAL_SESSION_TX_KIND_CTRL_ERROR;
    a.ncg1_type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    a.message_type = NINLIL_NCL1_MSG_CTRL_ERROR;
    a.body_length = NINLIL_NCL1_BODY_CTRL_ERROR_BYTES;
    a.body[1] = 1u; /* ERR_INVALID_NCL1 */
    while (s->action_count < NINLIL_LOGICAL_SESSION_TX_ACTION_MAX) {
        a.request_id = alloc_request_id(s);
        if (action_enqueue(s, &a) != 0) {
            break;
        }
    }
}

void ninlil_logical_session_test_force_burned_generation_count(
    ninlil_logical_session_t *session,
    uint32_t count)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s)) {
        return;
    }
    s->burned_generation_count = count;
}

ninlil_logical_session_status_t ninlil_logical_session_test_cell_try_prepare_ack(
    ninlil_logical_session_t *session,
    uint32_t request_id)
{
    struct ninlil_logical_session *s = (struct ninlil_logical_session *)session;
    if (!session_ok(s) || s->role != NINLIL_LOGICAL_SESSION_ROLE_CELL) {
        return NINLIL_LOGICAL_SESSION_INVALID_ARGUMENT;
    }
    if (cell_prepare_hello_ack(s, request_id, 1) != 0) {
        return NINLIL_LOGICAL_SESSION_CAPACITY;
    }
    return NINLIL_LOGICAL_SESSION_OK;
}
#endif
