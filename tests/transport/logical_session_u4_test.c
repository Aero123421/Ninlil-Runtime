/*
 * U4 scenario bridge: drives production logical_session from generated fixture.
 * Every action checks exact status, snapshot fields, counter abs/delta, TX summary.
 * No pass-mark catalog; no ID switch table.
 */
#include "control_frame_codec.h"
#include "fake_byte_stream.h"
#include "logical_session.h"
#include "logical_session_u4_vector_fixture.h"
#include "ncl1_codec.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "%s:%d: FAIL %s id=%s action=%u\n", __FILE__, \
                __LINE__, #cond, g_current_id, g_action_i);                    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const char *g_current_id = "";
static unsigned g_action_i = 0;

typedef struct cookie_rng_ctx {
    uint64_t seq[16];
    uint32_t n;
    uint32_t i;
    int fail;
} cookie_rng_ctx_t;

static int cookie_rng_cb(void *ctx, uint64_t *out)
{
    cookie_rng_ctx_t *c = (cookie_rng_ctx_t *)ctx;
    if (c == NULL || out == NULL) {
        return -1;
    }
    if (c->fail) {
        return -1;
    }
    if (c->i >= c->n) {
        *out = 0xC0FFEE0123456789ull;
        return 0;
    }
    *out = c->seq[c->i++];
    return 0;
}

typedef struct jitter_ctx {
    uint32_t value;
    int fail;
} jitter_ctx_t;

static int jitter_cb(void *ctx, uint32_t span, uint32_t *out)
{
    jitter_ctx_t *j = (jitter_ctx_t *)ctx;
    (void)span;
    if (j == NULL || out == NULL) {
        return -1;
    }
    if (j->fail) {
        return -1;
    }
    *out = j->value;
    return 0;
}

typedef struct peer {
    int used;
    ninlil_logical_session_object_t obj;
    ninlil_logical_session_t *sess;
    ninlil_fake_byte_stream_t fake;
    cookie_rng_ctx_t rng;
    jitter_ctx_t jitter;
    ninlil_logical_session_snapshot_t baseline;
    int have_baseline;
    uint8_t last_tx[2048];
    uint32_t last_tx_len;
    uint8_t last_tx_type;
    uint32_t last_tx_seq;
} peer_t;

static int peer_init_from_pre(peer_t *p, const ninlil_ls_u4_peer_pre_t *pre)
{
    ninlil_logical_session_config_t cfg;
    uint32_t i;
    (void)memset(p, 0, sizeof(*p));
    if (pre == NULL || pre->used == 0u) {
        return 0;
    }
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.role = (ninlil_logical_session_role_t)pre->role;
    p->rng.n = pre->n_cookies;
    if (p->rng.n > 16u) {
        p->rng.n = 16u;
    }
    for (i = 0u; i < p->rng.n; ++i) {
        p->rng.seq[i] = pre->cookies[i];
    }
    p->rng.fail = (int)pre->rng_fail;
    cfg.cookie_rng = cookie_rng_cb;
    cfg.cookie_rng_ctx = &p->rng;
    cfg.jitter_fn = jitter_cb;
    cfg.jitter_ctx = &p->jitter;
    ninlil_fake_byte_stream_init(&p->fake);
    ninlil_fake_byte_stream_open_up(&p->fake, 1u);
    REQUIRE(
        ninlil_logical_session_init_object(&p->obj, &cfg, &p->sess)
        == NINLIL_LOGICAL_SESSION_OK);
    REQUIRE(
        ninlil_logical_session_bind(p->sess, &p->fake.view)
        == NINLIL_LOGICAL_SESSION_OK);
    p->used = 1;
    return 0;
}

static void capture_tx(peer_t *p)
{
    p->last_tx_len =
        ninlil_fake_byte_stream_take_tx(&p->fake, p->last_tx, sizeof(p->last_tx));
    p->last_tx_type = 0u;
    p->last_tx_seq = 0u;
    if (p->last_tx_len >= 26u) {
        p->last_tx_type = p->last_tx[5];
        p->last_tx_seq = ((uint32_t)p->last_tx[12] << 24)
            | ((uint32_t)p->last_tx[13] << 16) | ((uint32_t)p->last_tx[14] << 8)
            | (uint32_t)p->last_tx[15];
    }
}

static uint64_t counter_at(
    const ninlil_logical_session_counters_t *c,
    uint16_t idx)
{
    const uint64_t *base = (const uint64_t *)(const void *)c;
    if (idx >= (uint16_t)NINLIL_LS_U4_COUNTER_FIELD_COUNT) {
        return 0ull;
    }
    return base[idx];
}

static int check_expect_on_peer(
    peer_t *p,
    const ninlil_ls_u4_expect_t *e,
    uint32_t status,
    int have_status)
{
    ninlil_logical_session_snapshot_t snap;
    uint8_t i;
    REQUIRE(p != NULL && p->used);
    ninlil_logical_session_snapshot(p->sess, &snap);

    if (have_status && (e->mask & NINLIL_LS_U4_EF_STATUS) != 0u) {
        REQUIRE(status == e->status);
    }
    if ((e->mask & NINLIL_LS_U4_EF_STATE) != 0u) {
        REQUIRE(snap.state == e->state);
    }
    if ((e->mask & NINLIL_LS_U4_EF_GEN) != 0u) {
        REQUIRE(snap.active_generation == e->active_generation);
    }
    if ((e->mask & NINLIL_LS_U4_EF_COOKIE) != 0u) {
        REQUIRE(snap.active_cookie == e->active_cookie);
    }
    if ((e->mask & NINLIL_LS_U4_EF_NEXT_TX) != 0u) {
        REQUIRE(snap.next_tx_seq == e->next_tx_seq);
    }
    if ((e->mask & NINLIL_LS_U4_EF_HAVE_RX) != 0u) {
        REQUIRE(snap.have_rx_seq == e->have_rx_seq);
    }
    if ((e->mask & NINLIL_LS_U4_EF_LAST_RX) != 0u) {
        REQUIRE(snap.last_rx_seq == e->last_rx_seq);
    }
    if ((e->mask & NINLIL_LS_U4_EF_COMMIT) != 0u) {
        REQUIRE(snap.last_tx_commit == e->last_tx_commit);
    }
    if ((e->mask & NINLIL_LS_U4_EF_KIND) != 0u) {
        REQUIRE(snap.last_tx_kind == e->last_tx_kind);
    }
    if ((e->mask & NINLIL_LS_U4_EF_BURNS) != 0u) {
        REQUIRE(snap.burned_generation_count == e->burned_generation_count);
    }
    if ((e->mask & NINLIL_LS_U4_EF_NOTICE_P) != 0u) {
        REQUIRE(snap.continuity_notice_pending == e->continuity_notice_pending);
    }
    if ((e->mask & NINLIL_LS_U4_EF_NOTICE_A) != 0u) {
        REQUIRE(
            snap.continuity_notice_raw_accepted
            == e->continuity_notice_raw_accepted);
    }
    if ((e->mask & NINLIL_LS_U4_EF_PING_Z) != 0u) {
        if (e->sole_ping_request_id_zero != 0) {
            REQUIRE(snap.sole_ping_request_id == 0u);
        } else {
            REQUIRE(snap.sole_ping_request_id != 0u);
        }
    }
    if ((e->mask & NINLIL_LS_U4_EF_HELLO_NZ) != 0u) {
        if (e->sole_hello_request_id_nonzero != 0) {
            REQUIRE(snap.sole_hello_request_id != 0u);
        } else {
            REQUIRE(snap.sole_hello_request_id == 0u);
        }
    }
    if ((e->mask & NINLIL_LS_U4_EF_TX_HEX) != 0u) {
        const uint8_t *want;
        REQUIRE(e->tx_blob >= 0);
        REQUIRE((uint32_t)e->tx_blob < NINLIL_LS_U4_BLOB_COUNT);
        REQUIRE(e->tx_len == (uint32_t)ninlil_ls_u4_blob_lens[e->tx_blob]);
        REQUIRE(p->last_tx_len == e->tx_len);
        want = ninlil_ls_u4_blobs[e->tx_blob];
        REQUIRE(memcmp(p->last_tx, want, e->tx_len) == 0);
    } else {
        if ((e->mask & NINLIL_LS_U4_EF_TX_LEN) != 0u) {
            REQUIRE(p->last_tx_len == e->tx_len);
        }
        if ((e->mask & NINLIL_LS_U4_EF_TX_TYPE) != 0u) {
            REQUIRE(p->last_tx_type == (uint8_t)e->tx_ncg1_type);
        }
        if ((e->mask & NINLIL_LS_U4_EF_TX_SEQ) != 0u) {
            REQUIRE(p->last_tx_seq == e->tx_sequence);
        }
    }
    for (i = 0u; i < e->n_counter; ++i) {
        uint16_t fi = e->counters[i].field_index;
        int32_t dv = e->counters[i].delta;
        uint64_t got = counter_at(&snap.counters, fi);
        uint64_t want;
        if (e->counters[i].is_abs != 0u) {
            want = (uint64_t)(int64_t)dv;
            REQUIRE(got == want);
        } else {
            REQUIRE(p->have_baseline);
            want = counter_at(&p->baseline.counters, fi) + (uint64_t)(int64_t)dv;
            REQUIRE(got == want);
        }
    }
    return 0;
}

static uint32_t resolve_u32(
    uint8_t mode,
    uint32_t fixed,
    const ninlil_logical_session_snapshot_t *snap)
{
    switch (mode) {
    case NINLIL_LS_U4_MODE_ACTIVE:
        return snap->active_generation;
    case NINLIL_LS_U4_MODE_ACTIVE_PLUS:
        return snap->active_generation + fixed;
    case NINLIL_LS_U4_MODE_ACTIVE_XOR:
        return snap->active_generation ^ (fixed ? fixed : 1u);
    case NINLIL_LS_U4_MODE_ZERO:
        return 0u;
    case NINLIL_LS_U4_MODE_LAST_RX:
        return snap->last_rx_seq;
    case NINLIL_LS_U4_MODE_LAST_RX_PLUS:
        return snap->last_rx_seq + (fixed ? fixed : 1u);
    case NINLIL_LS_U4_MODE_SOLE_HELLO:
        return snap->sole_hello_request_id;
    case NINLIL_LS_U4_MODE_SOLE_HELLO_XOR: {
        uint32_t r = snap->sole_hello_request_id ^ 0xffffffffu;
        return r == 0u ? 1u : r;
    }
    default:
        return fixed;
    }
}

static uint64_t resolve_u64(
    uint8_t mode,
    uint64_t fixed,
    const ninlil_logical_session_snapshot_t *snap)
{
    switch (mode) {
    case NINLIL_LS_U4_MODE_ACTIVE:
        return snap->active_cookie;
    case NINLIL_LS_U4_MODE_ACTIVE_XOR:
        return snap->active_cookie ^ (fixed ? fixed : 1ull);
    case NINLIL_LS_U4_MODE_ZERO:
        return 0ull;
    default:
        return fixed;
    }
}

static int run_inject(peer_t *p, const ninlil_ls_u4_action_t *a)
{
    ninlil_logical_session_snapshot_t snap;
    uint32_t seq;
    uint8_t payload[1100];
    uint32_t plen = 0u;
    ninlil_model_control_frame_fields_t f;
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t flen = 0u;

    REQUIRE(p != NULL && p->used);
    ninlil_logical_session_snapshot(p->sess, &snap);
    seq = resolve_u32(a->seq_mode, a->seq, &snap);

    if (a->has_ncl1 != 0u) {
        ninlil_ncl1_message_t msg;
        size_t nlen = 0u;
        uint8_t ncl1[128];
        const uint8_t *body = NULL;
        size_t body_len = 0u;
        uint32_t req = resolve_u32(a->req_mode, a->request_id, &snap);
        uint32_t gen = resolve_u32(a->gen_mode, a->generation, &snap);
        uint64_t cookie = resolve_u64(a->cookie_mode, a->cookie, &snap);
        if (a->body_blob >= 0
            && (uint32_t)a->body_blob < NINLIL_LS_U4_BLOB_COUNT) {
            body = ninlil_ls_u4_blobs[a->body_blob];
            body_len = ninlil_ls_u4_blob_lens[a->body_blob];
        }
        (void)memset(&msg, 0, sizeof(msg));
        msg.header.logical_version = 1u;
        msg.header.message_type = a->ncl1_msg_type;
        msg.header.request_id = req;
        msg.header.session_generation = gen;
        msg.header.session_cookie = cookie;
        msg.header.body_length = (uint16_t)body_len;
        if (body != NULL && body_len >= 8u
            && a->ncl1_msg_type == NINLIL_NCL1_MSG_HELLO) {
            msg.body.hello.min_control_version =
                (uint16_t)((body[0] << 8) | body[1]);
            msg.body.hello.max_control_version =
                (uint16_t)((body[2] << 8) | body[3]);
            msg.body.hello.flags_supported =
                (uint16_t)((body[4] << 8) | body[5]);
            msg.body.hello.reserved = (uint16_t)((body[6] << 8) | body[7]);
        } else if (
            body != NULL && body_len >= 8u
            && a->ncl1_msg_type == NINLIL_NCL1_MSG_HELLO_ACK) {
            msg.body.hello_ack.selected_control_version =
                (uint16_t)((body[0] << 8) | body[1]);
            msg.body.hello_ack.flags_selected =
                (uint16_t)((body[2] << 8) | body[3]);
            msg.body.hello_ack.result_code =
                (uint16_t)((body[4] << 8) | body[5]);
            msg.body.hello_ack.reserved =
                (uint16_t)((body[6] << 8) | body[7]);
        } else if (
            body != NULL && body_len >= 8u
            && a->ncl1_msg_type == NINLIL_NCL1_MSG_PING_BODY) {
            uint64_t tok = 0ull;
            int bi;
            for (bi = 0; bi < 8; ++bi) {
                tok = (tok << 8) | body[bi];
            }
            msg.body.ping.opaque_echo_token = tok;
        } else if (
            body != NULL && body_len >= 1u
            && a->ncl1_msg_type == NINLIL_NCL1_MSG_RESET_BODY) {
            msg.body.reset.reset_code = body[0];
        } else if (
            body != NULL && body_len >= 8u
            && a->ncl1_msg_type == NINLIL_NCL1_MSG_CTRL_ERROR) {
            msg.body.ctrl_error.error_code =
                (uint16_t)((body[0] << 8) | body[1]);
            msg.body.ctrl_error.reserved =
                (uint16_t)((body[2] << 8) | body[3]);
            msg.body.ctrl_error.related_request_id =
                ((uint32_t)body[4] << 24) | ((uint32_t)body[5] << 16)
                | ((uint32_t)body[6] << 8) | (uint32_t)body[7];
        }
        REQUIRE(
            ninlil_ncl1_encode(&msg, ncl1, sizeof(ncl1), &nlen) == NINLIL_NCL1_OK);
        REQUIRE(nlen <= sizeof(payload));
        (void)memcpy(payload, ncl1, nlen);
        plen = (uint32_t)nlen;
    } else if (
        a->payload_blob >= 0
        && (uint32_t)a->payload_blob < NINLIL_LS_U4_BLOB_COUNT) {
        plen = (uint32_t)ninlil_ls_u4_blob_lens[a->payload_blob];
        REQUIRE(plen <= sizeof(payload));
        if (plen > 0u) {
            (void)memcpy(payload, ninlil_ls_u4_blobs[a->payload_blob], plen);
        }
    }

    (void)memset(&f, 0, sizeof(f));
    f.type = a->ncg1_type;
    f.stream_or_cell_id = a->stream_id;
    f.sequence = seq;
    f.payload.data = plen > 0u ? payload : NULL;
    f.payload.length = plen;
    REQUIRE(
        ninlil_model_control_frame_encode(&f, frame, sizeof(frame), &flen)
        == NINLIL_OK);
    REQUIRE(ninlil_fake_byte_stream_inject_rx(&p->fake, frame, flen) == 1);
    p->last_tx_len = 0u;
    p->last_tx_type = 0u;
    p->last_tx_seq = 0u;
    return 0;
}

static int run_scenario(const ninlil_ls_u4_scenario_t *sc)
{
    peer_t peers[NINLIL_LS_U4_PEER_MAX];
    uint32_t ai;
    uint32_t ei;
    uint64_t now = 0ull;
    uint8_t pi;

    g_current_id = sc->id;
    (void)memset(peers, 0, sizeof(peers));
    for (pi = 0u; pi < NINLIL_LS_U4_PEER_MAX; ++pi) {
        if (sc->peers[pi].used != 0u) {
            if (peer_init_from_pre(&peers[pi], &sc->peers[pi]) != 0) {
                return 1;
            }
        }
    }

    for (ai = 0u; ai < sc->action_count; ++ai) {
        const ninlil_ls_u4_action_t *a = &sc->actions[ai];
        peer_t *p = a->peer < NINLIL_LS_U4_PEER_MAX ? &peers[a->peer] : NULL;
        peer_t *pb = a->peer_b < NINLIL_LS_U4_PEER_MAX ? &peers[a->peer_b] : NULL;
        ninlil_logical_session_status_t st = NINLIL_LOGICAL_SESSION_OK;
        g_action_i = ai;

        switch (a->op) {
        case NINLIL_LS_U4_OP_STEP:
            REQUIRE(p != NULL && p->used);
            if (a->now_ms != 0u) {
                now = a->now_ms;
            } else if (a->now_delta_ms != 0u) {
                now += a->now_delta_ms;
            }
            st = ninlil_logical_session_step(p->sess, now, 0u);
            capture_tx(p);
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, st, 1) != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_FORWARD:
            REQUIRE(p != NULL && pb != NULL && p->used && pb->used);
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 0)
                    != 0) {
                    return 1;
                }
            }
            if (p->last_tx_len > 0u) {
                REQUIRE(
                    ninlil_fake_byte_stream_inject_rx(
                        &pb->fake, p->last_tx, p->last_tx_len)
                    == 1);
            }
            p->last_tx_len = 0u;
            break;

        case NINLIL_LS_U4_OP_DROP_TX:
            REQUIRE(p != NULL && p->used);
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 0)
                    != 0) {
                    return 1;
                }
            }
            p->last_tx_len = 0u;
            break;

        case NINLIL_LS_U4_OP_INJECT:
            REQUIRE(p != NULL);
            if (run_inject(p, a) != 0) {
                return 1;
            }
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_MARK_BASELINE:
            REQUIRE(p != NULL && p->used);
            ninlil_logical_session_snapshot(p->sess, &p->baseline);
            p->have_baseline = 1;
            p->last_tx_len = 0u;
            break;

        case NINLIL_LS_U4_OP_FORCE_STATE:
            REQUIRE(p != NULL && p->used);
            ninlil_logical_session_test_force_state(
                p->sess, (ninlil_logical_session_state_t)a->u32_a);
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_FORCE_RX:
            REQUIRE(p != NULL && p->used);
            ninlil_logical_session_test_force_rx_baseline(
                p->sess, (int)a->u32_a, a->u32_b);
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_FORCE_TX_SEQ:
            REQUIRE(p != NULL && p->used);
            ninlil_logical_session_test_force_next_tx_seq(p->sess, a->u32_a);
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_FORCE_PING:
            REQUIRE(p != NULL && p->used);
            /* eligible_at_ms is carried in action.cookie (u64). */
            ninlil_logical_session_test_force_ping_eligible_at(
                p->sess, a->cookie != 0ull ? a->cookie : now);
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_REQUEST_HELLO:
            REQUIRE(p != NULL && p->used);
            ninlil_logical_session_test_controller_request_hello_now(p->sess);
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_CELL_LOSS:
            REQUIRE(p != NULL && p->used);
            st = ninlil_logical_session_test_cell_continuity_loss(p->sess);
            capture_tx(p);
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, st, 1) != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_WRITE_BLOCK:
            REQUIRE(p != NULL && p->used);
            ninlil_fake_byte_stream_set_force_write_would_block(
                &p->fake, (int)a->u32_a);
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;

        case NINLIL_LS_U4_OP_INIT_PEER: {
            ninlil_ls_u4_peer_pre_t pre;
            (void)memset(&pre, 0, sizeof(pre));
            pre.used = 1u;
            pre.role = (uint8_t)a->u32_a;
            pre.n_cookies = 1u;
            pre.cookies[0] = 0xC0FFEE0123456789ull;
            REQUIRE(a->peer < NINLIL_LS_U4_PEER_MAX);
            if (peer_init_from_pre(&peers[a->peer], &pre) != 0) {
                return 1;
            }
            p = &peers[a->peer];
            p->last_tx_len = 0u;
            if (a->has_expect != 0u) {
                if (check_expect_on_peer(p, &a->expect, NINLIL_LOGICAL_SESSION_OK, 1)
                    != 0) {
                    return 1;
                }
            }
            break;
        }

        case NINLIL_LS_U4_OP_SET_RNG_FAIL:
            REQUIRE(p != NULL && p->used);
            p->rng.fail = (int)a->u32_a;
            break;

        default:
            (void)fprintf(stderr, "unknown op %u id=%s\n", (unsigned)a->op, sc->id);
            return 1;
        }
    }

    for (ei = 0u; ei < sc->expect_count; ++ei) {
        const ninlil_ls_u4_expect_t *e = &sc->expects[ei];
        peer_t *p;
        REQUIRE(e->peer < NINLIL_LS_U4_PEER_MAX);
        p = &peers[e->peer];
        if (check_expect_on_peer(p, e, NINLIL_LOGICAL_SESSION_OK, 0) != 0) {
            return 1;
        }
    }
    return 0;
}

static int run_all_scenarios(void)
{
    size_t i;
    REQUIRE(NINLIL_LS_U4_BEHAVIOR_COUNT == 38u);
    REQUIRE(NINLIL_LS_U4_ENGINE_REQUIRED_ID_COUNT == 38u);
    for (i = 0u; i < 38u; ++i) {
        const ninlil_ls_u4_scenario_t *sc = &ninlil_ls_u4_scenarios[i];
        size_t j;
        int found = 0;
        REQUIRE(sc->id != NULL);
        REQUIRE(sc->action_count > 0u);
        REQUIRE(sc->expect_count > 0u);
        for (j = 0u; j < 38u; ++j) {
            if (strcmp(NINLIL_LS_U4_ENGINE_REQUIRED_IDS[j], sc->id) == 0) {
                found = 1;
                break;
            }
        }
        REQUIRE(found == 1);
        if (run_scenario(sc) != 0) {
            (void)fprintf(stderr, "scenario FAIL: %s\n", sc->id);
            return 1;
        }
    }
    return 0;
}

static int test_object_size_composition(void)
{
    size_t sz = ninlil_logical_session_object_size();
    size_t al = ninlil_logical_session_object_align();
    REQUIRE(sz <= NINLIL_LOGICAL_SESSION_OBJECT_BYTES);
    REQUIRE(sz > NINLIL_CTRL_SESSION_OBJECT_BYTES);
    REQUIRE(
        NINLIL_LOGICAL_SESSION_OBJECT_BYTES
        == NINLIL_CTRL_SESSION_OBJECT_BYTES
            + NINLIL_LOGICAL_SESSION_U4_EXCLUSIVE_BYTES);
    REQUIRE(al == _Alignof(ninlil_logical_session_object_t));
    REQUIRE(al >= NINLIL_LOGICAL_SESSION_OBJECT_ALIGN);
    REQUIRE(
        ninlil_ctrl_session_object_align()
        == _Alignof(ninlil_ctrl_session_object_t));
    return 0;
}

/* Minimal P0: gen burn cancel still exact */
static int test_gen_burn_on_cancel(void)
{
    peer_t e;
    ninlil_ls_u4_peer_pre_t pre;
    ninlil_logical_session_snapshot_t se1, se2;
    uint32_t gen1, gen2;
    ninlil_logical_session_status_t st;
    g_current_id = "GEN_BURN";
    (void)memset(&pre, 0, sizeof(pre));
    pre.used = 1u;
    pre.role = (uint8_t)NINLIL_LOGICAL_SESSION_ROLE_CELL;
    pre.n_cookies = 3u;
    pre.cookies[0] = 0x1111111111111111ull;
    pre.cookies[1] = 0x2222222222222222ull;
    pre.cookies[2] = 0x3333333333333333ull;
    REQUIRE(peer_init_from_pre(&e, &pre) == 0);
    st = ninlil_logical_session_test_cell_try_prepare_ack(e.sess, 0x1001u);
    REQUIRE(st == NINLIL_LOGICAL_SESSION_OK);
    ninlil_logical_session_snapshot(e.sess, &se1);
    gen1 = se1.last_issued_generation;
    REQUIRE(se1.burned_generation_count == 1u);
    st = ninlil_logical_session_test_cell_try_prepare_ack(e.sess, 0x1002u);
    REQUIRE(st == NINLIL_LOGICAL_SESSION_OK);
    ninlil_logical_session_snapshot(e.sess, &se2);
    gen2 = se2.last_issued_generation;
    REQUIRE(gen2 > gen1);
    REQUIRE(gen2 == gen1 + 1u);
    REQUIRE(se2.burned_generation_count == 2u);
    return 0;
}

int main(void)
{
    if (test_object_size_composition() != 0) {
        return 1;
    }
    if (test_gen_burn_on_cancel() != 0) {
        return 1;
    }
    if (run_all_scenarios() != 0) {
        return 1;
    }
    (void)printf(
        "logical_session_u4_test OK engine_scenarios=%u object_size=%u\n",
        (unsigned)NINLIL_LS_U4_ENGINE_REQUIRED_ID_COUNT,
        (unsigned)ninlil_logical_session_object_size());
    return 0;
}
