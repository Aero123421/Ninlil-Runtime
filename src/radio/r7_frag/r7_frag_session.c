/*
 * Integrated NRW1 LINK/FRAG session: wire AEAD + lanes + reasm.
 * Optional test durable simulator when NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE=1
 * (host lab only). Production N6 counters live in r7_frag_prod_orch.
 */

#include "r7_frag_session.h"

#include "r7_frag_internal.h"

#include <stdatomic.h>
#include <string.h>

#if !NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
/* Volatile-only lane burns: no crash simulator. */
#endif

static void sec_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;
    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);
}

static void put_u64_be(uint8_t *o, uint64_t v)
{
    size_t i;
    for (i = 0u; i < 8u; i++) {
        o[i] = (uint8_t)((v >> (56u - 8u * i)) & 0xffu);
    }
}

static void put_u32_be(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)((v >> 24) & 0xffu);
    o[1] = (uint8_t)((v >> 16) & 0xffu);
    o[2] = (uint8_t)((v >> 8) & 0xffu);
    o[3] = (uint8_t)(v & 0xffu);
}

static ninlil_r7_frag_sess_lane *lane_find(
    ninlil_r7_frag_sess *s, uint8_t kind, uint32_t ctx)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_SESS_LANES; i++) {
        if (s->lanes[i].in_use && s->lanes[i].kind == kind
            && s->lanes[i].context_id == ctx) {
            return &s->lanes[i];
        }
    }
    return NULL;
}

#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
static void lane_key(
    uint8_t kind, uint32_t ctx, uint64_t kgen, uint8_t out[16], size_t *out_len)
{
    out[0] = kind;
    put_u32_be(out + 1, ctx);
    put_u64_be(out + 5, kgen);
    out[13] = 0u;
    out[14] = 0u;
    out[15] = 0u;
    *out_len = 16u;
}

static void lane_val_tx(uint64_t next, uint64_t limit, uint8_t out[16])
{
    put_u64_be(out + 0, next);
    put_u64_be(out + 8, limit);
}

static void lane_val_rx(uint64_t through, uint64_t highest, uint8_t out[16])
{
    put_u64_be(out + 0, through);
    put_u64_be(out + 8, highest);
}
#endif

static int32_t map_wire(ninlil_r7_frag_status st)
{
    if (st == NINLIL_R7_FRAG_OK) {
        return NINLIL_R7_FRAG_SESS_OK;
    }
    if (st == NINLIL_R7_FRAG_AUTH_FAILED) {
        return NINLIL_R7_FRAG_SESS_AUTH;
    }
    if (st == NINLIL_R7_FRAG_REPLAY) {
        return NINLIL_R7_FRAG_SESS_REPLAY;
    }
    if (st == NINLIL_R7_FRAG_RESOURCE || st == NINLIL_R7_FRAG_CAPACITY) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    if (st == NINLIL_R7_FRAG_STRUCTURAL || st == NINLIL_R7_FRAG_LENGTH_CLASS) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    return NINLIL_R7_FRAG_SESS_INTERNAL;
}

static int32_t map_state(ninlil_r7_frag_state_status st)
{
    if (st == NINLIL_R7_FRAG_STATE_OK
        || st == NINLIL_R7_FRAG_STATE_EXACT_RETRY
        || st == NINLIL_R7_FRAG_STATE_DUPLICATE
        || st == NINLIL_R7_FRAG_STATE_NEED_DIGEST
        || st == NINLIL_R7_FRAG_STATE_PUBLISHED) {
        return NINLIL_R7_FRAG_SESS_OK;
    }
    if (st == NINLIL_R7_FRAG_STATE_CONFLICT
        || st == NINLIL_R7_FRAG_STATE_DIGEST) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (st == NINLIL_R7_FRAG_STATE_RESOURCE) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    if (st == NINLIL_R7_FRAG_STATE_FENCED) {
        return NINLIL_R7_FRAG_SESS_FENCED;
    }
    if (st == NINLIL_R7_FRAG_STATE_NO_TRANSFER) {
        return NINLIL_R7_FRAG_SESS_NO_PUB;
    }
    return NINLIL_R7_FRAG_SESS_INTERNAL;
}

/* TX allocate: test durable writepoint when enabled; else volatile RAM only. */
static int32_t lane_tx_alloc(
    ninlil_r7_frag_sess *s, ninlil_r7_frag_sess_lane *L, uint64_t *out_c)
{
    uint64_t C;
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    uint8_t key[16];
    uint8_t val[16];
    size_t klen = 0u;
    int32_t dr;
#endif

    if (L->fenced) {
        return NINLIL_R7_FRAG_SESS_FENCED;
    }
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    if (s->durable.fenced) {
        return NINLIL_R7_FRAG_SESS_FENCED;
    }
#endif
    if (L->tx_next == L->tx_limit) {
        uint64_t U = 0u;
        /* docs/30 §9.2: room=min(B, remaining); final 1..63 up to UINT64_MAX. */
        if (!ninlil_r7_frag_tx_exclusive_grow(
                L->tx_limit, NINLIL_R7_FRAG_TX_BLOCK, &U)) {
            return NINLIL_R7_FRAG_SESS_RESOURCE;
        }
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
        lane_key(L->kind, L->context_id, L->key_generation, key, &klen);
        lane_val_tx(L->tx_next, U, val);
        ninlil_r7_frag_dur_begin(&s->durable);
        if (ninlil_r7_frag_dur_put(&s->durable, key, klen, val, 16u)
            != NINLIL_R7_FRAG_DUR_OK) {
            return NINLIL_R7_FRAG_SESS_DURABLE;
        }
        dr = ninlil_r7_frag_dur_commit(&s->durable);
        if (dr == NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN) {
            ninlil_r7_frag_state_cu_result cls;
            int32_t rr = ninlil_r7_frag_dur_recover_cu(&s->durable, &cls);
            if (rr != NINLIL_R7_FRAG_DUR_OK) {
                L->fenced = 1u;
                return NINLIL_R7_FRAG_SESS_FENCED;
            }
            if (cls.class_code == NINLIL_R7_FRAG_STATE_CU_ALL_PROPOSED) {
                L->tx_limit = U;
            }
            if (L->tx_next == L->tx_limit) {
                return NINLIL_R7_FRAG_SESS_DURABLE;
            }
        } else if (dr != NINLIL_R7_FRAG_DUR_OK) {
            return NINLIL_R7_FRAG_SESS_DURABLE;
        } else {
            L->tx_limit = U;
        }
#else
        (void)s;
        L->tx_limit = U;
#endif
    }
    C = L->tx_next;
    /* assignable domain 1..UINT64_MAX-1 (shared §9.2 helper) */
    if (!ninlil_r7_frag_tx_counter_assignable(C)) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    L->tx_next = C + 1u;
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    lane_key(L->kind, L->context_id, L->key_generation, key, &klen);
    lane_val_tx(L->tx_next, L->tx_limit, val);
    ninlil_r7_frag_dur_begin(&s->durable);
    ninlil_r7_frag_dur_put(&s->durable, key, klen, val, 16u);
    dr = ninlil_r7_frag_dur_commit(&s->durable);
    if (dr == NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN) {
        ninlil_r7_frag_state_cu_result cls;
        (void)ninlil_r7_frag_dur_recover_cu(&s->durable, &cls);
        if (cls.class_code == NINLIL_R7_FRAG_STATE_CU_THIRD
            || cls.class_code == NINLIL_R7_FRAG_STATE_CU_CORRUPT) {
            L->fenced = 1u;
            return NINLIL_R7_FRAG_SESS_FENCED;
        }
    } else if (dr != NINLIL_R7_FRAG_DUR_OK
        && dr != NINLIL_R7_FRAG_DUR_DEFINITE_FAILURE) {
        /* definite fail after RAM burn: counter still burned */
    }
#endif
    *out_c = C;
    return NINLIL_R7_FRAG_SESS_OK;
}

static int32_t lane_rx_precheck(
    ninlil_r7_frag_sess_lane *L, uint64_t c)
{
    uint64_t delta;
    if (L->fenced) {
        return NINLIL_R7_FRAG_SESS_FENCED;
    }
    if (c == 0u || c == UINT64_MAX) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (c <= L->rx_boot_floor) {
        return NINLIL_R7_FRAG_SESS_REPLAY;
    }
    if (c <= L->rx_highest) {
        delta = L->rx_highest - c;
        if (delta >= 64u) {
            return NINLIL_R7_FRAG_SESS_REPLAY;
        }
        if ((L->rx_bitmap >> delta) & UINT64_C(1)) {
            return NINLIL_R7_FRAG_SESS_REPLAY;
        }
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

static int32_t lane_rx_admit(
    ninlil_r7_frag_sess *s, ninlil_r7_frag_sess_lane *L, uint64_t c)
{
    uint64_t delta;
    int32_t st = lane_rx_precheck(L, c);
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    uint8_t key[16];
    uint8_t val[16];
    size_t klen = 0u;
    int32_t dr;
#endif

    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return st;
    }
    if (c > L->rx_accept_through) {
        uint64_t nt = (c > (UINT64_MAX - 1u) - 63u) ? (UINT64_MAX - 1u)
                                                    : (c + 63u);
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
        lane_key(L->kind, L->context_id, L->key_generation, key, &klen);
        lane_val_rx(nt, (c > L->rx_highest) ? c : L->rx_highest, val);
        ninlil_r7_frag_dur_begin(&s->durable);
        ninlil_r7_frag_dur_put(&s->durable, key, klen, val, 16u);
        dr = ninlil_r7_frag_dur_commit(&s->durable);
        if (dr == NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN) {
            ninlil_r7_frag_state_cu_result cls;
            if (ninlil_r7_frag_dur_recover_cu(&s->durable, &cls)
                != NINLIL_R7_FRAG_DUR_OK) {
                L->fenced = 1u;
                return NINLIL_R7_FRAG_SESS_FENCED;
            }
            if (cls.class_code == NINLIL_R7_FRAG_STATE_CU_ALL_PROPOSED) {
                L->rx_accept_through = nt;
            } else if (cls.class_code != NINLIL_R7_FRAG_STATE_CU_ALL_OLD) {
                L->fenced = 1u;
                return NINLIL_R7_FRAG_SESS_FENCED;
            } else {
                return NINLIL_R7_FRAG_SESS_DURABLE; /* no admit */
            }
        } else if (dr != NINLIL_R7_FRAG_DUR_OK) {
            return NINLIL_R7_FRAG_SESS_DURABLE;
        } else {
            L->rx_accept_through = nt;
        }
#else
        (void)s;
        L->rx_accept_through = nt;
#endif
    }
    if (c > L->rx_highest) {
        delta = c - L->rx_highest;
        if (delta >= 64u) {
            L->rx_bitmap = UINT64_C(1);
        } else {
            L->rx_bitmap = (L->rx_bitmap << delta) | UINT64_C(1);
        }
        L->rx_highest = c;
    } else {
        delta = L->rx_highest - c;
        L->rx_bitmap |= (UINT64_C(1) << delta);
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

void ninlil_r7_frag_sess_init(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_sess_keys *keys)
{
    if (s == NULL) {
        return;
    }
    memset(s, 0, sizeof(*s));
    s->provider = provider;
    if (keys != NULL) {
        s->keys = *keys;
    }
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    /* Test durable only: instance cu_ws owned by session object. */
    s->durable.cu_ws = &s->cu_ws;
    ninlil_r7_frag_dur_init(&s->durable);
    s->durable.cu_ws = &s->cu_ws;
#endif
    ninlil_r7_frag_state_init(&s->reasm);
    ninlil_r7_frag_ack_ledger_init(&s->ack_ledger);
    s->ack_requested_default = 1u;
}

void ninlil_r7_frag_sess_zeroize(ninlil_r7_frag_sess *s)
{
    if (s == NULL) {
        return;
    }
    sec_zero(s, sizeof(*s));
}

void ninlil_r7_frag_sess_set_now(ninlil_r7_frag_sess *s, uint64_t now)
{
    if (s == NULL) {
        return;
    }
    s->now_mono = now;
    ninlil_r7_frag_state_set_now(&s->reasm, now);
}

int32_t ninlil_r7_frag_sess_install_lane(
    ninlil_r7_frag_sess *s,
    uint8_t kind,
    uint32_t context_id,
    uint64_t key_generation)
{
    size_t i;
    uint8_t key[16];
    uint8_t val[16];
    size_t klen = 0u;
    int32_t dr;

    if (s == NULL || key_generation == 0u || context_id == 0u
        || context_id == UINT32_MAX) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (lane_find(s, kind, context_id) != NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_SESS_LANES; i++) {
        if (!s->lanes[i].in_use) {
            ninlil_r7_frag_sess_lane *L = &s->lanes[i];
            memset(L, 0, sizeof(*L));
            L->in_use = 1u;
            L->kind = kind;
            L->context_id = context_id;
            L->key_generation = key_generation;
            L->tx_next = 1u;
            L->tx_limit = 1u;
            L->rx_boot_floor = 0u;
            L->rx_highest = 0u;
            L->rx_accept_through = 0u;
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
            lane_key(kind, context_id, key_generation, key, &klen);
            lane_val_tx(1u, 1u, val);
            ninlil_r7_frag_dur_begin(&s->durable);
            ninlil_r7_frag_dur_put(&s->durable, key, klen, val, 16u);
            dr = ninlil_r7_frag_dur_commit(&s->durable);
            if (dr != NINLIL_R7_FRAG_DUR_OK) {
                L->in_use = 0u;
                return NINLIL_R7_FRAG_SESS_DURABLE;
            }
#else
            (void)key;
            (void)val;
            (void)klen;
            (void)dr;
#endif
            if (kind == NINLIL_R7_FRAG_LANE_HOP_DATA) {
                s->hop_data_context_id = context_id;
                s->acked_hop_data_context_id = context_id;
            } else if (kind == NINLIL_R7_FRAG_LANE_HOP_ACK) {
                s->hop_ack_context_id = context_id;
            } else if (kind == NINLIL_R7_FRAG_LANE_E2E) {
                if (s->e2e_context_id == 0u) {
                    s->e2e_context_id = context_id;
                } else {
                    s->rev_e2e_context_id = context_id;
                }
            }
            s->key_generation = key_generation;
            return NINLIL_R7_FRAG_SESS_OK;
        }
    }
    return NINLIL_R7_FRAG_SESS_RESOURCE;
}

static int32_t seal_outer_for_e2e(
    ninlil_r7_frag_sess *s,
    const uint8_t *e2e_blob,
    size_t e2e_len,
    uint64_t hop_counter,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len)
{
    ninlil_r7_frag_outer_data_fields of;
    ninlil_r7_frag_status st;
    size_t need = 19u + e2e_len + 16u;

    if (out_cap < need) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    memset(&of, 0, sizeof(of));
    of.ack_requested = s->ack_requested_default;
    of.hop_remaining = 0u;
    of.hop_context_id = s->hop_data_context_id;
    of.hop_counter = hop_counter;
    of.route_handle = 0u;
    of.route_generation = 0u;
    st = ninlil_r7_frag_seal_outer_data(
        s->provider, s->keys.hop_data_key16, s->keys.hop_data_iv12, &of,
        e2e_blob, e2e_len, out_frame, need, out_len);
    return map_wire(st);
}

int32_t ninlil_r7_frag_sess_tx_begin(
    ninlil_r7_frag_sess *s,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t transfer_id[16],
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len,
    uint16_t *out_frag_index)
{
    ninlil_r7_frag_sess_lane *Le2e;
    ninlil_r7_frag_sess_lane *Lhop;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_cont_body cont;
    ninlil_r7_frag_e2e_fields e2e;
    ninlil_r7_frag_status st;
    uint64_t handle;
    uint16_t i;
    int32_t rs;

    if (s == NULL || payload == NULL || transfer_id == NULL || out_frame == NULL
        || out_len == NULL || out_frag_index == NULL || s->provider == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (s->tx.in_use) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    if (ninlil_r7_frag_state_plan_build((uint32_t)payload_len, &plan)
        != NINLIL_R7_FRAG_STATE_OK) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    Le2e = lane_find(s, NINLIL_R7_FRAG_LANE_E2E, s->e2e_context_id);
    Lhop = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_DATA, s->hop_data_context_id);
    if (Le2e == NULL || Lhop == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }

    memset(&s->tx, 0, sizeof(s->tx));
    s->tx.in_use = 1u;
    s->tx.e2e_context_id = s->e2e_context_id;
    s->tx.key_generation = s->key_generation;
    s->tx.plan = plan;
    memcpy(s->tx.transfer_id, transfer_id, 16u);
    s->tx.transfer_start_mono = s->now_mono;
    if (s->now_mono > UINT64_MAX - NINLIL_R7_FRAG_SENDER_TTL_MS) {
        s->tx.in_use = 0u;
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    s->tx.sender_absolute_deadline =
        s->now_mono + NINLIL_R7_FRAG_SENDER_TTL_MS;

    /* content_digest via approved provider */
    if (ninlil_r7_crypto_sha256(
            s->provider, payload, payload_len, s->tx.content_digest)
        != NINLIL_R7_CRYPTO_OK) {
        s->tx.in_use = 0u;
        return NINLIL_R7_FRAG_SESS_INTERNAL;
    }

    /* First START: transfer_handle = first E2E counter burn (prep 1 of ≤4) */
    if (s->now_mono >= s->tx.sender_absolute_deadline) {
        s->tx.in_use = 0u;
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    rs = lane_tx_alloc(s, Le2e, &handle);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        s->tx.in_use = 0u;
        return rs;
    }
    s->tx.e2e_prep_burns[0] = 1u;
    s->tx.transfer_handle = handle;
    s->tx.e2e_counter[0] = handle;

    memset(&start, 0, sizeof(start));
    memcpy(start.transfer_id, transfer_id, 16u);
    start.transfer_handle = handle;
    start.total_len = (uint32_t)payload_len;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, s->tx.content_digest, 32u);

    st = ninlil_r7_frag_start_fingerprint(
        s->provider, &start, payload, plan.first_chunk_len, s->tx.fingerprint);
    if (st != NINLIL_R7_FRAG_OK) {
        s->tx.in_use = 0u;
        return map_wire(st);
    }

    memset(&e2e, 0, sizeof(e2e));
    e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
    e2e.e2e_context_id = s->e2e_context_id;
    e2e.e2e_counter = handle;
    {
        size_t need = 14u + 64u + plan.first_chunk_len + 16u;
        size_t blen = 0u;
        st = ninlil_r7_frag_seal_e2e_start(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, &e2e, &start,
            payload, plan.first_chunk_len, s->tx.e2e_blob[0], need, &blen);
        if (st != NINLIL_R7_FRAG_OK) {
            s->tx.in_use = 0u;
            return map_wire(st);
        }
        s->tx.e2e_len[0] = (uint16_t)blen;
    }

    for (i = 1u; i < plan.frag_count; i++) {
        uint64_t c;
        size_t need;
        size_t blen = 0u;
        rs = lane_tx_alloc(s, Le2e, &c);
        if (rs != NINLIL_R7_FRAG_SESS_OK) {
            s->tx.in_use = 0u;
            return rs;
        }
        s->tx.e2e_prep_burns[i] = 1u;
        s->tx.e2e_counter[i] = c;
        memset(&cont, 0, sizeof(cont));
        cont.transfer_handle = handle;
        cont.frag_index = i;
        e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
        e2e.e2e_counter = c;
        need = 14u + 10u + plan.chunks[i].length + 16u;
        st = ninlil_r7_frag_seal_e2e_cont(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, &e2e, &cont,
            payload + plan.chunks[i].offset, plan.chunks[i].length,
            s->tx.e2e_blob[i], need, &blen);
        if (st != NINLIL_R7_FRAG_OK) {
            s->tx.in_use = 0u;
            return map_wire(st);
        }
        s->tx.e2e_len[i] = (uint16_t)blen;
    }

    /* First outer for frag 0 */
    {
        uint64_t hop_c;
        rs = lane_tx_alloc(s, Lhop, &hop_c);
        if (rs != NINLIL_R7_FRAG_SESS_OK) {
            return rs;
        }
        rs = seal_outer_for_e2e(
            s, s->tx.e2e_blob[0], s->tx.e2e_len[0], hop_c, out_frame, out_cap,
            out_len);
        if (rs != NINLIL_R7_FRAG_SESS_OK) {
            return rs;
        }
        s->tx.last_hop_counter[0] = hop_c;
        s->tx.last_outer_len[0] = (uint16_t)*out_len;
        memcpy(s->tx.last_outer[0], out_frame, *out_len);
        s->tx.outer_attempts[0] = 1u;
        *out_frag_index = 0u;
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

int32_t ninlil_r7_frag_sess_tx_air(
    ninlil_r7_frag_sess *s,
    uint16_t frag_index,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len)
{
    ninlil_r7_frag_sess_lane *Lhop;
    uint64_t hop_c;
    int32_t rs;

    if (s == NULL || !s->tx.in_use || out_frame == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (frag_index >= s->tx.plan.frag_count) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (s->tx.hop_attempts[frag_index] >= NINLIL_R7_FRAG_HOP_ATTEMPT_MAX) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    if (s->tx.outer_attempts[frag_index] >= NINLIL_R7_FRAG_OUTER_ATTEMPT_MAX) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    if (s->tx.frag_acked[frag_index]) {
        return NINLIL_R7_FRAG_SESS_DONE;
    }
    if (s->now_mono >= s->tx.sender_absolute_deadline) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    /* LINK retry: same E2E blob, fresh hop counter */
    Lhop = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_DATA, s->hop_data_context_id);
    if (Lhop == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (s->tx.hop_attempts[frag_index] > 0u
        && s->now_mono < s->tx.eligible_at[frag_index]) {
        return NINLIL_R7_FRAG_SESS_RETRY;
    }
    rs = lane_tx_alloc(s, Lhop, &hop_c);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    rs = seal_outer_for_e2e(
        s, s->tx.e2e_blob[frag_index], s->tx.e2e_len[frag_index], hop_c,
        out_frame, out_cap, out_len);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    s->tx.last_hop_counter[frag_index] = hop_c;
    s->tx.last_outer_len[frag_index] = (uint16_t)*out_len;
    memcpy(s->tx.last_outer[frag_index], out_frame, *out_len);
    s->tx.outer_attempts[frag_index] =
        (uint8_t)(s->tx.outer_attempts[frag_index] + 1u);
    return NINLIL_R7_FRAG_SESS_OK;
}

int32_t ninlil_r7_frag_sess_tx_e2e_retry(
    ninlil_r7_frag_sess *s,
    uint16_t frag_index,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len)
{
    ninlil_r7_frag_sess_lane *Le2e;
    ninlil_r7_frag_sess_lane *Lhop;
    uint64_t e2e_c;
    uint64_t hop_c;
    ninlil_r7_frag_e2e_fields e2e;
    ninlil_r7_frag_status st;
    int32_t rs;
    size_t need;
    size_t blen = 0u;
    uint16_t off;
    uint16_t clen;

    if (s == NULL || !s->tx.in_use || payload == NULL || out_frame == NULL
        || out_len == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (frag_index >= s->tx.plan.frag_count
        || payload_len != s->tx.plan.total_len) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (s->tx.e2e_prep_burns[frag_index] >= NINLIL_R7_FRAG_E2E_PREP_MAX) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    if (s->now_mono >= s->tx.sender_absolute_deadline) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    Le2e = lane_find(s, NINLIL_R7_FRAG_LANE_E2E, s->e2e_context_id);
    Lhop = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_DATA, s->hop_data_context_id);
    if (Le2e == NULL || Lhop == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    rs = lane_tx_alloc(s, Le2e, &e2e_c);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    s->tx.e2e_prep_burns[frag_index] =
        (uint8_t)(s->tx.e2e_prep_burns[frag_index] + 1u);
    s->tx.e2e_counter[frag_index] = e2e_c;
    /* Reset LINK group accounting for this fragment. */
    s->tx.hop_attempts[frag_index] = 0u;
    s->tx.outer_attempts[frag_index] = 0u;
    s->tx.frag_acked[frag_index] = 0u;
    s->tx.eligible_at[frag_index] = 0u;

    memset(&e2e, 0, sizeof(e2e));
    e2e.e2e_context_id = s->e2e_context_id;
    e2e.e2e_counter = e2e_c;
    if (frag_index == 0u) {
        ninlil_r7_frag_start_body start;
        memset(&start, 0, sizeof(start));
        memcpy(start.transfer_id, s->tx.transfer_id, 16u);
        start.transfer_handle = s->tx.transfer_handle; /* retained */
        start.total_len = s->tx.plan.total_len;
        start.frag_count = s->tx.plan.frag_count;
        start.continuation_unit = 180u;
        memcpy(start.content_digest, s->tx.content_digest, 32u);
        e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
        need = 14u + 64u + s->tx.plan.first_chunk_len + 16u;
        st = ninlil_r7_frag_seal_e2e_start(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, &e2e, &start,
            payload, s->tx.plan.first_chunk_len, s->tx.e2e_blob[0], need,
            &blen);
    } else {
        ninlil_r7_frag_cont_body cont;
        off = s->tx.plan.chunks[frag_index].offset;
        clen = s->tx.plan.chunks[frag_index].length;
        memset(&cont, 0, sizeof(cont));
        cont.transfer_handle = s->tx.transfer_handle;
        cont.frag_index = frag_index;
        e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
        need = 14u + 10u + clen + 16u;
        st = ninlil_r7_frag_seal_e2e_cont(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, &e2e, &cont,
            payload + off, clen, s->tx.e2e_blob[frag_index], need, &blen);
    }
    if (st != NINLIL_R7_FRAG_OK) {
        return map_wire(st);
    }
    s->tx.e2e_len[frag_index] = (uint16_t)blen;
    rs = lane_tx_alloc(s, Lhop, &hop_c);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    rs = seal_outer_for_e2e(
        s, s->tx.e2e_blob[frag_index], s->tx.e2e_len[frag_index], hop_c,
        out_frame, out_cap, out_len);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    s->tx.last_hop_counter[frag_index] = hop_c;
    s->tx.last_outer_len[frag_index] = (uint16_t)*out_len;
    memcpy(s->tx.last_outer[frag_index], out_frame, *out_len);
    s->tx.outer_attempts[frag_index] = 1u;
    return NINLIL_R7_FRAG_SESS_OK;
}

int32_t ninlil_r7_frag_sess_tx_note_air(
    ninlil_r7_frag_sess *s,
    uint16_t frag_index,
    uint64_t hop_counter)
{
    uint64_t ack_dl;
    uint64_t int_at;
    if (s == NULL || !s->tx.in_use) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (frag_index >= s->tx.plan.frag_count) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    (void)hop_counter;
    s->tx.hop_attempts[frag_index] =
        (uint8_t)(s->tx.hop_attempts[frag_index] + 1u);
    if (s->ack_requested_default) {
        if (s->now_mono > UINT64_MAX - 3000u
            || s->now_mono > UINT64_MAX - 500u) {
            return NINLIL_R7_FRAG_SESS_STRUCT;
        }
        ack_dl = s->now_mono + 3000u;
        int_at = s->now_mono + 500u;
        s->tx.eligible_at[frag_index] =
            (ack_dl > int_at) ? ack_dl : int_at;
    } else {
        s->tx.frag_acked[frag_index] = 1u; /* UNACKED success */
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

static int32_t finalize_if_needed(
    ninlil_r7_frag_sess *s,
    uint32_t e2e_ctx,
    uint64_t handle,
    ninlil_r7_frag_state_ack_intent *intent,
    ninlil_r7_frag_state_status st)
{
    const uint8_t *pay = NULL;
    size_t pay_len = 0u;
    uint8_t dig[32];
    ninlil_r7_frag_state_status st2;

    if (st != NINLIL_R7_FRAG_STATE_NEED_DIGEST) {
        return map_state(st);
    }
    if (ninlil_r7_frag_state_peek_reassembled(
            &s->reasm, e2e_ctx, handle, &pay, &pay_len)
        != NINLIL_R7_FRAG_STATE_OK) {
        return NINLIL_R7_FRAG_SESS_INTERNAL;
    }
    if (ninlil_r7_crypto_sha256(s->provider, pay, pay_len, dig)
        != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_SESS_INTERNAL;
    }
    st2 = ninlil_r7_frag_state_finalize(
        &s->reasm, e2e_ctx, handle, dig, intent);
    return map_state(st2);
}

/*
 * Normative RX (docs/30 §6.5):
 *   1 structural  2 context+replay precheck  3 AEAD  4 durable admit  5 body
 * Body reject after admit: publish/ACK/body mutation = 0; counters stay burned.
 * E2E REPLAY after hop admit: hop-only retransmit — LINK_ACK may regenerate;
 * no body re-apply / no double publish.
 */
static int32_t gen_link_ack(
    ninlil_r7_frag_sess *s,
    uint64_t acked_hop_counter,
    uint8_t *out_frame,
    size_t cap,
    size_t *out_len)
{
    ninlil_r7_frag_sess_lane *Lack;
    uint64_t ac;
    ninlil_r7_frag_outer_link_ack_fields lo;
    ninlil_r7_frag_link_ack_body lb;
    ninlil_r7_frag_status st;
    int32_t tr;

    if (out_frame == NULL || out_len == NULL || cap < 51u) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    *out_len = 0u;
    Lack = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_ACK, s->hop_ack_context_id);
    if (Lack == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    tr = lane_tx_alloc(s, Lack, &ac);
    if (tr != NINLIL_R7_FRAG_SESS_OK) {
        return tr;
    }
    memset(&lo, 0, sizeof(lo));
    lo.hop_context_id = s->hop_ack_context_id;
    lo.hop_counter = ac;
    memset(&lb, 0, sizeof(lb));
    lb.acked_hop_context_id = s->acked_hop_data_context_id;
    lb.ack_base_counter = acked_hop_counter;
    lb.ack_bitmap = 0x0001u;
    lb.ack_code = 0u;
    st = ninlil_r7_frag_seal_outer_link_ack(
        s->provider, s->keys.rev_hop_ack_key16, s->keys.rev_hop_ack_iv12, &lo,
        &lb, out_frame, out_len);
    return map_wire(st);
}

int32_t ninlil_r7_frag_sess_rx_data(
    ninlil_r7_frag_sess *s,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_state_ack_intent *out_frag_intent,
    uint8_t *out_link_ack_frame,
    size_t link_ack_cap,
    size_t *out_link_ack_len)
{
    ninlil_r7_frag_outer_data_fields of_struct;
    ninlil_r7_frag_outer_data_fields of;
    ninlil_r7_frag_e2e_fields ef;
    ninlil_r7_frag_e2e_fields hdr;
    ninlil_r7_frag_sess_lane *Lhop;
    ninlil_r7_frag_sess_lane *Le;
    uint8_t e2e_blob[220];
    size_t e2e_len = 0u;
    ninlil_r7_frag_status st;
    int32_t rs;
    uint8_t kind;
    uint8_t body_ok = 0u;
    uint8_t hop_only = 0u;

    if (s == NULL || frame == NULL || out_frag_intent == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (out_link_ack_len != NULL) {
        *out_link_ack_len = 0u;
    }
    memset(out_frag_intent, 0, sizeof(*out_frag_intent));

    Lhop = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_DATA, s->hop_data_context_id);
    if (Lhop == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }

    /* ---- 1. Structural outer (no crypto) ---- */
    if (frame_len < 66u || frame_len > 255u) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (frame[0] != NINLIL_R7_FRAG_PROFILE_ID) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    kind = (uint8_t)((frame[1] >> 4) & 0x0fu);
    if (kind != NINLIL_R7_FRAG_OUTER_KIND_DATA) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if ((frame[1] & 0x0eu) != 0u) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    memset(&of_struct, 0, sizeof(of_struct));
    of_struct.ack_requested = (uint8_t)(frame[1] & 0x01u);
    of_struct.hop_remaining = frame[2];
    of_struct.hop_context_id =
        ((uint32_t)frame[3] << 24) | ((uint32_t)frame[4] << 16)
        | ((uint32_t)frame[5] << 8) | (uint32_t)frame[6];
    of_struct.hop_counter =
        ((uint64_t)frame[7] << 56) | ((uint64_t)frame[8] << 48)
        | ((uint64_t)frame[9] << 40) | ((uint64_t)frame[10] << 32)
        | ((uint64_t)frame[11] << 24) | ((uint64_t)frame[12] << 16)
        | ((uint64_t)frame[13] << 8) | (uint64_t)frame[14];
    of_struct.route_handle =
        (uint16_t)(((uint16_t)frame[15] << 8) | frame[16]);
    of_struct.route_generation =
        (uint16_t)(((uint16_t)frame[17] << 8) | frame[18]);
    if (of_struct.hop_context_id != s->hop_data_context_id) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (of_struct.hop_counter == 0u || of_struct.hop_counter == UINT64_MAX) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (!((of_struct.route_handle == 0u && of_struct.route_generation == 0u
              && of_struct.hop_remaining == 0u)
            || (of_struct.route_handle != 0u && of_struct.route_generation != 0u
                && of_struct.hop_remaining >= 1u))) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }

    /* ---- 2. Hop replay precheck (mutation 0) ---- */
    rs = lane_rx_precheck(Lhop, of_struct.hop_counter);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }

    /* ---- 3. Hop AEAD ---- */
    st = ninlil_r7_frag_open_outer_data(
        s->provider, s->keys.hop_data_key16, s->keys.hop_data_iv12, frame,
        frame_len, &of, e2e_blob, frame_len - 19u - 16u, &e2e_len);
    if (st != NINLIL_R7_FRAG_OK) {
        return map_wire(st);
    }

    /* ---- 4. Hop durable admit ---- */
    rs = lane_rx_admit(s, Lhop, of.hop_counter);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }

    /* E2E structural on HopPT */
    st = ninlil_r7_frag_structural_e2e_header(e2e_blob, e2e_len, &hdr);
    if (st != NINLIL_R7_FRAG_OK) {
        /* hop already admitted; no body / no LINK_ACK enqueue */
        return map_wire(st);
    }
    Le = lane_find(s, NINLIL_R7_FRAG_LANE_E2E, hdr.e2e_context_id);
    if (Le == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }

    /* E2E precheck — REPLAY => hop-only retransmit path */
    rs = lane_rx_precheck(Le, hdr.e2e_counter);
    if (rs == NINLIL_R7_FRAG_SESS_REPLAY) {
        hop_only = 1u;
        /* Valid hop reception of retransmit: may LINK_ACK; no body mutation. */
        if (of.ack_requested && out_link_ack_frame != NULL
            && out_link_ack_len != NULL) {
            (void)gen_link_ack(
                s, of.hop_counter, out_link_ack_frame, link_ack_cap,
                out_link_ack_len);
        }
        /* Exact START retry intent refresh if active reasm matches handle */
        if (hdr.e2e_type == NINLIL_R7_FRAG_E2E_TYPE_START) {
            /* Best-effort: open E2E for fingerprint without re-admit */
            ninlil_r7_frag_start_body body;
            uint8_t first[126];
            size_t flen = 0u;
            ninlil_r7_frag_state_start_in sin;
            ninlil_r7_frag_state_status sst;
            st = ninlil_r7_frag_open_e2e_start(
                s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, e2e_blob,
                e2e_len, &ef, &body, first, sizeof(first), &flen);
            if (st == NINLIL_R7_FRAG_OK) {
                memset(&sin, 0, sizeof(sin));
                sin.e2e_context_id = ef.e2e_context_id;
                sin.key_generation = s->key_generation;
                memcpy(sin.transfer_id, body.transfer_id, 16u);
                sin.transfer_handle = body.transfer_handle;
                sin.total_len = body.total_len;
                sin.frag_count = body.frag_count;
                sin.continuation_unit = body.continuation_unit;
                memcpy(sin.content_digest, body.content_digest, 32u);
                sin.first_chunk = first;
                sin.first_chunk_len = (uint16_t)flen;
                (void)ninlil_r7_frag_start_fingerprint(
                    s->provider, &body, first, flen, sin.fingerprint);
                sst = ninlil_r7_frag_state_admit_start(
                    &s->reasm, &sin, out_frag_intent);
                /* Only EXACT_RETRY is body-mutation-zero refresh; CONFLICT ignored */
                if (sst != NINLIL_R7_FRAG_STATE_EXACT_RETRY) {
                    memset(out_frag_intent, 0, sizeof(*out_frag_intent));
                }
            }
        }
        return NINLIL_R7_FRAG_SESS_OK;
    }
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }

    /* E2E AEAD + admit + body */
    if (hdr.e2e_type == NINLIL_R7_FRAG_E2E_TYPE_START) {
        ninlil_r7_frag_start_body body;
        uint8_t first[126];
        size_t flen = 0u;
        ninlil_r7_frag_state_start_in sin;
        ninlil_r7_frag_state_status sst;

        st = ninlil_r7_frag_open_e2e_start(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, e2e_blob, e2e_len,
            &ef, &body, first, sizeof(first), &flen);
        if (st != NINLIL_R7_FRAG_OK) {
            return map_wire(st);
        }
        rs = lane_rx_admit(s, Le, ef.e2e_counter);
        if (rs != NINLIL_R7_FRAG_SESS_OK) {
            return rs;
        }
        memset(&sin, 0, sizeof(sin));
        sin.e2e_context_id = ef.e2e_context_id;
        sin.key_generation = s->key_generation;
        memcpy(sin.transfer_id, body.transfer_id, 16u);
        sin.transfer_handle = body.transfer_handle;
        sin.total_len = body.total_len;
        sin.frag_count = body.frag_count;
        sin.continuation_unit = body.continuation_unit;
        memcpy(sin.content_digest, body.content_digest, 32u);
        sin.first_chunk = first;
        sin.first_chunk_len = (uint16_t)flen;
        st = ninlil_r7_frag_start_fingerprint(
            s->provider, &body, first, flen, sin.fingerprint);
        if (st != NINLIL_R7_FRAG_OK) {
            return map_wire(st);
        }
        sst = ninlil_r7_frag_state_admit_start(
            &s->reasm, &sin, out_frag_intent);
        if (sst == NINLIL_R7_FRAG_STATE_OK
            || sst == NINLIL_R7_FRAG_STATE_EXACT_RETRY) {
            body_ok = 1u;
        } else {
            /* counters burned; body mutation 0; no LINK_ACK */
            memset(out_frag_intent, 0, sizeof(*out_frag_intent));
            return map_state(sst);
        }
        rs = map_state(sst);
    } else if (hdr.e2e_type == NINLIL_R7_FRAG_E2E_TYPE_CONT) {
        ninlil_r7_frag_cont_body body;
        uint8_t chunk[180];
        size_t clen = 0u;
        ninlil_r7_frag_state_cont_in cin;
        ninlil_r7_frag_state_status sst;

        st = ninlil_r7_frag_open_e2e_cont(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, e2e_blob, e2e_len,
            &ef, &body, chunk, sizeof(chunk), &clen);
        if (st != NINLIL_R7_FRAG_OK) {
            return map_wire(st);
        }
        rs = lane_rx_admit(s, Le, ef.e2e_counter);
        if (rs != NINLIL_R7_FRAG_SESS_OK) {
            return rs;
        }
        memset(&cin, 0, sizeof(cin));
        cin.e2e_context_id = ef.e2e_context_id;
        cin.key_generation = s->key_generation;
        cin.transfer_handle = body.transfer_handle;
        cin.frag_index = body.frag_index;
        cin.chunk = chunk;
        cin.chunk_len = (uint16_t)clen;
        cin.reassembled_digest32 = NULL;
        sst = ninlil_r7_frag_state_admit_cont(&s->reasm, &cin, out_frag_intent);
        if (sst == NINLIL_R7_FRAG_STATE_NO_TRANSFER) {
            /* CONT-before-START: counters durably admitted; body/pub/ACK=0 */
            memset(out_frag_intent, 0, sizeof(*out_frag_intent));
            return NINLIL_R7_FRAG_SESS_NO_PUB;
        }
        if (sst == NINLIL_R7_FRAG_STATE_OK
            || sst == NINLIL_R7_FRAG_STATE_DUPLICATE
            || sst == NINLIL_R7_FRAG_STATE_NEED_DIGEST) {
            body_ok = 1u;
            rs = finalize_if_needed(
                s, ef.e2e_context_id, body.transfer_handle, out_frag_intent,
                sst);
        } else {
            memset(out_frag_intent, 0, sizeof(*out_frag_intent));
            return map_state(sst);
        }
    } else if (hdr.e2e_type == NINLIL_R7_FRAG_E2E_TYPE_ACK) {
        ninlil_r7_frag_ack_body body;
        st = ninlil_r7_frag_open_e2e_ack(
            s->provider, s->keys.e2e_key16, s->keys.e2e_iv12, e2e_blob, e2e_len,
            &ef, &body);
        if (st != NINLIL_R7_FRAG_OK) {
            return map_wire(st);
        }
        rs = lane_rx_admit(s, Le, ef.e2e_counter);
        if (rs != NINLIL_R7_FRAG_SESS_OK) {
            return rs;
        }
        rs = ninlil_r7_frag_sess_tx_apply_frag_ack(s, &body);
        body_ok = (rs == NINLIL_R7_FRAG_SESS_OK) ? 1u : 0u;
    } else {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }

    /*
     * LINK_ACK only after hop admit AND body enqueued/accepted (docs/30 §11.1
     * steps 1–5). Not on body reject after counter burn.
     */
    if (body_ok && !hop_only && of.ack_requested && out_link_ack_frame != NULL
        && out_link_ack_len != NULL && link_ack_cap >= 51u) {
        (void)gen_link_ack(
            s, of.hop_counter, out_link_ack_frame, link_ack_cap,
            out_link_ack_len);
    }
    return rs;
}

int32_t ninlil_r7_frag_sess_rx_link_ack(
    ninlil_r7_frag_sess *s,
    const uint8_t *frame,
    size_t frame_len)
{
    ninlil_r7_frag_outer_link_ack_fields lo;
    ninlil_r7_frag_link_ack_body lb;
    ninlil_r7_frag_sess_lane *Lack;
    ninlil_r7_frag_status st;
    int32_t rs;
    uint16_t fi;

    if (s == NULL || frame == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    /* RX LINK_ACK uses reverse ACK lane keys on hop_ack context of peer.
     * Local sender RX: open with hop_ack keys matching the reverse path.
     * Use hop_ack_key of local reverse install. */
    st = ninlil_r7_frag_open_outer_link_ack(
        s->provider, s->keys.hop_ack_key16, s->keys.hop_ack_iv12, frame,
        frame_len, &lo, &lb);
    if (st != NINLIL_R7_FRAG_OK) {
        return map_wire(st);
    }
    /*
     * Exact authority bind (docs/30 §11.3): outer hop_context must match an
     * installed HOP_ACK lane. No fallback to s->hop_ack_context_id when outer
     * context differs — cross-context LINK_ACK must not mutate TX state.
     */
    Lack = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_ACK, lo.hop_context_id);
    if (Lack == NULL) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (s->hop_ack_context_id != 0u
        && lo.hop_context_id != s->hop_ack_context_id) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (ninlil_r7_frag_link_ack_body_validate(&lb) != NINLIL_R7_FRAG_OK) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    /* Reverse-pair (docs/30 §11.3): body acked hop DATA context exact. */
    {
        uint32_t expect_data = s->acked_hop_data_context_id != 0u
            ? s->acked_hop_data_context_id
            : s->hop_data_context_id;
        if (expect_data != 0u
            && lb.acked_hop_context_id != expect_data) {
            return NINLIL_R7_FRAG_SESS_STRUCT;
        }
    }
    rs = lane_rx_precheck(Lack, lo.hop_counter);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    rs = lane_rx_admit(s, Lack, lo.hop_counter);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        return rs;
    }
    if (!s->tx.in_use) {
        return NINLIL_R7_FRAG_SESS_OK; /* stale */
    }
    /*
     * ack_base_counter must not run ahead of owned DATA hop counters.
     * Apply bitmap only to pending fragments with counters ≤ base.
     */
    {
        uint64_t largest = 0u;
        for (fi = 0u; fi < s->tx.plan.frag_count; fi++) {
            if (s->tx.last_hop_counter[fi] > largest) {
                largest = s->tx.last_hop_counter[fi];
            }
        }
        if (largest != 0u && lb.ack_base_counter > largest) {
            return NINLIL_R7_FRAG_SESS_STRUCT;
        }
    }
    for (fi = 0u; fi < s->tx.plan.frag_count; fi++) {
        uint64_t c = s->tx.last_hop_counter[fi];
        if (c == 0u || s->tx.frag_acked[fi]) {
            continue;
        }
        if (c > lb.ack_base_counter) {
            continue;
        }
        {
            uint64_t d = lb.ack_base_counter - c;
            if (d < 16u && ((lb.ack_bitmap >> d) & 1u)) {
                s->tx.frag_acked[fi] = 1u;
            }
        }
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

int32_t ninlil_r7_frag_sess_tx_frag_ack(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_frag_state_ack_intent *intent,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len)
{
    ninlil_r7_frag_sess_lane *Le;
    ninlil_r7_frag_sess_lane *Lhop;
    ninlil_r7_frag_ack_body body;
    ninlil_r7_frag_ack_identity_t id;
    ninlil_r7_frag_e2e_fields e2e;
    uint8_t e2e_blob[44];
    uint8_t ack_pt[NINLIL_R7_FRAG_ACK_PT_LEN];
    size_t e2e_len = 0u;
    uint64_t e2e_c;
    uint64_t hop_c;
    uint64_t owner_exp;
    ninlil_r7_frag_status st;
    int32_t rs;
    int32_t lst;
    uint32_t rev_ctx;

    if (s == NULL || intent == NULL || !intent->valid || out_frame == NULL
        || out_len == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    /* Structural PT check before reserve/burn (no budget consume on bad body). */
    memset(&body, 0, sizeof(body));
    body.transfer_handle = intent->transfer_handle;
    body.frag_count = intent->frag_count;
    body.received_bitmap = intent->received_bitmap;
    body.status = intent->status;
    body.reason = intent->reason;
    st = ninlil_r7_frag_pack_ack_pt(&body, ack_pt);
    if (st != NINLIL_R7_FRAG_OK) {
        return map_wire(st);
    }
    ninlil_r7_frag_ack_ledger_tick(&s->ack_ledger, s->now_mono);
    ninlil_r7_frag_ack_identity_from_body(
        &id, intent->transfer_handle, intent->frag_count,
        intent->received_bitmap, intent->status, intent->reason);
    /* Bind aggregate owner to this transfer (receiver / tombstone). */
    owner_exp = s->now_mono;
    if (owner_exp <= UINT64_MAX - NINLIL_R7_FRAG_RECEIVER_TTL_MS) {
        owner_exp = owner_exp + NINLIL_R7_FRAG_RECEIVER_TTL_MS;
    } else {
        owner_exp = UINT64_MAX;
    }
    ninlil_r7_frag_ack_ledger_bind_owner(
        &s->ack_ledger, intent->transfer_handle, intent->frag_count, owner_exp);
    /* §15.3.7: control reserve then identity/aggregate budgets. */
    lst = ninlil_r7_frag_ack_ledger_reserve_acquire(&s->ack_ledger);
    if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    lst = ninlil_r7_frag_ack_ledger_may_burn(&s->ack_ledger, &id, s->now_mono);
    if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    rev_ctx = (s->rev_e2e_context_id != 0u) ? s->rev_e2e_context_id
                                           : s->e2e_context_id;
    Le = lane_find(s, NINLIL_R7_FRAG_LANE_E2E, rev_ctx);
    Lhop = lane_find(s, NINLIL_R7_FRAG_LANE_HOP_DATA, s->hop_data_context_id);
    if (Le == NULL || Lhop == NULL) {
        ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    rs = lane_tx_alloc(s, Le, &e2e_c);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
        return rs;
    }
    /* Durable reverse E2E burn succeeded: charge identity ledger once. */
    lst = ninlil_r7_frag_ack_ledger_charge_burn(&s->ack_ledger, &id, s->now_mono);
    if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    memset(&e2e, 0, sizeof(e2e));
    e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_ACK;
    e2e.e2e_context_id = rev_ctx;
    e2e.e2e_counter = e2e_c;
    st = ninlil_r7_frag_seal_e2e_ack(
        s->provider, s->keys.rev_e2e_key16, s->keys.rev_e2e_iv12, &e2e, &body,
        e2e_blob, 44u, &e2e_len);
    if (st != NINLIL_R7_FRAG_OK) {
        /* Burn charged; release reserve only (ledger retained for identity). */
        ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
        return map_wire(st);
    }
    rs = lane_tx_alloc(s, Lhop, &hop_c);
    if (rs != NINLIL_R7_FRAG_SESS_OK) {
        ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
        return rs;
    }
    rs = seal_outer_for_e2e(
        s, e2e_blob, e2e_len, hop_c, out_frame, out_cap, out_len);
    /* Intent complete or fail: release control reserve (ledger retained). */
    ninlil_r7_frag_ack_ledger_reserve_release(&s->ack_ledger);
    return rs;
}

int32_t ninlil_r7_frag_sess_tx_apply_frag_ack(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_frag_ack_body *body)
{
    uint16_t i;
    if (s == NULL || body == NULL || !s->tx.in_use) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    if (body->transfer_handle != s->tx.transfer_handle) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    if (ninlil_r7_frag_ack_rx_validate(
            s->tx.plan.frag_count, s->tx.transfer_handle, body)
        != NINLIL_R7_FRAG_OK) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    s->tx.bitmap_from_frag_ack = body->received_bitmap;
    if (body->status == NINLIL_R7_FRAG_STATUS_COMPLETE
        || body->status == NINLIL_R7_FRAG_STATUS_ABORT) {
        s->tx.complete = 1u;
        for (i = 0u; i < s->tx.plan.frag_count; i++) {
            s->tx.frag_acked[i] = 1u;
        }
    } else if (body->status == NINLIL_R7_FRAG_STATUS_PARTIAL) {
        for (i = 0u; i < s->tx.plan.frag_count; i++) {
            if ((body->received_bitmap >> i) & 1u) {
                s->tx.frag_acked[i] = 1u;
            }
        }
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

int32_t ninlil_r7_frag_sess_take_publication(
    ninlil_r7_frag_sess *s,
    uint8_t *out_payload,
    size_t out_cap,
    size_t *out_len)
{
    uint32_t ctx = 0u;
    uint64_t kgen = 0u;
    uint64_t h = 0u;
    ninlil_r7_frag_state_status st;

    if (s == NULL || out_payload == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    st = ninlil_r7_frag_state_take_publication(
        &s->reasm, &ctx, &kgen, &h, out_payload, out_cap, out_len);
    if (st == NINLIL_R7_FRAG_STATE_PUBLISHED) {
        s->publish_count += 1u;
        return NINLIL_R7_FRAG_SESS_OK;
    }
    if (st == NINLIL_R7_FRAG_STATE_NO_TRANSFER) {
        return NINLIL_R7_FRAG_SESS_NO_PUB;
    }
    return map_state(st);
}

int32_t ninlil_r7_frag_sess_tick(ninlil_r7_frag_sess *s, uint64_t now)
{
    if (s == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    s->now_mono = now;
    ninlil_r7_frag_ack_ledger_tick(&s->ack_ledger, now);
    return map_state(ninlil_r7_frag_state_tick(&s->reasm, now));
}

int32_t ninlil_r7_frag_sess_restart_encode(
    const ninlil_r7_frag_sess *s,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    size_t hdr;
    size_t dlen = 0u;
    size_t off;
    size_t i;
    uint8_t nlanes = 0u;
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    int32_t dr;
#endif

    if (s == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_SESS_LANES; i++) {
        if (s->lanes[i].in_use) {
            nlanes = (uint8_t)(nlanes + 1u);
        }
    }
    /* Header is 20 bytes (magic4+ver4+now8+nlanes1+reasm0+pad2) then
     * nlanes×48; optional test-durable snapshot encodes in-place into
     * caller out[] (no intermediate 4KiB stack scratch). */
    hdr = 20u + (size_t)nlanes * 48u;
    if (out_cap < hdr + 8u) {
        return NINLIL_R7_FRAG_SESS_RESOURCE;
    }
    off = 0u;
    put_u32_be(out + off, 0x52375345u); /* R7SE */
    off += 4u;
    put_u32_be(out + off, 1u);
    off += 4u;
    put_u64_be(out + off, s->now_mono);
    off += 8u;
    out[off++] = nlanes;
    out[off++] = 0u; /* reasm always 0 on restart encode (volatile) */
    out[off++] = 0u;
    out[off++] = 0u;
    for (i = 0u; i < NINLIL_R7_FRAG_SESS_LANES; i++) {
        const ninlil_r7_frag_sess_lane *L = &s->lanes[i];
        if (!L->in_use) {
            continue;
        }
        out[off++] = L->kind;
        out[off++] = L->fenced;
        put_u32_be(out + off, L->context_id);
        off += 4u;
        put_u64_be(out + off, L->key_generation);
        off += 8u;
        put_u64_be(out + off, L->tx_next);
        off += 8u;
        put_u64_be(out + off, L->tx_limit);
        off += 8u;
        put_u64_be(out + off, L->rx_accept_through);
        off += 8u;
        put_u64_be(out + off, L->rx_boot_floor);
        off += 8u;
        /* 2 pad to 48 */
        out[off++] = 0u;
        out[off++] = 0u;
    }
    if (off != hdr) {
        return NINLIL_R7_FRAG_SESS_INTERNAL;
    }
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    dr = ninlil_r7_frag_dur_snapshot_encode(
        &s->durable, out + hdr, out_cap - hdr, &dlen);
    if (dr != NINLIL_R7_FRAG_DUR_OK) {
        return NINLIL_R7_FRAG_SESS_DURABLE;
    }
    *out_len = hdr + dlen;
#else
    (void)dlen;
    *out_len = hdr;
#endif
    return NINLIL_R7_FRAG_SESS_OK;
}

int32_t ninlil_r7_frag_sess_restart_decode(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_sess_keys *keys,
    const uint8_t *in,
    size_t in_len)
{
    uint32_t magic;
    uint32_t ver;
    uint8_t nlanes;
    size_t off = 0u;
    size_t i;
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    int32_t dr;
#endif

    if (s == NULL || provider == NULL || keys == NULL || in == NULL
        || in_len < 16u) {
        return NINLIL_R7_FRAG_SESS_INVALID;
    }
    magic = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    if (magic != 0x52375345u) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    ver = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16)
        | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    if (ver != 1u) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    ninlil_r7_frag_sess_init(s, provider, keys);
    s->now_mono = ((uint64_t)in[8] << 56) | ((uint64_t)in[9] << 48)
        | ((uint64_t)in[10] << 40) | ((uint64_t)in[11] << 32)
        | ((uint64_t)in[12] << 24) | ((uint64_t)in[13] << 16)
        | ((uint64_t)in[14] << 8) | (uint64_t)in[15];
    off = 16u;
    if (off + 4u > in_len) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    nlanes = in[off++];
    if (in[off++] != 0u) { /* reasm claim must be 0 */
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    off += 2u;
    if ((size_t)nlanes > NINLIL_R7_FRAG_SESS_LANES) {
        return NINLIL_R7_FRAG_SESS_STRUCT;
    }
    for (i = 0u; i < nlanes; i++) {
        ninlil_r7_frag_sess_lane *L;
        if (off + 48u > in_len) {
            return NINLIL_R7_FRAG_SESS_STRUCT;
        }
        L = &s->lanes[i];
        memset(L, 0, sizeof(*L));
        L->in_use = 1u;
        L->kind = in[off++];
        L->fenced = in[off++];
        L->context_id = ((uint32_t)in[off] << 24) | ((uint32_t)in[off + 1] << 16)
            | ((uint32_t)in[off + 2] << 8) | (uint32_t)in[off + 3];
        off += 4u;
        L->key_generation = ((uint64_t)in[off] << 56)
            | ((uint64_t)in[off + 1] << 48) | ((uint64_t)in[off + 2] << 40)
            | ((uint64_t)in[off + 3] << 32) | ((uint64_t)in[off + 4] << 24)
            | ((uint64_t)in[off + 5] << 16) | ((uint64_t)in[off + 6] << 8)
            | (uint64_t)in[off + 7];
        off += 8u;
        L->tx_next = ((uint64_t)in[off] << 56) | ((uint64_t)in[off + 1] << 48)
            | ((uint64_t)in[off + 2] << 40) | ((uint64_t)in[off + 3] << 32)
            | ((uint64_t)in[off + 4] << 24) | ((uint64_t)in[off + 5] << 16)
            | ((uint64_t)in[off + 6] << 8) | (uint64_t)in[off + 7];
        off += 8u;
        L->tx_limit = ((uint64_t)in[off] << 56) | ((uint64_t)in[off + 1] << 48)
            | ((uint64_t)in[off + 2] << 40) | ((uint64_t)in[off + 3] << 32)
            | ((uint64_t)in[off + 4] << 24) | ((uint64_t)in[off + 5] << 16)
            | ((uint64_t)in[off + 6] << 8) | (uint64_t)in[off + 7];
        off += 8u;
        L->rx_accept_through = ((uint64_t)in[off] << 56)
            | ((uint64_t)in[off + 1] << 48) | ((uint64_t)in[off + 2] << 40)
            | ((uint64_t)in[off + 3] << 32) | ((uint64_t)in[off + 4] << 24)
            | ((uint64_t)in[off + 5] << 16) | ((uint64_t)in[off + 6] << 8)
            | (uint64_t)in[off + 7];
        off += 8u;
        L->rx_boot_floor = ((uint64_t)in[off] << 56)
            | ((uint64_t)in[off + 1] << 48) | ((uint64_t)in[off + 2] << 40)
            | ((uint64_t)in[off + 3] << 32) | ((uint64_t)in[off + 4] << 24)
            | ((uint64_t)in[off + 5] << 16) | ((uint64_t)in[off + 6] << 8)
            | (uint64_t)in[off + 7];
        off += 8u;
        /* Restart RX sliding is empty from boot floor */
        L->rx_highest = L->rx_boot_floor = L->rx_accept_through;
        L->rx_bitmap = 0u;
        off += 2u;
        if (L->kind == NINLIL_R7_FRAG_LANE_HOP_DATA) {
            s->hop_data_context_id = L->context_id;
            s->acked_hop_data_context_id = L->context_id;
        } else if (L->kind == NINLIL_R7_FRAG_LANE_HOP_ACK) {
            s->hop_ack_context_id = L->context_id;
        } else if (L->kind == NINLIL_R7_FRAG_LANE_E2E) {
            if (s->e2e_context_id == 0u) {
                s->e2e_context_id = L->context_id;
            } else {
                s->rev_e2e_context_id = L->context_id;
            }
        }
        s->key_generation = L->key_generation;
    }
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    /* Test durable store remainder (not production N6). */
    dr = ninlil_r7_frag_dur_snapshot_decode(&s->durable, in + off, in_len - off);
    if (dr != NINLIL_R7_FRAG_DUR_OK) {
        return NINLIL_R7_FRAG_SESS_DURABLE;
    }
#else
    (void)off;
#endif
    /* Volatile cleared: reasm empty, tx empty, no publication */
    ninlil_r7_frag_state_init(&s->reasm);
    s->reasm.now_mono = s->now_mono;
    memset(&s->tx, 0, sizeof(s->tx));
    s->publish_count = 0u;
    return NINLIL_R7_FRAG_SESS_OK;
}
