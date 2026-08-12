/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Dedicated R7 FRAG actual-wire/session lifecycle acceptance.
 *
 * The canonical sender maximizes START S.  Therefore total_len=2048 produces
 * 12 fragments (S=126), while the accepted wire geometry S=1 produces the
 * normative effective maximum of 13.  Rows 2..12 use sess_tx_begin/tx_air;
 * row 13 is deliberately materialized with the production codec/AEAD and then
 * consumed by sess_rx_data.  It is not silently omitted or replaced by a pure
 * state-only assertion.
 */

#include "r7_crypto_openssl3.h"
#include "r7_frag.h"
#include "r7_frag_profile.h"
#include "r7_frag_session.h"
#include "r7_frag_state.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MATRIX_HOP_CONTEXT ((uint32_t)11u)
#define MATRIX_E2E_CONTEXT ((uint32_t)21u)
#define MATRIX_KEY_GENERATION ((uint64_t)1u)
#define MATRIX_FUZZ_SEED ((uint32_t)0x7f4a7c15u)
#define MATRIX_FUZZ_ROUNDS ((uint16_t)2u)

typedef struct lifecycle_row {
    uint16_t frag_count;
    uint32_t total_len;
    uint16_t first_chunk_len;
    uint8_t manual_wire;
} lifecycle_row;

typedef struct wire_set {
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t first_chunk_len;
    uint8_t payload[NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX];
    uint8_t frames[NINLIL_R7_FRAG_SESS_MAX_FRAGS]
        [NINLIL_R7_FRAG_SESS_FRAME_MAX];
    size_t frame_lens[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
} wire_set;

static const lifecycle_row g_rows[] = {
    { 2u, 127u, 126u, 0u },
    { 3u, 307u, 126u, 0u },
    { 4u, 487u, 126u, 0u },
    { 5u, 667u, 126u, 0u },
    { 6u, 847u, 126u, 0u },
    { 7u, 1027u, 126u, 0u },
    { 8u, 1207u, 126u, 0u },
    { 9u, 1387u, 126u, 0u },
    { 10u, 1567u, 126u, 0u },
    { 11u, 1747u, 126u, 0u },
    { 12u, 1927u, 126u, 0u },
    { 13u, 2048u, 1u, 1u },
};

static int g_fail;
static uint32_t g_checks;
static uint32_t g_lifecycle_rows;
static uint32_t g_fault_scenarios;
static uint32_t g_fuzz_cases;
static ninlil_r7_crypto_provider g_provider;
static ninlil_r7_frag_sess_keys g_keys;
static ninlil_r7_frag_sess g_tx;
static ninlil_r7_frag_sess g_rx;
static ninlil_r7_frag_sess g_rx_restart;
static wire_set g_wire;
static uint8_t g_publication[NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX];
static uint8_t g_snapshot[8192];
static uint8_t g_oversize[NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX + 1u];

static void expect_i(
    const char *scope,
    uint16_t frag_count,
    const char *name,
    int32_t got,
    int32_t want)
{
    g_checks++;
    if (got != want) {
        fprintf(stderr,
            "FAIL %s fc=%u %s got=%d want=%d\n",
            scope,
            (unsigned)frag_count,
            name,
            (int)got,
            (int)want);
        g_fail++;
    }
}

static void expect_u64(
    const char *scope,
    uint16_t frag_count,
    const char *name,
    uint64_t got,
    uint64_t want)
{
    g_checks++;
    if (got != want) {
        fprintf(stderr,
            "FAIL %s fc=%u %s got=%llu want=%llu\n",
            scope,
            (unsigned)frag_count,
            name,
            (unsigned long long)got,
            (unsigned long long)want);
        g_fail++;
    }
}

static void expect_true(
    const char *scope,
    uint16_t frag_count,
    const char *name,
    int condition)
{
    g_checks++;
    if (!condition) {
        fprintf(stderr,
            "FAIL %s fc=%u %s\n",
            scope,
            (unsigned)frag_count,
            name);
        g_fail++;
    }
}

static void fill_bytes(uint8_t *out, size_t len, uint8_t seed)
{
    size_t i;
    uint32_t x = (uint32_t)seed + UINT32_C(0x9e3779b9);
    for (i = 0u; i < len; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out[i] = (uint8_t)(x ^ (uint32_t)i);
    }
}

static void fill_transfer_id(uint8_t out[16], uint8_t seed)
{
    size_t i;
    for (i = 0u; i < 16u; i++) {
        out[i] = (uint8_t)(seed + (uint8_t)(17u * i));
    }
}

static void init_keys(void)
{
    size_t i;
    memset(&g_keys, 0, sizeof(g_keys));
    for (i = 0u; i < 16u; i++) {
        g_keys.e2e_key16[i] = (uint8_t)(0x10u + i);
        g_keys.hop_data_key16[i] = (uint8_t)(0x30u + i);
        g_keys.hop_ack_key16[i] = (uint8_t)(0x50u + i);
        g_keys.rev_hop_ack_key16[i] = g_keys.hop_ack_key16[i];
        g_keys.rev_e2e_key16[i] = g_keys.e2e_key16[i];
    }
    for (i = 0u; i < 12u; i++) {
        g_keys.e2e_iv12[i] = (uint8_t)(0x20u + i);
        g_keys.hop_data_iv12[i] = (uint8_t)(0x40u + i);
        g_keys.hop_ack_iv12[i] = (uint8_t)(0x60u + i);
        g_keys.rev_hop_ack_iv12[i] = g_keys.hop_ack_iv12[i];
        g_keys.rev_e2e_iv12[i] = g_keys.e2e_iv12[i];
    }
}

static int32_t init_session(
    ninlil_r7_frag_sess *sess,
    uint64_t now_mono,
    uint8_t ack_requested)
{
    int32_t st;
    ninlil_r7_frag_sess_init(sess, &g_provider, &g_keys);
    ninlil_r7_frag_sess_set_now(sess, now_mono);
    st = ninlil_r7_frag_sess_install_lane(
        sess,
        NINLIL_R7_FRAG_LANE_HOP_DATA,
        MATRIX_HOP_CONTEXT,
        MATRIX_KEY_GENERATION);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return st;
    }
    st = ninlil_r7_frag_sess_install_lane(
        sess,
        NINLIL_R7_FRAG_LANE_E2E,
        MATRIX_E2E_CONTEXT,
        MATRIX_KEY_GENERATION);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return st;
    }
    sess->ack_requested_default = ack_requested;
    return NINLIL_R7_FRAG_SESS_OK;
}

static size_t active_reassembly_count(const ninlil_r7_frag_sess *sess)
{
    size_t i;
    size_t count = 0u;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
        if (sess->reasm.reasm[i].in_use) {
            count++;
        }
    }
    return count;
}

static size_t live_tombstone_count(const ninlil_r7_frag_sess *sess)
{
    size_t i;
    size_t count = 0u;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS; i++) {
        if (sess->reasm.tombs[i].in_use
            && !sess->reasm.tombs[i].is_reservation) {
            count++;
        }
    }
    return count;
}

static ninlil_r7_frag_state_slot *first_active_slot(
    ninlil_r7_frag_sess *sess)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
        if (sess->reasm.reasm[i].in_use) {
            return &sess->reasm.reasm[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_state_tombstone *first_terminal_tomb(
    ninlil_r7_frag_sess *sess)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS; i++) {
        if (sess->reasm.tombs[i].in_use
            && !sess->reasm.tombs[i].is_reservation) {
            return &sess->reasm.tombs[i];
        }
    }
    return NULL;
}

static int32_t seal_outer_blob(
    const uint8_t *e2e_blob,
    size_t e2e_len,
    uint64_t hop_counter,
    uint8_t out_frame[NINLIL_R7_FRAG_SESS_FRAME_MAX],
    size_t *out_len)
{
    ninlil_r7_frag_outer_data_fields outer;
    size_t frame_need =
        NINLIL_R7_FRAG_OUTER_AAD_LEN + e2e_len + NINLIL_R7_FRAG_TAG_LEN;
    memset(&outer, 0, sizeof(outer));
    outer.ack_requested = 0u;
    outer.hop_context_id = MATRIX_HOP_CONTEXT;
    outer.hop_counter = hop_counter;
    return ninlil_r7_frag_seal_outer_data(
        &g_provider,
        g_keys.hop_data_key16,
        g_keys.hop_data_iv12,
        &outer,
        e2e_blob,
        e2e_len,
        out_frame,
        frame_need,
        out_len);
}

static int32_t seal_manual_start(
    const uint8_t *payload,
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    const uint8_t transfer_id[16],
    uint64_t transfer_handle,
    uint64_t e2e_counter,
    uint64_t hop_counter,
    uint8_t out_frame[NINLIL_R7_FRAG_SESS_FRAME_MAX],
    size_t *out_len)
{
    ninlil_r7_frag_start_body body;
    ninlil_r7_frag_e2e_fields fields;
    uint8_t e2e_blob[220];
    size_t e2e_len = 0u;
    int32_t st;

    memset(&body, 0, sizeof(body));
    memcpy(body.transfer_id, transfer_id, 16u);
    body.transfer_handle = transfer_handle;
    body.total_len = total_len;
    body.frag_count = frag_count;
    body.continuation_unit = NINLIL_R7_FRAG_STATE_CONT_UNIT;
    if (ninlil_r7_crypto_sha256(
            &g_provider, payload, total_len, body.content_digest)
        != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_R7_FRAG_BACKEND_FAILED;
    }

    memset(&fields, 0, sizeof(fields));
    fields.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
    fields.e2e_context_id = MATRIX_E2E_CONTEXT;
    fields.e2e_counter = e2e_counter;
    st = ninlil_r7_frag_seal_e2e_start(
        &g_provider,
        g_keys.e2e_key16,
        g_keys.e2e_iv12,
        &fields,
        &body,
        payload,
        first_chunk_len,
        e2e_blob,
        NINLIL_R7_FRAG_E2E_AAD_LEN + 64u + first_chunk_len
            + NINLIL_R7_FRAG_TAG_LEN,
        &e2e_len);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    return seal_outer_blob(e2e_blob, e2e_len, hop_counter, out_frame, out_len);
}

static int32_t seal_manual_cont(
    uint64_t transfer_handle,
    uint16_t frag_index,
    const uint8_t *chunk,
    uint16_t chunk_len,
    uint64_t e2e_counter,
    uint64_t hop_counter,
    uint8_t out_frame[NINLIL_R7_FRAG_SESS_FRAME_MAX],
    size_t *out_len)
{
    ninlil_r7_frag_cont_body body;
    ninlil_r7_frag_e2e_fields fields;
    uint8_t e2e_blob[220];
    size_t e2e_len = 0u;
    int32_t st;

    memset(&body, 0, sizeof(body));
    body.transfer_handle = transfer_handle;
    body.frag_index = frag_index;
    memset(&fields, 0, sizeof(fields));
    fields.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
    fields.e2e_context_id = MATRIX_E2E_CONTEXT;
    fields.e2e_counter = e2e_counter;
    st = ninlil_r7_frag_seal_e2e_cont(
        &g_provider,
        g_keys.e2e_key16,
        g_keys.e2e_iv12,
        &fields,
        &body,
        chunk,
        chunk_len,
        e2e_blob,
        NINLIL_R7_FRAG_E2E_AAD_LEN + 10u + chunk_len
            + NINLIL_R7_FRAG_TAG_LEN,
        &e2e_len);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    return seal_outer_blob(e2e_blob, e2e_len, hop_counter, out_frame, out_len);
}

static int32_t build_manual_wire_set(
    wire_set *set,
    uint16_t frag_count,
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint8_t transfer_seed,
    uint64_t counter_base)
{
    uint8_t transfer_id[16];
    uint32_t offset;
    uint16_t i;
    int32_t st;

    set->total_len = total_len;
    set->frag_count = frag_count;
    set->first_chunk_len = first_chunk_len;
    fill_transfer_id(transfer_id, transfer_seed);
    st = seal_manual_start(
        set->payload,
        total_len,
        first_chunk_len,
        frag_count,
        transfer_id,
        counter_base,
        counter_base,
        counter_base,
        set->frames[0],
        &set->frame_lens[0]);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    offset = first_chunk_len;
    for (i = 1u; i < frag_count; i++) {
        uint32_t left = total_len - offset;
        uint16_t chunk_len = (left > NINLIL_R7_FRAG_STATE_CONT_UNIT)
            ? NINLIL_R7_FRAG_STATE_CONT_UNIT
            : (uint16_t)left;
        st = seal_manual_cont(
            counter_base,
            i,
            set->payload + offset,
            chunk_len,
            counter_base + i,
            counter_base + i,
            set->frames[i],
            &set->frame_lens[i]);
        if (st != NINLIL_R7_FRAG_OK) {
            return st;
        }
        offset += chunk_len;
    }
    return (offset == total_len) ? NINLIL_R7_FRAG_OK
                                 : NINLIL_R7_FRAG_INTERNAL_CONTRACT;
}

static int32_t build_canonical_wire_set(
    wire_set *set,
    uint32_t total_len,
    uint8_t transfer_seed)
{
    uint8_t transfer_id[16];
    uint16_t frag_index = UINT16_MAX;
    uint16_t i;
    int32_t st;

    set->total_len = total_len;
    fill_transfer_id(transfer_id, transfer_seed);
    st = ninlil_r7_frag_sess_tx_begin(
        &g_tx,
        set->payload,
        total_len,
        transfer_id,
        set->frames[0],
        sizeof(set->frames[0]),
        &set->frame_lens[0],
        &frag_index);
    if (st != NINLIL_R7_FRAG_SESS_OK) {
        return st;
    }
    set->frag_count = g_tx.tx.plan.frag_count;
    set->first_chunk_len = g_tx.tx.plan.first_chunk_len;
    if (frag_index != 0u) {
        return NINLIL_R7_FRAG_SESS_INTERNAL;
    }
    for (i = 1u; i < set->frag_count; i++) {
        st = ninlil_r7_frag_sess_tx_air(
            &g_tx,
            i,
            set->frames[i],
            sizeof(set->frames[i]),
            &set->frame_lens[i]);
        if (st != NINLIL_R7_FRAG_SESS_OK) {
            return st;
        }
    }
    return NINLIL_R7_FRAG_SESS_OK;
}

static int32_t receive_frame(
    ninlil_r7_frag_sess *rx,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_state_ack_intent *intent)
{
    return ninlil_r7_frag_sess_rx_data(
        rx, frame, frame_len, intent, NULL, 0u, NULL);
}

static void expect_publication_once(
    const char *scope,
    uint16_t frag_count,
    ninlil_r7_frag_sess *rx,
    const uint8_t *payload,
    size_t payload_len)
{
    size_t publication_len = 0u;
    int32_t st = ninlil_r7_frag_sess_take_publication(
        rx,
        g_publication,
        sizeof(g_publication),
        &publication_len);
    expect_i(scope, frag_count, "publication", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64(scope, frag_count, "publication length", publication_len, payload_len);
    expect_true(scope,
        frag_count,
        "publication bytes",
        publication_len == payload_len
            && memcmp(g_publication, payload, payload_len) == 0);
    expect_u64(scope, frag_count, "session publish count", rx->publish_count, 1u);
    st = ninlil_r7_frag_sess_take_publication(
        rx,
        g_publication,
        sizeof(g_publication),
        &publication_len);
    expect_i(
        scope, frag_count, "publication exact once", st, NINLIL_R7_FRAG_SESS_NO_PUB);
    expect_u64(scope, frag_count, "publish count stable", rx->publish_count, 1u);
}

static void test_lifecycle_rows_2_through_13(void)
{
    size_t row_index;
    for (row_index = 0u; row_index < sizeof(g_rows) / sizeof(g_rows[0]);
         row_index++) {
        const lifecycle_row *row = &g_rows[row_index];
        ninlil_r7_frag_state_ack_intent intent;
        ninlil_r7_frag_state_plan canonical_max;
        int32_t st;
        uint16_t i;

        memset(&g_wire, 0, sizeof(g_wire));
        fill_bytes(
            g_wire.payload, row->total_len, (uint8_t)(0x20u + row->frag_count));
        st = init_session(&g_rx, 1000u, 0u);
        expect_i("matrix", row->frag_count, "rx init", st, NINLIL_R7_FRAG_SESS_OK);
        if (st != NINLIL_R7_FRAG_SESS_OK) {
            continue;
        }
        if (row->manual_wire) {
            st = ninlil_r7_frag_state_plan_build(2048u, &canonical_max);
            expect_i("matrix",
                row->frag_count,
                "canonical max plan",
                st,
                NINLIL_R7_FRAG_STATE_OK);
            expect_u64("matrix",
                row->frag_count,
                "canonical sender maximum is 12",
                canonical_max.frag_count,
                12u);
            st = ninlil_r7_frag_state_plan_validate(
                2048u, 1u, 13u, NINLIL_R7_FRAG_STATE_CONT_UNIT);
            expect_i("matrix",
                row->frag_count,
                "manual 13 geometry valid",
                st,
                NINLIL_R7_FRAG_STATE_OK);
            st = build_manual_wire_set(
                &g_wire, 13u, 2048u, 1u, (uint8_t)0xd3u, 1u);
            expect_i(
                "matrix", row->frag_count, "manual wire build", st, NINLIL_R7_FRAG_OK);
        } else {
            st = init_session(&g_tx, 1000u, 0u);
            expect_i(
                "matrix", row->frag_count, "tx init", st, NINLIL_R7_FRAG_SESS_OK);
            if (st == NINLIL_R7_FRAG_SESS_OK) {
                st = build_canonical_wire_set(
                    &g_wire, row->total_len, (uint8_t)(0x80u + row->frag_count));
            }
            expect_i("matrix",
                row->frag_count,
                "canonical wire build",
                st,
                NINLIL_R7_FRAG_SESS_OK);
        }
        if (st != NINLIL_R7_FRAG_SESS_OK && st != NINLIL_R7_FRAG_OK) {
            continue;
        }
        expect_u64(
            "matrix", row->frag_count, "fragment count", g_wire.frag_count, row->frag_count);
        expect_u64("matrix",
            row->frag_count,
            "first chunk",
            g_wire.first_chunk_len,
            row->first_chunk_len);
        for (i = 0u; i < row->frag_count; i++) {
            memset(&intent, 0, sizeof(intent));
            st = receive_frame(
                &g_rx, g_wire.frames[i], g_wire.frame_lens[i], &intent);
            expect_i(
                "matrix", row->frag_count, "wire receive", st, NINLIL_R7_FRAG_SESS_OK);
            expect_true(
                "matrix", row->frag_count, "wire profile 0x11", g_wire.frames[i][0] == 0x11u);
        }
        expect_true("matrix",
            row->frag_count,
            "terminal COMPLETE intent",
            intent.valid
                && intent.status == NINLIL_R7_FRAG_STATE_STATUS_COMPLETE
                && intent.received_bitmap
                    == (uint16_t)((1u << row->frag_count) - 1u));
        expect_u64("matrix",
            row->frag_count,
            "engine completion count",
            g_rx.reasm.publish_count,
            1u);
        expect_publication_once(
            "matrix", row->frag_count, &g_rx, g_wire.payload, row->total_len);
        memset(&intent, 0, sizeof(intent));
        st = receive_frame(
            &g_rx, g_wire.frames[0], g_wire.frame_lens[0], &intent);
        expect_i(
            "matrix", row->frag_count, "outer replay", st, NINLIL_R7_FRAG_SESS_REPLAY);
        expect_u64(
            "matrix", row->frag_count, "no replay publish", g_rx.publish_count, 1u);
        g_lifecycle_rows++;
    }
}

static void test_loss_retry_and_sender_timer_boundary(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t original_e2e[220];
    uint8_t retry[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    size_t retry_len = 0u;
    size_t original_e2e_len;
    uint64_t original_hop;
    int32_t st;
    uint16_t i;

    memset(&g_wire, 0, sizeof(g_wire));
    fill_bytes(g_wire.payload, 307u, 0x31u);
    expect_i("loss-retry",
        3u,
        "tx init",
        init_session(&g_tx, 1000u, 1u),
        NINLIL_R7_FRAG_SESS_OK);
    expect_i("loss-retry",
        3u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = build_canonical_wire_set(&g_wire, 307u, 0x32u);
    expect_i(
        "loss-retry", 3u, "wire build", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64("loss-retry", 3u, "count", g_wire.frag_count, 3u);
    original_e2e_len = g_tx.tx.e2e_len[0];
    memcpy(original_e2e, g_tx.tx.e2e_blob[0], original_e2e_len);
    original_hop = g_tx.tx.last_hop_counter[0];
    st = ninlil_r7_frag_sess_tx_note_air(&g_tx, 0u, original_hop);
    expect_i(
        "loss-retry", 3u, "lost air noted", st, NINLIL_R7_FRAG_SESS_OK);
    ninlil_r7_frag_sess_set_now(&g_tx, 3999u);
    st = ninlil_r7_frag_sess_tx_air(
        &g_tx, 0u, retry, sizeof(retry), &retry_len);
    expect_i("loss-retry",
        3u,
        "one before eligible",
        st,
        NINLIL_R7_FRAG_SESS_RETRY);
    expect_u64("loss-retry",
        3u,
        "no early hop burn",
        g_tx.tx.last_hop_counter[0],
        original_hop);
    ninlil_r7_frag_sess_set_now(&g_tx, 4000u);
    st = ninlil_r7_frag_sess_tx_air(
        &g_tx, 0u, retry, sizeof(retry), &retry_len);
    expect_i(
        "loss-retry", 3u, "exact eligible retry", st, NINLIL_R7_FRAG_SESS_OK);
    expect_true("loss-retry",
        3u,
        "fresh hop counter",
        g_tx.tx.last_hop_counter[0] != original_hop);
    expect_true("loss-retry",
        3u,
        "bit-identical e2e",
        g_tx.tx.e2e_len[0] == original_e2e_len
            && memcmp(g_tx.tx.e2e_blob[0], original_e2e, original_e2e_len) == 0);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, retry, retry_len, &intent);
    expect_i(
        "loss-retry", 3u, "receive retry", st, NINLIL_R7_FRAG_SESS_OK);
    for (i = 1u; i < g_wire.frag_count; i++) {
        memset(&intent, 0, sizeof(intent));
        st = receive_frame(
            &g_rx, g_wire.frames[i], g_wire.frame_lens[i], &intent);
        expect_i(
            "loss-retry", 3u, "receive continuation", st, NINLIL_R7_FRAG_SESS_OK);
    }
    expect_publication_once(
        "loss-retry", 3u, &g_rx, g_wire.payload, g_wire.total_len);
    g_fault_scenarios += 2u; /* loss/retry + exact sender timer boundary */
}

static void test_reverse_reorder(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    int32_t st;
    uint16_t i;

    memset(&g_wire, 0, sizeof(g_wire));
    fill_bytes(g_wire.payload, 1927u, 0x41u);
    expect_i("reverse-reorder",
        12u,
        "tx init",
        init_session(&g_tx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    expect_i("reverse-reorder",
        12u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = build_canonical_wire_set(&g_wire, 1927u, 0x42u);
    expect_i(
        "reverse-reorder", 12u, "wire build", st, NINLIL_R7_FRAG_SESS_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx, g_wire.frames[0], g_wire.frame_lens[0], &intent);
    expect_i(
        "reverse-reorder", 12u, "START", st, NINLIL_R7_FRAG_SESS_OK);
    for (i = g_wire.frag_count; i > 1u; i--) {
        uint16_t index = (uint16_t)(i - 1u);
        memset(&intent, 0, sizeof(intent));
        st = receive_frame(
            &g_rx, g_wire.frames[index], g_wire.frame_lens[index], &intent);
        expect_i("reverse-reorder",
            12u,
            "reverse CONT",
            st,
            NINLIL_R7_FRAG_SESS_OK);
    }
    expect_publication_once(
        "reverse-reorder", 12u, &g_rx, g_wire.payload, g_wire.total_len);
    g_fault_scenarios++;
}

static void test_identical_and_conflicting_duplicate(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    ninlil_r7_frag_state_slot *slot;
    uint8_t transfer_id[16];
    uint8_t duplicate[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    uint8_t conflict[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    uint8_t bad_chunk[NINLIL_R7_FRAG_STATE_CONT_UNIT];
    size_t duplicate_len = 0u;
    size_t conflict_len = 0u;
    uint16_t bitmap_before;
    uint64_t idle_before;
    size_t bytes_before;
    int32_t st;

    memset(&g_wire, 0, sizeof(g_wire));
    g_wire.total_len = 487u;
    g_wire.frag_count = 4u;
    g_wire.first_chunk_len = 126u;
    fill_bytes(g_wire.payload, g_wire.total_len, 0x51u);
    fill_transfer_id(transfer_id, 0x52u);
    expect_i("duplicates",
        4u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = seal_manual_start(g_wire.payload,
        g_wire.total_len,
        g_wire.first_chunk_len,
        g_wire.frag_count,
        transfer_id,
        1u,
        1u,
        1u,
        g_wire.frames[0],
        &g_wire.frame_lens[0]);
    expect_i("duplicates", 4u, "seal START", st, NINLIL_R7_FRAG_OK);
    st = seal_manual_cont(1u,
        1u,
        g_wire.payload + 126u,
        NINLIL_R7_FRAG_STATE_CONT_UNIT,
        2u,
        2u,
        g_wire.frames[1],
        &g_wire.frame_lens[1]);
    expect_i("duplicates", 4u, "seal CONT", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx, g_wire.frames[0], g_wire.frame_lens[0], &intent);
    expect_i("duplicates", 4u, "receive START", st, NINLIL_R7_FRAG_SESS_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx, g_wire.frames[1], g_wire.frame_lens[1], &intent);
    expect_i("duplicates", 4u, "receive CONT", st, NINLIL_R7_FRAG_SESS_OK);
    slot = first_active_slot(&g_rx);
    expect_true("duplicates", 4u, "active owner", slot != NULL);
    if (slot == NULL) {
        return;
    }
    bitmap_before = slot->bitmap;
    idle_before = slot->idle_deadline;
    bytes_before = g_rx.reasm.payload_bytes_in_use;

    st = seal_manual_cont(1u,
        1u,
        g_wire.payload + 126u,
        NINLIL_R7_FRAG_STATE_CONT_UNIT,
        3u,
        3u,
        duplicate,
        &duplicate_len);
    expect_i(
        "duplicates", 4u, "seal identical fresh counters", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, duplicate, duplicate_len, &intent);
    expect_i(
        "duplicates", 4u, "identical duplicate", st, NINLIL_R7_FRAG_SESS_OK);
    slot = first_active_slot(&g_rx);
    expect_true("duplicates",
        4u,
        "identical no owner mutation",
        slot != NULL && slot->bitmap == bitmap_before
            && slot->idle_deadline == idle_before
            && g_rx.reasm.payload_bytes_in_use == bytes_before);
    expect_u64("duplicates", 4u, "identical no publish", g_rx.reasm.publish_count, 0u);

    memcpy(
        bad_chunk, g_wire.payload + 126u, NINLIL_R7_FRAG_STATE_CONT_UNIT);
    bad_chunk[17] ^= 0x80u;
    st = seal_manual_cont(1u,
        1u,
        bad_chunk,
        NINLIL_R7_FRAG_STATE_CONT_UNIT,
        4u,
        4u,
        conflict,
        &conflict_len);
    expect_i(
        "duplicates", 4u, "seal conflict fresh counters", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, conflict, conflict_len, &intent);
    expect_i(
        "duplicates", 4u, "conflicting duplicate", st, NINLIL_R7_FRAG_SESS_STRUCT);
    expect_u64(
        "duplicates", 4u, "conflict owner released", active_reassembly_count(&g_rx), 0u);
    expect_u64(
        "duplicates", 4u, "conflict tombstone", live_tombstone_count(&g_rx), 1u);
    expect_true("duplicates",
        4u,
        "conflict reason",
        first_terminal_tomb(&g_rx) != NULL
            && first_terminal_tomb(&g_rx)->reason
                == NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
    expect_u64("duplicates", 4u, "conflict no publish", g_rx.reasm.publish_count, 0u);
    g_fault_scenarios += 2u;
}

static void test_missing_start_then_fresh_e2e_recovery(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t fresh_cont[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    size_t fresh_cont_len = 0u;
    int32_t st;
    uint16_t i;

    memset(&g_wire, 0, sizeof(g_wire));
    fill_bytes(g_wire.payload, 667u, 0x61u);
    expect_i("missing-start",
        5u,
        "tx init",
        init_session(&g_tx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    expect_i("missing-start",
        5u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = build_canonical_wire_set(&g_wire, 667u, 0x62u);
    expect_i(
        "missing-start", 5u, "wire build", st, NINLIL_R7_FRAG_SESS_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx, g_wire.frames[1], g_wire.frame_lens[1], &intent);
    expect_i(
        "missing-start", 5u, "CONT before START", st, NINLIL_R7_FRAG_SESS_NO_PUB);
    expect_u64(
        "missing-start", 5u, "no owner allocated", active_reassembly_count(&g_rx), 0u);
    expect_true("missing-start", 5u, "no ACK intent", intent.valid == 0u);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx, g_wire.frames[0], g_wire.frame_lens[0], &intent);
    expect_i(
        "missing-start", 5u, "START after gap", st, NINLIL_R7_FRAG_SESS_OK);
    st = ninlil_r7_frag_sess_tx_e2e_retry(&g_tx,
        1u,
        g_wire.payload,
        g_wire.total_len,
        fresh_cont,
        sizeof(fresh_cont),
        &fresh_cont_len);
    expect_i("missing-start",
        5u,
        "fresh E2E retry",
        st,
        NINLIL_R7_FRAG_SESS_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, fresh_cont, fresh_cont_len, &intent);
    expect_i("missing-start",
        5u,
        "fresh CONT accepted",
        st,
        NINLIL_R7_FRAG_SESS_OK);
    for (i = 2u; i < g_wire.frag_count; i++) {
        memset(&intent, 0, sizeof(intent));
        st = receive_frame(
            &g_rx, g_wire.frames[i], g_wire.frame_lens[i], &intent);
        expect_i("missing-start",
            5u,
            "remaining CONT",
            st,
            NINLIL_R7_FRAG_SESS_OK);
    }
    expect_publication_once(
        "missing-start", 5u, &g_rx, g_wire.payload, g_wire.total_len);
    g_fault_scenarios++;
}

static void test_resource_max_and_plus_one(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[2] = { 0xa5u, 0x5au };
    uint8_t transfer_id[16];
    uint8_t frame[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    size_t frame_len = 0u;
    size_t i;
    int32_t st;
    uint16_t frag_index = UINT16_MAX;

    expect_i("resource",
        2u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    for (i = 0u; i <= NINLIL_R7_FRAG_STATE_MAX_PER_PEER; i++) {
        fill_transfer_id(transfer_id, (uint8_t)(0x70u + i));
        st = seal_manual_start(payload,
            2u,
            1u,
            2u,
            transfer_id,
            (uint64_t)(i + 1u),
            (uint64_t)(i + 1u),
            (uint64_t)(i + 1u),
            frame,
            &frame_len);
        expect_i("resource", 2u, "seal owner START", st, NINLIL_R7_FRAG_OK);
        memset(&intent, 0, sizeof(intent));
        st = receive_frame(&g_rx, frame, frame_len, &intent);
        if (i < NINLIL_R7_FRAG_STATE_MAX_PER_PEER) {
            expect_i(
                "resource", 2u, "owner at max", st, NINLIL_R7_FRAG_SESS_OK);
        } else {
            expect_i("resource",
                2u,
                "owner max plus one",
                st,
                NINLIL_R7_FRAG_SESS_RESOURCE);
            expect_true("resource", 2u, "plus one ACK zero", intent.valid == 0u);
        }
    }
    expect_u64("resource",
        2u,
        "max owners retained",
        active_reassembly_count(&g_rx),
        NINLIL_R7_FRAG_STATE_MAX_PER_PEER);

    fill_bytes(g_oversize, sizeof(g_oversize), 0x77u);
    expect_i("resource",
        12u,
        "max sender init",
        init_session(&g_tx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = ninlil_r7_frag_sess_tx_begin(&g_tx,
        g_oversize,
        NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX,
        transfer_id,
        frame,
        sizeof(frame),
        &frame_len,
        &frag_index);
    expect_i(
        "resource", 12u, "payload max accepted", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64(
        "resource", 12u, "canonical max count", g_tx.tx.plan.frag_count, 12u);
    expect_i("resource",
        0u,
        "max plus one sender init",
        init_session(&g_tx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = ninlil_r7_frag_sess_tx_begin(&g_tx,
        g_oversize,
        sizeof(g_oversize),
        transfer_id,
        frame,
        sizeof(frame),
        &frame_len,
        &frag_index);
    expect_i("resource",
        0u,
        "payload max plus one rejected",
        st,
        NINLIL_R7_FRAG_SESS_STRUCT);
    g_fault_scenarios++;
}

static void test_receiver_timer_boundary_and_tombstone_expiry(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    ninlil_r7_frag_state_tombstone *tomb;
    uint8_t payload[50];
    uint8_t transfer_id[16];
    uint8_t frame[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    size_t frame_len = 0u;
    uint64_t expiry = 0u;
    int32_t st;

    fill_bytes(payload, sizeof(payload), 0x81u);
    fill_transfer_id(transfer_id, 0x82u);
    expect_i("timer-tomb",
        2u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = seal_manual_start(payload,
        sizeof(payload),
        (uint16_t)(sizeof(payload) - 1u),
        2u,
        transfer_id,
        1u,
        1u,
        1u,
        frame,
        &frame_len);
    expect_i("timer-tomb", 2u, "seal START", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, frame, frame_len, &intent);
    expect_i(
        "timer-tomb", 2u, "receive START", st, NINLIL_R7_FRAG_SESS_OK);
    st = ninlil_r7_frag_sess_tick(
        &g_rx, 1000u + NINLIL_R7_FRAG_STATE_IDLE_TIMEOUT_MS - 1u);
    expect_i(
        "timer-tomb", 2u, "idle boundary minus one", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64(
        "timer-tomb", 2u, "owner live before boundary", active_reassembly_count(&g_rx), 1u);
    st = ninlil_r7_frag_sess_tick(
        &g_rx, 1000u + NINLIL_R7_FRAG_STATE_IDLE_TIMEOUT_MS);
    expect_i(
        "timer-tomb", 2u, "idle exact boundary", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64(
        "timer-tomb", 2u, "owner expired at boundary", active_reassembly_count(&g_rx), 0u);
    tomb = first_terminal_tomb(&g_rx);
    expect_true("timer-tomb",
        2u,
        "timeout tombstone",
        tomb != NULL && tomb->reason == NINLIL_R7_FRAG_STATE_REASON_TIMEOUT);
    if (tomb != NULL) {
        expiry = tomb->expiry_mono;
    }
    expect_u64("timer-tomb",
        2u,
        "exact tomb expiry",
        expiry,
        1000u + NINLIL_R7_FRAG_STATE_IDLE_TIMEOUT_MS
            + NINLIL_R7_FRAG_STATE_TOMBSTONE_TTL_MS);
    st = ninlil_r7_frag_sess_tick(&g_rx, expiry - 1u);
    expect_i(
        "timer-tomb", 2u, "tomb boundary minus one", st, NINLIL_R7_FRAG_SESS_OK);
    st = seal_manual_start(payload,
        sizeof(payload),
        (uint16_t)(sizeof(payload) - 1u),
        2u,
        transfer_id,
        1u,
        2u,
        2u,
        frame,
        &frame_len);
    expect_i("timer-tomb", 2u, "seal exact retry", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, frame, frame_len, &intent);
    expect_i("timer-tomb",
        2u,
        "terminal exact retry",
        st,
        NINLIL_R7_FRAG_SESS_OK);
    expect_true("timer-tomb",
        2u,
        "stored timeout intent",
        intent.valid && intent.status == NINLIL_R7_FRAG_STATE_STATUS_ABORT
            && intent.reason == NINLIL_R7_FRAG_STATE_REASON_TIMEOUT);
    tomb = first_terminal_tomb(&g_rx);
    expect_true("timer-tomb",
        2u,
        "exact retry does not extend TTL",
        tomb != NULL && tomb->expiry_mono == expiry);
    st = ninlil_r7_frag_sess_tick(&g_rx, expiry);
    expect_i(
        "timer-tomb", 2u, "tomb exact expiry", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64(
        "timer-tomb", 2u, "tomb removed", live_tombstone_count(&g_rx), 0u);
    st = seal_manual_start(payload,
        sizeof(payload),
        (uint16_t)(sizeof(payload) - 1u),
        2u,
        transfer_id,
        1u,
        3u,
        3u,
        frame,
        &frame_len);
    expect_i(
        "timer-tomb", 2u, "seal post-expiry START", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(&g_rx, frame, frame_len, &intent);
    expect_i("timer-tomb",
        2u,
        "late START may be new",
        st,
        NINLIL_R7_FRAG_SESS_OK);
    expect_u64(
        "timer-tomb", 2u, "new owner after expiry", active_reassembly_count(&g_rx), 1u);
    g_fault_scenarios += 2u;
}

static void test_restart_discards_volatile_then_retransfers(void)
{
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t fresh_start[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    uint8_t fresh_cont1[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    uint8_t fresh_cont2[NINLIL_R7_FRAG_SESS_FRAME_MAX];
    uint8_t transfer_id[16];
    size_t fresh_start_len = 0u;
    size_t fresh_cont1_len = 0u;
    size_t fresh_cont2_len = 0u;
    size_t snapshot_len = 0u;
    size_t publication_len = 0u;
    int32_t st;

    memset(&g_wire, 0, sizeof(g_wire));
    fill_bytes(g_wire.payload, 307u, 0x91u);
    expect_i("restart",
        3u,
        "tx init",
        init_session(&g_tx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    expect_i("restart",
        3u,
        "rx init",
        init_session(&g_rx, 1000u, 0u),
        NINLIL_R7_FRAG_SESS_OK);
    st = build_canonical_wire_set(&g_wire, 307u, 0x92u);
    expect_i("restart", 3u, "wire build", st, NINLIL_R7_FRAG_SESS_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx, g_wire.frames[0], g_wire.frame_lens[0], &intent);
    expect_i("restart", 3u, "START", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64(
        "restart", 3u, "active before restart", active_reassembly_count(&g_rx), 1u);
    st = ninlil_r7_frag_sess_restart_encode(
        &g_rx, g_snapshot, sizeof(g_snapshot), &snapshot_len);
    expect_i(
        "restart", 3u, "snapshot encode", st, NINLIL_R7_FRAG_SESS_OK);
    st = ninlil_r7_frag_sess_restart_decode(&g_rx_restart,
        &g_provider,
        &g_keys,
        g_snapshot,
        snapshot_len);
    expect_i(
        "restart", 3u, "snapshot decode", st, NINLIL_R7_FRAG_SESS_OK);
    expect_u64("restart",
        3u,
        "volatile reassembly discarded",
        active_reassembly_count(&g_rx_restart),
        0u);
    expect_u64("restart",
        3u,
        "volatile tombstones discarded",
        live_tombstone_count(&g_rx_restart),
        0u);
    st = ninlil_r7_frag_sess_take_publication(&g_rx_restart,
        g_publication,
        sizeof(g_publication),
        &publication_len);
    expect_i(
        "restart", 3u, "no manufactured publication", st, NINLIL_R7_FRAG_SESS_NO_PUB);

    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx_restart, g_wire.frames[1], g_wire.frame_lens[1], &intent);
    expect_i("restart",
        3u,
        "old reserved-window CONT replay",
        st,
        NINLIL_R7_FRAG_SESS_REPLAY);
    /*
     * Restart advances both durable RX boot floors through the previously
     * reserved 64-counter window.  A valid retransmission therefore uses
     * fresh counters above that floor while retaining the transfer handle.
     */
    fill_transfer_id(transfer_id, 0x92u);
    st = seal_manual_start(
        g_wire.payload,
        g_wire.total_len,
        g_wire.first_chunk_len,
        g_wire.frag_count,
        transfer_id,
        g_tx.tx.transfer_handle,
        65u,
        65u,
        fresh_start,
        &fresh_start_len);
    expect_i(
        "restart", 3u, "fresh START seal", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx_restart, fresh_start, fresh_start_len, &intent);
    expect_i(
        "restart", 3u, "fresh START accepted", st, NINLIL_R7_FRAG_SESS_OK);
    st = seal_manual_cont(
        g_tx.tx.transfer_handle,
        1u,
        g_wire.payload + g_tx.tx.plan.chunks[1].offset,
        g_tx.tx.plan.chunks[1].length,
        66u,
        66u,
        fresh_cont1,
        &fresh_cont1_len);
    expect_i(
        "restart", 3u, "fresh CONT1 seal", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx_restart, fresh_cont1, fresh_cont1_len, &intent);
    expect_i(
        "restart", 3u, "fresh CONT1 accepted", st, NINLIL_R7_FRAG_SESS_OK);
    st = seal_manual_cont(
        g_tx.tx.transfer_handle,
        2u,
        g_wire.payload + g_tx.tx.plan.chunks[2].offset,
        g_tx.tx.plan.chunks[2].length,
        67u,
        67u,
        fresh_cont2,
        &fresh_cont2_len);
    expect_i(
        "restart", 3u, "fresh CONT2 seal", st, NINLIL_R7_FRAG_OK);
    memset(&intent, 0, sizeof(intent));
    st = receive_frame(
        &g_rx_restart, fresh_cont2, fresh_cont2_len, &intent);
    expect_i(
        "restart", 3u, "fresh CONT2 accepted", st, NINLIL_R7_FRAG_SESS_OK);
    expect_publication_once(
        "restart", 3u, &g_rx_restart, g_wire.payload, g_wire.total_len);
    g_fault_scenarios++;
}

static uint32_t fuzz_next(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint32_t fuzz_total_len(uint16_t frag_count, uint32_t *state)
{
    uint32_t lower;
    uint32_t upper;
    if (frag_count == 13u) {
        return 2048u;
    }
    lower = 127u + 180u * (uint32_t)(frag_count - 2u);
    upper = lower + 179u;
    if (upper > NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX) {
        upper = NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX;
    }
    return lower + fuzz_next(state) % (upper - lower + 1u);
}

static void test_deterministic_fuzz_corpus(void)
{
    uint32_t rng = MATRIX_FUZZ_SEED;
    uint16_t round;
    uint16_t frag_count;

    for (round = 0u; round < MATRIX_FUZZ_ROUNDS; round++) {
        for (frag_count = 2u; frag_count <= 13u; frag_count++) {
            ninlil_r7_frag_state_ack_intent intent;
            uint16_t order[NINLIL_R7_FRAG_SESS_MAX_FRAGS - 1u];
            uint16_t ncont = (uint16_t)(frag_count - 1u);
            uint32_t total_len = fuzz_total_len(frag_count, &rng);
            uint16_t i;
            int32_t st;

            memset(&g_wire, 0, sizeof(g_wire));
            fill_bytes(
                g_wire.payload, total_len, (uint8_t)fuzz_next(&rng));
            expect_i("fuzz",
                frag_count,
                "rx init",
                init_session(&g_rx, 5000u + round, 0u),
                NINLIL_R7_FRAG_SESS_OK);
            if (frag_count == 13u) {
                st = build_manual_wire_set(&g_wire,
                    frag_count,
                    total_len,
                    1u,
                    (uint8_t)fuzz_next(&rng),
                    1u);
                expect_i(
                    "fuzz", frag_count, "manual build", st, NINLIL_R7_FRAG_OK);
            } else {
                expect_i("fuzz",
                    frag_count,
                    "tx init",
                    init_session(&g_tx, 5000u + round, 0u),
                    NINLIL_R7_FRAG_SESS_OK);
                st = build_canonical_wire_set(
                    &g_wire, total_len, (uint8_t)fuzz_next(&rng));
                expect_i("fuzz",
                    frag_count,
                    "canonical build",
                    st,
                    NINLIL_R7_FRAG_SESS_OK);
            }
            if (st != NINLIL_R7_FRAG_SESS_OK && st != NINLIL_R7_FRAG_OK) {
                continue;
            }
            expect_u64(
                "fuzz", frag_count, "generated count", g_wire.frag_count, frag_count);
            for (i = 0u; i < ncont; i++) {
                order[i] = (uint16_t)(i + 1u);
            }
            for (i = ncont; i > 1u; i--) {
                uint16_t j = (uint16_t)(fuzz_next(&rng) % i);
                uint16_t tmp = order[i - 1u];
                order[i - 1u] = order[j];
                order[j] = tmp;
            }
            memset(&intent, 0, sizeof(intent));
            st = receive_frame(
                &g_rx, g_wire.frames[0], g_wire.frame_lens[0], &intent);
            expect_i("fuzz",
                frag_count,
                "START",
                st,
                NINLIL_R7_FRAG_SESS_OK);
            for (i = 0u; i < ncont; i++) {
                uint16_t index = order[i];
                memset(&intent, 0, sizeof(intent));
                st = receive_frame(&g_rx,
                    g_wire.frames[index],
                    g_wire.frame_lens[index],
                    &intent);
                expect_i("fuzz",
                    frag_count,
                    "permuted CONT",
                    st,
                    NINLIL_R7_FRAG_SESS_OK);
            }
            expect_publication_once(
                "fuzz", frag_count, &g_rx, g_wire.payload, g_wire.total_len);
            g_fuzz_cases++;
        }
    }
}

int main(void)
{
    int32_t crypto_st;
    init_keys();
    crypto_st = ninlil_r7_crypto_openssl3_provider_init(&g_provider);
    expect_i(
        "setup", 0u, "OpenSSL provider", crypto_st, NINLIL_R7_CRYPTO_OK);
    if (crypto_st == NINLIL_R7_CRYPTO_OK) {
        test_lifecycle_rows_2_through_13();
        test_loss_retry_and_sender_timer_boundary();
        test_reverse_reorder();
        test_identical_and_conflicting_duplicate();
        test_missing_start_then_fresh_e2e_recovery();
        test_resource_max_and_plus_one();
        test_receiver_timer_boundary_and_tombstone_expiry();
        test_restart_discards_volatile_then_retransfers();
        test_deterministic_fuzz_corpus();
    }
    ninlil_r7_frag_sess_zeroize(&g_tx);
    ninlil_r7_frag_sess_zeroize(&g_rx);
    ninlil_r7_frag_sess_zeroize(&g_rx_restart);
    if (g_fail != 0) {
        fprintf(stderr,
            "r7_frag_lifecycle_matrix_test: FAIL checks=%u failures=%d "
            "rows=%u faults=%u fuzz=%u seed=0x%08x\n",
            (unsigned)g_checks,
            g_fail,
            (unsigned)g_lifecycle_rows,
            (unsigned)g_fault_scenarios,
            (unsigned)g_fuzz_cases,
            (unsigned)MATRIX_FUZZ_SEED);
        return 1;
    }
    printf("r7_frag_lifecycle_matrix_test: OK checks=%u rows=%u faults=%u "
           "fuzz=%u seed=0x%08x\n",
        (unsigned)g_checks,
        (unsigned)g_lifecycle_rows,
        (unsigned)g_fault_scenarios,
        (unsigned)g_fuzz_cases,
        (unsigned)MATRIX_FUZZ_SEED);
    return 0;
}
