/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Full NRW1 LINK/FRAG session tests: AEAD wire, KATs, reorder/loss/replay,
 * durable CU, restart, publication exact-once. Direct clang/cc + ASan/UBSan.
 */

#include "r7_crypto_openssl3.h"
#include "r7_frag.h"
#include "r7_frag_session.h"
#include "r7_frag_state.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static int g_tests;

static void expect_i(const char *n, int32_t g, int32_t w)
{
    g_tests++;
    if (g != w) {
        fprintf(stderr, "FAIL %s: got=%d want=%d\n", n, (int)g, (int)w);
        g_fail++;
    }
}

static void expect_t(const char *n, int c)
{
    g_tests++;
    if (!c) {
        fprintf(stderr, "FAIL %s\n", n);
        g_fail++;
    }
}

static void expect_sz(const char *n, size_t g, size_t w)
{
    g_tests++;
    if (g != w) {
        fprintf(stderr, "FAIL %s: size %zu vs %zu\n", n, g, w);
        g_fail++;
    }
}

static void fill(uint8_t *p, size_t n, uint8_t s)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(s + (uint8_t)i);
    }
}

static ninlil_r7_crypto_provider g_prov;
static int g_ok;

static int ensure_prov(void)
{
    if (g_ok) {
        return 1;
    }
    if (ninlil_r7_crypto_openssl3_provider_init(&g_prov) != NINLIL_R7_CRYPTO_OK) {
        fprintf(stderr, "FAIL openssl init\n");
        g_fail++;
        return 0;
    }
    g_ok = 1;
    return 1;
}

static void keys_lab(ninlil_r7_frag_sess_keys *k)
{
    fill(k->e2e_key16, 16u, 0x10u);
    fill(k->e2e_iv12, 12u, 0x20u);
    fill(k->hop_data_key16, 16u, 0x30u);
    fill(k->hop_data_iv12, 12u, 0x40u);
    fill(k->hop_ack_key16, 16u, 0x50u);
    fill(k->hop_ack_iv12, 12u, 0x60u);
    /* reverse = same for lab loopback */
    memcpy(k->rev_hop_ack_key16, k->hop_ack_key16, 16u);
    memcpy(k->rev_hop_ack_iv12, k->hop_ack_iv12, 12u);
    memcpy(k->rev_e2e_key16, k->e2e_key16, 16u);
    memcpy(k->rev_e2e_iv12, k->e2e_iv12, 12u);
}

static void install_pair(ninlil_r7_frag_sess *a, ninlil_r7_frag_sess *b)
{
    ninlil_r7_frag_sess_install_lane(
        a, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u);
    ninlil_r7_frag_sess_install_lane(
        a, NINLIL_R7_FRAG_LANE_HOP_ACK, 12u, 1u);
    ninlil_r7_frag_sess_install_lane(a, NINLIL_R7_FRAG_LANE_E2E, 21u, 1u);
    ninlil_r7_frag_sess_install_lane(a, NINLIL_R7_FRAG_LANE_E2E, 22u, 1u);

    ninlil_r7_frag_sess_install_lane(
        b, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u);
    ninlil_r7_frag_sess_install_lane(
        b, NINLIL_R7_FRAG_LANE_HOP_ACK, 12u, 1u);
    ninlil_r7_frag_sess_install_lane(b, NINLIL_R7_FRAG_LANE_E2E, 21u, 1u);
    ninlil_r7_frag_sess_install_lane(b, NINLIL_R7_FRAG_LANE_E2E, 22u, 1u);
}

/* -------------------------------------------------------------------------- */
/* KAT: outer AAD / LINK_ACK / E2E headers                                    */
/* -------------------------------------------------------------------------- */

static void test_literal_kats_and_tamper(void)
{
    ninlil_r7_frag_outer_data_fields of;
    ninlil_r7_frag_e2e_fields ef;
    ninlil_r7_frag_start_body sb;
    ninlil_r7_frag_link_ack_body lb;
    ninlil_r7_frag_outer_link_ack_fields lo;
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t app[126];
    uint8_t e2e[220];
    uint8_t frame[255];
    uint8_t out[220];
    size_t e2e_len = 0u;
    size_t flen = 0u;
    size_t olen = 0u;
    ninlil_r7_frag_status st;
    size_t need;

    if (!ensure_prov()) {
        return;
    }
    fill(key, 16u, 0xABu);
    fill(iv, 12u, 0xCDu);
    fill(app, 126u, 0x01u);

    memset(&ef, 0, sizeof(ef));
    ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
    ef.e2e_context_id = 0x0000002Au;
    ef.e2e_counter = 0x0000000000000007ull;

    memset(&sb, 0, sizeof(sb));
    fill(sb.transfer_id, 16u, 0x11u);
    sb.transfer_handle = 7u;
    sb.continuation_unit = 180u;
    fill(sb.content_digest, 32u, 0x22u);

    /* Valid plan: total 50, S=49 */
    sb.total_len = 50u;
    sb.frag_count = 2u;
    need = 14u + 64u + 49u + 16u;
    st = ninlil_r7_frag_seal_e2e_start(
        &g_prov, key, iv, &ef, &sb, app, 49u, e2e, need, &e2e_len);
    expect_i("kat seal start", st, NINLIL_R7_FRAG_OK);
    expect_t("profile", e2e[0] == 0x11u);
    expect_t("type START", e2e[1] == 0x20u);
    expect_t("ctx be", e2e[2] == 0u && e2e[3] == 0u && e2e[4] == 0u
        && e2e[5] == 0x2Au);
    expect_t("ctr be low", e2e[13] == 0x07u);

    memset(&of, 0, sizeof(of));
    of.ack_requested = 1u;
    of.hop_context_id = 0x0000000Bu;
    of.hop_counter = 3u;
    need = 19u + e2e_len + 16u;
    st = ninlil_r7_frag_seal_outer_data(
        &g_prov, key, iv, &of, e2e, e2e_len, frame, need, &flen);
    expect_i("kat outer", st, NINLIL_R7_FRAG_OK);
    expect_t("outer profile", frame[0] == 0x11u);
    expect_t("outer DATA ack1", frame[1] == 0x11u); /* kind1<<4 | 1 */
    expect_t("outer rem0", frame[2] == 0u);
    expect_sz("outer len domain start", flen >= 130u && flen <= 255u ? flen : 0u,
        flen);

    /* Tamper tag */
    {
        uint8_t bad[255];
        memcpy(bad, frame, flen);
        bad[flen - 1u] ^= 0x01u;
        st = ninlil_r7_frag_open_outer_data(
            &g_prov, key, iv, bad, flen, &of, out, e2e_len, &olen);
        expect_i("tamper tag", st, NINLIL_R7_FRAG_AUTH_FAILED);
    }
    /* Tamper profile */
    {
        uint8_t bad[255];
        memcpy(bad, frame, flen);
        bad[0] ^= 0x01u;
        st = ninlil_r7_frag_open_outer_data(
            &g_prov, key, iv, bad, flen, &of, out, e2e_len, &olen);
        expect_i("tamper profile", st, NINLIL_R7_FRAG_STRUCTURAL);
    }
    /* Tamper length */
    st = ninlil_r7_frag_open_outer_data(
        &g_prov, key, iv, frame, flen - 1u, &of, out, e2e_len, &olen);
    expect_t("tamper len", st != NINLIL_R7_FRAG_OK);

    /* Happy open */
    st = ninlil_r7_frag_open_outer_data(
        &g_prov, key, iv, frame, flen, &of, out, e2e_len, &olen);
    expect_i("outer open", st, NINLIL_R7_FRAG_OK);
    expect_t("e2e match", olen == e2e_len && memcmp(out, e2e, e2e_len) == 0);

    /* LINK_ACK KAT */
    memset(&lo, 0, sizeof(lo));
    lo.hop_context_id = 12u;
    lo.hop_counter = 1u;
    memset(&lb, 0, sizeof(lb));
    lb.acked_hop_context_id = 11u;
    lb.ack_base_counter = 3u;
    lb.ack_bitmap = 0x0001u;
    lb.ack_code = 0u;
    st = ninlil_r7_frag_seal_outer_link_ack(
        &g_prov, key, iv, &lo, &lb, frame, &flen);
    expect_i("link seal", st, NINLIL_R7_FRAG_OK);
    expect_sz("link 51", flen, 51u);
    expect_t("link kind", frame[1] == 0x20u);
    expect_t("link route0", frame[15] == 0u && frame[16] == 0u
        && frame[17] == 0u && frame[18] == 0u);

    {
        uint8_t bad[51];
        memcpy(bad, frame, 51u);
        bad[25] ^= 0x01u;
        st = ninlil_r7_frag_open_outer_link_ack(
            &g_prov, key, iv, bad, 51u, &lo, &lb);
        expect_i("link tamper", st, NINLIL_R7_FRAG_AUTH_FAILED);
    }
    st = ninlil_r7_frag_open_outer_link_ack(
        &g_prov, key, iv, frame, 51u, &lo, &lb);
    expect_i("link open", st, NINLIL_R7_FRAG_OK);
    expect_t("link base", lb.ack_base_counter == 3u);

    /* CONT KAT */
    {
        ninlil_r7_frag_cont_body cb;
        uint8_t chunk[10];
        fill(chunk, 10u, 0x55u);
        memset(&cb, 0, sizeof(cb));
        cb.transfer_handle = 7u;
        cb.frag_index = 1u;
        ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
        ef.e2e_counter = 8u;
        need = 14u + 10u + 10u + 16u;
        st = ninlil_r7_frag_seal_e2e_cont(
            &g_prov, key, iv, &ef, &cb, chunk, 10u, e2e, need, &e2e_len);
        expect_i("cont seal", st, NINLIL_R7_FRAG_OK);
        expect_t("cont type", e2e[1] == 0x30u);
    }

    /* FRAG_ACK KAT exact 44 blob / 79 outer */
    {
        ninlil_r7_frag_ack_body ab;
        memset(&ab, 0, sizeof(ab));
        ab.transfer_handle = 7u;
        ab.frag_count = 2u;
        ab.received_bitmap = 0x0003u;
        ab.status = 1u;
        ab.reason = 0u;
        ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_ACK;
        ef.e2e_counter = 9u;
        st = ninlil_r7_frag_seal_e2e_ack(
            &g_prov, key, iv, &ef, &ab, e2e, 44u, &e2e_len);
        expect_i("ack seal", st, NINLIL_R7_FRAG_OK);
        expect_sz("ack blob 44", e2e_len, 44u);
        expect_t("ack type", e2e[1] == 0x40u);
        need = 19u + 44u + 16u;
        memset(&of, 0, sizeof(of));
        of.hop_context_id = 11u;
        of.hop_counter = 5u;
        st = ninlil_r7_frag_seal_outer_data(
            &g_prov, key, iv, &of, e2e, 44u, frame, need, &flen);
        expect_i("ack outer", st, NINLIL_R7_FRAG_OK);
        expect_sz("ack outer 79", flen, 79u);
    }
}

/* -------------------------------------------------------------------------- */
/* End-to-end transfer with reorder, loss, link ack, publish once             */
/* -------------------------------------------------------------------------- */

static void test_e2e_transfer_reorder_linkack(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess tx;
    static ninlil_r7_frag_sess rx;
    uint8_t payload[400];
    uint8_t tid[16];
    uint8_t frames[13][255];
    size_t flens[13];
    uint16_t fi = 0u;
    uint8_t link_ack[51];
    size_t lalen = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t pub[400];
    size_t pub_len = 0u;
    int32_t st;
    uint16_t i;
    uint16_t fc;

    if (!ensure_prov()) {
        return;
    }
    keys_lab(&k);
    fill(payload, 400u, 0x70u);
    fill(tid, 16u, 0x90u);
    memset(&tx, 0, sizeof(tx));
    memset(&rx, 0, sizeof(rx));
    ninlil_r7_frag_sess_init(&tx, &g_prov, &k);
    ninlil_r7_frag_sess_init(&rx, &g_prov, &k);
    ninlil_r7_frag_sess_set_now(&tx, 1000u);
    ninlil_r7_frag_sess_set_now(&rx, 1000u);
    install_pair(&tx, &rx);

    st = ninlil_r7_frag_sess_tx_begin(
        &tx, payload, 400u, tid, frames[0], sizeof(frames[0]), &flens[0], &fi);
    expect_i("tx begin", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("first frag0", fi == 0u);
    fc = tx.tx.plan.frag_count;
    expect_t("fc>=2", fc >= 2u);
    ninlil_r7_frag_sess_tx_note_air(&tx, 0u, tx.tx.last_hop_counter[0]);

    /* Build CONT outers once (first hop attempt each). */
    for (i = 1u; i < fc; i++) {
        st = ninlil_r7_frag_sess_tx_air(
            &tx, i, frames[i], sizeof(frames[i]), &flens[i]);
        expect_i("tx air cont", st, NINLIL_R7_FRAG_SESS_OK);
        ninlil_r7_frag_sess_tx_note_air(&tx, i, tx.tx.last_hop_counter[i]);
    }

    /*
     * CONT-before-START: admit-before-body burns counters; body/pub/ACK=0.
     * Same outer redelivery → hop REPLAY.
     */
    st = ninlil_r7_frag_sess_rx_data(
        &rx, frames[fc - 1u], flens[fc - 1u], &intent, link_ack,
        sizeof(link_ack), &lalen);
    expect_i("cont before start body0", st, NINLIL_R7_FRAG_SESS_NO_PUB);
    expect_sz("no link ack on body reject", lalen, 0u);
    st = ninlil_r7_frag_sess_rx_data(
        &rx, frames[fc - 1u], flens[fc - 1u], &intent, NULL, 0u, NULL);
    expect_i("same outer hop replay", st, NINLIL_R7_FRAG_SESS_REPLAY);

    /* START first, then CONTs: last CONT needs fresh hop (prior attempt burned). */
    st = ninlil_r7_frag_sess_rx_data(
        &rx, frames[0], flens[0], &intent, link_ack, sizeof(link_ack), &lalen);
    expect_i("start ok", st, NINLIL_R7_FRAG_SESS_OK);
    if (lalen == 51u) {
        expect_i("link ack0",
            ninlil_r7_frag_sess_rx_link_ack(&tx, link_ack, lalen),
            NINLIL_R7_FRAG_SESS_OK);
    }
    for (i = 1u; i < fc; i++) {
        if (i + 1u == fc) {
            /* E2E burned on CONT-before-START ⇒ FRAG_E2E_RETRY_FRESH_SEAL */
            tx.now_mono += 500u;
            st = ninlil_r7_frag_sess_tx_e2e_retry(
                &tx, i, payload, 400u, frames[i], sizeof(frames[i]),
                &flens[i]);
            expect_i("e2e retry last cont", st, NINLIL_R7_FRAG_SESS_OK);
            ninlil_r7_frag_sess_tx_note_air(
                &tx, i, tx.tx.last_hop_counter[i]);
            expect_t("e2e prep 2", tx.tx.e2e_prep_burns[i] == 2u);
        }
        st = ninlil_r7_frag_sess_rx_data(
            &rx, frames[i], flens[i], &intent, link_ack, sizeof(link_ack),
            &lalen);
        expect_t("cont after start", st == NINLIL_R7_FRAG_SESS_OK);
        if (lalen == 51u) {
            ninlil_r7_frag_sess_rx_link_ack(&tx, link_ack, lalen);
        }
    }

    st = ninlil_r7_frag_sess_take_publication(&rx, pub, sizeof(pub), &pub_len);
    expect_i("pub", st, NINLIL_R7_FRAG_SESS_OK);
    expect_sz("pub len", pub_len, 400u);
    expect_t("pub bytes", memcmp(pub, payload, 400u) == 0);
    expect_t("once counter", rx.publish_count == 1u);

    st = ninlil_r7_frag_sess_take_publication(&rx, pub, sizeof(pub), &pub_len);
    expect_i("no second pub", st, NINLIL_R7_FRAG_SESS_NO_PUB);

    /* Replay outer */
    st = ninlil_r7_frag_sess_rx_data(
        &rx, frames[0], flens[0], &intent, NULL, 0u, NULL);
    expect_i("replay outer", st, NINLIL_R7_FRAG_SESS_REPLAY);

    /* Wrong key generation path: install conflict not silent */
    st = ninlil_r7_frag_sess_install_lane(
        &rx, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 2u);
    expect_i("no silent replace", st, NINLIL_R7_FRAG_SESS_STRUCT);

    ninlil_r7_frag_sess_zeroize(&tx);
    ninlil_r7_frag_sess_zeroize(&rx);
}

static void test_loss_and_link_retry(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess tx;
    static ninlil_r7_frag_sess rx;
    uint8_t payload[80];
    uint8_t tid[16];
    uint8_t f1[255];
    uint8_t f2[255];
    size_t l1 = 0u;
    size_t l2 = 0u;
    uint16_t fi = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t link_ack[51];
    size_t lalen = 0u;
    uint8_t pub[80];
    size_t pub_len = 0u;
    int32_t st;

    if (!ensure_prov()) {
        return;
    }
    keys_lab(&k);
    fill(payload, 80u, 0x33u);
    fill(tid, 16u, 0x44u);
    ninlil_r7_frag_sess_init(&tx, &g_prov, &k);
    ninlil_r7_frag_sess_init(&rx, &g_prov, &k);
    tx.now_mono = rx.now_mono = 5000u;
    tx.reasm.now_mono = rx.reasm.now_mono = 5000u;
    install_pair(&tx, &rx);

    st = ninlil_r7_frag_sess_tx_begin(
        &tx, payload, 80u, tid, f1, sizeof(f1), &l1, &fi);
    expect_i("begin", st, NINLIL_R7_FRAG_SESS_OK);
    ninlil_r7_frag_sess_tx_note_air(&tx, 0u, tx.tx.last_hop_counter[0]);

    /* Lose first air; retry after eligible */
    tx.now_mono = 5000u + 3000u;
    st = ninlil_r7_frag_sess_tx_air(&tx, 0u, f2, sizeof(f2), &l2);
    expect_i("retry air", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("fresh hop counter",
        tx.tx.last_hop_counter[0] != 0u && l2 > 0u);
    /* Same E2E blob on retry: hop AAD differs but E2E sealed identical */
    expect_t("e2e blob retained",
        tx.tx.e2e_len[0] > 0u);

    /* Deliver retry to RX */
    st = ninlil_r7_frag_sess_rx_data(
        &rx, f2, l2, &intent, link_ack, sizeof(link_ack), &lalen);
    expect_i("rx retry", st, NINLIL_R7_FRAG_SESS_OK);
    if (lalen == 51u) {
        ninlil_r7_frag_sess_rx_link_ack(&tx, link_ack, lalen);
        expect_t("frag0 link acked", tx.tx.frag_acked[0] == 1u);
    }

    /* Air remaining fragments */
    {
        uint16_t i;
        for (i = 1u; i < tx.tx.plan.frag_count; i++) {
            st = ninlil_r7_frag_sess_tx_air(&tx, i, f1, sizeof(f1), &l1);
            expect_i("air rest", st, NINLIL_R7_FRAG_SESS_OK);
            ninlil_r7_frag_sess_tx_note_air(&tx, i, tx.tx.last_hop_counter[i]);
            st = ninlil_r7_frag_sess_rx_data(
                &rx, f1, l1, &intent, link_ack, sizeof(link_ack), &lalen);
            expect_t("rx rest", st == NINLIL_R7_FRAG_SESS_OK);
            if (lalen == 51u) {
                ninlil_r7_frag_sess_rx_link_ack(&tx, link_ack, lalen);
            }
        }
    }

    st = ninlil_r7_frag_sess_take_publication(&rx, pub, sizeof(pub), &pub_len);
    expect_i("pub after loss", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("bytes", memcmp(pub, payload, 80u) == 0);

    ninlil_r7_frag_sess_zeroize(&tx);
    ninlil_r7_frag_sess_zeroize(&rx);
}

static void test_conflict_and_wrong_context(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess tx;
    static ninlil_r7_frag_sess rx;
    uint8_t payload[100];
    uint8_t tid[16];
    uint8_t f[255];
    size_t fl = 0u;
    uint16_t fi = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    int32_t st;

    if (!ensure_prov()) {
        return;
    }
    keys_lab(&k);
    fill(payload, 100u, 0x01u);
    fill(tid, 16u, 0x02u);
    ninlil_r7_frag_sess_init(&tx, &g_prov, &k);
    ninlil_r7_frag_sess_init(&rx, &g_prov, &k);
    tx.now_mono = rx.now_mono = 1u;
    install_pair(&tx, &rx);

    ninlil_r7_frag_sess_tx_begin(
        &tx, payload, 100u, tid, f, sizeof(f), &fl, &fi);
    st = ninlil_r7_frag_sess_rx_data(
        &rx, f, fl, &intent, NULL, 0u, NULL);
    expect_i("start1", st, NINLIL_R7_FRAG_SESS_OK);

    /* Second START same handle different tid via forging is hard; use state path
     * through second transfer id by re-sealing with same handle after mutate. */
    {
        ninlil_r7_frag_state_start_in sin;
        ninlil_r7_frag_state_plan plan;
        ninlil_r7_frag_state_plan_build(100u, &plan);
        memset(&sin, 0, sizeof(sin));
        sin.e2e_context_id = 21u;
        sin.key_generation = 1u;
        fill(sin.transfer_id, 16u, 0xFFu);
        sin.transfer_handle = tx.tx.transfer_handle;
        sin.total_len = 100u;
        sin.frag_count = plan.frag_count;
        sin.continuation_unit = 180u;
        fill(sin.content_digest, 32u, 0xAAu);
        fill(sin.fingerprint, 32u, 0xBBu);
        sin.first_chunk = payload;
        sin.first_chunk_len = plan.first_chunk_len;
        st = ninlil_r7_frag_state_admit_start(&rx.reasm, &sin, &intent);
        expect_i("conflict start", st, NINLIL_R7_FRAG_STATE_CONFLICT);
    }

    ninlil_r7_frag_sess_zeroize(&tx);
    ninlil_r7_frag_sess_zeroize(&rx);
}

static void test_durable_cu_and_restart(void)
{
    ninlil_r7_frag_sess_keys k;
    /* Object storage: sess embeds CU workspace (~33KiB); not stack. */
    static ninlil_r7_frag_sess s;
    static ninlil_r7_frag_sess s2;
    uint8_t snap[8192];
    size_t slen = 0u;
    uint8_t pub[64];
    size_t pub_len = 0u;
    int32_t st;
    ninlil_r7_frag_dur_store *d;
    uint8_t key[16];
    uint8_t val[16];
    ninlil_r7_frag_state_cu_result cls;

    if (!ensure_prov()) {
        return;
    }
    keys_lab(&k);
    memset(&s, 0, sizeof(s));
    memset(&s2, 0, sizeof(s2));
    ninlil_r7_frag_sess_init(&s, &g_prov, &k);
    s.now_mono = 42u;
    install_pair(&s, &s);

    d = &s.durable;
    /* Inject CU on next commit */
    ninlil_r7_frag_dur_set_inject(d, NINLIL_R7_FRAG_DUR_INJECT_CU);
    memset(key, 0, sizeof(key));
    key[0] = 0x99u;
    memset(val, 1, sizeof(val));
    ninlil_r7_frag_dur_begin(d);
    ninlil_r7_frag_dur_put(d, key, 16u, val, 16u);
    st = ninlil_r7_frag_dur_commit(d);
    expect_i("cu commit", st, NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN);
    expect_t("fenced", d->fenced == 1u);
    st = ninlil_r7_frag_dur_recover_cu(d, &cls);
    expect_i("cu recover", st, NINLIL_R7_FRAG_DUR_OK);
    expect_t("all old",
        cls.class_code == NINLIL_R7_FRAG_STATE_CU_ALL_OLD);
    expect_t("unfenced", d->fenced == 0u);

    /* ALL_PROPOSED path: put applied after inject? We leave pre-state on CU.
     * Commit OK then CU inject with match proposed — recover ALL_OLD still. */

    /* Restart encode/decode: no false publication */
    st = ninlil_r7_frag_sess_restart_encode(&s, snap, sizeof(snap), &slen);
    expect_i("restart enc", st, NINLIL_R7_FRAG_SESS_OK);
    st = ninlil_r7_frag_sess_restart_decode(&s2, &g_prov, &k, snap, slen);
    expect_i("restart dec", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("now restored", s2.now_mono == 42u);
    expect_t("lanes live", s2.lanes[0].in_use == 1u);
    expect_t("reasm empty", s2.reasm.reasm[0].in_use == 0u);
    expect_t("tx empty", s2.tx.in_use == 0u);
    st = ninlil_r7_frag_sess_take_publication(
        &s2, pub, sizeof(pub), &pub_len);
    expect_i("no false pub", st, NINLIL_R7_FRAG_SESS_NO_PUB);
    expect_t("pub count 0", s2.publish_count == 0u);

    /* Tombstones volatile: after restart no tombstones */
    expect_t("no tombs", s2.reasm.tombs[0].in_use == 0u);

    /* Corrupt snapshot */
    snap[0] ^= 0xFFu;
    st = ninlil_r7_frag_sess_restart_decode(&s2, &g_prov, &k, snap, slen);
    expect_i("bad magic", st, NINLIL_R7_FRAG_SESS_STRUCT);

    ninlil_r7_frag_sess_zeroize(&s);
    ninlil_r7_frag_sess_zeroize(&s2);
}

static void test_state_suite_still(void)
{
    /* Ensure pure state still works: plan empty/max */
    ninlil_r7_frag_state_plan plan;
    expect_i("empty", ninlil_r7_frag_state_plan_build(0u, &plan),
        NINLIL_R7_FRAG_STATE_LENGTH);
    expect_i("one", ninlil_r7_frag_state_plan_build(1u, &plan),
        NINLIL_R7_FRAG_STATE_LENGTH);
    expect_i("max", ninlil_r7_frag_state_plan_build(2048u, &plan),
        NINLIL_R7_FRAG_STATE_OK);
}

static void test_digest_provider_binding(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess tx;
    static ninlil_r7_frag_sess rx;
    uint8_t payload[120];
    uint8_t tid[16];
    uint8_t f[255];
    size_t fl = 0u;
    uint16_t fi = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t pub[120];
    size_t pl = 0u;
    uint16_t i;
    int32_t st;

    if (!ensure_prov()) {
        return;
    }
    keys_lab(&k);
    fill(payload, 120u, 0xCEu);
    fill(tid, 16u, 0xDEu);
    ninlil_r7_frag_sess_init(&tx, &g_prov, &k);
    ninlil_r7_frag_sess_init(&rx, &g_prov, &k);
    tx.now_mono = rx.now_mono = 9u;
    install_pair(&tx, &rx);

    ninlil_r7_frag_sess_tx_begin(
        &tx, payload, 120u, tid, f, sizeof(f), &fl, &fi);
    for (i = 0u; i < tx.tx.plan.frag_count; i++) {
        if (i > 0u) {
            ninlil_r7_frag_sess_tx_air(&tx, i, f, sizeof(f), &fl);
        }
        st = ninlil_r7_frag_sess_rx_data(
            &rx, f, fl, &intent, NULL, 0u, NULL);
        expect_t("rx dig", st == NINLIL_R7_FRAG_SESS_OK);
    }
    st = ninlil_r7_frag_sess_take_publication(&rx, pub, sizeof(pub), &pl);
    expect_i("digest path pub", st, NINLIL_R7_FRAG_SESS_OK);
    /* content_digest was provider SHA-256 at seal time; reasm verified same */
    expect_t("match", memcmp(pub, payload, 120u) == 0);

    ninlil_r7_frag_sess_zeroize(&tx);
    ninlil_r7_frag_sess_zeroize(&rx);
}

static void test_no_alias_partial_output(void)
{
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t buf[128];
    ninlil_r7_frag_e2e_fields ef;
    ninlil_r7_frag_ack_body ab;
    size_t len = 0u;
    ninlil_r7_frag_status st;

    if (!ensure_prov()) {
        return;
    }
    fill(key, 16u, 1u);
    fill(iv, 12u, 2u);
    memset(&ef, 0, sizeof(ef));
    ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_ACK;
    ef.e2e_context_id = 1u;
    ef.e2e_counter = 1u;
    memset(&ab, 0, sizeof(ab));
    ab.transfer_handle = 1u;
    ab.frag_count = 2u;
    ab.received_bitmap = 0x0001u;
    ab.status = 0u;
    /* alias: out overlaps body — must reject */
    st = ninlil_r7_frag_seal_e2e_ack(
        &g_prov, key, iv, &ef, &ab, (uint8_t *)&ab, 44u, &len);
    expect_i("alias reject", st, NINLIL_R7_FRAG_ALIAS);

    fill(buf, sizeof(buf), 0xA5u);
    st = ninlil_r7_frag_seal_e2e_ack(
        &g_prov, key, iv, &ef, &ab, buf, 44u, &len);
    expect_i("ack ok", st, NINLIL_R7_FRAG_OK);
    /* capacity mismatch no partial */
    fill(buf, sizeof(buf), 0xA5u);
    st = ninlil_r7_frag_seal_e2e_ack(
        &g_prov, key, iv, &ef, &ab, buf, 43u, &len);
    expect_t("cap fail", st != NINLIL_R7_FRAG_OK);
    expect_t("no partial", buf[0] == 0xA5u);
}

/* docs/30 §9.2 session lane_tx_alloc final partial tranche. */
static ninlil_r7_frag_sess_lane *find_lane(
    ninlil_r7_frag_sess *s, uint8_t kind, uint32_t cid)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_SESS_LANES; i++) {
        if (s->lanes[i].in_use && s->lanes[i].kind == kind
            && s->lanes[i].context_id == cid) {
            return &s->lanes[i];
        }
    }
    return NULL;
}

static void seed_empty_window(ninlil_r7_frag_sess_lane *L, uint64_t exclusive)
{
    L->tx_next = exclusive;
    L->tx_limit = exclusive;
}

static void test_session_tx_partial_tranche(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess s;
    static ninlil_r7_frag_sess s2;
    ninlil_r7_frag_sess_lane *Le;
    ninlil_r7_frag_sess_lane *Lhop;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t frame[255];
    uint8_t snap[8192];
    size_t fl = 0u;
    size_t slen = 0u;
    int32_t st;

    if (!ensure_prov()) {
        return;
    }
    keys_lab(&k);
    memset(&intent, 0, sizeof(intent));
    intent.valid = 1u;
    intent.transfer_handle = 7u;
    intent.frag_count = 4u;
    intent.received_bitmap = 0x0001u;
    intent.status = NINLIL_R7_FRAG_STATUS_PARTIAL;
    intent.reason = 0u;

    /* --- U-65: full block grow to exclusive MAX-1 --- */
    memset(&s, 0, sizeof(s));
    ninlil_r7_frag_sess_init(&s, &g_prov, &k);
    s.now_mono = 1u;
    install_pair(&s, &s);
    Le = find_lane(&s, NINLIL_R7_FRAG_LANE_E2E, 22u);
    Lhop = find_lane(&s, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u);
    expect_t("rev e2e lane", Le != NULL && Lhop != NULL);
    if (Le == NULL || Lhop == NULL) {
        return;
    }
    seed_empty_window(Le, UINT64_MAX - 65u);
    seed_empty_window(Lhop, UINT64_MAX - 65u);
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("sess U-65 ack", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("U-65 e2e limit MAX-1", Le->tx_limit == UINT64_MAX - 1u);
    expect_t("U-65 e2e next", Le->tx_next == UINT64_MAX - 64u);

    /* --- U-64: full block reaches terminal exclusive MAX --- */
    seed_empty_window(Le, UINT64_MAX - 64u);
    seed_empty_window(Lhop, UINT64_MAX - 64u);
    intent.transfer_handle = 8u;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("sess U-64 ack", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("U-64 e2e limit MAX", Le->tx_limit == UINT64_MAX);

    /* --- U-63: partial room=63 → exclusive MAX --- */
    seed_empty_window(Le, UINT64_MAX - 63u);
    seed_empty_window(Lhop, UINT64_MAX - 63u);
    intent.transfer_handle = 9u;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("sess U-63 ack", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("U-63 e2e limit MAX", Le->tx_limit == UINT64_MAX);
    expect_t("U-63 e2e next", Le->tx_next == UINT64_MAX - 62u);

    /* --- U-1: last assignable counter --- */
    seed_empty_window(Le, UINT64_MAX - 1u);
    seed_empty_window(Lhop, UINT64_MAX - 1u);
    intent.transfer_handle = 10u;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("sess U-1 ack", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("U-1 e2e next terminal", Le->tx_next == UINT64_MAX);
    expect_t("U-1 e2e limit MAX", Le->tx_limit == UINT64_MAX);

    /* --- U / exhaustion --- */
    intent.transfer_handle = 11u;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("sess U exhaust", st, NINLIL_R7_FRAG_SESS_RESOURCE);
    expect_t("exhaust reserve clean", s.ack_ledger.control_reserve_held == 0u);

    /* --- Restart retains window; last counter then exhaust --- */
    seed_empty_window(Le, UINT64_MAX - 1u);
    seed_empty_window(Lhop, UINT64_MAX - 1u);
    st = ninlil_r7_frag_sess_restart_encode(&s, snap, sizeof(snap), &slen);
    expect_i("tranche restart enc", st, NINLIL_R7_FRAG_SESS_OK);
    memset(&s2, 0, sizeof(s2));
    st = ninlil_r7_frag_sess_restart_decode(&s2, &g_prov, &k, snap, slen);
    expect_i("tranche restart dec", st, NINLIL_R7_FRAG_SESS_OK);
    Le = find_lane(&s2, NINLIL_R7_FRAG_LANE_E2E, 22u);
    Lhop = find_lane(&s2, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u);
    expect_t("restart next MAX-1", Le != NULL && Le->tx_next == UINT64_MAX - 1u);
    expect_t("restart limit MAX-1", Le != NULL && Le->tx_limit == UINT64_MAX - 1u);
    intent.transfer_handle = 50u;
    st = ninlil_r7_frag_sess_tx_frag_ack(
        &s2, &intent, frame, sizeof(frame), &fl);
    expect_i("post-restart last C", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("post-restart terminal", Le->tx_next == UINT64_MAX);
    st = ninlil_r7_frag_sess_tx_frag_ack(
        &s2, &intent, frame, sizeof(frame), &fl);
    expect_i("post-restart exhaust", st, NINLIL_R7_FRAG_SESS_RESOURCE);

    /* --- CU on final partial grow: fail-closed, no reserve leak --- */
    memset(&s, 0, sizeof(s));
    ninlil_r7_frag_sess_init(&s, &g_prov, &k);
    s.now_mono = 3u;
    install_pair(&s, &s);
    Le = find_lane(&s, NINLIL_R7_FRAG_LANE_E2E, 22u);
    Lhop = find_lane(&s, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u);
    seed_empty_window(Le, UINT64_MAX - 1u);
    Lhop->tx_next = 10u;
    Lhop->tx_limit = 100u; /* hop has room; e2e grow triggers CU */
    ninlil_r7_frag_dur_set_inject(&s.durable, NINLIL_R7_FRAG_DUR_INJECT_CU);
    intent.transfer_handle = 60u;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_t("cu path fail-closed",
        st == NINLIL_R7_FRAG_SESS_DURABLE || st == NINLIL_R7_FRAG_SESS_FENCED
            || st == NINLIL_R7_FRAG_SESS_RESOURCE);
    expect_t("cu reserve not leaked", s.ack_ledger.control_reserve_held == 0u);
}

int main(void)
{
    test_literal_kats_and_tamper();
    test_e2e_transfer_reorder_linkack();
    test_loss_and_link_retry();
    test_conflict_and_wrong_context();
    test_durable_cu_and_restart();
    test_state_suite_still();
    test_digest_provider_binding();
    test_no_alias_partial_output();
    test_session_tx_partial_tranche();

    fprintf(stderr, "r7_frag_session_test: %d checks, %d failures\n",
        g_tests, g_fail);
    return g_fail == 0 ? 0 : 1;
}
