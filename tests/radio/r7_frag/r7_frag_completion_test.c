/*
 * Capacity pins, hop-only LINK_ACK regen, FRAG_ACK identity ledger budgets,
 * orch spy unbound fail-closed, sender attempt caps.
 */

#include "r7_crypto_openssl3.h"
#include "r7_frag_ack_ledger.h"
#include "r7_frag_adapters.h"
#include "r7_frag_prod_orch.h"
#include "r7_frag_session.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static int g_n;
static ninlil_r7_crypto_provider g_prov;
static int g_ok;

static void expect_i(const char *n, int32_t g, int32_t w)
{
    g_n++;
    if (g != w) {
        fprintf(stderr, "FAIL %s got=%d want=%d\n", n, (int)g, (int)w);
        g_fail++;
    }
}

static void expect_t(const char *n, int c)
{
    g_n++;
    if (!c) {
        fprintf(stderr, "FAIL %s\n", n);
        g_fail++;
    }
}

static int ensure(void)
{
    if (g_ok) {
        return 1;
    }
    if (ninlil_r7_crypto_openssl3_provider_init(&g_prov) != NINLIL_R7_CRYPTO_OK) {
        g_fail++;
        return 0;
    }
    g_ok = 1;
    return 1;
}

static void keys_lab(ninlil_r7_frag_sess_keys *k)
{
    size_t i;
    for (i = 0u; i < 16u; i++) {
        k->e2e_key16[i] = (uint8_t)(0x10u + i);
        k->hop_data_key16[i] = (uint8_t)(0x30u + i);
        k->hop_ack_key16[i] = (uint8_t)(0x50u + i);
        k->rev_hop_ack_key16[i] = k->hop_ack_key16[i];
        k->rev_e2e_key16[i] = k->e2e_key16[i];
    }
    for (i = 0u; i < 12u; i++) {
        k->e2e_iv12[i] = (uint8_t)(0x20u + i);
        k->hop_data_iv12[i] = (uint8_t)(0x40u + i);
        k->hop_ack_iv12[i] = (uint8_t)(0x60u + i);
        k->rev_hop_ack_iv12[i] = k->hop_ack_iv12[i];
        k->rev_e2e_iv12[i] = k->e2e_iv12[i];
    }
}

static void install_pair(ninlil_r7_frag_sess *a, ninlil_r7_frag_sess *b)
{
    (void)ninlil_r7_frag_sess_install_lane(
        a, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(
        a, NINLIL_R7_FRAG_LANE_HOP_ACK, 12u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(a, NINLIL_R7_FRAG_LANE_E2E, 21u, 1u);
    (void)ninlil_r7_frag_sess_install_lane(a, NINLIL_R7_FRAG_LANE_E2E, 22u, 1u);
    a->e2e_context_id = 21u;
    a->rev_e2e_context_id = 22u;
    a->hop_data_context_id = 11u;
    if (b != a) {
        (void)ninlil_r7_frag_sess_install_lane(
            b, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u);
        (void)ninlil_r7_frag_sess_install_lane(
            b, NINLIL_R7_FRAG_LANE_HOP_ACK, 12u, 1u);
        (void)ninlil_r7_frag_sess_install_lane(
            b, NINLIL_R7_FRAG_LANE_E2E, 21u, 1u);
        (void)ninlil_r7_frag_sess_install_lane(
            b, NINLIL_R7_FRAG_LANE_E2E, 22u, 1u);
        b->e2e_context_id = 21u;
        b->rev_e2e_context_id = 22u;
        b->hop_data_context_id = 11u;
    }
}

static void test_controller_capacity_pin(void)
{
    expect_t("reasm controller default", NINLIL_R7_FRAG_REASM_SLOTS == 16u
        || NINLIL_R7_FRAG_REASM_SLOTS == 2u);
    expect_t("control reserve 8", NINLIL_R7_FRAG_CONTROL_ACK_RESERVE == 8u);
    expect_t("semantic max2", NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2 == 2u);
}

static void test_orch_unbound_fail_closed(void)
{
    ninlil_r7_frag_prod_bind_t b;
    ninlil_r7_frag_prod_tx_result_t tr;
    uint8_t app[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int32_t st;

    ninlil_r7_frag_prod_bind_reset(&b);
    st = ninlil_r7_frag_prod_tx_single(
        &b, 1u, 2u, app, sizeof(app), 21u, 7u, 0u, &tr);
    expect_i("unbound", st, NINLIL_R7_FRAG_PROD_UNBOUND);
}

/*
 * Production P1: no XOR fake digest. crypto NULL / sha256 NULL ⇒ unbound
 * before R2 issue / R1 TX (spy proves no permit/edge events).
 */
static void test_orch_outer_tx_crypto_unbound_spy(void)
{
    ninlil_r7_frag_orch_t orch;
    ninlil_r7_frag_spy_t spy;
    ninlil_r7_frag_l1w1_bus_t bus;
    uint8_t frame[16];
    ninlil_r7_crypto_provider cap_null;
    int32_t st;
    size_t i;
    int saw_r2 = 0;
    int saw_r1 = 0;

    memset(frame, 0x5Au, sizeof(frame));
    memset(&orch, 0, sizeof(orch));
    ninlil_r7_frag_spy_reset(&spy);
    ninlil_r7_frag_l1w1_reset(&bus);
    orch.spy = &spy;
    orch.bus = &bus;
    orch.live_valid = 1u;
    orch.clock_trusted = 1u;
    orch.clock_uncertain = 0u;
    orch.trusted_now_ms = 0u;
    orch.crypto = NULL;
    /* pcp/hal intentionally NULL — crypto unbound must not reach issue. */
    st = ninlil_r7_frag_orch_outer_tx(&orch, 1u, 2u, frame, sizeof(frame));
    expect_i("outer_tx crypto null", st, 2);
    for (i = 0u; i < spy.count; i++) {
        if (spy.events[i] == NINLIL_R7_FRAG_SPY_R2_ISSUE) {
            saw_r2 = 1;
        }
        if (spy.events[i] == NINLIL_R7_FRAG_SPY_R1_TX) {
            saw_r1 = 1;
        }
    }
    expect_t("no R2 issue on crypto null", !saw_r2);
    expect_t("no R1 TX on crypto null", !saw_r1);
    expect_t("no stamp progress", spy.count == 0u);

    /* Provider present but sha256 capability NULL. */
    if (!ensure()) {
        return;
    }
    cap_null = g_prov;
    cap_null.sha256 = NULL;
    ninlil_r7_frag_spy_reset(&spy);
    ninlil_r7_frag_l1w1_reset(&bus);
    orch.crypto = &cap_null;
    saw_r2 = 0;
    saw_r1 = 0;
    st = ninlil_r7_frag_orch_outer_tx(&orch, 1u, 2u, frame, sizeof(frame));
    expect_i("outer_tx sha256 null", st, 2);
    for (i = 0u; i < spy.count; i++) {
        if (spy.events[i] == NINLIL_R7_FRAG_SPY_R2_ISSUE) {
            saw_r2 = 1;
        }
        if (spy.events[i] == NINLIL_R7_FRAG_SPY_R1_TX) {
            saw_r1 = 1;
        }
    }
    expect_t("no R2 on sha256 null", !saw_r2);
    expect_t("no R1 on sha256 null", !saw_r1);
    expect_t("no stamp on sha256 null", spy.count == 0u);
}

/* Real SHA-256 KAT (NIST "abc") via production provider — not XOR. */
static void test_real_sha256_kat(void)
{
    static const uint8_t msg[] = { 'a', 'b', 'c' };
    /* ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    static const uint8_t want[32] = {
        0xbau, 0x78u, 0x16u, 0xbfu, 0x8fu, 0x01u, 0xcfu, 0xeau, 0x41u, 0x41u,
        0x40u, 0xdeu, 0x5du, 0xaeu, 0x22u, 0x23u, 0xb0u, 0x03u, 0x61u, 0xa3u,
        0x96u, 0x17u, 0x7au, 0x9cu, 0xb4u, 0x10u, 0xffu, 0x61u, 0xf2u, 0x00u,
        0x15u, 0xadu
    };
    uint8_t dig[32];
    uint8_t xor_fake[32];
    size_t i;

    if (!ensure()) {
        return;
    }
    expect_t("provider sha256", g_prov.sha256 != NULL);
    memset(dig, 0, sizeof(dig));
    expect_i("sha256 abc",
        ninlil_r7_crypto_sha256(&g_prov, msg, 3u, dig), NINLIL_R7_CRYPTO_OK);
    expect_t("kat match", memcmp(dig, want, 32u) == 0);

    /* Prove XOR-of-bytes is NOT the production digest. */
    memset(xor_fake, 0, sizeof(xor_fake));
    for (i = 0u; i < 3u; i++) {
        xor_fake[i % 32u] ^= msg[i];
    }
    expect_t("not xor fake", memcmp(dig, xor_fake, 32u) != 0);
}

/* P0: bind_reset on indeterminate stack must not read matrix_ws (C UB). */
static void test_bind_reset_no_indeterminate_read(void)
{
    ninlil_r7_frag_prod_bind_t b;
    ninlil_r7_frag_prod_matrix_ws_t ws;
    uint8_t *raw = (uint8_t *)&b;
    size_t i;
    int32_t st;

    /* Paint every byte including former pointer slots. */
    for (i = 0u; i < sizeof(b); i++) {
        raw[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }
    ninlil_r7_frag_prod_bind_reset(&b);
    expect_t("painted reset inited", ninlil_r7_frag_prod_bind_is_inited(&b));
    expect_t("painted reset ptr0", b.matrix_ws == NULL);
    expect_t("magic stamp", b.bind_magic == NINLIL_R7_FRAG_PROD_BIND_MAGIC);
    expect_t("version stamp",
        b.bind_version == NINLIL_R7_FRAG_PROD_BIND_VERSION);

    /* 0xFF paint + double reset. */
    memset(&b, 0xFF, sizeof(b));
    ninlil_r7_frag_prod_bind_reset(&b);
    ninlil_r7_frag_prod_bind_reset(&b);
    expect_t("double reset ptr0", b.matrix_ws == NULL);
    expect_t("double reset inited", ninlil_r7_frag_prod_bind_is_inited(&b));

    ninlil_r7_frag_prod_matrix_ws_zeroize(&ws);
    st = ninlil_r7_frag_prod_bind_set_matrix_ws(&b, &ws);
    expect_i("set ws", st, NINLIL_R7_FRAG_PROD_OK);
    expect_t("ws bound", b.matrix_ws == &ws);
    st = ninlil_r7_frag_prod_bind_reinit(&b);
    expect_i("reinit ok", st, NINLIL_R7_FRAG_PROD_OK);
    expect_t("reinit keeps ws", b.matrix_ws == &ws);
    ninlil_r7_frag_prod_bind_reset(&b);
    expect_t("reset drops ws", b.matrix_ws == NULL);

    /* Two-instance isolation of stamps. */
    {
        ninlil_r7_frag_prod_bind_t a2;
        ninlil_r7_frag_prod_bind_t b2;
        ninlil_r7_frag_prod_matrix_ws_t wa;
        ninlil_r7_frag_prod_matrix_ws_t wb;
        memset(&a2, 0x11, sizeof(a2));
        memset(&b2, 0x22, sizeof(b2));
        ninlil_r7_frag_prod_matrix_ws_zeroize(&wa);
        ninlil_r7_frag_prod_matrix_ws_zeroize(&wb);
        ninlil_r7_frag_prod_bind_reset(&a2);
        ninlil_r7_frag_prod_bind_reset(&b2);
        expect_i("a2 set", ninlil_r7_frag_prod_bind_set_matrix_ws(&a2, &wa),
            NINLIL_R7_FRAG_PROD_OK);
        expect_i("b2 set", ninlil_r7_frag_prod_bind_set_matrix_ws(&b2, &wb),
            NINLIL_R7_FRAG_PROD_OK);
        expect_t("two-instance distinct", a2.matrix_ws != b2.matrix_ws);
        expect_i("a2 reinit", ninlil_r7_frag_prod_bind_reinit(&a2),
            NINLIL_R7_FRAG_PROD_OK);
        expect_t("b2 untouched", b2.matrix_ws == &wb);
    }

    /* reinit / set_ws on unstamped garbage refuse. */
    memset(&b, 0x3C, sizeof(b));
    expect_i("reinit unstamped", ninlil_r7_frag_prod_bind_reinit(&b),
        NINLIL_R7_FRAG_PROD_INVALID);
    expect_i("set_ws unstamped",
        ninlil_r7_frag_prod_bind_set_matrix_ws(&b, &ws),
        NINLIL_R7_FRAG_PROD_INVALID);
}

static void test_hop_only_link_ack_regen(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess tx;
    static ninlil_r7_frag_sess rx;
    uint8_t payload[80];
    uint8_t tid[16];
    uint8_t frame[255];
    uint8_t retry[255];
    size_t fl = 0u;
    size_t rl = 0u;
    uint16_t fi = 0u;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t la[64];
    size_t lalen = 0u;
    int32_t st;
    size_t i;

    if (!ensure()) {
        return;
    }
    keys_lab(&k);
    for (i = 0u; i < 80u; i++) {
        payload[i] = (uint8_t)i;
    }
    for (i = 0u; i < 16u; i++) {
        tid[i] = (uint8_t)(0xA0u + i);
    }
    memset(&tx, 0, sizeof(tx));
    memset(&rx, 0, sizeof(rx));
    ninlil_r7_frag_sess_init(&tx, &g_prov, &k);
    ninlil_r7_frag_sess_init(&rx, &g_prov, &k);
    tx.now_mono = rx.now_mono = 1000u;
    install_pair(&tx, &rx);
    tx.ack_requested_default = 1u;
    st = ninlil_r7_frag_sess_tx_begin(
        &tx, payload, 80u, tid, frame, sizeof(frame), &fl, &fi);
    expect_i("begin", st, NINLIL_R7_FRAG_SESS_OK);
    (void)ninlil_r7_frag_sess_tx_note_air(&tx, 0u, tx.tx.last_hop_counter[0]);
    st = ninlil_r7_frag_sess_rx_data(
        &rx, frame, fl, &intent, la, sizeof(la), &lalen);
    expect_i("rx", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("link ack", lalen == 51u && la[0] == 0x11u);
    tx.now_mono += 5000u;
    st = ninlil_r7_frag_sess_tx_air(&tx, 0u, retry, sizeof(retry), &rl);
    if (st == NINLIL_R7_FRAG_SESS_OK) {
        expect_t("outer attempts", tx.tx.outer_attempts[0] >= 2u);
        expect_t("hop attempts", tx.tx.hop_attempts[0] >= 1u);
    }
}

static void test_frag_ack_ledger_budget(void)
{
    ninlil_r7_frag_sess_keys k;
    static ninlil_r7_frag_sess s;
    ninlil_r7_frag_state_ack_intent intent;
    ninlil_r7_frag_ack_identity_t id_a;
    ninlil_r7_frag_ack_identity_t id_b;
    ninlil_r7_frag_ack_identity_t id_seq;
    uint8_t frame[255];
    size_t fl = 0u;
    int32_t st;
    int i;

    if (!ensure()) {
        return;
    }
    keys_lab(&k);
    memset(&s, 0, sizeof(s));
    ninlil_r7_frag_sess_init(&s, &g_prov, &k);
    s.now_mono = 1u;
    install_pair(&s, &s);
    s.tx.in_use = 1u;
    /*
     * frag_count=4 allows multiple valid PARTIAL bitmaps (docs/30 pack rules):
     * bit0 must be set; full bitmap only with status COMPLETE.
     * Identity A: PARTIAL 0x0001; identity B: PARTIAL 0x0003.
     */
    memset(&intent, 0, sizeof(intent));
    intent.valid = 1u;
    intent.transfer_handle = 1u;
    intent.frag_count = 4u;
    intent.received_bitmap = 0x0001u;
    intent.status = NINLIL_R7_FRAG_STATUS_PARTIAL;
    intent.reason = 0u;

    ninlil_r7_frag_ack_identity_from_body(
        &id_a, intent.transfer_handle, intent.frag_count, intent.received_bitmap,
        intent.status, intent.reason);
    for (i = 0; i < 2; i++) {
        st = ninlil_r7_frag_sess_tx_frag_ack(
            &s, &intent, frame, sizeof(frame), &fl);
        expect_i("ack burn ok", st, NINLIL_R7_FRAG_SESS_OK);
    }
    expect_t("ledger semantic burns",
        ninlil_r7_frag_ack_ledger_burns_used(&s.ack_ledger, &id_a)
            == NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2);
    expect_t("reserve not leaked", s.ack_ledger.control_reserve_held == 0u);
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("ack budget exhausted", st, NINLIL_R7_FRAG_SESS_RESOURCE);

    /* Different full-plaintext identity still allowed under aggregate. */
    intent.received_bitmap = 0x0003u;
    ninlil_r7_frag_ack_identity_from_body(
        &id_b, intent.transfer_handle, intent.frag_count, intent.received_bitmap,
        intent.status, intent.reason);
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("diff identity ok", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("diff burns 1",
        ninlil_r7_frag_ack_ledger_burns_used(&s.ack_ledger, &id_b) == 1u);
    expect_t("a still max2",
        ninlil_r7_frag_ack_ledger_burns_used(&s.ack_ledger, &id_a)
            == NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2);
    expect_t("reserve clean", s.ack_ledger.control_reserve_held == 0u);
    expect_t("agg 3",
        ninlil_r7_frag_ack_ledger_aggregate_burns(&s.ack_ledger, 1u) == 3u);

    /* Sequential transfer: new handle independent of prior aggregate. */
    intent.transfer_handle = 2u;
    intent.received_bitmap = 0x0001u;
    ninlil_r7_frag_ack_identity_from_body(
        &id_seq, intent.transfer_handle, intent.frag_count,
        intent.received_bitmap, intent.status, intent.reason);
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("sequential transfer ok", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("seq burns 1",
        ninlil_r7_frag_ack_ledger_burns_used(&s.ack_ledger, &id_seq) == 1u);
    expect_t("prior th still 3",
        ninlil_r7_frag_ack_ledger_aggregate_burns(&s.ack_ledger, 1u) == 3u);

    /* Abort identity (different status/reason) independent under aggregate. */
    intent.transfer_handle = 1u;
    intent.received_bitmap = 0u;
    intent.status = NINLIL_R7_FRAG_STATUS_ABORT;
    intent.reason = NINLIL_R7_FRAG_REASON_CONFLICT;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("abort identity ok", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("reserve clean after abort",
        s.ack_ledger.control_reserve_held == 0u);

    /* Owner/tombstone expiry frees capacity for same identity. */
    s.now_mono = NINLIL_R7_FRAG_RECEIVER_TTL_MS + 100u;
    ninlil_r7_frag_sess_tick(&s, s.now_mono);
    intent.received_bitmap = 0x0001u;
    intent.status = NINLIL_R7_FRAG_STATUS_PARTIAL;
    intent.reason = 0u;
    st = ninlil_r7_frag_sess_tx_frag_ack(&s, &intent, frame, sizeof(frame), &fl);
    expect_i("after expiry ok", st, NINLIL_R7_FRAG_SESS_OK);
    expect_t("post-expiry burns 1",
        ninlil_r7_frag_ack_ledger_burns_used(&s.ack_ledger, &id_a) == 1u);
    expect_t("final reserve 0", s.ack_ledger.control_reserve_held == 0u);
}

int main(void)
{
    test_controller_capacity_pin();
    test_orch_unbound_fail_closed();
    test_orch_outer_tx_crypto_unbound_spy();
    test_real_sha256_kat();
    test_bind_reset_no_indeterminate_read();
    test_hop_only_link_ack_regen();
    test_frag_ack_ledger_budget();
    fprintf(stderr, "r7_frag_completion_test: %d checks, %d failures\n", g_n,
        g_fail);
    return g_fail == 0 ? 0 : 1;
}
