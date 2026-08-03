/*
 * FRAG_ACK identity-keyed ledger tests (docs/30 §15.3.7).
 * same identity max2, different identity, sequential transfers,
 * expiry recovery, reserve release no leak.
 */

#include "r7_frag_ack_ledger.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static int g_n;

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

static void id_set(
    ninlil_r7_frag_ack_identity_t *id,
    uint64_t th,
    uint16_t fc,
    uint16_t bm,
    uint8_t st,
    uint8_t rs)
{
    ninlil_r7_frag_ack_identity_from_body(id, th, fc, bm, st, rs);
}

static void test_same_identity_max2(void)
{
    ninlil_r7_frag_ack_ledger_t led;
    ninlil_r7_frag_ack_identity_t id;
    int i;

    ninlil_r7_frag_ack_ledger_init(&led);
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 7u, 2u, 100000u);
    id_set(&id, 7u, 2u, 0x0001u, 0u, 0u);
    for (i = 0; i < 2; i++) {
        expect_i("reserve", ninlil_r7_frag_ack_ledger_reserve_acquire(&led),
            NINLIL_R7_FRAG_ACK_LEDGER_OK);
        expect_i("charge",
            ninlil_r7_frag_ack_ledger_charge_burn(&led, &id, 10u + (uint64_t)i),
            NINLIL_R7_FRAG_ACK_LEDGER_OK);
        ninlil_r7_frag_ack_ledger_reserve_release(&led);
    }
    expect_t("burns_used 2",
        ninlil_r7_frag_ack_ledger_burns_used(&led, &id) == 2u);
    expect_i("reserve for 3rd", ninlil_r7_frag_ack_ledger_reserve_acquire(&led),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_i("3rd charge RESOURCE",
        ninlil_r7_frag_ack_ledger_charge_burn(&led, &id, 20u),
        NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE);
    ninlil_r7_frag_ack_ledger_reserve_release(&led);
    expect_t("reserve released", led.control_reserve_held == 0u);
}

static void test_different_identity_independent(void)
{
    ninlil_r7_frag_ack_ledger_t led;
    ninlil_r7_frag_ack_identity_t a;
    ninlil_r7_frag_ack_identity_t b;

    ninlil_r7_frag_ack_ledger_init(&led);
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 7u, 4u, 100000u);
    id_set(&a, 7u, 4u, 0x0001u, 0u, 0u);
    id_set(&b, 7u, 4u, 0x0003u, 0u, 0u); /* different bitmap = different identity */
    expect_i("a1", ninlil_r7_frag_ack_ledger_charge_burn(&led, &a, 1u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_i("a2", ninlil_r7_frag_ack_ledger_charge_burn(&led, &a, 2u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_i("a3 block", ninlil_r7_frag_ack_ledger_charge_burn(&led, &a, 3u),
        NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE);
    /* b is new identity: burns start at 0 */
    expect_i("b1", ninlil_r7_frag_ack_ledger_charge_burn(&led, &b, 4u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_t("a still 2", ninlil_r7_frag_ack_ledger_burns_used(&led, &a) == 2u);
    expect_t("b is 1", ninlil_r7_frag_ack_ledger_burns_used(&led, &b) == 1u);
    expect_t("agg 3", ninlil_r7_frag_ack_ledger_aggregate_burns(&led, 7u) == 3u);
}

static void test_sequential_transfers(void)
{
    ninlil_r7_frag_ack_ledger_t led;
    ninlil_r7_frag_ack_identity_t a;
    ninlil_r7_frag_ack_identity_t b;

    ninlil_r7_frag_ack_ledger_init(&led);
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 10u, 2u, 100000u);
    id_set(&a, 10u, 2u, 0x0003u, 1u, 0u);
    expect_i("t10 a1", ninlil_r7_frag_ack_ledger_charge_burn(&led, &a, 1u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_i("t10 a2", ninlil_r7_frag_ack_ledger_charge_burn(&led, &a, 2u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    /* New transfer handle: independent aggregate + identity */
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 11u, 2u, 100000u);
    id_set(&b, 11u, 2u, 0x0003u, 1u, 0u);
    expect_i("t11 b1", ninlil_r7_frag_ack_ledger_charge_burn(&led, &b, 3u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_t("t10 still 2", ninlil_r7_frag_ack_ledger_burns_used(&led, &a) == 2u);
    expect_t("t11 is 1", ninlil_r7_frag_ack_ledger_burns_used(&led, &b) == 1u);
    expect_t("agg10", ninlil_r7_frag_ack_ledger_aggregate_burns(&led, 10u) == 2u);
    expect_t("agg11", ninlil_r7_frag_ack_ledger_aggregate_burns(&led, 11u) == 1u);
}

static void test_aggregate_cap(void)
{
    ninlil_r7_frag_ack_ledger_t led;
    ninlil_r7_frag_ack_identity_t id;
    uint16_t i;
    uint16_t lim;

    ninlil_r7_frag_ack_ledger_init(&led);
    /* frag_count=2 ⇒ aggregate max 4 */
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 1u, 2u, 100000u);
    lim = ninlil_r7_frag_ack_ledger_aggregate_limit(2u);
    expect_t("lim 4", lim == 4u);
    for (i = 0u; i < 4u; i++) {
        /* distinct identities via bitmap/status to avoid max2 per id */
        id_set(&id, 1u, 2u, (uint16_t)(1u << (i % 2u)), (uint8_t)(i & 1u),
            (uint8_t)i);
        expect_i("agg charge",
            ninlil_r7_frag_ack_ledger_charge_burn(&led, &id, 10u + i),
            NINLIL_R7_FRAG_ACK_LEDGER_OK);
    }
    id_set(&id, 1u, 2u, 0x0002u, 2u, 9u);
    expect_i("agg full", ninlil_r7_frag_ack_ledger_charge_burn(&led, &id, 99u),
        NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE);
}

static void test_expiry_and_restart(void)
{
    ninlil_r7_frag_ack_ledger_t led;
    ninlil_r7_frag_ack_identity_t id;

    ninlil_r7_frag_ack_ledger_init(&led);
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 5u, 2u, 50u);
    id_set(&id, 5u, 2u, 0x0001u, 0u, 0u);
    expect_i("pre exp charge",
        ninlil_r7_frag_ack_ledger_charge_burn(&led, &id, 10u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    expect_t("used1", ninlil_r7_frag_ack_ledger_burns_used(&led, &id) == 1u);
    ninlil_r7_frag_ack_ledger_tick(&led, 50u);
    expect_t("expired row gone",
        ninlil_r7_frag_ack_ledger_burns_used(&led, &id) == 0u);
    /* After expiry, new burns allowed with fresh bind */
    ninlil_r7_frag_ack_ledger_bind_owner(&led, 5u, 2u, 200u);
    expect_i("post exp charge",
        ninlil_r7_frag_ack_ledger_charge_burn(&led, &id, 60u),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    ninlil_r7_frag_ack_ledger_discard_all(&led);
    expect_t("discard burns0",
        ninlil_r7_frag_ack_ledger_burns_used(&led, &id) == 0u);
    expect_t("discard reserve0", led.control_reserve_held == 0u);
}

static void test_reserve_no_leak(void)
{
    ninlil_r7_frag_ack_ledger_t led;
    int i;

    ninlil_r7_frag_ack_ledger_init(&led);
    for (i = 0; i < (int)NINLIL_R7_FRAG_CONTROL_ACK_RESERVE; i++) {
        expect_i("acq", ninlil_r7_frag_ack_ledger_reserve_acquire(&led),
            NINLIL_R7_FRAG_ACK_LEDGER_OK);
    }
    expect_i("full", ninlil_r7_frag_ack_ledger_reserve_acquire(&led),
        NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE);
    for (i = 0; i < (int)NINLIL_R7_FRAG_CONTROL_ACK_RESERVE; i++) {
        ninlil_r7_frag_ack_ledger_reserve_release(&led);
    }
    expect_t("held0", led.control_reserve_held == 0u);
    expect_i("acq after release",
        ninlil_r7_frag_ack_ledger_reserve_acquire(&led),
        NINLIL_R7_FRAG_ACK_LEDGER_OK);
    ninlil_r7_frag_ack_ledger_reserve_release(&led);
    expect_t("final0", led.control_reserve_held == 0u);
}

int main(void)
{
    test_same_identity_max2();
    test_different_identity_independent();
    test_sequential_transfers();
    test_aggregate_cap();
    test_expiry_and_restart();
    test_reserve_no_leak();
    fprintf(stderr, "r7_frag_ack_ledger_test: %d checks, %d fails\n", g_n,
        g_fail);
    return g_fail == 0 ? 0 : 1;
}
