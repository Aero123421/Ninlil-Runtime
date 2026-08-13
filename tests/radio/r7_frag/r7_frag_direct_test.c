/* SPDX-License-Identifier: Apache-2.0 */
/*
 * R7 private NRW1 LINK/FRAG/reassembly direct tests.
 *
 * Independent vectors: empty/1/max/exact boundaries, reorder/gap/dup/conflict,
 * replay, mixed context/generation, resource exhaustion, restart classes,
 * COMMIT_UNKNOWN, sender retry, receiver publication exact once.
 *
 * Compile via tools/r7_frag_direct_test_driver.sh (not CMake).
 * Not HIL. Not installed. Not public ABI.
 */

#include "r7_crypto_openssl3.h"
#include "r7_frag.h"
#include "r7_frag_internal.h"
#include "tx_exclusive_tranche.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_tests;

static void expect_status(const char *name, int32_t got, int32_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: status got=%d want=%d\n",
            name, (int)got, (int)want);
        g_failures++;
    }
}

static void expect_true(const char *name, int cond)
{
    g_tests++;
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_failures++;
    }
}

static void expect_u64(const char *name, uint64_t got, uint64_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: u64 got=%llu want=%llu\n", name,
            (unsigned long long)got, (unsigned long long)want);
        g_failures++;
    }
}

static void expect_size(const char *name, size_t got, size_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: size got=%zu want=%zu\n", name, got, want);
        g_failures++;
    }
}

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static ninlil_r7_crypto_provider g_prov;
static int g_prov_ok;

static int ensure_provider(void)
{
    if (g_prov_ok) {
        return 1;
    }
    if (ninlil_r7_crypto_openssl3_provider_init(&g_prov) != NINLIL_R7_CRYPTO_OK) {
        fprintf(stderr, "FAIL openssl3 provider init\n");
        g_failures++;
        return 0;
    }
    g_prov_ok = 1;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Plan boundaries                                                            */
/* -------------------------------------------------------------------------- */

static void test_plan_boundaries(void)
{
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_status st;

    st = ninlil_r7_frag_plan_build(0u, &plan);
    expect_status("plan empty", st, NINLIL_R7_FRAG_LENGTH_CLASS);

    st = ninlil_r7_frag_plan_build(1u, &plan);
    expect_status("plan total=1", st, NINLIL_R7_FRAG_LENGTH_CLASS);

    st = ninlil_r7_frag_plan_build(2u, &plan);
    expect_status("plan total=2", st, NINLIL_R7_FRAG_OK);
    expect_u64("plan2 S", plan.first_chunk_len, 1u);
    expect_u64("plan2 fc", plan.frag_count, 2u);
    expect_u64("plan2 c1", plan.chunks[1].length, 1u);

    st = ninlil_r7_frag_plan_build(127u, &plan);
    expect_status("plan 127", st, NINLIL_R7_FRAG_OK);
    expect_u64("plan127 S", plan.first_chunk_len, 126u);
    expect_u64("plan127 fc", plan.frag_count, 2u);
    expect_u64("plan127 c1", plan.chunks[1].length, 1u);

    st = ninlil_r7_frag_plan_build(306u, &plan); /* 126 + 180 */
    expect_status("plan 306", st, NINLIL_R7_FRAG_OK);
    expect_u64("plan306 fc", plan.frag_count, 2u);
    expect_u64("plan306 c1", plan.chunks[1].length, 180u);

    st = ninlil_r7_frag_plan_build(307u, &plan); /* 126 + 180 + 1 */
    expect_status("plan 307", st, NINLIL_R7_FRAG_OK);
    expect_u64("plan307 fc", plan.frag_count, 3u);
    expect_u64("plan307 c2", plan.chunks[2].length, 1u);

    st = ninlil_r7_frag_plan_build(2048u, &plan);
    expect_status("plan max", st, NINLIL_R7_FRAG_OK);
    /* Maximal-S plan: S=126 ⇒ fc=1+ceil((2048-126)/180)=12 (≤13 bound). */
    expect_u64("plan max fc", plan.frag_count, 12u);
    {
        uint32_t sum = 0u;
        uint16_t j;
        for (j = 0u; j < plan.frag_count; j++) {
            sum += plan.chunks[j].length;
        }
        expect_u64("plan max sum", sum, 2048u);
    }
    /* Effective max 13 is reachable with minimal S=1. */
    st = ninlil_r7_frag_plan_validate(2048u, 1u, 13u, 180u);
    expect_status("plan S=1 fc=13", st, NINLIL_R7_FRAG_OK);

    st = ninlil_r7_frag_plan_build(2049u, &plan);
    expect_status("plan oversize", st, NINLIL_R7_FRAG_LENGTH_CLASS);

    st = ninlil_r7_frag_plan_validate(100u, 50u, 2u, 180u);
    expect_status("plan validate ok", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_plan_validate(100u, 50u, 3u, 180u);
    expect_status("plan validate bad fc", st, NINLIL_R7_FRAG_STRUCTURAL);
    st = ninlil_r7_frag_plan_validate(100u, 50u, 2u, 179u);
    expect_status("plan validate unit", st, NINLIL_R7_FRAG_STRUCTURAL);
}

/* -------------------------------------------------------------------------- */
/* LINK_ACK body + outer roundtrip                                            */
/* -------------------------------------------------------------------------- */

static void test_link_ack_wire(void)
{
    ninlil_r7_frag_link_ack_body body;
    ninlil_r7_frag_link_ack_body out_body;
    ninlil_r7_frag_outer_link_ack_fields outer;
    ninlil_r7_frag_outer_link_ack_fields out_outer;
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t frame[51];
    size_t flen = 0u;
    ninlil_r7_frag_status st;
    uint8_t pt16[16];

    if (!ensure_provider()) {
        return;
    }
    fill(key, 16u, 0x10u);
    fill(iv, 12u, 0x20u);

    memset(&body, 0, sizeof(body));
    body.acked_hop_context_id = 7u;
    body.ack_base_counter = 5u;
    body.ack_bitmap = 0x001Fu; /* bits 0..4 */
    body.ack_code = 0u;
    st = ninlil_r7_frag_link_ack_body_validate(&body);
    expect_status("link body ok", st, NINLIL_R7_FRAG_OK);

    body.ack_bitmap = 0x0000u;
    st = ninlil_r7_frag_link_ack_body_validate(&body);
    expect_status("link body bit0", st, NINLIL_R7_FRAG_STRUCTURAL);

    body.ack_bitmap = 0x0021u; /* bit5 set but base=5 => i=5 >= base */
    body.ack_base_counter = 5u;
    st = ninlil_r7_frag_link_ack_body_validate(&body);
    expect_status("link body high bit", st, NINLIL_R7_FRAG_STRUCTURAL);

    body.ack_bitmap = 0x0003u;
    body.ack_base_counter = 3u;
    st = ninlil_r7_frag_pack_link_ack_body(&body, pt16);
    expect_status("link pack", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_parse_link_ack_body(pt16, &out_body);
    expect_status("link parse", st, NINLIL_R7_FRAG_OK);
    expect_u64("link base", out_body.ack_base_counter, 3u);

    memset(&outer, 0, sizeof(outer));
    outer.hop_context_id = 9u;
    outer.hop_counter = 1u;
    st = ninlil_r7_frag_seal_outer_link_ack(
        &g_prov, key, iv, &outer, &body, frame, &flen);
    expect_status("link seal", st, NINLIL_R7_FRAG_OK);
    expect_size("link outer len", flen, 51u);

    st = ninlil_r7_frag_open_outer_link_ack(
        &g_prov, key, iv, frame, flen, &out_outer, &out_body);
    expect_status("link open", st, NINLIL_R7_FRAG_OK);
    expect_u64("link outer ctr", out_outer.hop_counter, 1u);
    expect_u64("link body base2", out_body.ack_base_counter, 3u);

    /* wrong key => auth fail, no partial body */
    fill(key, 16u, 0x99u);
    memset(&out_body, 0xA5u, sizeof(out_body));
    st = ninlil_r7_frag_open_outer_link_ack(
        &g_prov, key, iv, frame, flen, &out_outer, &out_body);
    expect_status("link bad key", st, NINLIL_R7_FRAG_AUTH_FAILED);
}

/* -------------------------------------------------------------------------- */
/* FRAG seal/open roundtrip + reassembly                                      */
/* -------------------------------------------------------------------------- */

static void build_payload(uint8_t *p, size_t n, uint8_t seed)
{
    fill(p, n, seed);
}

static void test_frag_roundtrip_and_reasm(void)
{
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_cont_body cont;
    ninlil_r7_frag_e2e_fields e2e;
    ninlil_r7_frag_e2e_fields e2e_out;
    ninlil_r7_frag_start_body start_out;
    ninlil_r7_frag_cont_body cont_out;
    ninlil_r7_frag_ack_body intent;
    ninlil_r7_frag_engine eng;
    uint8_t payload[400];
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t blob[220];
    uint8_t chunk[180];
    uint8_t first[126];
    size_t blob_len = 0u;
    size_t first_len = 0u;
    size_t chunk_len = 0u;
    size_t i;
    ninlil_r7_frag_status st;
    uint32_t total = 200u;
    uint8_t digest[32];
    uint8_t pub[400];
    size_t pub_len = 0u;
    uint32_t pub_ctx = 0u;
    uint64_t pub_h = 0u;

    if (!ensure_provider()) {
        return;
    }
    fill(key, 16u, 0x30u);
    fill(iv, 12u, 0x40u);
    build_payload(payload, total, 0x50u);

    st = ninlil_r7_frag_plan_build(total, &plan);
    expect_status("reasm plan", st, NINLIL_R7_FRAG_OK);

    st = ninlil_r7_frag_content_digest(&g_prov, payload, total, digest);
    expect_status("content digest", st, NINLIL_R7_FRAG_OK);

    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0x60u);
    start.transfer_handle = 100u;
    start.total_len = total;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);

    memset(&e2e, 0, sizeof(e2e));
    e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
    e2e.e2e_context_id = 42u;
    e2e.e2e_counter = 10u;

    {
        size_t need = 14u + 64u + plan.first_chunk_len + 16u;
        st = ninlil_r7_frag_seal_e2e_start(
            &g_prov, key, iv, &e2e, &start, payload, plan.first_chunk_len, blob,
            need, &blob_len);
        expect_status("seal start", st, NINLIL_R7_FRAG_OK);
        expect_true("start blob domain",
            blob_len >= 95u && blob_len <= 220u);
    }

    st = ninlil_r7_frag_open_e2e_start(
        &g_prov, key, iv, blob, blob_len, &e2e_out, &start_out, first,
        sizeof(first), &first_len);
    expect_status("open start", st, NINLIL_R7_FRAG_OK);
    expect_u64("start handle", start_out.transfer_handle, 100u);
    expect_size("start S", first_len, plan.first_chunk_len);
    expect_true("start chunk", memcmp(first, payload, first_len) == 0);

    ninlil_r7_frag_engine_init(&eng);
    ninlil_r7_frag_engine_set_now(&eng, 1000u);
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 42u, &start_out, first, first_len, &intent);
    expect_status("admit start", st, NINLIL_R7_FRAG_OK);
    expect_u64("intent partial", intent.status, NINLIL_R7_FRAG_STATUS_PARTIAL);

    /* Exact retry START */
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 42u, &start_out, first, first_len, &intent);
    expect_status("exact retry start", st, NINLIL_R7_FRAG_EXACT_RETRY);

    /* Reorder: CONT last first if multi */
    for (i = 1u; i < plan.frag_count; i++) {
        size_t idx = plan.frag_count - i; /* reverse order */
        size_t need;
        memset(&cont, 0, sizeof(cont));
        cont.transfer_handle = 100u;
        cont.frag_index = (uint16_t)idx;
        e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
        e2e.e2e_counter = (uint64_t)(10u + idx);
        need = 14u + 10u + plan.chunks[idx].length + 16u;
        st = ninlil_r7_frag_seal_e2e_cont(
            &g_prov, key, iv, &e2e, &cont,
            payload + plan.chunks[idx].offset, plan.chunks[idx].length, blob,
            need, &blob_len);
        expect_status("seal cont", st, NINLIL_R7_FRAG_OK);
        st = ninlil_r7_frag_open_e2e_cont(
            &g_prov, key, iv, blob, blob_len, &e2e_out, &cont_out, chunk,
            sizeof(chunk), &chunk_len);
        expect_status("open cont", st, NINLIL_R7_FRAG_OK);
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 42u, &cont_out, chunk, chunk_len, &intent);
        expect_true("admit cont ok-ish",
            st == NINLIL_R7_FRAG_OK || st == NINLIL_R7_FRAG_DUPLICATE);
    }

    expect_u64("complete status", intent.status, NINLIL_R7_FRAG_STATUS_COMPLETE);
    st = ninlil_r7_frag_take_publication(
        &eng, &pub_ctx, &pub_h, pub, sizeof(pub), &pub_len);
    expect_status("take pub", st, NINLIL_R7_FRAG_PUBLISHED);
    expect_size("pub len", pub_len, total);
    expect_true("pub bytes", memcmp(pub, payload, total) == 0);
    expect_u64("publish count", eng.publish_count, 1u);

    /* Exact once: second take fails */
    st = ninlil_r7_frag_take_publication(
        &eng, &pub_ctx, &pub_h, pub, sizeof(pub), &pub_len);
    expect_status("take pub twice", st, NINLIL_R7_FRAG_NO_TRANSFER);
    expect_u64("publish count still 1", eng.publish_count, 1u);

    ninlil_r7_frag_engine_zeroize(&eng);
}

static void test_gap_dup_conflict(void)
{
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_cont_body cont;
    ninlil_r7_frag_ack_body intent;
    ninlil_r7_frag_engine eng;
    uint8_t payload[400];
    uint8_t digest[32];
    uint8_t first[126];
    uint8_t bad[180];
    ninlil_r7_frag_status st;
    uint32_t total = 400u;

    if (!ensure_provider()) {
        return;
    }
    build_payload(payload, total, 0x11u);
    st = ninlil_r7_frag_plan_build(total, &plan);
    expect_status("gap plan", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_content_digest(&g_prov, payload, total, digest);
    expect_status("gap digest", st, NINLIL_R7_FRAG_OK);

    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0x22u);
    start.transfer_handle = 200u;
    start.total_len = total;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);
    memcpy(first, payload, plan.first_chunk_len);

    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 5000u;
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 1u, &start, first, plan.first_chunk_len, &intent);
    expect_status("gap start", st, NINLIL_R7_FRAG_OK);

    /* CONT index 2 before 1 if fc>=3 (gap) is allowed out-of-order */
    if (plan.frag_count >= 3u) {
        memset(&cont, 0, sizeof(cont));
        cont.transfer_handle = 200u;
        cont.frag_index = 2u;
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 1u, &cont,
            payload + plan.chunks[2].offset, plan.chunks[2].length, &intent);
        expect_status("gap ooo cont2", st, NINLIL_R7_FRAG_OK);
        expect_u64("still partial", intent.status, NINLIL_R7_FRAG_STATUS_PARTIAL);
    }

    /* Duplicate same CONT (before completing the transfer). */
    memset(&cont, 0, sizeof(cont));
    cont.transfer_handle = 200u;
    cont.frag_index = 1u;
    st = ninlil_r7_frag_reasm_admit_cont(
        &eng, &g_prov, 1u, &cont,
        payload + plan.chunks[1].offset, plan.chunks[1].length, &intent);
    /* If fc==2 this completes; only assert dup/conflict when still active. */
    if (st == NINLIL_R7_FRAG_OK && intent.status == NINLIL_R7_FRAG_STATUS_PARTIAL) {
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 1u, &cont,
            payload + plan.chunks[1].offset, plan.chunks[1].length, &intent);
        expect_status("cont1 dup", st, NINLIL_R7_FRAG_DUPLICATE);

        fill(bad, plan.chunks[1].length, 0xFFu);
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 1u, &cont, bad, plan.chunks[1].length, &intent);
        expect_status("cont conflict", st, NINLIL_R7_FRAG_CONFLICT);
        expect_u64("abort conflict", intent.status, NINLIL_R7_FRAG_STATUS_ABORT);
    } else {
        /* With ooo cont2 already present, cont1 may complete (fc=3). Re-test
         * dup/conflict on a fresh engine without ooo pre-fill. */
        ninlil_r7_frag_engine_init(&eng);
        eng.now_mono = 5000u;
        st = ninlil_r7_frag_reasm_admit_start(
            &eng, &g_prov, 1u, &start, first, plan.first_chunk_len, &intent);
        expect_status("dup restart start", st, NINLIL_R7_FRAG_OK);
        memset(&cont, 0, sizeof(cont));
        cont.transfer_handle = 200u;
        cont.frag_index = 1u;
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 1u, &cont,
            payload + plan.chunks[1].offset, plan.chunks[1].length, &intent);
        expect_status("cont1 first clean", st, NINLIL_R7_FRAG_OK);
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 1u, &cont,
            payload + plan.chunks[1].offset, plan.chunks[1].length, &intent);
        expect_status("cont1 dup", st, NINLIL_R7_FRAG_DUPLICATE);
        fill(bad, plan.chunks[1].length, 0xFFu);
        st = ninlil_r7_frag_reasm_admit_cont(
            &eng, &g_prov, 1u, &cont, bad, plan.chunks[1].length, &intent);
        expect_status("cont conflict", st, NINLIL_R7_FRAG_CONFLICT);
        expect_u64("abort conflict", intent.status, NINLIL_R7_FRAG_STATUS_ABORT);
    }

    /* CONT before START */
    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 1u;
    cont.transfer_handle = 999u;
    cont.frag_index = 1u;
    st = ninlil_r7_frag_reasm_admit_cont(
        &eng, &g_prov, 1u, &cont, payload, 10u, &intent);
    expect_status("cont before start", st, NINLIL_R7_FRAG_NO_TRANSFER);

    ninlil_r7_frag_engine_zeroize(&eng);
}

static void test_conflict_fingerprint(void)
{
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_ack_body intent;
    ninlil_r7_frag_engine eng;
    uint8_t payload[50];
    uint8_t digest[32];
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_status st;

    if (!ensure_provider()) {
        return;
    }
    st = ninlil_r7_frag_plan_build(50u, &plan);
    build_payload(payload, 50u, 0x01u);
    ninlil_r7_frag_content_digest(&g_prov, payload, 50u, digest);
    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0xAAu);
    start.transfer_handle = 1u;
    start.total_len = 50u;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);

    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 10u;
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 5u, &start, payload, plan.first_chunk_len, &intent);
    expect_status("fp start", st, NINLIL_R7_FRAG_OK);

    /* Same handle, different transfer_id => CONFLICT */
    fill(start.transfer_id, 16u, 0xBBu);
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 5u, &start, payload, plan.first_chunk_len, &intent);
    expect_status("fp conflict tid", st, NINLIL_R7_FRAG_CONFLICT);

    ninlil_r7_frag_engine_zeroize(&eng);
}

/* -------------------------------------------------------------------------- */
/* Lane counters / replay / DATA vs ACK                                       */
/* -------------------------------------------------------------------------- */

static void test_lanes_replay(void)
{
    ninlil_r7_frag_engine eng;
    size_t data_slot = 0u;
    size_t ack_slot = 0u;
    uint64_t c = 0u;
    ninlil_r7_frag_status st;
    size_t i;

    ninlil_r7_frag_engine_init(&eng);
    st = ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 1u, 1u, &data_slot);
    expect_status("install data", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_ACK, 1u, 1u, &ack_slot);
    expect_status("install ack same ctx", st, NINLIL_R7_FRAG_OK);
    expect_true("lanes distinct", data_slot != ack_slot);

    st = ninlil_r7_frag_lane_tx_allocate(&eng, data_slot, &c);
    expect_status("tx data", st, NINLIL_R7_FRAG_OK);
    expect_u64("tx data c", c, 1u);
    st = ninlil_r7_frag_lane_tx_allocate(&eng, ack_slot, &c);
    expect_status("tx ack", st, NINLIL_R7_FRAG_OK);
    expect_u64("tx ack c independent", c, 1u);

    /* RX precheck / admit / replay */
    st = ninlil_r7_frag_lane_rx_precheck(&eng, data_slot, 1u);
    expect_status("rx pre 1", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_lane_rx_admit(&eng, data_slot, 1u);
    expect_status("rx admit 1", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_lane_rx_precheck(&eng, data_slot, 1u);
    expect_status("rx replay", st, NINLIL_R7_FRAG_REPLAY);

    /* Out-of-order then fill */
    st = ninlil_r7_frag_lane_rx_admit(&eng, data_slot, 3u);
    expect_status("rx admit 3", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_lane_rx_admit(&eng, data_slot, 2u);
    expect_status("rx admit 2 ooo", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_lane_rx_precheck(&eng, data_slot, 2u);
    expect_status("rx replay 2", st, NINLIL_R7_FRAG_REPLAY);

    /* Window edge deltas */
    for (i = 4u; i <= 66u; i++) {
        st = ninlil_r7_frag_lane_rx_admit(&eng, data_slot, (uint64_t)i);
        expect_status("rx bulk", st, NINLIL_R7_FRAG_OK);
    }
    /* 66-64=2 still in window if highest=66? bit for 2 is at delta 64 => reject */
    st = ninlil_r7_frag_lane_rx_precheck(&eng, data_slot, 2u);
    expect_status("rx old out window", st, NINLIL_R7_FRAG_REPLAY);

    /* Silent replace forbidden */
    st = ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 1u, 2u, &data_slot);
    expect_status("no silent replace", st, NINLIL_R7_FRAG_CONFLICT);

    /* Resource exhaustion of lane slots (fill remaining to LANE_SLOTS). */
    {
        size_t used = 2u; /* data + ack already installed */
        uint32_t cid = 2u;
        while (used < NINLIL_R7_FRAG_LANE_SLOTS) {
            st = ninlil_r7_frag_lane_install(
                &eng, NINLIL_R7_FRAG_LANE_E2E, cid, 1u, &data_slot);
            expect_status("lane fill", st, NINLIL_R7_FRAG_OK);
            used++;
            cid++;
        }
        st = ninlil_r7_frag_lane_install(
            &eng, NINLIL_R7_FRAG_LANE_E2E, cid, 1u, &data_slot);
        expect_status("lane exhaust", st, NINLIL_R7_FRAG_RESOURCE);
    }

    ninlil_r7_frag_engine_zeroize(&eng);
}

/* -------------------------------------------------------------------------- */
/* Outer DATA FRAG wrap                                                       */
/* -------------------------------------------------------------------------- */

static void test_outer_data_frag(void)
{
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_e2e_fields e2e;
    ninlil_r7_frag_outer_data_fields outer;
    ninlil_r7_frag_outer_data_fields outer_out;
    ninlil_r7_frag_e2e_fields struct_fields;
    uint8_t key_e2e[16];
    uint8_t iv_e2e[12];
    uint8_t key_hop[16];
    uint8_t iv_hop[12];
    uint8_t payload[80];
    uint8_t digest[32];
    uint8_t e2e_blob[220];
    uint8_t frame[255];
    uint8_t out_blob[220];
    size_t e2e_len = 0u;
    size_t frame_len = 0u;
    size_t out_len = 0u;
    size_t need;
    ninlil_r7_frag_status st;

    if (!ensure_provider()) {
        return;
    }
    fill(key_e2e, 16u, 0x01u);
    fill(iv_e2e, 12u, 0x02u);
    fill(key_hop, 16u, 0x03u);
    fill(iv_hop, 12u, 0x04u);
    build_payload(payload, 80u, 0x05u);
    ninlil_r7_frag_plan_build(80u, &plan);
    ninlil_r7_frag_content_digest(&g_prov, payload, 80u, digest);
    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0x06u);
    start.transfer_handle = 55u;
    start.total_len = 80u;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);
    e2e.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
    e2e.e2e_context_id = 8u;
    e2e.e2e_counter = 3u;
    need = 14u + 64u + plan.first_chunk_len + 16u;
    st = ninlil_r7_frag_seal_e2e_start(
        &g_prov, key_e2e, iv_e2e, &e2e, &start, payload, plan.first_chunk_len,
        e2e_blob, need, &e2e_len);
    expect_status("outer e2e seal", st, NINLIL_R7_FRAG_OK);

    st = ninlil_r7_frag_structural_e2e_header(e2e_blob, e2e_len, &struct_fields);
    expect_status("structural e2e", st, NINLIL_R7_FRAG_OK);
    expect_u64("struct type", struct_fields.e2e_type, NINLIL_R7_FRAG_E2E_TYPE_START);

    memset(&outer, 0, sizeof(outer));
    outer.ack_requested = 1u;
    outer.hop_remaining = 0u;
    outer.hop_context_id = 11u;
    outer.hop_counter = 4u;
    need = 19u + e2e_len + 16u;
    st = ninlil_r7_frag_seal_outer_data(
        &g_prov, key_hop, iv_hop, &outer, e2e_blob, e2e_len, frame, need,
        &frame_len);
    expect_status("outer seal", st, NINLIL_R7_FRAG_OK);
    expect_true("outer start domain", frame_len >= 130u && frame_len <= 255u);

    st = ninlil_r7_frag_open_outer_data(
        &g_prov, key_hop, iv_hop, frame, frame_len, &outer_out, out_blob,
        e2e_len, &out_len);
    expect_status("outer open", st, NINLIL_R7_FRAG_OK);
    expect_true("outer blob match",
        out_len == e2e_len && memcmp(out_blob, e2e_blob, e2e_len) == 0);
    expect_u64("outer ack bit", outer_out.ack_requested, 1u);
}

/* -------------------------------------------------------------------------- */
/* LINK group retry + ACK                                                     */
/* -------------------------------------------------------------------------- */

static void test_link_group_retry(void)
{
    ninlil_r7_frag_engine eng;
    size_t g = 0u;
    uint8_t blob[40];
    ninlil_r7_frag_link_ack_body ack;
    ninlil_r7_frag_status st;

    /* Minimal structurally valid E2E blob header bytes for copy-own only */
    memset(blob, 0x11u, sizeof(blob));
    blob[0] = 0x11u;
    blob[1] = 0x10u; /* SINGLE type for structural min size path - length 40 ok for link copy */

    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 100u;
    /* need 31..220 */
    st = ninlil_r7_frag_link_group_admit(
        &eng, 7u, 1u, 5u, blob, 40u, 100000u, &g);
    expect_status("link admit", st, NINLIL_R7_FRAG_OK);

    st = ninlil_r7_frag_link_group_note_air(&eng, g, 1u, 100u);
    expect_status("link air1", st, NINLIL_R7_FRAG_OK);
    st = ninlil_r7_frag_link_group_retry_ready(&eng, g, 100u);
    expect_status("not eligible yet", st, NINLIL_R7_FRAG_TIMEOUT);
    st = ninlil_r7_frag_link_group_retry_ready(&eng, g, 100u + 3000u);
    expect_status("eligible", st, NINLIL_R7_FRAG_OK);

    st = ninlil_r7_frag_link_group_note_air(&eng, g, 2u, 4100u);
    expect_status("link air2", st, NINLIL_R7_FRAG_OK);

    memset(&ack, 0, sizeof(ack));
    ack.acked_hop_context_id = 7u;
    ack.ack_base_counter = 2u;
    ack.ack_bitmap = 0x0003u; /* counters 2 and 1 */
    ack.ack_code = 0u;
    st = ninlil_r7_frag_link_group_apply_ack(&eng, g, &ack);
    expect_status("link apply ack", st, NINLIL_R7_FRAG_OK);
    expect_true("group completed", eng.links[g].completed == 1u);

    /* Sender retry budget: 4 attempts max */
    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 0u;
    ninlil_r7_frag_link_group_admit(
        &eng, 1u, 1u, 1u, blob, 40u, 1000000u, &g);
    st = ninlil_r7_frag_link_group_note_air(&eng, g, 1u, 0u);
    expect_status("a1", st, NINLIL_R7_FRAG_OK);
    eng.now_mono = 10000u;
    st = ninlil_r7_frag_link_group_note_air(&eng, g, 2u, 10000u);
    expect_status("a2", st, NINLIL_R7_FRAG_OK);
    eng.now_mono = 20000u;
    st = ninlil_r7_frag_link_group_note_air(&eng, g, 3u, 20000u);
    expect_status("a3", st, NINLIL_R7_FRAG_OK);
    eng.now_mono = 30000u;
    st = ninlil_r7_frag_link_group_note_air(&eng, g, 4u, 30000u);
    expect_status("a4", st, NINLIL_R7_FRAG_OK);
    eng.now_mono = 40000u;
    st = ninlil_r7_frag_link_group_note_air(&eng, g, 5u, 40000u);
    expect_status("a5 reject", st, NINLIL_R7_FRAG_RESOURCE);

    /* ack_requested=0 */
    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 0u;
    ninlil_r7_frag_link_group_admit(
        &eng, 1u, 0u, 1u, blob, 40u, 1000u, &g);
    st = ninlil_r7_frag_link_group_note_air(&eng, g, 1u, 0u);
    expect_status("unacked air", st, NINLIL_R7_FRAG_OK);
    expect_true("unacked complete", eng.links[g].completed == 1u);

    ninlil_r7_frag_engine_zeroize(&eng);
}

/* -------------------------------------------------------------------------- */
/* Resource exhaustion reassembly                                             */
/* -------------------------------------------------------------------------- */

static void test_resource_exhaustion(void)
{
    ninlil_r7_frag_engine eng;
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_ack_body intent;
    uint8_t payload[100];
    uint8_t digest[32];
    ninlil_r7_frag_status st;
    int k;

    if (!ensure_provider()) {
        return;
    }
    ninlil_r7_frag_plan_build(100u, &plan);
    build_payload(payload, 100u, 0x33u);
    ninlil_r7_frag_content_digest(&g_prov, payload, 100u, digest);
    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 1u;

    /* Fill all reasm slots for current profile (2 endpoint / 16 controller). */
    for (k = 0; k < (int)NINLIL_R7_FRAG_REASM_SLOTS; k++) {
        memset(&start, 0, sizeof(start));
        fill(start.transfer_id, 16u, (uint8_t)(0x10u + k));
        start.transfer_handle = (uint64_t)(10u + (unsigned)k);
        start.total_len = 100u;
        start.frag_count = plan.frag_count;
        start.continuation_unit = 180u;
        memcpy(start.content_digest, digest, 32u);
        st = ninlil_r7_frag_reasm_admit_start(
            &eng, &g_prov, 1u, &start, payload, plan.first_chunk_len, &intent);
        expect_status("reasm slot fill", st, NINLIL_R7_FRAG_OK);
    }
    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0x99u);
    start.transfer_handle = 99u;
    start.total_len = 100u;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 1u, &start, payload, plan.first_chunk_len, &intent);
    expect_status("reasm exhaust", st, NINLIL_R7_FRAG_RESOURCE);

    ninlil_r7_frag_engine_zeroize(&eng);
}

/* -------------------------------------------------------------------------- */
/* Restart snapshot classes                                                   */
/* -------------------------------------------------------------------------- */

static void test_restart_snapshot(void)
{
    ninlil_r7_frag_engine eng;
    ninlil_r7_frag_engine eng2;
    uint8_t snap[4096];
    size_t slen = 0u;
    size_t slot = 0u;
    ninlil_r7_frag_status st;
    uint8_t broken[64];

    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 12345u;
    ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 3u, 1u, &slot);
    {
        uint64_t c = 0u;
        ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
        (void)c;
    }

    st = ninlil_r7_frag_restart_encode(&eng, snap, sizeof(snap), &slen);
    expect_status("snap encode", st, NINLIL_R7_FRAG_OK);
    expect_true("snap nonempty", slen >= 24u);

    st = ninlil_r7_frag_restart_decode(&eng2, snap, slen);
    expect_status("snap decode ok", st, NINLIL_R7_FRAG_OK);
    expect_u64("snap now", eng2.now_mono, 12345u);
    expect_true("lane restored", eng2.lanes[0].in_use == 1u);
    expect_true("reasm not restored", eng2.reasm[0].in_use == 0u);
    expect_true("tomb not restored", eng2.tombs[0].in_use == 0u);

    /* partial */
    st = ninlil_r7_frag_restart_decode(&eng2, snap, 10u);
    expect_status("snap partial", st, NINLIL_R7_FRAG_STRUCTURAL);

    /* old magic */
    memcpy(broken, snap, 24u);
    broken[0] ^= 0xFFu;
    st = ninlil_r7_frag_restart_decode(&eng2, broken, 24u);
    expect_status("snap old/foreign", st, NINLIL_R7_FRAG_STRUCTURAL);

    /* new version */
    memcpy(broken, snap, slen > 64u ? 64u : slen);
    broken[4] = 0u;
    broken[5] = 99u;
    st = ninlil_r7_frag_restart_decode(&eng2, broken, 24u);
    expect_status("snap new ver", st, NINLIL_R7_FRAG_STRUCTURAL);

    /* extra trailing */
    if (slen + 1u < sizeof(snap)) {
        snap[slen] = 0xEEu;
        st = ninlil_r7_frag_restart_decode(&eng2, snap, slen + 1u);
        expect_status("snap extra", st, NINLIL_R7_FRAG_STRUCTURAL);
    }

    /* third: claim reasm_count != 0 */
    memcpy(broken, snap, 24u);
    broken[8] = 0u;
    broken[9] = 1u; /* reasm_count = 1 */
    st = ninlil_r7_frag_restart_decode(&eng2, broken, 24u);
    expect_status("snap third reasm", st, NINLIL_R7_FRAG_STRUCTURAL);

    ninlil_r7_frag_engine_zeroize(&eng);
    ninlil_r7_frag_engine_zeroize(&eng2);
}

/* -------------------------------------------------------------------------- */
/* COMMIT_UNKNOWN classifier                                                  */
/* -------------------------------------------------------------------------- */

static void test_cu_classifier(void)
{
    ninlil_r7_frag_cu_entry entries[3];
    ninlil_r7_frag_cu_result res;
    ninlil_r7_frag_status st;

    memset(entries, 0, sizeof(entries));
    /* ALL_PROPOSED: PUT observed==proposed */
    entries[0].old_present = 1u;
    entries[0].proposed_present = 1u;
    entries[0].key_len = 4u;
    memcpy(entries[0].key, "KEY1", 4u);
    entries[0].old_len = 2u;
    entries[0].old_bytes[0] = 1u;
    entries[0].old_bytes[1] = 2u;
    entries[0].proposed_len = 2u;
    entries[0].proposed_bytes[0] = 3u;
    entries[0].proposed_bytes[1] = 4u;
    entries[0].observed_status = 0u;
    entries[0].observed_len = 2u;
    entries[0].observed_bytes[0] = 3u;
    entries[0].observed_bytes[1] = 4u;
    st = ninlil_r7_frag_cu_classify(entries, 1u, &res);
    expect_status("cu all proposed", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu class proposed", res.class_code, NINLIL_R7_FRAG_CU_ALL_PROPOSED);

    /* ALL_OLD */
    entries[0].observed_bytes[0] = 1u;
    entries[0].observed_bytes[1] = 2u;
    st = ninlil_r7_frag_cu_classify(entries, 1u, &res);
    expect_status("cu all old", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu class old", res.class_code, NINLIL_R7_FRAG_CU_ALL_OLD);

    /* THIRD: neither */
    entries[0].observed_bytes[0] = 9u;
    st = ninlil_r7_frag_cu_classify(entries, 1u, &res);
    expect_status("cu third", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu class third", res.class_code, NINLIL_R7_FRAG_CU_THIRD);

    /* MIXED => THIRD */
    entries[0].observed_bytes[0] = 3u;
    entries[0].observed_bytes[1] = 4u; /* proposed */
    entries[1] = entries[0];
    entries[1].key[3] = '2';
    entries[1].observed_bytes[0] = 1u;
    entries[1].observed_bytes[1] = 2u; /* old */
    st = ninlil_r7_frag_cu_classify(entries, 2u, &res);
    expect_status("cu mixed", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu class mixed", res.class_code, NINLIL_R7_FRAG_CU_THIRD);

    /* RETRY BUSY */
    entries[0].observed_status = 2u;
    st = ninlil_r7_frag_cu_classify(entries, 1u, &res);
    expect_status("cu busy", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu retry", res.class_code, NINLIL_R7_FRAG_CU_RETRY_LATER);

    /* empty/corrupt count */
    st = ninlil_r7_frag_cu_classify(entries, 0u, &res);
    expect_status("cu empty", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu corrupt empty", res.class_code, NINLIL_R7_FRAG_CU_CORRUPT);

    /* DELETE proposed (NOT_FOUND) */
    memset(entries, 0, sizeof(entries));
    entries[0].old_present = 1u;
    entries[0].proposed_present = 0u;
    entries[0].key_len = 1u;
    entries[0].key[0] = 1u;
    entries[0].old_len = 1u;
    entries[0].old_bytes[0] = 7u;
    entries[0].observed_status = 1u; /* NOT_FOUND */
    st = ninlil_r7_frag_cu_classify(entries, 1u, &res);
    expect_status("cu delete proposed", st, NINLIL_R7_FRAG_OK);
    expect_u64("cu del prop", res.class_code, NINLIL_R7_FRAG_CU_ALL_PROPOSED);
}

/* -------------------------------------------------------------------------- */
/* FRAG_ACK body validate                                                     */
/* -------------------------------------------------------------------------- */

static void test_frag_ack_validate(void)
{
    ninlil_r7_frag_ack_body body;
    ninlil_r7_frag_status st;

    memset(&body, 0, sizeof(body));
    body.transfer_handle = 1u;
    body.frag_count = 3u;
    body.received_bitmap = 0x0007u;
    body.status = NINLIL_R7_FRAG_STATUS_COMPLETE;
    body.reason = 0u;
    st = ninlil_r7_frag_ack_rx_validate(3u, 1u, &body);
    expect_status("frag ack complete", st, NINLIL_R7_FRAG_OK);

    body.received_bitmap = 0x0003u;
    st = ninlil_r7_frag_ack_rx_validate(3u, 1u, &body);
    expect_status("frag ack bad complete", st, NINLIL_R7_FRAG_STRUCTURAL);

    body.status = NINLIL_R7_FRAG_STATUS_PARTIAL;
    body.received_bitmap = 0x0001u;
    st = ninlil_r7_frag_ack_rx_validate(3u, 1u, &body);
    expect_status("frag ack partial", st, NINLIL_R7_FRAG_OK);

    body.status = NINLIL_R7_FRAG_STATUS_ABORT;
    body.reason = NINLIL_R7_FRAG_REASON_TIMEOUT;
    body.received_bitmap = 0u;
    st = ninlil_r7_frag_ack_rx_validate(3u, 1u, &body);
    expect_status("frag ack abort", st, NINLIL_R7_FRAG_OK);

    body.received_bitmap = 1u;
    st = ninlil_r7_frag_ack_rx_validate(3u, 1u, &body);
    expect_status("frag ack abort bm", st, NINLIL_R7_FRAG_STRUCTURAL);
}

/* -------------------------------------------------------------------------- */
/* Timeout / eviction                                                         */
/* -------------------------------------------------------------------------- */

static void test_timeout_eviction(void)
{
    ninlil_r7_frag_engine eng;
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_ack_body intent;
    uint8_t payload[50];
    uint8_t digest[32];
    ninlil_r7_frag_status st;

    if (!ensure_provider()) {
        return;
    }
    ninlil_r7_frag_plan_build(50u, &plan);
    build_payload(payload, 50u, 0x44u);
    ninlil_r7_frag_content_digest(&g_prov, payload, 50u, digest);
    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0x55u);
    start.transfer_handle = 77u;
    start.total_len = 50u;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);

    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 1000u;
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 2u, &start, payload, plan.first_chunk_len, &intent);
    expect_status("to start", st, NINLIL_R7_FRAG_OK);
    expect_true("active", eng.reasm[0].in_use == 1u);

    st = ninlil_r7_frag_reasm_tick(&eng, 1000u + 20000u);
    expect_status("tick idle", st, NINLIL_R7_FRAG_OK);
    expect_true("timed out", eng.reasm[0].in_use == 0u);
    expect_true("tomb timeout", eng.tombs[0].in_use == 1u
        && eng.tombs[0].reason == NINLIL_R7_FRAG_REASON_TIMEOUT);

    ninlil_r7_frag_engine_zeroize(&eng);
}

/* -------------------------------------------------------------------------- */
/* Mixed generation / context                                                 */
/* -------------------------------------------------------------------------- */

static void test_mixed_context(void)
{
    ninlil_r7_frag_engine eng;
    ninlil_r7_frag_plan plan;
    ninlil_r7_frag_start_body start;
    ninlil_r7_frag_ack_body intent;
    uint8_t payload[40];
    uint8_t digest[32];
    ninlil_r7_frag_status st;

    if (!ensure_provider()) {
        return;
    }
    ninlil_r7_frag_plan_build(40u, &plan);
    build_payload(payload, 40u, 0x66u);
    ninlil_r7_frag_content_digest(&g_prov, payload, 40u, digest);
    memset(&start, 0, sizeof(start));
    fill(start.transfer_id, 16u, 0x77u);
    start.transfer_handle = 1u;
    start.total_len = 40u;
    start.frag_count = plan.frag_count;
    start.continuation_unit = 180u;
    memcpy(start.content_digest, digest, 32u);

    ninlil_r7_frag_engine_init(&eng);
    eng.now_mono = 1u;
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 10u, &start, payload, plan.first_chunk_len, &intent);
    expect_status("ctx A", st, NINLIL_R7_FRAG_OK);
    /* Same handle different e2e context is independent */
    st = ninlil_r7_frag_reasm_admit_start(
        &eng, &g_prov, 11u, &start, payload, plan.first_chunk_len, &intent);
    expect_status("ctx B same handle", st, NINLIL_R7_FRAG_OK);

    ninlil_r7_frag_engine_zeroize(&eng);
}

/* -------------------------------------------------------------------------- */
/* docs/30 §9.2 TX exclusive final partial tranche                           */
/* -------------------------------------------------------------------------- */

static void test_tx_exclusive_grow_helper(void)
{
    uint64_t U = 0u;
    uint64_t B = NINLIL_R7_FRAG_TX_BLOCK;

    /* Mid-range full block. */
    expect_true("grow from 1", ninlil_tx_exclusive_grow(1u, B, &U));
    expect_u64("U=65", U, 1u + B);

    /* U-65: full block leaves exclusive at UINT64_MAX-1. */
    expect_true("grow U-65",
        ninlil_tx_exclusive_grow(UINT64_MAX - 65u, B, &U));
    expect_u64("U after -65", U, UINT64_MAX - 1u);

    /* U-64: full block reaches terminal exclusive UINT64_MAX. */
    expect_true("grow U-64",
        ninlil_tx_exclusive_grow(UINT64_MAX - 64u, B, &U));
    expect_u64("U after -64", U, UINT64_MAX);

    /* U-63: partial tranche room=63 → exclusive MAX. */
    expect_true("grow U-63",
        ninlil_tx_exclusive_grow(UINT64_MAX - 63u, B, &U));
    expect_u64("U after -63", U, UINT64_MAX);

    /* U-1: partial room=1. */
    expect_true("grow U-1",
        ninlil_tx_exclusive_grow(UINT64_MAX - 1u, B, &U));
    expect_u64("U after -1", U, UINT64_MAX);

    /* Terminal exclusive: refuse. */
    expect_true("grow U refuse",
        !ninlil_tx_exclusive_grow(UINT64_MAX, B, &U));

    expect_true("assignable mid", ninlil_tx_counter_assignable(1u));
    expect_true("assignable max-1",
        ninlil_tx_counter_assignable(UINT64_MAX - 1u));
    expect_true("not assignable 0", !ninlil_tx_counter_assignable(0u));
    expect_true("not assignable U", !ninlil_tx_counter_assignable(UINT64_MAX));
}

static void test_core_lane_tx_partial_tranche(void)
{
    ninlil_r7_frag_engine eng;
    size_t slot = 0u;
    uint64_t c = 0u;
    ninlil_r7_frag_status st;
    uint64_t i;
    ninlil_r7_frag_lane *L;

    ninlil_r7_frag_engine_init(&eng);
    st = ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 9u, 1u, &slot);
    expect_status("install tranche lane", st, NINLIL_R7_FRAG_OK);
    L = &eng.lanes[slot];

    /* Seed empty window at UINT64_MAX-65 (next grow is full 64 → limit MAX-1). */
    L->tx_ram_next = UINT64_MAX - 65u;
    L->tx_ram_limit = UINT64_MAX - 65u;
    L->tx_reserved_exclusive = UINT64_MAX - 65u;
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("alloc at U-65", st, NINLIL_R7_FRAG_OK);
    expect_u64("c U-65", c, UINT64_MAX - 65u);
    expect_u64("limit after U-65 grow", L->tx_ram_limit, UINT64_MAX - 1u);

    /* Drain remaining through UINT64_MAX-2 in this block. */
    for (i = 0u; i < 63u; i++) {
        st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
        expect_status("drain mid", st, NINLIL_R7_FRAG_OK);
    }
    expect_u64("next at MAX-1", L->tx_ram_next, UINT64_MAX - 1u);

    /* Final partial tranche: room=1, grow to exclusive UINT64_MAX. */
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("alloc MAX-1", st, NINLIL_R7_FRAG_OK);
    expect_u64("c MAX-1", c, UINT64_MAX - 1u);
    expect_u64("limit terminal", L->tx_ram_limit, UINT64_MAX);
    expect_u64("next terminal", L->tx_ram_next, UINT64_MAX);

    /* Exhaustion: no further assignable counters. */
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("exhausted RESOURCE", st, NINLIL_R7_FRAG_RESOURCE);

    /* Boundary U-64 seed: single full grow to terminal. */
    ninlil_r7_frag_engine_init(&eng);
    ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 10u, 1u, &slot);
    L = &eng.lanes[slot];
    L->tx_ram_next = UINT64_MAX - 64u;
    L->tx_ram_limit = UINT64_MAX - 64u;
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("U-64 first", st, NINLIL_R7_FRAG_OK);
    expect_u64("U-64 c", c, UINT64_MAX - 64u);
    expect_u64("U-64 limit MAX", L->tx_ram_limit, UINT64_MAX);

    /* U-63 partial. */
    ninlil_r7_frag_engine_init(&eng);
    ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 11u, 1u, &slot);
    L = &eng.lanes[slot];
    L->tx_ram_next = UINT64_MAX - 63u;
    L->tx_ram_limit = UINT64_MAX - 63u;
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("U-63 first", st, NINLIL_R7_FRAG_OK);
    expect_u64("U-63 c", c, UINT64_MAX - 63u);
    expect_u64("U-63 limit MAX", L->tx_ram_limit, UINT64_MAX);

    /* U-1 last assignable. */
    ninlil_r7_frag_engine_init(&eng);
    ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 12u, 1u, &slot);
    L = &eng.lanes[slot];
    L->tx_ram_next = UINT64_MAX - 1u;
    L->tx_ram_limit = UINT64_MAX - 1u;
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("U-1 alloc", st, NINLIL_R7_FRAG_OK);
    expect_u64("U-1 c", c, UINT64_MAX - 1u);
    expect_u64("U-1 limit MAX", L->tx_ram_limit, UINT64_MAX);
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("after U-1 exhaust", st, NINLIL_R7_FRAG_RESOURCE);

    /* Terminal seed: refuse. */
    ninlil_r7_frag_engine_init(&eng);
    ninlil_r7_frag_lane_install(
        &eng, NINLIL_R7_FRAG_LANE_HOP_DATA, 13u, 1u, &slot);
    L = &eng.lanes[slot];
    L->tx_ram_next = UINT64_MAX;
    L->tx_ram_limit = UINT64_MAX;
    st = ninlil_r7_frag_lane_tx_allocate(&eng, slot, &c);
    expect_status("terminal refuse", st, NINLIL_R7_FRAG_RESOURCE);

    ninlil_r7_frag_engine_zeroize(&eng);
}

int main(void)
{
    test_plan_boundaries();
    test_link_ack_wire();
    test_frag_roundtrip_and_reasm();
    test_gap_dup_conflict();
    test_conflict_fingerprint();
    test_lanes_replay();
    test_outer_data_frag();
    test_link_group_retry();
    test_resource_exhaustion();
    test_restart_snapshot();
    test_cu_classifier();
    test_frag_ack_validate();
    test_timeout_eviction();
    test_mixed_context();
    test_tx_exclusive_grow_helper();
    test_core_lane_tx_partial_tranche();

    fprintf(stderr, "r7_frag_direct_test: %d checks, %d failures\n",
        g_tests, g_failures);
    return g_failures == 0 ? 0 : 1;
}
