/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Pure FRAG planner + reassembly state tests (no AEAD/wire).
 * Boundary vectors: empty/1/exact/max/gap/reorder/dup/conflict/resource/restart.
 */

#include "r7_frag_state.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_tests;

static void expect_st(const char *n, int32_t got, int32_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: status got=%d want=%d\n", n, (int)got, (int)want);
        g_failures++;
    }
}

static void expect_true(const char *n, int cond)
{
    g_tests++;
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", n);
        g_failures++;
    }
}

static void expect_u64(const char *n, uint64_t got, uint64_t want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: got=%llu want=%llu\n", n,
            (unsigned long long)got, (unsigned long long)want);
        g_failures++;
    }
}

static void fill(uint8_t *p, size_t n, uint8_t s)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(s + (uint8_t)i);
    }
}

/* Fake "digest" = rolling xor pattern (caller-bound; not SHA). */
static void fake_digest(const uint8_t *p, size_t n, uint8_t out[32])
{
    size_t i;
    memset(out, 0, 32u);
    for (i = 0u; i < n; i++) {
        out[i % 32u] = (uint8_t)(out[i % 32u] ^ p[i] ^ (uint8_t)(i & 0xffu));
    }
    out[0] ^= (uint8_t)n;
}

static void fake_fp(const ninlil_r7_frag_state_start_in *in, uint8_t out[32])
{
    size_t i;
    memset(out, 0, 32u);
    for (i = 0u; i < 16u; i++) {
        out[i] = in->transfer_id[i];
    }
    out[16] = (uint8_t)(in->transfer_handle & 0xffu);
    out[17] = (uint8_t)(in->total_len & 0xffu);
    out[18] = (uint8_t)in->frag_count;
    out[19] = (uint8_t)in->first_chunk_len;
    for (i = 0u; i < 32u; i++) {
        out[i] ^= in->content_digest[i];
    }
    if (in->first_chunk != NULL && in->first_chunk_len > 0u) {
        out[20] ^= in->first_chunk[0];
    }
}

/* -------------------------------------------------------------------------- */

static void test_plan_boundaries(void)
{
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_status st;
    uint16_t off = 0u;
    uint16_t len = 0u;
    uint32_t sum;
    uint16_t j;

    st = ninlil_r7_frag_state_plan_build(0u, &plan);
    expect_st("plan empty", st, NINLIL_R7_FRAG_STATE_LENGTH);
    st = ninlil_r7_frag_state_plan_build(1u, &plan);
    expect_st("plan 1", st, NINLIL_R7_FRAG_STATE_LENGTH);

    st = ninlil_r7_frag_state_plan_build(2u, &plan);
    expect_st("plan 2", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("plan2 S", plan.first_chunk_len, 1u);
    expect_u64("plan2 fc", plan.frag_count, 2u);
    expect_u64("plan2 c1", plan.chunks[1].length, 1u);

    st = ninlil_r7_frag_state_plan_build(127u, &plan);
    expect_st("plan 127", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("plan127 S", plan.first_chunk_len, 126u);
    expect_u64("plan127 c1", plan.chunks[1].length, 1u);

    st = ninlil_r7_frag_state_plan_build(306u, &plan);
    expect_st("plan exact 126+180", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("plan306 fc", plan.frag_count, 2u);

    st = ninlil_r7_frag_state_plan_build(307u, &plan);
    expect_st("plan 307", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("plan307 fc", plan.frag_count, 3u);

    /*
     * TRACE-INV010-REASSEMBLY-BOUNDARY
     * The profile maximum logical payload is accepted and max+1 is rejected.
     */
    st = ninlil_r7_frag_state_plan_build(2048u, &plan);
    expect_st("plan max", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("plan max fc", plan.frag_count, 12u); /* S=126 */
    sum = 0u;
    for (j = 0u; j < plan.frag_count; j++) {
        sum += plan.chunks[j].length;
    }
    expect_u64("plan max sum", sum, 2048u);

    st = ninlil_r7_frag_state_plan_validate(2048u, 1u, 13u, 180u);
    expect_st("S=1 => fc 13", st, NINLIL_R7_FRAG_STATE_OK);
    st = ninlil_r7_frag_state_plan_validate(2048u, 1u, 14u, 180u);
    expect_st("fc 14 reject", st, NINLIL_R7_FRAG_STATE_LENGTH);

    st = ninlil_r7_frag_state_plan_build(2049u, &plan);
    expect_st("plan oversize", st, NINLIL_R7_FRAG_STATE_LENGTH);

    st = ninlil_r7_frag_state_cont_geometry(400u, 126u, 3u, 1u, &off, &len);
    expect_st("geom1", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("geom1 off", off, 126u);
    expect_u64("geom1 len", len, 180u);
    st = ninlil_r7_frag_state_cont_geometry(400u, 126u, 3u, 2u, &off, &len);
    expect_st("geom2", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("geom2 off", off, 306u);
    expect_u64("geom2 len", len, 94u);
}

static void fill_start(
    ninlil_r7_frag_state_start_in *in,
    uint32_t ctx,
    uint64_t kgen,
    uint64_t handle,
    uint8_t tid_seed,
    const uint8_t *payload,
    uint32_t total,
    ninlil_r7_frag_state_plan *plan)
{
    memset(in, 0, sizeof(*in));
    ninlil_r7_frag_state_plan_build(total, plan);
    fill(in->transfer_id, 16u, tid_seed);
    in->e2e_context_id = ctx;
    in->key_generation = kgen;
    in->transfer_handle = handle;
    in->total_len = total;
    in->frag_count = plan->frag_count;
    in->continuation_unit = 180u;
    in->first_chunk = payload;
    in->first_chunk_len = plan->first_chunk_len;
    fake_digest(payload, total, in->content_digest);
    fake_fp(in, in->fingerprint);
}

static void test_reasm_happy_reorder_publish_once(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_cont_in cont;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[400];
    uint8_t digest[32];
    uint8_t pub[400];
    size_t pub_len = 0u;
    uint32_t pctx = 0u;
    uint64_t pk = 0u;
    uint64_t ph = 0u;
    ninlil_r7_frag_state_status st;
    uint16_t order[12];
    uint16_t ncont;
    uint16_t i;

    fill(payload, 400u, 0x10u);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1000u;
    fill_start(&start, 7u, 1u, 100u, 0x20u, payload, 400u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("start ok", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("partial", intent.status, NINLIL_R7_FRAG_STATE_STATUS_PARTIAL);

    /* Exact retry */
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("exact retry", st, NINLIL_R7_FRAG_STATE_EXACT_RETRY);

    /* Reorder CONT: reverse */
    ncont = (uint16_t)(plan.frag_count - 1u);
    for (i = 0u; i < ncont; i++) {
        order[i] = (uint16_t)(ncont - i);
    }
    for (i = 0u; i < ncont; i++) {
        uint16_t idx = order[i];
        memset(&cont, 0, sizeof(cont));
        cont.e2e_context_id = 7u;
        cont.key_generation = 1u;
        cont.transfer_handle = 100u;
        cont.frag_index = idx;
        cont.chunk = payload + plan.chunks[idx].offset;
        cont.chunk_len = plan.chunks[idx].length;
        if (i + 1u == ncont) {
            fake_digest(payload, 400u, digest);
            cont.reassembled_digest32 = digest;
        }
        st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
        expect_true("cont ok",
            st == NINLIL_R7_FRAG_STATE_OK
            || st == NINLIL_R7_FRAG_STATE_DUPLICATE);
    }
    expect_u64("complete", intent.status, NINLIL_R7_FRAG_STATE_STATUS_COMPLETE);

    st = ninlil_r7_frag_state_take_publication(
        &eng, &pctx, &pk, &ph, pub, sizeof(pub), &pub_len);
    expect_st("publish", st, NINLIL_R7_FRAG_STATE_PUBLISHED);
    expect_u64("pub len", pub_len, 400u);
    expect_true("pub bytes", memcmp(pub, payload, 400u) == 0);
    expect_u64("pub count", eng.publish_count, 1u);

    st = ninlil_r7_frag_state_take_publication(
        &eng, &pctx, &pk, &ph, pub, sizeof(pub), &pub_len);
    expect_st("publish once", st, NINLIL_R7_FRAG_STATE_NO_TRANSFER);
    expect_u64("pub count stick", eng.publish_count, 1u);

    ninlil_r7_frag_state_zeroize(&eng);
}

static void test_gap_dup_conflict(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_cont_in cont;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[400];
    uint8_t bad[180];
    ninlil_r7_frag_state_status st;

    fill(payload, 400u, 0x30u);
    fill(bad, 180u, 0xFFu);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1u;
    fill_start(&start, 1u, 1u, 200u, 0x40u, payload, 400u, &plan);
    expect_true("need fc>=3", plan.frag_count >= 3u);

    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("gap start", st, NINLIL_R7_FRAG_STATE_OK);

    /* Gap: CONT2 before CONT1 */
    memset(&cont, 0, sizeof(cont));
    cont.e2e_context_id = 1u;
    cont.key_generation = 1u;
    cont.transfer_handle = 200u;
    cont.frag_index = 2u;
    cont.chunk = payload + plan.chunks[2].offset;
    cont.chunk_len = plan.chunks[2].length;
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("ooo cont2", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("still partial", intent.status, NINLIL_R7_FRAG_STATE_STATUS_PARTIAL);

    /* CONT1 after CONT2 completes the transfer when fc==3. */
    {
        uint8_t digest[32];
        cont.frag_index = 1u;
        cont.chunk = payload + plan.chunks[1].offset;
        cont.chunk_len = plan.chunks[1].length;
        fake_digest(payload, 400u, digest);
        cont.reassembled_digest32 = digest;
        st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
        expect_st("cont1 complete", st, NINLIL_R7_FRAG_STATE_OK);
        expect_u64("gap complete", intent.status,
            NINLIL_R7_FRAG_STATE_STATUS_COMPLETE);
    }

    /* Clean conflict path without completing */
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1u;
    fill_start(&start, 1u, 1u, 201u, 0x41u, payload, 400u, &plan);
    ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    memset(&cont, 0, sizeof(cont));
    cont.e2e_context_id = 1u;
    cont.key_generation = 1u;
    cont.transfer_handle = 201u;
    cont.frag_index = 1u;
    cont.chunk = payload + plan.chunks[1].offset;
    cont.chunk_len = plan.chunks[1].length;
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("c1a", st, NINLIL_R7_FRAG_STATE_OK);
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("c1 dup", st, NINLIL_R7_FRAG_STATE_DUPLICATE);
    cont.chunk = bad;
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("c1 conflict", st, NINLIL_R7_FRAG_STATE_CONFLICT);

    /* CONT before START */
    ninlil_r7_frag_state_init(&eng);
    cont.transfer_handle = 999u;
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("cont before start", st, NINLIL_R7_FRAG_STATE_NO_TRANSFER);

    ninlil_r7_frag_state_zeroize(&eng);
}

static void test_resource_and_mixed_ctx(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[100];
    ninlil_r7_frag_state_status st;
    int k;

    fill(payload, 100u, 0x50u);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 10u;
    /* Fill slots respecting max 2 per e2e_context (peer). */
    for (k = 0; k < (int)NINLIL_R7_FRAG_STATE_REASM_SLOTS; k++) {
        uint32_t ctx = (uint32_t)(1u + (k / (int)NINLIL_R7_FRAG_STATE_MAX_PER_PEER));
        fill_start(
            &start, ctx, 1u, (uint64_t)(10u + k),
            (uint8_t)(0x60u + (k & 0x1f)), payload, 100u, &plan);
        st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
        expect_st("slot", st, NINLIL_R7_FRAG_STATE_OK);
    }
    fill_start(&start, 1u, 1u, 999u, 0x70u, payload, 100u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("exhaust", st, NINLIL_R7_FRAG_STATE_RESOURCE);

    /* Mixed context: same handle different e2e_context_id OK */
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1u;
    fill_start(&start, 10u, 1u, 1u, 0x80u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("ctxA", st, NINLIL_R7_FRAG_STATE_OK);
    fill_start(&start, 11u, 1u, 1u, 0x80u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("ctxB", st, NINLIL_R7_FRAG_STATE_OK);

    /* Same context 3rd transfer hits max_per_peer=2 */
    fill_start(&start, 10u, 1u, 2u, 0x82u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("peer max2", st, NINLIL_R7_FRAG_STATE_OK);
    fill_start(&start, 10u, 1u, 3u, 0x83u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("peer over", st, NINLIL_R7_FRAG_STATE_RESOURCE);

    /* Same context different generation on active handle => conflict */
    fill_start(&start, 11u, 2u, 1u, 0x81u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("kgen conflict", st, NINLIL_R7_FRAG_STATE_CONFLICT);

    ninlil_r7_frag_state_zeroize(&eng);
}

static void test_timeout_tombstone(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[50];
    ninlil_r7_frag_state_status st;

    fill(payload, 50u, 0x11u);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1000u;
    fill_start(&start, 2u, 1u, 77u, 0x22u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("to start", st, NINLIL_R7_FRAG_STATE_OK);
    st = ninlil_r7_frag_state_tick(&eng, 1000u + 20000u);
    expect_st("tick", st, NINLIL_R7_FRAG_STATE_OK);
    expect_true("reasm gone", eng.reasm[0].in_use == 0u);
    expect_true("tomb timeout",
        eng.tombs[0].in_use == 1u
        && eng.tombs[0].reason == NINLIL_R7_FRAG_STATE_REASON_TIMEOUT
        && eng.tombs[0].is_reservation == 0u);

    /* Exact retry of terminal */
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("tomb exact", st, NINLIL_R7_FRAG_STATE_EXACT_RETRY);
    expect_u64("tomb status", intent.status, NINLIL_R7_FRAG_STATE_STATUS_ABORT);

    ninlil_r7_frag_state_zeroize(&eng);
}

static void test_digest_fail_no_partial(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_cont_in cont;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[80];
    uint8_t bad_digest[32];
    uint8_t pub[80];
    size_t pub_len = 0u;
    uint32_t pctx;
    uint64_t pk, ph;
    ninlil_r7_frag_state_status st;
    uint16_t i;

    fill(payload, 80u, 0x90u);
    memset(bad_digest, 0xAAu, 32u);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 5u;
    fill_start(&start, 3u, 1u, 5u, 0x91u, payload, 80u, &plan);
    ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    for (i = 1u; i < plan.frag_count; i++) {
        memset(&cont, 0, sizeof(cont));
        cont.e2e_context_id = 3u;
        cont.key_generation = 1u;
        cont.transfer_handle = 5u;
        cont.frag_index = i;
        cont.chunk = payload + plan.chunks[i].offset;
        cont.chunk_len = plan.chunks[i].length;
        if (i + 1u == plan.frag_count) {
            cont.reassembled_digest32 = bad_digest;
        }
        st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    }
    expect_st("digest fail", st, NINLIL_R7_FRAG_STATE_DIGEST);
    expect_u64("abort digest", intent.status, NINLIL_R7_FRAG_STATE_STATUS_ABORT);
    st = ninlil_r7_frag_state_take_publication(
        &eng, &pctx, &pk, &ph, pub, sizeof(pub), &pub_len);
    expect_st("no pub on digest fail", st, NINLIL_R7_FRAG_STATE_NO_TRANSFER);
    expect_u64("pub count 0", eng.publish_count, 0u);

    ninlil_r7_frag_state_zeroize(&eng);
}

static void test_restart_classes(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_engine eng2;
    uint8_t snap[32];
    size_t slen = 0u;
    ninlil_r7_frag_state_status st;
    uint8_t buf[32];

    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 0x1122334455667788ull;
    eng.fenced = 0u;
    st = ninlil_r7_frag_state_restart_encode(&eng, snap, sizeof(snap), &slen);
    expect_st("enc", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("enc len", slen, 24u);

    st = ninlil_r7_frag_state_restart_decode(&eng2, snap, slen);
    expect_st("dec ok", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("now", eng2.now_mono, 0x1122334455667788ull);
    expect_true("empty reasm", eng2.reasm[0].in_use == 0u);
    expect_true("empty tomb", eng2.tombs[0].in_use == 0u);
    expect_true("empty pub", eng2.pub.valid == 0u);

    /* PARTIAL */
    st = ninlil_r7_frag_state_restart_decode(&eng2, snap, 10u);
    expect_st("partial", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);

    /* EXTRA */
    memcpy(buf, snap, 24u);
    buf[24] = 0xEEu;
    st = ninlil_r7_frag_state_restart_decode(&eng2, buf, 25u);
    expect_st("extra", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);

    /* OLD magic */
    memcpy(buf, snap, 24u);
    buf[0] ^= 0xFFu;
    st = ninlil_r7_frag_state_restart_decode(&eng2, buf, 24u);
    expect_st("old", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);

    /* NEW version */
    memcpy(buf, snap, 24u);
    buf[5] = 9u;
    st = ninlil_r7_frag_state_restart_decode(&eng2, buf, 24u);
    expect_st("new", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);

    /* THIRD: reasm_claim != 0 */
    memcpy(buf, snap, 24u);
    buf[7] = 1u;
    st = ninlil_r7_frag_state_restart_decode(&eng2, buf, 24u);
    expect_st("third", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);

    ninlil_r7_frag_state_zeroize(&eng);
    ninlil_r7_frag_state_zeroize(&eng2);
}

static void test_cu_classifier(void)
{
    ninlil_r7_frag_state_cu_entry e[2];
    ninlil_r7_frag_state_cu_result r;
    ninlil_r7_frag_state_status st;

    memset(e, 0, sizeof(e));
    e[0].old_present = 1u;
    e[0].proposed_present = 1u;
    e[0].key_len = 2u;
    e[0].key[0] = 1u;
    e[0].key[1] = 2u;
    e[0].old_len = 1u;
    e[0].old_bytes[0] = 0x0Au;
    e[0].proposed_len = 1u;
    e[0].proposed_bytes[0] = 0x0Bu;
    e[0].observed_status = 0u;
    e[0].observed_len = 1u;
    e[0].observed_bytes[0] = 0x0Bu;
    st = ninlil_r7_frag_state_cu_classify(e, 1u, &r);
    expect_st("cu prop", st, NINLIL_R7_FRAG_STATE_OK);
    expect_u64("ALL_PROPOSED", r.class_code, NINLIL_R7_FRAG_STATE_CU_ALL_PROPOSED);

    e[0].observed_bytes[0] = 0x0Au;
    st = ninlil_r7_frag_state_cu_classify(e, 1u, &r);
    expect_u64("ALL_OLD", r.class_code, NINLIL_R7_FRAG_STATE_CU_ALL_OLD);

    e[0].observed_bytes[0] = 0xFFu;
    st = ninlil_r7_frag_state_cu_classify(e, 1u, &r);
    expect_u64("THIRD", r.class_code, NINLIL_R7_FRAG_STATE_CU_THIRD);

    e[0].observed_bytes[0] = 0x0Bu;
    e[1] = e[0];
    e[1].key[0] = 9u;
    e[1].observed_bytes[0] = 0x0Au;
    st = ninlil_r7_frag_state_cu_classify(e, 2u, &r);
    expect_u64("MIXED THIRD", r.class_code, NINLIL_R7_FRAG_STATE_CU_THIRD);

    e[0].observed_status = 2u;
    st = ninlil_r7_frag_state_cu_classify(e, 1u, &r);
    expect_u64("RETRY", r.class_code, NINLIL_R7_FRAG_STATE_CU_RETRY_LATER);

    st = ninlil_r7_frag_state_cu_classify(e, 0u, &r);
    expect_u64("CORRUPT empty", r.class_code, NINLIL_R7_FRAG_STATE_CU_CORRUPT);

    /* COMMIT_UNKNOWN class name surface: THIRD is the ambiguous class */
    expect_true("COMMIT_UNKNOWN maps THIRD",
        NINLIL_R7_FRAG_STATE_CU_THIRD == 4u);
}

static void test_start_conflict_fingerprint(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[60];
    ninlil_r7_frag_state_status st;

    fill(payload, 60u, 0x01u);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1u;
    fill_start(&start, 5u, 1u, 1u, 0xAAu, payload, 60u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("s1", st, NINLIL_R7_FRAG_STATE_OK);

    /* Same handle, different transfer_id / fingerprint */
    fill_start(&start, 5u, 1u, 1u, 0xBBu, payload, 60u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("fp conflict", st, NINLIL_R7_FRAG_STATE_CONFLICT);

    ninlil_r7_frag_state_zeroize(&eng);
}

/*
 * Tombstone CONT must not regenerate terminal ACK for out-of-range frag_index
 * or wrong key_generation (docs audit: N6 replay consume + ACK false path).
 */
static void test_tombstone_cont_bounds_negative(void)
{
    static ninlil_r7_frag_state_engine eng;
    ninlil_r7_frag_state_plan plan;
    ninlil_r7_frag_state_start_in start;
    ninlil_r7_frag_state_cont_in cont;
    ninlil_r7_frag_state_ack_intent intent;
    uint8_t payload[50];
    ninlil_r7_frag_state_status st;

    fill(payload, 50u, 0x44u);
    ninlil_r7_frag_state_init(&eng);
    eng.now_mono = 1000u;
    fill_start(&start, 9u, 1u, 42u, 0x45u, payload, 50u, &plan);
    st = ninlil_r7_frag_state_admit_start(&eng, &start, &intent);
    expect_st("tb start", st, NINLIL_R7_FRAG_STATE_OK);
    /* Force terminal tombstone via idle timeout. */
    st = ninlil_r7_frag_state_tick(&eng, 1000u + 20000u);
    expect_st("tb tick", st, NINLIL_R7_FRAG_STATE_OK);
    expect_true("tb reasm empty", eng.reasm[0].in_use == 0u);
    expect_true("tb tomb live",
        eng.tombs[0].in_use == 1u && eng.tombs[0].is_reservation == 0u);

    memset(&intent, 0, sizeof(intent));
    memset(&cont, 0, sizeof(cont));
    cont.e2e_context_id = 9u;
    cont.key_generation = 1u;
    cont.transfer_handle = 42u;
    cont.frag_index = 0u; /* START index illegal on CONT tomb path */
    cont.chunk = payload;
    cont.chunk_len = 1u;
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("tb cont idx0 STRUCTURAL", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);
    expect_true("tb no intent idx0", intent.valid == 0u);

    cont.frag_index = plan.frag_count; /* == frag_count → OOR */
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("tb cont OOR STRUCTURAL", st, NINLIL_R7_FRAG_STATE_STRUCTURAL);
    expect_true("tb no intent OOR", intent.valid == 0u);

    cont.frag_index = 1u;
    cont.key_generation = 99u; /* wrong kgen */
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("tb cont kgen CONFLICT", st, NINLIL_R7_FRAG_STATE_CONFLICT);
    expect_true("tb no intent kgen", intent.valid == 0u);

    /* In-range + matching kgen may EXACT_RETRY terminal (not false publish). */
    cont.key_generation = 1u;
    cont.frag_index = 1u;
    st = ninlil_r7_frag_state_admit_cont(&eng, &cont, &intent);
    expect_st("tb cont exact retry", st, NINLIL_R7_FRAG_STATE_EXACT_RETRY);
    expect_true("tb intent terminal only",
        intent.valid == 1u
            && intent.status == NINLIL_R7_FRAG_STATE_STATUS_ABORT);
    expect_u64("tb no publish", eng.publish_count, 0u);

    ninlil_r7_frag_state_zeroize(&eng);
}

int main(void)
{
    test_plan_boundaries();
    test_reasm_happy_reorder_publish_once();
    test_gap_dup_conflict();
    test_resource_and_mixed_ctx();
    test_timeout_tombstone();
    test_digest_fail_no_partial();
    test_restart_classes();
    test_cu_classifier();
    test_start_conflict_fingerprint();
    test_tombstone_cont_bounds_negative();

    fprintf(stderr, "r7_frag_state_test: %d checks, %d failures\n",
        g_tests, g_failures);
    return g_failures == 0 ? 0 : 1;
}
