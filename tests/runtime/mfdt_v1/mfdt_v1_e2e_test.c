/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host E2E for private MFDT v1: min/max transfer, chunk boundaries, NRC1,
 * terminal retain+GC, abort/denied, crash inject, CU classifier pins.
 * Lab FULL store only — not power-cut HIL, not RF HIL.
 */
#include "mfdt_v1.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static uint8_t
    g_generation_nrc1_mutant[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];

static void recompute_nrc1_crc(uint8_t *record)
{
    ninlil_mfdt_v1_put_u32(
        record + 36u, ninlil_mfdt_v1_crc32c(record, 36u));
    ninlil_mfdt_v1_put_u32(
        record + NINLIL_MFDT_V1_NRC1_VALUE_BYTES - 4u,
        ninlil_mfdt_v1_crc32c(
            record, NINLIL_MFDT_V1_NRC1_VALUE_BYTES - 4u));
}

static void expect(int cond, const char *msg)
{
    if (!cond) {
        (void)fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void fill_tid(uint8_t tid[16], uint8_t tag)
{
    size_t i;
    for (i = 0; i < 16u; ++i) {
        tid[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void cfg_on(ninlil_mfdt_v1_config_t *cfg)
{
    ninlil_mfdt_v1_memzero(cfg, sizeof(*cfg));
    cfg->policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg->mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg->session_generation = 1u;
    cfg->mfdt_capability = 1u;
    cfg->session_generation = 1u;
    cfg->host_mode = 1u;
    cfg->retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    cfg->now_ms = 1000ull;
    (void)memset(cfg->local_clock_epoch.bytes, 0xc0, 16u);
}

static int build_deadline_open(uint8_t tid_tag, const uint8_t epoch[16],
                               uint64_t deadline_ms, uint8_t *open,
                               uint16_t *open_len)
{
    uint8_t tid[16];
    uint8_t content = 0x5au;
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t entries[40];
    uint8_t manifest[32];
    uint8_t whole[32];
    uint16_t entry_bytes = 0u;
    static const uint8_t ns[] = {'n'};
    static const uint8_t service[] = {'s'};
    static const uint8_t schema[] = {'x'};

    fill_tid(tid, tid_tag);
    (void)memset(&metadata, 0, sizeof(metadata));
    (void)memset(metadata.origin_transaction_id, 0x11,
                 sizeof(metadata.origin_transaction_id));
    if (deadline_ms == UINT64_MAX) {
        (void)memset(metadata.origin_event_id, 0x22,
                     sizeof(metadata.origin_event_id));
    }
    (void)memset(metadata.source_runtime_id, 0x33,
                 sizeof(metadata.source_runtime_id));
    (void)memset(metadata.target_runtime_id, 0x44,
                 sizeof(metadata.target_runtime_id));
    (void)memset(metadata.original_attempt_id, 0x55,
                 sizeof(metadata.original_attempt_id));
    (void)memset(metadata.source_application_instance_id, 0x66,
                 sizeof(metadata.source_application_instance_id));
    (void)memset(metadata.target_application_instance_id, 0x77,
                 sizeof(metadata.target_application_instance_id));
    ninlil_mfdt_v1_sha256(
        (const uint8_t *)"deadline-service", 16u,
        metadata.service_descriptor_digest);
    metadata.service_descriptor_revision = 1ull;
    if (epoch != NULL) {
        (void)memcpy(metadata.deadline_clock_epoch_id, epoch, 16u);
    }
    metadata.absolute_effect_deadline_ms = deadline_ms;
    metadata.service_schema_major = 1u;
    metadata.service_family = deadline_ms == UINT64_MAX ? 1u : 2u;
    metadata.application_generation = deadline_ms == UINT64_MAX ? 0ull : 1ull;
    metadata.required_evidence = 1u;
    metadata.namespace_bytes = ns;
    metadata.namespace_length = (uint16_t)sizeof(ns);
    metadata.service_bytes = service;
    metadata.service_length = (uint16_t)sizeof(service);
    metadata.schema_bytes = schema;
    metadata.schema_length = (uint16_t)sizeof(schema);
    return ninlil_mfdt_v1_encode_open(
        tid, 1u, &content, &metadata, open, open_len, entries, &entry_bytes,
        manifest, whole);
}

/* Run full sender→receiver transfer of content_len bytes (may be 0). */
static int run_transfer(uint32_t content_len, uint8_t tid_tag,
                        uint32_t session_generation, uint32_t *fulls_out)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    uint8_t content[32768];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t page[1024];
    uint8_t offer[1024];
    uint8_t fin[128];
    uint16_t open_len = 0u;
    uint16_t page_len = 0u;
    uint16_t offer_len = 0u;
    uint16_t fin_len = 0u;
    ninlil_mfdt_v1_response_t resp;
    ninlil_mfdt_v1_geometry_t geo;
    uint16_t p;
    uint16_t c;
    uint64_t rid = 1ull;
    int rc;

    cfg_on(&cfg);
    cfg.session_generation = session_generation;
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    if (ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) != NINLIL_MFDT_V1_OK) {
        return -1;
    }
    if (ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) != NINLIL_MFDT_V1_OK) {
        return -1;
    }
    fill_tid(tid, tid_tag);
    if (content_len > 0u) {
        uint32_t i;
        for (i = 0; i < content_len; ++i) {
            content[i] = (uint8_t)((i * 17u + tid_tag) & 0xffu);
        }
    }
    if (ninlil_mfdt_v1_geometry(content_len, &geo) != NINLIL_MFDT_V1_OK) {
        return -2;
    }
    rc = ninlil_mfdt_v1_sender_open(&tx, tid, content_len ? content : NULL,
                                    content_len, open, &open_len, rid);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -3;
    }
    rc = ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, rid, &resp);
    if (rc != NINLIL_MFDT_V1_OK ||
        resp.message_type != NINLIL_MFDT_V1_MSG_OPEN_ACCEPT) {
        return -4;
    }
    /* late-dup same request_id */
    {
        ninlil_mfdt_v1_response_t r2;
        rc = ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, rid, &r2);
        if (rc != NINLIL_MFDT_V1_OK || r2.from_nrc1_hit != 1u) {
            return -5;
        }
    }
    rc = ninlil_mfdt_v1_sender_on_open_accept(&tx, resp.body, resp.body_len, rid);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -6;
    }
    for (p = 0; p < geo.page_count; ++p) {
        rid += 1ull;
        rc = ninlil_mfdt_v1_sender_offer_page(&tx, p, rid, page, &page_len);
        if (rc != NINLIL_MFDT_V1_OK) {
            return -10;
        }
        rc = ninlil_mfdt_v1_receiver_on_page(&rx, page, page_len, rid, &resp);
        if (rc != NINLIL_MFDT_V1_OK ||
            resp.message_type != NINLIL_MFDT_V1_MSG_PAGE_ACCEPT) {
            return -11;
        }
        rc = ninlil_mfdt_v1_sender_on_page_accept(&tx, resp.body, resp.body_len, rid);
        if (rc != NINLIL_MFDT_V1_OK) {
            return -12;
        }
    }
    for (c = 0; c < geo.chunk_count; ++c) {
        rid += 1ull;
        rc = ninlil_mfdt_v1_sender_offer_chunk(&tx, c, rid, offer, &offer_len);
        if (rc != NINLIL_MFDT_V1_OK) {
            return -20;
        }
        /* reorder: for multi-chunk, send reverse on second half of test via
         * separate case; here sequential. */
        rc = ninlil_mfdt_v1_receiver_on_chunk(&rx, offer, offer_len, rid, &resp);
        if (rc != NINLIL_MFDT_V1_OK ||
            resp.message_type != NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT) {
            return -21;
        }
        rc = ninlil_mfdt_v1_sender_on_chunk_accept(&tx, resp.body, resp.body_len, rid);
        if (rc != NINLIL_MFDT_V1_OK) {
            return -22;
        }
    }
    rid += 1ull;
    rc = ninlil_mfdt_v1_sender_finalize(&tx, rid, fin, &fin_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -30;
    }
    rc = ninlil_mfdt_v1_receiver_on_finalize(&rx, fin, fin_len, rid, &resp);
    if (rc != NINLIL_MFDT_V1_OK ||
        resp.message_type != NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT) {
        return -31;
    }
    rc = ninlil_mfdt_v1_sender_on_transfer_accept(&tx, resp.body, resp.body_len, rid);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -32;
    }
    rc = ninlil_mfdt_v1_receiver_complete_handoff(&rx);
    if (rc != NINLIL_MFDT_V1_OK || !rx.handoff_complete) {
        return -33;
    }
    rc = ninlil_mfdt_v1_terminal_complete(&rx);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -34;
    }
    rc = ninlil_mfdt_v1_terminal_complete(&tx);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -35;
    }
    /* post-terminal NRC1 hit for finalize request_id */
    {
        ninlil_mfdt_v1_response_t late;
        uint8_t dig[32];
        ninlil_mfdt_v1_request_body_digest(NINLIL_MFDT_V1_MSG_FINALIZE, fin,
                                           fin_len, dig);
        rc = ninlil_mfdt_v1_nrc1_lookup(&rx, tid, rid, dig, &late);
        if (rc != NINLIL_MFDT_V1_OK || late.from_nrc1_hit != 1u) {
            return -36;
        }
    }
    /* retention GC → expired */
    ninlil_mfdt_v1_engine_set_now(
        &rx, 1000ull + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT - 1ull);
    rc = ninlil_mfdt_v1_retention_gc(&rx);
    if (rc != NINLIL_MFDT_V1_ERR_STATE) {
        return -37;
    }
    ninlil_mfdt_v1_engine_set_now(
        &rx, 1000ull + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT);
    rc = ninlil_mfdt_v1_retention_gc(&rx);
    if (rc != NINLIL_MFDT_V1_OK) {
        return -41;
    }
    {
        ninlil_mfdt_v1_response_t expired;
        rc = ninlil_mfdt_v1_nrc1_lookup(&rx, tid, rid, NULL, &expired);
        if (rc != NINLIL_MFDT_V1_ERR_EXPIRED) {
            return -38;
        }
    }
    if (fulls_out != NULL) {
        *fulls_out = rst.full_count;
    }
    /* wear bound: receiver FULLs must stay under max 77 */
    if (rst.full_count > NINLIL_MFDT_V1_RECEIVER_FULLS_MAX) {
        return -39;
    }
    if (tst.full_count > NINLIL_MFDT_V1_SENDER_FULLS_MAX) {
        return -40;
    }
    return 0;
}

static void test_min_max_boundaries(void)
{
    uint32_t fulls = 0u;
    int rc;
    rc = run_transfer(0u, 0x10u, 1u, &fulls);
    expect(rc == 0, "empty transfer");
    rc = run_transfer(1u, 0x20u, 1u, &fulls);
    expect(rc == 0, "one-byte transfer");
    rc = run_transfer(896u, 0x30u, 1u, &fulls);
    expect(rc == 0, "exact one chunk");
    rc = run_transfer(897u, 0x40u, 1u, &fulls);
    expect(rc == 0, "chunk+1");
    rc = run_transfer(22u * 896u, 0x50u, 1u, &fulls);
    expect(rc == 0, "exact one page of chunks");
    rc = run_transfer(22u * 896u + 1u, 0x60u, 1u, &fulls);
    expect(rc == 0, "page boundary +1");
    rc = run_transfer(32768u, 0x70u, 1u, &fulls);
    expect(rc == 0, "max transfer 32768");
    rc = run_transfer(1u, 0x80u, 7u, &fulls);
    expect(rc == 0, "arbitrary non-zero session generation full transfer");
}

static void test_abort_denied(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    uint8_t content[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t page[256];
    uint8_t offer[1024];
    uint8_t abortb[80];
    uint16_t open_len = 0u;
    uint16_t page_len = 0u;
    uint16_t offer_len = 0u;
    ninlil_mfdt_v1_response_t resp;
    uint64_t rid = 1ull;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == NINLIL_MFDT_V1_OK,
           "ab init tx");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == NINLIL_MFDT_V1_OK,
           "ab init rx");
    fill_tid(tid, 0xAAu);
    (void)memset(content, 0x5a, sizeof(content));
    expect(ninlil_mfdt_v1_sender_open(&tx, tid, content, 16u, open, &open_len,
                                      rid) == NINLIL_MFDT_V1_OK,
           "ab open");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ab ropen");
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, resp.body, resp.body_len, rid) ==
               NINLIL_MFDT_V1_OK,
           "ab oacc");
    /* abort mid-manifest allowed */
    rid = 2ull;
    ninlil_mfdt_v1_memzero(abortb, sizeof(abortb));
    ninlil_mfdt_v1_bind52(tid, ninlil_mfdt_v1_get_u32(open + 16),
                          open + 202, abortb);
    ninlil_mfdt_v1_put_u16(
        abortb + 52, NINLIL_MFDT_V1_TERM_REASON_OPERATOR);
    (void)memset(abortb + 56, 0xa5, 16u);
    ninlil_mfdt_v1_put_u32(abortb + 72, 1u);
    expect(ninlil_mfdt_v1_receiver_on_abort(&rx, abortb, 76u, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ab ok");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_ABORT_ACK, "ab ack");

    /* fresh transfer then deny abort after content verified */
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == NINLIL_MFDT_V1_OK,
           "ab2 tx");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == NINLIL_MFDT_V1_OK,
           "ab2 rx");
    fill_tid(tid, 0xBBu);
    rid = 1ull;
    expect(ninlil_mfdt_v1_sender_open(&tx, tid, content, 16u, open, &open_len,
                                      rid) == NINLIL_MFDT_V1_OK,
           "ab2 open");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ab2 ropen");
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, resp.body, resp.body_len, rid) ==
               NINLIL_MFDT_V1_OK,
           "ab2 oacc");
    rid = 2ull;
    expect(ninlil_mfdt_v1_sender_offer_page(&tx, 0u, rid, page, &page_len) ==
               NINLIL_MFDT_V1_OK,
           "ab2 page");
    expect(ninlil_mfdt_v1_receiver_on_page(&rx, page, page_len, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ab2 rpage");
    expect(ninlil_mfdt_v1_sender_on_page_accept(&tx, resp.body, resp.body_len, rid) ==
               NINLIL_MFDT_V1_OK,
           "ab2 pacc");
    rid = 3ull;
    expect(ninlil_mfdt_v1_sender_offer_chunk(&tx, 0u, rid, offer, &offer_len) ==
               NINLIL_MFDT_V1_OK,
           "ab2 chunk");
    expect(ninlil_mfdt_v1_receiver_on_chunk(&rx, offer, offer_len, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ab2 rchunk");
    expect(rx.publication_ready == 1u, "content verified");
    rid = 4ull;
    ninlil_mfdt_v1_memzero(abortb, sizeof(abortb));
    ninlil_mfdt_v1_bind52(tid, ninlil_mfdt_v1_get_u32(open + 16),
                          open + 202, abortb);
    ninlil_mfdt_v1_put_u16(
        abortb + 52, NINLIL_MFDT_V1_TERM_REASON_OPERATOR);
    (void)memset(abortb + 56, 0xa5, 16u);
    ninlil_mfdt_v1_put_u32(abortb + 72, 1u);
    expect(ninlil_mfdt_v1_receiver_on_abort(&rx, abortb, 76u, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ab denied path returns");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_REJECT, "ab denied reject");
    expect(resp.reject_code == NINLIL_MFDT_V1_REJ_ABORT_DENIED ||
               ninlil_mfdt_v1_get_u16(resp.body + 54) ==
                   NINLIL_MFDT_V1_REJ_ABORT_DENIED,
           "ab denied code");
}

static void test_crash_inject(void)
{
    ninlil_mfdt_v1_engine_t eng;
    ninlil_mfdt_v1_workspace_t ws;
    ninlil_mfdt_v1_lab_store_t st;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t olen = 0u;
    uint8_t key[20];
    uint32_t len = 0u;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &st, &cfg) == NINLIL_MFDT_V1_OK,
           "cr init");
    fill_tid(tid, 0xCCu);
    /* sender open FULL succeeds (crash inject off) */
    expect(ninlil_mfdt_v1_sender_open(&eng, tid, (const uint8_t *)"x", 1u, open,
                                      &olen, 1ull) == NINLIL_MFDT_V1_OK,
           "cr open1");
    {
        ninlil_mfdt_v1_engine_t rx;
        ninlil_mfdt_v1_workspace_t rws;
        ninlil_mfdt_v1_lab_store_t rst;
        ninlil_mfdt_v1_response_t resp;
        ninlil_mfdt_v1_lab_store_init(&rst);
        /* Co-located G_R_OPEN = one multi-key FULL (NM3R+NRC1). Fail that FULL
         * before apply so neither key is visible (ADR mutation+NRC1 co-FULL). */
        rst.crash_after_fulls = 1u;
        rst.full_count = 1u; /* next commit: full_count+1 > 1 ⇒ crash */
        expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
                   NINLIL_MFDT_V1_OK,
               "cr rx");
        expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, olen, 1ull, &resp) ==
                   NINLIL_MFDT_V1_ERR_STORAGE,
               "cr inject co-FULL");
        expect(rst.crash_armed == 1u, "cr armed");
        (void)memcpy(key, "NM3R", 4u);
        (void)memcpy(key + 4, open, 16u);
        expect(ninlil_mfdt_v1_lab_get(&rst, key, NULL, 0u, &len) !=
                   NINLIL_MFDT_V1_OK,
               "cr no NM3R after failed co-FULL");
        (void)memcpy(key, "NRC1", 4u);
        (void)memcpy(key + 4, open, 16u);
        expect(ninlil_mfdt_v1_lab_get(&rst, key, NULL, 0u, &len) !=
                   NINLIL_MFDT_V1_OK,
               "cr no NRC1 after failed co-FULL");
    }
}

static void test_digest_conflict(void)
{
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_lab_store_t tst;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t olen = 0u;
    ninlil_mfdt_v1_response_t resp;
    uint8_t open2[NINLIL_MFDT_V1_OPEN_BODY_MAX];

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0xDDu);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == NINLIL_MFDT_V1_OK,
           "dc tx");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == NINLIL_MFDT_V1_OK,
           "dc rx");
    expect(ninlil_mfdt_v1_sender_open(&tx, tid, (const uint8_t *)"a", 1u, open,
                                      &olen, 1ull) == NINLIL_MFDT_V1_OK,
           "dc open");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, olen, 1ull, &resp) ==
               NINLIL_MFDT_V1_OK,
           "dc ropen");
    /* same request_id, different body (digest-only; geometry fields intact) */
    (void)memcpy(open2, open, olen);
    open2[32] ^= 0x01u; /* flip whole_digest byte — layout still valid */
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open2, olen, 1ull, &resp) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "dc conflict");
}

static void test_reorder_chunks(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    /* Exactly two full chunks (reorder without partial publish). */
    uint8_t content[1792];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t page[1024];
    uint8_t o0[1024];
    uint8_t o1[1024];
    uint8_t fin[128];
    uint16_t open_len = 0u, page_len = 0u, l0 = 0u, l1 = 0u, fin_len = 0u;
    ninlil_mfdt_v1_response_t resp;
    uint32_t i;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    for (i = 0; i < sizeof(content); ++i) {
        content[i] = (uint8_t)(i & 0xffu);
    }
    fill_tid(tid, 0xEEu);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == NINLIL_MFDT_V1_OK,
           "ro tx");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == NINLIL_MFDT_V1_OK,
           "ro rx");
    expect(ninlil_mfdt_v1_sender_open(&tx, tid, content, (uint32_t)sizeof(content),
                                      open, &open_len, 1ull) == NINLIL_MFDT_V1_OK,
           "ro open");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, 1ull, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ro ropen");
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, resp.body, resp.body_len,
                                                1ull) == NINLIL_MFDT_V1_OK,
           "ro oacc");
    expect(ninlil_mfdt_v1_sender_offer_page(&tx, 0u, 2ull, page, &page_len) ==
               NINLIL_MFDT_V1_OK,
           "ro page");
    expect(ninlil_mfdt_v1_receiver_on_page(&rx, page, page_len, 2ull, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ro rpage");
    expect(ninlil_mfdt_v1_sender_on_page_accept(&tx, resp.body, resp.body_len,
                                                2ull) == NINLIL_MFDT_V1_OK,
           "ro pacc");
    /* Fairness: one unpaid CHUNK_OFFER. Encode both via wire API so receiver
     * sees network-reordered delivery without violating sender quantum. */
    {
        uint8_t md[32];
        (void)memcpy(md, open + 202, 32u);
        expect(ninlil_mfdt_v1_encode_chunk_offer(tid, 1u, md, 0u, 2u, 0u, 896u,
                                                 content, o0, &l0) == 0,
               "ro enc0");
        expect(ninlil_mfdt_v1_encode_chunk_offer(tid, 1u, md, 1u, 2u, 896u, 896u,
                                                 content + 896, o1, &l1) == 0,
               "ro enc1");
    }
    /* deliver chunk 1 before chunk 0 */
    expect(ninlil_mfdt_v1_receiver_on_chunk(&rx, o1, l1, 4ull, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ro r1 first");
    expect(rx.publication_ready == 0u, "no partial publish after 1/2");
    expect(ninlil_mfdt_v1_receiver_on_chunk(&rx, o0, l0, 3ull, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ro r0 second");
    expect(rx.publication_ready == 1u, "publish only when complete");
    /* Sender sequential offer/accept (fairness) then finalize. */
    {
        ninlil_mfdt_v1_response_t a0;
        ninlil_mfdt_v1_response_t a1;
        expect(ninlil_mfdt_v1_sender_offer_chunk(&tx, 0u, 3ull, o0, &l0) ==
                   NINLIL_MFDT_V1_OK,
               "ro s offer0");
        /* receiver already has chunk0; same body late-dup is NRC1 hit */
        expect(ninlil_mfdt_v1_receiver_on_chunk(&rx, o0, l0, 3ull, &a0) ==
                   NINLIL_MFDT_V1_OK,
               "ro hit0");
        expect(a0.from_nrc1_hit == 1u, "ro hit0 nrc1");
        expect(ninlil_mfdt_v1_sender_on_chunk_accept(&tx, a0.body, a0.body_len, 3ull) ==
                   NINLIL_MFDT_V1_OK,
               "ro sacc0");
        expect(ninlil_mfdt_v1_sender_offer_chunk(&tx, 1u, 4ull, o1, &l1) ==
                   NINLIL_MFDT_V1_OK,
               "ro s offer1");
        expect(ninlil_mfdt_v1_receiver_on_chunk(&rx, o1, l1, 4ull, &a1) ==
                   NINLIL_MFDT_V1_OK,
               "ro hit1");
        expect(a1.from_nrc1_hit == 1u, "ro hit1 nrc1");
        expect(ninlil_mfdt_v1_sender_on_chunk_accept(&tx, a1.body, a1.body_len, 4ull) ==
                   NINLIL_MFDT_V1_OK,
               "ro sacc1");
    }
    expect(ninlil_mfdt_v1_sender_finalize(&tx, 5ull, fin, &fin_len) ==
               NINLIL_MFDT_V1_OK,
           "ro fin");
    expect(ninlil_mfdt_v1_receiver_on_finalize(&rx, fin, fin_len, 5ull, &resp) ==
               NINLIL_MFDT_V1_OK,
           "ro rfin");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT, "ro accept");
}

/*
 * P0: open_accept wire min = 100; trunc 16..99 reject before +52 memcpy;
 * BIND52 (TID/revision/digest) mismatch leaves durable state invariant.
 */
static void test_open_accept_wire_min_and_bind52(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_active_snapshot_t snap0;
    ninlil_mfdt_v1_active_snapshot_t snap1;
    ninlil_mfdt_v1_response_t resp;
    uint8_t tid[16];
    uint8_t content[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t trunc[100];
    uint8_t mut[128];
    uint16_t open_len = 0u;
    uint16_t L;
    uint64_t rid = 1ull;
    uint64_t gen0 = 0ull;
    uint8_t state0 = 0u;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0x71u);
    (void)memset(content, 0x3c, sizeof(content));
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == NINLIL_MFDT_V1_OK,
           "oa tx");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == NINLIL_MFDT_V1_OK,
           "oa rx");
    expect(ninlil_mfdt_v1_sender_open(&tx, tid, content, 16u, open, &open_len,
                                      rid) == NINLIL_MFDT_V1_OK,
           "oa open");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, rid, &resp) ==
               NINLIL_MFDT_V1_OK,
           "oa ropen");
    expect(resp.body_len >= 100u, "oa accept wire min");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx, &snap0) == 0, "oa snap0");
    gen0 = snap0.record_generation;
    state0 = snap0.state_code;
    expect(state0 == NINLIL_MFDT_V1_S_OPEN_PENDING, "oa pending");

    /* Trunc mutations 16..99: exact wire minimum is 100. */
    for (L = 16u; L < 100u; ++L) {
        (void)memset(trunc, 0, sizeof(trunc));
        (void)memcpy(trunc, resp.body, L);
        expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, trunc, L, rid) ==
                   NINLIL_MFDT_V1_ERR_LAYOUT,
               "oa trunc layout");
        expect(ninlil_mfdt_v1_engine_active_snapshot(&tx, &snap1) == 0,
               "oa snap trunc");
        expect(snap1.record_generation == gen0, "oa gen stable trunc");
        expect(snap1.state_code == state0, "oa state stable trunc");
    }

    /* BIND52 TID mutation: full-length body, wrong transfer_id. */
    (void)memcpy(mut, resp.body, resp.body_len);
    mut[0] ^= 0x01u;
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, mut, resp.body_len, rid) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "oa bad tid");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx, &snap1) == 0, "oa snap tid");
    expect(snap1.record_generation == gen0 && snap1.state_code == state0,
           "oa tid invariant");

    /* Revision mutation at body[16..19]. */
    (void)memcpy(mut, resp.body, resp.body_len);
    mut[16] ^= 0x01u;
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, mut, resp.body_len, rid) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "oa bad rev");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx, &snap1) == 0, "oa snap rev");
    expect(snap1.record_generation == gen0 && snap1.state_code == state0,
           "oa rev invariant");

    /* Manifest digest mutation at body[20..51]. */
    (void)memcpy(mut, resp.body, resp.body_len);
    mut[20] ^= 0x01u;
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, mut, resp.body_len, rid) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "oa bad dig");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx, &snap1) == 0, "oa snap dig");
    expect(snap1.record_generation == gen0 && snap1.state_code == state0,
           "oa dig invariant");

    /* Good accept advances. */
    expect(ninlil_mfdt_v1_sender_on_open_accept(&tx, resp.body, resp.body_len,
                                                rid) == NINLIL_MFDT_V1_OK,
           "oa good");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx, &snap1) == 0, "oa snap ok");
    expect(snap1.state_code == NINLIL_MFDT_V1_S_OPEN_ACCEPTED, "oa accepted");
    expect(snap1.record_generation == gen0 + 1ull, "oa gen +1");
}

/*
 * An ESP-style COMMIT_UNKNOWN whose read-back is exact NEW is not externally
 * promotable while the physical FULL-attestation gate is OFF.  A same-ID
 * retry must not turn the durable NRC1 entry into a wire success and thereby
 * bypass the gate.
 */
static void test_cu_new_nrc1_retry_stays_unpromoted(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t resp;
    uint8_t tid[16];
    uint8_t content[1] = {0x5au};
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    int rc;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0x91u);
    cfg.host_mode = 0u; /* ESP target profile, not Host FULL-capable */
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "cu retry tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "cu retry rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, content, sizeof(content), open, &open_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "cu retry sender open");
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0,
           "cu retry gate off");

    rst.force_cu_new_not_promoted = 1u;
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 1ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "cu retry first response not promoted");

    (void)memset(&resp, 0, sizeof(resp));
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 1ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "cu retry cached response remains unpromoted");
    expect(resp.from_nrc1_hit == 0u,
           "cu retry no cached wire response while gate off");

    /* Cold process: only durable active+NRC1 survives. Profile-wide target
     * replay denial must not depend on the volatile CU latch. */
    (void)memset(&rx, 0xa5, sizeof(rx));
    (void)memset(&rws, 0x5a, sizeof(rws));
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "cu retry cold init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&rx, tid, 2u) ==
               NINLIL_MFDT_V1_OK,
           "cu retry cold active scan");
    (void)memset(&resp, 0, sizeof(resp));
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 1ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "cu retry cold cached response remains unpromoted");
    expect(resp.from_nrc1_hit == 0u && resp.body_len == 0u,
           "cu retry cold no wire response");
}

/*
 * NRC1-only FULL (no active mutation) has the same unattested target boundary.
 * Host STORAGE_OK replay remains functional across a real engine reinit.
 */
static void test_nrc1_only_target_and_host_restart_profiles(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t resp;
    uint8_t tid[16];
    uint8_t content[1] = {0x6bu};
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    int rc;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0xa1u);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only host rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, content, sizeof(content), open, &open_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only sender open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 1ull, &resp) == NINLIL_MFDT_V1_OK,
           "nrc-only initial host full");

    /* Rehydrate as actual target profile, then make a new request-id whose
     * first body only appends NRC1 (active record is unchanged). */
    cfg.host_mode = 0u;
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only target init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&rx, tid, 2u) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only target scan");
    rst.force_cu_new_not_promoted = 1u;
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 2ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "nrc-only first response not promoted");
    (void)memset(&resp, 0, sizeof(resp));
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 2ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "nrc-only warm retry not promoted");
    expect(resp.from_nrc1_hit == 0u && resp.body_len == 0u,
           "nrc-only warm no wire response");

    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only target cold init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&rx, tid, 2u) ==
               NINLIL_MFDT_V1_OK,
           "nrc-only target cold scan");
    (void)memset(&resp, 0, sizeof(resp));
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 2ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "nrc-only cold retry not promoted");
    expect(resp.from_nrc1_hit == 0u && resp.body_len == 0u,
           "nrc-only cold no wire response");

    /* Independent Host FULL-capable store: both active+NRC1 and NRC1-only
     * cached responses remain bit-exact after cold process restart. */
    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0xb1u);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "host replay tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "host replay rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, content, sizeof(content), open, &open_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "host replay sender open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 1ull, &resp) == NINLIL_MFDT_V1_OK,
           "host replay active+nrc1 full");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 2ull, &resp) == NINLIL_MFDT_V1_OK,
           "host replay nrc1-only full");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "host replay cold init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&rx, tid, 2u) ==
               NINLIL_MFDT_V1_OK,
           "host replay cold scan");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 1ull, &resp) == NINLIL_MFDT_V1_OK &&
               resp.from_nrc1_hit == 1u,
           "host replay active+nrc1 hit");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 2ull, &resp) == NINLIL_MFDT_V1_OK &&
               resp.from_nrc1_hit == 1u,
           "host replay nrc1-only hit");
}

/* Post-terminal retained NM30+NRC1 is also a cold-start replay boundary. */
static void test_post_terminal_target_replay_stays_unpromoted(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t resp;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t fin[128];
    uint16_t open_len = 0u;
    uint16_t fin_len = 0u;
    int rc;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0xc1u);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "terminal tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "terminal rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, NULL, 0u, open, &open_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "terminal empty open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 1ull, &resp) == NINLIL_MFDT_V1_OK,
           "terminal empty accept");
    expect(ninlil_mfdt_v1_sender_on_open_accept(
               &tx, resp.body, resp.body_len, 1ull) == NINLIL_MFDT_V1_OK,
           "terminal sender open accept");
    expect(ninlil_mfdt_v1_sender_finalize(
               &tx, 2ull, fin, &fin_len) == NINLIL_MFDT_V1_OK,
           "terminal finalize");
    expect(ninlil_mfdt_v1_receiver_on_finalize(
               &rx, fin, fin_len, 2ull, &resp) == NINLIL_MFDT_V1_OK,
           "terminal receiver finalize");
    expect(ninlil_mfdt_v1_receiver_complete_handoff(&rx) ==
               NINLIL_MFDT_V1_OK,
           "terminal handoff");
    expect(ninlil_mfdt_v1_terminal_complete(&rx) == NINLIL_MFDT_V1_OK,
           "terminal NM30+NRC1");

    cfg.host_mode = 0u;
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "terminal target cold init");
    (void)memset(&resp, 0, sizeof(resp));
    rc = ninlil_mfdt_v1_receiver_on_open(
        &rx, open, open_len, 1ull, &resp);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN,
           "terminal target cached response not promoted");
    expect(resp.from_nrc1_hit == 0u && resp.body_len == 0u,
           "terminal target no wire response");

    cfg.host_mode = 1u;
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "terminal host cold init");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 1ull, &resp) == NINLIL_MFDT_V1_OK &&
               resp.from_nrc1_hit == 1u,
           "terminal host retained replay");
}

/*
 * A Host profile advertises four coordinator slots, not four slots inside one
 * engine.  A second transfer presented to an occupied engine must be rejected
 * without combining its manifest with the incumbent reservation.
 */
static void test_host_single_engine_rejects_cross_transfer_open(void)
{
    ninlil_mfdt_v1_engine_t tx1;
    ninlil_mfdt_v1_engine_t tx2;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws1;
    ninlil_mfdt_v1_workspace_t tws2;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst1;
    ninlil_mfdt_v1_lab_store_t tst2;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t first;
    ninlil_mfdt_v1_response_t second;
    ninlil_mfdt_v1_response_t replay;
    uint8_t tid1[16];
    uint8_t tid2[16];
    uint8_t open1[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t open2[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t key[20];
    uint16_t open1_len = 0u;
    uint16_t open2_len = 0u;
    uint32_t before_len = 0u;
    uint32_t after_len = 0u;
    uint32_t fulls_before;
    static uint8_t before[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
    static uint8_t after[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst1);
    ninlil_mfdt_v1_lab_store_init(&tst2);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid1, 0xd1u);
    fill_tid(tid2, 0xe1u);
    expect(ninlil_mfdt_v1_engine_init(&tx1, &tws1, &tst1, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "single engine tx1 init");
    expect(ninlil_mfdt_v1_engine_init(&tx2, &tws2, &tst2, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "single engine tx2 init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "single engine rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx1, tid1, (const uint8_t *)"a", 1u, open1, &open1_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "single engine first sender open");
    expect(ninlil_mfdt_v1_sender_open(
               &tx2, tid2, (const uint8_t *)"b", 1u, open2, &open2_len, 2ull) ==
               NINLIL_MFDT_V1_OK,
           "single engine second sender open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open1, open1_len, 1ull, &first) == NINLIL_MFDT_V1_OK,
           "single engine first receiver open");
    (void)memcpy(key, "NM3R", 4u);
    (void)memcpy(key + 4u, tid1, 16u);
    expect(ninlil_mfdt_v1_lab_get(
               &rst, key, before, sizeof(before), &before_len) ==
               NINLIL_MFDT_V1_OK,
           "single engine incumbent snapshot");
    fulls_before = rst.full_count;

    (void)memset(&second, 0, sizeof(second));
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open2, open2_len, 2ull, &second) ==
               NINLIL_MFDT_V1_ERR_CAPACITY,
           "single engine cross transfer capacity");
    expect(second.message_type == NINLIL_MFDT_V1_MSG_BUSY &&
               second.reject_code == NINLIL_MFDT_V1_REJ_CAPACITY &&
               second.state_mutation == 0u && second.full_count == 0u,
           "single engine cross transfer busy no mutation");
    expect(rst.full_count == fulls_before,
           "single engine cross transfer no FULL");
    expect(ninlil_mfdt_v1_lab_get(
               &rst, key, after, sizeof(after), &after_len) ==
               NINLIL_MFDT_V1_OK &&
               after_len == before_len &&
               ninlil_mfdt_v1_memeq(before, after, before_len),
           "single engine incumbent durable bytes unchanged");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open1, open1_len, 1ull, &replay) == NINLIL_MFDT_V1_OK &&
               replay.from_nrc1_hit == 1u &&
               replay.body_len == first.body_len &&
               ninlil_mfdt_v1_memeq(replay.body, first.body, first.body_len),
           "single engine incumbent replay intact");
}

static void test_caller_metadata_roundtrip_and_restart(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_open_metadata_t metadata;
    ninlil_mfdt_v1_response_t resp;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t replay[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t content[3] = {0xa1u, 0xb2u, 0xc3u};
    uint16_t open_len = 0u;
    uint16_t replay_len = 0u;
    static const uint8_t ns[] = "field.ops-1";
    static const uint8_t service[] = "display_text-v2";
    static const uint8_t schema[] = "utf8_chunk.v1";
    size_t i;

    cfg_on(&cfg);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0x51u);
    (void)memset(&metadata, 0, sizeof(metadata));
    for (i = 0u; i < 16u; ++i) {
        metadata.origin_transaction_id[i] = (uint8_t)(0x10u + i);
        metadata.source_runtime_id[i] = (uint8_t)(0x50u + i);
        metadata.target_runtime_id[i] = (uint8_t)(0x70u + i);
        metadata.original_attempt_id[i] = (uint8_t)(0x30u + i);
        metadata.source_application_instance_id[i] =
            (uint8_t)(0x90u + i);
        metadata.target_application_instance_id[i] =
            (uint8_t)(0xb0u + i);
        metadata.deadline_clock_epoch_id[i] =
            cfg.local_clock_epoch.bytes[i];
    }
    metadata.service_descriptor_revision = 0x0102030405060708ull;
    ninlil_mfdt_v1_sha256(
        (const uint8_t *)"caller-service-descriptor", 25u,
        metadata.service_descriptor_digest);
    metadata.namespace_bytes = ns;
    metadata.namespace_length = (uint16_t)(sizeof(ns) - 1u);
    metadata.service_bytes = service;
    metadata.service_length = (uint16_t)(sizeof(service) - 1u);
    metadata.schema_bytes = schema;
    metadata.schema_length = (uint16_t)(sizeof(schema) - 1u);
    metadata.absolute_effect_deadline_ms = cfg.now_ms + 1234ull;
    metadata.service_schema_major = 1u;
    metadata.service_schema_minor = 2u;
    metadata.service_family = 2u;
    metadata.application_generation = 7ull;
    metadata.required_evidence = 3u;

    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "metadata tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "metadata rx init");
    expect(ninlil_mfdt_v1_sender_open_with_metadata(
               &tx, tid, content, sizeof(content), &metadata, open, &open_len,
               71ull) == NINLIL_MFDT_V1_OK,
           "metadata sender open");
    expect(open_len == NINLIL_MFDT_V1_OPEN_TEXT_OFFSET +
                           metadata.namespace_length +
                           metadata.service_length + metadata.schema_length,
           "metadata open length");
    expect(ninlil_mfdt_v1_memeq(
               open + 64u, metadata.origin_transaction_id, 16u) &&
               ninlil_mfdt_v1_memeq(
                   open + 80u, metadata.origin_event_id, 16u) &&
               ninlil_mfdt_v1_memeq(
                   open + 96u, metadata.source_runtime_id, 16u) &&
               ninlil_mfdt_v1_memeq(
                   open + 112u, metadata.target_runtime_id, 16u),
           "metadata identity exact");
    expect(ninlil_mfdt_v1_get_u64(open + 128u) ==
                   metadata.service_descriptor_revision &&
               ninlil_mfdt_v1_memeq(
                   open + 138u, metadata.service_descriptor_digest, 32u),
           "metadata service descriptor exact");
    expect(ninlil_mfdt_v1_memeq(
               open + 178u, metadata.deadline_clock_epoch_id, 16u) &&
               ninlil_mfdt_v1_get_u64(open + 194u) ==
                   metadata.absolute_effect_deadline_ms,
           "metadata deadline exact");
    expect(ninlil_mfdt_v1_memeq(
               open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET, ns,
               metadata.namespace_length) &&
               ninlil_mfdt_v1_memeq(
                   open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET +
                       metadata.namespace_length,
                   service,
                   metadata.service_length) &&
               ninlil_mfdt_v1_memeq(
                   open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET +
                       metadata.namespace_length +
                       metadata.service_length,
                   schema, metadata.schema_length),
           "metadata text exact");

    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 71ull, &resp) == NINLIL_MFDT_V1_OK &&
               resp.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT,
           "metadata receiver accepts canonical open");
    expect(ninlil_mfdt_v1_get_u64(resp.body + 88u) ==
               metadata.absolute_effect_deadline_ms,
           "metadata deadline bounds reservation");

    /* Cold restart must preserve the exact caller OPEN, not regenerate defaults. */
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "metadata sender cold init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&tx, tid, 1u) ==
               NINLIL_MFDT_V1_OK,
           "metadata sender cold scan");
    expect(ninlil_mfdt_v1_sender_reissue_open(
               &tx, replay, &replay_len) == NINLIL_MFDT_V1_OK &&
               replay_len == open_len &&
               ninlil_mfdt_v1_memeq(replay, open, open_len),
           "metadata exact cold reissue");
}

static void test_session_generation_atomic_reset_and_request_isolation(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t first;
    ninlil_mfdt_v1_response_t post_advance;
    ninlil_mfdt_v1_response_t hit;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    uint32_t fulls_before;
    uint8_t *nrc = NULL;
    size_t row;
    size_t slot;
    unsigned gen1_rid = 0u;
    unsigned gen2_rid = 0u;
    size_t gen1_slot_index = NINLIL_MFDT_V1_NRC1_SLOT_COUNT;
    size_t gen2_slot_index = NINLIL_MFDT_V1_NRC1_SLOT_COUNT;

    cfg_on(&cfg);
    cfg.session_generation = 7u;
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    fill_tid(tid, 0x61u);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "generation tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "generation rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, (const uint8_t *)"g", 1u, open, &open_len, 81ull) ==
               NINLIL_MFDT_V1_OK,
           "generation sender open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 81ull, &first) == NINLIL_MFDT_V1_OK,
           "generation first response");

    /* Failed co-FULL leaves config, active record, and NRC1 at generation 7. */
    fulls_before = rst.full_count;
    rst.crash_after_fulls = rst.full_count;
    expect(ninlil_mfdt_v1_advance_session_generation(&rx) ==
               NINLIL_MFDT_V1_ERR_STORAGE,
           "generation advance injected failure");
    expect(rx.cfg.session_generation == 7u &&
               rst.full_count == fulls_before,
           "generation failure rolls back atomically");
    rst.crash_after_fulls = 0u;
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 81ull, &hit) == NINLIL_MFDT_V1_OK &&
               hit.from_nrc1_hit == 1u,
           "initial generation response survives failed advance");

    expect(ninlil_mfdt_v1_advance_session_generation(&rx) ==
               NINLIL_MFDT_V1_OK &&
               rx.cfg.session_generation == 8u,
           "arbitrary generation exact successor co-FULL");
    /*
     * Same numeric request ID in generation 8 is a miss, never a replay of
     * generation 7's slot. The second attempt then hits generation 8.
     */
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 81ull, &post_advance) ==
               NINLIL_MFDT_V1_OK &&
               post_advance.from_nrc1_hit == 0u,
           "successor generation same request id is isolated miss");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 81ull, &hit) == NINLIL_MFDT_V1_OK &&
               hit.from_nrc1_hit == 1u &&
               hit.body_len == post_advance.body_len &&
               ninlil_mfdt_v1_memeq(
                   hit.body, post_advance.body, post_advance.body_len),
           "successor generation same request id becomes exact hit");
    expect(ninlil_mfdt_v1_advance_session_generation(&rx) ==
               NINLIL_MFDT_V1_ERR_CAPACITY &&
               rx.cfg.session_generation == 8u,
           "second generation advance is rejected");

    for (row = 0u; row < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++row) {
        if (rst.rows[row].occupied != 0u &&
            ninlil_mfdt_v1_memeq(rst.rows[row].key, "NRC1", 4u) &&
            ninlil_mfdt_v1_memeq(rst.rows[row].key + 4u, tid, 16u)) {
            nrc = rst.rows[row].value;
            break;
        }
    }
    expect(nrc != NULL &&
               ninlil_mfdt_v1_get_u32(nrc + 24u) == 8u &&
               ninlil_mfdt_v1_get_u16(nrc + 30u) == 2u,
           "generation NRC1 header/count");
    if (nrc != NULL) {
        for (slot = 0u; slot < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++slot) {
            const uint8_t *s =
                nrc + 40u + slot * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
            if (ninlil_mfdt_v1_get_u64(s) == 81ull) {
                if (ninlil_mfdt_v1_get_u32(s + 8u) == 7u) {
                    gen1_rid += 1u;
                    gen1_slot_index = slot;
                } else if (ninlil_mfdt_v1_get_u32(s + 8u) == 8u) {
                    gen2_rid += 1u;
                    gen2_slot_index = slot;
                }
            }
        }
    }
    expect(gen1_rid == 1u && gen2_rid == 1u,
           "generation request identity exact pair retained");
    if (nrc != NULL &&
        gen1_slot_index < NINLIL_MFDT_V1_NRC1_SLOT_COUNT &&
        gen2_slot_index < NINLIL_MFDT_V1_NRC1_SLOT_COUNT) {
        uint8_t *slot_bytes;
        size_t empty_slot_index = NINLIL_MFDT_V1_NRC1_SLOT_COUNT;

        expect(ninlil_mfdt_v1_validate_nrc1_record(
                   nrc, NINLIL_MFDT_V1_NRC1_VALUE_BYTES, tid, 8u) ==
                   NINLIL_MFDT_V1_OK,
               "generation 7/8 NRC1 validates");

        (void)memcpy(
            g_generation_nrc1_mutant, nrc,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
        slot_bytes =
            g_generation_nrc1_mutant + 40u +
            gen1_slot_index * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
        ninlil_mfdt_v1_put_u32(slot_bytes + 8u, 9u);
        recompute_nrc1_crc(g_generation_nrc1_mutant);
        expect(ninlil_mfdt_v1_validate_nrc1_record(
                   g_generation_nrc1_mutant,
                   NINLIL_MFDT_V1_NRC1_VALUE_BYTES, tid, 8u) ==
                   NINLIL_MFDT_V1_ERR_CORRUPT,
               "future generation slot is corrupt");

        (void)memcpy(
            g_generation_nrc1_mutant, nrc,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
        slot_bytes =
            g_generation_nrc1_mutant + 40u +
            gen1_slot_index * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
        ninlil_mfdt_v1_put_u32(slot_bytes + 8u, 6u);
        recompute_nrc1_crc(g_generation_nrc1_mutant);
        expect(ninlil_mfdt_v1_validate_nrc1_record(
                   g_generation_nrc1_mutant,
                   NINLIL_MFDT_V1_NRC1_VALUE_BYTES, tid, 8u) ==
                   NINLIL_MFDT_V1_ERR_CORRUPT,
               "generation gap is corrupt");

        (void)memcpy(
            g_generation_nrc1_mutant, nrc,
            NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
        ninlil_mfdt_v1_put_u32(
            g_generation_nrc1_mutant + 24u, 7u);
        recompute_nrc1_crc(g_generation_nrc1_mutant);
        expect(ninlil_mfdt_v1_validate_nrc1_record(
                   g_generation_nrc1_mutant,
                   NINLIL_MFDT_V1_NRC1_VALUE_BYTES, tid, 7u) ==
                   NINLIL_MFDT_V1_ERR_CORRUPT,
               "generation rollback with future slot is corrupt");

        for (slot = 0u; slot < NINLIL_MFDT_V1_NRC1_SLOT_COUNT; ++slot) {
            const uint8_t *candidate =
                nrc + 40u + slot * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
            if (ninlil_mfdt_v1_get_u64(candidate) == 0ull) {
                empty_slot_index = slot;
                break;
            }
        }
        if (empty_slot_index < NINLIL_MFDT_V1_NRC1_SLOT_COUNT) {
            uint8_t *third_slot;
            const uint8_t *source_slot =
                nrc + 40u +
                gen1_slot_index * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
            (void)memcpy(
                g_generation_nrc1_mutant, nrc,
                NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
            third_slot =
                g_generation_nrc1_mutant + 40u +
                empty_slot_index * NINLIL_MFDT_V1_NRC1_SLOT_BYTES;
            (void)memcpy(
                third_slot, source_slot,
                NINLIL_MFDT_V1_NRC1_SLOT_BYTES);
            ninlil_mfdt_v1_put_u64(third_slot, 82ull);
            ninlil_mfdt_v1_put_u32(third_slot + 8u, 6u);
            ninlil_mfdt_v1_put_u16(
                g_generation_nrc1_mutant + 30u, 3u);
            ninlil_mfdt_v1_put_u32(
                g_generation_nrc1_mutant + 32u, 3u);
            recompute_nrc1_crc(g_generation_nrc1_mutant);
            expect(ninlil_mfdt_v1_validate_nrc1_record(
                       g_generation_nrc1_mutant,
                       NINLIL_MFDT_V1_NRC1_VALUE_BYTES, tid, 8u) ==
                       NINLIL_MFDT_V1_ERR_CORRUPT,
                   "third distinct generation is corrupt");
        }
    }
}

static void test_session_generation_uint32_max_does_not_wrap(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t response;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;

    cfg_on(&cfg);
    cfg.session_generation = UINT32_MAX;
    fill_tid(tid, 0x91u);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "UINT32_MAX sender init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "UINT32_MAX receiver init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, NULL, 0u, open, &open_len, 91ull) ==
               NINLIL_MFDT_V1_OK,
           "UINT32_MAX sender open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 91ull, &response) ==
               NINLIL_MFDT_V1_OK,
           "UINT32_MAX receiver open");
    expect(ninlil_mfdt_v1_advance_session_generation(&rx) ==
               NINLIL_MFDT_V1_ERR_CAPACITY &&
               rx.cfg.session_generation == UINT32_MAX,
           "UINT32_MAX generation advance rejects wrap");
}

static void test_deadline_epoch_and_overflow_fail_without_mutation(void)
{
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t resp;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t epoch[16];
    uint16_t open_len = 0u;

    cfg_on(&cfg);
    (void)memcpy(epoch, cfg.local_clock_epoch.bytes, sizeof(epoch));
    expect(build_deadline_open(
               0x71u, epoch, cfg.now_ms, open, &open_len) ==
               NINLIL_MFDT_V1_OK,
           "deadline expired OPEN fixture");
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "deadline expired rx init");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 91ull, &resp) ==
               NINLIL_MFDT_V1_ERR_EXPIRED &&
               resp.message_type == NINLIL_MFDT_V1_MSG_REJECT &&
               resp.reject_code == NINLIL_MFDT_V1_REJ_EXPIRED &&
               rx.active_count == 0u && rst.full_count == 0u,
           "deadline same-epoch expired reject no mutation");

    (void)memset(epoch, 0xd1, sizeof(epoch));
    expect(build_deadline_open(
               0x72u, epoch, cfg.now_ms + 1000ull, open, &open_len) ==
               NINLIL_MFDT_V1_OK,
           "deadline foreign epoch OPEN fixture");
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "deadline foreign epoch rx init");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 92ull, &resp) ==
               NINLIL_MFDT_V1_ERR_STATE &&
               resp.message_type == NINLIL_MFDT_V1_MSG_REJECT &&
               resp.reject_code == NINLIL_MFDT_V1_REJ_STATE &&
               rx.active_count == 0u && rst.full_count == 0u,
           "deadline foreign epoch reject no projection");

    (void)memset(epoch, 0, sizeof(epoch));
    expect(build_deadline_open(
               0x73u, epoch, UINT64_MAX, open, &open_len) ==
               NINLIL_MFDT_V1_OK,
           "deadline overflow OPEN fixture");
    cfg.now_ms = UINT64_MAX - NINLIL_MFDT_V1_RESERVATION_MS + 1ull;
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) ==
               NINLIL_MFDT_V1_OK,
           "deadline overflow rx init");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 93ull, &resp) ==
               NINLIL_MFDT_V1_ERR_EXPIRED &&
               resp.reject_code == NINLIL_MFDT_V1_REJ_EXPIRED &&
               rx.active_count == 0u && rst.full_count == 0u,
           "reservation overflow reject no mutation");

    expect(ninlil_mfdt_v1_get_u64(open + 194u) == UINT64_MAX &&
               ninlil_mfdt_v1_get_u32(open + 434u) == 1u &&
               ninlil_mfdt_v1_get_u64(open + 438u) == 0ull,
           "EventFact NO_DEADLINE sentinel stays exact in OPEN");
    ninlil_mfdt_v1_put_u64(open + 194u, 0ull);
    expect(ninlil_mfdt_v1_validate_open(
               open, open_len, NULL, 40u, NULL, 1u, 0u) ==
               NINLIL_MFDT_V1_ERR_LAYOUT,
           "uplink deadline zero rejected");
    (void)memcpy(open + 178u, cfg.local_clock_epoch.bytes, 16u);
    ninlil_mfdt_v1_put_u64(open + 194u, UINT64_MAX);
    ninlil_mfdt_v1_put_u32(open + 434u, 2u);
    ninlil_mfdt_v1_put_u64(open + 438u, 1ull);
    (void)memset(open + 80u, 0, 16u);
    expect(ninlil_mfdt_v1_validate_open(
               open, open_len, NULL, 40u, NULL, 1u, 0u) ==
               NINLIL_MFDT_V1_ERR_LAYOUT,
           "downlink UINT64_MAX deadline rejected");
}

static void test_foreign_reservation_epoch_never_uses_sender_clock(void)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_engine_t tx_cold;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_workspace_t cold_ws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t tx_cfg;
    ninlil_mfdt_v1_config_t rx_cfg;
    uint8_t tid[16];
    uint8_t content = 0x5au;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    ninlil_mfdt_v1_response_t response;

    cfg_on(&tx_cfg);
    cfg_on(&rx_cfg);
    tx_cfg.now_ms = 1000000ull;
    rx_cfg.now_ms = 1000ull;
    (void)memset(tx_cfg.local_clock_epoch.bytes, 0xe1, 16u);
    (void)memset(rx_cfg.local_clock_epoch.bytes, 0xe2, 16u);
    fill_tid(tid, 0x7au);
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);

    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &tx_cfg) ==
               NINLIL_MFDT_V1_OK,
           "foreign reservation tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &rx_cfg) ==
               NINLIL_MFDT_V1_OK,
           "foreign reservation rx init");
    expect(ninlil_mfdt_v1_sender_open(
               &tx, tid, &content, 1u, open, &open_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "foreign reservation sender open");
    expect(ninlil_mfdt_v1_receiver_on_open(
               &rx, open, open_len, 1ull, &response) ==
               NINLIL_MFDT_V1_OK &&
               response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT,
           "foreign reservation receiver accept");
    expect(ninlil_mfdt_v1_get_u64(response.body + 88u) < tx_cfg.now_ms,
           "foreign reservation fixture has incomparable lower timestamp");
    expect(ninlil_mfdt_v1_sender_on_open_accept(
               &tx, response.body, response.body_len, 1ull) ==
               NINLIL_MFDT_V1_OK,
           "foreign reservation accepted without cross-epoch comparison");
    expect(ninlil_mfdt_v1_on_reservation_expired(&tx) ==
               NINLIL_MFDT_V1_ERR_STATE,
           "foreign reservation cannot expire on sender local clock");

    expect(ninlil_mfdt_v1_engine_init(
               &tx_cold, &cold_ws, &tst, &tx_cfg) ==
               NINLIL_MFDT_V1_OK,
           "foreign reservation sender cold init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(
               &tx_cold, tid, 1u) == NINLIL_MFDT_V1_OK,
           "foreign reservation sender cold restart");

    rx.cfg.now_ms = 1000ull + NINLIL_MFDT_V1_RESERVATION_MS;
    expect(ninlil_mfdt_v1_on_reservation_expired(&rx) ==
               NINLIL_MFDT_V1_OK,
           "reservation expires on receiver clock owner");
}

int main(void)
{
    g_fail = 0;
    test_min_max_boundaries();
    test_abort_denied();
    test_crash_inject();
    test_digest_conflict();
    test_reorder_chunks();
    test_open_accept_wire_min_and_bind52();
    test_cu_new_nrc1_retry_stays_unpromoted();
    test_nrc1_only_target_and_host_restart_profiles();
    test_post_terminal_target_replay_stays_unpromoted();
    test_host_single_engine_rejects_cross_transfer_open();
    test_caller_metadata_roundtrip_and_restart();
    test_session_generation_atomic_reset_and_request_isolation();
    test_session_generation_uint32_max_does_not_wrap();
    test_deadline_epoch_and_overflow_fail_without_mutation();
    test_foreign_reservation_epoch_never_uses_sender_clock();
    if (g_fail) {
        (void)fprintf(stderr, "mfdt_v1_e2e_test FAILED\n");
        return 1;
    }
    (void)printf("mfdt_v1_e2e_test OK\n");
    return 0;
}
