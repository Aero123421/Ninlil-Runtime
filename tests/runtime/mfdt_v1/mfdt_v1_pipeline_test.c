/* SPDX-License-Identifier: Apache-2.0
 * NCL1 + two-endpoint pipeline (no local self-echo).
 */
#include "mfdt_v1.h"
#include "mfdt_v1_bearer_worker.h"
#include "mfdt_v1_ncl1.h"
#include "mfdt_v1_pipeline.h"
#include "mfdt_v1_runtime_seam.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static void expect(int c, const char *m)
{
    if (!c) {
        fprintf(stderr, "FAIL: %s\n", m);
        g_fail = 1;
    }
}

typedef struct worker_link {
    struct worker_link *peer;
    uint8_t frames[8][NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint16_t lens[8];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
    uint64_t now_ms;
} worker_link_t;

typedef struct upper_fixture {
    uint8_t token[16];
    uint8_t valid;
    uint32_t prepare_calls;
    uint32_t effect_count;
} upper_fixture_t;

static int worker_link_tx(void *user, const uint8_t *frame, size_t frame_len)
{
    worker_link_t *link = (worker_link_t *)user;
    worker_link_t *peer;
    if (link == NULL || link->peer == NULL || frame == NULL ||
        frame_len > NINLIL_MFDT_V1_NCL1_MAX_MSG) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    peer = link->peer;
    if (peer->count >= 8u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    memcpy(peer->frames[peer->tail], frame, frame_len);
    peer->lens[peer->tail] = (uint16_t)frame_len;
    peer->tail = (uint8_t)((peer->tail + 1u) % 8u);
    peer->count = (uint8_t)(peer->count + 1u);
    return NINLIL_MFDT_V1_OK;
}

static int worker_link_rx(void *user, uint8_t *frame_out, size_t frame_cap,
                          size_t *frame_len_out)
{
    worker_link_t *link = (worker_link_t *)user;
    uint16_t len;
    if (link == NULL || frame_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (link->count == 0u) {
        *frame_len_out = 0u;
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    len = link->lens[link->head];
    if (frame_out == NULL || frame_cap < len) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    memcpy(frame_out, link->frames[link->head], len);
    link->head = (uint8_t)((link->head + 1u) % 8u);
    link->count = (uint8_t)(link->count - 1u);
    *frame_len_out = len;
    return NINLIL_MFDT_V1_OK;
}

static uint64_t worker_link_now(void *user)
{
    worker_link_t *link = (worker_link_t *)user;
    return link != NULL ? link->now_ms : 0ull;
}

static int upper_prepare_once(void *user, const uint8_t token[16],
                              const uint8_t *content, uint32_t content_len,
                              uint8_t evidence_out[32])
{
    upper_fixture_t *upper = (upper_fixture_t *)user;
    uint8_t material[16 + 4];
    if (upper == NULL || token == NULL || evidence_out == NULL ||
        (content_len > 0u && content == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    upper->prepare_calls += 1u;
    if (upper->valid != 0u) {
        if (memcmp(upper->token, token, 16u) != 0) {
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
        memcpy(material, token, 16u);
        ninlil_mfdt_v1_put_u32(material + 16u, content_len);
        ninlil_mfdt_v1_sha256(material, sizeof(material), evidence_out);
        return NINLIL_MFDT_V1_ALREADY_COMMITTED;
    }
    memcpy(upper->token, token, 16u);
    upper->valid = 1u;
    upper->effect_count += 1u;
    memcpy(material, token, 16u);
    ninlil_mfdt_v1_put_u32(material + 16u, content_len);
    ninlil_mfdt_v1_sha256(material, sizeof(material), evidence_out);
    return NINLIL_MFDT_V1_PREPARED;
}

static void test_ncl1_roundtrip(void)
{
    uint8_t body[16];
    uint8_t out[64];
    size_t olen = 0;
    uint8_t mtype = 0;
    uint32_t rid = 0, sgen = 0;
    uint64_t cookie = 0;
    const uint8_t *b = NULL;
    uint16_t blen = 0;
    memset(body, 0xab, sizeof(body));
    expect(ninlil_mfdt_v1_ncl1_encode(0x40, 7u, 1u, 0x99ull, body, 16u, out,
                                      sizeof(out), &olen) == 0,
           "enc");
    expect(olen == 26u + 16u, "len");
    expect(ninlil_mfdt_v1_ncl1_decode(out, olen, 0x03u, &mtype, &rid, &sgen,
                                      &cookie, &b, &blen) == 0,
           "dec");
    expect(mtype == 0x40u && rid == 7u && sgen == 1u && cookie == 0x99ull &&
               blen == 16u,
           "fields");
    expect(ninlil_mfdt_v1_memeq(b, body, 16u), "body");
    expect(ninlil_mfdt_v1_ncl1_binding_ok(0x03u, 0x40u), "bind DATA");
    expect(!ninlil_mfdt_v1_ncl1_binding_ok(0x01u, 0x40u), "no PING bind");
}

/* Two-endpoint pump: A sender, B receiver. No shared pipeline self-loop. */
static int pump_ab(ninlil_mfdt_v1_pipeline_t *a, ninlil_mfdt_v1_pipeline_t *b,
                   uint32_t max_steps)
{
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t flen = 0u;
    uint32_t step;
    int rc;
    for (step = 0u; step < max_steps; ++step) {
        if (a->complete) {
            return 0;
        }
        (void)ninlil_mfdt_v1_pipeline_sender_pump(a);
        if (ninlil_mfdt_v1_pipeline_take_outbound(a, frame, sizeof(frame),
                                                  &flen) == 0 &&
            flen > 0u) {
            rc = ninlil_mfdt_v1_pipeline_on_ncl1_ingress(b, frame, flen);
            if (rc != 0) {
                return rc;
            }
        }
        if (ninlil_mfdt_v1_pipeline_take_outbound(b, frame, sizeof(frame),
                                                  &flen) == 0 &&
            flen > 0u) {
            rc = ninlil_mfdt_v1_pipeline_on_ncl1_ingress(a, frame, flen);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return a->complete ? 0 : -1;
}

static void test_two_endpoint_empty_and_one_byte(void)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t ta, ra;
    ninlil_mfdt_v1_workspace_t tws, rws;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb;
    uint8_t tid[16];
    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = 1000;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 0x11, 16);
    tid[0] = 1;
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&ta, &tws, &tst, &cfg) == 0, "tx");
    expect(ninlil_mfdt_v1_engine_init(&ra, &rws, &rst, &cfg) == 0, "rx");
    ninlil_mfdt_v1_pipeline_init(&pa, &ta, NULL, NULL, NULL, 1u, 0x4d4644ull);
    ninlil_mfdt_v1_pipeline_init(&pb, NULL, &ra, NULL, NULL, 1u, 0x4d4644ull);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, NULL, 0) == 0,
           "empty begin");
    expect(pa.complete == 0, "not complete after begin");
    expect(ninlil_mfdt_v1_pipeline_outbox_pending(&pa) == 1, "open outbox");
    expect(pump_ab(&pa, &pb, 64) == 0, "empty pump");
    expect(pa.complete == 1, "empty complete after remote");
    expect(ra.publication_ready == 1, "rx published empty");

    /* one-byte */
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&ta, &tws, &tst, &cfg) == 0, "tx2");
    expect(ninlil_mfdt_v1_engine_init(&ra, &rws, &rst, &cfg) == 0, "rx2");
    ninlil_mfdt_v1_pipeline_init(&pa, &ta, NULL, NULL, NULL, 1u, 0x4d4644ull);
    ninlil_mfdt_v1_pipeline_init(&pb, NULL, &ra, NULL, NULL, 1u, 0x4d4644ull);
    tid[0] = 2;
    {
        uint8_t one = 0x5a;
        upper_fixture_t upper;
        const uint8_t *published = NULL;
        uint32_t published_len = 0u;
        uint8_t publication_token[16];
        uint8_t publication_evidence[32];
        uint64_t acceptance_generation = 0ull;
        int prepare_rc;
        memset(&upper, 0, sizeof(upper));
        expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, &one, 1) == 0,
               "one begin");
        expect(pa.complete == 0, "not complete mid");
        expect(pump_ab(&pa, &pb, 64) == 0, "one pump");
        expect(pa.complete == 1, "one complete");
        expect(ra.publication_ready == 1, "published");
        expect(ninlil_mfdt_v1_pipeline_finish_terminal(&pb) ==
                   NINLIL_MFDT_V1_ERR_STATE,
               "receiver terminal requires durable upper evidence");
        expect(ninlil_mfdt_v1_receiver_publication_view(
                   &ra, &published, &published_len, publication_token,
                   &acceptance_generation) == 0,
               "one publication view");
        prepare_rc = upper_prepare_once(
            &upper, publication_token, published, published_len,
            publication_evidence);
        expect(prepare_rc == NINLIL_MFDT_V1_PREPARED,
               "one upper durable prepare");
        expect(ninlil_mfdt_v1_receiver_commit_publication(
                   &ra, publication_token, publication_evidence) == 0,
               "one upper owner commit");
        expect(ninlil_mfdt_v1_pipeline_finish_terminal(&pa) == 0, "one term a");
        expect(ninlil_mfdt_v1_pipeline_finish_terminal(&pb) == 0, "one term b");
    }
}

static void test_no_local_echo_without_peer(void)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_pipeline_t pipe;
    uint8_t tid[16];
    uint8_t one = 1;
    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = 1;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 9, 16);
    ninlil_mfdt_v1_lab_store_init(&tst);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == 0, "tx");
    ninlil_mfdt_v1_pipeline_init(&pipe, &tx, NULL, NULL, NULL, 1u, 1ull);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pipe, tid, &one, 1) == 0,
           "begin");
    expect(pipe.complete == 0, "no fake complete");
    (void)ninlil_mfdt_v1_pipeline_sender_pump(&pipe);
    expect(pipe.complete == 0, "still not complete without peer");
    expect(pipe.phase == NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC, "await open");
}

static void test_seam_and_release_policy(void)
{
    ninlil_mfdt_v1_seam_config_t sc;
    uint8_t tid[16], tok[16];
    uint8_t big[1000];
    int rc;
    memset(&sc, 0, sizeof(sc));
    memset(big, 0xcd, sizeof(big));
    ninlil_mfdt_v1_seam_set_config(&sc);
    rc = ninlil_mfdt_v1_seam_try_application_data(big, 1000, NULL, tid, tok);
    expect(rc == NINLIL_MFDT_SEAM_REJECTED || rc == NINLIL_MFDT_SEAM_NOT_APPLICABLE,
           "off large");
    sc.policy_on = 1;
    sc.capability = 1;
    sc.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    sc.host_mode = 1;
    sc.session_generation = 1;
    sc.session_cookie = 1;
    sc.now_ms = 1;
    memset(sc.local_clock_epoch, 0xc0, 16u);
    ninlil_mfdt_v1_seam_set_config(&sc);
    rc = ninlil_mfdt_v1_seam_try_application_data(big, 1000, NULL, tid, tok);
    expect(rc == NINLIL_MFDT_SEAM_OK, "on large ok");
    expect(ninlil_mfdt_v1_release_policy_allows_default_on() == 0,
           "default on blocked until software matrix and HIL close");
}

/*
 * Cold-process mid-transfer restart:
 *  - progress two-endpoint until durable NM3S is past OPEN
 *  - copy only durable store rows into a fresh store (raw keys/values)
 *  - wipe all process-A eng/pipe/ws images
 *  - restart_scan_transfer + pipeline_sender_rehydrate only (no struct copy)
 *  - finish transfer; publication token/generation stable under duplicate rehydrate
 */
static void test_cold_restart_zero_struct_copy_and_publication(void)
{
    ninlil_mfdt_v1_engine_t ta, tb, ta2;
    ninlil_mfdt_v1_workspace_t wa, wb, wa2;
    ninlil_mfdt_v1_lab_store_t sa, sb, sa2;
    ninlil_mfdt_v1_pipeline_t pa, pb, pa2;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    uint8_t content[64];
    uint8_t tok_before[16];
    uint8_t tok_after[16];
    ninlil_mfdt_v1_active_snapshot_t snap1, snap2;
    uint64_t gen1 = 0ull;
    size_t i;
    uint32_t steps;
    int mid = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.session_generation = 1;
    cfg.now_ms = 1000;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 0xA5, 16);
    tid[0] = 0xC0;
    for (i = 0; i < sizeof(content); ++i) {
        content[i] = (uint8_t)(i + 1u);
    }

    ninlil_mfdt_v1_lab_store_init(&sa);
    ninlil_mfdt_v1_lab_store_init(&sb);
    expect(ninlil_mfdt_v1_engine_init(&ta, &wa, &sa, &cfg) == 0, "init ta");
    expect(ninlil_mfdt_v1_engine_init(&tb, &wb, &sb, &cfg) == 0, "init tb");
    ninlil_mfdt_v1_pipeline_init(&pa, &ta, NULL, NULL, NULL, 1u, 0x4d464454ull);
    ninlil_mfdt_v1_pipeline_init(&pb, NULL, &tb, NULL, NULL, 1u, 0x4d464454ull);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, content,
                                                (uint32_t)sizeof(content)) == 0,
           "begin");

    /* Advance a few steps so durable has OPEN_ACCEPTED+ pages. */
    for (steps = 0u; steps < 16u && !pa.complete; ++steps) {
        (void)pump_ab(&pa, &pb, 1u);
        if (ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap1) == 0 &&
            snap1.state_code >= NINLIL_MFDT_V1_S_OPEN_ACCEPTED) {
            mid = 1;
            gen1 = snap1.record_generation;
            if (snap1.publication_state != 0u) {
                memcpy(tok_before, snap1.publication_token, 16);
            } else {
                memset(tok_before, 0, 16);
            }
            break;
        }
    }
    expect(mid == 1, "reached mid durable state");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap1) == 0, "snap mid");

    /* Raw durable rows → fresh store only. */
    ninlil_mfdt_v1_lab_store_init(&sa2);
    for (i = 0; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        if (!sa.rows[i].occupied) {
            continue;
        }
        expect(ninlil_mfdt_v1_lab_full_begin(&sa2) == 0, "imp begin");
        expect(ninlil_mfdt_v1_lab_put(&sa2, sa.rows[i].key, sa.rows[i].value,
                                      sa.rows[i].value_len) == 0,
               "imp put");
        expect(ninlil_mfdt_v1_lab_full_commit(&sa2) == 0, "imp commit");
    }

    /* Destroy process-A RAM completely (struct poison). */
    memset(&ta, 0xA5, sizeof(ta));
    memset(&pa, 0xA5, sizeof(pa));
    memset(&wa, 0xA5, sizeof(wa));
    memset(&sa, 0xA5, sizeof(sa));

    expect(ninlil_mfdt_v1_engine_init(&ta2, &wa2, &sa2, &cfg) == 0, "init ta2");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&ta2, tid, 1u) == 0,
           "restart_scan_transfer");
    expect(ta2.active_count == 1u, "active rehydrated");
    expect(ninlil_mfdt_v1_pipeline_sender_rehydrate(&pa2, &ta2, tid, 1u,
                                                    0x4d464454ull) == 0,
           "rehydrate from durable only");
    expect(pa2.phase != NINLIL_MFDT_V1_PHASE_IDLE, "phase from durable");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta2, &snap2) == 0, "snap2");
    expect(snap2.record_generation == gen1, "generation durable invariant");
    expect(snap2.state_code == snap1.state_code, "state_code durable");

    /* Duplicate rehydrate must not mutate durable generation/token. */
    expect(ninlil_mfdt_v1_pipeline_sender_rehydrate(&pa2, &ta2, tid, 1u,
                                                    0x4d464454ull) == 0,
           "rehydrate dup");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta2, &snap2) == 0, "snap2b");
    expect(snap2.record_generation == gen1, "gen stable after dup rehydrate");
    if (snap2.publication_state != 0u) {
        memcpy(tok_after, snap2.publication_token, 16);
        expect(memcmp(tok_before, tok_after, 16) == 0, "token stable");
    }

    /* Finish transfer on cold-rehydrated sender with original receiver. */
    expect(pump_ab(&pa2, &pb, 64u) == 0, "finish after cold");
    expect(pa2.complete == 1u, "complete after cold");
}

/*
 * P0: pipeline passes NCL1 decode rid; wrong/stale rid/TID/rev/digest leave
 * phase/progress/durable writes unchanged; outstanding remains.
 */
static void test_outstanding_rid_bind_invariant(void)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t ta, ra;
    ninlil_mfdt_v1_workspace_t tws, rws;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb;
    ninlil_mfdt_v1_active_snapshot_t snap0, snap1;
    uint8_t tid[16];
    uint8_t one = 0x5a;
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint8_t bad_frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t flen = 0u;
    size_t blen = 0u;
    uint8_t mtype = 0u;
    uint32_t rid = 0u;
    uint32_t sgen = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *body = NULL;
    uint16_t body_len = 0u;
    uint8_t phase0 = 0u;
    uint64_t orid0 = 0ull;
    uint64_t gen0 = 0ull;
    uint8_t mut_body[256];

    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = 1000;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 0x44, 16);
    tid[0] = 0xC1;
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&ta, &tws, &tst, &cfg) == 0, "cor tx");
    expect(ninlil_mfdt_v1_engine_init(&ra, &rws, &rst, &cfg) == 0, "cor rx");
    ninlil_mfdt_v1_pipeline_init(&pa, &ta, NULL, NULL, NULL, 1u, 0x4d4644ull);
    ninlil_mfdt_v1_pipeline_init(&pb, NULL, &ra, NULL, NULL, 1u, 0x4d4644ull);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, &one, 1) == 0,
           "cor begin");
    expect(pa.has_outstanding == 1u, "cor outstanding after open");
    expect(pa.phase == NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC, "cor wait open");
    orid0 = pa.outstanding_rid;
    phase0 = pa.phase;
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap0) == 0, "cor snap0");
    gen0 = snap0.record_generation;

    /* Deliver OPEN to rx; capture OPEN_ACCEPT outbox. */
    expect(ninlil_mfdt_v1_pipeline_take_outbound(&pa, frame, sizeof(frame),
                                                 &flen) == 0 &&
               flen > 0u,
           "cor open frame");
    expect(ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pb, frame, flen) == 0,
           "cor rx open");
    expect(ninlil_mfdt_v1_pipeline_take_outbound(&pb, frame, sizeof(frame),
                                                 &flen) == 0 &&
               flen > 0u,
           "cor accept frame");
    expect(ninlil_mfdt_v1_ncl1_decode(frame, flen, NINLIL_MFDT_V1_NCG1_DATA,
                                      &mtype, &rid, &sgen, &cookie, &body,
                                      &body_len) == 0,
           "cor decode accept");
    expect(mtype == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT, "cor mtype open_accept");
    expect((uint64_t)rid == orid0, "cor rid preserved from request");

    /* Wrong rid: re-encode same body with stale request_id. */
    expect(ninlil_mfdt_v1_ncl1_encode(mtype, (uint32_t)(orid0 + 99ull), sgen,
                                      cookie, body, body_len, bad_frame,
                                      sizeof(bad_frame), &blen) == 0,
           "cor enc wrong rid");
    expect(ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pa, bad_frame, blen) ==
               NINLIL_MFDT_V1_ERR_STATE,
           "cor reject wrong rid");
    expect(pa.phase == phase0, "cor phase after wrong rid");
    expect(pa.has_outstanding == 1u && pa.outstanding_rid == orid0,
           "cor outstanding kept");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap1) == 0, "cor snap rid");
    expect(snap1.record_generation == gen0 && snap1.state_code == snap0.state_code,
           "cor durable after wrong rid");

    /* Stale/zero rid. */
    expect(ninlil_mfdt_v1_ncl1_encode(mtype, 0u, sgen, cookie, body, body_len,
                                      bad_frame, sizeof(bad_frame), &blen) != 0 ||
               ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pa, bad_frame, blen) != 0,
           "cor reject rid0");
    expect(pa.phase == phase0 && pa.has_outstanding == 1u, "cor rid0 phase");

    /* Correct rid, wrong TID in body: no phase/progress/durable advance. */
    (void)memcpy(mut_body, body, body_len);
    mut_body[0] ^= 0xffu;
    expect(ninlil_mfdt_v1_ncl1_encode(mtype, rid, sgen, cookie, mut_body,
                                      body_len, bad_frame, sizeof(bad_frame),
                                      &blen) == 0,
           "cor enc bad tid");
    expect(ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pa, bad_frame, blen) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "cor reject bad tid");
    expect(pa.phase == phase0 && pa.has_outstanding == 1u, "cor tid phase");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap1) == 0, "cor snap tid");
    expect(snap1.record_generation == gen0, "cor gen after bad tid");

    /* Correct rid, wrong revision. */
    (void)memcpy(mut_body, body, body_len);
    mut_body[16] ^= 0x01u;
    expect(ninlil_mfdt_v1_ncl1_encode(mtype, rid, sgen, cookie, mut_body,
                                      body_len, bad_frame, sizeof(bad_frame),
                                      &blen) == 0,
           "cor enc bad rev");
    expect(ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pa, bad_frame, blen) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "cor reject bad rev");
    expect(pa.phase == phase0 && pa.outstanding_rid == orid0, "cor rev phase");

    /* Correct rid, wrong digest. */
    (void)memcpy(mut_body, body, body_len);
    mut_body[20] ^= 0x01u;
    expect(ninlil_mfdt_v1_ncl1_encode(mtype, rid, sgen, cookie, mut_body,
                                      body_len, bad_frame, sizeof(bad_frame),
                                      &blen) == 0,
           "cor enc bad dig");
    expect(ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pa, bad_frame, blen) ==
               NINLIL_MFDT_V1_ERR_DIGEST,
           "cor reject bad dig");
    expect(pa.phase == phase0 && pa.has_outstanding == 1u, "cor dig phase");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap1) == 0, "cor snap dig");
    expect(snap1.record_generation == gen0, "cor gen after bad dig");

    /* Exact rid + BIND52: advance. */
    expect(ninlil_mfdt_v1_pipeline_on_ncl1_ingress(&pa, frame, flen) == 0,
           "cor good accept");
    expect(pa.phase == NINLIL_MFDT_V1_PHASE_SEND_PAGES, "cor advanced");
    expect(pa.has_outstanding == 0u, "cor outstanding cleared");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&ta, &snap1) == 0, "cor snap ok");
    expect(snap1.state_code == NINLIL_MFDT_V1_S_OPEN_ACCEPTED, "cor open accepted");
    expect(snap1.record_generation == gen0 + 1ull, "cor gen +1");
}

static void test_timeout_and_open_pending_cold_reissue(void)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t tx1, tx2;
    ninlil_mfdt_v1_workspace_t ws1, ws2;
    ninlil_mfdt_v1_lab_store_t st1, st2;
    ninlil_mfdt_v1_pipeline_t p1, p2;
    ninlil_mfdt_v1_active_snapshot_t before, after;
    uint8_t tid[16];
    uint8_t one = 0x7au;
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t frame_len = 0u;
    uint8_t type = 0u;
    uint32_t rid = 0u;
    uint32_t sgen = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *body = NULL;
    uint16_t body_len = 0u;
    uint64_t old_rid;
    size_t i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2u;
    cfg.host_mode = 1u;
    cfg.session_generation = 1u;
    cfg.now_ms = 0u;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 0x6bu, sizeof(tid));
    tid[0] = 0x31u;

    ninlil_mfdt_v1_lab_store_init(&st1);
    expect(ninlil_mfdt_v1_engine_init(&tx1, &ws1, &st1, &cfg) == 0,
           "timeout init");
    ninlil_mfdt_v1_pipeline_init(&p1, &tx1, NULL, NULL, NULL, 1u, 0x55ull);
    ninlil_mfdt_v1_pipeline_set_response_timeout(&p1, 10u);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&p1, tid, &one, 1u) == 0,
           "timeout begin");
    old_rid = p1.outstanding_rid;
    expect(ninlil_mfdt_v1_retry_budget_remaining(&tx1) == 8u, "timeout rb8");

    /* An undrained frame is not a response timeout and consumes no budget. */
    expect(ninlil_mfdt_v1_pipeline_tick(&p1, 10u) ==
               NINLIL_MFDT_V1_ERR_BUSY,
           "timeout owned outbox");
    expect(ninlil_mfdt_v1_retry_budget_remaining(&tx1) == 8u,
           "timeout no charge before dispatch");
    expect(ninlil_mfdt_v1_pipeline_take_outbound(
               &p1, frame, sizeof(frame), &frame_len) == 0 &&
               frame_len > 0u,
           "timeout drain first");
    expect(ninlil_mfdt_v1_pipeline_tick(&p1, 20u) == 0,
           "timeout fresh-id retry");
    expect(ninlil_mfdt_v1_retry_budget_remaining(&tx1) == 7u,
           "timeout charged durably");
    expect(p1.outstanding_rid != old_rid && p1.outbox_valid != 0u,
           "timeout new rid and frame");
    expect(ninlil_mfdt_v1_pipeline_take_outbound(
               &p1, frame, sizeof(frame), &frame_len) == 0,
           "timeout take retry");
    expect(ninlil_mfdt_v1_ncl1_decode(
               frame, frame_len, NINLIL_MFDT_V1_NCG1_DATA, &type, &rid, &sgen,
               &cookie, &body, &body_len) == 0,
           "timeout decode retry");
    expect(type == NINLIL_MFDT_V1_MSG_OPEN &&
               (uint64_t)rid == p1.outstanding_rid &&
                   body_len >= NINLIL_MFDT_V1_OPEN_BODY_MIN,
           "timeout exact semantic open");

    /*
     * Cold process from raw durable rows only. OPEN_PENDING rehydrate must not
     * wait forever: pump charges one retry and reconstructs the exact OPEN.
     */
    ninlil_mfdt_v1_lab_store_init(&st2);
    for (i = 0u; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        if (st1.rows[i].occupied == 0u) {
            continue;
        }
        expect(ninlil_mfdt_v1_lab_full_begin(&st2) == 0, "cold op begin");
        expect(ninlil_mfdt_v1_lab_put(&st2, st1.rows[i].key,
                                      st1.rows[i].value,
                                      st1.rows[i].value_len) == 0,
               "cold op put");
        expect(ninlil_mfdt_v1_lab_full_commit(&st2) == 0, "cold op commit");
    }
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx1, &before) == 0,
           "cold before snapshot");
    expect(ninlil_mfdt_v1_engine_init(&tx2, &ws2, &st2, &cfg) == 0,
           "cold fresh engine");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&tx2, tid, 1u) == 0,
           "cold raw restart");
    expect(ninlil_mfdt_v1_pipeline_sender_rehydrate(
               &p2, &tx2, tid, 1u, 0x55ull) == 0,
           "cold pipeline rehydrate");
    expect(p2.phase == NINLIL_MFDT_V1_PHASE_REISSUE_OPEN,
           "cold open reissue phase");
    expect(ninlil_mfdt_v1_pipeline_sender_pump(&p2) == 0,
           "cold open reissue pump");
    expect(p2.phase == NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC &&
               p2.outbox_valid != 0u,
           "cold open is on wire");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&tx2, &after) == 0,
           "cold after snapshot");
    expect(after.record_generation == before.record_generation + 1u &&
               ninlil_mfdt_v1_retry_budget_remaining(&tx2) + 1u ==
                   ninlil_mfdt_v1_retry_budget_remaining(&tx1),
           "cold retry FULL before wire");
}

static void test_generic_bearer_worker_publication_crash_restart(void)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t tx, rx, rx2;
    ninlil_mfdt_v1_workspace_t tws, rws, rws2;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb, pb2;
    ninlil_mfdt_v1_bearer_worker_t wa, wb, wb2;
    worker_link_t la, lb;
    upper_fixture_t upper;
    ninlil_mfdt_v1_active_snapshot_t before, after;
    uint8_t tid[16];
    uint8_t content[32];
    uint32_t step;
    int rc;

    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2u;
    cfg.host_mode = 1u;
    cfg.session_generation = 1u;
    cfg.now_ms = 100u;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 0x72, sizeof(tid));
    tid[0] = 0x41u;
    memset(content, 0xd3, sizeof(content));
    memset(&la, 0, sizeof(la));
    memset(&lb, 0, sizeof(lb));
    memset(&upper, 0, sizeof(upper));
    la.peer = &lb;
    lb.peer = &la;
    la.now_ms = 100u;
    lb.now_ms = 100u;
    ninlil_mfdt_v1_lab_store_init(&tst);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&tx, &tws, &tst, &cfg) == 0,
           "worker tx init");
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == 0,
           "worker rx init");
    ninlil_mfdt_v1_pipeline_init(&pa, &tx, NULL, NULL, NULL, 1u, 0x9911ull);
    ninlil_mfdt_v1_pipeline_init(&pb, NULL, &rx, NULL, NULL, 1u, 0x9911ull);
    expect(ninlil_mfdt_v1_bearer_worker_init(
               &wa, &pa, worker_link_tx, worker_link_rx, worker_link_now, &la,
               NULL, NULL, 2u) == 0,
           "worker a init");
    /* First transfer to ACCEPT_NOTIFIED without handing off to upper yet. */
    expect(ninlil_mfdt_v1_bearer_worker_init(
               &wb, &pb, worker_link_tx, worker_link_rx, worker_link_now, &lb,
               NULL, NULL, 2u) == 0,
           "worker b init");
    expect(ninlil_mfdt_v1_pipeline_sender_begin(
               &pa, tid, content, (uint32_t)sizeof(content)) == 0,
           "worker begin");
    for (step = 0u; step < 128u && pa.complete == 0u; ++step) {
        la.now_ms += 1u;
        lb.now_ms += 1u;
        expect(ninlil_mfdt_v1_bearer_worker_step(&wa) == 0, "worker a step");
        expect(ninlil_mfdt_v1_bearer_worker_step(&wb) == 0, "worker b step");
    }
    expect(pa.complete != 0u && rx.publication_ready != 0u,
           "worker remote accept only");
    expect(rx.handoff_complete == 0u && upper.effect_count == 0u,
           "worker no synthetic upper effect");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&rx, &before) == 0,
           "worker pub before");

    /*
     * Crash window: upper PREPARED is durable, receiver publication FULL fails.
     * A fresh process must re-present the same token; upper returns
     * ALREADY_COMMITTED and only the owner record generation advances once.
     */
    wb.prepare_fn = upper_prepare_once;
    wb.upper_user = &upper;
    rst.crash_after_fulls = rst.full_count;
    rc = ninlil_mfdt_v1_bearer_worker_step(&wb);
    expect(rc == NINLIL_MFDT_V1_ERR_STORAGE, "worker handoff crash");
    expect(upper.effect_count == 1u && upper.prepare_calls == 1u,
           "worker one upper effect before crash");
    expect(rx.handoff_complete == 0u, "worker owner not falsely committed");
    rst.crash_after_fulls = 0u;

    memset(&rx, 0xa5, sizeof(rx));
    memset(&rws, 0xa5, sizeof(rws));
    memset(&pb, 0xa5, sizeof(pb));
    expect(ninlil_mfdt_v1_engine_init(&rx2, &rws2, &rst, &cfg) == 0,
           "worker cold rx init");
    expect(ninlil_mfdt_v1_restart_scan_transfer(&rx2, tid, 2u) == 0,
           "worker cold rx scan");
    ninlil_mfdt_v1_pipeline_init(&pb2, NULL, &rx2, NULL, NULL, 1u, 0x9911ull);
    expect(ninlil_mfdt_v1_bearer_worker_init(
               &wb2, &pb2, worker_link_tx, worker_link_rx, worker_link_now, &lb,
               upper_prepare_once, &upper, 2u) == 0,
           "worker cold b init");
    expect(ninlil_mfdt_v1_bearer_worker_step(&wb2) == 0,
           "worker ALREADY commit");
    expect(upper.effect_count == 1u && upper.prepare_calls == 2u,
           "worker exactly one effect across restart");
    expect(rx2.handoff_complete != 0u, "worker durable handoff complete");
    expect(ninlil_mfdt_v1_engine_active_snapshot(&rx2, &after) == 0,
           "worker pub after");
    expect(after.acceptance_record_generation ==
               before.acceptance_record_generation &&
               after.record_generation == before.record_generation + 1u,
           "worker fixed acceptance generation and one handoff generation");
    expect(memcmp(after.publication_token, before.publication_token, 16u) == 0,
           "worker stable publication token");
    expect(ninlil_mfdt_v1_bearer_worker_step(&wb2) == 0,
           "worker duplicate step");
    expect(upper.effect_count == 1u && upper.prepare_calls == 2u,
           "worker no repeat after durable PUBLISHED");
}

int main(void)
{
    g_fail = 0;
    test_ncl1_roundtrip();
    test_two_endpoint_empty_and_one_byte();
    test_no_local_echo_without_peer();
    test_seam_and_release_policy();
    test_cold_restart_zero_struct_copy_and_publication();
    test_outstanding_rid_bind_invariant();
    test_timeout_and_open_pending_cold_reissue();
    test_generic_bearer_worker_publication_crash_restart();
    if (g_fail) {
        fprintf(stderr, "mfdt_v1_pipeline_test FAILED\n");
        return 1;
    }
    printf("mfdt_v1_pipeline_test OK\n");
    return 0;
}
