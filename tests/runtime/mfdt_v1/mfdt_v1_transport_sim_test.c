/* SPDX-License-Identifier: Apache-2.0
 * Two-endpoint transport simulation: WOULD_BLOCK, drop, reorder, restart.
 * No synthetic single-pipeline self-loop.
 */
#include "mfdt_v1.h"
#include "mfdt_v1_pipeline.h"

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

typedef struct {
    uint8_t frames[16][NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t lens[16];
    uint8_t count;
    uint8_t drop_next;
    uint8_t reorder; /* swap first two on flush */
    int would_block;
    int send_calls;
} sim_link_t;

static int sim_send(void *user, const uint8_t *ncl1, size_t nlen)
{
    sim_link_t *L = (sim_link_t *)user;
    L->send_calls += 1;
    if (L->would_block) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (L->drop_next) {
        L->drop_next = 0u;
        return 0; /* accepted by "network" then dropped */
    }
    if (L->count >= 16u || nlen > NINLIL_MFDT_V1_NCL1_MAX_MSG) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    (void)memcpy(L->frames[L->count], ncl1, nlen);
    L->lens[L->count] = nlen;
    L->count = (uint8_t)(L->count + 1u);
    return 0;
}

static void sim_flush_to(sim_link_t *L, ninlil_mfdt_v1_pipeline_t *peer)
{
    uint8_t i;
    if (L->reorder && L->count >= 2u) {
        uint8_t tmp[NINLIL_MFDT_V1_NCL1_MAX_MSG];
        size_t tl = L->lens[0];
        (void)memcpy(tmp, L->frames[0], tl);
        (void)memcpy(L->frames[0], L->frames[1], L->lens[1]);
        L->lens[0] = L->lens[1];
        (void)memcpy(L->frames[1], tmp, tl);
        L->lens[1] = tl;
        L->reorder = 0u;
    }
    for (i = 0u; i < L->count; ++i) {
        (void)ninlil_mfdt_v1_pipeline_on_ncl1_ingress(peer, L->frames[i],
                                                      L->lens[i]);
    }
    L->count = 0u;
}

static void setup_pair(ninlil_mfdt_v1_engine_t *ta, ninlil_mfdt_v1_engine_t *ra,
                       ninlil_mfdt_v1_workspace_t *tws,
                       ninlil_mfdt_v1_workspace_t *rws,
                       ninlil_mfdt_v1_lab_store_t *tst,
                       ninlil_mfdt_v1_lab_store_t *rst,
                       ninlil_mfdt_v1_pipeline_t *pa,
                       ninlil_mfdt_v1_pipeline_t *pb, sim_link_t *ab,
                       sim_link_t *ba)
{
    ninlil_mfdt_v1_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = 5000;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    ninlil_mfdt_v1_lab_store_init(tst);
    ninlil_mfdt_v1_lab_store_init(rst);
    (void)ninlil_mfdt_v1_engine_init(ta, tws, tst, &cfg);
    (void)ninlil_mfdt_v1_engine_init(ra, rws, rst, &cfg);
    memset(ab, 0, sizeof(*ab));
    memset(ba, 0, sizeof(*ba));
    ninlil_mfdt_v1_pipeline_init(pa, ta, NULL, sim_send, ab, 1u, 0x55ull);
    ninlil_mfdt_v1_pipeline_init(pb, NULL, ra, sim_send, ba, 1u, 0x55ull);
}

static int pump_links(ninlil_mfdt_v1_pipeline_t *pa, ninlil_mfdt_v1_pipeline_t *pb,
                      sim_link_t *ab, sim_link_t *ba, uint32_t steps)
{
    uint32_t i;
    for (i = 0u; i < steps; ++i) {
        if (pa->complete) {
            return 0;
        }
        (void)ninlil_mfdt_v1_pipeline_sender_pump(pa);
        /* Drain outbox if send_fn WOULD_BLOCK retained frames. */
        if (ninlil_mfdt_v1_pipeline_outbox_pending(pa)) {
            uint8_t f[NINLIL_MFDT_V1_NCL1_MAX_MSG];
            size_t n = 0u;
            if (ninlil_mfdt_v1_pipeline_take_outbound(pa, f, sizeof(f), &n) == 0 &&
                n > 0u) {
                (void)sim_send(ab, f, n);
            }
        }
        if (ninlil_mfdt_v1_pipeline_outbox_pending(pb)) {
            uint8_t f[NINLIL_MFDT_V1_NCL1_MAX_MSG];
            size_t n = 0u;
            if (ninlil_mfdt_v1_pipeline_take_outbound(pb, f, sizeof(f), &n) == 0 &&
                n > 0u) {
                (void)sim_send(ba, f, n);
            }
        }
        sim_flush_to(ab, pb);
        sim_flush_to(ba, pa);
    }
    return pa->complete ? 0 : -1;
}

static void test_happy_path(void)
{
    ninlil_mfdt_v1_engine_t ta, ra;
    ninlil_mfdt_v1_workspace_t tws, rws;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb;
    sim_link_t ab, ba;
    uint8_t tid[16];
    uint8_t data[32];
    memset(tid, 1, 16);
    memset(data, 0xee, sizeof(data));
    setup_pair(&ta, &ra, &tws, &rws, &tst, &rst, &pa, &pb, &ab, &ba);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, data, 32) == 0,
           "begin");
    expect(pa.complete == 0, "not done");
    expect(pump_links(&pa, &pb, &ab, &ba, 128) == 0, "pump");
    expect(pa.complete == 1, "done");
    expect(ra.publication_ready == 1, "pub");
}

static void test_would_block_then_resume(void)
{
    ninlil_mfdt_v1_engine_t ta, ra;
    ninlil_mfdt_v1_workspace_t tws, rws;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb;
    sim_link_t ab, ba;
    uint8_t tid[16];
    uint8_t data[8];
    memset(tid, 2, 16);
    memset(data, 0x11, sizeof(data));
    setup_pair(&ta, &ra, &tws, &rws, &tst, &rst, &pa, &pb, &ab, &ba);
    ab.would_block = 1;
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, data, 8) == 0,
           "begin wb");
    /* OPEN retained in outbox due to WOULD_BLOCK */
    expect(ninlil_mfdt_v1_pipeline_outbox_pending(&pa) == 1, "outbox retained");
    ab.would_block = 0;
    expect(pump_links(&pa, &pb, &ab, &ba, 128) == 0, "resume");
    expect(pa.complete == 1, "complete after resume");
}

static void test_drop_open_no_false_complete(void)
{
    ninlil_mfdt_v1_engine_t ta, ra;
    ninlil_mfdt_v1_workspace_t tws, rws;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb;
    sim_link_t ab, ba;
    uint8_t tid[16];
    uint8_t data[4];
    memset(tid, 3, 16);
    memset(data, 0x22, sizeof(data));
    setup_pair(&ta, &ra, &tws, &rws, &tst, &rst, &pa, &pb, &ab, &ba);
    ab.drop_next = 1;
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, data, 4) == 0, "begin");
    (void)ninlil_mfdt_v1_pipeline_sender_pump(&pa);
    sim_flush_to(&ab, &pb); /* drop already consumed */
    expect(pa.complete == 0, "no complete after drop");
    expect(ra.publication_ready == 0, "rx never saw open");
}

static void test_no_provider_outbox_only(void)
{
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_engine_t ta;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_lab_store_t tst;
    ninlil_mfdt_v1_pipeline_t pa;
    uint8_t tid[16];
    uint8_t f[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t n = 0u;
    memset(&cfg, 0, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 2;
    cfg.host_mode = 1;
    cfg.now_ms = 1;
    memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    memset(tid, 4, 16);
    ninlil_mfdt_v1_lab_store_init(&tst);
    (void)ninlil_mfdt_v1_engine_init(&ta, &tws, &tst, &cfg);
    ninlil_mfdt_v1_pipeline_init(&pa, &ta, NULL, NULL, NULL, 1u, 9ull);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, tid, 16) == 0, "begin");
    expect(ninlil_mfdt_v1_pipeline_outbox_pending(&pa) == 1, "outbox");
    expect(ninlil_mfdt_v1_pipeline_take_outbound(&pa, f, sizeof(f), &n) == 0 &&
               n > 0u,
           "take");
    expect(pa.complete == 0, "no complete without peer");
}

static void test_restart_mid_transfer(void)
{
    ninlil_mfdt_v1_engine_t ta, ra;
    ninlil_mfdt_v1_workspace_t tws, rws;
    ninlil_mfdt_v1_lab_store_t tst, rst;
    ninlil_mfdt_v1_pipeline_t pa, pb;
    sim_link_t ab, ba;
    uint8_t tid[16];
    uint8_t data[16];
    uint8_t key[20];
    uint32_t len = 0u;
    memset(tid, 5, 16);
    memset(data, 0x33, sizeof(data));
    setup_pair(&ta, &ra, &tws, &rws, &tst, &rst, &pa, &pb, &ab, &ba);
    expect(ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, data, 16) == 0,
           "begin");
    /* Deliver OPEN only */
    (void)ninlil_mfdt_v1_pipeline_sender_pump(&pa);
    sim_flush_to(&ab, &pb);
    sim_flush_to(&ba, &pa);
    expect(pa.complete == 0, "mid");
    memcpy(key, "NM3S", 4);
    memcpy(key + 4, tid, 16);
    expect(ninlil_mfdt_v1_lab_get(&tst, key, NULL, 0u, &len) == 0 && len > 0u,
           "NM3S durable mid");
    /* Restart scan keeps durable; no auto-complete */
    expect(ninlil_mfdt_v1_restart_scan(&ta) == 0, "restart");
    expect(pa.complete == 0, "still incomplete");
    /* Continue pump to finish */
    expect(pump_links(&pa, &pb, &ab, &ba, 128) == 0, "finish after restart");
    expect(pa.complete == 1, "complete");
}

int main(void)
{
    g_fail = 0;
    test_happy_path();
    test_would_block_then_resume();
    test_drop_open_no_false_complete();
    test_no_provider_outbox_only();
    test_restart_mid_transfer();
    if (g_fail) {
        fprintf(stderr, "mfdt_v1_transport_sim_test FAILED\n");
        return 1;
    }
    printf("mfdt_v1_transport_sim_test OK\n");
    return 0;
}
