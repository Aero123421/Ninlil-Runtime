/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host unit tests for private MFDT v1 (crypto, geometry, CU, policy).
 * Not HIL. Not public ABI. Not SPEC_ACCEPTED claim.
 */
#include "mfdt_v1.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        (void)fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void test_geometry(void)
{
    ninlil_mfdt_v1_geometry_t g;
    expect(ninlil_mfdt_v1_geometry(0u, &g) == NINLIL_MFDT_V1_OK, "geo0");
    expect(g.chunk_count == 0u && g.page_count == 0u, "geo0 counts");
    expect(ninlil_mfdt_v1_geometry(1u, &g) == NINLIL_MFDT_V1_OK, "geo1");
    expect(g.chunk_count == 1u && g.page_count == 1u &&
               g.final_chunk_length == 1u,
           "geo1 counts");
    expect(ninlil_mfdt_v1_geometry(896u, &g) == NINLIL_MFDT_V1_OK, "geo896");
    expect(g.chunk_count == 1u && g.final_chunk_length == 896u, "geo896 fin");
    expect(ninlil_mfdt_v1_geometry(897u, &g) == NINLIL_MFDT_V1_OK, "geo897");
    expect(g.chunk_count == 2u && g.page_count == 1u &&
               g.final_chunk_length == 1u,
           "geo897");
    /* 22 entries per page → 22 chunks = 1 page; 23 = 2 pages */
    expect(ninlil_mfdt_v1_geometry(22u * 896u, &g) == NINLIL_MFDT_V1_OK,
           "geo22c");
    expect(g.chunk_count == 22u && g.page_count == 1u, "geo22c pages");
    expect(ninlil_mfdt_v1_geometry(23u * 896u, &g) == NINLIL_MFDT_V1_OK,
           "geo23c");
    expect(g.chunk_count == 23u && g.page_count == 2u, "geo23c pages");
    expect(ninlil_mfdt_v1_geometry(32768u, &g) == NINLIL_MFDT_V1_OK, "geo max");
    expect(g.chunk_count == 37u && g.page_count == 2u, "geo max counts");
    expect(ninlil_mfdt_v1_geometry(32769u, &g) == NINLIL_MFDT_V1_ERR_PARAM,
           "geo over");
}

static void test_sha256_empty(void)
{
    uint8_t out[32];
    /* FIPS empty string digest */
    static const uint8_t exp[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    ninlil_mfdt_v1_sha256((const uint8_t *)"", 0u, out);
    expect(ninlil_mfdt_v1_memeq(out, exp, 32u), "sha256 empty");
}

static void test_request_body_digest(void)
{
    uint8_t a[32];
    uint8_t b[32];
    uint8_t body[4] = {1, 2, 3, 4};
    ninlil_mfdt_v1_request_body_digest(0x40u, body, 4u, a);
    ninlil_mfdt_v1_request_body_digest(0x40u, body, 4u, b);
    expect(ninlil_mfdt_v1_memeq(a, b, 32u), "req dig stable");
    ninlil_mfdt_v1_request_body_digest(0x41u, body, 4u, b);
    expect(!ninlil_mfdt_v1_memeq(a, b, 32u), "req dig type sensitive");
}

static void test_cu_classify(void)
{
    expect(ninlil_mfdt_v1_classify_cu(1, 0, 0, 0, 0, 0, 0) ==
               NINLIL_MFDT_V1_CU_OLD,
           "cu old");
    expect(ninlil_mfdt_v1_classify_cu(0, 1, 0, 0, 0, 0, 0) ==
               NINLIL_MFDT_V1_CU_NEW,
           "cu new");
    expect(ninlil_mfdt_v1_classify_cu(0, 0, 1, 0, 0, 0, 0) ==
               NINLIL_MFDT_V1_CU_PARTIAL,
           "cu partial");
    expect(ninlil_mfdt_v1_classify_cu(0, 0, 0, 1, 0, 0, 0) ==
               NINLIL_MFDT_V1_CU_EXTRA,
           "cu extra");
    expect(ninlil_mfdt_v1_classify_cu(0, 0, 0, 0, 1, 0, 0) ==
               NINLIL_MFDT_V1_CU_THIRD,
           "cu third");
    expect(ninlil_mfdt_v1_classify_cu(0, 0, 0, 0, 0, 0, 1) ==
               NINLIL_MFDT_V1_CU_ABSENT,
           "cu absent");
    expect(ninlil_mfdt_v1_classify_cu(0, 0, 0, 0, 0, 1, 0) ==
               NINLIL_MFDT_V1_CU_BOTH,
           "cu both");
}

static void test_budget_pins(void)
{
    expect(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX == 35211u,
           "active value max 35211");
    expect(ninlil_mfdt_v1_receiver_fulls_max() == 77u, "rx fulls 77");
    expect(ninlil_mfdt_v1_sender_fulls_max() == 67u, "tx fulls 67");
}

static void test_policy_off(void)
{
    ninlil_mfdt_v1_engine_t eng;
    ninlil_mfdt_v1_workspace_t ws;
    ninlil_mfdt_v1_lab_store_t st;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t olen = 0u;
    uint8_t tid[16];
    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_OFF;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
    cfg.host_mode = 1u;
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_engine_init(&eng, &ws, &st, &cfg) == NINLIL_MFDT_V1_OK,
           "init");
    ninlil_mfdt_v1_memzero(tid, sizeof(tid));
    tid[0] = 1u;
    expect(ninlil_mfdt_v1_sender_open(&eng, tid, NULL, 0u, open, &olen, 1ull) ==
               NINLIL_MFDT_V1_ERR_POLICY_OFF,
           "policy off");
    ninlil_mfdt_v1_engine_set_policy(&eng, NINLIL_MFDT_V1_POLICY_ON);
    ninlil_mfdt_v1_engine_set_admission_version(&eng, 1u);
    expect(ninlil_mfdt_v1_sender_open(&eng, tid, NULL, 0u, open, &olen, 1ull) ==
               NINLIL_MFDT_V1_ERR_VERSION,
           "version gate");
}

int main(void)
{
    g_fail = 0;
    test_geometry();
    test_sha256_empty();
    test_request_body_digest();
    test_cu_classify();
    test_budget_pins();
    test_policy_off();
    if (g_fail) {
        (void)fprintf(stderr, "mfdt_v1_unit_test FAILED\n");
        return 1;
    }
    (void)printf("mfdt_v1_unit_test OK\n");
    return 0;
}
