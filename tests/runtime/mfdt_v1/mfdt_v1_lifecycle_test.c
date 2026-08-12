/* SPDX-License-Identifier: Apache-2.0 */
/*
 * 10k transfer lifecycle reuse for private MFDT v1 (host lab store).
 * Not HIL. Not public ABI.
 */
#include "mfdt_v1.h"

#include <stdio.h>
#include <string.h>

enum { LIFECYCLE_ITERS = 10000 };

/* Persistent stores across cycles — not a fresh store each transfer. */
static ninlil_mfdt_v1_lab_store_t g_tst;
static ninlil_mfdt_v1_lab_store_t g_rst;
static int g_stores_ready;

static int one_empty_cycle(uint32_t n)
{
    ninlil_mfdt_v1_engine_t tx;
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t tws;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_config_t cfg;
    uint8_t tid[16];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t fin[128];
    uint16_t open_len = 0u;
    uint16_t fin_len = 0u;
    ninlil_mfdt_v1_response_t resp;
    uint64_t rid = 1ull + (uint64_t)n * 16ull;
    size_t i;

    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
    cfg.host_mode = 1u;
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    cfg.now_ms = 1000ull + (uint64_t)n;
    (void)memset(cfg.local_clock_epoch.bytes, 0xc0, 16u);
    if (!g_stores_ready) {
        ninlil_mfdt_v1_lab_store_init(&g_tst);
        ninlil_mfdt_v1_lab_store_init(&g_rst);
        g_stores_ready = 1;
    }
    if (ninlil_mfdt_v1_engine_init(&tx, &tws, &g_tst, &cfg) != NINLIL_MFDT_V1_OK) {
        return 1;
    }
    if (ninlil_mfdt_v1_engine_init(&rx, &rws, &g_rst, &cfg) != NINLIL_MFDT_V1_OK) {
        return 2;
    }
    for (i = 0; i < 16u; ++i) {
        tid[i] = (uint8_t)((n + (uint32_t)i) & 0xffu);
    }
    if (ninlil_mfdt_v1_sender_open(&tx, tid, NULL, 0u, open, &open_len, rid) !=
        NINLIL_MFDT_V1_OK) {
        return 3;
    }
    if (ninlil_mfdt_v1_receiver_on_open(&rx, open, open_len, rid, &resp) !=
            NINLIL_MFDT_V1_OK ||
        resp.message_type != NINLIL_MFDT_V1_MSG_OPEN_ACCEPT) {
        return 4;
    }
    if (ninlil_mfdt_v1_sender_on_open_accept(&tx, resp.body, resp.body_len, rid) !=
        NINLIL_MFDT_V1_OK) {
        return 5;
    }
    rid += 1ull;
    if (ninlil_mfdt_v1_sender_finalize(&tx, rid, fin, &fin_len) !=
        NINLIL_MFDT_V1_OK) {
        return 6;
    }
    if (ninlil_mfdt_v1_receiver_on_finalize(&rx, fin, fin_len, rid, &resp) !=
            NINLIL_MFDT_V1_OK ||
        resp.message_type != NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT) {
        return 7;
    }
    if (ninlil_mfdt_v1_sender_on_transfer_accept(&tx, resp.body, resp.body_len, rid) !=
        NINLIL_MFDT_V1_OK) {
        return 8;
    }
    if (ninlil_mfdt_v1_receiver_complete_handoff(&rx) != NINLIL_MFDT_V1_OK) {
        return 9;
    }
    if (ninlil_mfdt_v1_terminal_complete(&rx) != NINLIL_MFDT_V1_OK) {
        return 10;
    }
    if (ninlil_mfdt_v1_terminal_complete(&tx) != NINLIL_MFDT_V1_OK) {
        return 11;
    }
    ninlil_mfdt_v1_engine_set_now(
        &rx, cfg.now_ms + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT);
    ninlil_mfdt_v1_engine_set_now(
        &tx, cfg.now_ms + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT);
    if (ninlil_mfdt_v1_retention_gc(&rx) != NINLIL_MFDT_V1_OK) {
        return 12;
    }
    if (ninlil_mfdt_v1_retention_gc(&tx) != NINLIL_MFDT_V1_OK) {
        return 13;
    }
    return 0;
}

int main(void)
{
    uint32_t n;
    for (n = 0u; n < (uint32_t)LIFECYCLE_ITERS; ++n) {
        int rc = one_empty_cycle(n);
        if (rc != 0) {
            (void)fprintf(stderr, "lifecycle fail iter=%u rc=%d\n", n, rc);
            return 1;
        }
        if ((n % 2000u) == 0u) {
            (void)printf("lifecycle progress %u\n", n);
            (void)fflush(stdout);
        }
    }
    (void)printf("mfdt_v1_lifecycle_test OK (%d)\n", LIFECYCLE_ITERS);
    return 0;
}
