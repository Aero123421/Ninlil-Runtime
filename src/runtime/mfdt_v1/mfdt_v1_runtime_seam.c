/* SPDX-License-Identifier: Apache-2.0
 * Runtime seam: ApplicationData → two-endpoint MFDT transfer (private).
 * Host lab only: pumps real frames between local A(sender) and B(receiver).
 * No single-pipeline self-echo. BSS-backed workspaces.
 */
#include "mfdt_v1_runtime_seam.h"

#include "mfdt_v1.h"
#include "mfdt_v1_pipeline.h"

#include <string.h>

static ninlil_mfdt_v1_seam_config_t g_seam_cfg;

/*
 * The private engine and direct Fabric candidate are software-green, but the
 * release matrix is not: public Runtime scheduling, instance-local ownership,
 * Runtime Storage Port custody, and joined public-submit E2E remain open.
 * Keep this pin fail-closed independently of the HIL pin so that adding
 * physical evidence cannot accidentally enable an incomplete composition.
 */
static const int g_acceptance_software_green = 0;
static const int g_acceptance_hil_green = 0; /* honest: no physical HIL */

/*
 * Two endpoints: sender A + receiver B (no dual-role self-loop).
 * Host lab only: static dual workspace/store (~2 * (64K+lab)).
 * ESP: not BSS-resident — try_application_data fail-closed (spine path used).
 */
#if !defined(ESP_PLATFORM)
static ninlil_mfdt_v1_workspace_t g_seam_aws;
static ninlil_mfdt_v1_workspace_t g_seam_bws;
static ninlil_mfdt_v1_lab_store_t g_seam_ast;
static ninlil_mfdt_v1_lab_store_t g_seam_bst;
static ninlil_mfdt_v1_engine_t g_seam_a;
static ninlil_mfdt_v1_engine_t g_seam_b;
static uint8_t g_seam_busy;
#endif

void ninlil_mfdt_v1_seam_set_config(const ninlil_mfdt_v1_seam_config_t *cfg)
{
    if (cfg == NULL) {
        ninlil_mfdt_v1_memzero(&g_seam_cfg, sizeof(g_seam_cfg));
        return;
    }
    g_seam_cfg = *cfg;
}

void ninlil_mfdt_v1_seam_get_config(ninlil_mfdt_v1_seam_config_t *out)
{
    if (out != NULL) {
        *out = g_seam_cfg;
    }
}

int ninlil_mfdt_v1_release_policy_allows_default_on(void)
{
    return g_acceptance_software_green && g_acceptance_hil_green ? 1 : 0;
}

/*
 * Pump A→B→A until sender complete or max steps (bounded, no infinite loop).
 * Frames only move via take_outbound / on_ncl1_ingress (real endpoint path).
 */
#if !defined(ESP_PLATFORM)
static int two_endpoint_run(ninlil_mfdt_v1_pipeline_t *a,
                            ninlil_mfdt_v1_pipeline_t *b, uint32_t max_steps)
{
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t flen = 0u;
    uint32_t step;
    int rc;
    int progressed;

    for (step = 0u; step < max_steps; ++step) {
        if (a->complete && b->rx != NULL && b->rx->publication_ready) {
            return NINLIL_MFDT_V1_OK;
        }
        progressed = 0;
        (void)ninlil_mfdt_v1_pipeline_sender_pump(a);
        if (ninlil_mfdt_v1_pipeline_take_outbound(a, frame, sizeof(frame),
                                                  &flen) == 0 &&
            flen > 0u) {
            rc = ninlil_mfdt_v1_pipeline_on_ncl1_ingress(b, frame, flen);
            if (rc != NINLIL_MFDT_V1_OK) {
                return rc;
            }
            progressed = 1;
        }
        if (ninlil_mfdt_v1_pipeline_take_outbound(b, frame, sizeof(frame),
                                                  &flen) == 0 &&
            flen > 0u) {
            rc = ninlil_mfdt_v1_pipeline_on_ncl1_ingress(a, frame, flen);
            if (rc != NINLIL_MFDT_V1_OK) {
                return rc;
            }
            progressed = 1;
        }
        if (!progressed && a->complete) {
            return NINLIL_MFDT_V1_OK;
        }
        if (!progressed) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
    }
    return NINLIL_MFDT_V1_ERR_BUSY;
}

#endif /* !ESP_PLATFORM two_endpoint */

int ninlil_mfdt_v1_seam_try_application_data(
    const uint8_t *application_data, uint32_t data_len,
    const uint8_t transfer_id_hint[16], uint8_t out_transfer_id[16],
    uint8_t out_publication_token[16])
{
#if defined(ESP_PLATFORM)
    /* Host-lab dual-workspace seam is not linked into ESP DRAM. Use spine. */
    (void)application_data;
    (void)data_len;
    (void)transfer_id_hint;
    (void)out_transfer_id;
    (void)out_publication_token;
    return NINLIL_MFDT_SEAM_REJECTED;
#else

    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_pipeline_t pa;
    ninlil_mfdt_v1_pipeline_t pb;
    uint8_t tid[16];
    int rc;
    size_t i;
    uint32_t max_steps;

    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = g_seam_cfg.policy_on ? NINLIL_MFDT_V1_POLICY_ON
                                      : NINLIL_MFDT_V1_POLICY_OFF;
    cfg.mfdt_admission_version = g_seam_cfg.mfdt_admission_version;
    cfg.mfdt_capability = g_seam_cfg.capability;
    cfg.host_mode = g_seam_cfg.host_mode;
    cfg.session_generation = g_seam_cfg.session_generation;
    cfg.now_ms = g_seam_cfg.now_ms;
    (void)memcpy(cfg.local_clock_epoch.bytes,
                 g_seam_cfg.local_clock_epoch, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;

    if (!ninlil_mfdt_v1_pipeline_requires_mfdt(&cfg, data_len) &&
        !(g_seam_cfg.policy_on && g_seam_cfg.capability != 0u &&
          data_len > NINLIL_MFDT_V1_U6_SINGLE_FRAME_MAX)) {
        return NINLIL_MFDT_SEAM_NOT_APPLICABLE;
    }
    if (ninlil_mfdt_v1_admission_check(&cfg) != NINLIL_MFDT_V1_OK) {
        if (data_len > NINLIL_MFDT_V1_U6_SINGLE_FRAME_MAX) {
            return NINLIL_MFDT_SEAM_REJECTED;
        }
        return NINLIL_MFDT_SEAM_NOT_APPLICABLE;
    }
    if (data_len > NINLIL_MFDT_V1_MAX_CONTENT) {
        return NINLIL_MFDT_SEAM_REJECTED;
    }
    if (g_seam_busy) {
        return NINLIL_MFDT_SEAM_BUSY;
    }
    g_seam_busy = 1u;

    if (transfer_id_hint != NULL) {
        (void)memcpy(tid, transfer_id_hint, 16u);
    } else {
        for (i = 0; i < 16u; ++i) {
            tid[i] = (uint8_t)(0xa0u + (uint8_t)i);
        }
        tid[0] ^= (uint8_t)(data_len & 0xffu);
    }

    ninlil_mfdt_v1_lab_store_init(&g_seam_ast);
    ninlil_mfdt_v1_lab_store_init(&g_seam_bst);
    if (ninlil_mfdt_v1_engine_init(&g_seam_a, &g_seam_aws, &g_seam_ast, &cfg) !=
            NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_engine_init(&g_seam_b, &g_seam_bws, &g_seam_bst, &cfg) !=
            NINLIL_MFDT_V1_OK) {
        g_seam_busy = 0u;
        return NINLIL_MFDT_SEAM_STORAGE;
    }
    ninlil_mfdt_v1_pipeline_init(
        &pa, &g_seam_a, NULL, NULL, NULL,
        g_seam_cfg.session_generation ? g_seam_cfg.session_generation : 1u,
        g_seam_cfg.session_cookie ? g_seam_cfg.session_cookie : 0x4d464454ull);
    ninlil_mfdt_v1_pipeline_init(
        &pb, NULL, &g_seam_b, NULL, NULL,
        g_seam_cfg.session_generation ? g_seam_cfg.session_generation : 1u,
        g_seam_cfg.session_cookie ? g_seam_cfg.session_cookie : 0x4d464454ull);

    rc = ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, application_data,
                                              data_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        g_seam_busy = 0u;
        return NINLIL_MFDT_SEAM_REJECTED;
    }
    /* Bound: open + pages + chunks + fin + accepts ≈ 2*(1+2+37+1) + margin */
    max_steps = 256u;
    rc = two_endpoint_run(&pa, &pb, max_steps);
    if (rc != NINLIL_MFDT_V1_OK) {
        g_seam_busy = 0u;
        return NINLIL_MFDT_SEAM_REJECTED;
    }
    rc = ninlil_mfdt_v1_pipeline_finish_terminal(&pa);
    if (rc != NINLIL_MFDT_V1_OK) {
        g_seam_busy = 0u;
        return NINLIL_MFDT_SEAM_STORAGE;
    }
    /*
     * This Host seam proves transport/acceptance only.  It has no durable
     * upper application sink, so it must not synthesize publication evidence
     * or terminalize receiver custody. Production uses bearer_worker +
     * receiver_commit_publication().
     */
    if (out_transfer_id != NULL) {
        (void)memcpy(out_transfer_id, tid, 16u);
    }
    if (out_publication_token != NULL) {
        (void)memcpy(out_publication_token, pb.publication_token, 16u);
    }
    g_seam_busy = 0u;
    return NINLIL_MFDT_SEAM_OK;
#endif
}
