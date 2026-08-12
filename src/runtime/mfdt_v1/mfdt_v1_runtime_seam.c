/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Runtime seam: ApplicationData → two-endpoint MFDT transfer (private).
 * Host lab only: pumps real frames between local A(sender) and B(receiver).
 * No single-pipeline self-echo. Caller-owned workspaces.
 */
#include "mfdt_v1_runtime_seam.h"

#include "mfdt_v1.h"
#include "mfdt_v1_pipeline.h"

#include <string.h>

/* Private in-memory context tag; not a wire/storage protocol magic. */
#define MFDT_SEAM_MAGIC ((uint32_t)0x4d534d81u)

/*
 * The private engine and direct Fabric candidate are software-green, but the
 * release matrix is not: public Runtime scheduling, instance-local ownership,
 * Runtime Storage Port custody, and joined public-submit E2E remain open.
 * Keep this pin fail-closed independently of the HIL pin so that adding
 * physical evidence cannot accidentally enable an incomplete composition.
 */
static const int g_acceptance_software_green = 0;
static const int g_acceptance_hil_green = 0; /* honest: no physical HIL */

static int seam_valid(const ninlil_mfdt_v1_seam_ctx_t *ctx)
{
    return ctx != NULL && ctx->magic == MFDT_SEAM_MAGIC;
}

int ninlil_mfdt_v1_seam_init(ninlil_mfdt_v1_seam_ctx_t *ctx)
{
    if (ctx == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(ctx, sizeof(*ctx));
    ctx->magic = MFDT_SEAM_MAGIC;
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_seam_fini(ninlil_mfdt_v1_seam_ctx_t *ctx)
{
    if (ctx != NULL) {
        ninlil_mfdt_v1_memzero(ctx, sizeof(*ctx));
    }
}

int ninlil_mfdt_v1_seam_set_config(
    ninlil_mfdt_v1_seam_ctx_t *ctx,
    const ninlil_mfdt_v1_seam_config_t *cfg)
{
    if (!seam_valid(ctx) || ctx->busy != 0u) {
        return ctx != NULL && ctx->busy != 0u
                   ? NINLIL_MFDT_V1_ERR_BUSY
                   : NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(&ctx->config, sizeof(ctx->config));
    if (cfg != NULL) {
        ctx->config = *cfg;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_seam_get_config(
    const ninlil_mfdt_v1_seam_ctx_t *ctx,
    ninlil_mfdt_v1_seam_config_t *out)
{
    if (!seam_valid(ctx) || out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    *out = ctx->config;
    return NINLIL_MFDT_V1_OK;
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
    ninlil_mfdt_v1_seam_ctx_t *ctx,
    const uint8_t *application_data, uint32_t data_len,
    const uint8_t transfer_id_hint[16], uint8_t out_transfer_id[16],
    uint8_t out_publication_token[16])
{
#if defined(ESP_PLATFORM)
    /* Host-lab dual-workspace seam is unavailable on ESP. Use owner spine. */
    (void)ctx;
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

    if (!seam_valid(ctx)) {
        return NINLIL_MFDT_SEAM_REJECTED;
    }
    if (ctx->busy != 0u) {
        return NINLIL_MFDT_SEAM_BUSY;
    }
    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = ctx->config.policy_on ? NINLIL_MFDT_V1_POLICY_ON
                                       : NINLIL_MFDT_V1_POLICY_OFF;
    cfg.mfdt_admission_version = ctx->config.mfdt_admission_version;
    cfg.mfdt_capability = ctx->config.capability;
    cfg.host_mode = ctx->config.host_mode;
    cfg.session_generation = ctx->config.session_generation;
    cfg.now_ms = ctx->config.now_ms;
    (void)memcpy(cfg.local_clock_epoch.bytes,
                 ctx->config.local_clock_epoch, 16u);
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;

    if (!ninlil_mfdt_v1_pipeline_requires_mfdt(&cfg, data_len) &&
        !(ctx->config.policy_on && ctx->config.capability != 0u &&
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
    ctx->busy = 1u;

    if (transfer_id_hint != NULL) {
        (void)memcpy(tid, transfer_id_hint, 16u);
    } else {
        for (i = 0; i < 16u; ++i) {
            tid[i] = (uint8_t)(0xa0u + (uint8_t)i);
        }
        tid[0] ^= (uint8_t)(data_len & 0xffu);
    }

    ninlil_mfdt_v1_lab_store_init(&ctx->sender_store);
    ninlil_mfdt_v1_lab_store_init(&ctx->receiver_store);
    if (ninlil_mfdt_v1_engine_init(
            &ctx->sender, &ctx->sender_workspace, &ctx->sender_store, &cfg) !=
            NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_engine_init(
            &ctx->receiver, &ctx->receiver_workspace,
            &ctx->receiver_store, &cfg) != NINLIL_MFDT_V1_OK) {
        ctx->busy = 0u;
        return NINLIL_MFDT_SEAM_STORAGE;
    }
    ninlil_mfdt_v1_pipeline_init(
        &pa, &ctx->sender, NULL, NULL, NULL,
        ctx->config.session_generation ? ctx->config.session_generation : 1u,
        ctx->config.session_cookie ? ctx->config.session_cookie : 0x4d464454ull);
    ninlil_mfdt_v1_pipeline_init(
        &pb, NULL, &ctx->receiver, NULL, NULL,
        ctx->config.session_generation ? ctx->config.session_generation : 1u,
        ctx->config.session_cookie ? ctx->config.session_cookie : 0x4d464454ull);

    rc = ninlil_mfdt_v1_pipeline_sender_begin(&pa, tid, application_data,
                                              data_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        ctx->busy = 0u;
        return NINLIL_MFDT_SEAM_REJECTED;
    }
    /* Bound: open + pages + chunks + fin + accepts ≈ 2*(1+2+37+1) + margin */
    max_steps = 256u;
    rc = two_endpoint_run(&pa, &pb, max_steps);
    if (rc != NINLIL_MFDT_V1_OK) {
        ctx->busy = 0u;
        return NINLIL_MFDT_SEAM_REJECTED;
    }
    rc = ninlil_mfdt_v1_pipeline_finish_terminal(&pa);
    if (rc != NINLIL_MFDT_V1_OK) {
        ctx->busy = 0u;
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
    ctx->busy = 0u;
    return NINLIL_MFDT_SEAM_OK;
#endif
}
