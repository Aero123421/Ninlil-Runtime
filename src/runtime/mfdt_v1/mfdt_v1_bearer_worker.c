/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_bearer_worker.h"

#include <string.h>
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
#include <stdio.h>
#endif

static int dispatch_owned_outbox(ninlil_mfdt_v1_bearer_worker_t *worker)
{
    ninlil_mfdt_v1_pipeline_t *p = worker->pipeline;
    int rc;

    if (p->outbox_valid == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    rc = worker->tx_fn(worker->bearer_user, p->outbox, p->outbox_len);
    if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
        return rc;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc < 0 ? rc : NINLIL_MFDT_V1_ERR_STORAGE;
    }
    p->outbox_valid = 0u;
    p->outbox_len = 0u;
    return NINLIL_MFDT_V1_OK;
}

static int prepare_publication(ninlil_mfdt_v1_bearer_worker_t *worker)
{
    ninlil_mfdt_v1_engine_t *rx = worker->pipeline->rx;
    const uint8_t *content = NULL;
    uint32_t content_len = 0u;
    uint8_t token[16];
    uint8_t evidence[32];
    uint64_t acceptance_generation = 0ull;
    int rc;

    if (rx == NULL || rx->publication_ready == 0u ||
        rx->handoff_complete != 0u || worker->prepare_fn == NULL) {
        return NINLIL_MFDT_V1_OK;
    }
    rc = ninlil_mfdt_v1_receiver_publication_view(
        rx, &content, &content_len, token, &acceptance_generation);
    if (rc == NINLIL_MFDT_V1_ERR_STATE) {
        return NINLIL_MFDT_V1_OK;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (acceptance_generation == 0ull) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    (void)memset(evidence, 0, sizeof(evidence));
    worker->publication_attempt_count += 1u;
    rc = worker->prepare_fn(worker->upper_user, token, content, content_len,
                            evidence);
    if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
        return NINLIL_MFDT_V1_OK;
    }
    if (rc != NINLIL_MFDT_V1_PREPARED &&
        rc != NINLIL_MFDT_V1_ALREADY_COMMITTED) {
        return rc < 0 ? rc : NINLIL_MFDT_V1_ERR_STORAGE;
    }
    return ninlil_mfdt_v1_receiver_commit_publication(rx, token, evidence);
}

int ninlil_mfdt_v1_bearer_worker_init(
    ninlil_mfdt_v1_bearer_worker_t *worker,
    ninlil_mfdt_v1_pipeline_t *pipeline, ninlil_mfdt_v1_bearer_tx_fn tx_fn,
    ninlil_mfdt_v1_bearer_rx_fn rx_fn, ninlil_mfdt_v1_bearer_now_fn now_fn,
    void *bearer_user, ninlil_mfdt_v1_upper_prepare_fn prepare_fn,
    void *upper_user, uint8_t rx_budget)
{
    if (worker == NULL || pipeline == NULL || tx_fn == NULL || rx_fn == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(worker, 0, sizeof(*worker));
    worker->pipeline = pipeline;
    worker->tx_fn = tx_fn;
    worker->rx_fn = rx_fn;
    worker->now_fn = now_fn;
    worker->bearer_user = bearer_user;
    worker->prepare_fn = prepare_fn;
    worker->upper_user = upper_user;
    worker->rx_budget = rx_budget != 0u ? rx_budget : 1u;
    worker->initialized = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_bearer_worker_step(
    ninlil_mfdt_v1_bearer_worker_t *worker)
{
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t frame_len;
    uint64_t now_ms;
    uint8_t i;
    int rc;

    if (worker == NULL || worker->initialized == 0u ||
        worker->pipeline == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    now_ms = worker->now_fn != NULL
                 ? worker->now_fn(worker->bearer_user)
                 : worker->pipeline->now_ms;
    rc = ninlil_mfdt_v1_pipeline_tick(worker->pipeline, now_ms);
    if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
        return rc;
    }
    if (worker->pipeline->tx != NULL &&
        worker->pipeline->outbox_valid == 0u) {
        rc = ninlil_mfdt_v1_pipeline_sender_pump(worker->pipeline);
        if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
    }
    rc = dispatch_owned_outbox(worker);
    if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
        return rc;
    }
    for (i = 0u; i < worker->rx_budget; ++i) {
        frame_len = 0u;
        rc = worker->rx_fn(worker->bearer_user, frame, sizeof(frame),
                           &frame_len);
        if (rc == NINLIL_MFDT_V1_ERR_BUSY ||
            (rc == NINLIL_MFDT_V1_OK && frame_len == 0u)) {
            break;
        }
        if (rc != NINLIL_MFDT_V1_OK) {
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
            (void)fprintf(
                stderr,
                "mfdt bearer worker: receive failed rc=%d index=%u\n",
                rc,
                (unsigned)i);
#endif
            return rc < 0 ? rc : NINLIL_MFDT_V1_ERR_STORAGE;
        }
        if (frame_len > sizeof(frame)) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        rc = ninlil_mfdt_v1_pipeline_on_ncl1_ingress(
            worker->pipeline, frame, frame_len);
        if (rc != NINLIL_MFDT_V1_OK) {
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
            (void)fprintf(
                stderr,
                "mfdt bearer worker: ingress failed rc=%d len=%lu "
                "phase=%u\n",
                rc,
                (unsigned long)frame_len,
                (unsigned)worker->pipeline->phase);
#endif
            return rc;
        }
    }
    rc = prepare_publication(worker);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = dispatch_owned_outbox(worker);
    if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
        return NINLIL_MFDT_V1_OK;
    }
    return rc;
}
