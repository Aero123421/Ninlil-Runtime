/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Generic production bearer worker for the private MFDT candidate.
 *
 * The worker moves NCL1 DATA bytes only through caller-owned bearer callbacks.
 * It has no local echo, RF mapping, Wi-Fi mapping, or synthetic peer ACCEPT.
 */
#ifndef NINLIL_MFDT_V1_BEARER_WORKER_H
#define NINLIL_MFDT_V1_BEARER_WORKER_H

#include "mfdt_v1_pipeline.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MFDT_V1_PREPARED          ((int)0)
#define NINLIL_MFDT_V1_ALREADY_COMMITTED ((int)1)

typedef int (*ninlil_mfdt_v1_bearer_tx_fn)(void *user, const uint8_t *frame,
                                           size_t frame_len);
typedef int (*ninlil_mfdt_v1_bearer_rx_fn)(void *user, uint8_t *frame_out,
                                           size_t frame_cap,
                                           size_t *frame_len_out);
typedef uint64_t (*ninlil_mfdt_v1_bearer_now_fn)(void *user);

/*
 * Upper prepare owns the application effect and durable token dedupe.
 * On PREPARED or ALREADY_COMMITTED it must return a non-zero durable evidence
 * digest. ERR_BUSY means the effect owner is not ready yet.
 */
typedef int (*ninlil_mfdt_v1_upper_prepare_fn)(
    void *user, const uint8_t publication_token[16], const uint8_t *content,
    uint32_t content_len, uint8_t publication_evidence_digest_out[32]);

typedef struct ninlil_mfdt_v1_bearer_worker {
    ninlil_mfdt_v1_pipeline_t *pipeline;
    ninlil_mfdt_v1_bearer_tx_fn tx_fn;
    ninlil_mfdt_v1_bearer_rx_fn rx_fn;
    ninlil_mfdt_v1_bearer_now_fn now_fn;
    void *bearer_user;
    ninlil_mfdt_v1_upper_prepare_fn prepare_fn;
    void *upper_user;
    uint8_t rx_budget;
    uint8_t initialized;
    uint32_t publication_attempt_count; /* diagnostic only; not effect authority */
} ninlil_mfdt_v1_bearer_worker_t;

int ninlil_mfdt_v1_bearer_worker_init(
    ninlil_mfdt_v1_bearer_worker_t *worker,
    ninlil_mfdt_v1_pipeline_t *pipeline, ninlil_mfdt_v1_bearer_tx_fn tx_fn,
    ninlil_mfdt_v1_bearer_rx_fn rx_fn, ninlil_mfdt_v1_bearer_now_fn now_fn,
    void *bearer_user, ninlil_mfdt_v1_upper_prepare_fn prepare_fn,
    void *upper_user, uint8_t rx_budget);

/* One bounded scheduling quantum. No blocking and no unbounded receive loop. */
int ninlil_mfdt_v1_bearer_worker_step(
    ninlil_mfdt_v1_bearer_worker_t *worker);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_BEARER_WORKER_H */
