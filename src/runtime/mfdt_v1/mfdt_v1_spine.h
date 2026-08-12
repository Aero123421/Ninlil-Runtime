/* SPDX-License-Identifier: Apache-2.0 */
/*
 * MFDT bound into runtime_v1 spine submit/send/receive (private).
 * Content custody in NM3S/NM3R; wire progress is real outbound + inbound only.
 *
 * Footprint (ESP32-S3 budget target): single engine + single workspace +
 * single lab/host store (no dual tx/rx BSS pair). Measured evidence via
 * tools/mfdt_v1_footprint_gate.py.
 */
#ifndef NINLIL_MFDT_V1_SPINE_H
#define NINLIL_MFDT_V1_SPINE_H

#include "mfdt_v1.h"
#include "mfdt_v1_ncl1.h"
#include "mfdt_v1_pipeline.h"
#include "mfdt_v1_runtime_seam.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MFDT_V1_BEARER_ROUTE_CODE ((uint8_t)3u)

/*
 * Post-commit outcome / recovery contract (admission FULL already durable):
 *
 * | Phase | Failure | Public result | Durable TX | MFDT custody | Restart |
 * | pre-FULL arm clean fail | arm fail | REJECTED + STORAGE_IO | none | none | n/a |
 * | arm CU + cleanup OLD/mixed | fence | E_STORAGE_COMMIT_UNKNOWN + reconcile | none admit | outcome_unknown | recover/reconcile |
 * | arm OK, FULL commit fail | commit fail | not admit | none | FULL erase 4 keys | no apply |
 * | post-FULL family fail | family fail | ADMITTED_READY | keep TX | armed NM3S | recover resumes wire |
 * | restart + NM3S | — | keep TX | ADMITTED_READY | rehydrate | resume wire, no false REJECT |
 * | restart no NM3S | — | keep TX | ADMITTED_READY | none | terminalize local arm |
 *
 * Arm = durable OPEN custody + first OPEN outbox frame. Wire complete only after
 * real remote TRANSFER_ACCEPT (no local echo).
 */
typedef struct ninlil_mfdt_v1_spine_ctx {
    uint32_t magic;
    ninlil_mfdt_v1_seam_config_t seam;
    uint8_t armed;
    uint8_t role; /* 1 sender 2 receiver */
    uint8_t transfer_id[16];
    uint32_t content_len;
    uint8_t whole_digest[32];
    /* Single concurrent local role (shared workspace budget). */
    ninlil_mfdt_v1_engine_t eng;
    ninlil_mfdt_v1_workspace_t ws;
    ninlil_mfdt_v1_lab_store_t store;
    ninlil_mfdt_v1_pipeline_t pipe;
    uint8_t engines_ready;
    uint8_t store_inited;
    /*
     * Cleanup after arm CU could not confirm durable erase (OLD/mixed/unknown).
     * Process must reconcile — not pretend SUBMISSION_REJECTED with no custody.
     */
    uint8_t outcome_unknown;
    uint8_t busy;
    uint8_t outcome_tid[16];
    ninlil_mfdt_v1_cu_class_t last_cleanup_cu;
} ninlil_mfdt_v1_spine_ctx_t;

/* Caller-owned private lifecycle. fini zeroizes the complete context. */
int ninlil_mfdt_v1_spine_init(ninlil_mfdt_v1_spine_ctx_t *ctx);
void ninlil_mfdt_v1_spine_fini(ninlil_mfdt_v1_spine_ctx_t *ctx);
int ninlil_mfdt_v1_spine_set_config(
    ninlil_mfdt_v1_spine_ctx_t *ctx,
    const ninlil_mfdt_v1_seam_config_t *config);

int ninlil_mfdt_v1_spine_should_use_mfdt(
    const ninlil_mfdt_v1_spine_ctx_t *ctx, uint32_t payload_length);

/*
 * Pre-admission-FULL arm: durable OPEN into NM3S + queue OPEN outbox frame.
 * Does not complete wire transfer (no local echo).
 */
int ninlil_mfdt_v1_spine_arm_sender(
    ninlil_mfdt_v1_spine_ctx_t *ctx,
    const uint8_t transaction_id[16], const uint8_t *payload,
    uint32_t payload_len);

int ninlil_mfdt_v1_spine_disarm(
    ninlil_mfdt_v1_spine_ctx_t *ctx,
    const uint8_t transaction_id[16]);

/* 1 if last arm/cleanup left durable outcome unknown (reconcile required). */
int ninlil_mfdt_v1_spine_outcome_unknown(
    const ninlil_mfdt_v1_spine_ctx_t *ctx);

int ninlil_mfdt_v1_spine_arm_receiver(ninlil_mfdt_v1_spine_ctx_t *ctx);

int ninlil_mfdt_v1_spine_recover(ninlil_mfdt_v1_spine_ctx_t *ctx);

int ninlil_mfdt_v1_spine_recover_transaction(
    ninlil_mfdt_v1_spine_ctx_t *ctx,
    const uint8_t transaction_id[16]);

int ninlil_mfdt_v1_spine_is_armed(
    const ninlil_mfdt_v1_spine_ctx_t *ctx,
    const uint8_t transaction_id[16]);

/* Pump sender: produce next outbound when not awaiting remote accept. */
int ninlil_mfdt_v1_spine_sender_pump(ninlil_mfdt_v1_spine_ctx_t *ctx);

/* Take owned outbound NCL1 frame for bearer dispatch. */
int ninlil_mfdt_v1_spine_take_outbound_ncl1(
                                            ninlil_mfdt_v1_spine_ctx_t *ctx,
                                            uint8_t *out, size_t cap,
                                            size_t *out_len);

/* 1 if outbound frame pending. */
int ninlil_mfdt_v1_spine_outbox_pending(
    const ninlil_mfdt_v1_spine_ctx_t *ctx);

/* Ingress real NCL1 DATA only. */
int ninlil_mfdt_v1_spine_on_ncl1_data(
    ninlil_mfdt_v1_spine_ctx_t *ctx,
    const uint8_t *ncl1, size_t ncl1_len);

int ninlil_mfdt_v1_spine_restart_scan(ninlil_mfdt_v1_spine_ctx_t *ctx);

/* 1 if sender wire complete (TRANSFER_ACCEPT observed). */
int ninlil_mfdt_v1_spine_transfer_complete(
    const ninlil_mfdt_v1_spine_ctx_t *ctx);

ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_spine_cu_key(
    ninlil_mfdt_v1_spine_ctx_t *ctx,
    const uint8_t key[20], const uint8_t *oldb, uint32_t oldn, int has_old,
    const uint8_t *newb, uint32_t newn, int has_new);

/* Private/testable authority for an exact four-key delete read-back group. */
ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_spine_classify_delete_group(
    const ninlil_mfdt_v1_cu_class_t observations[4]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_SPINE_H */
