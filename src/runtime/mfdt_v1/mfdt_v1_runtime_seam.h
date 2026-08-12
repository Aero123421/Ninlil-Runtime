/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private seam: generic ninlil_submit ApplicationData → MFDT when admitted.
 * No separate product API. Default-OFF via admission policy.
 * SEMANTIC: NOT_PUBLIC_ABI
 */
#ifndef NINLIL_MFDT_V1_RUNTIME_SEAM_H
#define NINLIL_MFDT_V1_RUNTIME_SEAM_H

#include "mfdt_v1.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes aligned with ninlil_status_t values used by runtime. */
#ifndef NINLIL_MFDT_SEAM_OK
#define NINLIL_MFDT_SEAM_OK              ((int)0)
#define NINLIL_MFDT_SEAM_NOT_APPLICABLE  ((int)1001)
#define NINLIL_MFDT_SEAM_REJECTED        ((int)1002)
#define NINLIL_MFDT_SEAM_BUSY            ((int)1003)
#define NINLIL_MFDT_SEAM_STORAGE         ((int)1004)
#endif

typedef struct ninlil_mfdt_v1_seam_config {
    uint8_t policy_on;               /* 0=OFF 1=ON */
    uint8_t capability;              /* Private MFDT admission profile revision 2. */
    uint16_t mfdt_admission_version;
    uint8_t host_mode;
    uint32_t session_generation;
    uint64_t session_cookie;
    uint64_t now_ms;
    uint8_t local_clock_epoch[16];
} ninlil_mfdt_v1_seam_config_t;

/* Caller-owned Host/lab two-endpoint seam. Never installed or public ABI. */
typedef struct ninlil_mfdt_v1_seam_ctx {
    uint32_t magic;
    ninlil_mfdt_v1_seam_config_t config;
#if !defined(ESP_PLATFORM)
    ninlil_mfdt_v1_workspace_t sender_workspace;
    ninlil_mfdt_v1_workspace_t receiver_workspace;
    ninlil_mfdt_v1_lab_store_t sender_store;
    ninlil_mfdt_v1_lab_store_t receiver_store;
    ninlil_mfdt_v1_engine_t sender;
    ninlil_mfdt_v1_engine_t receiver;
#endif
    uint8_t busy;
} ninlil_mfdt_v1_seam_ctx_t;

int ninlil_mfdt_v1_seam_init(ninlil_mfdt_v1_seam_ctx_t *ctx);
void ninlil_mfdt_v1_seam_fini(ninlil_mfdt_v1_seam_ctx_t *ctx);
int ninlil_mfdt_v1_seam_set_config(
    ninlil_mfdt_v1_seam_ctx_t *ctx,
    const ninlil_mfdt_v1_seam_config_t *cfg);
int ninlil_mfdt_v1_seam_get_config(
    const ninlil_mfdt_v1_seam_ctx_t *ctx,
    ninlil_mfdt_v1_seam_config_t *out);

/*
 * Try multi-frame path for ApplicationData.
 * Returns NOT_APPLICABLE when single-frame / policy-OFF should use existing path.
 * On OK, *out_transfer_id (16) and *out_publication_token (16) filled when complete.
 */
int ninlil_mfdt_v1_seam_try_application_data(
    ninlil_mfdt_v1_seam_ctx_t *ctx,
    const uint8_t *application_data, uint32_t data_len,
    const uint8_t transfer_id_hint[16], uint8_t out_transfer_id[16],
    uint8_t out_publication_token[16]);

/* Release policy pin: 1 only when acceptance matrix all software-GREEN. */
int ninlil_mfdt_v1_release_policy_allows_default_on(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_RUNTIME_SEAM_H */
