/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ESP MFDT private target smoke — real session/ncl1/spine path.
 * Not public ABI. Not RF/power-cut HIL.
 */
#ifndef NINLIL_ESP_IDF_MFDT_V1_TARGET_SMOKE_H
#define NINLIL_ESP_IDF_MFDT_V1_TARGET_SMOKE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Execute from app_main when CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE=y.
 * The caller supplies an open Storage Port binding. The smoke binds it to its
 * own caller-owned spine/store and releases that owner before returning.
 *
 * Returns 0 only when ALL hold:
 *   - live negotiate/ncl1/spine symbols exercised
 *   - raw durable NEW classification PASS (read-back)
 *   - HIL full-promotion gate remains OFF (release NOT_PROMOTED)
 *
 * Map symbols alone are not enough. CU fence residual is not a pass.
 * See docs/work/2026-07-29-mfdt-esp-hil-promotion-contract.md.
 */
int32_t ninlil_mfdt_v1_target_smoke_run(const void *storage_ops,
                                        void *storage_handle);

size_t ninlil_mfdt_v1_target_smoke_rx_workspace_bytes(void);

#ifdef __cplusplus
}
#endif

#endif
