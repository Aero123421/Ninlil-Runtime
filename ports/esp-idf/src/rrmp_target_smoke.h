/* SPDX-License-Identifier: Apache-2.0
 * ESP RRMP target software smoke (private candidate).
 *
 * SPIRAM CAPS workspace + SPIRAM software FULL store + production
 * composition_bind/recover. Proves owner init, storage commit/readback,
 * 2-parent install/select, cold restart route/parent/attempt, parent_loss
 * SPLIT_BRAIN. Not RF air HIL. Not carrier provider proof (hop/ACK host KAT).
 */
#ifndef NINLIL_ESP_IDF_RRMP_TARGET_SMOKE_H
#define NINLIL_ESP_IDF_RRMP_TARGET_SMOKE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 0 = OK.
 * Negative = fail class (-1 SHA, -2 workspace/SPIRAM, -3 init/bind,
 * -4 storage, -5 route, -6 parent, -9 restart).
 */
int32_t ninlil_rrmp_target_smoke_run(void);
size_t ninlil_rrmp_target_smoke_workspace_bytes(void);

#ifdef __cplusplus
}
#endif

#endif
