/* SPDX-License-Identifier: Apache-2.0
 * Target bulk allocation for private MFDT (not public ABI).
 *
 * ESP: prefer SPIRAM CAPS, fall back to internal heap. Host: calloc/free.
 * Used only for fixed giant buffers that must not land in .dram0.bss.
 */
#ifndef NINLIL_MFDT_V1_TARGET_ALLOC_H
#define NINLIL_MFDT_V1_TARGET_ALLOC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *ninlil_mfdt_v1_target_zalloc(size_t nbytes);
void ninlil_mfdt_v1_target_free(void *p);

/*
 * Host/lab fault inject: force next zalloc to fail (OOM/NULL). ESP production
 * ignores (always returns 0). Used to prove no NULL deref on scratch paths.
 */
void ninlil_mfdt_v1_target_zalloc_force_fail(int enabled);
int ninlil_mfdt_v1_target_zalloc_force_fail_get(void);
/* Monotonic allocation-attempt counter used by startup/no-growth gates. */
uint64_t ninlil_mfdt_v1_target_zalloc_call_count(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_TARGET_ALLOC_H */
