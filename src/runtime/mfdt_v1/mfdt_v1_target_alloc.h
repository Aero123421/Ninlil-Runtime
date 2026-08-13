/* SPDX-License-Identifier: Apache-2.0 */
/*
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

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_TARGET_ALLOC_H */
