/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host bulk allocator for MFDT private giants (workspace-class buffers).
 * The ESP implementation lives in ports/esp-idf/src. Not public ABI.
 */
#include "mfdt_v1_target_alloc.h"

#include <stdlib.h>

void *ninlil_mfdt_v1_target_zalloc(size_t nbytes)
{
    if (nbytes == 0u) {
        return NULL;
    }
    return calloc(1u, nbytes);
}

void ninlil_mfdt_v1_target_free(void *p)
{
    if (p == NULL) {
        return;
    }
    free(p);
}
