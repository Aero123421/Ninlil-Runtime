/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ESP-IDF bulk allocator for MFDT private workspace-class buffers.
 * Not installed. Not public ABI.
 */
#include "mfdt_v1_target_alloc.h"

#include "esp_heap_caps.h"

void *ninlil_mfdt_v1_target_zalloc(size_t nbytes)
{
    void *p;

    if (nbytes == 0u) {
        return NULL;
    }
    p = heap_caps_calloc(1u, nbytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p == NULL) {
        p = heap_caps_calloc(1u, nbytes, MALLOC_CAP_8BIT);
    }
    return p;
}

void ninlil_mfdt_v1_target_free(void *p)
{
    if (p != NULL) {
        heap_caps_free(p);
    }
}
