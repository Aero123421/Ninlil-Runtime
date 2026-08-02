/* SPDX-License-Identifier: Apache-2.0
 * Bulk allocator for MFDT private giants (workspace-class buffers).
 * Not installed. Not public ABI.
 */
#include "mfdt_v1_target_alloc.h"

#include <stdlib.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "esp_heap_caps.h"
#endif

/* Host lab only: inject allocation failure for deterministic OOM tests. */
static int g_force_zalloc_fail = 0;
static uint64_t g_zalloc_call_count = 0ull;

void ninlil_mfdt_v1_target_zalloc_force_fail(int enabled)
{
#if defined(ESP_PLATFORM)
    (void)enabled; /* production target: no host inject surface */
#else
    g_force_zalloc_fail = (enabled != 0) ? 1 : 0;
#endif
}

int ninlil_mfdt_v1_target_zalloc_force_fail_get(void)
{
    return g_force_zalloc_fail != 0 ? 1 : 0;
}

uint64_t ninlil_mfdt_v1_target_zalloc_call_count(void)
{
    return g_zalloc_call_count;
}

void *ninlil_mfdt_v1_target_zalloc(size_t nbytes)
{
    void *p;

    if (nbytes == 0u) {
        return NULL;
    }
    g_zalloc_call_count += 1ull;
#if !defined(ESP_PLATFORM)
    if (g_force_zalloc_fail != 0) {
        return NULL;
    }
#endif
#if defined(ESP_PLATFORM)
    p = heap_caps_calloc(1u, nbytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p == NULL) {
        p = heap_caps_calloc(1u, nbytes, MALLOC_CAP_8BIT);
    }
    return p;
#else
    p = calloc(1u, nbytes);
    return p;
#endif
}

void ninlil_mfdt_v1_target_free(void *p)
{
    if (p == NULL) {
        return;
    }
#if defined(ESP_PLATFORM)
    heap_caps_free(p);
#else
    free(p);
#endif
}
