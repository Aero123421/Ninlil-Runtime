#include "execution_logic.h"

int ninlil_esp_idf_execution_handle_width_ok(size_t handle_bytes)
{
    return handle_bytes > 0u && handle_bytes <= sizeof(uint64_t);
}

uint64_t ninlil_esp_idf_execution_context_from_handle(const void *handle)
{
    if (handle == NULL) {
        return 0u;
    }
    return (uint64_t)(uintptr_t)handle;
}

uint64_t ninlil_esp_idf_execution_context_resolve(
    const void *handle,
    int in_isr_context)
{
    if (in_isr_context != 0) {
        return 0u;
    }
    return ninlil_esp_idf_execution_context_from_handle(handle);
}
