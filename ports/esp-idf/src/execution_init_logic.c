#include "execution_init_logic.h"

#include <stddef.h>

int ninlil_esp_idf_execution_init_with_context(
    ninlil_esp_idf_execution_t *execution,
    uint64_t (*current_context_id)(void *))
{
    if (execution == NULL || current_context_id == NULL
        || execution->lifecycle != 0u) {
        return 1;
    }
    execution->ops.abi_version = NINLIL_ABI_VERSION;
    execution->ops.struct_size = (uint16_t)sizeof(execution->ops);
    execution->ops.user = execution;
    execution->ops.current_context_id = current_context_id;
    execution->lifecycle = 1u;
    return 0;
}

void ninlil_esp_idf_execution_shutdown_host(
    ninlil_esp_idf_execution_t *execution)
{
    if (execution != NULL && execution->lifecycle == 1u) {
        execution->lifecycle = 2u;
    }
}
