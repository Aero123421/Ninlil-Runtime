/* ESP-IDF execution identity: one-shot state, immutable embedded ops. */

#include "ninlil_esp_idf/execution.h"

#include "execution_logic.h"
#include "execution_init_logic.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

_Static_assert(sizeof(TaskHandle_t) > 0u, "TaskHandle_t width");
_Static_assert(
    sizeof(TaskHandle_t) <= sizeof(uint64_t),
    "TaskHandle_t wider than uint64_t");

static portMUX_TYPE s_execution_mux = portMUX_INITIALIZER_UNLOCKED;

static uint64_t execution_current_context(void *user)
{
    ninlil_esp_idf_execution_t *execution =
        (ninlil_esp_idf_execution_t *)user;
    TaskHandle_t handle;

    if (xPortInIsrContext() != 0 || execution == NULL) {
        return 0u;
    }
    portENTER_CRITICAL(&s_execution_mux);
    if (execution->lifecycle != 1u) {
        portEXIT_CRITICAL(&s_execution_mux);
        return 0u;
    }
    portEXIT_CRITICAL(&s_execution_mux);
    if (!ninlil_esp_idf_execution_handle_width_ok(sizeof(TaskHandle_t))) {
        return 0u;
    }
    handle = xTaskGetCurrentTaskHandle();
    return ninlil_esp_idf_execution_context_resolve((const void *)handle, 0);
}

int ninlil_esp_idf_execution_init(ninlil_esp_idf_execution_t *execution)
{
    if (execution == NULL || xPortInIsrContext() != 0) {
        return 1;
    }
    portENTER_CRITICAL(&s_execution_mux);
    {
        int result = ninlil_esp_idf_execution_init_with_context(
            execution, execution_current_context);
        portEXIT_CRITICAL(&s_execution_mux);
        return result;
    }
}

void ninlil_esp_idf_execution_shutdown(ninlil_esp_idf_execution_t *execution)
{
    if (execution == NULL || xPortInIsrContext() != 0) {
        return;
    }
    portENTER_CRITICAL(&s_execution_mux);
    ninlil_esp_idf_execution_shutdown_host(execution);
    portEXIT_CRITICAL(&s_execution_mux);
}

const ninlil_execution_ops_t *ninlil_esp_idf_execution_ops(
    ninlil_esp_idf_execution_t *execution)
{
    const ninlil_execution_ops_t *ops = NULL;

    if (execution == NULL || xPortInIsrContext() != 0) {
        return NULL;
    }
    portENTER_CRITICAL(&s_execution_mux);
    if (execution->lifecycle == 1u) {
        ops = &execution->ops;
    }
    portEXIT_CRITICAL(&s_execution_mux);
    return ops;
}
