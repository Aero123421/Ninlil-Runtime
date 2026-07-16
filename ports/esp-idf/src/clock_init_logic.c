#include "clock_init_logic.h"

#include "clock_logic.h"

#include <stddef.h>

int ninlil_esp_idf_clock_init_with_now(
    ninlil_esp_idf_clock_t *clock,
    const ninlil_esp_idf_clock_config_t *config,
    ninlil_esp_idf_clock_now_fn now_fn)
{
    ninlil_esp_idf_clock_config_view_t view;

    if (clock == NULL || now_fn == NULL || clock->lifecycle != 0u) {
        return 1;
    }
    if (config == NULL
        || !ninlil_esp_idf_clock_config_try_copy(config, &view)) {
        return 1;
    }
    clock->ops.abi_version = NINLIL_ABI_VERSION;
    clock->ops.struct_size = (uint16_t)sizeof(clock->ops);
    clock->ops.user = clock;
    clock->ops.now = now_fn;
    clock->boot_epoch_id = view.boot_epoch_id;
    clock->has_last_sample = 0u;
    clock->last_now_ms = 0u;
    clock->lifecycle = 1u;
    return 0;
}

const ninlil_clock_ops_t *ninlil_esp_idf_clock_ops_host(
    ninlil_esp_idf_clock_t *clock)
{
    if (clock == NULL || clock->lifecycle != 1u) {
        return NULL;
    }
    return &clock->ops;
}

void ninlil_esp_idf_clock_shutdown_host(ninlil_esp_idf_clock_t *clock)
{
    if (clock != NULL) {
        if (clock->lifecycle == 1u) {
            clock->lifecycle = 2u;
        }
    }
}
