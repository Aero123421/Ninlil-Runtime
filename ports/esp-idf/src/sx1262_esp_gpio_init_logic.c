#include "sx1262_esp_gpio_init_logic.h"

#include <stddef.h>

int ninlil_sx1262_ant_inactive_level(uint8_t active_high)
{
    return active_high != 0u ? 0 : 1;
}

int ninlil_sx1262_ant_active_level(uint8_t active_high)
{
    return active_high != 0u ? 1 : 0;
}

void ninlil_sx1262_gpio_init_sm_reset(
    ninlil_sx1262_gpio_init_sm_t *sm,
    int with_ant,
    uint8_t ant_active_high)
{
    if (sm == NULL) {
        return;
    }
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_NONE;
    sm->reset_level = -1;
    sm->ant_level = -1;
    sm->with_ant = with_ant != 0 ? 1 : 0;
    sm->ant_active_high = ant_active_high;
    sm->safe_levels_held = 0;
}

int ninlil_sx1262_gpio_init_on_outputs_ok(ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL || sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_NONE) {
        return 0;
    }
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_OUTPUTS;
    return 1;
}

int ninlil_sx1262_gpio_init_on_safe_levels_ok(ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL || sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_OUTPUTS) {
        return 0;
    }
    sm->reset_level = 1; /* deasserted / high */
    if (sm->with_ant != 0) {
        sm->ant_level = ninlil_sx1262_ant_inactive_level(sm->ant_active_high);
    } else {
        sm->ant_level = -1;
    }
    sm->safe_levels_held = 1;
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_SAFE_LEVELS;
    return 1;
}

int ninlil_sx1262_gpio_init_on_inputs_ok(ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL || sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_SAFE_LEVELS) {
        return 0;
    }
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_INPUTS;
    return 1;
}

int ninlil_sx1262_gpio_init_on_inputs_fail(ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL || sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_SAFE_LEVELS) {
        return 0;
    }
    /* Safe levels remain held. */
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_FAILED;
    return 1;
}

int ninlil_sx1262_gpio_init_on_spi_fail(ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL) {
        return 0;
    }
    if (sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_INPUTS
        && sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_SPI) {
        return 0;
    }
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_FAILED;
    return 1;
}

int ninlil_sx1262_gpio_init_on_done(ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL || sm->stage != NINLIL_SX1262_GPIO_INIT_STAGE_INPUTS) {
        return 0;
    }
    sm->stage = NINLIL_SX1262_GPIO_INIT_STAGE_DONE;
    return 1;
}

int ninlil_sx1262_gpio_init_safe_levels_held(
    const ninlil_sx1262_gpio_init_sm_t *sm)
{
    if (sm == NULL || sm->safe_levels_held == 0) {
        return 0;
    }
    if (sm->reset_level != 1) {
        return 0;
    }
    if (sm->with_ant != 0) {
        if (sm->ant_level
            != ninlil_sx1262_ant_inactive_level(sm->ant_active_high)) {
            return 0;
        }
    }
    return 1;
}
