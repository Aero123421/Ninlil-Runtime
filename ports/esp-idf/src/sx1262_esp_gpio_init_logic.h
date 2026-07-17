#ifndef NINLIL_SX1262_ESP_GPIO_INIT_LOGIC_H
#define NINLIL_SX1262_ESP_GPIO_INIT_LOGIC_H

/*
 * Pure ESP GPIO safe-init ordering + ANT polarity (host + target).
 * docs/28 §6.5: outputs → safe levels (RESET high, ANT inactive) → inputs.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_GPIO_INIT_STAGE_NONE ((uint32_t)0u)
#define NINLIL_SX1262_GPIO_INIT_STAGE_OUTPUTS ((uint32_t)1u)
#define NINLIL_SX1262_GPIO_INIT_STAGE_SAFE_LEVELS ((uint32_t)2u)
#define NINLIL_SX1262_GPIO_INIT_STAGE_INPUTS ((uint32_t)3u)
#define NINLIL_SX1262_GPIO_INIT_STAGE_SPI ((uint32_t)4u)
#define NINLIL_SX1262_GPIO_INIT_STAGE_DONE ((uint32_t)5u)
#define NINLIL_SX1262_GPIO_INIT_STAGE_FAILED ((uint32_t)6u)

typedef struct ninlil_sx1262_gpio_init_sm {
    uint32_t stage;
    int reset_level; /* 0 low, 1 high, -1 unknown */
    int ant_level;   /* 0/1/-1; -1 if no ant */
    int with_ant;
    uint8_t ant_active_high;
    int safe_levels_held; /* 1 after successful safe drive */
} ninlil_sx1262_gpio_init_sm_t;

void ninlil_sx1262_gpio_init_sm_reset(
    ninlil_sx1262_gpio_init_sm_t *sm,
    int with_ant,
    uint8_t ant_active_high);

/* Polarity: logical inactive → physical level. */
int ninlil_sx1262_ant_inactive_level(uint8_t active_high);
int ninlil_sx1262_ant_active_level(uint8_t active_high);

int ninlil_sx1262_gpio_init_on_outputs_ok(ninlil_sx1262_gpio_init_sm_t *sm);
int ninlil_sx1262_gpio_init_on_safe_levels_ok(ninlil_sx1262_gpio_init_sm_t *sm);
int ninlil_sx1262_gpio_init_on_inputs_ok(ninlil_sx1262_gpio_init_sm_t *sm);
int ninlil_sx1262_gpio_init_on_inputs_fail(ninlil_sx1262_gpio_init_sm_t *sm);
int ninlil_sx1262_gpio_init_on_spi_fail(ninlil_sx1262_gpio_init_sm_t *sm);
int ninlil_sx1262_gpio_init_on_done(ninlil_sx1262_gpio_init_sm_t *sm);

/* After any post-safe failure, RESET high and ANT inactive must still hold. */
int ninlil_sx1262_gpio_init_safe_levels_held(
    const ninlil_sx1262_gpio_init_sm_t *sm);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_ESP_GPIO_INIT_LOGIC_H */
