/* ESP-IDF clock: one-shot caller-owned state with immutable embedded ops. */

#include "ninlil_esp_idf/clock.h"

#include "clock_init_logic.h"
#include "clock_logic.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static portMUX_TYPE s_clock_mux = portMUX_INITIALIZER_UNLOCKED;

static ninlil_port_status_t clock_now(
    void *user,
    ninlil_time_sample_t *out_sample)
{
    ninlil_esp_idf_clock_t *clock = (ninlil_esp_idf_clock_t *)user;
    int64_t time_us;
    uint64_t now_ms;
    ninlil_port_status_t status;

    if (xPortInIsrContext() != 0 || clock == NULL
        || !ninlil_esp_idf_clock_output_header_is_valid(out_sample)) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    time_us = esp_timer_get_time();
    if (!ninlil_esp_idf_clock_us_to_ms(time_us, &now_ms)) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }

    portENTER_CRITICAL(&s_clock_mux);
    if (clock->lifecycle != 1u) {
        portEXIT_CRITICAL(&s_clock_mux);
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    status = ninlil_esp_idf_clock_apply_now(
        &clock->boot_epoch_id,
        now_ms,
        &clock->has_last_sample,
        &clock->last_now_ms,
        out_sample);
    portEXIT_CRITICAL(&s_clock_mux);
    return status;
}

int ninlil_esp_idf_clock_init(
    ninlil_esp_idf_clock_t *clock,
    const ninlil_esp_idf_clock_config_t *config)
{
    int result;

    if (clock == NULL || xPortInIsrContext() != 0) {
        return 1;
    }
    portENTER_CRITICAL(&s_clock_mux);
    result = ninlil_esp_idf_clock_init_with_now(clock, config, clock_now);
    portEXIT_CRITICAL(&s_clock_mux);
    return result;
}

void ninlil_esp_idf_clock_shutdown(ninlil_esp_idf_clock_t *clock)
{
    if (clock == NULL || xPortInIsrContext() != 0) {
        return;
    }
    portENTER_CRITICAL(&s_clock_mux);
    if (clock->lifecycle == 1u) {
        clock->lifecycle = 2u;
    }
    portEXIT_CRITICAL(&s_clock_mux);
}

const ninlil_clock_ops_t *ninlil_esp_idf_clock_ops(
    ninlil_esp_idf_clock_t *clock)
{
    const ninlil_clock_ops_t *ops = NULL;

    if (clock == NULL || xPortInIsrContext() != 0) {
        return NULL;
    }
    portENTER_CRITICAL(&s_clock_mux);
    if (clock->lifecycle == 1u) {
        ops = &clock->ops;
    }
    portEXIT_CRITICAL(&s_clock_mux);
    return ops;
}
