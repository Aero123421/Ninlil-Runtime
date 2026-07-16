/*
 * Host-testable one-shot clock init with immutable embedded ops (no ESP-IDF).
 */

#ifndef NINLIL_ESP_IDF_CLOCK_INIT_LOGIC_H
#define NINLIL_ESP_IDF_CLOCK_INIT_LOGIC_H

#include "ninlil_esp_idf/clock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ninlil_port_status_t (*ninlil_esp_idf_clock_now_fn)(
    void *user,
    ninlil_time_sample_t *out_sample);

int ninlil_esp_idf_clock_init_with_now(
    ninlil_esp_idf_clock_t *clock,
    const ninlil_esp_idf_clock_config_t *config,
    ninlil_esp_idf_clock_now_fn now_fn);

const ninlil_clock_ops_t *ninlil_esp_idf_clock_ops_host(
    ninlil_esp_idf_clock_t *clock);

void ninlil_esp_idf_clock_shutdown_host(
    ninlil_esp_idf_clock_t *clock);

#ifdef __cplusplus
}
#endif

#endif
