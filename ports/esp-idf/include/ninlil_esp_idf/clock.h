/*
 * Port-owned ESP-IDF clock factory (M3-basic).
 *
 * Caller zero-initializes this one-shot state before init. The embedded ops
 * table is immutable after publication and remains readable until the state
 * object lifetime ends. Runtime borrowers must be destroyed before shutdown.
 *
 * Spec: docs/20-m3-basic-esp-idf-platform-adapters.md
 */

#ifndef NINLIL_ESP_IDF_CLOCK_H
#define NINLIL_ESP_IDF_CLOCK_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_esp_idf_clock {
    ninlil_clock_ops_t ops;
    ninlil_id128_t boot_epoch_id;
    uint64_t last_now_ms;
    uint32_t has_last_sample;
    uint32_t lifecycle; /* 0 zero-init, 1 active, 2 retired */
} ninlil_esp_idf_clock_t;

typedef struct ninlil_esp_idf_clock_config {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t boot_epoch_id;
} ninlil_esp_idf_clock_config_t;

/*
 * Caller must supply fresh non-zero boot_epoch_id after reboot (esp_timer
 * resets). Reusing epoch does not restore cross-reboot TRUSTED continuity.
 */
int ninlil_esp_idf_clock_init(
    ninlil_esp_idf_clock_t *clock,
    const ninlil_esp_idf_clock_config_t *config);

/*
 * Returns embedded immutable ops while active. After shutdown, retained ops
 * calls fail closed while the state object remains alive.
 */
const ninlil_clock_ops_t *ninlil_esp_idf_clock_ops(
    ninlil_esp_idf_clock_t *clock);

/* Retire after all calls and Runtime borrowers have quiesced. */
void ninlil_esp_idf_clock_shutdown(ninlil_esp_idf_clock_t *clock);

#ifdef __cplusplus
}
#endif

#endif
