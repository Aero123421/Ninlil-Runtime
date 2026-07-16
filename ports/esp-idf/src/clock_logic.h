/*
 * Backend-independent clock helpers for the ESP-IDF clock port.
 * Host unit tests compile this without ESP-IDF headers.
 */

#ifndef NINLIL_ESP_IDF_CLOCK_LOGIC_H
#define NINLIL_ESP_IDF_CLOCK_LOGIC_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal config view so pure logic does not depend on the port-owned
 * factory header. Mirrors ninlil_esp_idf_clock_config_t requirements.
 */
typedef struct ninlil_esp_idf_clock_config_view {
    uint16_t abi_version;
    uint16_t struct_size;
    ninlil_id128_t boot_epoch_id;
} ninlil_esp_idf_clock_config_view_t;

/* abi_version + struct_size only (safe first touch). */
#define NINLIL_ESP_IDF_CLOCK_CONFIG_HEADER_BYTES ((size_t)4u)

/* Full view size used as minimum struct_size to read boot_epoch_id. */
#define NINLIL_ESP_IDF_CLOCK_CONFIG_MIN_STRUCT_SIZE \
    ((uint16_t)sizeof(ninlil_esp_idf_clock_config_view_t))

int ninlil_esp_idf_clock_id_is_nonzero(const ninlil_id128_t *id);

int ninlil_esp_idf_clock_output_header_is_valid(
    const ninlil_time_sample_t *sample);

int ninlil_esp_idf_clock_config_is_valid(
    const ninlil_esp_idf_clock_config_view_t *config);

/*
 * Safe staged config read (alias-safe value copy):
 * 1) memcpy exactly 4 header bytes
 * 2) validate abi_version + struct_size
 * 3) only then copy boot_epoch_id
 *
 * Short objects with struct_size < full config never touch past the header.
 * config is treated as a byte pointer; do not use struct member access first.
 */
int ninlil_esp_idf_clock_config_try_copy(
    const void *config,
    ninlil_esp_idf_clock_config_view_t *out_view);

/* Negative us → 0. Positive us converts with floor division by 1000. */
int ninlil_esp_idf_clock_us_to_ms(int64_t time_us, uint64_t *out_ms);

/*
 * Apply a candidate now_ms into out_sample under fixed epoch + TRUSTED
 * boot-local policy. Updates *has_last / *last_now_ms only on OK.
 * Invalid header / same-epoch regression → PERMANENT_FAILURE without
 * publishing a success sample.
 */
ninlil_port_status_t ninlil_esp_idf_clock_apply_now(
    const ninlil_id128_t *epoch_id,
    uint64_t now_ms,
    uint32_t *has_last_sample,
    uint64_t *last_now_ms,
    ninlil_time_sample_t *out_sample);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_CLOCK_LOGIC_H */
