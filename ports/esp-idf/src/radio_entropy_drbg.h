/*
 * Private phase-separated entropy provider for the V1 external-radio image.
 * Authority: docs/adr/0035-v1-compact-radio-mapping.md
 *
 * The caller seeds this object before radio/ADC/Wi-Fi initialization, retires
 * the bootloader RNG source, then gives only this immutable ops table to the
 * Runtime. Not installed and not public ABI.
 */
#ifndef NINLIL_ESP_IDF_RADIO_ENTROPY_DRBG_H
#define NINLIL_ESP_IDF_RADIO_ENTROPY_DRBG_H

#include "ninlil/platform.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ctr_drbg.h"

#include <stdint.h>

#define NINLIL_ESP_IDF_RADIO_DRBG_SEED_BYTES ((uint32_t)64u)
#define NINLIL_ESP_IDF_RADIO_DRBG_MAX_DRAW_BYTES ((uint32_t)64u)
#define NINLIL_ESP_IDF_RADIO_DRBG_MAX_REQUESTS ((uint32_t)1000000u)

typedef struct ninlil_esp_idf_radio_drbg {
    ninlil_entropy_ops_t ops;
    mbedtls_ctr_drbg_context context;
    struct ninlil_esp_idf_radio_drbg *self;
    TaskHandle_t owner_task;
    uint32_t ready;
    uint32_t request_count;
    uint32_t seed_cursor;
    uint32_t seed_active;
    uint8_t seed_bytes[NINLIL_ESP_IDF_RADIO_DRBG_SEED_BYTES];
} ninlil_esp_idf_radio_drbg_t;

/*
 * State must be all-zero. seed_source and personalization_digest are borrowed
 * for this call only and are not retained.
 */
int ninlil_esp_idf_radio_drbg_init(
    ninlil_esp_idf_radio_drbg_t *state,
    const ninlil_entropy_ops_t *seed_source,
    const uint8_t personalization_digest[32]);

const ninlil_entropy_ops_t *ninlil_esp_idf_radio_drbg_ops(
    ninlil_esp_idf_radio_drbg_t *state);

void ninlil_esp_idf_radio_drbg_close(
    ninlil_esp_idf_radio_drbg_t *state);

#endif /* NINLIL_ESP_IDF_RADIO_ENTROPY_DRBG_H */
