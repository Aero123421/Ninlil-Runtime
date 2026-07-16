/*
 * Port-owned ESP-IDF entropy factory (M3-basic).
 *
 * Public Core ABI unchanged.
 *
 * Ops lifetime contract:
 * - caller zero-initializes this state before init; invalid config may be
 *   retried, but hardware arm/success makes the boot-global lifecycle one-shot;
 * - the embedded ops table is immutable after publication;
 * - after shutdown, retained non-zero fill() calls fail closed while this
 *   object lives; the public ABI's zero-length no-op remains OK;
 * - Task context only; ISR fail-closed.
 * - Process exclusive owner of bootloader_random; RF/ADC only after shutdown.
 *
 * Spec: docs/20-m3-basic-esp-idf-platform-adapters.md
 */

#ifndef NINLIL_ESP_IDF_ENTROPY_H
#define NINLIL_ESP_IDF_ENTROPY_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG ((uint32_t)1u)
#define NINLIL_ESP_IDF_ENTROPY_LIVE_MAGIC ((uint32_t)0x4e4c4555u)
#ifndef NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX
#define NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX ((uint32_t)0u)
#endif

/*
 * Caller-owned, zero-initialized storage. The global lifecycle registry is
 * authoritative for RNG ownership. The notification index above is reserved
 * for this adapter and must not be used by another facility on shutdown tasks.
 */
typedef struct ninlil_esp_idf_entropy {
    ninlil_entropy_ops_t ops;
    uint32_t live_magic;
    struct ninlil_esp_idf_entropy *self;
    uint32_t ready;
    uint32_t owns_bootloader_rng;
    uint32_t policy;
    uint32_t generation;
    uint32_t reserved_zero[2];
} ninlil_esp_idf_entropy_t;

typedef struct ninlil_esp_idf_entropy_config {
    NINLIL_STRUCT_HEADER;
    uint32_t policy;
} ninlil_esp_idf_entropy_config_t;

int ninlil_esp_idf_entropy_init(
    ninlil_esp_idf_entropy_t *entropy,
    const ninlil_esp_idf_entropy_config_t *config);

void ninlil_esp_idf_entropy_shutdown(ninlil_esp_idf_entropy_t *entropy);

int ninlil_esp_idf_entropy_is_ready(const ninlil_esp_idf_entropy_t *entropy);

/*
 * Returns immutable embedded ops while OWNED. Runtime borrowers must be
 * destroyed before shutdown and state destruction.
 */
const ninlil_entropy_ops_t *ninlil_esp_idf_entropy_ops(
    ninlil_esp_idf_entropy_t *entropy);

int ninlil_esp_idf_entropy_storage_is_published(
    const ninlil_esp_idf_entropy_t *entropy);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_ENTROPY_H */
