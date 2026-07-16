#ifndef NINLIL_PORT_ESP_STORAGE_CODEC_H
#define NINLIL_PORT_ESP_STORAGE_CODEC_H

#include "esp_storage_private.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t ninlil_port_esp_storage_crc32c(const uint8_t *bytes, uint32_t length);

void ninlil_port_esp_storage_store_u16_le(uint8_t *out, uint16_t value);
void ninlil_port_esp_storage_store_u32_le(uint8_t *out, uint32_t value);
void ninlil_port_esp_storage_store_u64_le(uint8_t *out, uint64_t value);
uint16_t ninlil_port_esp_storage_load_u16_le(const uint8_t *in);
uint32_t ninlil_port_esp_storage_load_u32_le(const uint8_t *in);
uint64_t ninlil_port_esp_storage_load_u64_le(const uint8_t *in);

/*
 * Encode a full directory sector.
 * seal_committed non-zero stores DIR_SEAL_COMMITTED; zero stores SEAL_NONE
 * (caller writes SEAL_COMMITTED as a final independent 4-byte boundary).
 */
int ninlil_port_esp_storage_encode_directory(
    uint64_t generation,
    const ninlil_port_esp_storage_config_t *config,
    const ninlil_port_esp_storage_directory_cache_t *cache,
    int seal_committed,
    uint8_t *out,
    uint32_t capacity);

/*
 * Decode directory image.
 * Returns: 1 valid sealed, 0 invalid/empty-like/unsealed, -1 corrupt-not-empty.
 */
int ninlil_port_esp_storage_decode_directory(
    const uint8_t *image,
    uint32_t length,
    const ninlil_port_esp_storage_config_t *expected_config,
    ninlil_port_esp_storage_directory_cache_t *out_cache,
    uint64_t *out_generation);

int ninlil_port_esp_storage_encode_slot(
    uint32_t schema,
    uint64_t generation,
    const uint8_t *namespace_bytes,
    uint32_t namespace_length,
    const ninlil_port_esp_storage_view_t *view,
    uint8_t *out,
    uint32_t capacity);

/*
 * expected_namespace NULL => skip identity check (codec unit tests).
 * Returns 1 valid, 0 invalid empty-like, -1 wrong-identity/corrupt.
 */
int ninlil_port_esp_storage_decode_slot(
    const uint8_t *image,
    uint32_t length,
    uint32_t expected_schema,
    const uint8_t *expected_namespace,
    uint32_t expected_namespace_length,
    ninlil_port_esp_storage_view_t *out_view,
    uint64_t *out_generation);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_PORT_ESP_STORAGE_CODEC_H */
