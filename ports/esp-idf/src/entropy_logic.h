/*
 * Backend-independent entropy config / ready / fill rules.
 * Host unit tests compile this without ESP-IDF headers.
 */

#ifndef NINLIL_ESP_IDF_ENTROPY_LOGIC_H
#define NINLIL_ESP_IDF_ENTROPY_LOGIC_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Must match ninlil_esp_idf/entropy.h (port-owned; not public ABI). */
#define NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG_LOGIC ((uint32_t)1u)

typedef struct ninlil_esp_idf_entropy_config_view {
    uint16_t abi_version;
    uint16_t struct_size;
    uint32_t policy;
} ninlil_esp_idf_entropy_config_view_t;

#define NINLIL_ESP_IDF_ENTROPY_CONFIG_HEADER_BYTES ((size_t)4u)
#define NINLIL_ESP_IDF_ENTROPY_CONFIG_MIN_STRUCT_SIZE \
    ((uint16_t)sizeof(ninlil_esp_idf_entropy_config_view_t))

int ninlil_esp_idf_entropy_policy_is_supported(uint32_t policy);

/*
 * Staged read: 4-byte header first, then policy only if struct_size admits it.
 */
int ninlil_esp_idf_entropy_config_try_copy(
    const void *config,
    ninlil_esp_idf_entropy_config_view_t *out_view);

/*
 * ready == 0: length > 0 fails closed (no backend). length == 0 stays OK.
 * ready != 0: same null/length rules as before; backend only when needed.
 */
ninlil_port_status_t ninlil_esp_idf_entropy_classify_fill(
    int ready,
    uint8_t *out,
    uint32_t length,
    int *out_invoke_backend);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_ENTROPY_LOGIC_H */
