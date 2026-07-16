#include "entropy_logic.h"

#include <string.h>

int ninlil_esp_idf_entropy_policy_is_supported(uint32_t policy)
{
    return policy == NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG_LOGIC;
}

int ninlil_esp_idf_entropy_config_try_copy(
    const void *config,
    ninlil_esp_idf_entropy_config_view_t *out_view)
{
    uint8_t header[NINLIL_ESP_IDF_ENTROPY_CONFIG_HEADER_BYTES];
    uint16_t abi_version;
    uint16_t struct_size;
    uint32_t policy;
    const uint8_t *bytes;

    if (config == NULL || out_view == NULL) {
        return 0;
    }

    bytes = (const uint8_t *)config;
    (void)memcpy(header, bytes, sizeof(header));
    (void)memcpy(&abi_version, &header[0], sizeof(abi_version));
    (void)memcpy(&struct_size, &header[2], sizeof(struct_size));

    if (abi_version != NINLIL_ABI_VERSION
        || struct_size < NINLIL_ESP_IDF_ENTROPY_CONFIG_MIN_STRUCT_SIZE) {
        return 0;
    }

    (void)memcpy(&policy, bytes + NINLIL_ESP_IDF_ENTROPY_CONFIG_HEADER_BYTES,
        sizeof(policy));
    if (!ninlil_esp_idf_entropy_policy_is_supported(policy)) {
        return 0;
    }

    (void)memset(out_view, 0, sizeof(*out_view));
    out_view->abi_version = abi_version;
    out_view->struct_size = struct_size;
    out_view->policy = policy;
    return 1;
}

ninlil_port_status_t ninlil_esp_idf_entropy_classify_fill(
    int ready,
    uint8_t *out,
    uint32_t length,
    int *out_invoke_backend)
{
    if (out_invoke_backend == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    *out_invoke_backend = 0;
    if (length == 0u) {
        return NINLIL_PORT_OK;
    }
    if (ready == 0) {
        /* Not armed: do not claim quality via esp_fill_random. */
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (out == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    *out_invoke_backend = 1;
    return NINLIL_PORT_OK;
}
