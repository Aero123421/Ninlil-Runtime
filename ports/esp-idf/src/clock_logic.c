#include "clock_logic.h"

#include <stddef.h>
#include <string.h>

int ninlil_esp_idf_clock_id_is_nonzero(const ninlil_id128_t *id)
{
    size_t index;

    if (id == NULL) {
        return 0;
    }
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

int ninlil_esp_idf_clock_output_header_is_valid(
    const ninlil_time_sample_t *sample)
{
    return sample != NULL
        && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size >= (uint16_t)sizeof(*sample);
}

int ninlil_esp_idf_clock_config_is_valid(
    const ninlil_esp_idf_clock_config_view_t *config)
{
    return config != NULL
        && config->abi_version == NINLIL_ABI_VERSION
        && config->struct_size >= NINLIL_ESP_IDF_CLOCK_CONFIG_MIN_STRUCT_SIZE
        && ninlil_esp_idf_clock_id_is_nonzero(&config->boot_epoch_id);
}

int ninlil_esp_idf_clock_config_try_copy(
    const void *config,
    ninlil_esp_idf_clock_config_view_t *out_view)
{
    uint8_t header[NINLIL_ESP_IDF_CLOCK_CONFIG_HEADER_BYTES];
    uint16_t abi_version;
    uint16_t struct_size;
    const uint8_t *bytes;

    if (config == NULL || out_view == NULL) {
        return 0;
    }

    bytes = (const uint8_t *)config;
    /* Stage 1: only the ABI header (4 bytes). Never touch boot_epoch_id yet. */
    (void)memcpy(header, bytes, sizeof(header));
    (void)memcpy(&abi_version, &header[0], sizeof(abi_version));
    (void)memcpy(&struct_size, &header[2], sizeof(struct_size));

    if (abi_version != NINLIL_ABI_VERSION
        || struct_size < NINLIL_ESP_IDF_CLOCK_CONFIG_MIN_STRUCT_SIZE) {
        return 0;
    }

    /* Stage 2: full field copy into local view (alias-safe for later publish). */
    (void)memset(out_view, 0, sizeof(*out_view));
    out_view->abi_version = abi_version;
    out_view->struct_size = struct_size;
    (void)memcpy(
        &out_view->boot_epoch_id,
        bytes + NINLIL_ESP_IDF_CLOCK_CONFIG_HEADER_BYTES,
        sizeof(out_view->boot_epoch_id));
    return ninlil_esp_idf_clock_id_is_nonzero(&out_view->boot_epoch_id);
}

int ninlil_esp_idf_clock_us_to_ms(int64_t time_us, uint64_t *out_ms)
{
    if (out_ms == NULL || time_us < 0) {
        return 0;
    }
    *out_ms = (uint64_t)time_us / 1000u;
    return 1;
}

ninlil_port_status_t ninlil_esp_idf_clock_apply_now(
    const ninlil_id128_t *epoch_id,
    uint64_t now_ms,
    uint32_t *has_last_sample,
    uint64_t *last_now_ms,
    ninlil_time_sample_t *out_sample)
{
    if (epoch_id == NULL || has_last_sample == NULL || last_now_ms == NULL
        || !ninlil_esp_idf_clock_id_is_nonzero(epoch_id)
        || !ninlil_esp_idf_clock_output_header_is_valid(out_sample)) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (*has_last_sample != 0u && now_ms < *last_now_ms) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }

    out_sample->clock_epoch_id = *epoch_id;
    out_sample->now_ms = now_ms;
    /* Boot-local esp_timer monotonicity is the sole TRUSTED basis. */
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    out_sample->reserved_zero = 0u;
    *has_last_sample = 1u;
    *last_now_ms = now_ms;
    return NINLIL_PORT_OK;
}
