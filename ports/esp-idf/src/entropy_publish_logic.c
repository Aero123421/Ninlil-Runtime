#include "entropy_publish_logic.h"

#include <stddef.h>

int ninlil_esp_idf_entropy_storage_is_zero(
    const ninlil_esp_idf_entropy_t *entropy)
{
    return entropy != NULL
        && entropy->ops.abi_version == 0u
        && entropy->ops.struct_size == 0u
        && entropy->ops.user == NULL
        && entropy->ops.fill == NULL
        && entropy->live_magic == 0u
        && entropy->self == NULL
        && entropy->ready == 0u
        && entropy->owns_bootloader_rng == 0u
        && entropy->policy == 0u
        && entropy->generation == 0u
        && entropy->reserved_zero[0] == 0u
        && entropy->reserved_zero[1] == 0u;
}

int ninlil_esp_idf_entropy_publish_once(
    ninlil_esp_idf_entropy_t *entropy,
    ninlil_port_status_t (*fill)(void *, uint8_t *, uint32_t),
    uint32_t policy,
    uint32_t generation)
{
    if (!ninlil_esp_idf_entropy_storage_is_zero(entropy)
        || fill == NULL || generation == 0u) {
        return 1;
    }
    entropy->ops.abi_version = NINLIL_ABI_VERSION;
    entropy->ops.struct_size = (uint16_t)sizeof(entropy->ops);
    entropy->ops.user = entropy;
    entropy->ops.fill = fill;
    entropy->ready = 1u;
    entropy->owns_bootloader_rng = 1u;
    entropy->policy = policy;
    entropy->generation = generation;
    entropy->live_magic = NINLIL_ESP_IDF_ENTROPY_LIVE_MAGIC;
    entropy->self = entropy;
    return 0;
}

void ninlil_esp_idf_entropy_retire_storage(
    ninlil_esp_idf_entropy_t *entropy)
{
    if (entropy != NULL) {
        entropy->ready = 0u;
        entropy->owns_bootloader_rng = 0u;
    }
}
