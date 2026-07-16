/*
 * Port-owned ESP-IDF durable storage API (M3 storage slice).
 * Format 4: directory + namespace dual-slot images on a wear-levelled medium.
 * Not public ABI. See docs/21-m3-esp-idf-durable-storage.md.
 */

#ifndef NINLIL_PORT_ESP_STORAGE_H
#define NINLIL_PORT_ESP_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION ((uint32_t)4u)
#define NINLIL_PORT_ESP_STORAGE_DIR_MAGIC ((uint32_t)0x444C494Eu) /* 'NILD' */
#define NINLIL_PORT_ESP_STORAGE_SLOT_MAGIC ((uint32_t)0x534C494Eu) /* 'NILS' */

#define NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN ((uint32_t)4096u)
#define NINLIL_PORT_ESP_STORAGE_DIR_BYTES ((uint32_t)4096u)

/*
 * Hard transaction-staging ceilings (compile-time PSRAM workspace).
 *
 * These deliberately exceed the persisted/production capacity. A transaction
 * may temporarily contain old and new logical rows before a later erase; only
 * commit applies the configured persisted capacity. Repeated replacement of a
 * key never accumulates old value bytes because put atomically rebuilds the
 * materialized final view.
 */
#define NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES ((uint32_t)4u)
#define NINLIL_PORT_ESP_STORAGE_HARD_MAX_ENTRIES ((uint32_t)64u)
#define NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES ((uint32_t)139264u)
#define NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES ((uint32_t)32u)
#define NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES ((uint32_t)69632u)
#define NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS ((uint32_t)3u)
#define NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS ((uint32_t)2u)
#define NINLIL_PORT_ESP_STORAGE_HARD_MAX_KEY_BYTES ((uint32_t)255u)

/*
 * Directory dual-slot layout.
 */
#define NINLIL_PORT_ESP_STORAGE_DIR_HEADER_BYTES ((uint32_t)48u)
#define NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BYTES ((uint32_t)272u)
#define NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BASE ((uint32_t)48u)
#define NINLIL_PORT_ESP_STORAGE_DIR_ENTRIES_BYTES                              \
    (NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES                               \
        * NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BYTES)
#define NINLIL_PORT_ESP_STORAGE_DIR_PAD_OFFSET                                 \
    (NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BASE                                    \
        + NINLIL_PORT_ESP_STORAGE_DIR_ENTRIES_BYTES)
#define NINLIL_PORT_ESP_STORAGE_DIR_PROTECTED_BYTES ((uint32_t)4088u)
#define NINLIL_PORT_ESP_STORAGE_DIR_IMAGE_CRC_OFFSET ((uint32_t)4088u)
#define NINLIL_PORT_ESP_STORAGE_DIR_SEAL_OFFSET ((uint32_t)4092u)
#define NINLIL_PORT_ESP_STORAGE_DIR_SEAL_NONE ((uint32_t)0xFFFFFFFFu)
#define NINLIL_PORT_ESP_STORAGE_DIR_SEAL_COMMITTED ((uint32_t)0x4C414553u)
#define NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE ((uint8_t)0xFFu)

/* Production default (XIAO ESP32-S3: PSRAM required). */
#define NINLIL_PORT_ESP_STORAGE_PROD_MAX_NAMESPACES ((uint32_t)2u)
#define NINLIL_PORT_ESP_STORAGE_PROD_MAX_ENTRIES ((uint32_t)32u)
#define NINLIL_PORT_ESP_STORAGE_PROD_MAX_LOGICAL_BYTES ((uint32_t)69632u)
#define NINLIL_PORT_ESP_STORAGE_PROD_MAX_TXNS ((uint32_t)3u)
#define NINLIL_PORT_ESP_STORAGE_PROD_MAX_ITERS ((uint32_t)2u)

#define NINLIL_PORT_ESP_STORAGE_SLOT_HEADER_BYTES ((uint32_t)320u)
#define NINLIL_PORT_ESP_STORAGE_SLOT_PAYLOAD_BYTES                             \
    (NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES                       \
        + (NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES * 6u))
#define NINLIL_PORT_ESP_STORAGE_SLOT_RAW_BYTES                                 \
    (NINLIL_PORT_ESP_STORAGE_SLOT_HEADER_BYTES                                 \
        + NINLIL_PORT_ESP_STORAGE_SLOT_PAYLOAD_BYTES)
#define NINLIL_PORT_ESP_STORAGE_SLOT_BYTES                                     \
    ((((NINLIL_PORT_ESP_STORAGE_SLOT_RAW_BYTES)                                \
          + (NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN - 1u))                        \
         / NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN)                                 \
        * NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN)

#define NINLIL_PORT_ESP_STORAGE_CONTROL_SIZEOF_CEILING ((size_t)8192u)
#define NINLIL_PORT_ESP_STORAGE_VIEW_SIZEOF_CEILING ((size_t)172032u)
#define NINLIL_PORT_ESP_STORAGE_OBJECT_SIZEOF_CEILING ((size_t)1572864u)
#define NINLIL_PORT_ESP_STORAGE_MAX_STACK_FRAME_BYTES ((size_t)2048u)

#define NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE ((uint8_t)0u)
#define NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED ((uint8_t)1u)

/* Logical media sector count. Physical ESP media is larger and wear-levelled. */
#define NINLIL_PORT_ESP_STORAGE_MEDIA_SECTOR_COUNT                             \
    (2u + NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES                         \
        * 2u * (NINLIL_PORT_ESP_STORAGE_SLOT_BYTES                            \
            / NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN))

/* Host wear model matches the 4 MiB reference partition. */
#define NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT ((uint32_t)1024u)

typedef struct ninlil_port_esp_storage_config {
    uint32_t max_namespaces;
    uint64_t max_entries_per_namespace;
    uint64_t max_bytes_per_namespace;
    uint32_t max_live_txns;
    uint32_t max_live_iters;
    /* Explicit wear-admission contract; zero/over-budget is invalid. */
    uint32_t wl_usable_sector_count;
    uint32_t assumed_erase_endurance;
    uint32_t wear_reserve_percent;
    /*
     * Planned FULL commits per calendar day for THIS physical WL partition /
     * wear-budget domain: the sum of FULL commits that actually occur across
     * all storage instances and namespaces bound to that domain.
     *
     * - Separate physical partitions (or separate wear-budget domains) each
     *   carry their own budget and their own planned_full_commits_per_day.
     * - Do not multiply by namespace count inside one domain.
     * - Do not double-count the same traffic into two configs that share one
     *   domain (two live instances on the same partition are still one domain).
     */
    uint32_t planned_full_commits_per_day;
    uint32_t planned_service_days;
} ninlil_port_esp_storage_config_t;

void ninlil_port_esp_storage_config_production(
    ninlil_port_esp_storage_config_t *out_config);

uint64_t ninlil_port_esp_storage_endurance_commit_budget(
    const ninlil_port_esp_storage_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_PORT_ESP_STORAGE_H */
