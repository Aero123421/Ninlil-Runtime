/*
 * Binder-owned PSRAM workspace. Views hold the large value blobs; namespaces
 * do not embed full committed images (directory + media are durable authority).
 * Ownership: opaque flash_bind allocates this object in PSRAM; flash_unbind
 * releases it. Callers never place ninlil_port_esp_storage_t in internal BSS.
 */

#ifndef NINLIL_PORT_ESP_STORAGE_WORKSPACE_H
#define NINLIL_PORT_ESP_STORAGE_WORKSPACE_H

#include <stdint.h>

#include "ninlil_port/esp_storage.h"
#include "esp_storage_hil_observer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_port_esp_storage_entry {
    uint16_t key_length;
    uint32_t value_length;
    uint32_t value_offset;
    uint8_t key[NINLIL_PORT_ESP_STORAGE_HARD_MAX_KEY_BYTES];
} ninlil_port_esp_storage_entry_t;

typedef struct ninlil_port_esp_storage_view {
    uint32_t entry_count;
    uint64_t used_logical_bytes;
    uint32_t value_blob_used;
    ninlil_port_esp_storage_entry_t
        entries[NINLIL_PORT_ESP_STORAGE_HARD_MAX_ENTRIES];
    uint8_t value_blob[NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES];
} ninlil_port_esp_storage_view_t;

typedef struct ninlil_port_esp_storage_iterator {
    int in_use;
    uint32_t generation;
    uint32_t transaction_index;
    uint32_t transaction_generation;
    uint32_t row_count;
    uint32_t position;
    uint32_t row_indices[NINLIL_PORT_ESP_STORAGE_HARD_MAX_ENTRIES];
    /* Deep-copy transaction snapshot fixed by iter_open(). */
    ninlil_port_esp_storage_view_t snapshot;
} ninlil_port_esp_storage_iterator_t;

typedef struct ninlil_port_esp_storage_transaction {
    int in_use;
    uint32_t generation;
    uint32_t handle_index;
    uint32_t handle_generation;
    ninlil_storage_mode_t mode;
    uint32_t ns_index;
    ninlil_port_esp_storage_view_t view;
} ninlil_port_esp_storage_transaction_t;

typedef struct ninlil_port_esp_storage_handle {
    int in_use;
    uint32_t generation;
    uint32_t namespace_index;
    int has_writer;
} ninlil_port_esp_storage_handle_t;

/* Volatile cache of one directory entry; durable truth is on media. */
typedef struct ninlil_port_esp_storage_namespace {
    int cached;
    int leased;
    uint32_t name_length;
    uint8_t name[NINLIL_PORT_ESP_STORAGE_HARD_MAX_KEY_BYTES];
    uint32_t schema;
    uint64_t active_generation;
    uint32_t active_slot;
    uint64_t used_entries;
    uint64_t used_bytes;
} ninlil_port_esp_storage_namespace_t;

typedef struct ninlil_port_esp_storage_directory_cache {
    uint64_t generation;
    uint32_t active_dir_slot;
    uint8_t state[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES];
    uint8_t name_length[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES];
    uint8_t name[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES]
                [NINLIL_PORT_ESP_STORAGE_HARD_MAX_KEY_BYTES];
    uint32_t schema[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES];
    /* OCCUPIED requires data_seed_generation >= 1 (seeded empty or later data). */
    uint64_t data_seed_generation[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES];
} ninlil_port_esp_storage_directory_cache_t;

struct ninlil_port_esp_storage {
    ninlil_storage_ops_t ops;
    ninlil_port_esp_storage_config_t config;
    const ninlil_port_esp_storage_private_media_ops_t *media_ops;
    void *media_user;
    ninlil_port_esp_storage_private_full_policy_t full_policy;
    ninlil_port_esp_storage_hil_observer_t hil_observer;
    void *hil_observer_user;
    int initialized;
    /* After COMMIT_UNKNOWN on seed/directory publish: force media reload. */
    int directory_cache_fenced;
    ninlil_port_esp_storage_directory_cache_t directory;
    ninlil_port_esp_storage_namespace_t
        namespaces[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES];
    ninlil_port_esp_storage_handle_t
        handles[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES];
    ninlil_port_esp_storage_transaction_t
        transactions[NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS];
    ninlil_port_esp_storage_iterator_t
        iterators[NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS];
    /*
     * Explicit dual-slot load / seed workspace. MUST NOT be automatic on stack
     * (each view is ~78 KiB). Lives in the binder-owned PSRAM object.
     */
    ninlil_port_esp_storage_view_t work_view_a;
    ninlil_port_esp_storage_view_t work_view_b;
    /* Atomic put/erase rebuild target; txn view changes only after success. */
    ninlil_port_esp_storage_view_t mutation_scratch;
    /* Directory dual-slot decode scratch (also too large for FreeRTOS stack). */
    ninlil_port_esp_storage_directory_cache_t dir_cache_a;
    ninlil_port_esp_storage_directory_cache_t dir_cache_b;
    uint8_t pack_scratch[NINLIL_PORT_ESP_STORAGE_SLOT_BYTES];
    uint8_t dir_scratch[NINLIL_PORT_ESP_STORAGE_DIR_BYTES];
};

struct ninlil_port_esp_storage_host_media {
    int initialized;
    uint32_t max_namespaces;
    uint8_t directory[2u][NINLIL_PORT_ESP_STORAGE_DIR_BYTES];
    uint8_t data[NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES][2u]
                [NINLIL_PORT_ESP_STORAGE_SLOT_BYTES];
    /* Flash realism: erase=0xFF, program 1→0 only, wear counters. */
    uint64_t erase_count;
    uint32_t physical_erase_count
        [NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT];
    uint32_t next_physical_sector;
    uint64_t program_byte_count;
    uint64_t program_reject_count;
    uint64_t erase_reject_count;
    int write_fault_active;
    int write_fault_mode;
    uint32_t write_fault_remaining;
    int write_partial_active;
    uint32_t write_partial_length;
    int write_directory_only;
    int erase_fault_active;
    int erase_fault_mode;
    uint32_t erase_fault_remaining;
    int sync_fault_active;
    int sync_fault_mode;
    uint32_t sync_fault_remaining;
};

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_PORT_ESP_STORAGE_WORKSPACE_H */
