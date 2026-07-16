#ifndef NINLIL_PORT_ESP_STORAGE_PRIVATE_H
#define NINLIL_PORT_ESP_STORAGE_PRIVATE_H

#include "ninlil_port/esp_storage.h"
#include "esp_storage_hil_observer.h"

typedef struct ninlil_port_esp_storage ninlil_port_esp_storage_t;
typedef struct ninlil_port_esp_storage_host_media
    ninlil_port_esp_storage_host_media_t;

typedef enum ninlil_port_esp_storage_private_full_policy {
#if !defined(ESP_PLATFORM)
    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL = 1,
#endif
    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN = 2
} ninlil_port_esp_storage_private_full_policy_t;

typedef struct ninlil_port_esp_storage_private_media_ops {
    int (*read)(void *media_user, uint64_t offset, uint8_t *out,
        uint32_t length);
    int (*write)(void *media_user, uint64_t offset, const uint8_t *data,
        uint32_t length);
    int (*erase)(void *media_user, uint64_t offset, uint32_t length);
    int (*sync)(void *media_user);
} ninlil_port_esp_storage_private_media_ops_t;

#include "esp_storage_workspace.h"

typedef struct ninlil_port_esp_flash_media {
    void *partition;
    uint32_t max_namespaces;
    int32_t wl_handle;
    uint32_t mounted;
} ninlil_port_esp_flash_media_t;

struct ninlil_port_esp_storage_flash_binding {
    ninlil_port_esp_storage_t storage;
    ninlil_port_esp_flash_media_t media;
};

int ninlil_port_esp_storage_private_init(
    ninlil_port_esp_storage_t *storage,
    const ninlil_port_esp_storage_config_t *config,
    const ninlil_port_esp_storage_private_media_ops_t *media_ops,
    void *media_user,
    ninlil_port_esp_storage_private_full_policy_t full_policy);
void ninlil_port_esp_storage_private_deinit(
    ninlil_port_esp_storage_t *storage);
const ninlil_storage_ops_t *ninlil_port_esp_storage_private_ops(
    ninlil_port_esp_storage_t *storage);
void ninlil_port_esp_storage_private_simulate_crash(
    ninlil_port_esp_storage_t *storage);
int ninlil_port_esp_storage_private_simulate_full_reinit(
    ninlil_port_esp_storage_t *storage,
    const ninlil_port_esp_storage_config_t *config,
    const ninlil_port_esp_storage_private_media_ops_t *media_ops,
    void *media_user,
    ninlil_port_esp_storage_private_full_policy_t full_policy);

uint64_t ninlil_port_esp_storage_media_directory_offset(uint32_t dir_slot);
uint64_t ninlil_port_esp_storage_media_data_offset(
    uint32_t max_namespaces, uint32_t namespace_index, uint32_t slot);
uint64_t ninlil_port_esp_storage_media_total_bytes(uint32_t max_namespaces);
int ninlil_port_esp_storage_private_placement_ok(const void *object);
uint32_t ninlil_port_esp_storage_token_generation_max_for_bits(
    uint32_t max_index_exclusive, uint32_t uintptr_bits);
int ninlil_port_esp_storage_token_next_generation_for_bits(
    uint32_t current, uint32_t max_index_exclusive, uint32_t uintptr_bits,
    uint32_t *out_generation);

#if !defined(ESP_PLATFORM)
int ninlil_port_esp_storage_host_media_init(
    ninlil_port_esp_storage_host_media_t *media, uint32_t max_namespaces);
void ninlil_port_esp_storage_host_media_deinit(
    ninlil_port_esp_storage_host_media_t *media);
const ninlil_port_esp_storage_private_media_ops_t *
ninlil_port_esp_storage_host_media_ops(void);
int ninlil_port_esp_storage_host_media_fault_write(
    ninlil_port_esp_storage_host_media_t *media, int mode,
    uint32_t remaining_count);
int ninlil_port_esp_storage_host_media_fault_sync(
    ninlil_port_esp_storage_host_media_t *media, int mode,
    uint32_t remaining_count);
int ninlil_port_esp_storage_host_media_fault_partial_write(
    ninlil_port_esp_storage_host_media_t *media, uint32_t partial_length,
    int mode, uint32_t remaining_count);
int ninlil_port_esp_storage_host_media_fault_directory_only(
    ninlil_port_esp_storage_host_media_t *media, int enable);
int ninlil_port_esp_storage_host_media_fault_erase(
    ninlil_port_esp_storage_host_media_t *media, int mode,
    uint32_t remaining_count);
uint64_t ninlil_port_esp_storage_host_media_erase_count(
    const ninlil_port_esp_storage_host_media_t *media);
uint64_t ninlil_port_esp_storage_host_media_program_byte_count(
    const ninlil_port_esp_storage_host_media_t *media);
uint32_t ninlil_port_esp_storage_host_media_sector_erase_count(
    const ninlil_port_esp_storage_host_media_t *media, uint32_t sector_index);
uint32_t ninlil_port_esp_storage_host_media_hotspot_erase_count(
    const ninlil_port_esp_storage_host_media_t *media);
uint32_t ninlil_port_esp_storage_host_media_coldspot_erase_count(
    const ninlil_port_esp_storage_host_media_t *media);
uint32_t ninlil_port_esp_storage_host_media_hotspot_sector(
    const ninlil_port_esp_storage_host_media_t *media);
#endif

#endif
