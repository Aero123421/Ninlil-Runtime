/*
 * Host media models NOR flash constraints:
 * - erase sets 0xFF on erase-aligned regions
 * - program allows only 1→0 bit flips
 * - fault injection + wear accounting
 */

#include "esp_storage_private.h"

#include <string.h>

static int region_for_offset(
    const ninlil_port_esp_storage_host_media_t *media,
    uint64_t offset,
    uint32_t length,
    int *is_directory,
    uint32_t *index_a,
    uint32_t *index_b,
    uint32_t *within)
{
    uint64_t dir_span = 2u * (uint64_t)NINLIL_PORT_ESP_STORAGE_DIR_BYTES;
    uint64_t total;

    if (media == NULL || length == 0u) {
        return 0;
    }
    total = ninlil_port_esp_storage_media_total_bytes(media->max_namespaces);
    if (offset > total || length > total - offset) {
        return 0;
    }
    if (offset + length <= dir_span) {
        *is_directory = 1;
        *index_a = (uint32_t)(offset / NINLIL_PORT_ESP_STORAGE_DIR_BYTES);
        *within = (uint32_t)(offset % NINLIL_PORT_ESP_STORAGE_DIR_BYTES);
        *index_b = 0u;
        if (*index_a > 1u
            || *within + length > NINLIL_PORT_ESP_STORAGE_DIR_BYTES) {
            return 0;
        }
        return 1;
    }
    {
        uint64_t data_off = offset - dir_span;
        uint64_t slot_span = (uint64_t)NINLIL_PORT_ESP_STORAGE_SLOT_BYTES;
        uint64_t linear = data_off / slot_span;
        *is_directory = 0;
        *index_a = (uint32_t)(linear / 2u);
        *index_b = (uint32_t)(linear % 2u);
        *within = (uint32_t)(data_off % slot_span);
        if (*index_a >= media->max_namespaces
            || *within + length > NINLIL_PORT_ESP_STORAGE_SLOT_BYTES) {
            return 0;
        }
        return 1;
    }
}

static uint8_t *region_ptr(
    ninlil_port_esp_storage_host_media_t *media,
    int is_dir,
    uint32_t a,
    uint32_t b,
    uint32_t within)
{
    if (is_dir) {
        return &media->directory[a][within];
    }
    return &media->data[a][b][within];
}

static int program_bytes(uint8_t *dest, const uint8_t *src, uint32_t length)
{
    uint32_t i;
    for (i = 0u; i < length; ++i) {
        /* NOR: can only clear bits (1→0). */
        if ((uint8_t)(dest[i] & src[i]) != src[i]) {
            return 0;
        }
    }
    for (i = 0u; i < length; ++i) {
        dest[i] = (uint8_t)(dest[i] & src[i]);
    }
    return 1;
}

static int host_read(
    void *media_user,
    uint64_t offset,
    uint8_t *out,
    uint32_t length)
{
    ninlil_port_esp_storage_host_media_t *media =
        (ninlil_port_esp_storage_host_media_t *)media_user;
    int is_dir = 0;
    uint32_t a = 0u;
    uint32_t b = 0u;
    uint32_t within = 0u;

    if (media == NULL || !media->initialized || out == NULL) {
        return 1;
    }
    if (!region_for_offset(media, offset, length, &is_dir, &a, &b, &within)) {
        return 1;
    }
    (void)memcpy(out, region_ptr(media, is_dir, a, b, within), length);
    return 0;
}

static int host_write(
    void *media_user,
    uint64_t offset,
    const uint8_t *data,
    uint32_t length)
{
    ninlil_port_esp_storage_host_media_t *media =
        (ninlil_port_esp_storage_host_media_t *)media_user;
    int is_dir = 0;
    uint32_t a = 0u;
    uint32_t b = 0u;
    uint32_t within = 0u;
    uint32_t write_len = length;
    int mode = 0;
    uint8_t *dest;

    if (media == NULL || !media->initialized || data == NULL) {
        return 1;
    }
    if (!region_for_offset(media, offset, length, &is_dir, &a, &b, &within)) {
        return 1;
    }
    dest = region_ptr(media, is_dir, a, b, within);

    if (media->write_fault_active && media->write_fault_remaining > 0u) {
        if (!(media->write_directory_only && !is_dir)) {
            mode = media->write_fault_mode;
            media->write_fault_remaining -= 1u;
            if (media->write_fault_remaining == 0u) {
                media->write_fault_active = 0;
                media->write_partial_active = 0;
                media->write_directory_only = 0;
            }
            if (media->write_partial_active
                && media->write_partial_length < length) {
                write_len = media->write_partial_length;
            }
            if (mode == 1) {
                return 1;
            }
            if (write_len != 0u) {
                if (!program_bytes(dest, data, write_len)) {
                    media->program_reject_count += 1u;
                    return 1;
                }
                media->program_byte_count += write_len;
            }
            if (mode == 2) {
                return 2;
            }
            if (write_len != length) {
                return 1;
            }
            return 0;
        }
    }

    if (!program_bytes(dest, data, length)) {
        media->program_reject_count += 1u;
        return 1;
    }
    media->program_byte_count += length;
    return 0;
}

static int host_erase(void *media_user, uint64_t offset, uint32_t length)
{
    ninlil_port_esp_storage_host_media_t *media =
        (ninlil_port_esp_storage_host_media_t *)media_user;
    int is_dir = 0;
    uint32_t a = 0u;
    uint32_t b = 0u;
    uint32_t within = 0u;

    if (media == NULL || !media->initialized) {
        return 1;
    }
    /* Erase alignment matches SPI flash sector size. */
    if ((offset % NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN) != 0u
        || (length % NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN) != 0u
        || length == 0u) {
        media->erase_reject_count += 1u;
        return 1;
    }
    if (!region_for_offset(media, offset, length, &is_dir, &a, &b, &within)) {
        media->erase_reject_count += 1u;
        return 1;
    }
    if (media->erase_fault_active && media->erase_fault_remaining > 0u) {
        int mode = media->erase_fault_mode;
        media->erase_fault_remaining -= 1u;
        if (media->erase_fault_remaining == 0u) {
            media->erase_fault_active = 0;
        }
        if (mode != 0) {
            return mode == 2 ? 2 : 1;
        }
    }
    (void)memset(
        region_ptr(media, is_dir, a, b, within),
        (int)NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE,
        length);
    /*
     * Account erase wear per physical 4 KiB sector, not per range call.
     * The host backend keeps logical bytes directly addressable for fault
     * tests, while this round-robin physical accounting models the contract
     * supplied by ESP-IDF wear_levelling in the target backend.
     */
    {
        uint32_t sectors = length / NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN;
        uint32_t sector;
        for (sector = 0u; sector < sectors; ++sector) {
            uint32_t physical = media->next_physical_sector;
            media->physical_erase_count[physical] += 1u;
            media->next_physical_sector =
                (physical + 1u)
                % NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT;
            media->erase_count += 1u;
        }
    }
    return 0;
}

static int host_sync(void *media_user)
{
    ninlil_port_esp_storage_host_media_t *media =
        (ninlil_port_esp_storage_host_media_t *)media_user;
    if (media == NULL || !media->initialized) {
        return 1;
    }
    if (media->sync_fault_active && media->sync_fault_remaining > 0u) {
        int mode = media->sync_fault_mode;
        media->sync_fault_remaining -= 1u;
        if (media->sync_fault_remaining == 0u) {
            media->sync_fault_active = 0;
        }
        return mode;
    }
    return 0;
}

static const ninlil_port_esp_storage_private_media_ops_t g_host_media_ops = {
    host_read,
    host_write,
    host_erase,
    host_sync,
};

int ninlil_port_esp_storage_host_media_init(
    ninlil_port_esp_storage_host_media_t *media,
    uint32_t max_namespaces)
{
    if (media == NULL || max_namespaces == 0u
        || max_namespaces > NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES) {
        return -1;
    }
    (void)memset(media, 0, sizeof(*media));
    /* Fresh partition: erased flash is 0xFF, not 0x00. */
    (void)memset(
        media->directory,
        (int)NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE,
        sizeof(media->directory));
    (void)memset(
        media->data,
        (int)NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE,
        sizeof(media->data));
    media->max_namespaces = max_namespaces;
    media->initialized = 1;
    return 0;
}

void ninlil_port_esp_storage_host_media_deinit(
    ninlil_port_esp_storage_host_media_t *media)
{
    if (media == NULL) {
        return;
    }
    (void)memset(media, 0, sizeof(*media));
}

const ninlil_port_esp_storage_private_media_ops_t *
ninlil_port_esp_storage_host_media_ops(void)
{
    return &g_host_media_ops;
}

int ninlil_port_esp_storage_host_media_fault_write(
    ninlil_port_esp_storage_host_media_t *media,
    int mode,
    uint32_t remaining_count)
{
    if (media == NULL || !media->initialized || remaining_count == 0u
        || (mode != 0 && mode != 1 && mode != 2)) {
        return -1;
    }
    media->write_fault_active = 1;
    media->write_fault_mode = mode;
    media->write_fault_remaining = remaining_count;
    media->write_partial_active = 0;
    media->write_partial_length = 0u;
    return 0;
}

int ninlil_port_esp_storage_host_media_fault_sync(
    ninlil_port_esp_storage_host_media_t *media,
    int mode,
    uint32_t remaining_count)
{
    if (media == NULL || !media->initialized || remaining_count == 0u
        || (mode != 0 && mode != 1 && mode != 2)) {
        return -1;
    }
    media->sync_fault_active = 1;
    media->sync_fault_mode = mode;
    media->sync_fault_remaining = remaining_count;
    return 0;
}

int ninlil_port_esp_storage_host_media_fault_partial_write(
    ninlil_port_esp_storage_host_media_t *media,
    uint32_t partial_length,
    int mode,
    uint32_t remaining_count)
{
    if (media == NULL || !media->initialized || remaining_count == 0u
        || (mode != 0 && mode != 1 && mode != 2)) {
        return -1;
    }
    media->write_fault_active = 1;
    media->write_fault_mode = mode;
    media->write_fault_remaining = remaining_count;
    media->write_partial_active = 1;
    media->write_partial_length = partial_length;
    return 0;
}

int ninlil_port_esp_storage_host_media_fault_directory_only(
    ninlil_port_esp_storage_host_media_t *media,
    int enable)
{
    if (media == NULL || !media->initialized || (enable != 0 && enable != 1)) {
        return -1;
    }
    media->write_directory_only = enable;
    return 0;
}

int ninlil_port_esp_storage_host_media_fault_erase(
    ninlil_port_esp_storage_host_media_t *media,
    int mode,
    uint32_t remaining_count)
{
    if (media == NULL || !media->initialized || remaining_count == 0u
        || (mode != 0 && mode != 1 && mode != 2)) {
        return -1;
    }
    media->erase_fault_active = 1;
    media->erase_fault_mode = mode;
    media->erase_fault_remaining = remaining_count;
    return 0;
}

uint64_t ninlil_port_esp_storage_host_media_erase_count(
    const ninlil_port_esp_storage_host_media_t *media)
{
    return media == NULL ? 0u : media->erase_count;
}

uint64_t ninlil_port_esp_storage_host_media_program_byte_count(
    const ninlil_port_esp_storage_host_media_t *media)
{
    return media == NULL ? 0u : media->program_byte_count;
}

uint32_t ninlil_port_esp_storage_host_media_sector_erase_count(
    const ninlil_port_esp_storage_host_media_t *media,
    uint32_t sector_index)
{
    if (media == NULL
        || sector_index >= NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT) {
        return 0u;
    }
    return media->physical_erase_count[sector_index];
}

uint32_t ninlil_port_esp_storage_host_media_hotspot_erase_count(
    const ninlil_port_esp_storage_host_media_t *media)
{
    uint32_t maximum = 0u;
    uint32_t index;
    if (media == NULL) {
        return 0u;
    }
    for (index = 0u;
         index < NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT;
         ++index) {
        if (media->physical_erase_count[index] > maximum) {
            maximum = media->physical_erase_count[index];
        }
    }
    return maximum;
}

uint32_t ninlil_port_esp_storage_host_media_coldspot_erase_count(
    const ninlil_port_esp_storage_host_media_t *media)
{
    uint32_t minimum = UINT32_MAX;
    uint32_t index;
    if (media == NULL) {
        return 0u;
    }
    for (index = 0u;
         index < NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT;
         ++index) {
        if (media->physical_erase_count[index] < minimum) {
            minimum = media->physical_erase_count[index];
        }
    }
    return minimum == UINT32_MAX ? 0u : minimum;
}

uint32_t ninlil_port_esp_storage_host_media_hotspot_sector(
    const ninlil_port_esp_storage_host_media_t *media)
{
    uint32_t maximum = 0u;
    uint32_t maximum_index = 0u;
    uint32_t index;
    if (media == NULL) {
        return 0u;
    }
    for (index = 0u;
         index < NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT;
         ++index) {
        if (media->physical_erase_count[index] > maximum) {
            maximum = media->physical_erase_count[index];
            maximum_index = index;
        }
    }
    return maximum_index;
}
