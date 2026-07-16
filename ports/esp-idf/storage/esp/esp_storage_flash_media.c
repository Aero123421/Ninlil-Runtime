/*
 * ESP-IDF wear-levelled partition media. FULL OK is not claimed without HIL.
 * See docs/21-m3-esp-idf-durable-storage.md §7.
 */

#include "ninlil_port/esp_storage_flash.h"
#include "esp_storage_hil_observer.h"
#include "esp_storage_private.h"

#include <string.h>

#if defined(ESP_PLATFORM)

#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_partition.h"
#include "wear_levelling.h"

static const esp_partition_t *flash_part(const ninlil_port_esp_flash_media_t *media)
{
    return (const esp_partition_t *)media->partition;
}

static wl_handle_t flash_wl(const ninlil_port_esp_flash_media_t *media)
{
    return (wl_handle_t)media->wl_handle;
}

static int flash_read(
    void *media_user,
    uint64_t offset,
    uint8_t *out,
    uint32_t length)
{
    ninlil_port_esp_flash_media_t *media =
        (ninlil_port_esp_flash_media_t *)media_user;
    if (media == NULL || flash_part(media) == NULL || media->mounted == 0u
        || out == NULL
        || length == 0u || offset > UINT32_MAX) {
        return 1;
    }
    return wl_read(flash_wl(media), (size_t)offset, out, (size_t)length)
            == ESP_OK
        ? 0
        : 1;
}

static int flash_write(
    void *media_user,
    uint64_t offset,
    const uint8_t *data,
    uint32_t length)
{
    ninlil_port_esp_flash_media_t *media =
        (ninlil_port_esp_flash_media_t *)media_user;
    esp_err_t err;
    if (media == NULL || flash_part(media) == NULL || media->mounted == 0u
        || data == NULL
        || length == 0u || offset > UINT32_MAX) {
        return 1;
    }
    err = wl_write(flash_wl(media), (size_t)offset, data, (size_t)length);
    if (err == ESP_OK) {
        return 0;
    }
    return 2;
}

static int flash_erase(void *media_user, uint64_t offset, uint32_t length)
{
    ninlil_port_esp_flash_media_t *media =
        (ninlil_port_esp_flash_media_t *)media_user;
    if (media == NULL || flash_part(media) == NULL || media->mounted == 0u
        || length == 0u
        || offset > UINT32_MAX) {
        return 1;
    }
    return wl_erase_range(
               flash_wl(media), (size_t)offset, (size_t)length)
            == ESP_OK
        ? 0
        : 1;
}

/*
 * ESP-IDF WL write/erase return is the documented program/erase
 * completion boundary for the API call. There is no separate fsync for
 * wear-levelled media. Multi-key FULL atomic power-cut all-old/all-new is NOT
 * hardware-proven in this slice; the model still calls sync as a no-op
 * success, while full_policy=ESP_UNPROVEN refuses STORAGE_OK for FULL.
 */
static int flash_sync(void *media_user)
{
    (void)media_user;
    return 0;
}

static const ninlil_port_esp_storage_private_media_ops_t g_flash_media_ops = {
    flash_read,
    flash_write,
    flash_erase,
    flash_sync,
};

int ninlil_port_esp_storage_flash_bind(
    const char *partition_label,
    const ninlil_port_esp_storage_config_t *config,
    ninlil_port_esp_storage_flash_binding_t **out_binding,
    const ninlil_storage_ops_t **out_ops)
{
    ninlil_port_esp_storage_flash_binding_t *binding = NULL;
    ninlil_port_esp_flash_media_t *media;
    const esp_partition_t *part;
    uint64_t need;
    wl_handle_t wl = WL_INVALID_HANDLE;
    ninlil_port_esp_storage_config_t admitted_config;
    size_t sector_size;
    size_t logical_size;

    if (out_binding == NULL || out_ops == NULL) {
        return -1;
    }
    *out_binding = NULL;
    *out_ops = NULL;
    if (partition_label == NULL || config == NULL) {
        return -1;
    }
    part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        ESP_PARTITION_SUBTYPE_ANY,
        partition_label);
    if (part == NULL) {
        return -1;
    }
    if (wl_mount(part, &wl) != ESP_OK) {
        return -1;
    }
    sector_size = wl_sector_size(wl);
    logical_size = wl_size(wl);
    need = ninlil_port_esp_storage_media_total_bytes(config->max_namespaces);
    if ((uint64_t)logical_size < need
        || sector_size != NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN
        || logical_size / sector_size > UINT32_MAX) {
        (void)wl_unmount(wl);
        return -1;
    }
    admitted_config = *config;
    /* Actual mounted WL geometry is authority; never trust a reference size. */
    admitted_config.wl_usable_sector_count =
        (uint32_t)(logical_size / sector_size);
    binding = (ninlil_port_esp_storage_flash_binding_t *)heap_caps_calloc(
        1u, sizeof(*binding), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (binding == NULL) {
        (void)wl_unmount(wl);
        return -1;
    }
    media = &binding->media;
    (void)memset(media, 0, sizeof(*media));
    media->partition = (void *)part;
    media->max_namespaces = config->max_namespaces;
    media->wl_handle = (int32_t)wl;
    media->mounted = 1u;
    /* Never claim FULL OK without HIL attestation in this slice. */
    if (ninlil_port_esp_storage_private_init(
        &binding->storage,
        &admitted_config,
        &g_flash_media_ops,
        media,
        NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN)
        != 0) {
        (void)wl_unmount(wl);
        (void)memset(media, 0, sizeof(*media));
        heap_caps_free(binding);
        return -1;
    }
    *out_ops = ninlil_port_esp_storage_private_ops(&binding->storage);
    if (*out_ops == NULL) {
        ninlil_port_esp_storage_private_deinit(&binding->storage);
        (void)wl_unmount(wl);
        heap_caps_free(binding);
        return -1;
    }
    *out_binding = binding;
    return 0;
}

void ninlil_port_esp_storage_flash_unbind(
    ninlil_port_esp_storage_flash_binding_t *binding)
{
    if (binding != NULL) {
        ninlil_port_esp_storage_private_deinit(&binding->storage);
        if (binding->media.mounted != 0u) {
            (void)wl_unmount(flash_wl(&binding->media));
        }
        (void)memset(binding, 0, sizeof(*binding));
        heap_caps_free(binding);
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int ninlil_port_esp_storage_flash_set_hil_observer(
    ninlil_port_esp_storage_flash_binding_t *binding,
    ninlil_port_esp_storage_hil_observer_t observer,
    void *observer_user)
{
    if (binding == NULL) {
        return -1;
    }
    return ninlil_port_esp_storage_private_set_hil_observer(
        &binding->storage, observer, observer_user);
}

#else /* !ESP_PLATFORM */

int ninlil_port_esp_storage_flash_bind(
    const char *partition_label,
    const ninlil_port_esp_storage_config_t *config,
    ninlil_port_esp_storage_flash_binding_t **out_binding,
    const ninlil_storage_ops_t **out_ops)
{
    (void)partition_label;
    (void)config;
    if (out_binding != NULL) {
        *out_binding = NULL;
    }
    if (out_ops != NULL) {
        *out_ops = NULL;
    }
    return -1;
}

void ninlil_port_esp_storage_flash_unbind(
    ninlil_port_esp_storage_flash_binding_t *binding)
{
    (void)binding;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int ninlil_port_esp_storage_flash_set_hil_observer(
    ninlil_port_esp_storage_flash_binding_t *binding,
    ninlil_port_esp_storage_hil_observer_t observer,
    void *observer_user)
{
    (void)binding;
    (void)observer;
    (void)observer_user;
    return -1;
}

#endif /* ESP_PLATFORM */
