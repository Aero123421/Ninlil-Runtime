/*
 * ESP-IDF flash partition bind API (port-owned).
 *
 * The binder owns the PSRAM workspace allocated for the storage object.
 * Caller must unbind exactly once when finished. Simultaneous use of two
 * live bindings against the same partition, or double-bind without unbind,
 * is forbidden. Double-unbind is a no-op for NULL; unbind of a live binding
 * releases the binder-owned workspace.
 */

#ifndef NINLIL_PORT_ESP_STORAGE_FLASH_H
#define NINLIL_PORT_ESP_STORAGE_FLASH_H

#include "ninlil_port/esp_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_port_esp_storage_flash_binding
    ninlil_port_esp_storage_flash_binding_t;

int ninlil_port_esp_storage_flash_bind(
    const char *partition_label,
    const ninlil_port_esp_storage_config_t *config,
    ninlil_port_esp_storage_flash_binding_t **out_binding,
    const ninlil_storage_ops_t **out_ops);

void ninlil_port_esp_storage_flash_unbind(
    ninlil_port_esp_storage_flash_binding_t *binding);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_PORT_ESP_STORAGE_FLASH_H */
