/*
 * Port-private HIL observation seam.
 *
 * Not a consumer-visible public header. Production public headers under
 * ports/esp-idf/storage/include must not re-export this vocabulary.
 * HIL firmware and host private tests may include this via PRIV_INCLUDE only.
 */

#ifndef NINLIL_PORT_ESP_STORAGE_HIL_OBSERVER_H
#define NINLIL_PORT_ESP_STORAGE_HIL_OBSERVER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Events identify exact durable-media boundaries without changing the Storage
 * ABI or enabling FULL success. A callback must not re-enter storage.
 * NULL observer means no observation.
 */
typedef enum ninlil_port_esp_storage_hil_event {
    NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_ERASE = 1,
    NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_WRITE = 2,
    NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_SEAL = 3,
    NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE = 4,
    NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE = 5,
    NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN = 6
} ninlil_port_esp_storage_hil_event_t;

typedef int (*ninlil_port_esp_storage_hil_observer_t)(
    void *observer_user,
    ninlil_port_esp_storage_hil_event_t event);

typedef struct ninlil_port_esp_storage ninlil_port_esp_storage_t;
typedef struct ninlil_port_esp_storage_flash_binding
    ninlil_port_esp_storage_flash_binding_t;

int ninlil_port_esp_storage_private_set_hil_observer(
    ninlil_port_esp_storage_t *storage,
    ninlil_port_esp_storage_hil_observer_t observer,
    void *observer_user);

/*
 * ESP flash binder HIL seam. Not part of the public flash bind/unbind API.
 * Visibility is hidden so production archives do not re-export it globally.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int ninlil_port_esp_storage_flash_set_hil_observer(
    ninlil_port_esp_storage_flash_binding_t *binding,
    ninlil_port_esp_storage_hil_observer_t observer,
    void *observer_user);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_PORT_ESP_STORAGE_HIL_OBSERVER_H */
