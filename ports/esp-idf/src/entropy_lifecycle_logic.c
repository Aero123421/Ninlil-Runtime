#include "entropy_lifecycle_logic.h"

#include <stddef.h>

int ninlil_esp_idf_entropy_life_is_serving_owner(
    const ninlil_esp_idf_entropy_lifecycle_t *life,
    const void *instance)
{
    return life != NULL
        && instance != NULL
        && life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED
        && life->owner == instance;
}

int ninlil_esp_idf_entropy_life_instance_holds_resource(
    const ninlil_esp_idf_entropy_lifecycle_t *life,
    const void *instance)
{
    if (life == NULL || instance == NULL) {
        return 0;
    }
    if (life->owner == instance
        && (life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED
            || life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING
            || life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_DISABLING)) {
        return 1;
    }
    if (life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_ACQUIRING
        && life->pending == instance) {
        return 1;
    }
    return 0;
}

int ninlil_esp_idf_entropy_life_begin_acquire(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance,
    int config_ok,
    int *out_should_enable)
{
    if (out_should_enable != NULL) {
        *out_should_enable = 0;
    }
    if (life == NULL || instance == NULL) {
        return 1;
    }
    if (ninlil_esp_idf_entropy_life_instance_holds_resource(life, instance)) {
        return 2;
    }
    if (life->state != NINLIL_ESP_IDF_ENTROPY_LIFE_FREE
        || life->generation == UINT32_MAX) {
        return 3;
    }
    if (config_ok == 0) {
        return 4;
    }
    life->state = NINLIL_ESP_IDF_ENTROPY_LIFE_ACQUIRING;
    life->pending = instance;
    life->owner = NULL;
    life->cancel_acquire = 0u;
    if (out_should_enable != NULL) {
        *out_should_enable = 1;
    }
    return 0;
}

int ninlil_esp_idf_entropy_life_complete_acquire(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance)
{
    if (life == NULL || instance == NULL) {
        return 1;
    }
    if (life->state != NINLIL_ESP_IDF_ENTROPY_LIFE_ACQUIRING
        || life->pending != instance) {
        return 1;
    }
    if (life->cancel_acquire != 0u) {
        life->state = NINLIL_ESP_IDF_ENTROPY_LIFE_DISABLING;
        life->owner = instance;
        life->pending = NULL;
        return 2; /* cancelled — caller disables, then retires */
    }
    life->state = NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED;
    life->owner = instance;
    life->pending = NULL;
    life->fill_active = 0u;
    life->generation += 1u;
    return 0;
}

int ninlil_esp_idf_entropy_life_request_shutdown(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance,
    int *out_can_start_disable)
{
    if (out_can_start_disable != NULL) {
        *out_can_start_disable = 0;
    }
    if (life == NULL || instance == NULL) {
        return NINLIL_ESP_IDF_ENTROPY_SD_NOP;
    }
    if (life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_ACQUIRING
        && life->pending == instance) {
        life->cancel_acquire = 1u;
        return NINLIL_ESP_IDF_ENTROPY_SD_CANCEL_ACQUIRE;
    }
    if (life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED
        && life->owner == instance) {
        life->state = NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING;
        if (out_can_start_disable != NULL) {
            *out_can_start_disable = life->fill_active == 0u ? 1 : 0;
        }
        return NINLIL_ESP_IDF_ENTROPY_SD_BEGIN_RELEASE;
    }
    return NINLIL_ESP_IDF_ENTROPY_SD_NOP;
}

int ninlil_esp_idf_entropy_life_begin_fill(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance)
{
    if (life == NULL || instance == NULL) {
        return 1;
    }
    if (life->state != NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED
        || life->owner != instance) {
        return 2;
    }
    if (life->fill_active == UINT32_MAX) {
        return 2;
    }
    life->fill_active += 1u;
    return 0;
}

int ninlil_esp_idf_entropy_life_end_fill(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance)
{
    int wake = 0;

    if (life == NULL || instance == NULL || life->fill_active == 0u) {
        return 0;
    }
    if (life->owner == instance
        && (life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED
            || life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING)) {
        life->fill_active -= 1u;
        if (life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING
            && life->fill_active == 0u) {
            wake = 1;
        }
    }
    return wake;
}

int ninlil_esp_idf_entropy_life_release_drained(
    const ninlil_esp_idf_entropy_lifecycle_t *life,
    const void *instance)
{
    return life != NULL
        && instance != NULL
        && life->state == NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING
        && life->owner == instance
        && life->fill_active == 0u;
}

int ninlil_esp_idf_entropy_life_begin_disable(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance)
{
    if (life == NULL || instance == NULL) {
        return 1;
    }
    if (life->state != NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING
        || life->owner != instance
        || life->fill_active != 0u) {
        return 1;
    }
    life->state = NINLIL_ESP_IDF_ENTROPY_LIFE_DISABLING;
    return 0;
}

int ninlil_esp_idf_entropy_life_finish_disable(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance,
    int *out_should_retire_storage)
{
    if (out_should_retire_storage != NULL) {
        *out_should_retire_storage = 0;
    }
    if (life == NULL || instance == NULL) {
        return 1;
    }
    if (life->state != NINLIL_ESP_IDF_ENTROPY_LIFE_DISABLING
        || life->owner != instance) {
        return 1;
    }
    life->state = NINLIL_ESP_IDF_ENTROPY_LIFE_RETIRED;
    life->owner = NULL;
    life->pending = NULL;
    life->fill_active = 0u;
    life->cancel_acquire = 0u;
    if (out_should_retire_storage != NULL) {
        *out_should_retire_storage = 1;
    }
    return 0;
}
