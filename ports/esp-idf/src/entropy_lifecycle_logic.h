/*
 * Entropy exclusive ownership SM + ACQUIRING cancel linearization.
 * FREE → ACQUIRING → OWNED → RELEASING → DISABLING → RETIRED
 * ACQUIRING may be cancelled by shutdown so the instance never becomes live.
 */

#ifndef NINLIL_ESP_IDF_ENTROPY_LIFECYCLE_LOGIC_H
#define NINLIL_ESP_IDF_ENTROPY_LIFECYCLE_LOGIC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_ENTROPY_LIFE_FREE       ((uint32_t)0u)
#define NINLIL_ESP_IDF_ENTROPY_LIFE_ACQUIRING  ((uint32_t)1u)
#define NINLIL_ESP_IDF_ENTROPY_LIFE_OWNED      ((uint32_t)2u)
#define NINLIL_ESP_IDF_ENTROPY_LIFE_RELEASING  ((uint32_t)3u)
#define NINLIL_ESP_IDF_ENTROPY_LIFE_DISABLING  ((uint32_t)4u)
#define NINLIL_ESP_IDF_ENTROPY_LIFE_RETIRED    ((uint32_t)5u)

/* request_shutdown results */
#define NINLIL_ESP_IDF_ENTROPY_SD_NOP            0
#define NINLIL_ESP_IDF_ENTROPY_SD_CANCEL_ACQUIRE 1
#define NINLIL_ESP_IDF_ENTROPY_SD_BEGIN_RELEASE  2

typedef struct ninlil_esp_idf_entropy_lifecycle {
    void *owner;
    void *pending;
    uint32_t state;
    uint32_t fill_active;
    uint32_t generation;
    uint32_t cancel_acquire; /* 1 if shutdown cancelled ACQUIRING */
} ninlil_esp_idf_entropy_lifecycle_t;

int ninlil_esp_idf_entropy_life_is_serving_owner(
    const ninlil_esp_idf_entropy_lifecycle_t *life,
    const void *instance);

int ninlil_esp_idf_entropy_life_instance_holds_resource(
    const ninlil_esp_idf_entropy_lifecycle_t *life,
    const void *instance);

int ninlil_esp_idf_entropy_life_begin_acquire(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance,
    int config_ok,
    int *out_should_enable);

int ninlil_esp_idf_entropy_life_complete_acquire(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance);

/* After complete_acquire: if cancelled, abort without publish. Returns 1 if cancelled. */
/*
 * Linearized shutdown entry:
 * - ACQUIRING && pending==instance → cancel_acquire (instance never goes live)
 * - OWNED && owner==instance → begin RELEASING
 * - else NOP
 */
int ninlil_esp_idf_entropy_life_request_shutdown(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance,
    int *out_can_start_disable);

int ninlil_esp_idf_entropy_life_begin_fill(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance);

/* Returns 1 if waiter should be woken (RELEASING && fill_active hit 0). */
int ninlil_esp_idf_entropy_life_end_fill(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance);

int ninlil_esp_idf_entropy_life_release_drained(
    const ninlil_esp_idf_entropy_lifecycle_t *life,
    const void *instance);

int ninlil_esp_idf_entropy_life_begin_disable(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance);

int ninlil_esp_idf_entropy_life_finish_disable(
    ninlil_esp_idf_entropy_lifecycle_t *life,
    void *instance,
    int *out_should_retire_storage);

#ifdef __cplusplus
}
#endif

#endif
