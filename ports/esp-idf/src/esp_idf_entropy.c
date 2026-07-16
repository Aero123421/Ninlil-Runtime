/*
 * ESP-IDF entropy: boot-global one-shot ownership, immutable embedded ops,
 * cancellation-safe acquire, and blocking task-notification drain.
 */

#include "ninlil_esp_idf/entropy.h"

#include "entropy_lifecycle_logic.h"
#include "entropy_logic.h"
#include "entropy_publish_logic.h"

#include "bootloader_random.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static ninlil_esp_idf_entropy_lifecycle_t s_entropy_life;
static portMUX_TYPE s_entropy_mux = portMUX_INITIALIZER_UNLOCKED;
static TaskHandle_t s_shutdown_waiter;

_Static_assert(
    configUSE_TASK_NOTIFICATIONS == 1,
    "entropy lifecycle requires task notifications");
_Static_assert(
    NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX
        < configTASK_NOTIFICATION_ARRAY_ENTRIES,
    "entropy notification index unavailable");

static int entropy_in_isr(void)
{
    return xPortInIsrContext() != 0 ? 1 : 0;
}

static void notify_waiter(TaskHandle_t waiter)
{
    if (waiter != NULL) {
        xTaskNotifyGiveIndexed(
            waiter, (UBaseType_t)NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX);
    }
}

static ninlil_port_status_t entropy_fill(
    void *user,
    uint8_t *out,
    uint32_t length)
{
    ninlil_esp_idf_entropy_t *entropy =
        (ninlil_esp_idf_entropy_t *)user;
    int invoke_backend = 0;
    int wake;
    TaskHandle_t waiter = NULL;
    ninlil_port_status_t status;

    if (entropy_in_isr() != 0 || entropy == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    status = ninlil_esp_idf_entropy_classify_fill(
        1, out, length, &invoke_backend);
    if (length == 0u || status != NINLIL_PORT_OK || invoke_backend == 0) {
        return status;
    }

    portENTER_CRITICAL(&s_entropy_mux);
    if (ninlil_esp_idf_entropy_life_begin_fill(
            &s_entropy_life, entropy)
        != 0) {
        portEXIT_CRITICAL(&s_entropy_mux);
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    portEXIT_CRITICAL(&s_entropy_mux);

    /* ESP-IDF contract: synchronous and bounded for this armed source. */
    esp_fill_random(out, (size_t)length);

    portENTER_CRITICAL(&s_entropy_mux);
    wake = ninlil_esp_idf_entropy_life_end_fill(&s_entropy_life, entropy);
    if (wake != 0) {
        waiter = s_shutdown_waiter;
        s_shutdown_waiter = NULL;
    }
    portEXIT_CRITICAL(&s_entropy_mux);
    notify_waiter(waiter);
    return NINLIL_PORT_OK;
}

int ninlil_esp_idf_entropy_init(
    ninlil_esp_idf_entropy_t *entropy,
    const ninlil_esp_idf_entropy_config_t *config)
{
    ninlil_esp_idf_entropy_config_view_t view;
    TaskHandle_t waiter = NULL;
    int config_ok;
    int should_enable = 0;
    int decision;
    int ignored = 0;

    if (entropy == NULL || entropy_in_isr() != 0) {
        return 1;
    }
    config_ok = config != NULL
        && ninlil_esp_idf_entropy_storage_is_zero(entropy)
        && ninlil_esp_idf_entropy_config_try_copy(config, &view);

    portENTER_CRITICAL(&s_entropy_mux);
    decision = ninlil_esp_idf_entropy_life_begin_acquire(
        &s_entropy_life, entropy, config_ok, &should_enable);
    portEXIT_CRITICAL(&s_entropy_mux);
    if (decision != 0) {
        return 1;
    }

    if (should_enable != 0) {
        bootloader_random_enable();
    }

    portENTER_CRITICAL(&s_entropy_mux);
    decision = ninlil_esp_idf_entropy_life_complete_acquire(
        &s_entropy_life, entropy);
    if (decision == 0) {
        decision = ninlil_esp_idf_entropy_publish_once(
            entropy, entropy_fill, view.policy, s_entropy_life.generation);
        portEXIT_CRITICAL(&s_entropy_mux);
        return decision;
    }
    portEXIT_CRITICAL(&s_entropy_mux);

    /* A concurrent shutdown cancelled ACQUIRING after hardware enable. */
    if (decision == 2) {
        bootloader_random_disable();
        portENTER_CRITICAL(&s_entropy_mux);
        (void)ninlil_esp_idf_entropy_life_finish_disable(
            &s_entropy_life, entropy, &ignored);
        waiter = s_shutdown_waiter;
        s_shutdown_waiter = NULL;
        portEXIT_CRITICAL(&s_entropy_mux);
        notify_waiter(waiter);
    }
    return 1;
}

void ninlil_esp_idf_entropy_shutdown(ninlil_esp_idf_entropy_t *entropy)
{
    int can_start_disable = 0;
    int ignored = 0;
    int shutdown_decision;
    TaskHandle_t current;

    if (entropy == NULL || entropy_in_isr() != 0) {
        return;
    }
    current = xTaskGetCurrentTaskHandle();
    (void)ulTaskNotifyTakeIndexed(
        (UBaseType_t)NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX,
        pdTRUE,
        0u);

    portENTER_CRITICAL(&s_entropy_mux);
    shutdown_decision = ninlil_esp_idf_entropy_life_request_shutdown(
        &s_entropy_life, entropy, &can_start_disable);
    if (shutdown_decision == NINLIL_ESP_IDF_ENTROPY_SD_NOP) {
        portEXIT_CRITICAL(&s_entropy_mux);
        return;
    }
    if (shutdown_decision == NINLIL_ESP_IDF_ENTROPY_SD_CANCEL_ACQUIRE) {
        if (s_shutdown_waiter != NULL) {
            portEXIT_CRITICAL(&s_entropy_mux);
            return;
        }
        s_shutdown_waiter = current;
        portEXIT_CRITICAL(&s_entropy_mux);
        (void)ulTaskNotifyTakeIndexed(
            (UBaseType_t)NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX,
            pdTRUE,
            portMAX_DELAY);
        return;
    }

    entropy->ready = 0u;
    if (can_start_disable == 0) {
        s_shutdown_waiter = current;
        portEXIT_CRITICAL(&s_entropy_mux);
        (void)ulTaskNotifyTakeIndexed(
            (UBaseType_t)NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX,
            pdTRUE,
            portMAX_DELAY);
        portENTER_CRITICAL(&s_entropy_mux);
    }
    if (ninlil_esp_idf_entropy_life_begin_disable(
            &s_entropy_life, entropy)
        != 0) {
        portEXIT_CRITICAL(&s_entropy_mux);
        return;
    }
    portEXIT_CRITICAL(&s_entropy_mux);

    bootloader_random_disable();

    portENTER_CRITICAL(&s_entropy_mux);
    if (ninlil_esp_idf_entropy_life_finish_disable(
            &s_entropy_life, entropy, &ignored)
        == 0) {
        ninlil_esp_idf_entropy_retire_storage(entropy);
    }
    portEXIT_CRITICAL(&s_entropy_mux);
}

int ninlil_esp_idf_entropy_is_ready(const ninlil_esp_idf_entropy_t *entropy)
{
    int ready;

    if (entropy == NULL || entropy_in_isr() != 0) {
        return 0;
    }
    portENTER_CRITICAL(&s_entropy_mux);
    ready = ninlil_esp_idf_entropy_life_is_serving_owner(
        &s_entropy_life, entropy);
    portEXIT_CRITICAL(&s_entropy_mux);
    return ready;
}

const ninlil_entropy_ops_t *ninlil_esp_idf_entropy_ops(
    ninlil_esp_idf_entropy_t *entropy)
{
    const ninlil_entropy_ops_t *ops = NULL;

    if (entropy == NULL || entropy_in_isr() != 0) {
        return NULL;
    }
    portENTER_CRITICAL(&s_entropy_mux);
    if (ninlil_esp_idf_entropy_life_is_serving_owner(
            &s_entropy_life, entropy)) {
        ops = &entropy->ops;
    }
    portEXIT_CRITICAL(&s_entropy_mux);
    return ops;
}

int ninlil_esp_idf_entropy_storage_is_published(
    const ninlil_esp_idf_entropy_t *entropy)
{
    return ninlil_esp_idf_entropy_is_ready(entropy);
}
