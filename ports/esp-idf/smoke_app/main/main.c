/*
 * M3-prep smoke application.
 *
 * Proves the ninlil ESP-IDF component public headers compile and the
 * portable private library links into an ESP32-S3 firmware image.
 * Does not exercise public Runtime API bodies, storage ports, FreeRTOS
 * owner tasks, USB, Wi-Fi, radio, or hardware.
 */

#include "ninlil/platform.h"
#include "ninlil/runtime.h"
#include "ninlil/service.h"
#include "ninlil/transaction.h"
#include "ninlil/version.h"

#include "esp_log.h"

static const char *TAG = "ninlil_m3_prep";

void app_main(void)
{
    ESP_LOGI(TAG,
             "Ninlil M3-prep smoke: ABI=0x%04x storage_schema=%u",
             (unsigned)NINLIL_ABI_VERSION,
             (unsigned)NINLIL_STORAGE_SCHEMA_M1A);
    (void)sizeof(ninlil_runtime_config_t);
    (void)sizeof(ninlil_platform_ops_t);
    (void)sizeof(ninlil_submission_t);
    (void)sizeof(ninlil_service_descriptor_t);
}
