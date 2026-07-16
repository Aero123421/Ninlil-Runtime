/*
 * M3-basic smoke application.
 *
 * Proves type/link + minimal contracts for clock / entropy / execution:
 * - clock: staged config, side-effect-free one-shot re-init rejection
 * - entropy: exclusive BOOTLOADER_RNG owner + fill path in source
 * - execution: task-context identity (ISR fail-closed is host/doc covered)
 *
 * CI evidence for this app is compile/link of the esp32s3 image only
 * (idf.py build). Device execution / HIL is not claimed by workflow.
 *
 * Boot epoch: fresh non-zero id after reboot is caller responsibility.
 * Entropy: process singleton; shutdown before RF/ADC (ESP-IDF v5.5.3).
 */

#include "ninlil/platform.h"
#include "ninlil/runtime.h"
#include "ninlil/service.h"
#include "ninlil/transaction.h"
#include "ninlil/version.h"

#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/entropy.h"
#include "ninlil_esp_idf/execution.h"

#include "esp_log.h"

#include <string.h>

static const char *TAG = "ninlil_m3_basic";

static ninlil_esp_idf_clock_t s_clock;
static ninlil_esp_idf_entropy_t s_entropy;
static ninlil_esp_idf_execution_t s_execution;

static ninlil_time_sample_t smoke_time_sample(void)
{
    ninlil_time_sample_t sample;

    (void)memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    return sample;
}

void app_main(void)
{
    ninlil_esp_idf_clock_config_t clock_config;
    ninlil_esp_idf_clock_config_t bad_clock;
    ninlil_esp_idf_entropy_config_t entropy_config;
    const ninlil_clock_ops_t *clock_ops;
    const ninlil_entropy_ops_t *entropy_ops;
    const ninlil_execution_ops_t *execution_ops;
    ninlil_time_sample_t sample;
    uint8_t entropy_bytes[16];
    uint64_t context_id;
    ninlil_port_status_t status;

    ESP_LOGI(TAG,
             "Ninlil M3-basic smoke: ABI=0x%04x storage_schema=%u",
             (unsigned)NINLIL_ABI_VERSION,
             (unsigned)NINLIL_STORAGE_SCHEMA_M1A);
    (void)sizeof(ninlil_runtime_config_t);
    (void)sizeof(ninlil_platform_ops_t);

    (void)memset(&clock_config, 0, sizeof(clock_config));
    clock_config.abi_version = NINLIL_ABI_VERSION;
    clock_config.struct_size = (uint16_t)sizeof(clock_config);
    /*
     * Caller-supplied non-zero boot epoch for *this* boot only.
     * Production must regenerate after reboot; adapter does not auto-rotate.
     * Reusing the same epoch across reboot does not re-establish TRUSTED
     * cross-reboot continuity (docs/20 §4.2).
     */
    clock_config.boot_epoch_id.bytes[0] = 0xe5u;
    clock_config.boot_epoch_id.bytes[15] = 0x01u;

    (void)memset(&entropy_config, 0, sizeof(entropy_config));
    entropy_config.abi_version = NINLIL_ABI_VERSION;
    entropy_config.struct_size = (uint16_t)sizeof(entropy_config);
    /*
     * Explicit ready policy: arm bootloader hardware RNG before any
     * non-zero fill. Smoke must not claim OK without ready.
     */
    entropy_config.policy = NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG;

    if (ninlil_esp_idf_clock_init(&s_clock, &clock_config) != 0
        || ninlil_esp_idf_entropy_init(&s_entropy, &entropy_config) != 0
        || ninlil_esp_idf_execution_init(&s_execution) != 0) {
        ESP_LOGE(TAG, "adapter init failed");
        return;
    }
    if (!ninlil_esp_idf_entropy_is_ready(&s_entropy)) {
        ESP_LOGE(TAG, "entropy must be ready after policy init");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }

    clock_ops = ninlil_esp_idf_clock_ops(&s_clock);
    entropy_ops = ninlil_esp_idf_entropy_ops(&s_entropy);
    execution_ops = ninlil_esp_idf_execution_ops(&s_execution);
    if (clock_ops == NULL || clock_ops->now == NULL
        || entropy_ops == NULL || entropy_ops->fill == NULL
        || execution_ops == NULL
        || execution_ops->current_context_id == NULL) {
        ESP_LOGE(TAG, "adapter ops missing");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }

    (void)memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    status = clock_ops->now(clock_ops->user, &sample);
    ESP_LOGI(TAG,
             "clock.now status=%u now_ms=%llu trust=%u epoch0=%02x",
             (unsigned)status,
             (unsigned long long)sample.now_ms,
             (unsigned)sample.trust,
             (unsigned)sample.clock_epoch_id.bytes[0]);

    (void)memset(entropy_bytes, 0, sizeof(entropy_bytes));
    status = entropy_ops->fill(
        entropy_ops->user, entropy_bytes, (uint32_t)sizeof(entropy_bytes));
    if (status != NINLIL_PORT_OK) {
        ESP_LOGE(TAG, "entropy.fill after ready should OK, got %u",
            (unsigned)status);
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }
    ESP_LOGI(TAG,
             "entropy.fill status=%u first=%02x last=%02x ready=1",
             (unsigned)status,
             (unsigned)entropy_bytes[0],
             (unsigned)entropy_bytes[15]);

    /*
     * Task context (app_main): identity must be resolvable for confinement.
     * ISR path returns 0 (xPortInIsrContext) — host pure tests cover that
     * branch; do not call this from an ISR and expect owner identity.
     */
    context_id = execution_ops->current_context_id(execution_ops->user);
    if (context_id == 0u) {
        ESP_LOGE(TAG, "task-context context_id should be non-zero");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }
    ESP_LOGI(TAG,
             "execution.current_context_id=0x%llx (task context)",
             (unsigned long long)context_id);

    status = clock_ops->now(clock_ops->user, NULL);
    if (status != NINLIL_PORT_PERMANENT_FAILURE) {
        ESP_LOGE(TAG, "clock null out should permanent-fail");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }
    status = entropy_ops->fill(entropy_ops->user, NULL, 1u);
    if (status != NINLIL_PORT_PERMANENT_FAILURE) {
        ESP_LOGE(TAG, "entropy null out should permanent-fail");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }
    status = entropy_ops->fill(entropy_ops->user, NULL, 0u);
    if (status != NINLIL_PORT_OK) {
        ESP_LOGE(TAG, "entropy length 0 should OK");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }

    /* Invalid re-init leaves the prior one-shot state and ops unchanged. */
    (void)memset(&bad_clock, 0, sizeof(bad_clock));
    bad_clock.abi_version = NINLIL_ABI_VERSION;
    bad_clock.struct_size = (uint16_t)sizeof(bad_clock);
    if (ninlil_esp_idf_clock_init(&s_clock, &bad_clock) == 0) {
        ESP_LOGE(TAG, "invalid clock re-init should fail");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }
    if (ninlil_esp_idf_clock_ops(&s_clock) == NULL) {
        ESP_LOGE(TAG, "invalid re-init must not clear live clock state");
        ninlil_esp_idf_entropy_shutdown(&s_entropy);
        return;
    }

    ninlil_esp_idf_entropy_shutdown(&s_entropy);
    ninlil_esp_idf_clock_shutdown(&s_clock);
    ninlil_esp_idf_execution_shutdown(&s_execution);
    if (ninlil_esp_idf_entropy_is_ready(&s_entropy)
        || ninlil_esp_idf_entropy_ops(&s_entropy) != NULL) {
        ESP_LOGE(TAG, "entropy shutdown must retire readiness/publication");
        return;
    }
    sample = smoke_time_sample();
    if (clock_ops->now(clock_ops->user, &sample)
            != NINLIL_PORT_PERMANENT_FAILURE
        || entropy_ops->fill(entropy_ops->user, entropy_bytes, 1u)
            != NINLIL_PORT_PERMANENT_FAILURE
        || execution_ops->current_context_id(execution_ops->user) != 0u) {
        ESP_LOGE(TAG, "retained immutable ops must fail closed after shutdown");
        return;
    }

    ESP_LOGI(TAG,
             "M3-basic adapter contracts exercised "
             "(one-shot immutable ops + boot-global entropy + task context)");
}
