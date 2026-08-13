/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Final ESP32-S3 Wi-Fi bearer composition application.
 *
 * One runtime-selected image retains both roles:
 *   STA -> TCP client/listener -> direct mbedTLS 1.3 mTLS
 *       -> peer exporter -> durable M4 FULL
 *       -> attached exporter -> ESP Fabric packet-link.
 *
 * Provisioning comes only from NVS and serial output never contains SSIDs,
 * passphrases, PEM material, private keys, runtime IDs, or binding digests.
 * Building this image proves composition; physical AP HIL remains NOT_RUN
 * until two provisioned boards and an AP are exercised by the HIL runner.
 */
#include "wifi_adapter_v1.h"
#include "wifi_budget.h"
#include "wifi_esp_owner.h"
#include "wifi_esp_sta.h"
#include "wifi_esp_tls_mbedtls.h"
#include "wifi_esp_tls_allocator.h"
#include "wifi_hil_m4.h"
#include "wifi_hil_provision.h"

#include "r7_crypto_mbedtls.h"
#include "r7_crypto_provider.h"

#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/execution.h"
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define NINLIL_WIFI_HIL_TLS_WORKSPACE_BYTES 16384u
#define NINLIL_WIFI_HIL_ADAPTER_WORKSPACE_BYTES 24576u
#define NINLIL_WIFI_HIL_COMMAND_BYTES 96u

static const char *TAG = "wifi_hil";

/*
 * Final-ELF authority: `xtensa-esp32s3-elf-nm -S` reports this array's exact
 * target size. app_main performs a volatile read so --gc-sections retains it.
 */
const volatile uint8_t
    ninlil_wifi_esp_owner_target_size_probe[sizeof(ninlil_wifi_esp_owner_t)] = {
        0
    };
extern const uint8_t ninlil_wifi_esp_tls_target_max_align_size_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_max_align_alignment_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_r7_sha_context_size_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_r7_sha_charge_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_r7_hmac_charge_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_r7_aes_context_size_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_r7_gcm_charge_probe[];
extern const uint8_t ninlil_wifi_esp_tls_target_r7_reservation_probe[];

typedef struct wifi_hil_command {
    char text[NINLIL_WIFI_HIL_COMMAND_BYTES];
} wifi_hil_command_t;

_Alignas(max_align_t)
static uint8_t g_tls_workspace[NINLIL_WIFI_HIL_TLS_WORKSPACE_BYTES];
_Alignas(max_align_t)
static uint8_t g_sta_workspace[NINLIL_WIFI_ESP_STA_STORAGE_BYTES];
_Alignas(max_align_t)
static uint8_t g_adapter_workspace[NINLIL_WIFI_HIL_ADAPTER_WORKSPACE_BYTES];

static ninlil_wifi_hil_provision_t g_provision;
static ninlil_wifi_hil_m4_t g_m4;
static ninlil_esp_idf_clock_t g_clock;
static ninlil_esp_idf_execution_t g_execution;
static ninlil_port_esp_storage_flash_binding_t *g_storage_binding;
static const ninlil_storage_ops_t *g_storage;
static wifi_adapter_private_v1_t *g_adapter;
static const ninlil_fabric_link_descriptor_v1_t *g_descriptor;
static const ninlil_fabric_packet_link_ops_v1_t *g_link_ops;
static ninlil_fabric_packet_link_handle_t g_link_handle;
static QueueHandle_t g_command_queue;
static ninlil_wifi_hil_provision_status_t g_provision_status =
    NINLIL_WIFI_HIL_PROVISION_MISSING;
static wifi_private_adapter_status_v1_t g_create_status =
    WIFI_PRIVATE_UNAVAILABLE;
static wifi_private_adapter_status_v1_t g_last_step_status =
    WIFI_PRIVATE_UNAVAILABLE;
static uint32_t g_last_step_work;
static ninlil_r7_crypto_provider g_r7_provider;
static ninlil_wifi_esp_tls_allocator_snapshot_t g_r7_allocator;
static ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t
    g_allocator_aggregate;
static uint32_t g_r7_cotenant_ready;

static void secure_zero(void *pointer, size_t bytes)
{
    volatile uint8_t *cursor = (volatile uint8_t *)pointer;
    while (cursor != NULL && bytes != 0u) {
        *cursor++ = 0u;
        --bytes;
    }
}

/*
 * Runtime evidence, not a compile-time keepalive:
 *
 * - provider_init installs the sole allocator before any application crypto;
 * - RFC 5869 and AES-128-GCM KATs execute both allocating R7 raw mbedTLS
 *   paths under the registered R7 owner; and
 * - exact zero-outstanding/304-byte-peak state is published by STATUS.
 *
 * A linked image remains software evidence only.  These observations become
 * physical evidence only when this code executes on an ESP32-S3 and its
 * serial transcript is captured by the HIL runner.
 */
static int r7_cotenant_start(void)
{
    static const uint8_t expected_prk[32] = {
        0xacu, 0xfeu, 0xcbu, 0xc3u, 0x29u, 0x26u, 0x4du, 0x7fu,
        0xdfu, 0x1fu, 0x0bu, 0x94u, 0x28u, 0xf9u, 0xfcu, 0xd8u,
        0x93u, 0x6du, 0xa6u, 0x20u, 0x09u, 0x60u, 0xa4u, 0x22u,
        0x17u, 0x0fu, 0x3du, 0x7au, 0x97u, 0xeau, 0xedu, 0x0eu
    };
    static const uint8_t expected_okm[16] = {
        0xf3u, 0x64u, 0xe6u, 0x96u, 0x03u, 0x0cu, 0x82u, 0x43u,
        0xffu, 0x92u, 0x30u, 0x9bu, 0xe2u, 0xf5u, 0x7eu, 0x0fu
    };
    static const uint8_t expected_gcm_sealed[32] = {
        0x03u, 0x88u, 0xdau, 0xceu, 0x60u, 0xb6u, 0xa3u, 0x92u,
        0xf3u, 0x28u, 0xc2u, 0xb9u, 0x71u, 0xb2u, 0xfeu, 0x78u,
        0xabu, 0x6eu, 0x47u, 0xd4u, 0x2cu, 0xecu, 0x13u, 0xbdu,
        0xf5u, 0x3au, 0x67u, 0xb2u, 0x12u, 0x57u, 0xbdu, 0xdfu
    };
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t info[8];
    uint8_t prk[32];
    uint8_t okm[16];
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t plaintext[16];
    uint8_t sealed[32];
    uint8_t opened[16];
    size_t sealed_length = 0u;
    size_t opened_length = 0u;
    int result = 1;

    (void)memset(salt, 0x11, sizeof(salt));
    (void)memset(ikm, 0x22, sizeof(ikm));
    (void)memset(info, 0x33, sizeof(info));
    (void)memset(prk, 0, sizeof(prk));
    (void)memset(okm, 0, sizeof(okm));
    (void)memset(key, 0, sizeof(key));
    (void)memset(nonce, 0, sizeof(nonce));
    (void)memset(plaintext, 0, sizeof(plaintext));
    (void)memset(sealed, 0, sizeof(sealed));
    (void)memset(opened, 0xa5, sizeof(opened));

    if (ninlil_r7_crypto_mbedtls_provider_init(&g_r7_provider)
            != NINLIL_R7_CRYPTO_OK
        || ninlil_r7_crypto_hkdf_extract_sha256(
               &g_r7_provider,
               salt,
               sizeof(salt),
               ikm,
               sizeof(ikm),
               prk)
            != NINLIL_R7_CRYPTO_OK
        || memcmp(prk, expected_prk, sizeof(prk)) != 0
        || ninlil_r7_crypto_hkdf_expand_sha256(
               &g_r7_provider,
               prk,
               info,
               sizeof(info),
               okm,
               sizeof(okm))
            != NINLIL_R7_CRYPTO_OK
        || memcmp(okm, expected_okm, sizeof(okm)) != 0
        || ninlil_r7_crypto_aes128_gcm_seal(
               &g_r7_provider,
               key,
               nonce,
               NULL,
               0u,
               plaintext,
               sizeof(plaintext),
               sealed,
               sizeof(sealed),
               &sealed_length)
            != NINLIL_R7_CRYPTO_OK
        || sealed_length != sizeof(sealed)
        || memcmp(sealed, expected_gcm_sealed, sizeof(sealed)) != 0
        || ninlil_r7_crypto_aes128_gcm_open(
               &g_r7_provider,
               key,
               nonce,
               NULL,
               0u,
               sealed,
               sizeof(sealed),
               opened,
               sizeof(opened),
               &opened_length)
            != NINLIL_R7_CRYPTO_OK
        || opened_length != sizeof(opened)
        || memcmp(opened, plaintext, sizeof(opened)) != 0
        || ninlil_wifi_esp_tls_allocator_other_snapshot(
               NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1,
               &g_r7_allocator)
            != NINLIL_WIFI_OK
        || g_r7_allocator.current_bytes != 0u
        || g_r7_allocator.outstanding_allocations != 0u
        || g_r7_allocator.peak_bytes
            != NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET
        || ninlil_wifi_esp_tls_allocator_aggregate_snapshot(
               &g_allocator_aggregate)
            != NINLIL_WIFI_OK
        || g_allocator_aggregate.active_other_registered != 1u
        || g_allocator_aggregate.other_registered_reserved_bytes
            != NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET
        || g_allocator_aggregate.fatal != 0u) {
        goto cleanup;
    }
    g_r7_cotenant_ready = 1u;
    result = 0;

cleanup:
    secure_zero(prk, sizeof(prk));
    secure_zero(okm, sizeof(okm));
    secure_zero(ikm, sizeof(ikm));
    secure_zero(key, sizeof(key));
    secure_zero(sealed, sizeof(sealed));
    secure_zero(opened, sizeof(opened));
    return result;
}

static void fill_boot_epoch(ninlil_id128_t *epoch)
{
    if (epoch == NULL) {
        return;
    }
    do {
        esp_fill_random(epoch->bytes, sizeof(epoch->bytes));
    } while (memcmp(epoch->bytes, (uint8_t[16]){0}, 16u) == 0);
}

static int runtime_start(void)
{
    ninlil_esp_idf_clock_config_t clock_config;
    ninlil_port_esp_storage_config_t storage_config;
    const ninlil_clock_ops_t *clock_ops;
    const ninlil_execution_ops_t *execution_ops;
    const wifi_m4_attachment_carrier_ops_v1_t *m4_ops;
    uint32_t required_bytes = 0u;
    uint32_t required_alignment = 0u;

    /*
     * Must precede provision_load(): that path performs SHA-256 and the sole
     * mbedTLS allocator must already be installed before application crypto.
     */
    if (r7_cotenant_start() != 0) {
        g_create_status = WIFI_PRIVATE_UNAVAILABLE;
        return 1;
    }
    g_provision_status = ninlil_wifi_hil_provision_load(
        &g_provision,
        g_tls_workspace,
        (uint32_t)sizeof(g_tls_workspace),
        g_sta_workspace,
        (uint32_t)sizeof(g_sta_workspace));
    if (g_provision_status != NINLIL_WIFI_HIL_PROVISION_OK) {
        return 1;
    }
    if (ninlil_wifi_esp_tls_sizeof() > sizeof(g_tls_workspace)
        || ninlil_wifi_esp_sta_sizeof() > sizeof(g_sta_workspace)
        || ninlil_esp_idf_execution_init(&g_execution) != 0) {
        g_create_status = WIFI_PRIVATE_CAPACITY;
        return 1;
    }
    (void)memset(&clock_config, 0, sizeof(clock_config));
    clock_config.abi_version = NINLIL_ABI_VERSION;
    clock_config.struct_size = (uint16_t)sizeof(clock_config);
    fill_boot_epoch(&clock_config.boot_epoch_id);
    if (ninlil_esp_idf_clock_init(&g_clock, &clock_config) != 0) {
        g_create_status = WIFI_PRIVATE_UNAVAILABLE;
        return 1;
    }
    clock_ops = ninlil_esp_idf_clock_ops(&g_clock);
    execution_ops = ninlil_esp_idf_execution_ops(&g_execution);
    if (clock_ops == NULL || execution_ops == NULL) {
        g_create_status = WIFI_PRIVATE_UNAVAILABLE;
        return 1;
    }
    ninlil_port_esp_storage_config_production(&storage_config);
    if (ninlil_port_esp_storage_flash_bind(
            "ninlil_st",
            &storage_config,
            &g_storage_binding,
            &g_storage)
            != 0
        || g_storage_binding == NULL || g_storage == NULL) {
        g_create_status = WIFI_PRIVATE_STORAGE;
        return 1;
    }
    if (ninlil_wifi_hil_m4_init(&g_m4, g_storage, &g_provision) != 0) {
        g_create_status = WIFI_PRIVATE_UNAVAILABLE;
        return 1;
    }
    m4_ops = ninlil_wifi_hil_m4_ops(&g_m4);
    ninlil_wifi_hil_provision_bind_runtime(
        &g_provision, g_storage, clock_ops, execution_ops, m4_ops);
    if (wifi_workspace_required_v1(
            WIFI_ADAPTER_KIND_ESP32S3_STA_TCP,
            &required_bytes,
            &required_alignment)
            != WIFI_PRIVATE_OK
        || required_bytes > sizeof(g_adapter_workspace)
        || required_alignment > _Alignof(max_align_t)
        || ((uintptr_t)g_adapter_workspace % required_alignment) != 0u) {
        g_create_status = WIFI_PRIVATE_CAPACITY;
        return 1;
    }
    g_create_status = wifi_create_v1(
        &g_provision.adapter_config,
        g_adapter_workspace,
        (uint32_t)sizeof(g_adapter_workspace),
        &g_adapter);
    /*
     * mbedTLS parsed CA/certificate/key during create. Do not retain borrowed
     * PEM bytes or pointers in the application after that boundary.
     */
    ninlil_wifi_hil_provision_wipe_parsed_pems(&g_provision);
    if (g_create_status != WIFI_PRIVATE_OK || g_adapter == NULL) {
        g_adapter = NULL;
        return 1;
    }
    g_last_step_status = WIFI_PRIVATE_OK;
    return 0;
}

static void refresh_fabric_surface(void)
{
    if (g_adapter == NULL || g_descriptor != NULL || g_link_ops != NULL) {
        return;
    }
    if (wifi_packet_link_descriptor_v1(g_adapter, &g_descriptor)
            != WIFI_PRIVATE_OK
        || g_descriptor == NULL
        || wifi_packet_link_ops_v1(g_adapter, &g_link_ops)
            != WIFI_PRIVATE_OK
        || g_link_ops == NULL) {
        g_descriptor = NULL;
        g_link_ops = NULL;
    }
}

static void print_status(void)
{
    wifi_operational_state_v1_t state = WIFI_OPERATIONAL_DISABLED;
    uint32_t reason = WIFI_REASON_NONE;
    uint64_t epoch = 0u;
    wifi_private_adapter_status_v1_t state_status =
        WIFI_PRIVATE_UNAVAILABLE;
    if (g_r7_cotenant_ready != 0u) {
        (void)ninlil_wifi_esp_tls_allocator_other_snapshot(
            NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1,
            &g_r7_allocator);
        (void)ninlil_wifi_esp_tls_allocator_aggregate_snapshot(
            &g_allocator_aggregate);
    }
    if (g_adapter != NULL) {
        state_status =
            wifi_state_v1(g_adapter, &state, &reason, &epoch);
    }
    (void)printf(
        "OK STATUS provision=%u create=%u step=%u state_status=%u "
        "state=%u reason=%u epoch=%llu work=%u role=%u "
        "fabric_descriptor=%s packet_link=%s "
        "r7_cotenant=%s r7_peak=%u r7_outstanding=%u "
        "allocator_fatal=%u allocator_trace=%u/%u "
        "allocator_trace_dropped=%u physical_ap_hil=NOT_RUN\n",
        (unsigned)g_provision_status,
        (unsigned)g_create_status,
        (unsigned)g_last_step_status,
        (unsigned)state_status,
        (unsigned)state,
        (unsigned)reason,
        (unsigned long long)epoch,
        (unsigned)g_last_step_work,
        (unsigned)g_provision.adapter_config.tls_role,
        g_descriptor == NULL ? "unavailable" : "ready",
        g_link_ops == NULL ? "unavailable" : "ready",
        g_r7_cotenant_ready == 0u ? "unavailable" : "ready",
        (unsigned)g_r7_allocator.peak_bytes,
        (unsigned)g_r7_allocator.outstanding_allocations,
        (unsigned)g_allocator_aggregate.fatal,
        (unsigned)g_allocator_aggregate.trace_count,
        (unsigned)NINLIL_WIFI_ESP_TLS_ALLOC_TRACE_CAPACITY,
        (unsigned)g_allocator_aggregate.trace_dropped);
}

static void print_r7_allocator_trace(void)
{
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t aggregate;
    ninlil_wifi_esp_tls_allocator_trace_record_t record;
    ninlil_wifi_status_t status;
    uint32_t index;
    status = ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate);
    if (status != NINLIL_WIFI_OK && status != NINLIL_WIFI_CORRUPT) {
        (void)printf("ERR r7_allocator_trace_unavailable\n");
        return;
    }
    (void)printf(
        "OK R7_ALLOC_TRACE count=%u dropped=%u fatal=%u "
        "scope=runtime_observation\n",
        (unsigned)aggregate.trace_count,
        (unsigned)aggregate.trace_dropped,
        (unsigned)aggregate.fatal);
    for (index = 0u; index < aggregate.trace_count; ++index) {
        if (ninlil_wifi_esp_tls_allocator_trace_at(index, &record)
            != NINLIL_WIFI_OK) {
            (void)printf("ERR r7_allocator_trace_read index=%u\n",
                         (unsigned)index);
            return;
        }
        /*
         * Deliberately metadata-only: never print pointers, keys, input/output
         * bytes, credentials, or peer identifiers.
         */
        (void)printf(
            "TRACE sequence=%u event=%u owner=%u component=%08x "
            "requested=%u current=%u outstanding=%u status=%u\n",
            (unsigned)record.sequence,
            (unsigned)record.event,
            (unsigned)record.owner,
            (unsigned)record.component_id,
            (unsigned)record.requested_bytes,
            (unsigned)record.current_bytes,
            (unsigned)record.outstanding_allocations,
            (unsigned)record.status);
    }
    (void)printf("OK R7_ALLOC_TRACE_END\n");
}

static void handle_command(char *line)
{
    size_t length = strlen(line);
    while (length > 0u
        && (line[length - 1u] == '\n' || line[length - 1u] == '\r')) {
        line[--length] = '\0';
    }
    if (length == 0u) {
        return;
    }
    if (strcmp(line, "PING") == 0) {
        (void)printf("OK PONG\n");
    } else if (strcmp(line, "STATUS") == 0) {
        refresh_fabric_surface();
        print_status();
    } else if (strcmp(line, "R7_ALLOC_TRACE") == 0) {
        print_r7_allocator_trace();
    } else if (strcmp(line, "BUDGET") == 0) {
        (void)printf(
            "OK BUDGET owner_target=%u owner_contract=%u owner_measured=%u "
            "tls_object=%u adapter_workspace=%u\n",
            (unsigned)sizeof(ninlil_wifi_esp_owner_t),
            (unsigned)NINLIL_WIFI_ESP_SESSION_WORKSPACE_BYTES,
            (unsigned)ninlil_wifi_esp_owner_measured_workspace_bytes(),
            (unsigned)ninlil_wifi_esp_tls_sizeof(),
            (unsigned)sizeof(g_adapter_workspace));
    } else if (strcmp(line, "FABRIC_OPEN") == 0) {
        refresh_fabric_surface();
        if (g_link_ops == NULL || g_link_handle != NULL
            || g_link_ops->open(g_link_ops->user, &g_link_handle)
                != NINLIL_FABRIC_LINK_OK
            || g_link_handle == NULL) {
            (void)printf("ERR fabric_open_unavailable\n");
        } else {
            (void)printf("OK FABRIC_OPEN\n");
        }
    } else if (strcmp(line, "FABRIC_CLOSE") == 0) {
        if (g_link_ops == NULL || g_link_handle == NULL) {
            (void)printf("ERR fabric_not_open\n");
        } else {
            g_link_ops->close(g_link_ops->user, g_link_handle);
            g_link_handle = NULL;
            (void)printf("OK FABRIC_CLOSE\n");
        }
    } else if (strcmp(line, "REBOOT") == 0) {
        (void)printf("OK REBOOT\n");
        (void)fflush(stdout);
        esp_restart();
    } else {
        /*
         * Deliberately no serial SET/PROVISION command: it would expose Wi-Fi
         * and private-key material to terminal history and HIL logs.
         */
        (void)printf("ERR unknown_or_secret_command_forbidden\n");
    }
    (void)fflush(stdout);
}

static void serial_reader_task(void *argument)
{
    wifi_hil_command_t command;
    (void)argument;
    while (fgets(command.text, (int)sizeof(command.text), stdin) != NULL) {
        if (xQueueSend(
                g_command_queue, &command, pdMS_TO_TICKS(1000u))
            != pdPASS) {
            (void)printf("ERR command_queue_full\n");
            (void)fflush(stdout);
        }
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    wifi_hil_command_t command;
    esp_err_t nvs_status;
    volatile uint8_t owner_size_probe_read =
        ninlil_wifi_esp_owner_target_size_probe[
            sizeof(ninlil_wifi_esp_owner_target_size_probe) - 1u];
    volatile uint8_t r7_target_probe_read =
        ninlil_wifi_esp_tls_target_max_align_size_probe[0]
        ^ ninlil_wifi_esp_tls_target_max_align_alignment_probe[0]
        ^ ninlil_wifi_esp_tls_target_r7_sha_context_size_probe[0]
        ^ ninlil_wifi_esp_tls_target_r7_sha_charge_probe[0]
        ^ ninlil_wifi_esp_tls_target_r7_hmac_charge_probe[0]
        ^ ninlil_wifi_esp_tls_target_r7_aes_context_size_probe[0]
        ^ ninlil_wifi_esp_tls_target_r7_gcm_charge_probe[0]
        ^ ninlil_wifi_esp_tls_target_r7_reservation_probe[0];
    (void)owner_size_probe_read;
    (void)r7_target_probe_read;
    (void)setvbuf(stdin, NULL, _IONBF, 0);
    (void)setvbuf(stdout, NULL, _IONBF, 0);

    /*
     * Never erase NVS automatically: that would destroy factory credentials.
     * Operators must repair/re-provision an incompatible or full partition.
     */
    nvs_status = nvs_flash_init();
    if (nvs_status != ESP_OK) {
        ESP_LOGE(TAG, "nvs init failed code=%d", (int)nvs_status);
        (void)printf(
            "READY wifi_hil_app provision=unreadable "
            "physical_ap_hil=NOT_RUN\n");
        return;
    }
    (void)runtime_start();
    g_command_queue = xQueueCreate(4u, sizeof(wifi_hil_command_t));
    if (g_command_queue == NULL
        || xTaskCreate(
               serial_reader_task,
               "wifi_hil_serial",
               4096u,
               NULL,
               tskIDLE_PRIORITY + 1u,
               NULL)
            != pdPASS) {
        ESP_LOGE(TAG, "serial command task initialization failed");
        return;
    }
    (void)printf(
        "READY wifi_hil_app provision=%u create=%u "
        "r7_cotenant=%s physical_ap_hil=NOT_RUN\n",
        (unsigned)g_provision_status,
        (unsigned)g_create_status,
        g_r7_cotenant_ready == 0u ? "unavailable" : "ready");
    (void)fflush(stdout);

    for (;;) {
        if (g_adapter != NULL) {
            g_last_step_work = 0u;
            g_last_step_status =
                wifi_step_v1(g_adapter, 16u, &g_last_step_work);
            if (g_last_step_status == WIFI_PRIVATE_OK) {
                refresh_fabric_surface();
            }
        }
        if (xQueueReceive(
                g_command_queue, &command, pdMS_TO_TICKS(20u))
            == pdPASS) {
            handle_command(command.text);
        }
    }
}
