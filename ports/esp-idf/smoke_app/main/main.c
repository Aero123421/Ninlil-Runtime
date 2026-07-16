/*
 * Combined owner/cell + durable-storage self-test source.
 * Real ISR: esp_timer ESP_TIMER_ISR (requires SUPPORTS_ISR_DISPATCH_METHOD).
 * Storage: flash bind + FULL → COMMIT_UNKNOWN (ESP_UNPROVEN).
 * Compile/link ≠ HIL PASS / dual-core race PASS / physical power-cut HIL.
 * Device: idf.py flash monitor.
 */

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include "ninlil_esp_idf/cell_agent_storage.h"
#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/entropy.h"
#include "ninlil_esp_idf/execution.h"
#include "ninlil_esp_idf/loopback_tx_permit.h"
#include "ninlil_esp_idf/owner_task_storage.h"
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include <string.h>

static const char *TAG = "ninlil_m3_owner_qa";

static ninlil_esp_idf_clock_t s_clock;
static ninlil_esp_idf_entropy_t s_entropy;
static ninlil_esp_idf_execution_t s_execution;
static ninlil_esp_idf_loopback_tx_permit_t s_loopback;
static ninlil_esp_idf_cell_agent_t s_agent;

/*
 * Standalone owner forward-extension fixture for smoke.
 * Must NOT live on app_main stack: owner_task_t embeds FreeRTOS stack+TCB
 * (~4KiB+), which alone exceeds CONFIG_ESP_MAIN_TASK_STACK_SIZE (3584 on
 * official v5.5.3). BSS placement uses the type's natural alignment
 * (StackType_t / StaticTask_t). Zero before init only — after shutdown the
 * retired owner state is retained as lifecycle evidence (no full memset).
 */
typedef struct {
    ninlil_esp_idf_owner_task_config_t known;
    uint8_t tail[16];
} smoke_ext_owner_cfg_t;

static ninlil_esp_idf_owner_task_t s_standalone_owner;
static smoke_ext_owner_cfg_t s_ext_owner_cfg;

static EventGroupHandle_t s_ev;
#define EV_PROD_DONE BIT0

static ninlil_esp_idf_owner_task_t *s_isr_owner;
static esp_timer_handle_t s_isr_timer;
static portMUX_TYPE s_isr_ctr_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_isr_ok;
static uint32_t s_isr_fail;
static uint32_t s_prod_ok;
static uint32_t s_prod_full;


/* Storage self-test: production bind path; FULL stays ESP_UNPROVEN/COMMIT_UNKNOWN.
 * Large media/workspace is binder-owned (not app_main stack). Keep locals small.
 */
static int smoke_storage_commit_unknown(void)
{
    ninlil_port_esp_storage_flash_binding_t *binding = NULL;
    ninlil_port_esp_storage_config_t config;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t ns[] = {'s', 'm', 'k'};
    static const uint8_t key[] = {'k'};
    static const uint8_t value[] = {'v'};
    ninlil_bytes_view_t ns_view = {ns, (uint32_t)sizeof(ns)};
    ninlil_bytes_view_t key_view = {key, (uint32_t)sizeof(key)};
    ninlil_bytes_view_t value_view = {value, (uint32_t)sizeof(value)};
    ninlil_storage_status_t commit_status;
    int result = -1;

    ninlil_port_esp_storage_config_production(&config);
    if (ninlil_port_esp_storage_flash_bind(
            "ninlil_st", &config, &binding, &ops)
        != 0) {
        ESP_LOGE(TAG, "storage flash bind failed");
        goto cleanup;
    }
    if (ops == NULL
        || ops->open(
               ops->user,
               ns_view,
               NINLIL_STORAGE_SCHEMA_M1A,
               &handle)
            != NINLIL_STORAGE_OK
        || ops->begin(
               ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            != NINLIL_STORAGE_OK
        || ops->put(ops->user, txn, key_view, value_view)
            != NINLIL_STORAGE_OK) {
        ESP_LOGE(TAG, "storage open/begin/put failed");
        goto unbind;
    }
    commit_status =
        ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
    txn = NULL;
    if (commit_status != NINLIL_STORAGE_COMMIT_UNKNOWN) {
        ESP_LOGE(TAG,
            "ESP_UNPROVEN FULL must be COMMIT_UNKNOWN, got %u",
            (unsigned)commit_status);
        goto unbind;
    }
    ESP_LOGI(TAG, "storage FULL correctly remains ESP_UNPROVEN");
    result = 0;

unbind:
    if (txn != NULL) {
        (void)ops->rollback(ops->user, txn);
    }
    if (handle != NULL) {
        ops->close(ops->user, handle);
    }
    ninlil_port_esp_storage_flash_unbind(binding);
cleanup:
    return result;
}

static void IRAM_ATTR isr_timer_cb(void *arg)
{
    ninlil_esp_idf_owner_status_t st;
    (void)arg;
    if (s_isr_owner == NULL) {
        return;
    }
    st = ninlil_esp_idf_owner_task_post_tick_from_isr(s_isr_owner);
    portENTER_CRITICAL_ISR(&s_isr_ctr_mux);
    if (st == NINLIL_ESP_IDF_OWNER_OK) {
        s_isr_ok++;
    } else {
        s_isr_fail++;
    }
    portEXIT_CRITICAL_ISR(&s_isr_ctr_mux);
}

static void producer_task(void *arg)
{
    ninlil_esp_idf_owner_task_t *o = (ninlil_esp_idf_owner_task_t *)arg;
    int i;
    ninlil_esp_idf_owner_status_t st;

    for (i = 0; i < 24; ++i) {
        st = ninlil_esp_idf_owner_task_post_tick(o);
        if (st == NINLIL_ESP_IDF_OWNER_OK) {
            s_prod_ok++;
        } else if (st == NINLIL_ESP_IDF_OWNER_MAILBOX_FULL) {
            s_prod_full++;
        }
        vTaskDelay(1);
    }
    (void)xEventGroupSetBits(s_ev, EV_PROD_DONE);
    vTaskDelete(NULL);
}

static void fill_req(ninlil_tx_request_t *r, ninlil_time_sample_t *n)
{
    (void)memset(r, 0, sizeof(*r));
    r->abi_version = NINLIL_ABI_VERSION;
    r->struct_size = (uint16_t)sizeof(*r);
    r->transaction_id.bytes[0] = 1u;
    r->attempt_id.bytes[0] = 2u;
    r->message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    r->logical_bytes = 8u;
    r->content_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memset(n, 0, sizeof(*n));
    n->abi_version = NINLIL_ABI_VERSION;
    n->struct_size = (uint16_t)sizeof(*n);
    n->clock_epoch_id.bytes[0] = 3u;
    n->now_ms = 20u;
    n->trust = NINLIL_CLOCK_TRUSTED;
}

static void smoke_cleanup_basic(void)
{
    ninlil_esp_idf_entropy_shutdown(&s_entropy);
    ninlil_esp_idf_clock_shutdown(&s_clock);
    ninlil_esp_idf_execution_shutdown(&s_execution);
    if (s_ev != NULL) {
        vEventGroupDelete(s_ev);
        s_ev = NULL;
    }
}

void app_main(void)
{
    ninlil_esp_idf_clock_config_t ccfg;
    ninlil_esp_idf_entropy_config_t ecfg;
    ninlil_esp_idf_loopback_tx_permit_config_t lcfg;
    ninlil_esp_idf_cell_agent_config_t acfg;
    ninlil_esp_idf_cell_assignment_t asg;
    ninlil_esp_idf_owner_snapshot_t snap;
    ninlil_esp_idf_tx_gate_lease_t lease_a;
    ninlil_esp_idf_tx_gate_lease_t lease_b;
    ninlil_tx_request_t req;
    ninlil_time_sample_t now;
    ninlil_tx_permit_t permit;
    const ninlil_tx_gate_ops_t *tx;
    ninlil_esp_idf_owner_status_t st;
    esp_timer_create_args_t targs;
    TaskHandle_t prod = NULL;
    EventBits_t bits;
    int fail = 0;
    int i;
    int j;

    s_ev = xEventGroupCreate();
    if (s_ev == NULL) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=event_group_null");
        return;
    }
    ESP_LOGI(TAG, "sizeof(owner)=%u stack_bytes=%u max_leases=%u",
        (unsigned)sizeof(ninlil_esp_idf_owner_task_t),
        (unsigned)NINLIL_ESP_IDF_OWNER_TASK_STACK_BYTES,
        (unsigned)NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES);

    (void)memset(&ccfg, 0, sizeof(ccfg));
    ccfg.abi_version = NINLIL_ABI_VERSION;
    ccfg.struct_size = (uint16_t)sizeof(ccfg);
    ccfg.boot_epoch_id.bytes[0] = 0xe5u;
    (void)memset(&ecfg, 0, sizeof(ecfg));
    ecfg.abi_version = NINLIL_ABI_VERSION;
    ecfg.struct_size = (uint16_t)sizeof(ecfg);
    ecfg.policy = NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG;
    if (ninlil_esp_idf_clock_init(&s_clock, &ccfg) != 0
        || ninlil_esp_idf_entropy_init(&s_entropy, &ecfg) != 0
        || ninlil_esp_idf_execution_init(&s_execution) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=basic_adapter_init");
        smoke_cleanup_basic();
        return;
    }

    /* invalid priority must fail init */
    (void)memset(&s_agent, 0, sizeof(s_agent));
    (void)memset(&acfg, 0, sizeof(acfg));
    acfg.abi_version = NINLIL_ABI_VERSION;
    acfg.struct_size = (uint16_t)sizeof(acfg);
    acfg.owner.abi_version = NINLIL_ABI_VERSION;
    acfg.owner.struct_size = (uint16_t)sizeof(acfg.owner);
    acfg.owner.task_priority = 0xffffu;
    if (ninlil_esp_idf_cell_agent_init(&s_agent, &acfg) == 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=invalid_priority_accepted");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        smoke_cleanup_basic();
        return;
    }

    (void)memset(&s_loopback, 0, sizeof(s_loopback));
    (void)memset(&lcfg, 0, sizeof(lcfg));
    lcfg.abi_version = NINLIL_ABI_VERSION;
    lcfg.struct_size = (uint16_t)sizeof(lcfg);
    lcfg.environment = NINLIL_ENV_TEST;
    lcfg.loopback_enabled = 1u;
    if (ninlil_esp_idf_loopback_tx_permit_init(&s_loopback, &lcfg) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_init");
        smoke_cleanup_basic();
        return;
    }
    tx = ninlil_esp_idf_loopback_tx_permit_ops(&s_loopback);
    if (tx == NULL) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_ops_null");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    fill_req(&req, &now);
    req.logical_bytes = 0u;
    if (tx->acquire(tx->user, &req, &now, &permit) != NINLIL_TX_GATE_DENIED) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_zero_bytes_not_denied");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    fill_req(&req, &now);
    if (tx->acquire(tx->user, &req, &now, &permit) != NINLIL_TX_GATE_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_acquire");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback) == 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_shutdown_while_live");
        tx->release_unused(tx->user, &permit);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    tx->release_unused(tx->user, &permit);
    if (ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_shutdown");
        smoke_cleanup_basic();
        return;
    }
    (void)memset(&s_loopback, 0, sizeof(s_loopback));
    if (ninlil_esp_idf_loopback_tx_permit_init(&s_loopback, &lcfg) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_reinit");
        smoke_cleanup_basic();
        return;
    }
    tx = ninlil_esp_idf_loopback_tx_permit_ops(&s_loopback);
    if (tx == NULL) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_ops_null_reinit");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }

    /*
     * Standalone owner_task_init with forward-extended config (declared
     * struct_size > known sizeof). Exercises production owner_config_stage
     * path on target, not a generic helper-only host probe.
     * Storage/fixture are file-scope BSS (not app_main locals) — see
     * s_standalone_owner / s_ext_owner_cfg above.
     */
    (void)memset(&s_standalone_owner, 0, sizeof(s_standalone_owner));
    (void)memset(&s_ext_owner_cfg, 0, sizeof(s_ext_owner_cfg));
    s_ext_owner_cfg.known.abi_version = NINLIL_ABI_VERSION;
    s_ext_owner_cfg.known.struct_size = (uint16_t)sizeof(s_ext_owner_cfg);
    s_ext_owner_cfg.known.task_priority = 5u;
    (void)memset(s_ext_owner_cfg.tail, 0x5Au, sizeof(s_ext_owner_cfg.tail));
    if (ninlil_esp_idf_owner_task_init(
            &s_standalone_owner,
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)
                &s_ext_owner_cfg)
        != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=owner_init_forward_ext");
        /* Keep BSS evidence; do not wipe failed/partial owner state. */
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_owner_task_shutdown(&s_standalone_owner)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=owner_shutdown_forward_ext");
        /* Retain retired/partial owner for post-mortem; no full memset. */
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    /* Intentionally keep retired s_standalone_owner / s_ext_owner_cfg state. */

    (void)memset(&s_agent, 0, sizeof(s_agent));
    (void)memset(&acfg, 0, sizeof(acfg));
    acfg.abi_version = NINLIL_ABI_VERSION;
    acfg.struct_size = (uint16_t)sizeof(acfg);
    acfg.owner.abi_version = NINLIL_ABI_VERSION;
    acfg.owner.struct_size = (uint16_t)sizeof(acfg.owner);
    acfg.owner.task_priority = 5u;
    acfg.tx_gate = tx;
    if (ninlil_esp_idf_cell_agent_init(&s_agent, &acfg) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=cell_agent_init");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }

    /*
     * Target direct backend evidence (not host pure substitute):
     * 2 leases held → get_snapshot borrowers=2; shutdown BUSY;
     * double/forged release leave snapshot unchanged; only after both
     * released is shutdown allowed.
     */
    st = ninlil_esp_idf_cell_agent_acquire_tx_gate_lease(&s_agent, &lease_a);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_a_acquire");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    st = ninlil_esp_idf_cell_agent_acquire_tx_gate_lease(&s_agent, &lease_b);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_b_acquire");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap)
        != NINLIL_ESP_IDF_OWNER_OK
        || snap.tx_gate_borrowers != 2u) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=snapshot_borrowers_not_2");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a);
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_shutdown(&s_agent)
        != NINLIL_ESP_IDF_OWNER_BUSY) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=shutdown_not_busy_two_leases");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a);
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_a_release");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a)
        != NINLIL_ESP_IDF_OWNER_LEASE_STALE) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=double_release_not_stale");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    {
        ninlil_esp_idf_tx_gate_lease_t forged = lease_b;
        forged.token ^= 0x11u;
        if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &forged)
            != NINLIL_ESP_IDF_OWNER_LEASE_STALE) {
            ESP_LOGE(TAG, "SELFTEST FAIL reason=forged_release_not_stale");
            (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(
                &s_agent, &lease_b);
            (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
            (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
            smoke_cleanup_basic();
            return;
        }
    }
    if (ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap)
        != NINLIL_ESP_IDF_OWNER_OK
        || snap.tx_gate_borrowers != 1u) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=snapshot_not_1_after_stale");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_set_tx_gate(&s_agent, tx)
        != NINLIL_ESP_IDF_OWNER_BUSY) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=set_while_B_held");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_shutdown(&s_agent)
        != NINLIL_ESP_IDF_OWNER_BUSY) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=shutdown_not_busy_one_lease");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_b_release");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap)
        != NINLIL_ESP_IDF_OWNER_OK
        || snap.tx_gate_borrowers != 0u) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=snapshot_borrowers_not_0");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_set_tx_gate(&s_agent, tx)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=set_after_all_released");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }

    for (i = 0; i < 3; ++i) {
        st = ninlil_esp_idf_cell_agent_start(&s_agent);
        if (st != NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(40));

        s_isr_owner = &s_agent.owner;
        s_isr_ok = 0u;
        s_isr_fail = 0u;
        s_prod_ok = 0u;
        s_prod_full = 0u;
        (void)xEventGroupClearBits(s_ev, EV_PROD_DONE);

        (void)memset(&targs, 0, sizeof(targs));
        targs.callback = isr_timer_cb;
        targs.name = "n_isr";
        targs.dispatch_method = ESP_TIMER_ISR;
        if (esp_timer_create(&targs, &s_isr_timer) != 0) {
            fail = 1;
        } else {
            (void)esp_timer_start_periodic(s_isr_timer, 2000);
        }

        if (xTaskCreatePinnedToCore(
                producer_task, "prod", 3072, &s_agent.owner, 4, &prod, 1)
            != pdPASS) {
            fail = 1;
        }

        (void)memset(&asg, 0, sizeof(asg));
        asg.cell_id = (uint32_t)(i + 1);
        asg.channel_id = 1u;
        asg.role = NINLIL_ROLE_CELL_AGENT_RESERVED;
        asg.assignment_epoch = 1u;
        asg.controller_term = 1u;
        (void)ninlil_esp_idf_cell_agent_apply_assignment(&s_agent, &asg);

        for (j = 0; j < 40; ++j) {
            (void)ninlil_esp_idf_owner_task_post_tick(&s_agent.owner);
        }

        bits = xEventGroupWaitBits(
            s_ev, EV_PROD_DONE, pdTRUE, pdFALSE, pdMS_TO_TICKS(3000));
        if ((bits & EV_PROD_DONE) == 0) {
            fail = 1;
        }

        if (s_isr_timer != NULL) {
            (void)esp_timer_stop(s_isr_timer);
            (void)esp_timer_delete(s_isr_timer);
            s_isr_timer = NULL;
        }
        s_isr_owner = NULL;

        (void)ninlil_esp_idf_owner_task_post_self_stop_probe(&s_agent.owner);
        vTaskDelay(pdMS_TO_TICKS(20));

        st = ninlil_esp_idf_cell_agent_stop(&s_agent);
        if (st != NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
            break;
        }
        if (ninlil_esp_idf_cell_agent_stop(&s_agent)
            != NINLIL_ESP_IDF_OWNER_DOUBLE_STOP) {
            fail = 1;
        }
        (void)ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap);
        if (snap.lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPED) {
            fail = 1;
        }
        ESP_LOGI(TAG,
            "iter %d hwm_bytes=%u isr_ok=%u isr_fail=%u prod_ok=%u full=%u tcb_gen=%u",
            i,
            (unsigned)snap.stack_hwm_bytes,
            (unsigned)s_isr_ok,
            (unsigned)s_isr_fail,
            (unsigned)s_prod_ok,
            (unsigned)s_prod_full,
            (unsigned)snap.tcb_generation);
        if (s_isr_ok == 0u) {
            /* real ISR path should have posted at least once while running */
            fail = 1;
        }
        if (ninlil_esp_idf_owner_task_post_tick(&s_agent.owner)
            == NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
        }
        if (ninlil_esp_idf_cell_agent_set_tx_gate(&s_agent, tx)
            != NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
        }
    }

    st = ninlil_esp_idf_cell_agent_shutdown(&s_agent);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=cell_agent_shutdown");
        fail = 1;
    }
    if (ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_final_shutdown");
        fail = 1;
    }
    smoke_cleanup_basic();

    /* Owner/cell first, then storage bind/COMMIT_UNKNOWN on the same app_main. */
    if (smoke_storage_commit_unknown() != 0) {
        fail = 1;
    }

    if (fail != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL (device HIL required for runtime verdict)");
    } else {
        ESP_LOGI(TAG,
            "SELFTEST owner/cell + storage paths exercised; "
            "compile!=HIL; flash monitor for runtime");
    }
}
