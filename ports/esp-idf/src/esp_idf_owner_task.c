/*
 * FreeRTOS owner-task backend (docs/22).
 * ESP-IDF v5.5.3: vTaskDelete of non-running task calls prvDeleteTCB sync.
 */

#include "ninlil_esp_idf/owner_task_storage.h"

#include "abi_header_stage_logic.h"
#include "cell_assignment_logic.h"
#include "control_boundary_logic.h"
#include "owner_config_stage_logic.h"
#include "owner_lifecycle_logic.h"
#include "owner_publish_logic.h"
#include "tx_gate_lease_logic.h"

#include <stddef.h>
#include <string.h>

#define OWNER_STOP_WAIT_TICKS ((TickType_t)pdMS_TO_TICKS(5000))
#define OWNER_DEFAULT_PRIORITY ((uint32_t)5u)

/* Fixed-size public arg vs owner storage (pre-critical). 1 = reject. */
static int owner_fixed_arg_rejects(
    const ninlil_esp_idf_owner_task_t *t,
    const void *arg,
    size_t arg_size)
{
    if (t == NULL) {
        return 1;
    }
    return ninlil_esp_idf_fixed_arg_rejects(arg, arg_size, t, sizeof(*t));
}

/*
 * Stage struct_size-bearing ops vs owner storage.
 * Returns: 0 ok, 1 invalid/alias/header, 2 shape poison (known prefix invalid).
 */
static int owner_stage_tx_gate_ops(
    const ninlil_esp_idf_owner_task_t *t,
    const ninlil_tx_gate_ops_t *ops,
    ninlil_tx_gate_ops_t *out_local)
{
    ninlil_esp_idf_abi_header_t hdr;

    if (t == NULL || ops == NULL || out_local == NULL) {
        return 1;
    }
    if (ninlil_esp_idf_abi_stage_known_prefix(
            ops,
            sizeof(*out_local),
            t,
            sizeof(*t),
            out_local,
            &hdr)
        != 0) {
        return 1;
    }
    (void)hdr;
    if (!ninlil_esp_idf_tx_gate_ops_validate(out_local)) {
        return 2;
    }
    return 0;
}

static uint64_t current_context_id(void)
{
    TaskHandle_t h;

    if (xPortInIsrContext() != 0) {
        return 0u;
    }
    h = xTaskGetCurrentTaskHandle();
    return h == NULL ? 0u : (uint64_t)(uintptr_t)h;
}

static void mux_init_once(ninlil_esp_idf_owner_task_t *t)
{
    /* Never memset a live mux. Only assign INITIALIZER when !mux_ready. */
    if (t->mux_ready == 0u) {
        t->mux = (portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;
        t->mux_ready = 1u;
    }
}

static void publish_locked(
    ninlil_esp_idf_owner_task_t *t,
    uint8_t lc,
    uint32_t accepting,
    uint32_t gen)
{
    t->published_lifecycle = lc;
    t->accepting = accepting;
    t->published_generation = gen;
}

static int try_claim_locked(ninlil_esp_idf_owner_task_t *t, uint32_t *tok)
{
    if (t->op_claim != 0u) {
        return 0;
    }
    if (t->next_claim_token == 0u) {
        t->next_claim_token = 1u;
    }
    t->op_claim = t->next_claim_token;
    *tok = t->op_claim;
    t->next_claim_token += 1u;
    return 1;
}

static void release_claim_locked(ninlil_esp_idf_owner_task_t *t, uint32_t tok)
{
    if (t->op_claim == tok) {
        t->op_claim = 0u;
    }
}

static void owner_task_fn(void *arg)
{
    ninlil_esp_idf_owner_task_t *t = (ninlil_esp_idf_owner_task_t *)arg;
    ninlil_esp_idf_owner_msg_t msg;
    uint64_t ctx;
    uint32_t nv;
    int stop;

    if (t == NULL) {
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        portENTER_CRITICAL(&t->mux);
        if (t->start_gate != 0u && t->task_handle != NULL) {
            portEXIT_CRITICAL(&t->mux);
            break;
        }
        portEXIT_CRITICAL(&t->mux);
        (void)xTaskNotifyWait(0u, UINT32_MAX, &nv, portMAX_DELAY);
    }

    ctx = current_context_id();
    if (ninlil_esp_idf_owner_complete_start(&t->core, ctx)
        != NINLIL_ESP_IDF_OWNER_OK) {
        portENTER_CRITICAL(&t->mux);
        ninlil_esp_idf_owner_fail_joined(&t->core);
        publish_locked(
            t, NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED, 0u, t->core.generation);
        t->will_suspend = 1u;
        portEXIT_CRITICAL(&t->mux);
        for (;;) {
            vTaskSuspend(NULL);
        }
    }

    portENTER_CRITICAL(&t->mux);
    publish_locked(
        t, NINLIL_ESP_IDF_OWNER_LC_RUNNING, 1u, t->core.generation);
    portEXIT_CRITICAL(&t->mux);

    stop = 0;
    for (;;) {
        nv = 0u;
        (void)xTaskNotifyWait(0u, UINT32_MAX, &nv, portMAX_DELAY);
        for (;;) {
            if (xQueueReceive(t->queue_handle, &msg, 0) != pdTRUE) {
                break;
            }
            ctx = current_context_id();
            (void)ninlil_esp_idf_owner_apply_msg(&t->core, &msg, ctx);
        }
        if ((nv & NINLIL_ESP_IDF_OWNER_NOTIFY_STOP) != 0u) {
            stop = 1;
            if (t->core.lifecycle == NINLIL_ESP_IDF_OWNER_LC_RUNNING
                || t->core.lifecycle == NINLIL_ESP_IDF_OWNER_LC_STARTING) {
                (void)ninlil_esp_idf_owner_begin_stop(&t->core);
            }
            while (xQueueReceive(t->queue_handle, &msg, 0) == pdTRUE) {
                ctx = current_context_id();
                (void)ninlil_esp_idf_owner_apply_msg(&t->core, &msg, ctx);
            }
        }
        if (stop != 0) {
            break;
        }
    }

    (void)ninlil_esp_idf_owner_mark_join_ack_core(&t->core);
    portENTER_CRITICAL(&t->mux);
    t->stack_hwm_bytes = (uint32_t)uxTaskGetStackHighWaterMark(NULL);
    t->will_suspend = 1u;
    portEXIT_CRITICAL(&t->mux);
    for (;;) {
        vTaskSuspend(NULL);
    }
}

static ninlil_esp_idf_owner_status_t post_impl(
    ninlil_esp_idf_owner_task_t *t,
    uint8_t kind,
    int is_isr,
    const uint8_t *payload,
    uint16_t payload_len)
{
    ninlil_esp_idf_owner_msg_t msg;
    ninlil_esp_idf_owner_status_t st;
    TaskHandle_t handle;
    QueueHandle_t qh;
    uint32_t gen;
    uint32_t accepting;
    BaseType_t sent;

    if (t == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }

    if (is_isr != 0) {
        portENTER_CRITICAL_ISR(&t->mux);
    } else {
        portENTER_CRITICAL(&t->mux);
    }

    if (t->api_lifecycle != 1u || t->mux_ready == 0u) {
        st = NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
        goto leave_fail;
    }
    gen = t->published_generation;
    accepting = t->accepting;
    handle = t->task_handle;
    qh = t->queue_handle;
    st = ninlil_esp_idf_owner_build_post(
        gen, accepting, kind, is_isr, payload, payload_len, &msg);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        if (st == NINLIL_ESP_IDF_OWNER_ISR_DENIED) {
            ninlil_esp_idf_owner_stats_sat_inc(&t->producer_stats.isr_denied);
        } else if (st == NINLIL_ESP_IDF_OWNER_NOT_ACCEPTING) {
            ninlil_esp_idf_owner_stats_sat_inc(
                &t->producer_stats.stale_or_not_accepting);
        } else if (st == NINLIL_ESP_IDF_OWNER_POISON) {
            ninlil_esp_idf_owner_stats_sat_inc(&t->producer_stats.poison);
        }
        goto leave_fail;
    }
    if (handle == NULL || qh == NULL || t->reclaim_closed != 0u) {
        ninlil_esp_idf_owner_stats_sat_inc(
            &t->producer_stats.stale_or_not_accepting);
        st = NINLIL_ESP_IDF_OWNER_NOT_ACCEPTING;
        goto leave_fail;
    }
    if (t->inflight_posts == UINT32_MAX) {
        ninlil_esp_idf_owner_stats_sat_inc(
            &t->producer_stats.inflight_overflow);
        st = NINLIL_ESP_IDF_OWNER_INFLIGHT_OVERFLOW;
        goto leave_fail;
    }
    t->inflight_posts += 1u;
    if (is_isr != 0) {
        portEXIT_CRITICAL_ISR(&t->mux);
    } else {
        portEXIT_CRITICAL(&t->mux);
    }

    if (is_isr != 0) {
        BaseType_t hpw = pdFALSE;
        sent = xQueueSendFromISR(qh, &msg, &hpw);
        if (sent == pdTRUE) {
            (void)xTaskNotifyFromISR(
                handle, NINLIL_ESP_IDF_OWNER_NOTIFY_DATA, eSetBits, &hpw);
            if (hpw != pdFALSE) {
                portYIELD_FROM_ISR();
            }
        }
    } else {
        sent = xQueueSend(qh, &msg, 0);
        if (sent == pdTRUE) {
            (void)xTaskNotify(
                handle, NINLIL_ESP_IDF_OWNER_NOTIFY_DATA, eSetBits);
        }
    }

    if (is_isr != 0) {
        portENTER_CRITICAL_ISR(&t->mux);
    } else {
        portENTER_CRITICAL(&t->mux);
    }
    if (t->inflight_posts > 0u) {
        t->inflight_posts -= 1u;
    }
    if (sent != pdTRUE) {
        ninlil_esp_idf_owner_stats_sat_inc(&t->producer_stats.posts_full);
        st = NINLIL_ESP_IDF_OWNER_MAILBOX_FULL;
    } else {
        ninlil_esp_idf_owner_stats_sat_inc(&t->producer_stats.posts_ok);
        st = NINLIL_ESP_IDF_OWNER_OK;
    }
    if (is_isr != 0) {
        portEXIT_CRITICAL_ISR(&t->mux);
    } else {
        portEXIT_CRITICAL(&t->mux);
    }
    return st;

leave_fail:
    if (is_isr != 0) {
        portEXIT_CRITICAL_ISR(&t->mux);
    } else {
        portEXIT_CRITICAL(&t->mux);
    }
    return st;
}

int ninlil_esp_idf_owner_task_init(
    ninlil_esp_idf_owner_task_t *t,
    const ninlil_esp_idf_owner_task_config_t *cfg)
{
    ninlil_esp_idf_owner_task_config_t local_cfg;
    ninlil_esp_idf_abi_header_t hdr;
    uint32_t prio;
    QueueHandle_t qh;

    if (t == NULL || cfg == NULL) {
        return 1;
    }
    if (xPortInIsrContext() != 0) {
        return 1;
    }
    /*
     * Owner-dedicated pure staging (shared with host tests). Declared
     * forward-extension OK; known prefix only; never re-read caller tail.
     */
    if (ninlil_esp_idf_owner_config_stage(
            cfg, t, sizeof(*t), &local_cfg, &hdr)
        != 0) {
        return 1;
    }
    (void)hdr;

    /* mux BEFORE any critical; never critical into zero free-sentinel. */
    mux_init_once(t);

    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 0u) {
        portEXIT_CRITICAL(&t->mux);
        return 1; /* one-shot or retired: no re-init of live object */
    }
    portEXIT_CRITICAL(&t->mux);

    prio = local_cfg.task_priority == 0u ? OWNER_DEFAULT_PRIORITY
                                        : local_cfg.task_priority;
    if (prio == 0u || prio >= (uint32_t)configMAX_PRIORITIES) {
        return 1;
    }

    /*
     * Zero non-mux fields without memset of the whole object (would destroy
     * mux). Clear tail of struct after mux/mux_ready. Uses local_cfg only.
     */
    {
        uint8_t *p = (uint8_t *)t + offsetof(ninlil_esp_idf_owner_task_t, api_lifecycle);
        size_t n = sizeof(*t) - offsetof(ninlil_esp_idf_owner_task_t, api_lifecycle);
        (void)memset(p, 0, n);
    }
    /* mux_ready already 1; mux intact. */
    t->mux_ready = 1u;
    ninlil_esp_idf_owner_core_clear(&t->core);
    t->task_priority = prio;
    t->next_claim_token = 1u;
    ninlil_esp_idf_tx_gate_lease_registry_clear(&t->lease_reg);

    qh = xQueueCreateStatic(
        (UBaseType_t)NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH,
        (UBaseType_t)sizeof(ninlil_esp_idf_owner_msg_t),
        t->queue_storage,
        &t->queue_cb);
    if (qh == NULL) {
        return 1;
    }

    portENTER_CRITICAL(&t->mux);
    t->queue_handle = qh;
    publish_locked(t, NINLIL_ESP_IDF_OWNER_LC_STOPPED, 0u, 0u);
    t->api_lifecycle = 1u;
    portEXIT_CRITICAL(&t->mux);
    return 0;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_start(
    ninlil_esp_idf_owner_task_t *t)
{
    ninlil_esp_idf_owner_status_t st;
    TaskHandle_t handle;
    uint32_t claim = 0u;

    if (t == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }

    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (!try_claim_locked(t, &claim)) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_BUSY;
    }
    if (t->published_lifecycle == NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (t->published_lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPED
        && t->published_lifecycle != NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_DOUBLE_START;
    }
    if (t->task_handle != NULL || t->inflight_posts != 0u) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_DOUBLE_START;
    }
    st = ninlil_esp_idf_owner_begin_start(&t->core);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return st;
    }
    (void)xQueueReset(t->queue_handle);
    (void)memset(t->task_stack, 0, sizeof(t->task_stack));
    t->start_gate = 0u;
    t->will_suspend = 0u;
    t->reclaim_closed = 0u;
    t->inflight_posts = 0u;
    (void)memset(&t->producer_stats, 0, sizeof(t->producer_stats));
    publish_locked(
        t, NINLIL_ESP_IDF_OWNER_LC_STARTING, 0u, t->core.generation);
    portEXIT_CRITICAL(&t->mux);

    handle = xTaskCreateStatic(
        owner_task_fn,
        "ninlil_own",
        NINLIL_ESP_IDF_OWNER_TASK_STACK_BYTES,
        t,
        (UBaseType_t)t->task_priority,
        t->task_stack,
        &t->task_tcb);
    if (handle == NULL) {
        portENTER_CRITICAL(&t->mux);
        ninlil_esp_idf_owner_fail_joined(&t->core);
        publish_locked(
            t, NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED, 0u, t->core.generation);
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_POISON;
    }

    portENTER_CRITICAL(&t->mux);
    t->task_handle = handle;
    t->start_gate = 1u;
    portEXIT_CRITICAL(&t->mux);
    (void)xTaskNotify(handle, NINLIL_ESP_IDF_OWNER_NOTIFY_START, eSetBits);

    portENTER_CRITICAL(&t->mux);
    release_claim_locked(t, claim);
    portEXIT_CRITICAL(&t->mux);
    return NINLIL_ESP_IDF_OWNER_OK;
}

/*
 * ESP-IDF v5.5.3 FreeRTOS: when task is not currently running on any core,
 * vTaskDelete calls prvDeleteTCB synchronously. Static TCB/stack are not
 * freed (app-owned). Precondition: eSuspended (not eRunning/eReady).
 * No fixed idle delay.
 */
static ninlil_esp_idf_owner_status_t reclaim_suspended_static(
    ninlil_esp_idf_owner_task_t *t,
    TaskHandle_t handle)
{
    TickType_t start;
    eTaskState state;

    start = xTaskGetTickCount();
    for (;;) {
        state = eTaskGetState(handle);
        if (state == eSuspended) {
            break;
        }
        if ((xTaskGetTickCount() - start) > OWNER_STOP_WAIT_TICKS) {
            return NINLIL_ESP_IDF_OWNER_TIMEOUT;
        }
        vTaskDelay(1);
    }

    portENTER_CRITICAL(&t->mux);
    publish_locked(
        t, NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK, 0u, t->published_generation);
    portEXIT_CRITICAL(&t->mux);

    /* Non-running delete → sync prvDeleteTCB (ESP-IDF v5.5.3). */
    vTaskDelete(handle);

    portENTER_CRITICAL(&t->mux);
    t->task_handle = NULL;
    t->start_gate = 0u;
    t->will_suspend = 0u;
    t->reclaim_closed = 0u;
    if (t->tcb_generation < UINT32_MAX) {
        t->tcb_generation += 1u;
    }
    (void)xQueueReset(t->queue_handle);
    if (t->core.lifecycle == NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK
        || t->core.lifecycle == NINLIL_ESP_IDF_OWNER_LC_STOPPING) {
        (void)ninlil_esp_idf_owner_complete_join(&t->core);
    }
    publish_locked(
        t, NINLIL_ESP_IDF_OWNER_LC_STOPPED, 0u, t->core.generation);
    portEXIT_CRITICAL(&t->mux);
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_stop(
    ninlil_esp_idf_owner_task_t *t)
{
    TaskHandle_t handle;
    TaskHandle_t self;
    TickType_t start;
    uint8_t lc;
    uint32_t claim = 0u;
    ninlil_esp_idf_owner_status_t st;

    if (t == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }

    self = xTaskGetCurrentTaskHandle();
    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (!try_claim_locked(t, &claim)) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_BUSY;
    }
    handle = t->task_handle;
    lc = t->published_lifecycle;
    if (handle != NULL && self == handle) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_SELF_STOP;
    }
    if (lc == NINLIL_ESP_IDF_OWNER_LC_STOPPED
        || lc == NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_DOUBLE_STOP;
    }
    if (lc == NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE) {
        /* Do not touch core/storage; refuse reclaim. */
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    t->accepting = 0u;
    t->reclaim_closed = 1u;
    publish_locked(
        t, NINLIL_ESP_IDF_OWNER_LC_STOPPING, 0u, t->published_generation);
    portEXIT_CRITICAL(&t->mux);

    if (handle != NULL) {
        (void)xTaskNotify(handle, NINLIL_ESP_IDF_OWNER_NOTIFY_STOP, eSetBits);
    }

    start = xTaskGetTickCount();
    for (;;) {
        portENTER_CRITICAL(&t->mux);
        if (t->inflight_posts == 0u && t->will_suspend != 0u) {
            handle = t->task_handle;
            portEXIT_CRITICAL(&t->mux);
            break;
        }
        handle = t->task_handle;
        portEXIT_CRITICAL(&t->mux);
        if ((xTaskGetTickCount() - start) > OWNER_STOP_WAIT_TICKS) {
            portENTER_CRITICAL(&t->mux);
            /* FAILED_LIVE: no core mutation, no reclaim. */
            publish_locked(
                t,
                NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE,
                0u,
                t->published_generation);
            release_claim_locked(t, claim);
            portEXIT_CRITICAL(&t->mux);
            return NINLIL_ESP_IDF_OWNER_TIMEOUT;
        }
        if (handle != NULL) {
            (void)xTaskNotify(
                handle, NINLIL_ESP_IDF_OWNER_NOTIFY_STOP, eSetBits);
        }
        vTaskDelay(1);
    }

    if (handle == NULL) {
        portENTER_CRITICAL(&t->mux);
        publish_locked(
            t, NINLIL_ESP_IDF_OWNER_LC_STOPPED, 0u, t->core.generation);
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_OK;
    }

    st = reclaim_suspended_static(t, handle);
    portENTER_CRITICAL(&t->mux);
    if (st == NINLIL_ESP_IDF_OWNER_TIMEOUT) {
        publish_locked(
            t,
            NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE,
            0u,
            t->published_generation);
    }
    release_claim_locked(t, claim);
    portEXIT_CRITICAL(&t->mux);
    return st;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_tick(
    ninlil_esp_idf_owner_task_t *t)
{
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    return post_impl(t, NINLIL_ESP_IDF_OWNER_MSG_TICK, 0, NULL, 0u);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_tick_from_isr(
    ninlil_esp_idf_owner_task_t *t)
{
    if (xPortInIsrContext() == 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    return post_impl(t, NINLIL_ESP_IDF_OWNER_MSG_TICK, 1, NULL, 0u);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_assignment(
    ninlil_esp_idf_owner_task_t *t,
    const ninlil_esp_idf_cell_assignment_t *a)
{
    uint8_t payload[NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES];
    uint16_t len = 0u;
    ninlil_esp_idf_owner_status_t st;

    if (t == NULL || a == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    if (owner_fixed_arg_rejects(t, a, sizeof(*a))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    (void)memset(payload, 0, sizeof(payload));
    st = ninlil_esp_idf_cell_assignment_pack(a, payload, &len);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        return st;
    }
    return post_impl(t, NINLIL_ESP_IDF_OWNER_MSG_ASSIGNMENT, 0, payload, len);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_control_summary(
    ninlil_esp_idf_owner_task_t *t,
    const ninlil_esp_idf_owner_control_summary_t *s)
{
    uint8_t payload[NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES];
    uint16_t len = 0u;
    ninlil_esp_idf_owner_status_t st;

    if (t == NULL || s == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    if (owner_fixed_arg_rejects(t, s, sizeof(*s))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    (void)memset(payload, 0, sizeof(payload));
    st = ninlil_esp_idf_control_boundary_pack_summary(s, payload, &len);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        return st;
    }
    return post_impl(
        t, NINLIL_ESP_IDF_OWNER_MSG_CONTROL_SUMMARY, 0, payload, len);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_self_stop_probe(
    ninlil_esp_idf_owner_task_t *t)
{
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    return post_impl(
        t, NINLIL_ESP_IDF_OWNER_MSG_SELF_STOP_PROBE, 0, NULL, 0u);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_get_snapshot(
    ninlil_esp_idf_owner_task_t *t,
    ninlil_esp_idf_owner_snapshot_t *out)
{
    if (t == NULL || out == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    if (owner_fixed_arg_rejects(t, out, sizeof(*out))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    out->lifecycle = t->published_lifecycle;
    out->accepting = (uint8_t)(t->accepting != 0u ? 1u : 0u);
    out->generation = t->published_generation;
    out->inflight_posts = t->inflight_posts;
    out->stack_hwm_bytes = t->stack_hwm_bytes;
    out->tcb_generation = t->tcb_generation;
    out->tx_gate_epoch = t->lease_reg.epoch;
    out->tx_gate_borrowers = t->lease_reg.occupied_count;
    out->producer = t->producer_stats;
    if (t->published_lifecycle == NINLIL_ESP_IDF_OWNER_LC_STOPPED
        || t->published_lifecycle == NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        out->owner = t->core.stats;
    }
    portEXIT_CRITICAL(&t->mux);
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_acquire_tx_gate_lease(
    ninlil_esp_idf_owner_task_t *t,
    ninlil_esp_idf_tx_gate_lease_t *out)
{
    ninlil_esp_idf_owner_status_t st;

    if (t == NULL || out == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    if (owner_fixed_arg_rejects(t, out, sizeof(*out))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    st = ninlil_esp_idf_tx_gate_lease_registry_acquire(&t->lease_reg, out);
    portEXIT_CRITICAL(&t->mux);
    return st;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_release_tx_gate_lease(
    ninlil_esp_idf_owner_task_t *t,
    const ninlil_esp_idf_tx_gate_lease_t *lease)
{
    ninlil_esp_idf_owner_status_t st;

    if (t == NULL || lease == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    if (owner_fixed_arg_rejects(t, lease, sizeof(*lease))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    st = ninlil_esp_idf_tx_gate_lease_registry_release(&t->lease_reg, lease);
    portEXIT_CRITICAL(&t->mux);
    return st;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_set_tx_gate(
    ninlil_esp_idf_owner_task_t *t,
    const ninlil_tx_gate_ops_t *tx_gate)
{
    ninlil_tx_gate_ops_t local_ops;
    uint8_t lc;

    if (t == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }
    /*
     * Public path: header stage + declared full-range nonoverlap + validate.
     * Independent of cell init trusted seam.
     */
    if (tx_gate != NULL) {
        int stage = owner_stage_tx_gate_ops(t, tx_gate, &local_ops);
        if (stage == 1) {
            return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
        }
        if (stage == 2) {
            return NINLIL_ESP_IDF_OWNER_POISON;
        }
        (void)local_ops;
    }

    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    lc = t->published_lifecycle;
    if (lc != NINLIL_ESP_IDF_OWNER_LC_STOPPED
        && lc != NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (t->lease_reg.occupied_count != 0u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_BUSY;
    }
    if (ninlil_esp_idf_tx_gate_lease_registry_set_ops(&t->lease_reg, tx_gate)
        != 0) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    portEXIT_CRITICAL(&t->mux);
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_shutdown(
    ninlil_esp_idf_owner_task_t *t)
{
    uint32_t claim = 0u;
    uint8_t lc;
    ninlil_esp_idf_owner_status_t st;

    if (t == NULL || t->mux_ready == 0u) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (xPortInIsrContext() != 0) {
        return NINLIL_ESP_IDF_OWNER_ISR_DENIED;
    }

    portENTER_CRITICAL(&t->mux);
    if (t->api_lifecycle != 1u) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    lc = t->published_lifecycle;
    portEXIT_CRITICAL(&t->mux);

    if (lc == NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (lc != NINLIL_ESP_IDF_OWNER_LC_STOPPED
        && lc != NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        st = ninlil_esp_idf_owner_task_stop(t);
        if (st != NINLIL_ESP_IDF_OWNER_OK
            && st != NINLIL_ESP_IDF_OWNER_DOUBLE_STOP) {
            return st;
        }
    }

    portENTER_CRITICAL(&t->mux);
    if (!try_claim_locked(t, &claim)) {
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_BUSY;
    }
    if (t->task_handle != NULL || t->inflight_posts != 0u
        || t->lease_reg.occupied_count != 0u
        || (t->published_lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPED
            && t->published_lifecycle
                != NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED)) {
        release_claim_locked(t, claim);
        portEXIT_CRITICAL(&t->mux);
        return NINLIL_ESP_IDF_OWNER_BUSY;
    }
    (void)ninlil_esp_idf_tx_gate_lease_registry_set_ops(&t->lease_reg, NULL);
    /* set_ops bumps epoch; clear ops for retire */
    t->lease_reg.current_ops = NULL;
    t->api_lifecycle = 2u;
    release_claim_locked(t, claim);
    portEXIT_CRITICAL(&t->mux);
    return NINLIL_ESP_IDF_OWNER_OK;
}
