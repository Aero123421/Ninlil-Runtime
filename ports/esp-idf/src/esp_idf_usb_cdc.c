/*
 * A2 ESP32-S3 esp_tinyusb 2.1.1 CDC-ACM backend.
 *
 * Callback context: TinyUSB service *task* (not hard-ISR).
 *
 * Locks (never invert; never hold s_mux across I/O wait or driver FIFO APIs):
 * - s_mux (portMUX): s_live, core admission/epoch, global bind, physical seq
 * - s_lifecycle (mutex): open/close/init serialization
 * - s_io (mutex, firmware-lifetime): all TinyUSB *software FIFO* ops
 *     RX read/drain, TX queue/flush, soft clear/flush (DOWN + park)
 *   driver_install / cdc_init / tud_mounted snapshot run without s_io
 *   (avoid deadlock with TinyUSB task callbacks that need s_io).
 *
 * esp_tinyusb==2.1.1 exact evidence (managed component sources):
 * - tinyusb.c: tinyusb_task_start() runs before event_cb/event_arg are stored.
 * - tinyusb_cdc_acm.c: get_acm(itf) then user callback; deinit frees ACM.
 * Therefore V1 never cdc_deinit/driver_uninstall on close (UAF / pre-dispatch).
 *
 * Persistent USB service (firmware lifetime once READY):
 *   ABSENT → STARTING → READY (stays) | POISONED (no V1 recovery)
 * Logical bind: FREE → CLAIMING → BOUND → PARKING → FREE | POISONED
 * Open: claim/core/service ensure without s_live; then U2-FLUSH-BEFORE-PUBLISH
 *   (s_io → RX flush+TX clear → s_mux publish s_live).
 * Close: s_mux fence + s_live unpublish first → inflight drain → s_io soft
 *   clear → FREE. Device event arg is NULL.
 * Control CDC sole-owner: service is not transferred to other USB roles.
 * Explicit full USB runtime shutdown is V1-unsupported.
 *
 * TinyUSB software FIFO clear only (no wire/in-flight recall).
 */

#include "ninlil_esp_idf/usb_cdc.h"

#include "usb_cdc_orch_logic.h"
#include "usb_cdc_state_logic.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_cdc_acm.h"
#include "class/cdc/cdc_device.h"
#include "tusb.h"

#include <string.h>

#define NINLIL_ESP_USB_CDC_MAGIC ((uint32_t)0x4e455543u)
#define NINLIL_ESP_CDC_INFLIGHT_SLICE_TICKS ((TickType_t)1)

typedef struct ninlil_esp_idf_usb_cdc {
    uint32_t magic;
    ninlil_usb_cdc_core_t core;
    TaskHandle_t owner_task;
    uint8_t tx_chunk[NINLIL_ESP_IDF_USB_CDC_TX_DRAIN_CHUNK];
} ninlil_esp_idf_usb_cdc_t;

_Static_assert(
    sizeof(ninlil_esp_idf_usb_cdc_t) <= NINLIL_ESP_IDF_USB_CDC_OBJECT_BYTES,
    "esp usb cdc object exceeds storage");
_Static_assert(
    sizeof(ninlil_esp_idf_usb_cdc_object_t) >= sizeof(ninlil_esp_idf_usb_cdc_t),
    "opaque object too small");

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static ninlil_esp_idf_usb_cdc_t *s_live;
static ninlil_usb_cdc_global_res_t s_global;
static int s_global_inited;
static StaticSemaphore_t s_lifecycle_buf;
static SemaphoreHandle_t s_lifecycle;
static ninlil_usb_cdc_once_t s_lifecycle_once;
static StaticSemaphore_t s_io_buf;
static SemaphoreHandle_t s_io;
static ninlil_usb_cdc_once_t s_io_once;
#define NINLIL_ESP_CDC_ONCE_WAIT_SLICES ((uint32_t)64u)

/*
 * Once-safe static mutex create under s_mux claim; create body runs without
 * s_mux so xSemaphoreCreate* is never under spinlock. Never call while
 * holding s_mux (wait path uses vTaskDelay).
 */
static int ensure_static_mutex_once(
    ninlil_usb_cdc_once_t *once,
    StaticSemaphore_t *buf,
    SemaphoreHandle_t *out_handle)
{
    uint32_t wait_slices = 0u;

    for (;;) {
        int claim;

        portENTER_CRITICAL(&s_mux);
        claim = ninlil_usb_cdc_once_claim_create(once);
        if (claim < 0) {
            *out_handle = (SemaphoreHandle_t)once->handle;
            portEXIT_CRITICAL(&s_mux);
            return *out_handle != NULL ? 1 : 0;
        }
        if (claim == 1) {
            portEXIT_CRITICAL(&s_mux);
            {
                SemaphoreHandle_t created = xSemaphoreCreateMutexStatic(buf);
                portENTER_CRITICAL(&s_mux);
                if (created != NULL) {
                    ninlil_usb_cdc_once_mark_ready(once, (void *)created);
                    *out_handle = created;
                    portEXIT_CRITICAL(&s_mux);
                    return 1;
                }
                ninlil_usb_cdc_once_mark_failed(once);
                *out_handle = NULL;
                portEXIT_CRITICAL(&s_mux);
                return 0;
            }
        }
        portEXIT_CRITICAL(&s_mux);
        if (wait_slices >= NINLIL_ESP_CDC_ONCE_WAIT_SLICES) {
            portENTER_CRITICAL(&s_mux);
            *out_handle = (SemaphoreHandle_t)once->handle;
            portEXIT_CRITICAL(&s_mux);
            return *out_handle != NULL ? 1 : 0;
        }
        wait_slices += 1u;
        vTaskDelay(NINLIL_ESP_CDC_INFLIGHT_SLICE_TICKS);
    }
}

static int ensure_lifecycle_mutex(void)
{
    return ensure_static_mutex_once(
        &s_lifecycle_once, &s_lifecycle_buf, &s_lifecycle);
}

/* U2-IO-MUTEX: firmware-lifetime USB software-FIFO serializer. */
static int ensure_io_mutex(void)
{
    return ensure_static_mutex_once(&s_io_once, &s_io_buf, &s_io);
}

static int io_lock(void)
{
    if (!ensure_io_mutex() || s_io == NULL) {
        return 0;
    }
    return xSemaphoreTake(s_io, portMAX_DELAY) == pdTRUE ? 1 : 0;
}

static void io_unlock(void)
{
    if (s_io != NULL) {
        (void)xSemaphoreGive(s_io);
    }
}

/* Caller must hold s_io. Never call under s_mux. */
static void soft_tx_clear_holding_io(void)
{
    (void)tud_cdc_n_write_clear(0);
}

static void soft_rx_flush_holding_io(void)
{
    tud_cdc_n_read_flush(0);
}

static ninlil_esp_idf_usb_cdc_t *self_from(ninlil_byte_stream_t *stream)
{
    ninlil_esp_idf_usb_cdc_t *self;

    if (stream == NULL || stream->self == NULL) {
        return NULL;
    }
    self = (ninlil_esp_idf_usb_cdc_t *)stream->self;
    if (self->magic != NINLIL_ESP_USB_CDC_MAGIC) {
        return NULL;
    }
    return self;
}

static const ninlil_esp_idf_usb_cdc_t *self_from_const(
    const ninlil_byte_stream_t *stream)
{
    return self_from((ninlil_byte_stream_t *)(uintptr_t)stream);
}

static uint64_t current_owner_id(void)
{
    return (uint64_t)(uintptr_t)xTaskGetCurrentTaskHandle();
}

static uint64_t self_id(const ninlil_esp_idf_usb_cdc_t *self)
{
    return (uint64_t)(uintptr_t)self;
}

static ninlil_usb_cdc_addr_range_t storage_range_of(
    const ninlil_esp_idf_usb_cdc_t *self)
{
    ninlil_usb_cdc_addr_range_t r;

    r.base = (uint64_t)(uintptr_t)self;
    r.bytes = (uint64_t)sizeof(*self);
    return r;
}

static void error_out_only(
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    if (out_error == NULL) {
        return;
    }
    (void)memset(&local, 0, sizeof(local));
    local.status = status;
    local.stage = stage;
    if (hint != NULL) {
        size_t n = strlen(hint);
        if (n >= sizeof(local.hint)) {
            n = sizeof(local.hint) - 1u;
        }
        (void)memcpy(local.hint, hint, n);
        local.hint[n] = '\0';
    }
    *out_error = local;
}

/* Open-path BUSY must not poison first_teardown_error. */
static void persist_open_error(
    ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    (void)memset(&local, 0, sizeof(local));
    local.status = status;
    local.stage = stage;
    if (core != NULL && core->endpoint[0] != '\0') {
        (void)memcpy(local.path, core->endpoint, sizeof(local.path));
        local.path[sizeof(local.path) - 1u] = '\0';
    }
    if (hint != NULL) {
        size_t n = strlen(hint);
        if (n >= sizeof(local.hint)) {
            n = sizeof(local.hint) - 1u;
        }
        (void)memcpy(local.hint, hint, n);
        local.hint[n] = '\0';
    }
    if (core != NULL) {
        core->last_error = local;
        /* intentionally do NOT set first_teardown_error on open paths */
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static void persist_teardown_error(
    ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    (void)memset(&local, 0, sizeof(local));
    local.status = status;
    local.stage = stage;
    if (core != NULL && core->endpoint[0] != '\0') {
        (void)memcpy(local.path, core->endpoint, sizeof(local.path));
        local.path[sizeof(local.path) - 1u] = '\0';
    }
    if (hint != NULL) {
        size_t n = strlen(hint);
        if (n >= sizeof(local.hint)) {
            n = sizeof(local.hint) - 1u;
        }
        (void)memcpy(local.hint, hint, n);
        local.hint[n] = '\0';
    }
    if (core != NULL) {
        core->last_error = local;
        if (!core->has_first_teardown_error
            && status != NINLIL_BYTE_STREAM_OK) {
            core->first_teardown_error = local;
            core->has_first_teardown_error = 1;
        }
        if (out_error != NULL && core->has_first_teardown_error) {
            *out_error = core->first_teardown_error;
            return;
        }
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

/* ---- driver ops ------------------------------------------------------- */

static void device_event_handler(tinyusb_event_t *event, void *arg);
static void cdc_line_state_changed(int itf, cdcacm_event_t *event);
static void cdc_rx_callback(int itf, cdcacm_event_t *event);
static int wait_callbacks_drained(ninlil_esp_idf_usb_cdc_t *self);

static int esp_drv_install(void *user)
{
    tinyusb_config_t tusb_cfg;

    (void)user;
    /* Storage-free event arg: callbacks use s_live under s_mux. */
    tusb_cfg = TINYUSB_DEFAULT_CONFIG(device_event_handler, NULL);
    {
        esp_err_t err = tinyusb_driver_install(&tusb_cfg);
        return (err == ESP_OK) ? 0 : (int)err;
    }
}

static int esp_cdc_init(void *user)
{
    tinyusb_config_cdcacm_t acm_cfg;
    esp_err_t err;

    (void)user;
    (void)memset(&acm_cfg, 0, sizeof(acm_cfg));
    acm_cfg.cdc_port = TINYUSB_CDC_ACM_0;
    acm_cfg.callback_rx = &cdc_rx_callback;
    acm_cfg.callback_line_state_changed = &cdc_line_state_changed;
    err = tinyusb_cdcacm_init(&acm_cfg);
    return (err == ESP_OK) ? 0 : (int)err;
}

static int esp_cdc_deinit_unused(void *user)
{
    (void)user;
    /* V1 persistent: never call tinyusb_cdcacm_deinit on park path. */
    return 1;
}

static int esp_drv_uninstall_unused(void *user)
{
    (void)user;
    return 1;
}

static uint32_t esp_tx_queue(void *user, const uint8_t *data, uint32_t n)
{
    size_t q;

    (void)user;
    if (data == NULL || n == 0u) {
        return 0u;
    }
    /* I/O mutex; never called under s_mux (drain peeks then unlocks first). */
    if (!io_lock()) {
        return 0u;
    }
    q = tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, data, (size_t)n);
    if (q > 0u) {
        (void)tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, 0);
    }
    io_unlock();
    return (uint32_t)q;
}

static void esp_tx_fifo_soft_clear(void *user)
{
    (void)user;
    if (!io_lock()) {
        return;
    }
    soft_tx_clear_holding_io();
    io_unlock();
}

static void esp_rx_fifo_soft_flush(void *user)
{
    (void)user;
    if (!io_lock()) {
        return;
    }
    soft_rx_flush_holding_io();
    io_unlock();
}

static void esp_state_lock(void *user)
{
    (void)user;
    portENTER_CRITICAL(&s_mux);
}

static void esp_state_unlock(void *user)
{
    (void)user;
    portEXIT_CRITICAL(&s_mux);
}

static int esp_wait_callbacks_drained(void *user)
{
    return wait_callbacks_drained((ninlil_esp_idf_usb_cdc_t *)user);
}

static void esp_physical_snapshot(void *user, int *out_attached, int *out_dtr)
{
    (void)user;
    if (out_attached != NULL) {
        *out_attached = tud_mounted() ? 1 : 0;
    }
    if (out_dtr != NULL) {
        *out_dtr = tud_cdc_n_connected(0) ? 1 : 0;
    }
}

static const ninlil_usb_cdc_driver_ops_t s_esp_ops = {
    esp_drv_install,
    esp_cdc_init,
    esp_cdc_deinit_unused,
    esp_drv_uninstall_unused,
    esp_tx_queue,
    esp_tx_fifo_soft_clear,
    esp_rx_fifo_soft_flush,
    esp_state_lock,
    esp_state_unlock,
    esp_wait_callbacks_drained,
    esp_physical_snapshot,
    NULL,
};

/* ---- callbacks: s_live only under s_mux -------------------------------- */

/*
 * Drop TinyUSB software RX FIFO while unbound (or admit fenced).
 * Caller must hold s_io; must not hold s_mux. Bounded iterations.
 * Never writes Ninlil rings.
 */
static void unbound_rx_fifo_drain_drop_holding_io(int itf)
{
    uint8_t stack_chunk[NINLIL_ESP_IDF_USB_CDC_TX_DRAIN_CHUNK];
    size_t rx_size = 0;
    uint32_t iters;
    const uint32_t max_iters = 32u;

    /* U2-UNBOUND-RX-DRAIN */
    for (iters = 0u; iters < max_iters; ++iters) {
        rx_size = 0u;
        if (tinyusb_cdcacm_read(
                (tinyusb_cdcacm_itf_t)itf,
                stack_chunk,
                sizeof(stack_chunk),
                &rx_size)
            != ESP_OK) {
            break;
        }
        if (rx_size == 0u) {
            break;
        }
        /* drop: intentionally not forwarded to any generation ring */
    }
}

static void device_event_handler(tinyusb_event_t *event, void *arg)
{
    ninlil_esp_idf_usb_cdc_t *self;
    uint32_t epoch = 0u;
    int attached;
    int dtr;
    int entered;
    int need_soft_clear = 0;

    (void)arg; /* must be NULL — no storage lifetime in upstream arg */
    if (event == NULL) {
        return;
    }
    if (event->id != TINYUSB_EVENT_ATTACHED
        && event->id != TINYUSB_EVENT_DETACHED) {
        return;
    }

    portENTER_CRITICAL(&s_mux);
    /*
     * U2-UNBOUND-SEQ-BUMP: always advance physical_event_seq under s_mux,
     * including persistent-service unbound windows (s_live == NULL).
     */
    (void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);
    self = s_live;
    if (self == NULL) {
        need_soft_clear = (event->id == TINYUSB_EVENT_DETACHED) ? 1 : 0;
        portEXIT_CRITICAL(&s_mux);
        if (need_soft_clear) {
            /* I/O mutex via ops; s_mux not held. */
            esp_tx_fifo_soft_clear(NULL);
            esp_rx_fifo_soft_flush(NULL);
        }
        return;
    }
    entered = ninlil_usb_cdc_core_callback_try_enter(&self->core, &epoch);
    if (!entered) {
        need_soft_clear = (event->id == TINYUSB_EVENT_DETACHED) ? 1 : 0;
        portEXIT_CRITICAL(&s_mux);
        if (need_soft_clear) {
            esp_tx_fifo_soft_clear(NULL);
            esp_rx_fifo_soft_flush(NULL);
        }
        return;
    }
    attached = self->core.usb_attached;
    dtr = self->core.dtr_asserted;
    switch (event->id) {
    case TINYUSB_EVENT_ATTACHED:
        attached = 1;
        break;
    case TINYUSB_EVENT_DETACHED:
        attached = 0;
        dtr = 0;
        need_soft_clear = 1;
        break;
    default:
        ninlil_usb_cdc_core_callback_leave(&self->core);
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    (void)ninlil_usb_cdc_core_apply_physical(
        &self->core, epoch, attached, dtr);
    /* U2-CB-SOFT-CLEAR-BEFORE-LEAVE: hold inflight across soft clear */
    if (!need_soft_clear) {
        ninlil_usb_cdc_core_callback_leave(&self->core);
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    portEXIT_CRITICAL(&s_mux);

    /* Soft clear under s_io; inflight still held; s_mux depth 0. */
    esp_tx_fifo_soft_clear(NULL);
    esp_rx_fifo_soft_flush(NULL);

    portENTER_CRITICAL(&s_mux);
    ninlil_usb_cdc_core_callback_leave(&self->core);
    portEXIT_CRITICAL(&s_mux);
}

static void cdc_line_state_changed(int itf, cdcacm_event_t *event)
{
    ninlil_esp_idf_usb_cdc_t *self;
    uint32_t epoch = 0u;
    int attached;
    int dtr;
    int entered;
    int was_up;
    int now_up;
    int need_soft_clear = 0;

    (void)itf;
    if (event == NULL || event->type != CDC_EVENT_LINE_STATE_CHANGED) {
        return;
    }
    portENTER_CRITICAL(&s_mux);
    /* U2-UNBOUND-SEQ-BUMP: DTR transitions bump seq even when unbound. */
    (void)ninlil_usb_cdc_global_bump_physical_seq(&s_global);
    self = s_live;
    if (self == NULL) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    was_up = (self->core.link == NINLIL_BYTE_STREAM_LINK_UP);
    entered = ninlil_usb_cdc_core_callback_try_enter(&self->core, &epoch);
    if (!entered) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    attached = self->core.usb_attached;
    dtr = event->line_state_changed_data.dtr ? 1 : 0;
    (void)ninlil_usb_cdc_core_apply_physical(
        &self->core, epoch, attached, dtr);
    now_up = (self->core.link == NINLIL_BYTE_STREAM_LINK_UP);
    if (was_up && !now_up) {
        need_soft_clear = 1;
    }
    if (!need_soft_clear) {
        ninlil_usb_cdc_core_callback_leave(&self->core);
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    portEXIT_CRITICAL(&s_mux);

    esp_tx_fifo_soft_clear(NULL);
    esp_rx_fifo_soft_flush(NULL);

    portENTER_CRITICAL(&s_mux);
    ninlil_usb_cdc_core_callback_leave(&self->core);
    portEXIT_CRITICAL(&s_mux);
}

static void cdc_rx_callback(int itf, cdcacm_event_t *event)
{
    ninlil_esp_idf_usb_cdc_t *self;
    uint32_t epoch = 0u;
    int entered;
    uint8_t stack_chunk[NINLIL_ESP_IDF_USB_CDC_TX_DRAIN_CHUNK];
    size_t rx_size = 0;
    esp_err_t err;
    ninlil_byte_stream_event_t ev = NINLIL_BYTE_STREAM_EVENT_NONE;

    (void)event;
    /*
     * U2-RX-IO-FIRST: take s_io before s_mux so pre-dispatch callbacks
     * serialize with open flush-before-publish and close soft clear.
     * Never hold s_mux across read/drain.
     */
    if (!io_lock()) {
        return;
    }

    portENTER_CRITICAL(&s_mux);
    self = s_live;
    if (self == NULL) {
        portEXIT_CRITICAL(&s_mux);
        /* Persistent service unbound: drop under s_io; no ring. */
        unbound_rx_fifo_drain_drop_holding_io(itf);
        io_unlock();
        return;
    }
    entered = ninlil_usb_cdc_core_callback_try_enter(&self->core, &epoch);
    portEXIT_CRITICAL(&s_mux);
    if (!entered) {
        /* admit fenced (park/close): drain under s_io only */
        unbound_rx_fifo_drain_drop_holding_io(itf);
        io_unlock();
        return;
    }

    /* FIFO read at s_mux depth 0 while holding s_io. */
    err = tinyusb_cdcacm_read(
        (tinyusb_cdcacm_itf_t)itf,
        stack_chunk,
        sizeof(stack_chunk),
        &rx_size);

    portENTER_CRITICAL(&s_mux);
    if (err == ESP_OK && rx_size > 0u && self == s_live) {
        (void)ninlil_usb_cdc_core_rx_ingress(
            &self->core, epoch, stack_chunk, (uint32_t)rx_size, &ev);
        (void)ev;
        ninlil_usb_cdc_core_callback_leave(&self->core);
        portEXIT_CRITICAL(&s_mux);
        io_unlock();
        return;
    }
    /* lost binding / empty: leave under lock, drop residual under s_io */
    ninlil_usb_cdc_core_callback_leave(&self->core);
    portEXIT_CRITICAL(&s_mux);
    if (err == ESP_OK && rx_size > 0u) {
        /* Byte was already pulled; drop rest of residual FIFO. */
        unbound_rx_fifo_drain_drop_holding_io(itf);
    }
    io_unlock();
}

static int wait_callbacks_drained(ninlil_esp_idf_usb_cdc_t *self)
{
    uint32_t slices;

    for (slices = 0u; slices < NINLIL_ESP_CDC_INFLIGHT_WAIT_SLICES_MAX;
         ++slices) {
        int drained;

        portENTER_CRITICAL(&s_mux);
        drained = ninlil_usb_cdc_core_callbacks_drained(&self->core);
        portEXIT_CRITICAL(&s_mux);
        if (drained) {
            return 1;
        }
        vTaskDelay(NINLIL_ESP_CDC_INFLIGHT_SLICE_TICKS);
    }
    portENTER_CRITICAL(&s_mux);
    {
        int drained = ninlil_usb_cdc_core_callbacks_drained(&self->core);
        portEXIT_CRITICAL(&s_mux);
        return drained;
    }
}

static int drain_tx_nonblocking(
    ninlil_esp_idf_usb_cdc_t *self,
    uint64_t owner_id,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_usb_cdc_tx_ticket_t ticket;
    uint32_t peeked;
    uint32_t queued;
    uint32_t i;
    uint32_t total = 0u;
    const uint32_t max_iters = 8u;
    ninlil_usb_cdc_driver_ops_t ops = s_esp_ops;

    ops.user = self;
    for (i = 0u; i < max_iters; ++i) {
        portENTER_CRITICAL(&s_mux);
        if (!ninlil_usb_cdc_core_check_owner(
                &self->core, owner_id, out_error)) {
            portEXIT_CRITICAL(&s_mux);
            return -1;
        }
        peeked = ninlil_usb_cdc_core_tx_drain_begin(
            &self->core,
            self->tx_chunk,
            (uint32_t)sizeof(self->tx_chunk),
            &ticket);
        portEXIT_CRITICAL(&s_mux);
        if (peeked == 0u) {
            break;
        }
        queued = ops.tx_queue(ops.user, self->tx_chunk, peeked);
        portENTER_CRITICAL(&s_mux);
        (void)ninlil_usb_cdc_core_tx_drain_finish(
            &self->core, &ticket, queued);
        portEXIT_CRITICAL(&s_mux);
        if (queued == 0u) {
            break;
        }
        total += queued;
    }
    return total > 0u ? 1 : 0;
}

static void reconcile_physical_after_bind(ninlil_esp_idf_usb_cdc_t *self)
{
    uint64_t captured_seq = 0u;
    uint32_t epoch = 0u;
    int attached = 0;
    int dtr = 0;
    int entered;

    /*
     * U2-RECONCILE-SEQ-BEFORE-SNAPSHOT:
     * capture seq under s_mux first (with s_live check), unlock, snapshot
     * tud_mounted/connected outside lock, relock and apply only if seq
     * unchanged — stale snapshots never win over intervening events.
     */
    portENTER_CRITICAL(&s_mux);
    if (self != s_live) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    captured_seq = s_global.physical_event_seq;
    portEXIT_CRITICAL(&s_mux);

    esp_physical_snapshot(NULL, &attached, &dtr);

    portENTER_CRITICAL(&s_mux);
    if (self != s_live) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    if (s_global.physical_event_seq != captured_seq) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    entered = ninlil_usb_cdc_core_callback_try_enter(&self->core, &epoch);
    if (!entered) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    (void)ninlil_usb_cdc_reconcile_physical_if_seq(
        &self->core, &s_global, captured_seq, epoch, attached, dtr);
    ninlil_usb_cdc_core_callback_leave(&self->core);
    portEXIT_CRITICAL(&s_mux);
}

/* ---- public API -------------------------------------------------------- */

size_t ninlil_esp_idf_usb_cdc_object_size(void)
{
    return sizeof(ninlil_esp_idf_usb_cdc_t);
}

size_t ninlil_esp_idf_usb_cdc_object_align(void)
{
    return NINLIL_ESP_IDF_USB_CDC_OBJECT_ALIGN;
}

static const ninlil_byte_stream_ops_t *esp_usb_cdc_ops(void);

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_init(
    void *storage,
    size_t storage_bytes,
    ninlil_byte_stream_t *out_stream)
{
    ninlil_esp_idf_usb_cdc_t *self;
    uintptr_t addr;
    ninlil_usb_cdc_addr_range_t storage_r;
    ninlil_usb_cdc_addr_range_t stream_r;
    ninlil_usb_cdc_addr_range_t live_r;

    if (storage == NULL || out_stream == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (storage_bytes < sizeof(ninlil_esp_idf_usb_cdc_t)) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    addr = (uintptr_t)storage;
    if ((addr % NINLIL_ESP_IDF_USB_CDC_OBJECT_ALIGN) != 0u) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    storage_r.base = (uint64_t)addr;
    storage_r.bytes = (uint64_t)sizeof(ninlil_esp_idf_usb_cdc_t);
    stream_r.base = (uint64_t)(uintptr_t)out_stream;
    stream_r.bytes = (uint64_t)sizeof(*out_stream);

    /*
     * U2-INIT-GUARD-BEFORE-MEMSET: lifecycle mutex + range overlap vs live
     * storage / reserved object before any wipe or out_stream write.
     */
    if (!ensure_lifecycle_mutex() || s_lifecycle == NULL
        || xSemaphoreTake(s_lifecycle, portMAX_DELAY) != pdTRUE) {
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }

    portENTER_CRITICAL(&s_mux);
    if (!s_global_inited) {
        ninlil_usb_cdc_global_init(&s_global);
        s_global_inited = 1;
    }
    if (s_live != NULL) {
        live_r = storage_range_of(s_live);
    } else {
        live_r.base = 0u;
        live_r.bytes = 0u;
    }
    if (!ninlil_usb_cdc_init_ranges_may_claim(
            &storage_r,
            &stream_r,
            &s_global,
            live_r.bytes > 0u ? &live_r : NULL)) {
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return NINLIL_BYTE_STREAM_BUSY;
    }
    portEXIT_CRITICAL(&s_mux);

    self = (ninlil_esp_idf_usb_cdc_t *)storage;
    (void)memset(self, 0, sizeof(*self));
    self->magic = NINLIL_ESP_USB_CDC_MAGIC;
    ninlil_usb_cdc_core_init(&self->core);

    out_stream->ops = esp_usb_cdc_ops();
    out_stream->self = self;
    (void)xSemaphoreGive(s_lifecycle);
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_init_object(
    ninlil_esp_idf_usb_cdc_object_t *object,
    ninlil_byte_stream_t *out_stream)
{
    if (object == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_usb_cdc_init(
        object->bytes, sizeof(object->bytes), out_stream);
}

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_open(
    ninlil_byte_stream_t *stream,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_esp_idf_usb_cdc_t *self = self_from(stream);
    ninlil_byte_stream_status_t st;
    uint64_t owner;
    uint64_t id;
    ninlil_usb_cdc_driver_ops_t ops = s_esp_ops;
    ninlil_usb_cdc_addr_range_t sr;

    if (self == NULL) {
        error_out_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "null stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    owner = current_owner_id();
    id = self_id(self);
    ops.user = self;

    if (!ensure_lifecycle_mutex() || s_lifecycle == NULL
        || xSemaphoreTake(s_lifecycle, portMAX_DELAY) != pdTRUE) {
        portENTER_CRITICAL(&s_mux);
        persist_open_error(
            &self->core,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "lifecycle mutex unavailable",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }

    portENTER_CRITICAL(&s_mux);
    /* Nonmutating preflight before global claim. */
    st = ninlil_usb_cdc_open_preflight(
        &self->core, owner, endpoint_token, out_error);
    if (st != NINLIL_BYTE_STREAM_OK) {
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return st;
    }
    if (!ninlil_usb_cdc_global_try_begin_install(&s_global, id)) {
        /* U2-PERSIST-UNDER-SMUX: core diagnosis mutation under s_mux */
        persist_open_error(
            &self->core,
            NINLIL_BYTE_STREAM_BUSY,
            NINLIL_BYTE_STREAM_STAGE_USB_STACK,
            "logical Control CDC bind busy or service poisoned",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return NINLIL_BYTE_STREAM_BUSY;
    }
    st = ninlil_usb_cdc_core_open(
        &self->core, endpoint_token, owner, out_error);
    if (st != NINLIL_BYTE_STREAM_OK) {
        ninlil_usb_cdc_global_install_abort(&s_global);
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return st;
    }
    /*
     * Record reserved storage for init overlap / poison protection, but do
     * NOT publish s_live until READY+BOUND+flush-before-publish (below).
     * Invariant: s_live only on successful bind (U2-SLIVE-SUCCESS-ONLY).
     */
    sr = storage_range_of(self);
    ninlil_usb_cdc_global_set_live_storage(&s_global, &sr);
    portEXIT_CRITICAL(&s_mux);

    self->owner_task = xTaskGetCurrentTaskHandle();

    st = ninlil_usb_cdc_orch_install(
        &self->core, &s_global, id, owner, &ops, out_error);

    if (st != NINLIL_BYTE_STREAM_OK) {
        portENTER_CRITICAL(&s_mux);
        /*
         * Never publish s_live on install failure (including POISONED).
         * Poisoned storage protection uses live_storage/reserved_id only.
         */
        if (s_live == self) {
            s_live = NULL;
        }
        if (s_global.state == NINLIL_USB_CDC_BIND_FREE) {
            ninlil_usb_cdc_global_clear_live_storage(&s_global);
            self->owner_task = NULL;
        } else if (s_global.state == NINLIL_USB_CDC_BIND_POISONED) {
            self->owner_task = xTaskGetCurrentTaskHandle();
        }
        if (out_error != NULL && self->core.last_error.status != 0u) {
            *out_error = self->core.last_error;
        }
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return st;
    }

    /*
     * U2-FLUSH-BEFORE-PUBLISH:
     * Service READY + bind marked. Hold s_io across old FIFO flush/clear and
     * atomic s_live publish so prebind / unbound FIFO bytes never enter B's
     * ring. Non-recallable: software FIFO only.
     */
    if (!io_lock()) {
        portENTER_CRITICAL(&s_mux);
        (void)ninlil_usb_cdc_core_begin_close_fence(&self->core, owner, NULL);
        if (s_global.reserved_id == id) {
            if (ninlil_usb_cdc_global_try_begin_teardown(&s_global, id)) {
                ninlil_usb_cdc_global_teardown_fail(&s_global);
            }
        }
        if (s_live == self) {
            s_live = NULL;
        }
        self->owner_task = NULL;
        persist_open_error(
            &self->core,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "USB I/O mutex unavailable at publish",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    soft_tx_clear_holding_io();
    soft_rx_flush_holding_io();
    portENTER_CRITICAL(&s_mux);
    if (s_global.state != NINLIL_USB_CDC_BIND_BOUND
        || s_global.reserved_id != id
        || self->core.lifecycle != NINLIL_USB_CDC_LC_LIVE) {
        /*
         * U2-OPEN-PUBLISH-VALIDATE-POISON: do not clear live_storage while
         * leaving BOUND/LIVE (that loses partial-overlap reinit protection).
         * Fail-closed: fence → PARKING → POISONED; keep live_storage +
         * reserved_id; s_live stays NULL (never published).
         */
        if (s_live == self) {
            s_live = NULL;
        }
        (void)ninlil_usb_cdc_core_begin_close_fence(&self->core, owner, NULL);
        if (s_global.reserved_id == id) {
            if (ninlil_usb_cdc_global_try_begin_teardown(&s_global, id)) {
                ninlil_usb_cdc_global_teardown_fail(&s_global);
            }
        }
        /* intentionally retain live_storage / reserved_id for range guards */
        self->owner_task = xTaskGetCurrentTaskHandle();
        persist_open_error(
            &self->core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "bind invalid at s_live publish; POISONED with storage retained",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        io_unlock();
        (void)xSemaphoreGive(s_lifecycle);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    /* U2-SLIVE-SUCCESS-ONLY: sole success-path publish site */
    s_live = self;
    portEXIT_CRITICAL(&s_mux);
    io_unlock();

    /* After publish: reconcile missed ATTACHED/DTR (existing seq protocol). */
    reconcile_physical_after_bind(self);

    (void)xSemaphoreGive(s_lifecycle);
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_close(
    ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_esp_idf_usb_cdc_t *self = self_from(stream);
    ninlil_byte_stream_status_t st;
    uint64_t owner;
    uint64_t id;
    int drained;
    ninlil_usb_cdc_driver_ops_t ops = s_esp_ops;

    if (self == NULL) {
        error_out_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "null stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    owner = current_owner_id();
    id = self_id(self);
    ops.user = self;

    if (!ensure_lifecycle_mutex() || s_lifecycle == NULL
        || xSemaphoreTake(s_lifecycle, portMAX_DELAY) != pdTRUE) {
        portENTER_CRITICAL(&s_mux);
        persist_teardown_error(
            &self->core,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "lifecycle mutex unavailable",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }

    portENTER_CRITICAL(&s_mux);
    {
        int idle_pol = ninlil_usb_cdc_closed_idle_close_policy(
            &self->core, &s_global, id);
        if (idle_pol == 1) {
            portEXIT_CRITICAL(&s_mux);
            (void)xSemaphoreGive(s_lifecycle);
            return NINLIL_BYTE_STREAM_OK;
        }
        if (idle_pol < 0) {
            persist_teardown_error(
                &self->core,
                NINLIL_BYTE_STREAM_INVALID_STATE,
                NINLIL_BYTE_STREAM_STAGE_CLOSE,
                "close inconsistency: CLOSED idle but bind holds id",
                out_error);
            portEXIT_CRITICAL(&s_mux);
            (void)xSemaphoreGive(s_lifecycle);
            return NINLIL_BYTE_STREAM_INVALID_STATE;
        }
    }
    st = ninlil_usb_cdc_core_begin_close_fence(&self->core, owner, out_error);
    /*
     * U2-CLOSE-FENCE-FAILCLOSED: any non-OK fence (WRONG_OWNER, epoch
     * exhaustion INVALID_STATE, …) must not claim PARKING / unpublish /
     * I/O quiesce / orch teardown.
     */
    if (st != NINLIL_BYTE_STREAM_OK) {
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return st;
    }
    if (!ninlil_usb_cdc_global_try_begin_teardown(&s_global, id)) {
        persist_teardown_error(
            &self->core,
            NINLIL_BYTE_STREAM_BUSY,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "close cannot claim PARKING for this object id",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return NINLIL_BYTE_STREAM_BUSY;
    }
    /*
     * U2-CLOSE-UNPUBLISH-FIRST: fence + s_live unpublish under s_mux before
     * any I/O soft clear.
     */
    if (s_live == self) {
        s_live = NULL;
    }
    portEXIT_CRITICAL(&s_mux);

    drained = wait_callbacks_drained(self);

    /*
     * Explicit I/O quiesce under s_io. Failure is fail-closed: do not call
     * orch_teardown (would re-attempt soft clear / hide error). Keep PARKING
     * / TEARDOWN_PENDING and poison bind so reopen cannot false-green.
     */
    if (!io_lock()) {
        portENTER_CRITICAL(&s_mux);
        ninlil_usb_cdc_global_teardown_fail(&s_global);
        /* U2-SLIVE-SUCCESS-ONLY: never re-publish s_live on close failure */
        if (s_live == self) {
            s_live = NULL;
        }
        self->owner_task = xTaskGetCurrentTaskHandle();
        persist_teardown_error(
            &self->core,
            NINLIL_BYTE_STREAM_IO_ERROR,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "USB I/O mutex unavailable at park quiesce",
            out_error);
        portEXIT_CRITICAL(&s_mux);
        (void)xSemaphoreGive(s_lifecycle);
        return NINLIL_BYTE_STREAM_IO_ERROR;
    }
    soft_tx_clear_holding_io();
    soft_rx_flush_holding_io();
    io_unlock();

    /*
     * Soft clear already done under s_io; pass NULL clear ops so orch cannot
     * double-execute and hide a second soft-clear failure.
     */
    ops.tx_fifo_soft_clear = NULL;
    ops.rx_fifo_soft_flush = NULL;

    /* Logical park: no cdc_deinit / uninstall (persistent service). */
    st = ninlil_usb_cdc_orch_teardown(
        &self->core, &s_global, id, owner, drained, &ops, out_error);

    portENTER_CRITICAL(&s_mux);
    if (st == NINLIL_BYTE_STREAM_OK) {
        self->owner_task = NULL;
        ninlil_usb_cdc_global_clear_live_storage(&s_global);
    } else {
        /* Keep s_live NULL; protect storage via live_storage/reserved_id. */
        if (s_live == self) {
            s_live = NULL;
        }
        self->owner_task = xTaskGetCurrentTaskHandle();
        if (out_error != NULL && self->core.last_error.status != 0u) {
            *out_error = self->core.last_error;
        }
    }
    portEXIT_CRITICAL(&s_mux);
    (void)xSemaphoreGive(s_lifecycle);
    return st;
}

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_esp_idf_usb_cdc_t *self = self_from(stream);
    ninlil_byte_stream_status_t st;

    if (self == NULL) {
        error_out_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            "null stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    portENTER_CRITICAL(&s_mux);
    st = ninlil_usb_cdc_core_write(
        &self->core, current_owner_id(), data, length, out_accepted, out_error);
    portEXIT_CRITICAL(&s_mux);
    return st;
}

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_esp_idf_usb_cdc_t *self = self_from(stream);
    ninlil_byte_stream_status_t st;

    if (self == NULL) {
        error_out_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            "null stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    portENTER_CRITICAL(&s_mux);
    st = ninlil_usb_cdc_core_read(
        &self->core,
        current_owner_id(),
        out_data,
        capacity,
        out_length,
        out_error);
    portEXIT_CRITICAL(&s_mux);
    return st;
}

ninlil_byte_stream_status_t ninlil_esp_idf_usb_cdc_poll(
    ninlil_byte_stream_t *stream,
    uint32_t timeout_ms,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_esp_idf_usb_cdc_t *self = self_from(stream);
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    ninlil_byte_stream_status_t st;
    uint64_t owner;
    int did_drain;
    uint64_t budget;
    uint64_t elapsed = 0u;
    uint32_t entry_tick;
    uint32_t last_tick;
    uint32_t now_tick;

    if (self == NULL) {
        error_out_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            "null stream",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    /*
     * U2-POLL-CALL-ENTRY-TICK: absolute deadline baseline is call entry
     * (before first pump I/O). Owner check is non-I/O; initial nonblocking
     * pump is always allowed (C1); its duration charges the budget.
     */
    entry_tick = xTaskGetTickCount();
    last_tick = entry_tick;

    owner = current_owner_id();

    /* U2-POLL-OWNER-BEFORE-TX */
    portENTER_CRITICAL(&s_mux);
    if (!ninlil_usb_cdc_core_check_owner(&self->core, owner, out_error)) {
        portEXIT_CRITICAL(&s_mux);
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    portEXIT_CRITICAL(&s_mux);

    /* Initial nonblocking TX pump + snapshot (C1: at least one progress). */
    did_drain = drain_tx_nonblocking(self, owner, out_error);
    if (did_drain < 0) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    portENTER_CRITICAL(&s_mux);
    st = ninlil_usb_cdc_core_poll_snapshot(
        &self->core, owner, &events, out_error);
    if (st == NINLIL_BYTE_STREAM_OK && did_drain > 0
        && self->core.link == NINLIL_BYTE_STREAM_LINK_UP
        && self->core.tx.len == 0u) {
        events |= NINLIL_BYTE_STREAM_EVENT_TX_DRAINED;
    }
    portEXIT_CRITICAL(&s_mux);
    if (st != NINLIL_BYTE_STREAM_OK) {
        return st;
    }
    if (events != NINLIL_BYTE_STREAM_EVENT_NONE || timeout_ms == 0u) {
        if (out_events != NULL) {
            *out_events = events;
        }
        return NINLIL_BYTE_STREAM_OK;
    }

    /*
     * Budget: ceil(timeout_ms * configTICK_RATE_HZ / 1000) — arbitrary HZ,
     * not portTICK_PERIOD_MS integer divide.
     */
    budget = ninlil_usb_cdc_poll_required_ticks_hz(
        timeout_ms, (uint32_t)configTICK_RATE_HZ);

    /* Charge initial pump wall time against call-entry deadline. */
    now_tick = xTaskGetTickCount();
    if (ninlil_usb_cdc_poll_elapsed_reached(
            &elapsed, last_tick, now_tick, budget)) {
        goto poll_timeout;
    }
    last_tick = now_tick;

    for (;;) {
        uint32_t slice;
        uint64_t remain;

        now_tick = xTaskGetTickCount();
        if (ninlil_usb_cdc_poll_elapsed_reached(
                &elapsed, last_tick, now_tick, budget)) {
            break;
        }
        last_tick = now_tick;
        remain = budget - elapsed;
        slice = (remain > 10u) ? 10u : (uint32_t)remain;
        if (slice == 0u) {
            slice = 1u;
        }
        vTaskDelay((TickType_t)slice);

        /*
         * U2-POLL-RECHECK-BEFORE-IO: after delay, re-evaluate deadline before
         * any additional TX drain / driver I/O. timeout of 1 tick must not
         * perform a second I/O after the deadline has been reached.
         */
        now_tick = xTaskGetTickCount();
        if (ninlil_usb_cdc_poll_elapsed_reached(
                &elapsed, last_tick, now_tick, budget)) {
            break;
        }
        last_tick = now_tick;

        did_drain = drain_tx_nonblocking(self, owner, out_error);
        if (did_drain < 0) {
            return NINLIL_BYTE_STREAM_WRONG_OWNER;
        }
        portENTER_CRITICAL(&s_mux);
        st = ninlil_usb_cdc_core_poll_snapshot(
            &self->core, owner, &events, out_error);
        if (st == NINLIL_BYTE_STREAM_OK && did_drain > 0
            && self->core.link == NINLIL_BYTE_STREAM_LINK_UP
            && self->core.tx.len == 0u) {
            events |= NINLIL_BYTE_STREAM_EVENT_TX_DRAINED;
        }
        portEXIT_CRITICAL(&s_mux);
        if (st != NINLIL_BYTE_STREAM_OK) {
            return st;
        }
        if (events != NINLIL_BYTE_STREAM_EVENT_NONE) {
            if (out_events != NULL) {
                *out_events = events;
            }
            return NINLIL_BYTE_STREAM_OK;
        }
    }

poll_timeout:
    portENTER_CRITICAL(&s_mux);
    self->core.stats.poll_timeout_count = ninlil_byte_stream_sat_add_u64(
        self->core.stats.poll_timeout_count, 1u);
    portEXIT_CRITICAL(&s_mux);
    events |= NINLIL_BYTE_STREAM_EVENT_TIMEOUT;
    if (out_events != NULL) {
        *out_events = events;
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_link_t ninlil_esp_idf_usb_cdc_link(
    const ninlil_byte_stream_t *stream)
{
    const ninlil_esp_idf_usb_cdc_t *self = self_from_const(stream);
    ninlil_byte_stream_link_t link;
    uint64_t caller = current_owner_id();

    if (self == NULL) {
        return NINLIL_BYTE_STREAM_LINK_CLOSED;
    }
    portENTER_CRITICAL(&s_mux);
    if (!ninlil_usb_cdc_core_observer_allowed(&self->core, caller)) {
        portEXIT_CRITICAL(&s_mux);
        return NINLIL_BYTE_STREAM_LINK_CLOSED;
    }
    link = ninlil_usb_cdc_core_link_get(&self->core);
    portEXIT_CRITICAL(&s_mux);
    return link;
}

uint64_t ninlil_esp_idf_usb_cdc_link_generation(
    const ninlil_byte_stream_t *stream)
{
    const ninlil_esp_idf_usb_cdc_t *self = self_from_const(stream);
    uint64_t gen;
    uint64_t caller = current_owner_id();

    if (self == NULL) {
        return 0u;
    }
    portENTER_CRITICAL(&s_mux);
    if (!ninlil_usb_cdc_core_observer_allowed(&self->core, caller)) {
        portEXIT_CRITICAL(&s_mux);
        return 0u;
    }
    gen = ninlil_usb_cdc_core_generation_get(&self->core);
    portEXIT_CRITICAL(&s_mux);
    return gen;
}

void ninlil_esp_idf_usb_cdc_stats(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_stats_t *out_stats)
{
    const ninlil_esp_idf_usb_cdc_t *self = self_from_const(stream);
    uint64_t caller = current_owner_id();

    if (out_stats == NULL || self == NULL) {
        return;
    }
    portENTER_CRITICAL(&s_mux);
    if (!ninlil_usb_cdc_core_observer_allowed(&self->core, caller)) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    ninlil_usb_cdc_core_stats_copy(&self->core, out_stats);
    portEXIT_CRITICAL(&s_mux);
}

void ninlil_esp_idf_usb_cdc_last_error(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error)
{
    const ninlil_esp_idf_usb_cdc_t *self = self_from_const(stream);
    uint64_t caller = current_owner_id();

    if (out_error == NULL || self == NULL) {
        return;
    }
    portENTER_CRITICAL(&s_mux);
    if (!ninlil_usb_cdc_core_observer_allowed(&self->core, caller)) {
        portEXIT_CRITICAL(&s_mux);
        return;
    }
    ninlil_usb_cdc_core_last_error_copy(&self->core, out_error);
    portEXIT_CRITICAL(&s_mux);
}

static const ninlil_byte_stream_ops_t s_ops = {
    ninlil_esp_idf_usb_cdc_open,
    ninlil_esp_idf_usb_cdc_close,
    ninlil_esp_idf_usb_cdc_write,
    ninlil_esp_idf_usb_cdc_read,
    ninlil_esp_idf_usb_cdc_poll,
    ninlil_esp_idf_usb_cdc_link,
    ninlil_esp_idf_usb_cdc_link_generation,
    ninlil_esp_idf_usb_cdc_stats,
    ninlil_esp_idf_usb_cdc_last_error,
};

static const ninlil_byte_stream_ops_t *esp_usb_cdc_ops(void)
{
    return &s_ops;
}
