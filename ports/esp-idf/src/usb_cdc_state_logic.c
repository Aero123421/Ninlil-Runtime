#include "usb_cdc_state_logic.h"

#include <string.h>

static void error_clear(ninlil_byte_stream_error_t *err)
{
    if (err == NULL) {
        return;
    }
    (void)memset(err, 0, sizeof(*err));
}

static void error_set(
    ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    int sys_errno,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    error_clear(&local);
    local.status = status;
    local.stage = stage;
    local.sys_errno = (int32_t)sys_errno;
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
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static void sticky_teardown_error(
    ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    error_set(core, status, stage, 0, hint, out_error);
    if (core != NULL && !core->has_first_teardown_error) {
        core->first_teardown_error = core->last_error;
        core->has_first_teardown_error = 1;
    } else if (core != NULL && out_error != NULL && core->has_first_teardown_error) {
        /* Surface first sticky fact to caller while keeping last_error current. */
        *out_error = core->first_teardown_error;
    }
}

static void wrong_owner_out(
    const char *hint,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t local;

    if (out_error == NULL) {
        return;
    }
    error_clear(&local);
    local.status = NINLIL_BYTE_STREAM_WRONG_OWNER;
    local.stage = NINLIL_BYTE_STREAM_STAGE_OWNER;
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

static void copy_endpoint(ninlil_usb_cdc_core_t *core, const char *token)
{
    size_t n;

    (void)memset(core->endpoint, 0, sizeof(core->endpoint));
    if (token == NULL) {
        return;
    }
    n = strlen(token);
    if (n >= sizeof(core->endpoint)) {
        n = sizeof(core->endpoint) - 1u;
    }
    (void)memcpy(core->endpoint, token, n);
}

static void rings_bind(ninlil_usb_cdc_core_t *core)
{
    core->rx.bytes = core->rx_storage;
    core->rx.capacity = NINLIL_BYTE_STREAM_RING_BYTES;
    core->tx.bytes = core->tx_storage;
    core->tx.capacity = NINLIL_BYTE_STREAM_RING_BYTES;
}

static void rings_clear(ninlil_usb_cdc_core_t *core)
{
    ninlil_usb_cdc_ring_reset(&core->rx);
    ninlil_usb_cdc_ring_reset(&core->tx);
    core->stats.rx_ring_bytes = 0u;
    core->stats.tx_ring_bytes = 0u;
    core->rx_overflow_latched = 0;
    core->rx_overflow_event_pending = 0;
}

static void discard_rx_for_generation(ninlil_usb_cdc_core_t *core)
{
    uint32_t discarded = core->rx.len;

    if (discarded > 0u) {
        core->stats.generation_rx_discard_bytes =
            ninlil_byte_stream_sat_add_u64(
                core->stats.generation_rx_discard_bytes, (uint64_t)discarded);
    }
    ninlil_usb_cdc_ring_reset(&core->rx);
    core->stats.rx_ring_bytes = 0u;
    core->rx_overflow_latched = 0;
    core->rx_overflow_event_pending = 0;
}

static int physical_up(const ninlil_usb_cdc_core_t *core)
{
    return core->usb_attached != 0 && core->dtr_asserted != 0;
}

static int advance_generation(ninlil_usb_cdc_core_t *core)
{
    if (core->link_generation == UINT64_MAX) {
        return 0;
    }
    core->link_generation += 1u;
    if (core->link_generation == 0u) {
        /* u64 wrap to 0 is impossible after +1 from non-MAX without overflow;
         * keep fail-closed belt. */
        return 0;
    }
    return 1;
}

/* Advance epoch; 0 on wrap exhaustion (fail-closed). */
static int advance_epoch(ninlil_usb_cdc_core_t *core)
{
    if (core->callback_epoch == UINT32_MAX) {
        return 0;
    }
    core->callback_epoch += 1u;
    if (core->callback_epoch == 0u) {
        return 0;
    }
    return 1;
}

void ninlil_usb_cdc_core_init(ninlil_usb_cdc_core_t *core)
{
    if (core == NULL) {
        return;
    }
    (void)memset(core, 0, sizeof(*core));
    rings_bind(core);
    core->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
    core->lifecycle = NINLIL_USB_CDC_LC_CLOSED;
    core->callback_epoch = 1u;
    core->callback_admit = 0;
}

int ninlil_usb_cdc_endpoint_token_ok(const char *endpoint_token)
{
    if (endpoint_token == NULL || endpoint_token[0] == '\0') {
        return 1;
    }
    if (strlen(endpoint_token) != NINLIL_ESP_CDC_ENDPOINT_TOKEN_LEN) {
        return 0;
    }
    return memcmp(
               endpoint_token,
               NINLIL_ESP_CDC_ENDPOINT_TOKEN,
               NINLIL_ESP_CDC_ENDPOINT_TOKEN_LEN)
        == 0;
}

int ninlil_usb_cdc_core_generation_can_advance(
    const ninlil_usb_cdc_core_t *core)
{
    return core != NULL && core->link_generation != UINT64_MAX;
}

int ninlil_usb_cdc_core_check_owner(
    const ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    ninlil_byte_stream_error_t *out_error)
{
    if (core == NULL) {
        wrong_owner_out("null core", out_error);
        return 0;
    }
    if (!core->owner_set) {
        return 1;
    }
    if (core->owner_id != caller_id) {
        wrong_owner_out(
            "owner task mismatch; C1 APIs are single-owner only",
            out_error);
        return 0;
    }
    return 1;
}

int ninlil_usb_cdc_core_observer_allowed(
    const ninlil_usb_cdc_core_t *core,
    uint64_t caller_id)
{
    if (core == NULL) {
        return 0;
    }
    if (!core->owner_set) {
        /* Pre-open observers: allow init-time CLOSED snapshot. */
        return 1;
    }
    return core->owner_id == caller_id;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_core_open(
    ninlil_usb_cdc_core_t *core,
    const char *endpoint_token,
    uint64_t owner_id,
    ninlil_byte_stream_error_t *out_error)
{
    if (core == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    if (core->lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING) {
        if (core->owner_set
            && !ninlil_usb_cdc_core_check_owner(core, owner_id, out_error)) {
            return NINLIL_BYTE_STREAM_WRONG_OWNER;
        }
        sticky_teardown_error(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "open rejected: TEARDOWN_PENDING; retry close until logical park completes",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    if (core->owner_set && core->lifecycle != NINLIL_USB_CDC_LC_CLOSED) {
        if (!ninlil_usb_cdc_core_check_owner(core, owner_id, out_error)) {
            return NINLIL_BYTE_STREAM_WRONG_OWNER;
        }
    }

    if (core->lifecycle != NINLIL_USB_CDC_LC_CLOSED || core->stack_installed
        || core->cdc_inited) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "open only from CLOSED with driver fully released",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    if (!ninlil_usb_cdc_endpoint_token_ok(endpoint_token)) {
        copy_endpoint(core, endpoint_token != NULL ? endpoint_token : "");
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_ENDPOINT,
            0,
            "A2 endpoint_token must be empty/default or exact control-cdc "
            "(no fake /dev path)",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    if (!ninlil_usb_cdc_core_generation_can_advance(core)) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "link generation exhausted; cannot open without generation reuse",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    if (!advance_epoch(core)) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            0,
            "callback epoch exhausted; process restart required",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    error_clear(&core->last_error);
    core->has_first_teardown_error = 0;
    error_clear(&core->first_teardown_error);
    copy_endpoint(
        core,
        (endpoint_token == NULL || endpoint_token[0] == '\0')
            ? NINLIL_ESP_CDC_ENDPOINT_TOKEN
            : endpoint_token);

    rings_clear(core);
    core->usb_attached = 0;
    core->dtr_asserted = 0;
    core->link_down_event_pending = 0;
    core->link_up_event_pending = 0;
    core->partial_init_stage = 0;
    core->callback_inflight = 0u;
    core->callback_admit = 1;
    core->owner_id = owner_id;
    core->owner_set = 1;
    core->link = NINLIL_BYTE_STREAM_LINK_LISTENING;
    core->lifecycle = NINLIL_USB_CDC_LC_LIVE;
    core->stats.open_count =
        ninlil_byte_stream_sat_add_u64(core->stats.open_count, 1u);
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_core_begin_close_fence(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    ninlil_byte_stream_error_t *out_error)
{
    if (core == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            0,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    if (core->lifecycle == NINLIL_USB_CDC_LC_CLOSED && !core->stack_installed
        && !core->cdc_inited) {
        return NINLIL_BYTE_STREAM_OK;
    }

    if (core->owner_set
        && !ninlil_usb_cdc_core_check_owner(core, caller_id, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }

    /* Stop new callbacks first. */
    core->callback_admit = 0;
    if (!advance_epoch(core)) {
        core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
        sticky_teardown_error(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "callback epoch exhausted during close fence; TEARDOWN_PENDING",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    if (core->stack_installed || core->cdc_inited
        || core->lifecycle == NINLIL_USB_CDC_LC_LIVE
        || core->lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING) {
        core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
    }
    return NINLIL_BYTE_STREAM_OK;
}

int ninlil_usb_cdc_core_callbacks_drained(const ninlil_usb_cdc_core_t *core)
{
    return core != NULL && core->callback_inflight == 0u;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_core_apply_teardown_result(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    int had_cdc,
    int cdc_deinit_status,
    int had_driver,
    int uninstall_status,
    ninlil_byte_stream_error_t *out_error)
{
    if (core == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            0,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (core->owner_set
        && !ninlil_usb_cdc_core_check_owner(core, caller_id, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (!ninlil_usb_cdc_core_callbacks_drained(core)) {
        core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
        sticky_teardown_error(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "callbacks still in flight; TEARDOWN_PENDING",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }

    if (had_cdc) {
        if (cdc_deinit_status != 0) {
            /* Keep cdc_inited ownership; do not pretend deinit succeeded. */
            core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
            sticky_teardown_error(
                core,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_USB_STACK,
                "tinyusb_cdcacm_deinit failed; TEARDOWN_PENDING; retry close",
                out_error);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        core->cdc_inited = 0;
    }

    if (had_driver) {
        if (uninstall_status != 0) {
            core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
            sticky_teardown_error(
                core,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_USB_STACK,
                "tinyusb_driver_uninstall failed; TEARDOWN_PENDING; retry close",
                out_error);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        core->stack_installed = 0;
    }

    /* Full teardown success: safe CLOSED. */
    rings_clear(core);
    core->usb_attached = 0;
    core->dtr_asserted = 0;
    core->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
    core->lifecycle = NINLIL_USB_CDC_LC_CLOSED;
    core->owner_set = 0;
    core->owner_id = 0u;
    core->callback_admit = 0;
    core->callback_inflight = 0u;
    core->partial_init_stage = 0;
    core->link_down_event_pending = 0;
    core->link_up_event_pending = 0;
    core->stats.close_count =
        ninlil_byte_stream_sat_add_u64(core->stats.close_count, 1u);
    error_clear(&core->last_error);
    return NINLIL_BYTE_STREAM_OK;
}

void ninlil_usb_cdc_core_set_partial_stage(
    ninlil_usb_cdc_core_t *core,
    int stage)
{
    if (core != NULL) {
        core->partial_init_stage = stage;
    }
}

void ninlil_usb_cdc_core_mark_stack_installed(
    ninlil_usb_cdc_core_t *core,
    int on)
{
    if (core != NULL) {
        core->stack_installed = on != 0 ? 1 : 0;
    }
}

void ninlil_usb_cdc_core_mark_cdc_inited(ninlil_usb_cdc_core_t *core, int on)
{
    if (core != NULL) {
        core->cdc_inited = on != 0 ? 1 : 0;
    }
}

int ninlil_usb_cdc_core_callback_try_enter(
    ninlil_usb_cdc_core_t *core,
    uint32_t *out_captured_epoch)
{
    if (core == NULL || out_captured_epoch == NULL) {
        return 0;
    }
    if (!core->callback_admit
        || core->lifecycle != NINLIL_USB_CDC_LC_LIVE) {
        return 0;
    }
    if (core->callback_inflight == UINT32_MAX) {
        return 0;
    }
    core->callback_inflight += 1u;
    *out_captured_epoch = core->callback_epoch;
    return 1;
}

void ninlil_usb_cdc_core_callback_leave(ninlil_usb_cdc_core_t *core)
{
    if (core == NULL) {
        return;
    }
    if (core->callback_inflight > 0u) {
        core->callback_inflight -= 1u;
    }
}

ninlil_byte_stream_event_t ninlil_usb_cdc_core_apply_physical(
    ninlil_usb_cdc_core_t *core,
    uint32_t captured_epoch,
    int usb_attached,
    int dtr_asserted)
{
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    int was_up;
    int now_up;

    if (core == NULL) {
        return events;
    }
    if (core->lifecycle != NINLIL_USB_CDC_LC_LIVE) {
        return events;
    }
    if (captured_epoch != core->callback_epoch) {
        return events;
    }

    was_up = (core->link == NINLIL_BYTE_STREAM_LINK_UP);
    core->usb_attached = usb_attached != 0 ? 1 : 0;
    core->dtr_asserted = dtr_asserted != 0 ? 1 : 0;
    now_up = physical_up(core);

    if (now_up && !was_up) {
        if (!advance_generation(core)) {
            /*
             * Fail-closed: do not enter UP with exhausted generation.
             * Clear physical claim consistency: park DOWN (not UP).
             */
            core->usb_attached = 0;
            core->dtr_asserted = 0;
            core->link = NINLIL_BYTE_STREAM_LINK_DOWN;
            error_set(
                core,
                NINLIL_BYTE_STREAM_INVALID_STATE,
                NINLIL_BYTE_STREAM_STAGE_USB_LINK,
                0,
                "link generation exhausted on physical UP; non-UP fault",
                NULL);
            return events;
        }
        /* No stale bytes cross generations (account residual). */
        discard_rx_for_generation(core);
        ninlil_usb_cdc_ring_reset(&core->tx);
        core->stats.tx_ring_bytes = 0u;
        core->link = NINLIL_BYTE_STREAM_LINK_UP;
        core->stats.link_up_count =
            ninlil_byte_stream_sat_add_u64(core->stats.link_up_count, 1u);
        core->link_up_event_pending = 1;
        events |= NINLIL_BYTE_STREAM_EVENT_LINK_UP;
        return events;
    }

    if (!now_up && was_up) {
        core->link = NINLIL_BYTE_STREAM_LINK_DOWN;
        ninlil_usb_cdc_ring_reset(&core->tx);
        core->stats.tx_ring_bytes = 0u;
        core->stats.link_down_count =
            ninlil_byte_stream_sat_add_u64(core->stats.link_down_count, 1u);
        core->link_down_event_pending = 1;
        events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
        error_set(
            core,
            NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
            NINLIL_BYTE_STREAM_STAGE_USB_LINK,
            0,
            "physical USB detach or DTR deassert (host close)",
            NULL);
        return events;
    }
    return events;
}

uint32_t ninlil_usb_cdc_core_rx_ingress(
    ninlil_usb_cdc_core_t *core,
    uint32_t captured_epoch,
    const uint8_t *data,
    uint32_t length,
    ninlil_byte_stream_event_t *out_events)
{
    uint32_t accepted;
    uint32_t free_space;

    if (out_events != NULL) {
        *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
    }
    if (core == NULL || data == NULL || length == 0u) {
        return 0u;
    }
    if (core->lifecycle != NINLIL_USB_CDC_LC_LIVE) {
        return 0u;
    }
    if (captured_epoch != core->callback_epoch) {
        return 0u;
    }
    if (core->link != NINLIL_BYTE_STREAM_LINK_UP) {
        return 0u;
    }

    free_space = ninlil_usb_cdc_ring_free(&core->rx);
    if (free_space == 0u) {
        if (!core->rx_overflow_latched) {
            core->rx_overflow_latched = 1;
            core->stats.rx_overflow_count = ninlil_byte_stream_sat_add_u64(
                core->stats.rx_overflow_count, 1u);
            core->rx_overflow_event_pending = 1;
        }
        if (out_events != NULL && core->rx_overflow_event_pending) {
            *out_events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
        }
        error_set(
            core,
            NINLIL_BYTE_STREAM_RX_OVERFLOW,
            NINLIL_BYTE_STREAM_STAGE_RX_RING,
            0,
            "RX ring full; continuity loss (not physical link down)",
            NULL);
        return 0u;
    }

    accepted = ninlil_usb_cdc_ring_push(&core->rx, data, length);
    core->stats.rx_ring_bytes = core->rx.len;
    core->stats.rx_high_watermark = ninlil_byte_stream_sat_hwm_u32(
        core->stats.rx_high_watermark, core->rx.len);
    if (accepted < length) {
        if (!core->rx_overflow_latched) {
            core->rx_overflow_latched = 1;
            core->stats.rx_overflow_count = ninlil_byte_stream_sat_add_u64(
                core->stats.rx_overflow_count, 1u);
            core->rx_overflow_event_pending = 1;
        }
        if (out_events != NULL) {
            *out_events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
        }
        error_set(
            core,
            NINLIL_BYTE_STREAM_RX_OVERFLOW,
            NINLIL_BYTE_STREAM_STAGE_RX_RING,
            0,
            "RX ring saturated mid-copy; continuity loss (not link down)",
            NULL);
    }
    if (accepted > 0u && out_events != NULL) {
        *out_events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
    }
    return accepted;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_core_write(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error)
{
    uint32_t free_space;

    /* WRONG_OWNER before any out_* mutation. */
    if (core == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!ninlil_usb_cdc_core_check_owner(core, caller_id, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (out_accepted != NULL) {
        *out_accepted = 0u;
    }
    if (core->lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING) {
        sticky_teardown_error(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            "write rejected: TEARDOWN_PENDING",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (core->link == NINLIL_BYTE_STREAM_LINK_CLOSED
        || core->lifecycle == NINLIL_USB_CDC_LC_CLOSED) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "write on closed stream",
            out_error);
        return NINLIL_BYTE_STREAM_CLOSED;
    }
    if (core->link != NINLIL_BYTE_STREAM_LINK_UP) {
        if (core->link == NINLIL_BYTE_STREAM_LINK_DOWN) {
            error_set(
                core,
                NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
                NINLIL_BYTE_STREAM_STAGE_WRITE,
                0,
                "write while physical link down",
                out_error);
            return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
        }
        core->stats.would_block_count = ninlil_byte_stream_sat_add_u64(
            core->stats.would_block_count, 1u);
        error_set(
            core,
            NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "write while LISTENING (host not attached/DTR)",
            out_error);
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    if (length == 0u) {
        return NINLIL_BYTE_STREAM_OK;
    }
    if (data == NULL) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_WRITE,
            0,
            "null write buffer with nonzero length",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    free_space = ninlil_usb_cdc_ring_free(&core->tx);
    if (free_space < length) {
        core->stats.would_block_count = ninlil_byte_stream_sat_add_u64(
            core->stats.would_block_count, 1u);
        error_set(
            core,
            NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_TX_RING,
            0,
            "TX ring cannot admit whole write (all-or-none)",
            out_error);
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    (void)ninlil_usb_cdc_ring_push(&core->tx, data, length);
    core->stats.tx_ring_bytes = core->tx.len;
    core->stats.tx_high_watermark = ninlil_byte_stream_sat_hwm_u32(
        core->stats.tx_high_watermark, core->tx.len);
    if (out_accepted != NULL) {
        *out_accepted = length;
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_core_read(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error)
{
    uint32_t n;

    if (core == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!ninlil_usb_cdc_core_check_owner(core, caller_id, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (core->lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING) {
        sticky_teardown_error(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_READ,
            "read rejected: TEARDOWN_PENDING",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (core->link == NINLIL_BYTE_STREAM_LINK_CLOSED
        || core->lifecycle == NINLIL_USB_CDC_LC_CLOSED) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "read on closed stream",
            out_error);
        return NINLIL_BYTE_STREAM_CLOSED;
    }
    if (capacity == 0u) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "capacity == 0 is INVALID_ARGUMENT",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (out_data == NULL) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ,
            0,
            "null read buffer",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    if (core->link == NINLIL_BYTE_STREAM_LINK_DOWN) {
        if (core->rx.len == 0u) {
            error_set(
                core,
                NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
                NINLIL_BYTE_STREAM_STAGE_READ,
                0,
                "link down and RX empty",
                out_error);
            return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
        }
        n = ninlil_usb_cdc_ring_pop(&core->rx, out_data, capacity);
        core->stats.rx_ring_bytes = core->rx.len;
        core->stats.bytes_read =
            ninlil_byte_stream_sat_add_u64(core->stats.bytes_read, (uint64_t)n);
        if (out_length != NULL) {
            *out_length = n;
        }
        return NINLIL_BYTE_STREAM_OK;
    }

    n = ninlil_usb_cdc_ring_pop(&core->rx, out_data, capacity);
    core->stats.rx_ring_bytes = core->rx.len;
    core->stats.bytes_read =
        ninlil_byte_stream_sat_add_u64(core->stats.bytes_read, (uint64_t)n);
    if (out_length != NULL) {
        *out_length = n;
    }
    return NINLIL_BYTE_STREAM_OK;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_core_poll_snapshot(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;

    if (core == NULL) {
        error_set(
            NULL,
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            0,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!ninlil_usb_cdc_core_check_owner(core, caller_id, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (core->lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING) {
        sticky_teardown_error(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            "poll rejected: TEARDOWN_PENDING",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (core->link == NINLIL_BYTE_STREAM_LINK_CLOSED
        || core->lifecycle == NINLIL_USB_CDC_LC_CLOSED) {
        error_set(
            core,
            NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_POLL,
            0,
            "poll on closed stream",
            out_error);
        return NINLIL_BYTE_STREAM_CLOSED;
    }

    /* One-shot pending events (cleared when observed). */
    if (core->link_up_event_pending) {
        events |= NINLIL_BYTE_STREAM_EVENT_LINK_UP;
        core->link_up_event_pending = 0;
    }
    if (core->link_down_event_pending) {
        events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
        core->link_down_event_pending = 0;
    }
    if (core->rx_overflow_event_pending) {
        events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
        core->rx_overflow_event_pending = 0;
    }
    if (core->rx.len > 0u) {
        events |= NINLIL_BYTE_STREAM_EVENT_READABLE;
    }
    /* WRITABLE only while physically UP (not LISTENING/DOWN). */
    if (core->link == NINLIL_BYTE_STREAM_LINK_UP
        && ninlil_usb_cdc_ring_free(&core->tx) > 0u) {
        events |= NINLIL_BYTE_STREAM_EVENT_WRITABLE;
    }
    /* TX_DRAINED is not sticky here; backend may OR it after a successful drain. */
    if (out_events != NULL) {
        *out_events = events;
    }
    return NINLIL_BYTE_STREAM_OK;
}

uint32_t ninlil_usb_cdc_core_tx_drain_peek(
    ninlil_usb_cdc_core_t *core,
    uint8_t *out,
    uint32_t max_bytes)
{
    if (core == NULL || out == NULL || max_bytes == 0u) {
        return 0u;
    }
    if (core->link != NINLIL_BYTE_STREAM_LINK_UP) {
        return 0u;
    }
    return ninlil_usb_cdc_ring_peek(&core->tx, out, max_bytes);
}

void ninlil_usb_cdc_core_tx_drain_commit(
    ninlil_usb_cdc_core_t *core,
    uint32_t accepted_by_driver)
{
    if (core == NULL || accepted_by_driver == 0u) {
        return;
    }
    ninlil_usb_cdc_ring_consume(&core->tx, accepted_by_driver);
    core->stats.tx_ring_bytes = core->tx.len;
    core->stats.bytes_written = ninlil_byte_stream_sat_add_u64(
        core->stats.bytes_written, (uint64_t)accepted_by_driver);
}

ninlil_byte_stream_link_t ninlil_usb_cdc_core_link_get(
    const ninlil_usb_cdc_core_t *core)
{
    if (core == NULL) {
        return NINLIL_BYTE_STREAM_LINK_CLOSED;
    }
    return core->link;
}

uint64_t ninlil_usb_cdc_core_generation_get(
    const ninlil_usb_cdc_core_t *core)
{
    if (core == NULL) {
        return 0u;
    }
    return core->link_generation;
}

void ninlil_usb_cdc_core_stats_copy(
    const ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_stats_t *out_stats)
{
    if (out_stats == NULL || core == NULL) {
        return;
    }
    *out_stats = core->stats;
}

void ninlil_usb_cdc_core_last_error_copy(
    const ninlil_usb_cdc_core_t *core,
    ninlil_byte_stream_error_t *out_error)
{
    if (out_error == NULL || core == NULL) {
        return;
    }
    *out_error = core->last_error;
}

void ninlil_usb_cdc_core_test_force_generation(
    ninlil_usb_cdc_core_t *core,
    uint64_t generation)
{
    if (core != NULL) {
        core->link_generation = generation;
    }
}

void ninlil_usb_cdc_core_test_force_epoch(
    ninlil_usb_cdc_core_t *core,
    uint32_t epoch)
{
    if (core != NULL) {
        core->callback_epoch = epoch;
    }
}
