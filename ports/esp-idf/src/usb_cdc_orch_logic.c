#include "usb_cdc_orch_logic.h"

#include <stdint.h>
#include <string.h>

/* ---- ranges ------------------------------------------------------------ */

int ninlil_usb_cdc_range_valid(const ninlil_usb_cdc_addr_range_t *r)
{
    if (r == NULL || r->bytes == 0u) {
        return 0;
    }
    if (r->base > UINT64_MAX - r->bytes) {
        return 0; /* wrap */
    }
    return 1;
}

int ninlil_usb_cdc_range_valid_in_space(
    const ninlil_usb_cdc_addr_range_t *r,
    uint64_t addr_max)
{
    uint64_t last;

    if (!ninlil_usb_cdc_range_valid(r)) {
        return 0;
    }
    if (r->base > addr_max) {
        return 0;
    }
    /* last byte index = base + bytes - 1 must be <= addr_max */
    last = r->base + r->bytes - 1u;
    if (last > addr_max) {
        return 0;
    }
    return 1;
}

int ninlil_usb_cdc_ranges_overlap(
    const ninlil_usb_cdc_addr_range_t *a,
    const ninlil_usb_cdc_addr_range_t *b)
{
    uint64_t a_end;
    uint64_t b_end;

    if (!ninlil_usb_cdc_range_valid(a) || !ninlil_usb_cdc_range_valid(b)) {
        return 1; /* fail-closed */
    }
    a_end = a->base + a->bytes;
    b_end = b->base + b->bytes;
    /* half-open: adjacent (a_end == b->base) does NOT overlap */
    return (a->base < b_end) && (b->base < a_end);
}

/* ---- sticky / lock helpers -------------------------------------------- */

static void sticky(
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
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static void sticky_teardown(
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
        if (!core->has_first_teardown_error) {
            core->first_teardown_error = local;
            core->has_first_teardown_error = 1;
        }
        if (out_error != NULL) {
            *out_error = core->first_teardown_error;
            return;
        }
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static void out_error_only(
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

static void ops_lock(const ninlil_usb_cdc_driver_ops_t *ops)
{
    if (ops != NULL && ops->state_lock != NULL) {
        ops->state_lock(ops->user);
    }
}

static void ops_unlock(const ninlil_usb_cdc_driver_ops_t *ops)
{
    if (ops != NULL && ops->state_unlock != NULL) {
        ops->state_unlock(ops->user);
    }
}

static int ops_wait_drained(
    ninlil_usb_cdc_core_t *core,
    const ninlil_usb_cdc_driver_ops_t *ops)
{
    if (ops != NULL && ops->wait_callbacks_drained != NULL) {
        return ops->wait_callbacks_drained(ops->user) ? 1 : 0;
    }
    return ninlil_usb_cdc_core_callbacks_drained(core);
}

/* ---- global ------------------------------------------------------------ */

void ninlil_usb_cdc_global_init(ninlil_usb_cdc_global_res_t *g)
{
    if (g == NULL) {
        return;
    }
    (void)memset(g, 0, sizeof(*g));
    g->service = NINLIL_USB_CDC_SVC_ABSENT;
    g->state = NINLIL_USB_CDC_BIND_FREE;
}

int ninlil_usb_cdc_global_try_begin_install(
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id)
{
    if (g == NULL || id == 0u) {
        return 0;
    }
    if (g->service == NINLIL_USB_CDC_SVC_POISONED) {
        return 0;
    }
    if (g->state != NINLIL_USB_CDC_BIND_FREE) {
        return 0;
    }
    g->state = NINLIL_USB_CDC_BIND_CLAIMING;
    g->reserved_id = id;
    return 1;
}

void ninlil_usb_cdc_global_mark_active(
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id)
{
    if (g == NULL) {
        return;
    }
    if (g->state == NINLIL_USB_CDC_BIND_CLAIMING && g->reserved_id == id) {
        g->state = NINLIL_USB_CDC_BIND_BOUND;
    }
}

int ninlil_usb_cdc_global_try_begin_teardown(
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id)
{
    if (g == NULL) {
        return 0;
    }
    if (g->reserved_id != id) {
        return 0;
    }
    if (g->state != NINLIL_USB_CDC_BIND_BOUND
        && g->state != NINLIL_USB_CDC_BIND_POISONED
        && g->state != NINLIL_USB_CDC_BIND_PARKING) {
        return 0;
    }
    g->state = NINLIL_USB_CDC_BIND_PARKING;
    return 1;
}

void ninlil_usb_cdc_global_teardown_success(ninlil_usb_cdc_global_res_t *g)
{
    if (g == NULL) {
        return;
    }
    g->state = NINLIL_USB_CDC_BIND_FREE;
    g->reserved_id = 0u;
    g->live_storage.base = 0u;
    g->live_storage.bytes = 0u;
    /* service stays READY if already ready */
}

void ninlil_usb_cdc_global_teardown_fail(ninlil_usb_cdc_global_res_t *g)
{
    if (g == NULL) {
        return;
    }
    if (g->state == NINLIL_USB_CDC_BIND_PARKING
        || g->state == NINLIL_USB_CDC_BIND_CLAIMING) {
        g->state = NINLIL_USB_CDC_BIND_POISONED;
    }
}

void ninlil_usb_cdc_global_install_abort(ninlil_usb_cdc_global_res_t *g)
{
    if (g == NULL) {
        return;
    }
    if (g->state == NINLIL_USB_CDC_BIND_CLAIMING) {
        g->state = NINLIL_USB_CDC_BIND_FREE;
        g->reserved_id = 0u;
        g->live_storage.base = 0u;
        g->live_storage.bytes = 0u;
    }
}

void ninlil_usb_cdc_global_set_live_storage(
    ninlil_usb_cdc_global_res_t *g,
    const ninlil_usb_cdc_addr_range_t *storage)
{
    if (g == NULL) {
        return;
    }
    if (storage == NULL) {
        g->live_storage.base = 0u;
        g->live_storage.bytes = 0u;
        return;
    }
    g->live_storage = *storage;
}

void ninlil_usb_cdc_global_clear_live_storage(ninlil_usb_cdc_global_res_t *g)
{
    if (g == NULL) {
        return;
    }
    g->live_storage.base = 0u;
    g->live_storage.bytes = 0u;
}

uint64_t ninlil_usb_cdc_global_bump_physical_seq(ninlil_usb_cdc_global_res_t *g)
{
    if (g == NULL) {
        return 0u;
    }
    if (g->physical_event_seq == UINT64_MAX) {
        return g->physical_event_seq;
    }
    g->physical_event_seq += 1u;
    return g->physical_event_seq;
}

int ninlil_usb_cdc_reconcile_physical_if_seq(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_global_res_t *g,
    uint64_t captured_seq,
    uint32_t captured_epoch,
    int usb_attached,
    int dtr_asserted)
{
    if (core == NULL || g == NULL) {
        return 0;
    }
    /*
     * UINT64_MAX is a saturated / non-advancing seq: never apply a hardware
     * snapshot under it (stale snapshot must not win; fail-closed skip).
     */
    if (captured_seq == UINT64_MAX || g->physical_event_seq == UINT64_MAX) {
        return 0;
    }
    if (g->physical_event_seq != captured_seq) {
        return 0;
    }
    (void)ninlil_usb_cdc_core_apply_physical(
        core, captured_epoch, usb_attached, dtr_asserted);
    return 1;
}

int ninlil_usb_cdc_rx_should_ingress(int live_bound, int admit_entered)
{
    return (live_bound && admit_entered) ? 1 : 0;
}

uint64_t ninlil_usb_cdc_note_physical_event(
    ninlil_usb_cdc_global_res_t *g,
    int live_bound)
{
    (void)live_bound; /* events always bump, bound or not */
    return ninlil_usb_cdc_global_bump_physical_seq(g);
}

/* ---- TX ticket --------------------------------------------------------- */

uint32_t ninlil_usb_cdc_core_tx_drain_begin(
    ninlil_usb_cdc_core_t *core,
    uint8_t *out,
    uint32_t max_bytes,
    ninlil_usb_cdc_tx_ticket_t *ticket)
{
    uint32_t n;

    if (ticket != NULL) {
        (void)memset(ticket, 0, sizeof(*ticket));
    }
    if (core == NULL || out == NULL || max_bytes == 0u || ticket == NULL) {
        return 0u;
    }
    if (core->link != NINLIL_BYTE_STREAM_LINK_UP
        || core->lifecycle != NINLIL_USB_CDC_LC_LIVE) {
        return 0u;
    }
    n = ninlil_usb_cdc_ring_peek(&core->tx, out, max_bytes);
    if (n == 0u) {
        return 0u;
    }
    ticket->n = n;
    ticket->link_generation = core->link_generation;
    ticket->callback_epoch = core->callback_epoch;
    ticket->valid = 1;
    return n;
}

int ninlil_usb_cdc_core_tx_drain_finish(
    ninlil_usb_cdc_core_t *core,
    const ninlil_usb_cdc_tx_ticket_t *ticket,
    uint32_t queued_by_driver)
{
    uint32_t consume;

    if (core == NULL || ticket == NULL || !ticket->valid) {
        return 0;
    }
    if (queued_by_driver == 0u) {
        return 0;
    }
    if (core->link != NINLIL_BYTE_STREAM_LINK_UP
        || core->lifecycle != NINLIL_USB_CDC_LC_LIVE
        || core->link_generation != ticket->link_generation
        || core->callback_epoch != ticket->callback_epoch) {
        core->stats.tx_driver_stale_accepted = ninlil_byte_stream_sat_add_u64(
            core->stats.tx_driver_stale_accepted, (uint64_t)queued_by_driver);
        return 0;
    }
    consume = queued_by_driver;
    if (consume > ticket->n) {
        consume = ticket->n;
    }
    if (consume > core->tx.len) {
        core->stats.tx_driver_stale_accepted = ninlil_byte_stream_sat_add_u64(
            core->stats.tx_driver_stale_accepted, (uint64_t)queued_by_driver);
        return 0;
    }
    ninlil_usb_cdc_ring_consume(&core->tx, consume);
    core->stats.tx_ring_bytes = core->tx.len;
    core->stats.bytes_written = ninlil_byte_stream_sat_add_u64(
        core->stats.bytes_written, (uint64_t)consume);
    return 1;
}

/* ---- open preflight ---------------------------------------------------- */

ninlil_byte_stream_status_t ninlil_usb_cdc_open_preflight(
    const ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error)
{
    if (core == NULL) {
        out_error_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "null core",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (core->owner_set && core->owner_id != caller_id
        && core->lifecycle != NINLIL_USB_CDC_LC_CLOSED) {
        out_error_only(
            NINLIL_BYTE_STREAM_WRONG_OWNER,
            NINLIL_BYTE_STREAM_STAGE_OWNER,
            "open preflight wrong owner",
            out_error);
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (core->lifecycle == NINLIL_USB_CDC_LC_LIVE
        || core->lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING) {
        out_error_only(
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "open preflight: already live/pending",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (!ninlil_usb_cdc_endpoint_token_ok(endpoint_token)) {
        out_error_only(
            NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_ENDPOINT,
            "bad endpoint_token",
            out_error);
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    return NINLIL_BYTE_STREAM_OK;
}

/* ---- install (service ensure + bind) ---------------------------------- */

ninlil_byte_stream_status_t ninlil_usb_cdc_orch_install(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id,
    uint64_t owner_id,
    const ninlil_usb_cdc_driver_ops_t *ops,
    ninlil_byte_stream_error_t *out_error)
{
    int st;
    int drained;
    int need_install = 0;
    int need_cdc = 0;

    if (core == NULL || g == NULL || ops == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    ops_lock(ops);
    if (core->lifecycle != NINLIL_USB_CDC_LC_LIVE
        || !core->owner_set || core->owner_id != owner_id) {
        sticky(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN,
            "orch install requires LIVE owned core",
            out_error);
        ops_unlock(ops);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (g->state != NINLIL_USB_CDC_BIND_CLAIMING || g->reserved_id != id) {
        sticky(
            core,
            NINLIL_BYTE_STREAM_BUSY,
            NINLIL_BYTE_STREAM_STAGE_USB_STACK,
            "global reservation not CLAIMING for this id",
            out_error);
        ops_unlock(ops);
        return NINLIL_BYTE_STREAM_BUSY;
    }
    if (g->service == NINLIL_USB_CDC_SVC_POISONED) {
        sticky(
            core,
            NINLIL_BYTE_STREAM_BUSY,
            NINLIL_BYTE_STREAM_STAGE_USB_STACK,
            "USB CDC service poisoned; reboot required (V1)",
            out_error);
        ops_unlock(ops);
        return NINLIL_BYTE_STREAM_BUSY;
    }
    if (g->service == NINLIL_USB_CDC_SVC_ABSENT) {
        need_install = 1;
        need_cdc = 1;
        g->service = NINLIL_USB_CDC_SVC_STARTING;
    } else if (g->service == NINLIL_USB_CDC_SVC_STARTING) {
        /* Stack may exist without CDC after partial; try cdc only. */
        need_cdc = 1;
    } else if (g->service == NINLIL_USB_CDC_SVC_READY) {
        need_install = 0;
        need_cdc = 0;
    }
    ops_unlock(ops);

    if (need_install) {
        if (ops->driver_install == NULL) {
            ops_lock(ops);
            g->service = NINLIL_USB_CDC_SVC_POISONED;
            ninlil_usb_cdc_global_teardown_fail(g);
            sticky(
                core,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_USB_STACK,
                "driver_install op missing",
                out_error);
            ops_unlock(ops);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        st = ops->driver_install(ops->user); /* depth 0 */
        if (st != 0) {
            ops_lock(ops);
            g->service = NINLIL_USB_CDC_SVC_ABSENT;
            ninlil_usb_cdc_global_install_abort(g);
            core->stack_installed = 0;
            core->cdc_inited = 0;
            core->lifecycle = NINLIL_USB_CDC_LC_CLOSED;
            core->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
            core->owner_set = 0;
            core->callback_admit = 0;
            sticky(
                core,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_USB_STACK,
                "driver_install failed",
                out_error);
            ops_unlock(ops);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        ops_lock(ops);
        core->stack_installed = 1;
        core->partial_init_stage = 1;
        ops_unlock(ops);
    }

    if (need_cdc) {
        if (ops->cdc_init == NULL) {
            ops_lock(ops);
            g->service = NINLIL_USB_CDC_SVC_POISONED;
            ninlil_usb_cdc_global_teardown_fail(g);
            sticky(
                core,
                NINLIL_BYTE_STREAM_IO_ERROR,
                NINLIL_BYTE_STREAM_STAGE_USB_STACK,
                "cdc_init op missing",
                out_error);
            ops_unlock(ops);
            return NINLIL_BYTE_STREAM_IO_ERROR;
        }
        st = ops->cdc_init(ops->user); /* depth 0 */
        if (st != 0) {
            /*
             * Do NOT uninstall/deinit (upstream UAF). Fence + drain; poison
             * service so V1 will not claim USB again without reboot.
             */
            ops_lock(ops);
            (void)ninlil_usb_cdc_core_begin_close_fence(core, owner_id, NULL);
            (void)ninlil_usb_cdc_global_try_begin_teardown(g, id);
            ops_unlock(ops);
            drained = ops_wait_drained(core, ops);
            ops_lock(ops);
            g->service = NINLIL_USB_CDC_SVC_POISONED;
            core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
            ninlil_usb_cdc_global_teardown_fail(g);
            sticky_teardown(
                core,
                drained ? NINLIL_BYTE_STREAM_IO_ERROR
                        : NINLIL_BYTE_STREAM_INVALID_STATE,
                NINLIL_BYTE_STREAM_STAGE_USB_STACK,
                drained
                    ? "cdc_init failed; service POISONED (no uninstall V1)"
                    : "cdc_init failed; callbacks not drained; service POISONED",
                out_error);
            ops_unlock(ops);
            return drained ? NINLIL_BYTE_STREAM_IO_ERROR
                           : NINLIL_BYTE_STREAM_INVALID_STATE;
        }
        ops_lock(ops);
        core->cdc_inited = 1;
        core->partial_init_stage = 3;
        g->service = NINLIL_USB_CDC_SVC_READY;
        ops_unlock(ops);
    }

    ops_lock(ops);
    /* Bind success: mark stack/cdc ownership facts for already-ready service. */
    if (g->service == NINLIL_USB_CDC_SVC_READY) {
        core->stack_installed = 1;
        core->cdc_inited = 1;
        core->partial_init_stage = 3;
    }
    ninlil_usb_cdc_global_mark_active(g, id);
    ops_unlock(ops);
    return NINLIL_BYTE_STREAM_OK;
}

/* ---- logical park (no deinit/uninstall) -------------------------------- */

ninlil_byte_stream_status_t ninlil_usb_cdc_orch_teardown(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_global_res_t *g,
    uint64_t id,
    uint64_t owner_id,
    int callbacks_drained,
    const ninlil_usb_cdc_driver_ops_t *ops,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_status_t st;

    if (core == NULL || g == NULL || ops == NULL || id == 0u) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }

    ops_lock(ops);
    if (g->reserved_id != id || g->state != NINLIL_USB_CDC_BIND_PARKING) {
        ops_unlock(ops);
        out_error_only(
            NINLIL_BYTE_STREAM_BUSY,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "orch park rejected: bind id/state mismatch",
            out_error);
        return NINLIL_BYTE_STREAM_BUSY;
    }
    if (core->owner_set && core->owner_id != owner_id) {
        ops_unlock(ops);
        out_error_only(
            NINLIL_BYTE_STREAM_WRONG_OWNER,
            NINLIL_BYTE_STREAM_STAGE_OWNER,
            "orch park wrong owner",
            out_error);
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (!callbacks_drained) {
        core->lifecycle = NINLIL_USB_CDC_LC_TEARDOWN_PENDING;
        ninlil_usb_cdc_global_teardown_fail(g);
        sticky_teardown(
            core,
            NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_CLOSE,
            "callbacks not drained; PARK POISONED",
            out_error);
        ops_unlock(ops);
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    ops_unlock(ops);

    /* Soft FIFO clear outside lock; service stays READY (no free). */
    if (ops->tx_fifo_soft_clear != NULL) {
        ops->tx_fifo_soft_clear(ops->user);
    }
    if (ops->rx_fifo_soft_flush != NULL) {
        ops->rx_fifo_soft_flush(ops->user);
    }

    ops_lock(ops);
    /*
     * Logical close: release Ninlil ownership flags without telling TinyUSB
     * to free ACM (V1 persistent service). apply_teardown with no residual
     * driver bits still transitions core to CLOSED.
     */
    core->cdc_inited = 0;
    core->stack_installed = 0;
    st = ninlil_usb_cdc_core_apply_teardown_result(
        core, owner_id, 0, 0, 0, 0, out_error);
    if (st != NINLIL_BYTE_STREAM_OK) {
        ninlil_usb_cdc_global_teardown_fail(g);
        ops_unlock(ops);
        return st;
    }
    ninlil_usb_cdc_global_clear_live_storage(g);
    ninlil_usb_cdc_global_teardown_success(g);
    /* service remains READY if it was READY */
    ops_unlock(ops);
    return NINLIL_BYTE_STREAM_OK;
}

/* ---- closed-idle / init ranges ---------------------------------------- */

int ninlil_usb_cdc_closed_idle_close_policy(
    const ninlil_usb_cdc_core_t *core,
    const ninlil_usb_cdc_global_res_t *g,
    uint64_t id)
{
    if (core == NULL || g == NULL || id == 0u) {
        return 0;
    }
    if (core->lifecycle != NINLIL_USB_CDC_LC_CLOSED
        || core->stack_installed || core->cdc_inited) {
        return 0;
    }
    if (g->reserved_id == id && g->state != NINLIL_USB_CDC_BIND_FREE) {
        return -1;
    }
    return 1;
}

int ninlil_usb_cdc_init_storage_may_wipe(
    uint64_t storage_id,
    const ninlil_usb_cdc_global_res_t *g,
    uint64_t live_id)
{
    ninlil_usb_cdc_addr_range_t storage;
    ninlil_usb_cdc_addr_range_t live;

    if (storage_id == 0u) {
        return 0;
    }
    storage.base = storage_id;
    storage.bytes = 1u; /* legacy single-address probe */
    if (live_id != 0u) {
        live.base = live_id;
        live.bytes = 1u;
    } else if (g != NULL && g->live_storage.bytes > 0u) {
        live = g->live_storage;
    } else {
        live.base = 0u;
        live.bytes = 0u;
    }
    return ninlil_usb_cdc_init_ranges_may_claim(
        &storage, NULL, g, live.bytes > 0u ? &live : NULL);
}

int ninlil_usb_cdc_init_ranges_may_claim_in_space(
    const ninlil_usb_cdc_addr_range_t *storage,
    const ninlil_usb_cdc_addr_range_t *out_stream,
    const ninlil_usb_cdc_global_res_t *g,
    const ninlil_usb_cdc_addr_range_t *live_storage,
    uint64_t addr_max)
{
    ninlil_usb_cdc_addr_range_t reserved;

    /* ESP/host pointer objects: reject base+bytes past address-space ceiling. */
    if (!ninlil_usb_cdc_range_valid_in_space(storage, addr_max)) {
        return 0;
    }
    if (out_stream != NULL) {
        if (!ninlil_usb_cdc_range_valid_in_space(out_stream, addr_max)) {
            return 0;
        }
        if (ninlil_usb_cdc_ranges_overlap(storage, out_stream)) {
            return 0;
        }
    }
    if (live_storage != NULL && live_storage->bytes > 0u) {
        if (!ninlil_usb_cdc_range_valid_in_space(live_storage, addr_max)) {
            return 0;
        }
        if (ninlil_usb_cdc_ranges_overlap(storage, live_storage)) {
            return 0;
        }
        if (out_stream != NULL
            && ninlil_usb_cdc_ranges_overlap(out_stream, live_storage)) {
            return 0;
        }
    }
    if (g != NULL && g->state != NINLIL_USB_CDC_BIND_FREE
        && g->live_storage.bytes > 0u) {
        if (ninlil_usb_cdc_ranges_overlap(storage, &g->live_storage)) {
            return 0;
        }
        if (out_stream != NULL
            && ninlil_usb_cdc_ranges_overlap(out_stream, &g->live_storage)) {
            return 0;
        }
    }
    if (g != NULL && g->state != NINLIL_USB_CDC_BIND_FREE
        && g->reserved_id != 0u) {
        /* reserved_id is object identity; also treat as 1-byte range if no live */
        if (g->live_storage.bytes == 0u) {
            reserved.base = g->reserved_id;
            reserved.bytes = 1u;
            if (ninlil_usb_cdc_ranges_overlap(storage, &reserved)) {
                return 0;
            }
            if (out_stream != NULL
                && ninlil_usb_cdc_ranges_overlap(out_stream, &reserved)) {
                return 0;
            }
        }
    }
    return 1;
}

int ninlil_usb_cdc_init_ranges_may_claim(
    const ninlil_usb_cdc_addr_range_t *storage,
    const ninlil_usb_cdc_addr_range_t *out_stream,
    const ninlil_usb_cdc_global_res_t *g,
    const ninlil_usb_cdc_addr_range_t *live_storage)
{
    /* Production: pointer-width ceiling (ESP32 = 32-bit, host may be 64). */
    return ninlil_usb_cdc_init_ranges_may_claim_in_space(
        storage,
        out_stream,
        g,
        live_storage,
        (uint64_t)UINTPTR_MAX);
}

/* ---- once / soft-clear / poll ----------------------------------------- */

void ninlil_usb_cdc_once_init(ninlil_usb_cdc_once_t *o)
{
    if (o == NULL) {
        return;
    }
    o->state = NINLIL_USB_CDC_ONCE_FREE;
    o->handle = NULL;
}

int ninlil_usb_cdc_once_claim_create(ninlil_usb_cdc_once_t *o)
{
    if (o == NULL) {
        return 0;
    }
    if (o->state == NINLIL_USB_CDC_ONCE_READY) {
        return -1;
    }
    if (o->state == NINLIL_USB_CDC_ONCE_CREATING) {
        return 0;
    }
    o->state = NINLIL_USB_CDC_ONCE_CREATING;
    return 1;
}

void ninlil_usb_cdc_once_mark_ready(ninlil_usb_cdc_once_t *o, void *handle)
{
    if (o == NULL) {
        return;
    }
    o->handle = handle;
    o->state = NINLIL_USB_CDC_ONCE_READY;
}

void ninlil_usb_cdc_once_mark_failed(ninlil_usb_cdc_once_t *o)
{
    if (o == NULL) {
        return;
    }
    o->handle = NULL;
    o->state = NINLIL_USB_CDC_ONCE_FREE;
}

void ninlil_usb_cdc_cb_soft_work_reset(ninlil_usb_cdc_cb_soft_work_t *w)
{
    if (w != NULL) {
        (void)memset(w, 0, sizeof(*w));
    }
}

void ninlil_usb_cdc_cb_soft_work_enter(
    ninlil_usb_cdc_cb_soft_work_t *w,
    int need_soft_clear)
{
    if (w == NULL) {
        return;
    }
    w->active = 1;
    w->need_soft_clear = need_soft_clear ? 1 : 0;
    w->soft_clear_done = 0;
    w->left = 0;
}

void ninlil_usb_cdc_cb_soft_work_mark_soft_clear_done(
    ninlil_usb_cdc_cb_soft_work_t *w)
{
    if (w != NULL) {
        w->soft_clear_done = 1;
    }
}

int ninlil_usb_cdc_cb_soft_work_may_leave(
    const ninlil_usb_cdc_cb_soft_work_t *w)
{
    if (w == NULL || !w->active || w->left) {
        return 0;
    }
    if (w->need_soft_clear && !w->soft_clear_done) {
        return 0;
    }
    return 1;
}

int ninlil_usb_cdc_cb_soft_work_leave(
    ninlil_usb_cdc_core_t *core,
    ninlil_usb_cdc_cb_soft_work_t *w)
{
    if (core == NULL || w == NULL) {
        return 0;
    }
    if (!ninlil_usb_cdc_cb_soft_work_may_leave(w)) {
        return 0;
    }
    ninlil_usb_cdc_core_callback_leave(core);
    w->left = 1;
    w->active = 0;
    return 1;
}

ninlil_byte_stream_status_t ninlil_usb_cdc_poll_owner_before_tx(
    ninlil_usb_cdc_core_t *core,
    uint64_t caller_id,
    uint32_t (*tx_queue)(void *user, const uint8_t *data, uint32_t n),
    void *tx_user,
    const uint8_t *peek_data,
    uint32_t peek_n,
    uint32_t *out_queued,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error)
{
    uint32_t q = 0u;

    if (core == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!ninlil_usb_cdc_core_check_owner(core, caller_id, out_error)) {
        return NINLIL_BYTE_STREAM_WRONG_OWNER;
    }
    if (out_queued != NULL) {
        *out_queued = 0u;
    }
    if (tx_queue != NULL && peek_data != NULL && peek_n > 0u) {
        q = tx_queue(tx_user, peek_data, peek_n);
        if (out_queued != NULL) {
            *out_queued = q;
        }
    }
    if (out_events != NULL) {
        *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
    }
    (void)q;
    return NINLIL_BYTE_STREAM_OK;
}

uint64_t ninlil_usb_cdc_poll_required_ticks(
    uint32_t timeout_ms,
    uint32_t ms_per_tick)
{
    uint64_t t;
    uint64_t m;
    uint64_t ticks;

    if (timeout_ms == 0u) {
        return 0u;
    }
    m = (ms_per_tick == 0u) ? 1u : (uint64_t)ms_per_tick;
    t = (uint64_t)timeout_ms;
    ticks = (t + m - 1u) / m;
    if (ticks == 0u) {
        ticks = 1u;
    }
    return ticks;
}

uint64_t ninlil_usb_cdc_poll_required_ticks_hz(
    uint32_t timeout_ms,
    uint32_t tick_rate_hz)
{
    uint64_t num;
    uint64_t ticks;
    uint64_t hz;

    if (timeout_ms == 0u) {
        return 0u;
    }
    hz = (tick_rate_hz == 0u) ? 1u : (uint64_t)tick_rate_hz;
    /* ceil(timeout_ms * hz / 1000) without intermediate overflow of u32. */
    num = (uint64_t)timeout_ms * hz;
    ticks = (num + 999ull) / 1000ull;
    if (ticks == 0u) {
        ticks = 1u;
    }
    return ticks;
}

int ninlil_usb_cdc_poll_elapsed_reached(
    uint64_t *inout_elapsed_u64,
    uint32_t last_tick,
    uint32_t now_tick,
    uint64_t budget_ticks)
{
    uint32_t delta;

    if (inout_elapsed_u64 == NULL) {
        return 1;
    }
    delta = now_tick - last_tick; /* modular uint32 */
    if (*inout_elapsed_u64 > UINT64_MAX - (uint64_t)delta) {
        *inout_elapsed_u64 = UINT64_MAX;
    } else {
        *inout_elapsed_u64 += (uint64_t)delta;
    }
    return (*inout_elapsed_u64 >= budget_ticks) ? 1 : 0;
}

void ninlil_usb_cdc_poll_deadline_init(
    ninlil_usb_cdc_poll_deadline_t *d,
    uint64_t budget_ticks,
    uint32_t entry_tick)
{
    if (d == NULL) {
        return;
    }
    (void)memset(d, 0, sizeof(*d));
    d->budget_ticks = budget_ticks;
    d->last_tick = entry_tick;
    d->entry_captured = 1;
}

int ninlil_usb_cdc_poll_deadline_initial_io(
    ninlil_usb_cdc_poll_deadline_t *d,
    uint32_t now_tick)
{
    if (d == NULL || !d->entry_captured) {
        return 0;
    }
    d->io_ops += 1u;
    (void)ninlil_usb_cdc_poll_elapsed_reached(
        &d->elapsed, d->last_tick, now_tick, d->budget_ticks);
    d->last_tick = now_tick;
    return 1;
}

int ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(
    ninlil_usb_cdc_poll_deadline_t *d,
    uint32_t now_tick)
{
    if (d == NULL || !d->entry_captured) {
        return 0;
    }
    if (ninlil_usb_cdc_poll_elapsed_reached(
            &d->elapsed, d->last_tick, now_tick, d->budget_ticks)) {
        d->last_tick = now_tick;
        return 0;
    }
    d->last_tick = now_tick;
    return 1;
}

void ninlil_usb_cdc_poll_deadline_note_extra_io(
    ninlil_usb_cdc_poll_deadline_t *d)
{
    if (d == NULL) {
        return;
    }
    d->io_ops += 1u;
}

/* ---- bind / I-O protocol model (host pure) ----------------------------- */

void ninlil_usb_cdc_bind_io_protocol_init(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL) {
        return;
    }
    (void)memset(p, 0, sizeof(*p));
    p->last_rx_ingressed_gen = -1;
}

int ninlil_usb_cdc_proto_state_enter(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (p->state_locked) {
        p->fault = 1;
        return -1;
    }
    p->state_locked = 1;
    return 0;
}

int ninlil_usb_cdc_proto_state_leave(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (!p->state_locked) {
        p->fault = 1;
        return -1;
    }
    p->state_locked = 0;
    return 0;
}

int ninlil_usb_cdc_proto_io_enter(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    /* Never take I/O while holding state (s_mux). */
    if (p->state_locked) {
        p->fault = 1;
        p->io_ops_while_state_held += 1u;
        return -1;
    }
    if (p->io_locked) {
        p->fault = 1;
        return -1;
    }
    p->io_locked = 1;
    return 0;
}

int ninlil_usb_cdc_proto_io_leave(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (!p->io_locked) {
        p->fault = 1;
        return -1;
    }
    p->io_locked = 0;
    return 0;
}

int ninlil_usb_cdc_proto_soft_flush_fifo(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (!p->io_locked) {
        p->fault = 1;
        return -1;
    }
    if (p->state_locked) {
        p->fault = 1;
        p->io_ops_while_state_held += 1u;
        return -1;
    }
    p->fifo_bytes = 0u;
    p->soft_flush_count += 1u;
    return 0;
}

void ninlil_usb_cdc_proto_fifo_inject(
    ninlil_usb_cdc_bind_io_protocol_t *p,
    uint32_t n)
{
    if (p == NULL || n == 0u) {
        return;
    }
    if (p->fifo_bytes > UINT32_MAX - n) {
        p->fifo_bytes = UINT32_MAX;
    } else {
        p->fifo_bytes += n;
    }
}

int ninlil_usb_cdc_proto_open_service_ready(
    ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    /* Service ensure must not publish live. */
    if (p->live_published) {
        p->fault = 1;
        return -1;
    }
    p->service_ready = 1;
    return 0;
}

int ninlil_usb_cdc_proto_open_flush_and_publish(
    ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (!p->service_ready || p->live_published) {
        p->fault = 1;
        return -1;
    }
    if (p->io_locked || p->state_locked) {
        p->fault = 1;
        return -1;
    }
    /* I/O first: flush prebind FIFO, then publish under state while I/O held. */
    if (ninlil_usb_cdc_proto_io_enter(p) != 0) {
        return -1;
    }
    if (ninlil_usb_cdc_proto_soft_flush_fifo(p) != 0) {
        return -1;
    }
    if (ninlil_usb_cdc_proto_state_enter(p) != 0) {
        return -1;
    }
    p->live_published = 1;
    p->callback_admit = 1;
    if (p->generation == UINT32_MAX) {
        p->fault = 1;
        return -1;
    }
    p->generation += 1u;
    p->publish_count += 1u;
    p->ring_bytes = 0u;
    if (ninlil_usb_cdc_proto_state_leave(p) != 0) {
        return -1;
    }
    if (ninlil_usb_cdc_proto_io_leave(p) != 0) {
        return -1;
    }
    return 0;
}

int ninlil_usb_cdc_proto_close_fence_unpublish(
    ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (p->io_locked || p->state_locked) {
        p->fault = 1;
        return -1;
    }
    if (ninlil_usb_cdc_proto_state_enter(p) != 0) {
        return -1;
    }
    /* Fence admit then unpublish s_live — before any I/O soft clear. */
    p->callback_admit = 0;
    if (p->live_published) {
        p->live_published = 0;
        p->unpublish_count += 1u;
    }
    if (ninlil_usb_cdc_proto_state_leave(p) != 0) {
        return -1;
    }
    return 0;
}

int ninlil_usb_cdc_proto_close_quiesce_flush_free(
    ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (p->live_published || p->callback_admit) {
        p->fault = 1;
        return -1;
    }
    if (p->inflight != 0u) {
        p->fault = 1;
        return -1;
    }
    if (p->io_locked || p->state_locked) {
        p->fault = 1;
        return -1;
    }
    if (ninlil_usb_cdc_proto_io_enter(p) != 0) {
        return -1;
    }
    if (ninlil_usb_cdc_proto_soft_flush_fifo(p) != 0) {
        return -1;
    }
    if (ninlil_usb_cdc_proto_io_leave(p) != 0) {
        return -1;
    }
    /* FREE abstract: no live, no admit. */
    return 0;
}

int ninlil_usb_cdc_proto_rx_callback(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    int live;
    int admit;
    int ingressed = 0;
    uint32_t n;
    uint32_t gen;

    if (p == NULL || p->fault) {
        return -1;
    }
    if (p->io_locked || p->state_locked) {
        p->fault = 1;
        return -1;
    }
    /* 1) I/O mutex first — serializes with open flush / close soft clear. */
    if (ninlil_usb_cdc_proto_io_enter(p) != 0) {
        return -1;
    }
    /* 2) State: snapshot live + admit; brief inflight enter. */
    if (ninlil_usb_cdc_proto_state_enter(p) != 0) {
        return -1;
    }
    live = p->live_published;
    admit = p->callback_admit;
    if (live && admit) {
        if (p->inflight == UINT32_MAX) {
            p->fault = 1;
            return -1;
        }
        p->inflight += 1u;
    }
    if (ninlil_usb_cdc_proto_state_leave(p) != 0) {
        return -1;
    }

    if (!live || !admit) {
        /* Unbound / fenced: drain-drop under I/O only; never touch ring. */
        if (p->state_locked) {
            p->fault = 1;
            p->io_ops_while_state_held += 1u;
            return -1;
        }
        n = p->fifo_bytes;
        p->fifo_bytes = 0u;
        if (n > 0u) {
            p->rx_drop_count += 1u;
        }
        if (ninlil_usb_cdc_proto_io_leave(p) != 0) {
            return -1;
        }
        return 0;
    }

    /* 3) Read under I/O, state unlocked. */
    if (p->state_locked) {
        p->fault = 1;
        p->io_ops_while_state_held += 1u;
        return -1;
    }
    n = p->fifo_bytes;
    p->fifo_bytes = 0u;

    /* 4) Apply / leave under state. */
    if (ninlil_usb_cdc_proto_state_enter(p) != 0) {
        return -1;
    }
    gen = p->generation;
    if (p->live_published && p->callback_admit && n > 0u) {
        if (p->ring_bytes > UINT32_MAX - n) {
            p->ring_bytes = UINT32_MAX;
        } else {
            p->ring_bytes += n;
        }
        p->rx_ingress_count += 1u;
        p->last_rx_ingressed_gen = (int)gen;
        ingressed = 1;
    } else if (n > 0u) {
        p->rx_drop_count += 1u;
    }
    if (p->inflight > 0u) {
        p->inflight -= 1u;
    }
    if (ninlil_usb_cdc_proto_state_leave(p) != 0) {
        return -1;
    }
    if (ninlil_usb_cdc_proto_io_leave(p) != 0) {
        return -1;
    }
    (void)gen;
    return ingressed ? 1 : 0;
}

int ninlil_usb_cdc_proto_tx_fifo_op(ninlil_usb_cdc_bind_io_protocol_t *p)
{
    if (p == NULL || p->fault) {
        return -1;
    }
    if (p->state_locked) {
        p->fault = 1;
        p->io_ops_while_state_held += 1u;
        return -1;
    }
    if (p->io_locked) {
        /* Nested I/O not modeled for TX path entry. */
        p->fault = 1;
        return -1;
    }
    if (ninlil_usb_cdc_proto_io_enter(p) != 0) {
        return -1;
    }
    /* Abstract TX software FIFO touch (no state). */
    if (p->state_locked) {
        p->fault = 1;
        p->io_ops_while_state_held += 1u;
        return -1;
    }
    if (ninlil_usb_cdc_proto_io_leave(p) != 0) {
        return -1;
    }
    return 0;
}
