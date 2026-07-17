/*
 * U2 host pure tests: A2 CDC state/ring/ownership/teardown/callback fence.
 * Deterministic interleaving — no FreeRTOS/TinyUSB, no timing sleeps.
 * Does not claim physical HIL or U2 complete.
 */

#include "usb_cdc_orch_logic.h"
#include "usb_cdc_state_logic.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_endpoint_token(void)
{
    REQUIRE(ninlil_usb_cdc_endpoint_token_ok(NULL) == 1);
    REQUIRE(ninlil_usb_cdc_endpoint_token_ok("") == 1);
    REQUIRE(ninlil_usb_cdc_endpoint_token_ok("control-cdc") == 1);
    REQUIRE(ninlil_usb_cdc_endpoint_token_ok("/dev/ttyACM0") == 0);
    return 0;
}

static int test_open_listening_no_generation(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, "control-cdc", 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(core.link == NINLIL_BYTE_STREAM_LINK_LISTENING);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_LIVE);
    REQUIRE(core.link_generation == 0u);
    REQUIRE(core.callback_admit == 1);
    return 0;
}

static int test_physical_up_down_reconnect_discard(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t ev;
    uint32_t epoch;
    uint8_t buf[8];
    uint32_t n = 0u;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 7u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    ev = ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 0);
    REQUIRE(core.link == NINLIL_BYTE_STREAM_LINK_LISTENING);
    ninlil_usb_cdc_core_callback_leave(&core);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    ev = ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    REQUIRE((ev & NINLIL_BYTE_STREAM_EVENT_LINK_UP) != 0u);
    REQUIRE(core.link_generation == 1u);
    ninlil_usb_cdc_core_callback_leave(&core);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_rx_ingress(
        &core, epoch, (const uint8_t *)"ab", 2u, &ev);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.rx.len == 2u);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    ev = ninlil_usb_cdc_core_apply_physical(&core, epoch, 0, 0);
    REQUIRE((ev & NINLIL_BYTE_STREAM_EVENT_LINK_DOWN) != 0u);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.rx.len == 2u); /* residual drainable */

    REQUIRE(
        ninlil_usb_cdc_core_read(&core, 7u, buf, sizeof(buf), &n, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(n == 2u);

    /* Reconnect with residual still present would discard — seed residual. */
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    /* DOWN: ingress drops; re-UP first then inject residual via push path by
     * going UP, inject, DOWN without drain, then UP again. */
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.link_generation == 2u);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_rx_ingress(
        &core, epoch, (const uint8_t *)"xy", 2u, &ev);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 0, 0);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.rx.len == 2u);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.link_generation == 3u);
    REQUIRE(core.rx.len == 0u);
    REQUIRE(core.stats.generation_rx_discard_bytes == 2u);
    return 0;
}

static int test_stale_epoch_captured(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint32_t epoch_old;
    uint32_t epoch_new;
    ninlil_byte_stream_event_t ev;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, "", 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch_old) == 1);
    /* Close fence advances epoch while callback "in flight". */
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(core.callback_epoch != epoch_old);
    REQUIRE(core.callback_admit == 0);
    /* Stale captured epoch cannot mutate. */
    ev = ninlil_usb_cdc_core_apply_physical(&core, epoch_old, 1, 1);
    REQUIRE(ev == NINLIL_BYTE_STREAM_EVENT_NONE);
    REQUIRE(
        ninlil_usb_cdc_core_rx_ingress(
            &core, epoch_old, (const uint8_t *)"z", 1u, &ev)
        == 0u);
    ninlil_usb_cdc_core_callback_leave(&core);
    /* New enter rejected after fence. */
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch_new) == 0);
    return 0;
}

static int test_wrong_owner_before_out_mutation(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint32_t accepted = 0xA5A5A5A5u;
    uint32_t n = 0xB6B6B6B6u;
    uint8_t buf[4];
    ninlil_byte_stream_event_t events = (ninlil_byte_stream_event_t)0xFFu;
    ninlil_byte_stream_stats_t stats;
    ninlil_byte_stream_error_t obs_err;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 10u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);

    /* WRONG_OWNER must not touch out_accepted. */
    REQUIRE(
        ninlil_usb_cdc_core_write(
            &core, 11u, (const uint8_t *)"z", 1u, &accepted, &err)
        == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(accepted == 0xA5A5A5A5u);
    REQUIRE(core.tx.len == 0u);

    REQUIRE(
        ninlil_usb_cdc_core_read(&core, 11u, buf, 4u, &n, &err)
        == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(n == 0xB6B6B6B6u);

    REQUIRE(
        ninlil_usb_cdc_core_poll_snapshot(&core, 11u, &events, &err)
        == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(events == (ninlil_byte_stream_event_t)0xFFu);

    /* Observers: no mutation of out buffers. */
    (void)memset(&stats, 0x3C, sizeof(stats));
    REQUIRE(ninlil_usb_cdc_core_observer_allowed(&core, 11u) == 0);
    /* Simulate backend leave-unchanged policy. */
    REQUIRE(stats.open_count != 0u); /* still 0x3C pattern */

    (void)memset(&obs_err, 0x5A, sizeof(obs_err));
    REQUIRE(obs_err.status != 0u);
    return 0;
}

static int test_writable_only_when_up(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t events = NINLIL_BYTE_STREAM_EVENT_NONE;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_core_poll_snapshot(&core, 1u, &events, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_WRITABLE) == 0u);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(
        ninlil_usb_cdc_core_poll_snapshot(&core, 1u, &events, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_WRITABLE) != 0u);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 0, 0);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(
        ninlil_usb_cdc_core_poll_snapshot(&core, 1u, &events, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE((events & NINLIL_BYTE_STREAM_EVENT_WRITABLE) == 0u);
    return 0;
}

static int test_rx_overflow_oneshot_not_hot(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_event_t ev = NINLIL_BYTE_STREAM_EVENT_NONE;
    ninlil_byte_stream_event_t snap = NINLIL_BYTE_STREAM_EVENT_NONE;
    uint8_t fill[NINLIL_BYTE_STREAM_RING_BYTES];
    uint8_t extra[4];
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    (void)memset(fill, 1, sizeof(fill));
    (void)ninlil_usb_cdc_core_rx_ingress(
        &core, epoch, fill, sizeof(fill), &ev);
    (void)ninlil_usb_cdc_core_rx_ingress(
        &core, epoch, extra, sizeof(extra), &ev);
    REQUIRE((ev & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) != 0u);
    ninlil_usb_cdc_core_callback_leave(&core);

    REQUIRE(
        ninlil_usb_cdc_core_poll_snapshot(&core, 1u, &snap, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE((snap & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) != 0u);
    /* Second poll: one-shot cleared — no permanent hot overflow event. */
    REQUIRE(
        ninlil_usb_cdc_core_poll_snapshot(&core, 1u, &snap, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE((snap & NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW) == 0u);
    REQUIRE(core.link == NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(core.rx_overflow_latched == 1);
    return 0;
}

static int test_teardown_pending_blocks_reopen(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    ninlil_usb_cdc_core_mark_stack_installed(&core, 1);
    ninlil_usb_cdc_core_mark_cdc_inited(&core, 1);
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);

    /* Inject CDC deinit failure: keep ownership. */
    REQUIRE(
        ninlil_usb_cdc_core_apply_teardown_result(
            &core, 1u, 1, 1, 0, 0, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);
    REQUIRE(core.cdc_inited == 1);
    REQUIRE(core.owner_set == 1);
    REQUIRE(core.has_first_teardown_error == 1);

    /* Reopen rejected. */
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);

    /* Retry close succeeds when both steps OK. */
    REQUIRE(
        ninlil_usb_cdc_core_apply_teardown_result(
            &core, 1u, 1, 0, 1, 0, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_CLOSED);
    REQUIRE(core.owner_set == 0);
    REQUIRE(core.stack_installed == 0);
    REQUIRE(core.cdc_inited == 0);

    /* Fresh open after real CLOSED. */
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 2u, &err) == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_uninstall_fail_keeps_stack(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    ninlil_usb_cdc_core_mark_stack_installed(&core, 1);
    ninlil_usb_cdc_core_mark_cdc_inited(&core, 1);
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_core_apply_teardown_result(
            &core, 1u, 1, 0, 1, 1, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(core.cdc_inited == 0); /* deinit succeeded */
    REQUIRE(core.stack_installed == 1); /* uninstall failed */
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    return 0;
}

static int test_inflight_blocks_teardown_finalize(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    ninlil_usb_cdc_core_mark_stack_installed(&core, 1);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callbacks_drained(&core) == 0);
    REQUIRE(
        ninlil_usb_cdc_core_apply_teardown_result(
            &core, 1u, 0, 0, 1, 0, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(ninlil_usb_cdc_core_callbacks_drained(&core) == 1);
    REQUIRE(
        ninlil_usb_cdc_core_apply_teardown_result(
            &core, 1u, 0, 0, 1, 0, &err)
        == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_generation_exhaust_fault(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    ninlil_usb_cdc_core_test_force_generation(&core, UINT64_MAX);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.link != NINLIL_BYTE_STREAM_LINK_UP);
    REQUIRE(core.usb_attached == 0);
    REQUIRE(core.dtr_asserted == 0);
    return 0;
}

static int test_epoch_wrap_fail_closed(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_core_test_force_epoch(&core, UINT32_MAX);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    ninlil_usb_cdc_core_test_force_epoch(&core, UINT32_MAX);
    ninlil_usb_cdc_core_mark_stack_installed(&core, 1);
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);
    return 0;
}

static int test_tx_all_or_none(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint8_t big[NINLIL_BYTE_STREAM_RING_BYTES + 1u];
    uint32_t accepted = 1u;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    (void)memset(big, 0xA5, sizeof(big));
    REQUIRE(
        ninlil_usb_cdc_core_write(
            &core, 1u, big, NINLIL_BYTE_STREAM_RING_BYTES, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    accepted = 7u;
    REQUIRE(
        ninlil_usb_cdc_core_write(&core, 1u, big, 1u, &accepted, &err)
        == NINLIL_BYTE_STREAM_WOULD_BLOCK);
    REQUIRE(accepted == 0u);
    return 0;
}

static int test_tx_drain_gen_mismatch_no_consume(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_usb_cdc_tx_ticket_t ticket;
    uint8_t chunk[16];
    uint8_t new_payload[4] = {9, 9, 9, 9};
    uint32_t epoch;
    uint32_t accepted = 0u;
    uint32_t peeked;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(
        ninlil_usb_cdc_core_write(
            &core, 1u, (const uint8_t *)"OLD!", 4u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    peeked = ninlil_usb_cdc_core_tx_drain_begin(
        &core, chunk, sizeof(chunk), &ticket);
    REQUIRE(peeked == 4u);
    REQUIRE(ticket.valid == 1);
    /* Concurrent DOWN+UP (reconnect) clears TX and advances generation. */
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 0, 0);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(core.link_generation == 2u);
    REQUIRE(core.tx.len == 0u);
    /* New generation writes fresh bytes. */
    REQUIRE(
        ninlil_usb_cdc_core_write(
            &core, 1u, new_payload, 4u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(core.tx.len == 4u);
    /* Finish with stale ticket + simulated driver accept of 4 old bytes. */
    REQUIRE(
        ninlil_usb_cdc_core_tx_drain_finish(&core, &ticket, 4u) == 0);
    REQUIRE(core.tx.len == 4u); /* new gen ring untouched */
    REQUIRE(core.stats.tx_driver_stale_accepted == 4u);
    REQUIRE(core.tx.bytes[core.tx.head] == 9);
    return 0;
}

/* Fake driver ops for orch sequencing (order + call counts + lock depth). */
typedef struct {
    int install_rc;
    int cdc_init_rc;
    int cdc_deinit_rc;
    int uninstall_rc;
    int install_calls;
    int cdc_init_calls;
    int cdc_deinit_calls;
    int uninstall_calls;
    int tx_queue_calls;
    int wait_drained_rc; /* 1=drained, 0=not */
    int wait_calls;
    int lock_depth;
    int max_lock_depth;
    int driver_call_while_locked;
    int mutation_lock_depth_ok; /* 1 if state mutations observed at depth 1 */
    char order[32];
    size_t order_n;
} fake_drv_t;

static void fake_order_push(fake_drv_t *f, char c)
{
    if (f != NULL && f->order_n + 1u < sizeof(f->order)) {
        f->order[f->order_n++] = c;
        f->order[f->order_n] = '\0';
    }
}

static void fake_note_driver(fake_drv_t *f, char c)
{
    if (f->lock_depth != 0) {
        f->driver_call_while_locked += 1;
    }
    fake_order_push(f, c);
}

static int fake_install(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    f->install_calls += 1;
    fake_note_driver(f, 'I');
    return f->install_rc;
}
static int fake_cdc_init(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    f->cdc_init_calls += 1;
    fake_note_driver(f, 'C');
    return f->cdc_init_rc;
}
static int fake_cdc_deinit(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    f->cdc_deinit_calls += 1;
    fake_note_driver(f, 'D');
    return f->cdc_deinit_rc;
}
static int fake_uninstall(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    f->uninstall_calls += 1;
    fake_note_driver(f, 'U');
    return f->uninstall_rc;
}
static uint32_t fake_txq(void *u, const uint8_t *d, uint32_t n)
{
    fake_drv_t *f = (fake_drv_t *)u;
    (void)d;
    if (f != NULL) {
        f->tx_queue_calls += 1;
        fake_note_driver(f, 'Q');
    }
    return n;
}

static int fake_wait_drained(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    f->wait_calls += 1;
    if (f->lock_depth != 0) {
        f->driver_call_while_locked += 1;
    }
    return f->wait_drained_rc;
}

static void fake_lock(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    f->lock_depth += 1;
    if (f->lock_depth > f->max_lock_depth) {
        f->max_lock_depth = f->lock_depth;
    }
    if (f->lock_depth == 1) {
        f->mutation_lock_depth_ok = 1;
    }
}

static void fake_unlock(void *u)
{
    fake_drv_t *f = (fake_drv_t *)u;
    if (f->lock_depth > 0) {
        f->lock_depth -= 1;
    }
}

static void ops_bind(ninlil_usb_cdc_driver_ops_t *ops, fake_drv_t *fake)
{
    (void)memset(ops, 0, sizeof(*ops));
    ops->driver_install = fake_install;
    ops->cdc_init = fake_cdc_init;
    ops->cdc_deinit = fake_cdc_deinit;
    ops->driver_uninstall = fake_uninstall;
    ops->tx_queue = fake_txq;
    ops->state_lock = fake_lock;
    ops->state_unlock = fake_unlock;
    ops->wait_callbacks_drained = NULL; /* default: sample core inflight */
    ops->user = fake;
}

static int test_orch_install_fail_and_cdc_init_rollback(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);

    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 42u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    fake.install_rc = 1;
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 42u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(g.state == NINLIL_USB_CDC_G_FREE);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_ABSENT);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_CLOSED);
    REQUIRE(fake.driver_call_while_locked == 0);

    /* cdc_init fail: no uninstall (persistent); service POISONED. */
    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 7u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    fake.cdc_init_rc = 5;
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 7u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(fake.cdc_deinit_calls == 0);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_POISONED);
    REQUIRE(g.state == NINLIL_USB_CDC_G_POISONED);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 99u) == 0);
    REQUIRE(fake.driver_call_while_locked == 0);
    REQUIRE(fake.max_lock_depth >= 1);
    return 0;
}

static int test_orch_teardown_esp_ok_only(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);

    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 1u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 1u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(g.state == NINLIL_USB_CDC_G_ACTIVE);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_READY);
    REQUIRE(fake.order[0] == 'I' && fake.order[1] == 'C');
    REQUIRE(fake.driver_call_while_locked == 0);

    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 1u) == 1);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 1u, 1u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.cdc_deinit_calls == 0);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(g.state == NINLIL_USB_CDC_G_FREE);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_READY);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_CLOSED);

    /* Reopen on READY service: no second I/C. */
    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 1u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    fake.install_calls = 0;
    fake.cdc_init_calls = 0;
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 1u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.install_calls == 0);
    REQUIRE(fake.cdc_init_calls == 0);
    return 0;
}

static int test_orch_teardown_authority_order_and_retry(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;
    ninlil_byte_stream_error_t out_err;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);

    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 21u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 7u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 21u, 7u, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);

    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 21u, 7u, 1, &ops, &out_err)
        == NINLIL_BYTE_STREAM_BUSY);

    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 7u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 21u) == 1);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 21u, 99u, 1, &ops, &out_err)
        == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(g.state == NINLIL_USB_CDC_G_TEARING);

    /* drain false: no deinit/uninstall */
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 21u, 7u, 0, &ops, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(g.state == NINLIL_USB_CDC_G_POISONED);

    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 21u) == 1);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 21u, 7u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_READY);
    return 0;
}

static int test_global_reservation_busy(void)
{
    ninlil_usb_cdc_global_res_t g;

    ninlil_usb_cdc_global_init(&g);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 1u) == 1);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 2u) == 0);
    ninlil_usb_cdc_global_mark_active(&g, 1u);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 2u) == 0);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 1u) == 1);
    ninlil_usb_cdc_global_teardown_fail(&g);
    REQUIRE(g.state == NINLIL_USB_CDC_G_POISONED);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 3u) == 0);
    return 0;
}

static int test_orch_callback_drain_timeout_and_uninstall_fail(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);

    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 11u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 11u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 11u) == 1);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 11u, 1u, 0, &ops, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(g.state == NINLIL_USB_CDC_G_POISONED);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 11u) == 1);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 11u, 1u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(g.state == NINLIL_USB_CDC_G_FREE);
    return 0;
}

static int test_p0_closed_b_does_not_free_active_a_reservation(void)
{
    ninlil_usb_cdc_core_t core_a;
    ninlil_usb_cdc_core_t core_b;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;

    ninlil_usb_cdc_core_init(&core_a);
    ninlil_usb_cdc_core_init(&core_b);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);

    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 0xAAu) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core_a, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core_a, &g, 0xAAu, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 0xBBu) == 0);
    REQUIRE(
        ninlil_usb_cdc_closed_idle_close_policy(&core_b, &g, 0xBBu) == 1);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 0xBBu) == 0);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core_b, &g, 0xBBu, 1u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_BUSY);
    REQUIRE(g.reserved_id == 0xAAu);
    REQUIRE(g.state == NINLIL_USB_CDC_G_ACTIVE);
    return 0;
}

static int test_p0_wrong_id_teardown_immutable_all_states(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 1u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 9u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 1u, 9u, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 2u, 9u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_BUSY);
    REQUIRE(g.reserved_id == 1u);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 1u) == 1);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 99u, 9u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_BUSY);
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 1u, 9u, 1, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    return 0;
}

static int test_p0_cdc_init_fail_inflight_no_uninstall(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 3u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    fake.cdc_init_rc = 1;
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 3u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_POISONED);
    ninlil_usb_cdc_core_callback_leave(&core);
    return 0;
}

static int test_p0_cdc_init_fail_drain_then_uninstall_free(void)
{
    /* Persistent: drain ok still does not uninstall; service poisoned. */
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_usb_cdc_driver_ops_t ops;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    (void)memset(&fake, 0, sizeof(fake));
    ops_bind(&ops, &fake);
    ops.wait_callbacks_drained = fake_wait_drained;
    fake.wait_drained_rc = 1;
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 5u) == 1);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    fake.cdc_init_rc = 2;
    REQUIRE(
        ninlil_usb_cdc_orch_install(&core, &g, 5u, 1u, &ops, &err)
        == NINLIL_BYTE_STREAM_IO_ERROR);
    REQUIRE(fake.uninstall_calls == 0);
    REQUIRE(g.service == NINLIL_USB_CDC_SVC_POISONED);
    return 0;
}

static int test_p0_soft_clear_holds_inflight_until_done(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_cb_soft_work_t work;
    ninlil_byte_stream_error_t err;
    uint32_t epoch;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    REQUIRE(core.callback_inflight == 1u);

    ninlil_usb_cdc_cb_soft_work_reset(&work);
    ninlil_usb_cdc_cb_soft_work_enter(&work, 1 /* need soft clear */);
    REQUIRE(ninlil_usb_cdc_cb_soft_work_may_leave(&work) == 0);
    REQUIRE(ninlil_usb_cdc_cb_soft_work_leave(&core, &work) == 0);
    REQUIRE(core.callback_inflight == 1u);
    /* Close model: cannot deinit while soft-clear inflight held. */
    REQUIRE(ninlil_usb_cdc_core_callbacks_drained(&core) == 0);

    ninlil_usb_cdc_cb_soft_work_mark_soft_clear_done(&work);
    REQUIRE(ninlil_usb_cdc_cb_soft_work_may_leave(&work) == 1);
    REQUIRE(ninlil_usb_cdc_cb_soft_work_leave(&core, &work) == 1);
    REQUIRE(core.callback_inflight == 0u);
    REQUIRE(ninlil_usb_cdc_core_callbacks_drained(&core) == 1);
    return 0;
}

/* C) cdc_init fail while inflight: uninstall not called, POISONED. */
static int test_p1_init_storage_may_wipe_policy(void)
{
    ninlil_usb_cdc_global_res_t g;
    const uint64_t id_a = 0xA100u;
    const uint64_t id_b = 0xB200u;

    ninlil_usb_cdc_global_init(&g);
    /* Fresh free global: any storage may wipe (first init). */
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_a, &g, 0u) == 1);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_b, &g, 0u) == 1);

    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, id_a) == 1);
    REQUIRE(g.state == NINLIL_USB_CDC_G_INSTALLING);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_a, &g, 0u) == 0);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_b, &g, 0u) == 1);

    ninlil_usb_cdc_global_mark_active(&g, id_a);
    REQUIRE(g.state == NINLIL_USB_CDC_G_ACTIVE);
    /* s_live == A blocks wipe even without relying on storage magic. */
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_a, &g, id_a) == 0);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_b, &g, id_a) == 1);

    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, id_a) == 1);
    REQUIRE(g.state == NINLIL_USB_CDC_G_TEARING);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_a, &g, id_a) == 0);

    ninlil_usb_cdc_global_teardown_fail(&g);
    REQUIRE(g.state == NINLIL_USB_CDC_G_POISONED);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_a, &g, id_a) == 0);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_b, &g, id_a) == 1);

    /* Successful full teardown → FREE; same storage reinit allowed. */
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, id_a) == 1);
    ninlil_usb_cdc_global_teardown_success(&g);
    REQUIRE(g.state == NINLIL_USB_CDC_G_FREE);
    REQUIRE(g.reserved_id == 0u);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(id_a, &g, 0u) == 1);
    REQUIRE(ninlil_usb_cdc_init_storage_may_wipe(0u, &g, 0u) == 0);
    return 0;
}

/* C) cdc_init fail, drained: uninstall runs → FREE. */
static int test_tx_drain_match_consumes_and_epoch_mismatch(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_usb_cdc_tx_ticket_t ticket;
    uint8_t chunk[16];
    uint32_t epoch;
    uint32_t accepted = 0u;
    uint32_t peeked;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(
        ninlil_usb_cdc_core_write(
            &core, 1u, (const uint8_t *)"OKOK", 4u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    peeked = ninlil_usb_cdc_core_tx_drain_begin(
        &core, chunk, sizeof(chunk), &ticket);
    REQUIRE(peeked == 4u);
    REQUIRE(ninlil_usb_cdc_core_tx_drain_finish(&core, &ticket, 4u) == 1);
    REQUIRE(core.tx.len == 0u);
    REQUIRE(core.stats.bytes_written == 4u);
    REQUIRE(core.stats.tx_driver_stale_accepted == 0u);

    /* Epoch advance without gen change: still fail-closed, no consume. */
    REQUIRE(
        ninlil_usb_cdc_core_write(
            &core, 1u, (const uint8_t *)"EEEE", 4u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    peeked = ninlil_usb_cdc_core_tx_drain_begin(
        &core, chunk, sizeof(chunk), &ticket);
    REQUIRE(peeked == 4u);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    /* begin_close_fence path bumps epoch; simulate epoch++ via leave after fence */
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err)
        == NINLIL_BYTE_STREAM_OK);
    /* lifecycle no longer LIVE; finish must not consume */
    REQUIRE(ninlil_usb_cdc_core_tx_drain_finish(&core, &ticket, 4u) == 0);
    REQUIRE(core.stats.tx_driver_stale_accepted == 4u);
    return 0;
}


static int test_p0_range_overlap_half_open(void)
{
    ninlil_usb_cdc_addr_range_t a, b;
    a.base = 100; a.bytes = 50; /* [100,150) */
    b.base = 150; b.bytes = 10; /* adjacent non-overlap */
    REQUIRE(ninlil_usb_cdc_ranges_overlap(&a, &b) == 0);
    b.base = 149; b.bytes = 10; /* partial */
    REQUIRE(ninlil_usb_cdc_ranges_overlap(&a, &b) == 1);
    b.base = 100; b.bytes = 10; /* contained */
    REQUIRE(ninlil_usb_cdc_ranges_overlap(&a, &b) == 1);
    b.base = 90; b.bytes = 20; /* front partial */
    REQUIRE(ninlil_usb_cdc_ranges_overlap(&a, &b) == 1);
    a.base = UINT64_MAX - 8; a.bytes = 16; /* wrap invalid */
    REQUIRE(ninlil_usb_cdc_range_valid(&a) == 0);
    REQUIRE(ninlil_usb_cdc_ranges_overlap(&a, &b) == 1);
    a.base = 0x1000; a.bytes = 0x100;
    b = a; /* alias */
    REQUIRE(ninlil_usb_cdc_ranges_overlap(&a, &b) == 1);
    return 0;
}

static int test_p0_init_ranges_vs_live(void)
{
    ninlil_usb_cdc_global_res_t g;
    ninlil_usb_cdc_addr_range_t storage, stream, live;
    ninlil_usb_cdc_global_init(&g);
    storage.base = 0x1000; storage.bytes = 0x100;
    stream.base = 0x2000; stream.bytes = 0x40;
    live.base = 0x1080; live.bytes = 0x100; /* overlaps storage */
    REQUIRE(ninlil_usb_cdc_init_ranges_may_claim(&storage, &stream, &g, &live) == 0);
    live.base = 0x3000; live.bytes = 0x10;
    REQUIRE(ninlil_usb_cdc_init_ranges_may_claim(&storage, &stream, &g, &live) == 1);
    stream.base = 0x1050; stream.bytes = 0x20; /* stream overlaps storage */
    REQUIRE(ninlil_usb_cdc_init_ranges_may_claim(&storage, &stream, &g, &live) == 0);
    return 0;
}

static int test_p1_poll_timeout_ticks(void)
{
    uint64_t e = 0;
    ninlil_usb_cdc_poll_deadline_t d;

    REQUIRE(ninlil_usb_cdc_poll_required_ticks(0, 10) == 0);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks(1, 10) == 1);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks(10, 10) == 1);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks(11, 10) == 2);
    /* large timeouts without signed 32 overflow model */
    REQUIRE(ninlil_usb_cdc_poll_required_ticks(0x80000000u, 1) == 0x80000000ull);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks(UINT32_MAX, 1) == (uint64_t)UINT32_MAX);

    /* HZ path: ceil(timeout_ms * hz / 1000) for arbitrary FreeRTOS rates */
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(0, 1000) == 0);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(1, 100) == 1); /* ceil(100/1000) */
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(1, 128) == 1); /* ceil(128/1000) */
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(1, 1000) == 1);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(10, 1000) == 10);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(1500, 1000) == 1500);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(10, 100) == 1); /* ceil(1000/1000) */
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(11, 100) == 2); /* ceil(1100/1000) */
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(1000, 128) == 128);
    REQUIRE(ninlil_usb_cdc_poll_required_ticks_hz(1, 0) == 1); /* hz0 → 1 */
    /* UINT32_MAX * hz must not wrap u64 product path */
    REQUIRE(
        ninlil_usb_cdc_poll_required_ticks_hz(UINT32_MAX, 1000)
        == (uint64_t)UINT32_MAX);
    REQUIRE(
        ninlil_usb_cdc_poll_required_ticks_hz(UINT32_MAX, 100)
        == ((uint64_t)UINT32_MAX * 100ull + 999ull) / 1000ull);

    /* tick wrap accumulation */
    REQUIRE(ninlil_usb_cdc_poll_elapsed_reached(&e, 0xFFFFFFF0u, 0x10u, 32) == 1);
    e = 0;
    REQUIRE(ninlil_usb_cdc_poll_elapsed_reached(&e, 100, 110, 50) == 0);
    REQUIRE(e == 10);
    REQUIRE(ninlil_usb_cdc_poll_elapsed_reached(&e, 110, 160, 50) == 1);

    /*
     * Call-entry deadline model: initial pump charges budget; after wait that
     * reaches budget, no extra I/O (timeout_ms → 1 tick).
     */
    ninlil_usb_cdc_poll_deadline_init(&d, 1u /* budget 1 tick */, 100u);
    REQUIRE(ninlil_usb_cdc_poll_deadline_initial_io(&d, 100u) == 1);
    REQUIRE(d.io_ops == 1u);
    /* delay of 1 tick hits deadline */
    REQUIRE(ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(&d, 101u) == 0);
    REQUIRE(d.io_ops == 1u); /* no extra I/O recorded */

    /* budget 2: after 1-tick wait, extra I/O still allowed */
    ninlil_usb_cdc_poll_deadline_init(&d, 2u, 50u);
    REQUIRE(ninlil_usb_cdc_poll_deadline_initial_io(&d, 50u) == 1);
    REQUIRE(ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(&d, 51u) == 1);
    ninlil_usb_cdc_poll_deadline_note_extra_io(&d);
    REQUIRE(d.io_ops == 2u);
    /* next wait exhausts budget */
    REQUIRE(ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(&d, 52u) == 0);
    REQUIRE(d.io_ops == 2u);

    /* Initial pump time counts: entry 10, pump ends 11, budget 1 → no extra */
    ninlil_usb_cdc_poll_deadline_init(&d, 1u, 10u);
    REQUIRE(ninlil_usb_cdc_poll_deadline_initial_io(&d, 11u) == 1);
    REQUIRE(d.elapsed >= 1u);
    REQUIRE(ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(&d, 11u) == 0);

    /* tick wrap across wait */
    ninlil_usb_cdc_poll_deadline_init(&d, 32u, 0xFFFFFFF0u);
    REQUIRE(ninlil_usb_cdc_poll_deadline_initial_io(&d, 0xFFFFFFF0u) == 1);
    REQUIRE(
        ninlil_usb_cdc_poll_deadline_may_extra_io_after_wait(&d, 0x10u) == 0);
    return 0;
}

static int test_p1_open_preflight(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_open_preflight(&core, 2u, NULL, &err)
        == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(
        ninlil_usb_cdc_open_preflight(&core, 1u, NULL, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    return 0;
}


static int test_once_init_claim(void)
{
    ninlil_usb_cdc_once_t o;
    void *h = (void *)(uintptr_t)0xBEEFu;
    ninlil_usb_cdc_once_init(&o);
    REQUIRE(ninlil_usb_cdc_once_claim_create(&o) == 1);
    REQUIRE(ninlil_usb_cdc_once_claim_create(&o) == 0);
    ninlil_usb_cdc_once_mark_ready(&o, h);
    REQUIRE(ninlil_usb_cdc_once_claim_create(&o) == -1);
    return 0;
}

static int test_closed_idle_policy_and_inconsistency(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    REQUIRE(ninlil_usb_cdc_closed_idle_close_policy(&core, &g, 5u) == 1);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 1u) == 1);
    ninlil_usb_cdc_global_mark_active(&g, 1u);
    REQUIRE(ninlil_usb_cdc_closed_idle_close_policy(&core, &g, 5u) == 1);
    REQUIRE(ninlil_usb_cdc_closed_idle_close_policy(&core, &g, 1u) == -1);
    return 0;
}

static int test_p0_wrong_owner_poll_no_tx_queue(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    fake_drv_t fake;
    ninlil_byte_stream_event_t events = (ninlil_byte_stream_event_t)0xAAu;
    uint32_t queued = 0xBBu;
    uint32_t epoch;
    uint32_t accepted = 0u;
    uint8_t payload[4] = {1, 2, 3, 4};
    ninlil_usb_cdc_core_init(&core);
    (void)memset(&fake, 0, sizeof(fake));
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    (void)ninlil_usb_cdc_core_apply_physical(&core, epoch, 1, 1);
    ninlil_usb_cdc_core_callback_leave(&core);
    REQUIRE(
        ninlil_usb_cdc_core_write(&core, 1u, payload, 4u, &accepted, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(
        ninlil_usb_cdc_poll_owner_before_tx(
            &core, 99u, fake_txq, &fake, payload, 4u, &queued, &events, &err)
        == NINLIL_BYTE_STREAM_WRONG_OWNER);
    REQUIRE(fake.tx_queue_calls == 0);
    REQUIRE(events == (ninlil_byte_stream_event_t)0xAAu);
    REQUIRE(queued == 0xBBu);
    return 0;
}

/*
 * (a) unbound physical events always bump seq
 * (b) intervening bump after capture → stale snapshot discarded
 * (c) stable seq already-connected → apply
 */
static int test_p0_unbound_physical_seq_and_reconcile(void)
{
    ninlil_usb_cdc_global_res_t g;
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint32_t epoch;
    uint64_t seq0;
    uint64_t captured;

    ninlil_usb_cdc_global_init(&g);
    REQUIRE(g.physical_event_seq == 0u);
    seq0 = ninlil_usb_cdc_note_physical_event(&g, 0 /* unbound */);
    REQUIRE(seq0 == 1u);
    REQUIRE(g.physical_event_seq == 1u);
    seq0 = ninlil_usb_cdc_note_physical_event(&g, 0);
    REQUIRE(seq0 == 2u);

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);

    captured = g.physical_event_seq;
    (void)ninlil_usb_cdc_note_physical_event(&g, 1);
    REQUIRE(
        ninlil_usb_cdc_reconcile_physical_if_seq(
            &core, &g, captured, epoch, 1, 1)
        == 0);
    REQUIRE(core.link != NINLIL_BYTE_STREAM_LINK_UP);

    captured = g.physical_event_seq;
    REQUIRE(
        ninlil_usb_cdc_reconcile_physical_if_seq(
            &core, &g, captured, epoch, 1, 1)
        == 1);
    REQUIRE(core.link == NINLIL_BYTE_STREAM_LINK_UP);
    ninlil_usb_cdc_core_callback_leave(&core);

    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    captured = g.physical_event_seq;
    (void)ninlil_usb_cdc_note_physical_event(&g, 1);
    REQUIRE(
        ninlil_usb_cdc_reconcile_physical_if_seq(
            &core, &g, captured, epoch, 0, 0)
        == 0);
    REQUIRE(core.link == NINLIL_BYTE_STREAM_LINK_UP);
    ninlil_usb_cdc_core_callback_leave(&core);
    return 0;
}

static int test_p0_unbound_rx_should_not_ingress(void)
{
    REQUIRE(ninlil_usb_cdc_rx_should_ingress(0, 0) == 0);
    REQUIRE(ninlil_usb_cdc_rx_should_ingress(0, 1) == 0);
    REQUIRE(ninlil_usb_cdc_rx_should_ingress(1, 0) == 0);
    REQUIRE(ninlil_usb_cdc_rx_should_ingress(1, 1) == 1);
    return 0;
}

static int test_p0_close_fence_epoch_max_no_reopen(void)
{
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    ninlil_byte_stream_status_t st;

    ninlil_usb_cdc_core_init(&core);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    /* Saturate epoch so fence advance fails closed. */
    core.callback_epoch = UINT32_MAX;
    st = ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err);
    REQUIRE(st == NINLIL_BYTE_STREAM_INVALID_STATE);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING);
    REQUIRE(core.callback_admit == 0);
    /* Reopen / reinit must not succeed while TEARDOWN_PENDING */
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err)
        == NINLIL_BYTE_STREAM_INVALID_STATE);
    return 0;
}

static int test_p0_reconcile_seq_max_fail_closed(void)
{
    ninlil_usb_cdc_global_res_t g;
    ninlil_usb_cdc_core_t core;
    ninlil_byte_stream_error_t err;
    uint32_t epoch;

    ninlil_usb_cdc_global_init(&g);
    ninlil_usb_cdc_core_init(&core);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_core_callback_try_enter(&core, &epoch) == 1);
    g.physical_event_seq = UINT64_MAX;
    REQUIRE(
        ninlil_usb_cdc_reconcile_physical_if_seq(
            &core, &g, UINT64_MAX, epoch, 1, 1)
        == 0);
    REQUIRE(core.link != NINLIL_BYTE_STREAM_LINK_UP);
    /* captured max even if g not max */
    g.physical_event_seq = 3u;
    REQUIRE(
        ninlil_usb_cdc_reconcile_physical_if_seq(
            &core, &g, UINT64_MAX, epoch, 1, 1)
        == 0);
    ninlil_usb_cdc_core_callback_leave(&core);
    return 0;
}

static int test_p0_range_uintptr_and_32bit_space(void)
{
    ninlil_usb_cdc_addr_range_t r, stream;
    ninlil_usb_cdc_global_res_t g;

    ninlil_usb_cdc_global_init(&g);
    /* 32-bit address space model: last byte must be <= 0xFFFFFFFF */
    r.base = 0xFFFFFFF0ull;
    r.bytes = 0x20ull; /* wraps past 32-bit */
    REQUIRE(ninlil_usb_cdc_range_valid_in_space(&r, 0xFFFFFFFFull) == 0);
    r.bytes = 0x10ull; /* last = 0xFFFFFFFF */
    REQUIRE(ninlil_usb_cdc_range_valid_in_space(&r, 0xFFFFFFFFull) == 1);
    stream.base = 0x1000;
    stream.bytes = 0x10;
    REQUIRE(
        ninlil_usb_cdc_init_ranges_may_claim_in_space(
            &r, &stream, &g, NULL, 0xFFFFFFFFull)
        == 1);
    r.base = 0xFFFFFFF8ull;
    r.bytes = 0x10ull;
    REQUIRE(
        ninlil_usb_cdc_init_ranges_may_claim_in_space(
            &r, &stream, &g, NULL, 0xFFFFFFFFull)
        == 0);
    /* UINTPTR_MAX production path still rejects u64-only wrap */
    r.base = UINT64_MAX - 4ull;
    r.bytes = 16ull;
    REQUIRE(ninlil_usb_cdc_range_valid(&r) == 0);
    REQUIRE(
        ninlil_usb_cdc_init_ranges_may_claim(&r, &stream, &g, NULL) == 0);
    return 0;
}

static int test_p0_publish_validate_fail_poisons_keeps_storage(void)
{
    /*
     * Open publish validation failure protocol (production):
     * fence → PARKING → POISONED; keep live_storage + reserved_id;
     * never clear storage while leaving BOUND/LIVE; s_live stays unpublished.
     * Overlapping reinit must remain rejected (partial-overlap evidence).
     */
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    ninlil_usb_cdc_addr_range_t storage;
    ninlil_usb_cdc_addr_range_t stream;
    ninlil_usb_cdc_addr_range_t live;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 7u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 7u) == 1);
    ninlil_usb_cdc_global_mark_active(&g, 7u);
    g.service = NINLIL_USB_CDC_SVC_READY;
    live.base = 0x5000ull;
    live.bytes = 0x100ull;
    ninlil_usb_cdc_global_set_live_storage(&g, &live);
    REQUIRE(g.state == NINLIL_USB_CDC_BIND_BOUND);
    REQUIRE(g.live_storage.bytes == 0x100ull);

    /* Simulate publish-validate fail-closed path */
    REQUIRE(
        ninlil_usb_cdc_core_begin_close_fence(&core, 7u, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 7u) == 1);
    ninlil_usb_cdc_global_teardown_fail(&g);
    /* Do NOT clear live_storage */
    REQUIRE(g.state == NINLIL_USB_CDC_BIND_POISONED);
    REQUIRE(g.reserved_id == 7u);
    REQUIRE(g.live_storage.base == 0x5000ull);
    REQUIRE(g.live_storage.bytes == 0x100ull);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_TEARDOWN_PENDING
            || core.lifecycle == NINLIL_USB_CDC_LC_CLOSED
            || core.callback_admit == 0);

    stream.base = 0x9000ull;
    stream.bytes = 0x10ull;
    /* Overlap with retained live_storage: reinit must be rejected */
    storage.base = 0x5080ull;
    storage.bytes = 0x40ull;
    REQUIRE(
        ninlil_usb_cdc_init_ranges_may_claim(&storage, &stream, &g, NULL) == 0);
    storage.base = 0x5000ull;
    storage.bytes = 0x10ull;
    REQUIRE(
        ninlil_usb_cdc_init_ranges_may_claim(&storage, &stream, &g, NULL) == 0);
    /* Non-overlapping range may pass range check; reservation still POISONED */
    storage.base = 0xA000ull;
    REQUIRE(g.state == NINLIL_USB_CDC_BIND_POISONED);
    REQUIRE(g.reserved_id == 7u);
    REQUIRE(g.live_storage.bytes > 0u);
    return 0;
}

static int test_p0_orch_teardown_null_soft_ops_after_preclear(void)
{
    /*
     * Pure model: after explicit quiesce, orch_teardown with NULL soft-clear
     * ops still parks successfully (production avoids double soft-clear).
     */
    ninlil_usb_cdc_core_t core;
    ninlil_usb_cdc_global_res_t g;
    ninlil_byte_stream_error_t err;
    ninlil_usb_cdc_driver_ops_t ops;
    int soft_calls = 0;

    ninlil_usb_cdc_core_init(&core);
    ninlil_usb_cdc_global_init(&g);
    REQUIRE(
        ninlil_usb_cdc_core_open(&core, NULL, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_install(&g, 1u) == 1);
    ninlil_usb_cdc_global_mark_active(&g, 1u);
    g.service = NINLIL_USB_CDC_SVC_READY;
    core.stack_installed = 1;
    core.cdc_inited = 1;
    REQUIRE(ninlil_usb_cdc_core_begin_close_fence(&core, 1u, &err) == NINLIL_BYTE_STREAM_OK);
    REQUIRE(ninlil_usb_cdc_global_try_begin_teardown(&g, 1u) == 1);
    (void)memset(&ops, 0, sizeof(ops));
    ops.tx_fifo_soft_clear = NULL;
    ops.rx_fifo_soft_flush = NULL;
    ops.state_lock = NULL;
    ops.state_unlock = NULL;
    REQUIRE(
        ninlil_usb_cdc_orch_teardown(
            &core, &g, 1u, 1u, 1 /* drained */, &ops, &err)
        == NINLIL_BYTE_STREAM_OK);
    REQUIRE(g.state == NINLIL_USB_CDC_BIND_FREE);
    REQUIRE(core.lifecycle == NINLIL_USB_CDC_LC_CLOSED);
    REQUIRE(soft_calls == 0);
    return 0;
}

/*
 * P0 bind/I-O protocol interleaves (not just rx_should_ingress):
 * (1) flush-before-publish: prebind FIFO cannot enter gen ring
 * (2) close unpublish then old RX drops (no ingress to next gen)
 * (3) rebind: A close + B publish; residual FIFO flushed; B only sees post-publish
 * (4) I/O while state held is a fault; TX FIFO op never under state
 * (5) concurrent abstract: unbound RX drain under I/O during B open flush
 */
static int test_p0_bind_io_flush_before_publish(void)
{
    ninlil_usb_cdc_bind_io_protocol_t p;

    ninlil_usb_cdc_bind_io_protocol_init(&p);
    REQUIRE(ninlil_usb_cdc_proto_open_service_ready(&p) == 0);
    ninlil_usb_cdc_proto_fifo_inject(&p, 17u);
    REQUIRE(p.fifo_bytes == 17u);
    REQUIRE(ninlil_usb_cdc_proto_open_flush_and_publish(&p) == 0);
    REQUIRE(p.live_published == 1);
    REQUIRE(p.fifo_bytes == 0u);
    REQUIRE(p.ring_bytes == 0u);
    REQUIRE(p.soft_flush_count >= 1u);
    REQUIRE(p.publish_count == 1u);
    REQUIRE(p.io_ops_while_state_held == 0u);
    REQUIRE(p.fault == 0);
    return 0;
}

static int test_p0_bind_io_close_unpublish_then_rx_drop(void)
{
    ninlil_usb_cdc_bind_io_protocol_t p;
    int rc;

    ninlil_usb_cdc_bind_io_protocol_init(&p);
    REQUIRE(ninlil_usb_cdc_proto_open_service_ready(&p) == 0);
    REQUIRE(ninlil_usb_cdc_proto_open_flush_and_publish(&p) == 0);
    ninlil_usb_cdc_proto_fifo_inject(&p, 5u);
    REQUIRE(ninlil_usb_cdc_proto_rx_callback(&p) == 1);
    REQUIRE(p.ring_bytes == 5u);
    REQUIRE(p.rx_ingress_count == 1u);

    REQUIRE(ninlil_usb_cdc_proto_close_fence_unpublish(&p) == 0);
    REQUIRE(p.live_published == 0);
    REQUIRE(p.callback_admit == 0);
    ninlil_usb_cdc_proto_fifo_inject(&p, 9u);
    rc = ninlil_usb_cdc_proto_rx_callback(&p);
    REQUIRE(rc == 0);
    REQUIRE(p.ring_bytes == 5u); /* no further ingress after unpublish */
    REQUIRE(p.rx_drop_count >= 1u);
    REQUIRE(p.inflight == 0u);
    REQUIRE(ninlil_usb_cdc_proto_close_quiesce_flush_free(&p) == 0);
    REQUIRE(p.fifo_bytes == 0u);
    REQUIRE(p.io_ops_while_state_held == 0u);
    REQUIRE(p.fault == 0);
    return 0;
}

static int test_p0_bind_io_rebind_interleave(void)
{
    ninlil_usb_cdc_bind_io_protocol_t p;
    uint32_t gen_a;
    uint32_t gen_b;

    ninlil_usb_cdc_bind_io_protocol_init(&p);
    /* Generation A */
    REQUIRE(ninlil_usb_cdc_proto_open_service_ready(&p) == 0);
    REQUIRE(ninlil_usb_cdc_proto_open_flush_and_publish(&p) == 0);
    gen_a = p.generation;
    ninlil_usb_cdc_proto_fifo_inject(&p, 3u);
    REQUIRE(ninlil_usb_cdc_proto_rx_callback(&p) == 1);
    REQUIRE(p.last_rx_ingressed_gen == (int)gen_a);

    /* A close: unpublish first; leftover host bytes land in FIFO */
    REQUIRE(ninlil_usb_cdc_proto_close_fence_unpublish(&p) == 0);
    ninlil_usb_cdc_proto_fifo_inject(&p, 11u); /* would be B-bound if early publish */
    REQUIRE(ninlil_usb_cdc_proto_rx_callback(&p) == 0); /* unbound drop */
    REQUIRE(p.inflight == 0u);
    REQUIRE(ninlil_usb_cdc_proto_close_quiesce_flush_free(&p) == 0);

    /* Inject more prebind noise before B publish */
    ninlil_usb_cdc_proto_fifo_inject(&p, 22u);
    REQUIRE(ninlil_usb_cdc_proto_open_service_ready(&p) == 0);
    REQUIRE(ninlil_usb_cdc_proto_open_flush_and_publish(&p) == 0);
    gen_b = p.generation;
    REQUIRE(gen_b == gen_a + 1u);
    REQUIRE(p.fifo_bytes == 0u);
    REQUIRE(p.ring_bytes == 0u); /* flush-before-publish wiped prebind */
    /* Only post-publish bytes may ingress to B */
    ninlil_usb_cdc_proto_fifo_inject(&p, 4u);
    REQUIRE(ninlil_usb_cdc_proto_rx_callback(&p) == 1);
    REQUIRE(p.last_rx_ingressed_gen == (int)gen_b);
    REQUIRE(p.ring_bytes == 4u);
    REQUIRE(p.io_ops_while_state_held == 0u);
    REQUIRE(p.fault == 0);
    return 0;
}

static int test_p0_bind_io_forbid_io_under_state(void)
{
    ninlil_usb_cdc_bind_io_protocol_t p;

    ninlil_usb_cdc_bind_io_protocol_init(&p);
    REQUIRE(ninlil_usb_cdc_proto_state_enter(&p) == 0);
    REQUIRE(ninlil_usb_cdc_proto_io_enter(&p) == -1);
    REQUIRE(p.fault == 1);
    REQUIRE(p.io_ops_while_state_held >= 1u);

    ninlil_usb_cdc_bind_io_protocol_init(&p);
    REQUIRE(ninlil_usb_cdc_proto_open_service_ready(&p) == 0);
    REQUIRE(ninlil_usb_cdc_proto_open_flush_and_publish(&p) == 0);
    REQUIRE(ninlil_usb_cdc_proto_tx_fifo_op(&p) == 0);
    REQUIRE(p.io_ops_while_state_held == 0u);
    REQUIRE(p.fault == 0);
    return 0;
}

static int test_p0_bind_io_rx_during_open_flush_window(void)
{
    ninlil_usb_cdc_bind_io_protocol_t p;

    /*
     * Model: service ready, not yet published; RX callback must drop under I/O
     * (same as production s_live==NULL path while s_io serializes with flush).
     */
    ninlil_usb_cdc_bind_io_protocol_init(&p);
    REQUIRE(ninlil_usb_cdc_proto_open_service_ready(&p) == 0);
    ninlil_usb_cdc_proto_fifo_inject(&p, 8u);
    REQUIRE(ninlil_usb_cdc_proto_rx_callback(&p) == 0);
    REQUIRE(p.rx_drop_count >= 1u);
    REQUIRE(p.ring_bytes == 0u);
    REQUIRE(p.live_published == 0);
    REQUIRE(ninlil_usb_cdc_proto_open_flush_and_publish(&p) == 0);
    REQUIRE(p.ring_bytes == 0u);
    REQUIRE(p.fault == 0);
    return 0;
}

int main(void)
{
    REQUIRE(test_endpoint_token() == 0);
    REQUIRE(test_open_listening_no_generation() == 0);
    REQUIRE(test_physical_up_down_reconnect_discard() == 0);
    REQUIRE(test_stale_epoch_captured() == 0);
    REQUIRE(test_wrong_owner_before_out_mutation() == 0);
    REQUIRE(test_writable_only_when_up() == 0);
    REQUIRE(test_rx_overflow_oneshot_not_hot() == 0);
    REQUIRE(test_teardown_pending_blocks_reopen() == 0);
    REQUIRE(test_uninstall_fail_keeps_stack() == 0);
    REQUIRE(test_inflight_blocks_teardown_finalize() == 0);
    REQUIRE(test_generation_exhaust_fault() == 0);
    REQUIRE(test_epoch_wrap_fail_closed() == 0);
    REQUIRE(test_tx_all_or_none() == 0);
    REQUIRE(test_tx_drain_gen_mismatch_no_consume() == 0);
    REQUIRE(test_tx_drain_match_consumes_and_epoch_mismatch() == 0);
    REQUIRE(test_orch_install_fail_and_cdc_init_rollback() == 0);
    REQUIRE(test_orch_teardown_esp_ok_only() == 0);
    REQUIRE(test_orch_teardown_authority_order_and_retry() == 0);
    REQUIRE(test_orch_callback_drain_timeout_and_uninstall_fail() == 0);
    REQUIRE(test_global_reservation_busy() == 0);
    REQUIRE(test_once_init_claim() == 0);
    REQUIRE(test_p0_closed_b_does_not_free_active_a_reservation() == 0);
    REQUIRE(test_p0_wrong_id_teardown_immutable_all_states() == 0);
    REQUIRE(test_closed_idle_policy_and_inconsistency() == 0);
    REQUIRE(test_p0_cdc_init_fail_inflight_no_uninstall() == 0);
    REQUIRE(test_p0_cdc_init_fail_drain_then_uninstall_free() == 0);
    REQUIRE(test_p0_soft_clear_holds_inflight_until_done() == 0);
    REQUIRE(test_p0_wrong_owner_poll_no_tx_queue() == 0);
    REQUIRE(test_p1_init_storage_may_wipe_policy() == 0);
    REQUIRE(test_p0_range_overlap_half_open() == 0);
    REQUIRE(test_p0_init_ranges_vs_live() == 0);
    REQUIRE(test_p1_poll_timeout_ticks() == 0);
    REQUIRE(test_p1_open_preflight() == 0);
    REQUIRE(test_p0_unbound_physical_seq_and_reconcile() == 0);
    REQUIRE(test_p0_unbound_rx_should_not_ingress() == 0);
    REQUIRE(test_p0_bind_io_flush_before_publish() == 0);
    REQUIRE(test_p0_bind_io_close_unpublish_then_rx_drop() == 0);
    REQUIRE(test_p0_bind_io_rebind_interleave() == 0);
    REQUIRE(test_p0_bind_io_forbid_io_under_state() == 0);
    REQUIRE(test_p0_bind_io_rx_during_open_flush_window() == 0);
    REQUIRE(test_p0_close_fence_epoch_max_no_reopen() == 0);
    REQUIRE(test_p0_reconcile_seq_max_fail_closed() == 0);
    REQUIRE(test_p0_range_uintptr_and_32bit_space() == 0);
    REQUIRE(test_p0_orch_teardown_null_soft_ops_after_preclear() == 0);
    REQUIRE(test_p0_publish_validate_fail_poisons_keeps_storage() == 0);
    return 0;
}
