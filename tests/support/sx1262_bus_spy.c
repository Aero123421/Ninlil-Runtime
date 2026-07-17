#include "sx1262_bus_spy.h"

#include <string.h>

static void push_trace(
    ninlil_sx1262_bus_spy_t *spy,
    ninlil_sx1262_spy_event_t ev,
    uint32_t opcode,
    uint32_t len,
    const uint8_t *sample,
    size_t sample_len)
{
    ninlil_sx1262_spy_trace_t *rec;
    size_t i;

    if (spy == NULL || spy->trace_len >= NINLIL_SX1262_SPY_TRACE_CAP) {
        return;
    }
    rec = &spy->trace[spy->trace_len];
    (void)memset(rec, 0, sizeof(*rec));
    spy->trace_seq = ninlil_sx1262_sat_add_u64(spy->trace_seq, 1u);
    rec->sequence = spy->trace_seq;
    rec->event = ev;
    rec->opcode = opcode;
    rec->len = len;
    if (sample != NULL && sample_len > 0u) {
        rec->sample_len = (uint8_t)(sample_len > NINLIL_SX1262_SPY_XFER_SAMPLE
                ? NINLIL_SX1262_SPY_XFER_SAMPLE
                : sample_len);
        for (i = 0u; i < (size_t)rec->sample_len; ++i) {
            rec->sample[i] = sample[i];
        }
    }
    spy->trace_len += 1u;
}

void ninlil_sx1262_bus_spy_init(ninlil_sx1262_bus_spy_t *spy)
{
    if (spy == NULL) {
        return;
    }
    (void)memset(spy, 0, sizeof(*spy));
    spy->advance_ms_per_now = 1u;
    ninlil_sx1262_bus_spy_model_healthy(spy);
}

void ninlil_sx1262_bus_spy_model_healthy(ninlil_sx1262_bus_spy_t *spy)
{
    if (spy == NULL) {
        return;
    }
    spy->busy_high = 0;
    spy->miso_rfu_byte = 0u;
    spy->status_byte =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    spy->device_errors = 0u;
    spy->device_errors_after_cal = 0u;
    spy->busy_low_after_polls = 0;
    spy->busy_polls = 0;
    spy->force_busy_stuck = 0;
    spy->delayed_busy_assert_polls = 0;
    spy->post_spi_busy_phase = 0;
    spy->post_spi_busy_high_left = 0;
    spy->busy_low_when_now_ge = 0u;
    if (spy->advance_ms_per_now == 0u) {
        /* allow frozen clock tests to keep 0 */
    }
}

static int spy_reset_assert(void *ctx)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;

    if (spy == NULL) {
        return 1;
    }
    spy->reset_assert_calls =
        ninlil_sx1262_sat_add_u64(spy->reset_assert_calls, 1u);
    push_trace(spy, NINLIL_SX1262_SPY_EV_RESET_ASSERT, 0u, 0u, NULL, 0u);
    if (spy->fail_reset_assert != 0) {
        return 1;
    }
    spy->busy_high = 1;
    spy->busy_polls = 0;
    return 0;
}

static int spy_reset_deassert(void *ctx)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;

    if (spy == NULL) {
        return 1;
    }
    spy->reset_deassert_calls =
        ninlil_sx1262_sat_add_u64(spy->reset_deassert_calls, 1u);
    push_trace(spy, NINLIL_SX1262_SPY_EV_RESET_DEASSERT, 0u, 0u, NULL, 0u);
    if (spy->fail_reset_deassert != 0) {
        return 1;
    }
    if (spy->force_busy_stuck == 0 && spy->busy_low_after_polls == 0
        && spy->busy_low_when_now_ge == 0u) {
        spy->busy_high = 0;
    } else if (spy->force_busy_stuck == 0 && spy->busy_low_when_now_ge == 0u) {
        spy->busy_high = 1;
        spy->busy_polls = 0;
    }
    return 0;
}

static int spy_busy_is_high(void *ctx, int *out_high)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;

    if (spy == NULL || out_high == NULL) {
        return 1;
    }
    spy->busy_calls = ninlil_sx1262_sat_add_u64(spy->busy_calls, 1u);
    if (spy->fail_busy_read != 0) {
        return 1;
    }
    if (spy->fail_busy_on_call_n != 0
        && spy->busy_calls == (uint64_t)spy->fail_busy_on_call_n) {
        return 1;
    }

    /* Monotonic release: BUSY low once wall clock reaches threshold. */
    if (spy->busy_low_when_now_ge != 0u
        && spy->now_ms >= spy->busy_low_when_now_ge) {
        *out_high = 0;
        spy->busy_high = 0;
        push_trace(spy, NINLIL_SX1262_SPY_EV_BUSY_POLL, 0u, 0u, NULL, 0u);
        return 0;
    }

    /* Delayed post-SPI BUSY assert model */
    if (spy->post_spi_busy_phase > 0) {
        spy->post_spi_busy_phase -= 1;
        *out_high = 0;
        push_trace(spy, NINLIL_SX1262_SPY_EV_BUSY_POLL, 0u, 0u, NULL, 0u);
        if (spy->post_spi_busy_phase == 0) {
            spy->busy_high = 1;
            spy->post_spi_busy_high_left =
                spy->busy_low_after_polls > 0 ? spy->busy_low_after_polls : 2;
        }
        return 0;
    }
    if (spy->post_spi_busy_high_left > 0) {
        *out_high = 1;
        spy->post_spi_busy_high_left -= 1;
        if (spy->post_spi_busy_high_left == 0) {
            spy->busy_high = 0;
        }
        push_trace(spy, NINLIL_SX1262_SPY_EV_BUSY_POLL, 1u, 0u, NULL, 0u);
        return 0;
    }

    if (spy->force_busy_stuck != 0) {
        *out_high = 1;
        push_trace(spy, NINLIL_SX1262_SPY_EV_BUSY_POLL, 1u, 0u, NULL, 0u);
        return 0;
    }
    if (spy->busy_high != 0 && spy->busy_low_after_polls > 0) {
        spy->busy_polls += 1;
        if (spy->busy_polls >= spy->busy_low_after_polls) {
            spy->busy_high = 0;
        }
    }
    *out_high = spy->busy_high != 0 ? 1 : 0;
    push_trace(
        spy, NINLIL_SX1262_SPY_EV_BUSY_POLL, (uint32_t)(*out_high), 0u, NULL, 0u);
    return 0;
}

static int spy_spi_transfer(
    void *ctx,
    const uint8_t *tx,
    uint8_t *rx,
    size_t len)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;
    uint8_t opcode;

    if (spy == NULL || tx == NULL || len == 0u) {
        return 1;
    }
    spy->spi_calls = ninlil_sx1262_sat_add_u64(spy->spi_calls, 1u);
    opcode = tx[0];
    if (opcode == NINLIL_SX1262_CMD_SET_TX) {
        spy->settx_opcodes_seen =
            ninlil_sx1262_sat_add_u64(spy->settx_opcodes_seen, 1u);
    }
    push_trace(spy, NINLIL_SX1262_SPY_EV_SPI, opcode, (uint32_t)len, tx, len);

    if (spy->short_spi != 0 && len > spy->short_spi_max) {
        return 1;
    }
    if (spy->fail_spi_on_n != 0
        && spy->spi_calls == (uint64_t)spy->fail_spi_on_n) {
        return 1;
    }

    if (rx != NULL) {
        uint8_t status_b;

        (void)memset(rx, 0, len);
        if (len >= 1u) {
            rx[0] = spy->miso_rfu_byte;
        }
        status_b = spy->status_byte;
        if (opcode == NINLIL_SX1262_CMD_GET_STATUS) {
            spy->get_status_count += 1;
            if (spy->fail_status_after_n_gets != 0
                && spy->get_status_count >= spy->fail_status_after_n_gets) {
                status_b = spy->status_byte_poison;
                spy->status_byte = spy->status_byte_poison;
            }
        }
        spy->spi_xfer_count_for_status += 1;
        if (spy->fail_status_after_n_spi != 0
            && spy->spi_xfer_count_for_status >= spy->fail_status_after_n_spi) {
            status_b = spy->status_byte_poison;
            spy->status_byte = spy->status_byte_poison;
        }
        if (len >= 2u) {
            rx[1] = status_b;
        }
        if (opcode == NINLIL_SX1262_CMD_GET_DEVICE_ERRORS && len >= 4u) {
            rx[2] = (uint8_t)((spy->device_errors >> 8) & 0xFFu);
            rx[3] = (uint8_t)(spy->device_errors & 0xFFu);
        }
    }

    if (opcode == NINLIL_SX1262_CMD_CALIBRATE
        && spy->device_errors_after_cal != 0u) {
        spy->device_errors = spy->device_errors_after_cal;
    }
    if (opcode == NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS) {
        spy->device_errors = 0u;
    }

    if (spy->delayed_busy_assert_polls > 0) {
        spy->post_spi_busy_phase = spy->delayed_busy_assert_polls;
        spy->busy_high = 0;
    } else if (spy->force_busy_stuck == 0 && spy->busy_low_when_now_ge == 0u) {
        spy->busy_high = 0;
    }
    return 0;
}

static int spy_delay_us(void *ctx, uint32_t us)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;

    if (spy == NULL) {
        return 1;
    }
    spy->delay_calls = ninlil_sx1262_sat_add_u64(spy->delay_calls, 1u);
    spy->last_delay_us = us;
    push_trace(spy, NINLIL_SX1262_SPY_EV_DELAY, us, 0u, NULL, 0u);
    if (spy->reenter_tx_on_delay != 0 && spy->reenter_backend != NULL
        && spy->reenter_tx_calls == 0u) {
        ninlil_sx1262_error_t err;
        uint8_t frame[1] = {0xAAu};

        spy->reenter_tx_calls =
            ninlil_sx1262_sat_add_u64(spy->reenter_tx_calls, 1u);
        spy->reenter_tx_status = ninlil_sx1262_request_transmit(
            spy->reenter_backend, frame, 1u, &err);
    }
    if (spy->fail_delay != 0) {
        return 1;
    }
    if (spy->fail_delay_on_call_n != 0
        && spy->delay_calls == (uint64_t)spy->fail_delay_on_call_n) {
        return 1;
    }
    if (spy->fail_delay_us_eq != 0u && us == spy->fail_delay_us_eq
        && spy->fail_delay_us_eq_armed == 0) {
        spy->fail_delay_us_eq_armed = 1;
        return 1;
    }
    if (spy->post_spi_busy_phase > 0 && us > 0u) {
        if ((uint32_t)spy->post_spi_busy_phase <= us) {
            spy->post_spi_busy_phase = 0;
            spy->busy_high = 1;
            spy->post_spi_busy_high_left =
                spy->busy_low_after_polls > 0 ? spy->busy_low_after_polls : 2;
        } else {
            spy->post_spi_busy_phase -= (int)us;
        }
    }
    /*
     * Delay advances wall now_ms unless freeze_delay_clock (poll-cap) or
     * hold_delay_clock_until_busy (NRESET pulse before first BUSY sample).
     */
    if (spy->freeze_delay_clock == 0
        && !(spy->hold_delay_clock_until_busy != 0 && spy->busy_calls == 0u)
        && us > 0u && us <= UINT32_MAX - spy->us_accum) {
        spy->us_accum += us;
        while (spy->us_accum >= 1000u) {
            spy->now_ms = spy->now_ms + 1u;
            spy->us_accum -= 1000u;
        }
    }
    return 0;
}

static int spy_now_ms(void *ctx, uint64_t *out_ms)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;

    if (spy == NULL || out_ms == NULL) {
        return 1;
    }
    spy->now_calls = ninlil_sx1262_sat_add_u64(spy->now_calls, 1u);
    if (spy->fail_now != 0) {
        return 1;
    }
    if (spy->fail_now_on_call_n != 0
        && spy->now_calls == (uint64_t)spy->fail_now_on_call_n) {
        return 1;
    }
    *out_ms = spy->now_ms;
    spy->last_now_returned = spy->now_ms;
    if (spy->first_now_captured == 0) {
        spy->first_now_returned = spy->now_ms;
        spy->first_now_captured = 1;
    }
    spy->now_ms = spy->now_ms + (uint64_t)spy->advance_ms_per_now;
    push_trace(spy, NINLIL_SX1262_SPY_EV_NOW, 0u, 0u, NULL, 0u);
    return 0;
}

static int spy_ant_sw_set(void *ctx, int active)
{
    ninlil_sx1262_bus_spy_t *spy = (ninlil_sx1262_bus_spy_t *)ctx;

    if (spy == NULL) {
        return 1;
    }
    spy->ant_sw_set_calls =
        ninlil_sx1262_sat_add_u64(spy->ant_sw_set_calls, 1u);
    spy->last_ant_sw_active = active;
    return 0;
}

static const ninlil_sx1262_bus_ops_t s_ops = {
    spy_reset_assert,
    spy_reset_deassert,
    spy_busy_is_high,
    spy_spi_transfer,
    spy_delay_us,
    spy_now_ms,
    NULL
};

static const ninlil_sx1262_bus_ops_t s_ops_ant = {
    spy_reset_assert,
    spy_reset_deassert,
    spy_busy_is_high,
    spy_spi_transfer,
    spy_delay_us,
    spy_now_ms,
    spy_ant_sw_set
};

const ninlil_sx1262_bus_ops_t *ninlil_sx1262_bus_spy_ops(void)
{
    return &s_ops;
}

const ninlil_sx1262_bus_ops_t *ninlil_sx1262_bus_spy_ops_with_ant_sw(void)
{
    return &s_ops_ant;
}

void ninlil_sx1262_bus_spy_ops_copy(ninlil_sx1262_bus_ops_t *out)
{
    if (out == NULL) {
        return;
    }
    *out = s_ops;
}

size_t ninlil_sx1262_bus_spy_count_opcode(
    const ninlil_sx1262_bus_spy_t *spy,
    uint8_t opcode)
{
    size_t i;
    size_t n = 0u;

    if (spy == NULL) {
        return 0u;
    }
    for (i = 0u; i < spy->trace_len; ++i) {
        if (spy->trace[i].event == NINLIL_SX1262_SPY_EV_SPI
            && spy->trace[i].opcode == (uint32_t)opcode) {
            n += 1u;
        }
    }
    return n;
}

int ninlil_sx1262_bus_spy_spi_opcode_sequence_eq(
    const ninlil_sx1262_bus_spy_t *spy,
    const uint8_t *expected,
    size_t expected_len)
{
    size_t i;
    size_t j = 0u;

    if (spy == NULL || (expected == NULL && expected_len != 0u)) {
        return 0;
    }
    for (i = 0u; i < spy->trace_len; ++i) {
        if (spy->trace[i].event != NINLIL_SX1262_SPY_EV_SPI) {
            continue;
        }
        if (j >= expected_len) {
            return 0;
        }
        if ((uint8_t)spy->trace[i].opcode != expected[j]) {
            return 0;
        }
        j += 1u;
    }
    return j == expected_len ? 1 : 0;
}

size_t ninlil_sx1262_bus_spy_last_len_for_opcode(
    const ninlil_sx1262_bus_spy_t *spy,
    uint8_t opcode)
{
    size_t i;
    size_t last = 0u;

    if (spy == NULL) {
        return 0u;
    }
    for (i = 0u; i < spy->trace_len; ++i) {
        if (spy->trace[i].event == NINLIL_SX1262_SPY_EV_SPI
            && spy->trace[i].opcode == (uint32_t)opcode) {
            last = (size_t)spy->trace[i].len;
        }
    }
    return last;
}

size_t ninlil_sx1262_bus_spy_nth_spi_index(
    const ninlil_sx1262_bus_spy_t *spy,
    size_t n_zero_based)
{
    size_t i;
    size_t n = 0u;

    if (spy == NULL) {
        return (size_t)-1;
    }
    for (i = 0u; i < spy->trace_len; ++i) {
        if (spy->trace[i].event == NINLIL_SX1262_SPY_EV_SPI) {
            if (n == n_zero_based) {
                return i;
            }
            n += 1u;
        }
    }
    return (size_t)-1;
}

size_t ninlil_sx1262_bus_spy_spi_event_count(const ninlil_sx1262_bus_spy_t *spy)
{
    size_t i;
    size_t n = 0u;

    if (spy == NULL) {
        return 0u;
    }
    for (i = 0u; i < spy->trace_len; ++i) {
        if (spy->trace[i].event == NINLIL_SX1262_SPY_EV_SPI) {
            n += 1u;
        }
    }
    return n;
}
