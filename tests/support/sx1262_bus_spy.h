#ifndef NINLIL_TEST_SX1262_BUS_SPY_H
#define NINLIL_TEST_SX1262_BUS_SPY_H

/*
 * Host-only R4 bus spy. Not production. Not public ABI.
 */

#include "ninlil_sx1262_backend.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_SPY_TRACE_CAP ((size_t)160u)
#define NINLIL_SX1262_SPY_XFER_SAMPLE ((size_t)8u)

typedef uint32_t ninlil_sx1262_spy_event_t;

#define NINLIL_SX1262_SPY_EV_RESET_ASSERT ((ninlil_sx1262_spy_event_t)1u)
#define NINLIL_SX1262_SPY_EV_RESET_DEASSERT ((ninlil_sx1262_spy_event_t)2u)
#define NINLIL_SX1262_SPY_EV_BUSY_POLL ((ninlil_sx1262_spy_event_t)3u)
#define NINLIL_SX1262_SPY_EV_SPI ((ninlil_sx1262_spy_event_t)4u)
#define NINLIL_SX1262_SPY_EV_DELAY ((ninlil_sx1262_spy_event_t)5u)
#define NINLIL_SX1262_SPY_EV_NOW ((ninlil_sx1262_spy_event_t)6u)

typedef struct ninlil_sx1262_spy_trace {
    uint64_t sequence;
    ninlil_sx1262_spy_event_t event;
    uint32_t opcode; /* SPI opcode, or delay_us, or busy high flag */
    uint32_t len;
    uint8_t sample[NINLIL_SX1262_SPY_XFER_SAMPLE];
    uint8_t sample_len;
    uint8_t reserved0[3];
} ninlil_sx1262_spy_trace_t;

typedef struct ninlil_sx1262_bus_spy {
    int busy_high;
    /*
     * DS Rev2.2 Table 10-1 / 13-85: MISO byte0=RFU, byte1=Status.
     * Independent so tests can prove rx[0] is not decoded as status.
     */
    uint8_t miso_rfu_byte;
    uint8_t status_byte;
    uint16_t device_errors;
    uint16_t device_errors_after_cal; /* if set, apply after CALIBRATE */

    int fail_reset_assert;
    int fail_reset_deassert;
    /* 0=off; fail when call count (after increment) equals N */
    int fail_busy_on_call_n;
    int fail_delay_on_call_n;
    int fail_now_on_call_n;
    /* 0=off; fail first delay whose us equals this value (reset/guard/poll). */
    uint32_t fail_delay_us_eq;
    int fail_delay_us_eq_armed; /* internal once */

    int fail_busy_read; /* legacy: fail every busy read if non-zero */
    int fail_delay;     /* legacy: fail every delay if non-zero */
    int fail_now;       /* legacy: fail every now if non-zero */
    int fail_spi_on_n;
    int force_busy_stuck;
    int busy_low_after_polls;
    int busy_polls;
    /*
     * Monotonic deadline helper: when now_ms >= busy_low_when_now_ge (if !=0),
     * report BUSY low (overrides force_busy_stuck).
     */
    uint64_t busy_low_when_now_ge;

    /*
     * After each SPI, schedule delayed BUSY assert:
     * for busy_delay_assert_polls after SPI, report low, then high until
     * busy_low_after_polls clears. Tests post-guard requirement.
     */
    int delayed_busy_assert_polls;
    int post_spi_busy_phase; /* 0=idle, >0 remaining low-before-assert polls */
    int post_spi_busy_high_left;

    int short_spi;
    size_t short_spi_max;

    /* After N GetStatus SPI calls, switch status_byte to poison. 0=off */
    int fail_status_after_n_gets;
    int get_status_count;
    /* After N SPI of any opcode, poison status_byte (rx[1]). 0=off */
    int fail_status_after_n_spi;
    int spi_xfer_count_for_status;
    uint8_t status_byte_poison;

    uint64_t now_ms;
    uint32_t advance_ms_per_now; /* side-effect step on each now_ms call */
    uint32_t us_accum; /* for delay→ms conversion */
    /* 1 = delay does not advance now_ms (frozen clock poll-cap tests). */
    int freeze_delay_clock;
    /*
     * 1 = ignore delay→ms until first busy_is_high (isolates post-reset wait
     * from NRESET pulse time for deadline tests).
     */
    int hold_delay_clock_until_busy;
    /* First now_ms sample returned (wait_busy_low start after hold ends). */
    uint64_t first_now_returned;
    int first_now_captured;
    /* Last now_ms value returned to caller (deadline comparison sample). */
    uint64_t last_now_returned;

    uint64_t reset_assert_calls;
    uint64_t reset_deassert_calls;
    uint64_t busy_calls;
    uint64_t spi_calls;
    uint64_t delay_calls;
    uint64_t now_calls;
    uint64_t settx_opcodes_seen;
    uint64_t ant_sw_set_calls;
    int last_ant_sw_active;
    uint64_t last_delay_us;

    /*
     * INITING re-entry: during delay_us, call request_transmit on reenter_backend
     * (same object storage under init). Observes BUSY + zero extra SPI.
     */
    int reenter_tx_on_delay;
    ninlil_sx1262_backend_t *reenter_backend;
    ninlil_sx1262_status_t reenter_tx_status;
    uint64_t reenter_tx_calls;

    ninlil_sx1262_spy_trace_t trace[NINLIL_SX1262_SPY_TRACE_CAP];
    size_t trace_len;
    uint64_t trace_seq;
} ninlil_sx1262_bus_spy_t;

void ninlil_sx1262_bus_spy_init(ninlil_sx1262_bus_spy_t *spy);
void ninlil_sx1262_bus_spy_model_healthy(ninlil_sx1262_bus_spy_t *spy);
const ninlil_sx1262_bus_ops_t *ninlil_sx1262_bus_spy_ops(void);
const ninlil_sx1262_bus_ops_t *ninlil_sx1262_bus_spy_ops_with_ant_sw(void);

/* Mutable ops table for NULL-function-pointer matrix tests (not const). */
void ninlil_sx1262_bus_spy_ops_copy(ninlil_sx1262_bus_ops_t *out);

size_t ninlil_sx1262_bus_spy_count_opcode(
    const ninlil_sx1262_bus_spy_t *spy,
    uint8_t opcode);

int ninlil_sx1262_bus_spy_spi_opcode_sequence_eq(
    const ninlil_sx1262_bus_spy_t *spy,
    const uint8_t *expected,
    size_t expected_len);

/* Exact SPI transfer lengths for opcode (0 if never seen). */
size_t ninlil_sx1262_bus_spy_last_len_for_opcode(
    const ninlil_sx1262_bus_spy_t *spy,
    uint8_t opcode);

/* Index of N-th SPI event in trace (0-based N); SIZE_MAX if missing. */
size_t ninlil_sx1262_bus_spy_nth_spi_index(
    const ninlil_sx1262_bus_spy_t *spy,
    size_t n_zero_based);

/* Count SPI events in trace. */
size_t ninlil_sx1262_bus_spy_spi_event_count(const ninlil_sx1262_bus_spy_t *spy);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TEST_SX1262_BUS_SPY_H */
