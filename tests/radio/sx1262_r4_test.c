/*
 * R4 host tests (audit P1). Not R4 complete / RF / HIL.
 * docs/28 §12.1 T01–T15 tracking — gate enforces tokens.
 */

#include "ninlil_esp_idf/sx1262_bus.h"
#include "ninlil_sx1262_backend.h"
#include "sx1262_bus_spy.h"
#include "sx1262_esp_gpio_init_logic.h"
#include "sx1262_spi_pending_logic.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Pure ESP timeout helpers (no ESP headers). */
int ninlil_esp_idf_sx1262_ms_to_ticks(
    uint32_t timeout_ms,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks);
int ninlil_esp_idf_sx1262_us_to_ticks_ceil(
    uint32_t delay_us,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks);

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c);      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

/*
 * Independent Semtech primary-source opcode pins (docs/28 §3.1 / §12.2).
 * Hex literals only — MUST NOT use NINLIL_SX1262_CMD_* for expected values
 * (production macro drift must not update golden expectations).
 */
enum {
    SX126X_GOLDEN_GET_STATUS = 0xC0u,
    SX126X_GOLDEN_SET_STANDBY = 0x80u,
    SX126X_GOLDEN_GET_DEVICE_ERRORS = 0x17u,
    SX126X_GOLDEN_CLR_DEVICE_ERRORS = 0x07u,
    SX126X_GOLDEN_SET_REGULATOR_MODE = 0x96u,
    SX126X_GOLDEN_CALIBRATE = 0x89u,
    SX126X_GOLDEN_SET_DIO2_RF_SWITCH = 0x9Du,
    SX126X_GOLDEN_SET_DIO3_TCXO = 0x97u,
    SX126X_GOLDEN_SET_TX_BAN = 0x83u,
    SX126X_GOLDEN_SPI_NOP = 0x00u,
    SX126X_GOLDEN_STANDBY_RC = 0x00u,
    SX126X_GOLDEN_STANDBY_XOSC = 0x01u,
    SX126X_GOLDEN_REG_LDO = 0x00u,
    SX126X_GOLDEN_REG_DCDC = 0x01u,
    SX126X_GOLDEN_CAL_ALL = 0x7Fu,
    SX126X_GOLDEN_TCXO_1_8V = 0x02u
};

/* Independent golden SPI sequences (not production macros). */
static const uint8_t k_xtal_ok[] = {
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_GET_DEVICE_ERRORS,
    SX126X_GOLDEN_GET_STATUS, /* verify after GetErrors */
    SX126X_GOLDEN_SET_REGULATOR_MODE,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_SET_STANDBY,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_GET_STATUS
};

static void fill_valid_board(ninlil_sx1262_board_config_t *cfg)
{
    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->abi_version = NINLIL_SX1262_ABI_VERSION;
    cfg->struct_size = (uint16_t)sizeof(*cfg);
    cfg->pin_nss = 1001u;
    cfg->pin_sck = 1002u;
    cfg->pin_mosi = 1003u;
    cfg->pin_miso = 1004u;
    cfg->pin_reset = 1005u;
    cfg->pin_busy = 1006u;
    cfg->pin_dio1 = 1007u;
    cfg->pin_ant_sw = NINLIL_SX1262_PIN_UNSET;
    cfg->reset_pulse_us = 1000u;
    cfg->busy_timeout_ms = 50u;
    cfg->spi_busy_timeout_ms = 50u;
    cfg->post_spi_busy_guard_us = 1u;
    cfg->busy_poll_interval_us = 100u;
    cfg->busy_poll_slack = 2u;
    cfg->regulator_mode = NINLIL_SX1262_REG_MODE_LDO;
}

static int test_calc_polls_overflow(void)
{
    uint64_t maxp;

    REQUIRE(ninlil_sx1262_calc_busy_max_polls(50u, 100u, 2u, &maxp) == 1);
    /* ceil(50000/100)+2 = 500+2 = 502 */
    REQUIRE(maxp == 502u);
    REQUIRE(ninlil_sx1262_calc_busy_max_polls(0u, 100u, 2u, &maxp) == 0);
    REQUIRE(ninlil_sx1262_calc_busy_max_polls(50u, 0u, 2u, &maxp) == 0);
    REQUIRE(ninlil_sx1262_calc_busy_max_polls(50u, 100u, 0u, &maxp) == 0);
    REQUIRE(
        ninlil_sx1262_calc_busy_max_polls(
            NINLIL_SX1262_TIMEOUT_MS_MAX + 1u, 100u, 2u, &maxp)
        == 0);
    return 0;
}

static int test_esp_ticks_overflow(void)
{
    uint32_t ticks;

    REQUIRE(ninlil_esp_idf_sx1262_ms_to_ticks(1u, 1000u, &ticks) == 1);
    REQUIRE(ticks == 1u);
    REQUIRE(ninlil_esp_idf_sx1262_ms_to_ticks(0u, 1000u, &ticks) == 0);
    REQUIRE(ninlil_esp_idf_sx1262_ms_to_ticks(10u, 0u, &ticks) == 0);
    REQUIRE(ninlil_esp_idf_sx1262_ms_to_ticks(1000u, 1000u, &ticks) == 1);
    REQUIRE(ticks == 1000u);
    /* us→ticks: 1ms @ 100Hz must be ≥1 tick (not pdMS_TO_TICKS round-down 0) */
    REQUIRE(ninlil_esp_idf_sx1262_us_to_ticks_ceil(1000u, 100u, &ticks) == 1);
    REQUIRE(ticks >= 1u);
    REQUIRE(ninlil_esp_idf_sx1262_us_to_ticks_ceil(1u, 1000u, &ticks) == 1);
    REQUIRE(ticks == 1u);
    REQUIRE(ninlil_esp_idf_sx1262_us_to_ticks_ceil(0u, 1000u, &ticks) == 0);
    return 0;
}

static int test_success_xtal(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    REQUIRE(be->last_chip_mode == NINLIL_SX1262_CHIP_MODE_STBY_RC);
    REQUIRE(ninlil_sx1262_bus_spy_spi_opcode_sequence_eq(
        &spy, k_xtal_ok, sizeof(k_xtal_ok)));
    REQUIRE(ninlil_sx1262_bus_spy_last_len_for_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_GET_STATUS)
        == 2u);
    REQUIRE(ninlil_sx1262_bus_spy_last_len_for_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS)
        == 4u);
    REQUIRE(spy.settx_opcodes_seen == 0u);
    return 0;
}

static void fill_tcxo_board(ninlil_sx1262_board_config_t *cfg)
{
    fill_valid_board(cfg);
    cfg->feature_flags = NINLIL_SX1262_FEATURE_TCXO_PRESENT
        | NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH;
    cfg->tcxo_delay_rtc_steps = 0x010203u;
    cfg->tcxo_busy_timeout_ms = 50u;
    cfg->tcxo_voltage = NINLIL_SX1262_TCXO_1_8V;
    cfg->vdd_op_mv = 3300u;
    cfg->regulator_mode = NINLIL_SX1262_REG_MODE_DCDC;
}

/* DS §9.2.1: raw cold bits → Clear → SetDIO3 → CAL_ALL → post errors 0. */
static int tcxo_cold_positive(uint16_t cold_errors)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    size_t i;
    int saw_get_err = 0;
    int saw_clr = 0;
    int saw_dio3 = 0;
    int saw_cal = 0;
    int found_reg = 0;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_tcxo_board(&cfg);
    spy.device_errors = cold_errors;

    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    REQUIRE(be->first_device_errors == cold_errors);
    if (cold_errors != 0u) {
        REQUIRE(be->expected_cold_errors_latched == (uint32_t)cold_errors);
        REQUIRE(be->stats.expected_cold_errors_seen == 1u);
        REQUIRE(ninlil_sx1262_bus_spy_last_len_for_opcode(
                    &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
            == 3u);
    } else {
        REQUIRE(be->stats.expected_cold_errors_seen == 0u);
        REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                    &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
            == 0u);
    }
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_SET_DIO2_RF_SWITCH)
        == 1u);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_CALIBRATE)
        == 1u);

    /* Ordering: GetErrors → (Clear?) → … → SetDIO3 → CAL_ALL (golden pins) */
    for (i = 0u; i < spy.trace_len; ++i) {
        if (spy.trace[i].event != NINLIL_SX1262_SPY_EV_SPI) {
            continue;
        }
        if (spy.trace[i].opcode == (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS
            && !saw_get_err) {
            saw_get_err = 1;
        }
        if (spy.trace[i].opcode == (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS) {
            REQUIRE(saw_get_err == 1);
            REQUIRE(saw_dio3 == 0);
            REQUIRE(saw_cal == 0);
            saw_clr = 1;
        }
        if (spy.trace[i].opcode == (uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO) {
            if (cold_errors != 0u) {
                REQUIRE(saw_clr == 1);
            }
            REQUIRE(saw_cal == 0);
            saw_dio3 = 1;
            REQUIRE(spy.trace[i].sample_len >= 5u);
            REQUIRE(spy.trace[i].sample[1] == (uint8_t)SX126X_GOLDEN_TCXO_1_8V);
            REQUIRE(spy.trace[i].sample[2] == 0x01u);
            REQUIRE(spy.trace[i].sample[3] == 0x02u);
            REQUIRE(spy.trace[i].sample[4] == 0x03u);
        }
        if (spy.trace[i].opcode == (uint8_t)SX126X_GOLDEN_CALIBRATE) {
            REQUIRE(saw_dio3 == 1);
            saw_cal = 1;
            REQUIRE(spy.trace[i].sample_len >= 2u);
            REQUIRE(spy.trace[i].sample[1] == (uint8_t)SX126X_GOLDEN_CAL_ALL);
        }
        if (spy.trace[i].opcode == (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE
            && spy.trace[i].sample_len >= 2u
            && spy.trace[i].sample[1] == (uint8_t)SX126X_GOLDEN_REG_DCDC) {
            found_reg = 1;
        }
    }
    REQUIRE(saw_get_err == 1);
    REQUIRE(saw_dio3 == 1);
    REQUIRE(saw_cal == 1);
    REQUIRE(found_reg == 1);
    REQUIRE(be->last_device_errors == 0u);
    return 0;
}

static int test_tcxo_path(void)
{
    /* XOSC-only positive (also wires DIO2/regulator/Cal ALL bytes). */
    return tcxo_cold_positive(NINLIL_SX1262_ERR_XOSC_START);
}

static int test_tcxo_cold_img_only(void)
{
    return tcxo_cold_positive(NINLIL_SX1262_ERR_IMG_CAL);
}

static int test_tcxo_cold_both(void)
{
    return tcxo_cold_positive(
        (uint16_t)(NINLIL_SX1262_ERR_XOSC_START | NINLIL_SX1262_ERR_IMG_CAL));
}

static int test_tcxo_cold_zero(void)
{
    /* Clean TCXO board: no cold bits → Clear skipped, SetDIO3+CAL still. */
    return tcxo_cold_positive(0u);
}

static int test_tcxo_cold_mixed_negative(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* XOSC + unexpected PLL_CAL → fail; Clear must not run. */
    ninlil_sx1262_bus_spy_init(&spy);
    fill_tcxo_board(&cfg);
    spy.device_errors = (uint16_t)(NINLIL_SX1262_ERR_XOSC_START
        | NINLIL_SX1262_ERR_PLL_CAL);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
        == 0u);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO)
        == 0u);
    REQUIRE(be->stats.expected_cold_errors_seen == 0u);

    /* IMG + unexpected PLL_LOCK */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_tcxo_board(&cfg);
    spy.device_errors = (uint16_t)(NINLIL_SX1262_ERR_IMG_CAL
        | NINLIL_SX1262_ERR_PLL_LOCK);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
        == 0u);

    /* Both expected bits + unexpected RC64K */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_tcxo_board(&cfg);
    spy.device_errors = (uint16_t)(NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED
        | NINLIL_SX1262_ERR_RC64K_CAL);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
        == 0u);
    return 0;
}

static int test_ant_sw_contracts(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* Flag off + ant_sw_set non-NULL → reject (unused callback). */
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops_with_ant_sw(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);

    /* Flag on + pin UNSET → reject. */
    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_ANT_SW_PRESENT;
    cfg.pin_ant_sw = NINLIL_SX1262_PIN_UNSET;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops_with_ant_sw(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);

    /* Flag on + pin dup with DIO1 → reject. */
    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_ANT_SW_PRESENT;
    cfg.pin_ant_sw = cfg.pin_dio1;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops_with_ant_sw(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_PIN_DUP);

    /* Flag on + pin set but ops without ant_sw_set → reject. */
    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_ANT_SW_PRESENT;
    cfg.pin_ant_sw = 1008u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);

    /* Positive: safe inactive level after successful init (active-high). */
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_ANT_SW_PRESENT;
    cfg.pin_ant_sw = 1008u;
    cfg.ant_sw_active_high = 1u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops_with_ant_sw(), &spy, &be,
            &err)
        == NINLIL_SX1262_OK);
    REQUIRE(spy.ant_sw_set_calls == 1u);
    REQUIRE(spy.last_ant_sw_active == 0); /* logical inactive */
    return 0;
}

static int test_error_before_clear(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.device_errors = NINLIL_SX1262_ERR_PLL_CAL;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
        == 0u);
    return 0;
}

static int test_cmd_status_fail_first(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.status_byte = (uint8_t)(0x20u | (3u << 1));
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_STATUS_INVALID);
    return 0;
}

static int test_cmd_status_fail_after_write(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    /* After first GetStatus OK, poison status for subsequent GetStatus verify */
    spy.status_byte =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    spy.fail_status_after_n_gets = 2; /* second GetStatus (verify after GetErrors) */
    spy.status_byte_poison = (uint8_t)(0x20u | (5u << 1));
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_STATUS_INVALID);
    return 0;
}

static int test_frozen_clock_poll_cap(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = 5u;
    cfg.busy_poll_interval_us = 1000u;
    cfg.busy_poll_slack = 2u;
    spy.force_busy_stuck = 1;
    spy.advance_ms_per_now = 0u;
    spy.freeze_delay_clock = 1; /* poll-cap without delay advancing wall */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_BUSY_TIMEOUT);
    REQUIRE(spy.spi_calls == 0u);
    return 0;
}

static int test_clock_wrap(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = 3u;
    spy.now_ms = UINT64_MAX - 1u;
    spy.force_busy_stuck = 1;
    spy.advance_ms_per_now = 1u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_BUSY_TIMEOUT);
    return 0;
}

static int test_delayed_busy(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.post_spi_busy_guard_us = 2u;
    spy.delayed_busy_assert_polls = 2;
    spy.busy_low_after_polls = 2;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    return 0;
}

static int test_tx_deny_and_failed_zero_spi(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    uint64_t spi0;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.device_errors = NINLIL_SX1262_ERR_IMG_CAL;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    spi0 = spy.spi_calls;
    REQUIRE(
        ninlil_sx1262_request_transmit(be, (const uint8_t *)"x", 1u, &err)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(spy.spi_calls == spi0);
    REQUIRE(spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_config_bounds(void)
{
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* R4: reset_pulse_us must be exactly 1000 (SWSD003); not ">=100". */
    fill_valid_board(&cfg);
    cfg.reset_pulse_us = 99u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    fill_valid_board(&cfg);
    cfg.reset_pulse_us = 100u; /* DS typical — not accepted as R4 value */
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    fill_valid_board(&cfg);
    cfg.reset_pulse_us = 1001u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    fill_valid_board(&cfg);
    cfg.reserved0 = 1u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_RESERVED);
    /* interval_us > timeout_us: 1ms busy with 1_000_000 us interval */
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = 1u;
    cfg.busy_poll_interval_us = 1000000u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    /* boundary: interval == timeout_us OK */
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = 1u;
    cfg.spi_busy_timeout_ms = 1u;
    cfg.busy_poll_interval_us = 1000u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_OK);
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = 1u;
    cfg.spi_busy_timeout_ms = 1u;
    cfg.busy_poll_interval_us = 1001u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    fill_valid_board(&cfg);
    cfg.busy_poll_interval_us = 0u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    fill_valid_board(&cfg);
    cfg.regulator_mode = 9u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    /* TCXO_PRESENT requires nonzero tcxo_delay_rtc_steps */
    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_TCXO_PRESENT;
    cfg.tcxo_delay_rtc_steps = 0u;
    cfg.tcxo_busy_timeout_ms = 20u;
    cfg.tcxo_voltage = NINLIL_SX1262_TCXO_1_8V;
    cfg.vdd_op_mv = 3300u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_TCXO_DELAY);
    return 0;
}

/*
 * P1-1: DS Table 10-1 / 13-85 — status is rx[1], not rx[0].
 * (a) rx[0] error-like RFU, rx[1] healthy → success
 * (b) rx[0] healthy RFU, rx[1] fail on GetDeviceErrors → STATUS_INVALID
 */
static int test_miso_status_byte_position(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    const uint8_t healthy =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    const uint8_t fail5 = (uint8_t)(0x20u | (5u << 1)); /* EXEC_FAILURE */

    /* (a) RFU byte looks like cmd_status fail; status byte healthy → OK */
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.miso_rfu_byte = fail5;
    spy.status_byte = healthy;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    REQUIRE(be->last_status_byte == healthy);

    /* (b) GetDeviceErrors (2nd SPI after reset GetStatus): poison rx[1] only */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.miso_rfu_byte = 0u;
    spy.status_byte = healthy;
    spy.fail_status_after_n_spi = 2; /* GetDeviceErrors xfer */
    spy.status_byte_poison = fail5;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_STATUS_INVALID);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS)
        == 1u);
    /* Must fail on GetDeviceErrors MISO status before Clear / later path */
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
        == 0u);
    REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                &spy, (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE)
        == 0u);

    /* (b2) also fail when only GetStatus rx[1] is poisoned mid-path (write verify) */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.miso_rfu_byte = fail5; /* still ignored */
    spy.status_byte = healthy;
    spy.fail_status_after_n_gets = 2;
    spy.status_byte_poison = fail5;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_STATUS_INVALID);
    return 0;
}

/* Host compile-time + runtime: ESP bus trans_storage alignment (no ESP types). */
static int test_esp_bus_trans_storage_align(void)
{
    ninlil_esp_idf_sx1262_bus_t bus = NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT;
    uintptr_t addr;

    REQUIRE(
        sizeof(bus.trans_storage) == NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES);
    addr = (uintptr_t)(void *)&bus.trans_storage[0];
    REQUIRE((addr % (uintptr_t)_Alignof(max_align_t)) == 0u);
    REQUIRE(
        (offsetof(ninlil_esp_idf_sx1262_bus_t, trans_storage)
            % _Alignof(max_align_t))
        == 0u);
    return 0;
}

static int test_rfu_and_tx_done_reject(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* RFU=1 on mid-init GetStatus verify after GetErrors */
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.status_byte =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    spy.fail_status_after_n_gets = 2;
    spy.status_byte_poison = (uint8_t)(0x20u | (1u << 1)); /* RFU */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_STATUS_INVALID);

    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.status_byte =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);
    spy.fail_status_after_n_gets = 2;
    spy.status_byte_poison = (uint8_t)(0x20u | (6u << 1)); /* TX_DONE */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_STATUS_INVALID);
    return 0;
}

static int test_shutdown_reinit(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_backend_t *be2 = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    /* T10: READY double init */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be2, &err)
        == NINLIL_SX1262_INVALID_STATE);
    REQUIRE(ninlil_sx1262_shutdown(be, &err) == NINLIL_SX1262_OK);
    ninlil_sx1262_bus_spy_init(&spy);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    return 0;
}

/* --- docs/28 §12.1 T02–T15 expansion --- */

static int test_null_args(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_init(
            NULL, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(spy.spi_calls == 0u);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, NULL, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(spy.spi_calls == 0u);
    REQUIRE(
        ninlil_sx1262_init(&obj, &cfg, NULL, &spy, &be, &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(spy.spi_calls == 0u);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, NULL, &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(spy.spi_calls == 0u);
    REQUIRE(
        ninlil_sx1262_validate_board_config(NULL, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_sx1262_validate_board_config(&cfg, NULL, &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    return 0;
}

static int test_each_required_pin_unset(void)
{
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    size_t i;

    for (i = 0u; i < 7u; ++i) {
        fill_valid_board(&cfg);
        switch (i) {
        case 0u:
            cfg.pin_nss = NINLIL_SX1262_PIN_UNSET;
            break;
        case 1u:
            cfg.pin_sck = NINLIL_SX1262_PIN_UNSET;
            break;
        case 2u:
            cfg.pin_mosi = NINLIL_SX1262_PIN_UNSET;
            break;
        case 3u:
            cfg.pin_miso = NINLIL_SX1262_PIN_UNSET;
            break;
        case 4u:
            cfg.pin_reset = NINLIL_SX1262_PIN_UNSET;
            break;
        case 5u:
            cfg.pin_busy = NINLIL_SX1262_PIN_UNSET;
            break;
        default:
            cfg.pin_dio1 = NINLIL_SX1262_PIN_UNSET;
            break;
        }
        REQUIRE(
            ninlil_sx1262_validate_board_config(
                &cfg, ninlil_sx1262_bus_spy_ops(), &err)
            == NINLIL_SX1262_INVALID_ARGUMENT);
        REQUIRE(err.reason == NINLIL_SX1262_REASON_PIN_UNSET);
    }
    return 0;
}

static int test_pin_duplicate(void)
{
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    fill_valid_board(&cfg);
    cfg.pin_sck = cfg.pin_nss;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_PIN_DUP);

    fill_valid_board(&cfg);
    cfg.pin_dio1 = cfg.pin_busy;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);

    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_ANT_SW_PRESENT;
    cfg.pin_ant_sw = cfg.pin_reset;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops_with_ant_sw(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_PIN_DUP);
    return 0;
}

static int test_feature_mismatches(void)
{
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* TCXO params without flag */
    fill_valid_board(&cfg);
    cfg.tcxo_delay_rtc_steps = 1u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_FEATURE_MISMATCH);

    /* TCXO flag without VDD margin */
    fill_valid_board(&cfg);
    cfg.feature_flags = NINLIL_SX1262_FEATURE_TCXO_PRESENT;
    cfg.tcxo_delay_rtc_steps = 10u;
    cfg.tcxo_busy_timeout_ms = 20u;
    cfg.tcxo_voltage = NINLIL_SX1262_TCXO_3_3V;
    cfg.vdd_op_mv = 3300u; /* not > 3300+200 */
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    REQUIRE(err.reason == NINLIL_SX1262_REASON_TCXO_VDD);

    /* ANT_SW pin without flag */
    fill_valid_board(&cfg);
    cfg.pin_ant_sw = 1008u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);

    /* unknown feature bit */
    fill_valid_board(&cfg);
    cfg.feature_flags = (uint32_t)8u;
    REQUIRE(
        ninlil_sx1262_validate_board_config(
            &cfg, ninlil_sx1262_bus_spy_ops(), &err)
        == NINLIL_SX1262_INVALID_ARGUMENT);
    return 0;
}

/* XTAL golden SPI count (verify+final GetStatus). */
/* Independent golden: TCXO+DIO2+XOSC cold (verify after each write + post-cal). */
static const uint8_t k_tcxo_dio2_xosc[] = {
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_GET_DEVICE_ERRORS,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_CLR_DEVICE_ERRORS,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_SET_REGULATOR_MODE,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_SET_DIO2_RF_SWITCH,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_SET_DIO3_TCXO,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_CALIBRATE,
    SX126X_GOLDEN_GET_STATUS, /* verify after Calibrate write */
    SX126X_GOLDEN_GET_STATUS, /* post-cal GetStatus */
    SX126X_GOLDEN_GET_DEVICE_ERRORS,
    SX126X_GOLDEN_GET_STATUS,
    SX126X_GOLDEN_SET_STANDBY,
    SX126X_GOLDEN_GET_STATUS, /* verify after SetStandby */
    SX126X_GOLDEN_GET_STATUS  /* final STBY_RC */
};

static int test_bus_faults_matrix(void)
{
    ninlil_sx1262_backend_object_t obj;
    ninlil_sx1262_backend_t *be;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    uint64_t spi_n;
    size_t xtal_n;
    size_t tcxo_n;
    size_t step;
    ninlil_sx1262_bus_ops_t ops;
    size_t op_i;

    /* Measure full SPI counts on success */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    xtal_n = ninlil_sx1262_bus_spy_spi_event_count(&spy);
    REQUIRE(xtal_n == sizeof(k_xtal_ok));
    REQUIRE(ninlil_sx1262_bus_spy_spi_opcode_sequence_eq(
        &spy, k_xtal_ok, sizeof(k_xtal_ok)));

    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_tcxo_board(&cfg);
    spy.device_errors = NINLIL_SX1262_ERR_XOSC_START;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    tcxo_n = ninlil_sx1262_bus_spy_spi_event_count(&spy);
    REQUIRE(tcxo_n == sizeof(k_tcxo_dio2_xosc));
    REQUIRE(ninlil_sx1262_bus_spy_spi_opcode_sequence_eq(
        &spy, k_tcxo_dio2_xosc, sizeof(k_tcxo_dio2_xosc)));

    /* SPI error at every XTAL transfer step */
    for (step = 1u; step <= xtal_n; ++step) {
        obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
        ninlil_sx1262_bus_spy_init(&spy);
        fill_valid_board(&cfg);
        spy.fail_spi_on_n = (int)step;
        REQUIRE(
            ninlil_sx1262_init(
                &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
            != NINLIL_SX1262_OK);
        REQUIRE(spy.spi_calls == (uint64_t)step);
        spi_n = spy.spi_calls;
        REQUIRE(
            ninlil_sx1262_request_transmit(be, (const uint8_t *)"x", 1u, &err)
            == NINLIL_SX1262_TX_DENIED);
        REQUIRE(spy.spi_calls == spi_n);
        REQUIRE(spy.settx_opcodes_seen == 0u);
    }

    /* SPI error at every TCXO+DIO2 transfer step */
    for (step = 1u; step <= tcxo_n; ++step) {
        obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
        ninlil_sx1262_bus_spy_init(&spy);
        fill_tcxo_board(&cfg);
        spy.device_errors = NINLIL_SX1262_ERR_XOSC_START;
        spy.fail_spi_on_n = (int)step;
        REQUIRE(
            ninlil_sx1262_init(
                &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
            != NINLIL_SX1262_OK);
        REQUIRE(spy.spi_calls == (uint64_t)step);
        spi_n = spy.spi_calls;
        REQUIRE(
            ninlil_sx1262_request_transmit(be, (const uint8_t *)"x", 1u, &err)
            == NINLIL_SX1262_TX_DENIED);
        REQUIRE(spy.spi_calls == spi_n);
        REQUIRE(spy.settx_opcodes_seen == 0u);
    }

    /* reset_assert / deassert / short */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_reset_assert = 1;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);
    REQUIRE(spy.reset_deassert_calls >= 1u);

    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_reset_deassert = 1;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);

    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.short_spi = 1;
    spy.short_spi_max = 1u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_SPI_ERROR);

    /*
     * Required ops function-pointer NULL matrix — typed members only
     * (no void** / strict-aliasing; ISO C portable).
     */
    for (op_i = 0u; op_i < 6u; ++op_i) {
        ninlil_sx1262_bus_spy_ops_copy(&ops);
        switch (op_i) {
        case 0u:
            ops.reset_assert = NULL;
            break;
        case 1u:
            ops.reset_deassert = NULL;
            break;
        case 2u:
            ops.busy_is_high = NULL;
            break;
        case 3u:
            ops.spi_transfer = NULL;
            break;
        case 4u:
            ops.delay_us = NULL;
            break;
        default:
            ops.now_ms = NULL;
            break;
        }
        fill_valid_board(&cfg);
        REQUIRE(
            ninlil_sx1262_validate_board_config(&cfg, &ops, &err)
            == NINLIL_SX1262_INVALID_ARGUMENT);
    }
    return 0;
}

/* BUSY read fail at post-reset wait and post-SPI BUSY positions */
static int test_fail_busy_read_positions(void)
{
    ninlil_sx1262_backend_object_t obj;
    ninlil_sx1262_backend_t *be;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* First BUSY sample after reset */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_busy_on_call_n = 1;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);

    /*
     * Reachable positions before SPI: (1) post-reset wait, (2) pre-SPI wait.
     * Post-SPI BUSY is call 3 after SPI1 (reset + pre-SPI + post-SPI).
     */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_busy_on_call_n = 3;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls >= 1u);
    REQUIRE(spy.settx_opcodes_seen == 0u);
    return 0;
}

/* Delay fail: reset pulse / post-guard / busy-poll interval */
static int test_delay_fail_positions(void)
{
    ninlil_sx1262_backend_object_t obj;
    ninlil_sx1262_backend_t *be;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    /* reset_pulse_us == 1000 */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_delay_us_eq = 1000u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);

    /* post_spi_busy_guard_us == 1 after first SPI */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_delay_us_eq = 1u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls >= 1u);

    /* busy poll interval while stuck (after reset, before SPI) */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.force_busy_stuck = 1;
    spy.fail_delay_us_eq = 100u; /* poll interval */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);
    return 0;
}

/* now_ms fail at first sample and mid-loop */
static int test_now_fail_positions(void)
{
    ninlil_sx1262_backend_object_t obj;
    ninlil_sx1262_backend_t *be;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;

    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.fail_now_on_call_n = 1; /* start of post-reset wait */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);

    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.force_busy_stuck = 1;
    spy.fail_now_on_call_n = 2; /* loop after first delay */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        != NINLIL_SX1262_OK);
    REQUIRE(spy.spi_calls == 0u);
    return 0;
}

static int test_timeout_boundary_exact(void)
{
    uint64_t maxp;

    /* poll formula exact: timeout_ms=1, interval=1000us, slack=1 → 2 */
    REQUIRE(ninlil_sx1262_calc_busy_max_polls(1u, 1000u, 1u, &maxp) == 1);
    REQUIRE(maxp == 2u);
    return 0;
}

/*
 * Pure deadline predicate 1:1 with wait_busy_low:
 *   elapsed < timeout → not reached
 *   elapsed == timeout → reached (BUSY_TIMEOUT)
 *   elapsed > timeout → reached
 */
static int test_busy_deadline_helper(void)
{
    REQUIRE(ninlil_sx1262_busy_deadline_reached(100u, 104u, 5u) == 0);
    REQUIRE(ninlil_sx1262_busy_deadline_reached(100u, 105u, 5u) == 1);
    REQUIRE(ninlil_sx1262_busy_deadline_reached(100u, 106u, 5u) == 1);
    /* wrap-safe: start near max */
    REQUIRE(
        ninlil_sx1262_busy_deadline_reached(
            UINT64_MAX - 1u, UINT64_MAX - 1u + 5u, 5u)
        == 1);
    REQUIRE(ninlil_sx1262_busy_deadline_reached(UINT64_MAX - 1u, UINT64_MAX, 5u)
        == 0);
    return 0;
}

/*
 * Monotonic deadline via full wait_busy (distinct from frozen poll-cap).
 * hold_delay_clock_until_busy isolates NRESET 1ms from wait start.
 * Boundary (docs/28): elapsed >= timeout_ms ⇒ BUSY_TIMEOUT.
 *   before (<): release BUSY → OK
 *   exact (==): BUSY_TIMEOUT, last_now - wait_start == timeout
 *   after (>): BUSY_TIMEOUT, last_now - wait_start > timeout
 */
static int test_monotonic_deadline_boundary(void)
{
    ninlil_sx1262_backend_object_t obj;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    uint64_t wait_start;
    uint64_t elapsed;
    const uint32_t timeout = 5u;

    /* before: release at wait_start + (timeout - 1) → elapsed max 4 < 5 → OK */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = timeout;
    cfg.spi_busy_timeout_ms = 50u;
    cfg.busy_poll_interval_us = 1000u;
    cfg.busy_poll_slack = 16u;
    spy.now_ms = 10000u;
    spy.advance_ms_per_now = 0u;
    spy.hold_delay_clock_until_busy = 1;
    spy.force_busy_stuck = 1;
    /* wait_start will be 10000; release when now >= 10004 */
    spy.busy_low_when_now_ge = 10000u + (uint64_t)timeout - 1u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    REQUIRE(spy.first_now_captured == 1);
    wait_start = spy.first_now_returned;
    REQUIRE(wait_start == 10000u);
    REQUIRE(spy.last_now_returned - wait_start < (uint64_t)timeout);

    /* exact: never release; first deadline hit when elapsed == timeout */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = timeout;
    cfg.spi_busy_timeout_ms = 50u;
    cfg.busy_poll_interval_us = 1000u;
    cfg.busy_poll_slack = 16u;
    spy.now_ms = 20000u;
    spy.advance_ms_per_now = 0u;
    spy.hold_delay_clock_until_busy = 1;
    spy.force_busy_stuck = 1;
    spy.busy_low_when_now_ge = 0u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_BUSY_TIMEOUT);
    REQUIRE(err.status == NINLIL_SX1262_BUSY_TIMEOUT);
    wait_start = spy.first_now_returned;
    REQUIRE(wait_start == 20000u);
    elapsed = spy.last_now_returned - wait_start;
    REQUIRE(elapsed == (uint64_t)timeout);
    REQUIRE(ninlil_sx1262_busy_deadline_reached(
                wait_start, spy.last_now_returned, timeout)
        == 1);
    REQUIRE(spy.spi_calls == 0u);

    /*
     * after: interval 3ms, timeout 5ms → samples elapsed 3 then 6;
     * first fire when elapsed 6 > 5 (strictly after exact boundary).
     */
    obj = (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    cfg.busy_timeout_ms = 5u;
    cfg.spi_busy_timeout_ms = 50u;
    cfg.busy_poll_interval_us = 3000u;
    cfg.busy_poll_slack = 16u;
    spy.now_ms = 30000u;
    spy.advance_ms_per_now = 0u;
    spy.hold_delay_clock_until_busy = 1;
    spy.force_busy_stuck = 1;
    spy.busy_low_when_now_ge = 0u;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_BUSY_TIMEOUT);
    wait_start = spy.first_now_returned;
    REQUIRE(wait_start == 30000u);
    elapsed = spy.last_now_returned - wait_start;
    REQUIRE(elapsed > 5u);
    REQUIRE(ninlil_sx1262_busy_deadline_reached(
                wait_start, spy.last_now_returned, 5u)
        == 1);
    REQUIRE(spy.spi_calls == 0u);
    return 0;
}

static int test_initing_reentry(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    uint64_t spi_before_reenter;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.reenter_tx_on_delay = 1;
    spy.reenter_backend = &obj; /* same storage; in_flight during init */
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    REQUIRE(spy.reenter_tx_calls == 1u);
    REQUIRE(spy.reenter_tx_status == NINLIL_SX1262_BUSY);
    REQUIRE(be->stats.reentrant >= 1u);
    REQUIRE(spy.settx_opcodes_seen == 0u);
    (void)spi_before_reenter;
    return 0;
}

static int test_failed_shutdown_reinit(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    uint64_t spi0;

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.device_errors = NINLIL_SX1262_ERR_PLL_CAL;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    REQUIRE(be != NULL);
    REQUIRE(be->lifecycle != 0u); /* FAILED domain */
    spi0 = spy.spi_calls;
    /* direct re-init from FAILED refused (out_backend nulled on entry) */
    {
        ninlil_sx1262_backend_t *failed = be;
        ninlil_sx1262_backend_t *be2 = NULL;

        REQUIRE(
            ninlil_sx1262_init(
                &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be2, &err)
            == NINLIL_SX1262_INVALID_STATE);
        REQUIRE(be2 == NULL);
        REQUIRE(spy.spi_calls == spi0);
        REQUIRE(ninlil_sx1262_shutdown(failed, &err) == NINLIL_SX1262_OK);
    }
    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    return 0;
}

static int test_tx_deny_all_lifecycles(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_object_t zero_obj = NINLIL_SX1262_OBJECT_INIT;
    ninlil_sx1262_backend_t *be = NULL;
    ninlil_sx1262_bus_spy_t spy;
    ninlil_sx1262_board_config_t cfg;
    ninlil_sx1262_error_t err;
    uint8_t frame[2] = {0x83u, 0x00u};
    uint64_t spi0;

    /* ZERO / never inited — separate object so last_error does not dirty init */
    REQUIRE(
        ninlil_sx1262_request_transmit(&zero_obj, frame, 2u, &err)
        == NINLIL_SX1262_INVALID_STATE);
    REQUIRE(err.status == NINLIL_SX1262_INVALID_STATE);

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    spy.device_errors = NINLIL_SX1262_ERR_PLL_CAL;
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_DEVICE_ERROR);
    spi0 = spy.spi_calls;
    REQUIRE(
        ninlil_sx1262_request_transmit(be, frame, 2u, &err)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(spy.spi_calls == spi0);
    REQUIRE(spy.settx_opcodes_seen == 0u);

    REQUIRE(ninlil_sx1262_shutdown(be, &err) == NINLIL_SX1262_OK);
    REQUIRE(
        ninlil_sx1262_request_transmit(be, frame, 2u, &err)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(spy.settx_opcodes_seen == 0u);

    ninlil_sx1262_bus_spy_init(&spy);
    fill_valid_board(&cfg);
    REQUIRE(
        ninlil_sx1262_init(
            &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
        == NINLIL_SX1262_OK);
    spi0 = spy.spi_calls;
    REQUIRE(
        ninlil_sx1262_request_transmit(be, frame, 2u, &err)
        == NINLIL_SX1262_TX_DENIED);
    REQUIRE(spy.spi_calls == spi0);
    REQUIRE(spy.settx_opcodes_seen == 0u);
    return 0;
}

static int test_object_size_align(void)
{
    ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;

    REQUIRE(ninlil_sx1262_object_size() <= NINLIL_SX1262_OBJECT_BYTES);
    REQUIRE(ninlil_sx1262_object_size() == sizeof(ninlil_sx1262_backend_t));
    REQUIRE(ninlil_sx1262_object_align() >= NINLIL_SX1262_OBJECT_ALIGN);
    REQUIRE(
        ((uintptr_t)(void *)&obj % NINLIL_SX1262_OBJECT_ALIGN) == 0u);
    return 0;
}

/* T15: pure SPI pending ownership SM (ESP adapter contracts). */
static int test_spi_pending_ownership_sm(void)
{
    ninlil_sx1262_spi_own_t own;
    uint32_t norm;
    uint64_t wait_ms;

    /* Drain budget closed set: 0→default3; 1..16 ok; 17 reject */
    REQUIRE(ninlil_sx1262_spi_own_normalize_max_drain(0u, &norm) == 1);
    REQUIRE(norm == NINLIL_SX1262_SPI_OWN_DEFAULT_MAX_DRAIN);
    REQUIRE(norm == 3u);
    REQUIRE(ninlil_sx1262_spi_own_normalize_max_drain(1u, &norm) == 1);
    REQUIRE(norm == 1u);
    REQUIRE(ninlil_sx1262_spi_own_normalize_max_drain(16u, &norm) == 1);
    REQUIRE(norm == 16u);
    REQUIRE(ninlil_sx1262_spi_own_normalize_max_drain(17u, &norm) == 0);
    REQUIRE(ninlil_sx1262_spi_own_normalize_max_drain(100u, &norm) == 0);
    /* Finite shutdown wait: attempts * timeout_ms */
    REQUIRE(
        ninlil_sx1262_spi_own_max_drain_wait_ms(3u, 50u, &wait_ms) == 1);
    REQUIRE(wait_ms == 150u);
    REQUIRE(
        ninlil_sx1262_spi_own_max_drain_wait_ms(16u, 1000u, &wait_ms) == 1);
    REQUIRE(wait_ms == 16000u);
    REQUIRE(ninlil_sx1262_spi_own_max_drain_wait_ms(0u, 50u, &wait_ms) == 0);
    REQUIRE(ninlil_sx1262_spi_own_max_drain_wait_ms(17u, 50u, &wait_ms) == 0);

    /* Path A: queue → result timeout → late drain → may release → reinit */
    ninlil_sx1262_spi_own_reset(&own, 3u);
    REQUIRE(ninlil_sx1262_spi_own_can_transfer(&own) == 1);
    REQUIRE(ninlil_sx1262_spi_own_on_queued(&own) == 1);
    REQUIRE(own.pend == NINLIL_SX1262_SPI_PEND_IN_FLIGHT);
    REQUIRE(ninlil_sx1262_spi_own_can_transfer(&own) == 0);
    REQUIRE(ninlil_sx1262_spi_own_on_result_timeout(&own) == 1);
    REQUIRE(own.pend == NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD);
    REQUIRE(own.poisoned == 1u);
    REQUIRE(ninlil_sx1262_spi_own_may_release_hw(&own) == 0);
    REQUIRE(ninlil_sx1262_spi_own_needs_drain(&own) == 1);
    REQUIRE(ninlil_sx1262_spi_own_on_drain_ok(&own) == 1);
    REQUIRE(own.pend == NINLIL_SX1262_SPI_PEND_NONE);
    REQUIRE(own.poisoned == 1u); /* still fail-closed */
    REQUIRE(ninlil_sx1262_spi_own_may_release_hw(&own) == 1);
    ninlil_sx1262_spi_own_on_hw_released(&own);
    REQUIRE(own.life == NINLIL_SX1262_SPI_OWN_LIFE_SHUTDOWN);
    REQUIRE(ninlil_sx1262_spi_own_reinit_allowed(&own) == 1);

    /* Path B: continuous drain timeout → reboot-required; no release */
    ninlil_sx1262_spi_own_reset(&own, 2u);
    REQUIRE(ninlil_sx1262_spi_own_on_queued(&own) == 1);
    REQUIRE(ninlil_sx1262_spi_own_on_result_timeout(&own) == 1);
    REQUIRE(ninlil_sx1262_spi_own_on_drain_timeout(&own) == 1);
    REQUIRE(own.drain_attempts == 1u);
    REQUIRE(ninlil_sx1262_spi_own_is_reboot_required(&own) == 0);
    REQUIRE(ninlil_sx1262_spi_own_on_drain_timeout(&own) == 1);
    REQUIRE(own.drain_attempts == 2u);
    REQUIRE(ninlil_sx1262_spi_own_is_reboot_required(&own) == 1);
    REQUIRE(own.life == NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED);
    REQUIRE(own.pend == NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD);
    REQUIRE(ninlil_sx1262_spi_own_may_release_hw(&own) == 0);
    REQUIRE(ninlil_sx1262_spi_own_reinit_allowed(&own) == 0);
    REQUIRE(ninlil_sx1262_spi_own_can_transfer(&own) == 0);
    /*
     * Caller MUST: bus object + trans_storage/scratch stay alive/immutable
     * until reboot — may_release_object_storage == 0.
     */
    REQUIRE(ninlil_sx1262_spi_own_may_release_object_storage(&own) == 0);
    /* never clear pending on reboot path — UAF ban */
    REQUIRE(own.pend != NINLIL_SX1262_SPI_PEND_NONE);
    /* After clean release path, object storage may be released */
    ninlil_sx1262_spi_own_reset(&own, 3u);
    REQUIRE(ninlil_sx1262_spi_own_may_release_object_storage(&own) == 1);

    /* Happy queue/result */
    ninlil_sx1262_spi_own_reset(&own, 3u);
    REQUIRE(ninlil_sx1262_spi_own_on_queued(&own) == 1);
    REQUIRE(ninlil_sx1262_spi_own_on_result_ok(&own) == 1);
    REQUIRE(own.pend == NINLIL_SX1262_SPI_PEND_NONE);
    REQUIRE(ninlil_sx1262_spi_own_can_transfer(&own) == 1);
    return 0;
}

/*
 * A: mid-init rx[1] {0,2}; reject 1/3/4/5/6.
 * Exact ordering via spy event trace (not string heuristics):
 *   2nd SPI → GUARD delay (us==post_spi_busy_guard) → BUSY_POLL → fail
 *   (no further SPI / no SetRegulator).
 */
static int test_mid_status_closed_set_after_busy(void)
{
    const uint8_t codes[] = {1u, 3u, 4u, 5u, 6u};
    size_t i;
    const uint8_t healthy =
        (uint8_t)(NINLIL_SX1262_CHIP_MODE_STBY_RC << NINLIL_SX1262_CHIP_MODES_POS);

    for (i = 0u; i < sizeof(codes); ++i) {
        ninlil_sx1262_backend_object_t obj = NINLIL_SX1262_OBJECT_INIT;
        ninlil_sx1262_backend_t *be = NULL;
        ninlil_sx1262_bus_spy_t spy;
        ninlil_sx1262_board_config_t cfg;
        ninlil_sx1262_error_t err;
        size_t spi2;
        size_t j;
        int saw_guard = 0;
        int saw_busy = 0;

        ninlil_sx1262_bus_spy_init(&spy);
        fill_valid_board(&cfg);
        spy.status_byte = healthy;
        spy.fail_status_after_n_spi = 2; /* GetDeviceErrors */
        spy.status_byte_poison =
            (uint8_t)(0x20u | (uint8_t)(codes[i] << 1));
        REQUIRE(
            ninlil_sx1262_init(
                &obj, &cfg, ninlil_sx1262_bus_spy_ops(), &spy, &be, &err)
            == NINLIL_SX1262_STATUS_INVALID);
        REQUIRE(ninlil_sx1262_bus_spy_spi_event_count(&spy) == 2u);
        REQUIRE(ninlil_sx1262_bus_spy_count_opcode(
                    &spy, (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE)
            == 0u);
        spi2 = ninlil_sx1262_bus_spy_nth_spi_index(&spy, 1u);
        REQUIRE(spi2 != (size_t)-1);
        for (j = spi2 + 1u; j < spy.trace_len; ++j) {
            if (spy.trace[j].event == NINLIL_SX1262_SPY_EV_SPI) {
                REQUIRE(0); /* no SPI after 2nd until fail */
            }
            if (spy.trace[j].event == NINLIL_SX1262_SPY_EV_DELAY
                && spy.trace[j].opcode == cfg.post_spi_busy_guard_us) {
                REQUIRE(saw_busy == 0); /* guard before post-BUSY */
                saw_guard = 1;
            }
            if (spy.trace[j].event == NINLIL_SX1262_SPY_EV_BUSY_POLL) {
                REQUIRE(saw_guard == 1);
                saw_busy = 1;
            }
        }
        REQUIRE(saw_guard == 1);
        REQUIRE(saw_busy == 1);
    }
    return 0;
}

/*
 * B: closed command schema using independent golden opcodes/params.
 * Production validator must accept primary-source frames; production macros
 * are only compared in test_primary_opcode_pin (not used as frame builders).
 */
static int test_cmd_frame_schema(void)
{
    uint8_t tx[8];

    /* GetStatus */
    tx[0] = (uint8_t)SX126X_GOLDEN_GET_STATUS;
    tx[1] = (uint8_t)SX126X_GOLDEN_SPI_NOP;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 1);
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 1u) == 0);
    tx[1] = 0xFFu;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);

    /* SetStandby RC only */
    tx[0] = (uint8_t)SX126X_GOLDEN_SET_STANDBY;
    tx[1] = (uint8_t)SX126X_GOLDEN_STANDBY_RC;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 1);
    tx[1] = (uint8_t)SX126X_GOLDEN_STANDBY_XOSC;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);

    /* ClearDeviceErrors len=3 NOP */
    tx[0] = (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS;
    tx[1] = (uint8_t)SX126X_GOLDEN_SPI_NOP;
    tx[2] = (uint8_t)SX126X_GOLDEN_SPI_NOP;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 3u) == 1);
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);
    tx[1] = 1u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 3u) == 0);

    /* GetDeviceErrors len=4 */
    tx[0] = (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS;
    tx[1] = tx[2] = tx[3] = (uint8_t)SX126X_GOLDEN_SPI_NOP;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 4u) == 1);
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 3u) == 0);

    /* Regulator LDO/DCDC */
    tx[0] = (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE;
    tx[1] = (uint8_t)SX126X_GOLDEN_REG_LDO;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 1);
    tx[1] = (uint8_t)SX126X_GOLDEN_REG_DCDC;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 1);
    tx[1] = 9u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);

    /* Calibrate ALL only */
    tx[0] = (uint8_t)SX126X_GOLDEN_CALIBRATE;
    tx[1] = (uint8_t)SX126X_GOLDEN_CAL_ALL;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 1);
    tx[1] = 0x01u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);

    /* DIO2 enable=1 */
    tx[0] = (uint8_t)SX126X_GOLDEN_SET_DIO2_RF_SWITCH;
    tx[1] = 1u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 1);
    tx[1] = 0u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);

    /* DIO3: voltage + nonzero delay24 */
    tx[0] = (uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO;
    tx[1] = (uint8_t)SX126X_GOLDEN_TCXO_1_8V;
    tx[2] = 0x00u;
    tx[3] = 0x00u;
    tx[4] = 0x01u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 5u) == 1);
    tx[4] = 0u;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 5u) == 0);
    tx[4] = 1u;
    tx[1] = 0xFFu;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 5u) == 0);
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 4u) == 0);

    /* ban opcode never valid */
    tx[0] = (uint8_t)SX126X_GOLDEN_SET_TX_BAN;
    tx[1] = 0;
    REQUIRE(ninlil_sx1262_cmd_frame_valid(tx, 2u) == 0);
    return 0;
}

/*
 * Production macros must match independent Semtech primary pins.
 * Detects production opcode drift without rewriting golden expectations.
 * Allowlist all 8 opcodes + ban SetTx + params pinned as test-side literals.
 */
static int test_primary_opcode_pin(void)
{
    /* Allowlist (docs/28 §3.1) — 8 opcodes */
    REQUIRE((uint8_t)SX126X_GOLDEN_GET_STATUS == 0xC0u);
    REQUIRE((uint8_t)SX126X_GOLDEN_SET_STANDBY == 0x80u);
    REQUIRE((uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS == 0x17u);
    REQUIRE((uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS == 0x07u);
    REQUIRE((uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE == 0x96u);
    REQUIRE((uint8_t)SX126X_GOLDEN_CALIBRATE == 0x89u);
    REQUIRE((uint8_t)SX126X_GOLDEN_SET_DIO2_RF_SWITCH == 0x9Du);
    REQUIRE((uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO == 0x97u);
    /* Ban + params */
    REQUIRE((uint8_t)SX126X_GOLDEN_SET_TX_BAN == 0x83u);
    REQUIRE((uint8_t)SX126X_GOLDEN_SPI_NOP == 0x00u);
    REQUIRE((uint8_t)SX126X_GOLDEN_STANDBY_RC == 0x00u);
    REQUIRE((uint8_t)SX126X_GOLDEN_STANDBY_XOSC == 0x01u);
    REQUIRE((uint8_t)SX126X_GOLDEN_REG_LDO == 0x00u);
    REQUIRE((uint8_t)SX126X_GOLDEN_REG_DCDC == 0x01u);
    REQUIRE((uint8_t)SX126X_GOLDEN_CAL_ALL == 0x7Fu);
    REQUIRE((uint8_t)SX126X_GOLDEN_TCXO_1_8V == 0x02u);

    /* Production drift vs independent golden (not used to build golden) */
    REQUIRE(NINLIL_SX1262_CMD_GET_STATUS == (uint8_t)SX126X_GOLDEN_GET_STATUS);
    REQUIRE(NINLIL_SX1262_CMD_SET_STANDBY == (uint8_t)SX126X_GOLDEN_SET_STANDBY);
    REQUIRE(
        NINLIL_SX1262_CMD_GET_DEVICE_ERRORS
        == (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS);
    REQUIRE(
        NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS
        == (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS);
    REQUIRE(
        NINLIL_SX1262_CMD_SET_REGULATOR_MODE
        == (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE);
    REQUIRE(NINLIL_SX1262_CMD_CALIBRATE == (uint8_t)SX126X_GOLDEN_CALIBRATE);
    REQUIRE(
        NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL
        == (uint8_t)SX126X_GOLDEN_SET_DIO2_RF_SWITCH);
    REQUIRE(
        NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL
        == (uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO);
    REQUIRE(NINLIL_SX1262_CMD_SET_TX == (uint8_t)SX126X_GOLDEN_SET_TX_BAN);
    REQUIRE(NINLIL_SX1262_SPI_NOP == (uint8_t)SX126X_GOLDEN_SPI_NOP);
    REQUIRE(NINLIL_SX1262_STANDBY_CFG_RC == (uint8_t)SX126X_GOLDEN_STANDBY_RC);
    REQUIRE(NINLIL_SX1262_STANDBY_CFG_XOSC == (uint8_t)SX126X_GOLDEN_STANDBY_XOSC);
    REQUIRE(NINLIL_SX1262_REG_MODE_LDO == (uint8_t)SX126X_GOLDEN_REG_LDO);
    REQUIRE(NINLIL_SX1262_REG_MODE_DCDC == (uint8_t)SX126X_GOLDEN_REG_DCDC);
    REQUIRE(NINLIL_SX1262_CAL_ALL == (uint8_t)SX126X_GOLDEN_CAL_ALL);
    REQUIRE(NINLIL_SX1262_TCXO_1_8V == (uint8_t)SX126X_GOLDEN_TCXO_1_8V);

    /* Allowlist closed set: each of 8 is allowlisted; SetTx banned */
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted((uint8_t)SX126X_GOLDEN_GET_STATUS)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted((uint8_t)SX126X_GOLDEN_SET_STANDBY)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted(
                (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted(
                (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted(
                (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted((uint8_t)SX126X_GOLDEN_CALIBRATE)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted(
                (uint8_t)SX126X_GOLDEN_SET_DIO2_RF_SWITCH)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted(
                (uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO)
        == 1);
    REQUIRE(ninlil_sx1262_cmd_is_allowlisted((uint8_t)SX126X_GOLDEN_SET_TX_BAN)
        == 0);
    REQUIRE(ninlil_sx1262_cmd_is_rf_banned((uint8_t)SX126X_GOLDEN_SET_TX_BAN)
        == 1);

    /* Sequence vectors built only from golden (not production macros) */
    REQUIRE(sizeof(k_xtal_ok) >= 8u);
    REQUIRE(k_xtal_ok[0] == (uint8_t)SX126X_GOLDEN_GET_STATUS);
    REQUIRE(k_xtal_ok[1] == (uint8_t)SX126X_GOLDEN_GET_DEVICE_ERRORS);
    REQUIRE(k_xtal_ok[3] == (uint8_t)SX126X_GOLDEN_SET_REGULATOR_MODE);
    REQUIRE(k_xtal_ok[5] == (uint8_t)SX126X_GOLDEN_SET_STANDBY);
    REQUIRE(k_tcxo_dio2_xosc[0] == (uint8_t)SX126X_GOLDEN_GET_STATUS);
    REQUIRE(k_tcxo_dio2_xosc[3] == (uint8_t)SX126X_GOLDEN_CLR_DEVICE_ERRORS);
    REQUIRE(k_tcxo_dio2_xosc[7] == (uint8_t)SX126X_GOLDEN_SET_DIO2_RF_SWITCH);
    REQUIRE(k_tcxo_dio2_xosc[9] == (uint8_t)SX126X_GOLDEN_SET_DIO3_TCXO);
    REQUIRE(k_tcxo_dio2_xosc[11] == (uint8_t)SX126X_GOLDEN_CALIBRATE);
    return 0;
}

/* E: ESP GPIO safe-init SM + polarity */
static int test_esp_gpio_safe_init_sm(void)
{
    ninlil_sx1262_gpio_init_sm_t sm;

    REQUIRE(ninlil_sx1262_ant_inactive_level(1u) == 0);
    REQUIRE(ninlil_sx1262_ant_active_level(1u) == 1);
    REQUIRE(ninlil_sx1262_ant_inactive_level(0u) == 1);
    REQUIRE(ninlil_sx1262_ant_active_level(0u) == 0);

    /* active-high path: outputs → safe → input fail holds levels */
    ninlil_sx1262_gpio_init_sm_reset(&sm, 1, 1u);
    REQUIRE(ninlil_sx1262_gpio_init_on_outputs_ok(&sm) == 1);
    REQUIRE(ninlil_sx1262_gpio_init_on_safe_levels_ok(&sm) == 1);
    REQUIRE(sm.reset_level == 1);
    REQUIRE(sm.ant_level == 0);
    REQUIRE(ninlil_sx1262_gpio_init_safe_levels_held(&sm) == 1);
    REQUIRE(ninlil_sx1262_gpio_init_on_inputs_fail(&sm) == 1);
    REQUIRE(ninlil_sx1262_gpio_init_safe_levels_held(&sm) == 1);

    /* active-low ANT inactive = high */
    ninlil_sx1262_gpio_init_sm_reset(&sm, 1, 0u);
    REQUIRE(ninlil_sx1262_gpio_init_on_outputs_ok(&sm) == 1);
    REQUIRE(ninlil_sx1262_gpio_init_on_safe_levels_ok(&sm) == 1);
    REQUIRE(sm.ant_level == 1);
    REQUIRE(ninlil_sx1262_gpio_init_on_inputs_ok(&sm) == 1);
    REQUIRE(ninlil_sx1262_gpio_init_on_spi_fail(&sm) == 1);
    REQUIRE(ninlil_sx1262_gpio_init_safe_levels_held(&sm) == 1);

    /* cannot skip to safe levels without outputs */
    ninlil_sx1262_gpio_init_sm_reset(&sm, 0, 0u);
    REQUIRE(ninlil_sx1262_gpio_init_on_safe_levels_ok(&sm) == 0);
    return 0;
}

int main(void)
{
    if (test_calc_polls_overflow() != 0 || test_esp_ticks_overflow() != 0
        || test_success_xtal() != 0 || test_tcxo_path() != 0
        || test_tcxo_cold_img_only() != 0 || test_tcxo_cold_both() != 0
        || test_tcxo_cold_zero() != 0 || test_tcxo_cold_mixed_negative() != 0
        || test_ant_sw_contracts() != 0
        || test_error_before_clear() != 0 || test_cmd_status_fail_first() != 0
        || test_cmd_status_fail_after_write() != 0
        || test_miso_status_byte_position() != 0
        || test_esp_bus_trans_storage_align() != 0
        || test_rfu_and_tx_done_reject() != 0
        || test_frozen_clock_poll_cap() != 0 || test_clock_wrap() != 0
        || test_delayed_busy() != 0 || test_tx_deny_and_failed_zero_spi() != 0
        || test_config_bounds() != 0 || test_shutdown_reinit() != 0
        || test_null_args() != 0 || test_each_required_pin_unset() != 0
        || test_pin_duplicate() != 0 || test_feature_mismatches() != 0
        || test_bus_faults_matrix() != 0 || test_fail_busy_read_positions() != 0
        || test_delay_fail_positions() != 0 || test_now_fail_positions() != 0
        || test_timeout_boundary_exact() != 0
        || test_busy_deadline_helper() != 0
        || test_monotonic_deadline_boundary() != 0
        || test_initing_reentry() != 0 || test_failed_shutdown_reinit() != 0
        || test_tx_deny_all_lifecycles() != 0 || test_object_size_align() != 0
        || test_spi_pending_ownership_sm() != 0
        || test_mid_status_closed_set_after_busy() != 0
        || test_cmd_frame_schema() != 0
        || test_primary_opcode_pin() != 0
        || test_esp_gpio_safe_init_sm() != 0) {
        return 1;
    }
    (void)printf("sx1262_r4_test: OK\n");
    return 0;
}
