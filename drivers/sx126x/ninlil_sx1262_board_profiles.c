/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Release encode for XIAO ESP32-S3 + Wio-SX1262.
 * Source identity: Seeed Wio-SX1262 datasheet v1.0 (informative only —
 * not RF HIL PASS / physical verification). See header for statements.
 */
#include "ninlil_sx1262_board_profiles.h"

#include <string.h>

static const ninlil_sx1262_board_config_t k_xiao_wio_sx1262_v1 = {
    .abi_version = NINLIL_SX1262_ABI_VERSION,
    .struct_size = (uint16_t)sizeof(ninlil_sx1262_board_config_t),
    .pin_nss = NINLIL_SX1262_XIAO_WIO_PIN_NSS,
    .pin_sck = NINLIL_SX1262_XIAO_WIO_PIN_SCK,
    .pin_mosi = NINLIL_SX1262_XIAO_WIO_PIN_MOSI,
    .pin_miso = NINLIL_SX1262_XIAO_WIO_PIN_MISO,
    .pin_reset = NINLIL_SX1262_XIAO_WIO_PIN_RESET,
    .pin_busy = NINLIL_SX1262_XIAO_WIO_PIN_BUSY,
    .pin_dio1 = NINLIL_SX1262_XIAO_WIO_PIN_DIO1,
    .pin_ant_sw = NINLIL_SX1262_XIAO_WIO_PIN_ANT_SW,
    .feature_flags = NINLIL_SX1262_XIAO_WIO_FEATURE_FLAGS,
    .reset_pulse_us = NINLIL_SX1262_RESET_PULSE_US_R4,
    .busy_timeout_ms = 200u,
    .spi_busy_timeout_ms = 200u,
    .post_spi_busy_guard_us = 2u,
    .busy_poll_interval_us = 50u,
    .busy_poll_slack = 2u,
    .tcxo_delay_rtc_steps = NINLIL_SX1262_XIAO_WIO_TCXO_DELAY_RTC_STEPS,
    .tcxo_busy_timeout_ms = NINLIL_SX1262_XIAO_WIO_TCXO_BUSY_TIMEOUT_MS,
    .vdd_op_mv = NINLIL_SX1262_XIAO_WIO_VDD_OP_MV,
    .tcxo_voltage = NINLIL_SX1262_XIAO_WIO_TCXO_VOLTAGE,
    .regulator_mode = NINLIL_SX1262_REG_MODE_DCDC,
    .ant_sw_active_high = 1u,
    .reserved0 = 0u,
    .reserved_zero = 0u,
};

const ninlil_sx1262_board_config_t *
ninlil_sx1262_board_profile_xiao_wio_sx1262_v1(void)
{
    return &k_xiao_wio_sx1262_v1;
}

int ninlil_sx1262_board_profile_copy_xiao_wio_sx1262_v1(
    ninlil_sx1262_board_config_t *out)
{
    if (out == NULL) {
        return -1;
    }
    (void)memcpy(out, &k_xiao_wio_sx1262_v1, sizeof(*out));
    return 0;
}

int ninlil_sx1262_board_profile_xiao_wio_pins_match(
    uint32_t pin_nss,
    uint32_t pin_sck,
    uint32_t pin_mosi,
    uint32_t pin_miso,
    uint32_t pin_reset,
    uint32_t pin_busy,
    uint32_t pin_dio1,
    uint32_t pin_ant_sw)
{
    return (pin_nss == NINLIL_SX1262_XIAO_WIO_PIN_NSS
            && pin_sck == NINLIL_SX1262_XIAO_WIO_PIN_SCK
            && pin_mosi == NINLIL_SX1262_XIAO_WIO_PIN_MOSI
            && pin_miso == NINLIL_SX1262_XIAO_WIO_PIN_MISO
            && pin_reset == NINLIL_SX1262_XIAO_WIO_PIN_RESET
            && pin_busy == NINLIL_SX1262_XIAO_WIO_PIN_BUSY
            && pin_dio1 == NINLIL_SX1262_XIAO_WIO_PIN_DIO1
            && pin_ant_sw == NINLIL_SX1262_XIAO_WIO_PIN_ANT_SW)
        ? 1
        : 0;
}

int ninlil_sx1262_board_profile_xiao_wio_features_match(
    const ninlil_sx1262_board_config_t *cfg)
{
    if (cfg == NULL) {
        return 0;
    }
    if (cfg->feature_flags != NINLIL_SX1262_XIAO_WIO_FEATURE_FLAGS) {
        return 0;
    }
    if (cfg->tcxo_voltage != NINLIL_SX1262_XIAO_WIO_TCXO_VOLTAGE) {
        return 0;
    }
    if (cfg->tcxo_delay_rtc_steps != NINLIL_SX1262_XIAO_WIO_TCXO_DELAY_RTC_STEPS) {
        return 0;
    }
    if (cfg->ant_sw_active_high != 1u) {
        return 0;
    }
    if (cfg->regulator_mode != NINLIL_SX1262_REG_MODE_DCDC) {
        return 0;
    }
    return 1;
}

int ninlil_sx1262_board_profile_xiao_wio_tcxo_opcodes(
    uint8_t *out_opcodes,
    size_t out_cap,
    size_t *out_n)
{
    static const uint8_t k_ops[3] = {
        NINLIL_SX1262_XIAO_WIO_OPCODE_SET_DIO2,
        NINLIL_SX1262_XIAO_WIO_OPCODE_SET_DIO3,
        NINLIL_SX1262_XIAO_WIO_OPCODE_CALIBRATE,
    };

    if (out_n == NULL) {
        return -1;
    }
    *out_n = 3u;
    if (out_opcodes == NULL || out_cap < 3u) {
        return -1;
    }
    out_opcodes[0] = k_ops[0];
    out_opcodes[1] = k_ops[1];
    out_opcodes[2] = k_ops[2];
    return 0;
}
