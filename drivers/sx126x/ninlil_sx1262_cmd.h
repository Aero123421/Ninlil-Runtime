#ifndef NINLIL_SX1262_CMD_H
#define NINLIL_SX1262_CMD_H

/*
 * R4 closed opcode / status / error constants (docs/28 §3).
 *
 * Primary sources:
 *   - Semtech DS.SX1261-2.W.APP Rev 2.2 Dec 2024
 *   - Semtech sx126x_driver v2.3.2 Commands Interface / masks
 *   - SWSD003 v2.3.0 apps_common.c / sx126x_hal.c
 *
 * Banlist opcodes are for deny/gates only — never SPI-transferred.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Allowlist --- */
#define NINLIL_SX1262_CMD_GET_STATUS ((uint8_t)0xC0u)
#define NINLIL_SX1262_CMD_SET_STANDBY ((uint8_t)0x80u)
#define NINLIL_SX1262_CMD_GET_DEVICE_ERRORS ((uint8_t)0x17u)
#define NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS ((uint8_t)0x07u)
#define NINLIL_SX1262_CMD_SET_REGULATOR_MODE ((uint8_t)0x96u)
#define NINLIL_SX1262_CMD_CALIBRATE ((uint8_t)0x89u)
#define NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL ((uint8_t)0x9Du)
#define NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL ((uint8_t)0x97u)

/* --- Banlist (RF emission class) --- */
#define NINLIL_SX1262_CMD_SET_TX ((uint8_t)0x83u)
#define NINLIL_SX1262_CMD_SET_RX ((uint8_t)0x82u)
#define NINLIL_SX1262_CMD_SET_FS ((uint8_t)0xC1u)
#define NINLIL_SX1262_CMD_SET_TX_CONTINUOUS_WAVE ((uint8_t)0xD1u)
#define NINLIL_SX1262_CMD_SET_TX_INFINITE_PREAMBLE ((uint8_t)0xD2u)
#define NINLIL_SX1262_CMD_SET_CAD ((uint8_t)0xC5u)
#define NINLIL_SX1262_CMD_SET_SLEEP ((uint8_t)0x84u)
#define NINLIL_SX1262_CMD_SET_RF_FREQUENCY ((uint8_t)0x86u)
#define NINLIL_SX1262_CMD_SET_TX_PARAMS ((uint8_t)0x8Eu)
#define NINLIL_SX1262_CMD_WRITE_BUFFER ((uint8_t)0x0Eu)

#define NINLIL_SX1262_SPI_NOP ((uint8_t)0x00u)

#define NINLIL_SX1262_STANDBY_CFG_RC ((uint8_t)0x00u)
#define NINLIL_SX1262_STANDBY_CFG_XOSC ((uint8_t)0x01u)

#define NINLIL_SX1262_REG_MODE_LDO ((uint8_t)0x00u)
#define NINLIL_SX1262_REG_MODE_DCDC ((uint8_t)0x01u)

/* CAL_ALL = 0x7F (driver SX126X_CAL_ALL bits 0..6) */
#define NINLIL_SX1262_CAL_ALL ((uint8_t)0x7Fu)

/* GetStatus bitfields */
#define NINLIL_SX1262_CHIP_MODES_POS ((uint8_t)4u)
#define NINLIL_SX1262_CHIP_MODES_MASK ((uint8_t)(0x07u << NINLIL_SX1262_CHIP_MODES_POS))
#define NINLIL_SX1262_CMD_STATUS_POS ((uint8_t)1u)
#define NINLIL_SX1262_CMD_STATUS_MASK ((uint8_t)(0x07u << NINLIL_SX1262_CMD_STATUS_POS))

#define NINLIL_SX1262_CHIP_MODE_UNUSED ((uint8_t)0u)
#define NINLIL_SX1262_CHIP_MODE_RFU ((uint8_t)1u)
#define NINLIL_SX1262_CHIP_MODE_STBY_RC ((uint8_t)2u)
#define NINLIL_SX1262_CHIP_MODE_STBY_XOSC ((uint8_t)3u)
#define NINLIL_SX1262_CHIP_MODE_FS ((uint8_t)4u)
#define NINLIL_SX1262_CHIP_MODE_RX ((uint8_t)5u)
#define NINLIL_SX1262_CHIP_MODE_TX ((uint8_t)6u)

#define NINLIL_SX1262_CMD_STATUS_RESERVED ((uint8_t)0u)
#define NINLIL_SX1262_CMD_STATUS_RFU ((uint8_t)1u)
#define NINLIL_SX1262_CMD_STATUS_DATA_AVAILABLE ((uint8_t)2u)
#define NINLIL_SX1262_CMD_STATUS_CMD_TIMEOUT ((uint8_t)3u)
#define NINLIL_SX1262_CMD_STATUS_CMD_PROCESS_ERROR ((uint8_t)4u)
#define NINLIL_SX1262_CMD_STATUS_CMD_EXEC_FAILURE ((uint8_t)5u)
#define NINLIL_SX1262_CMD_STATUS_CMD_TX_DONE ((uint8_t)6u)

/* Device errors mask (driver) */
#define NINLIL_SX1262_ERR_RC64K_CAL ((uint16_t)(1u << 0))
#define NINLIL_SX1262_ERR_RC13M_CAL ((uint16_t)(1u << 1))
#define NINLIL_SX1262_ERR_PLL_CAL ((uint16_t)(1u << 2))
#define NINLIL_SX1262_ERR_ADC_CAL ((uint16_t)(1u << 3))
#define NINLIL_SX1262_ERR_IMG_CAL ((uint16_t)(1u << 4))
#define NINLIL_SX1262_ERR_XOSC_START ((uint16_t)(1u << 5))
#define NINLIL_SX1262_ERR_PLL_LOCK ((uint16_t)(1u << 6))
#define NINLIL_SX1262_ERR_PA_RAMP ((uint16_t)(1u << 8))

/*
 * DS §9.2.1: with TCXO the 32 MHz clock is not ready at first image cal —
 * cold-start may latch XOSC_START and/or IMG_CAL before SetDIO3+CAL_ALL.
 */
#define NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED \
    ((uint16_t)(NINLIL_SX1262_ERR_XOSC_START | NINLIL_SX1262_ERR_IMG_CAL))

/* R4 adopts SWSD003 reset = 1 ms (not DS "typically 100 us" as guaranteed min). */
#define NINLIL_SX1262_RESET_PULSE_US_R4 ((uint32_t)1000u)
#define NINLIL_SX1262_TCXO_STEP_NS ((uint32_t)15625u)
#define NINLIL_SX1262_SPI_CLOCK_MAX_HZ ((uint32_t)16000000u)

static inline uint8_t ninlil_sx1262_status_chip_mode(uint8_t status_byte)
{
    return (uint8_t)((status_byte & NINLIL_SX1262_CHIP_MODES_MASK)
        >> NINLIL_SX1262_CHIP_MODES_POS);
}

static inline uint8_t ninlil_sx1262_status_cmd_status(uint8_t status_byte)
{
    return (uint8_t)((status_byte & NINLIL_SX1262_CMD_STATUS_MASK)
        >> NINLIL_SX1262_CMD_STATUS_POS);
}

/* Fail closed on cmd_status 3/4/5 (docs/28). */
static inline int ninlil_sx1262_cmd_status_is_fail(uint8_t cmd_status)
{
    return cmd_status == NINLIL_SX1262_CMD_STATUS_CMD_TIMEOUT
        || cmd_status == NINLIL_SX1262_CMD_STATUS_CMD_PROCESS_ERROR
        || cmd_status == NINLIL_SX1262_CMD_STATUS_CMD_EXEC_FAILURE;
}

/* Mid-init accepted cmd_status set: {0, 2} only (not RFU=1 / TX_DONE=6). */
static inline int ninlil_sx1262_cmd_status_accepted_mid(uint8_t cmd_status)
{
    return cmd_status == NINLIL_SX1262_CMD_STATUS_RESERVED
        || cmd_status == NINLIL_SX1262_CMD_STATUS_DATA_AVAILABLE;
}

static inline int ninlil_sx1262_cmd_is_allowlisted(uint8_t opcode)
{
    switch (opcode) {
    case NINLIL_SX1262_CMD_GET_STATUS:
    case NINLIL_SX1262_CMD_SET_STANDBY:
    case NINLIL_SX1262_CMD_GET_DEVICE_ERRORS:
    case NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS:
    case NINLIL_SX1262_CMD_SET_REGULATOR_MODE:
    case NINLIL_SX1262_CMD_CALIBRATE:
    case NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL:
    case NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL:
        return 1;
    default:
        return 0;
    }
}

static inline int ninlil_sx1262_cmd_is_rf_banned(uint8_t opcode)
{
    switch (opcode) {
    case NINLIL_SX1262_CMD_SET_TX:
    case NINLIL_SX1262_CMD_SET_RX:
    case NINLIL_SX1262_CMD_SET_FS:
    case NINLIL_SX1262_CMD_SET_TX_CONTINUOUS_WAVE:
    case NINLIL_SX1262_CMD_SET_TX_INFINITE_PREAMBLE:
    case NINLIL_SX1262_CMD_SET_CAD:
    case NINLIL_SX1262_CMD_SET_RF_FREQUENCY:
    case NINLIL_SX1262_CMD_SET_TX_PARAMS:
    case NINLIL_SX1262_CMD_WRITE_BUFFER:
        return 1;
    default:
        return 0;
    }
}

/* TCXO supply mV for VDD constraint (typed profile). */
static inline uint16_t ninlil_sx1262_tcxo_voltage_mv(uint8_t tcxo_code)
{
    switch (tcxo_code) {
    case 0x00u:
        return 1600u;
    case 0x01u:
        return 1700u;
    case 0x02u:
        return 1800u;
    case 0x03u:
        return 2200u;
    case 0x04u:
        return 2400u;
    case 0x05u:
        return 2700u;
    case 0x06u:
        return 3000u;
    case 0x07u:
        return 3300u;
    default:
        return 0u;
    }
}

/*
 * Closed production frame schema: opcode + exact len + parameters (docs/28).
 * Returns 1 if the full TX buffer is a legal R4 control-plane frame.
 */
static inline int ninlil_sx1262_cmd_frame_valid(const uint8_t *tx, size_t len)
{
    uint32_t delay24;

    if (tx == NULL || len == 0u || !ninlil_sx1262_cmd_is_allowlisted(tx[0])) {
        return 0;
    }
    switch (tx[0]) {
    case NINLIL_SX1262_CMD_GET_STATUS:
        return len == 2u && tx[1] == NINLIL_SX1262_SPI_NOP;
    case NINLIL_SX1262_CMD_SET_STANDBY:
        /* R4 ends in STBY_RC only — STBY_XOSC not allowed on wire. */
        return len == 2u && tx[1] == NINLIL_SX1262_STANDBY_CFG_RC;
    case NINLIL_SX1262_CMD_GET_DEVICE_ERRORS:
        return len == 4u && tx[1] == NINLIL_SX1262_SPI_NOP
            && tx[2] == NINLIL_SX1262_SPI_NOP && tx[3] == NINLIL_SX1262_SPI_NOP;
    case NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS:
        return len == 3u && tx[1] == NINLIL_SX1262_SPI_NOP
            && tx[2] == NINLIL_SX1262_SPI_NOP;
    case NINLIL_SX1262_CMD_SET_REGULATOR_MODE:
        return len == 2u
            && (tx[1] == NINLIL_SX1262_REG_MODE_LDO
                || tx[1] == NINLIL_SX1262_REG_MODE_DCDC);
    case NINLIL_SX1262_CMD_CALIBRATE:
        return len == 2u && tx[1] == NINLIL_SX1262_CAL_ALL;
    case NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL:
        return len == 2u && tx[1] == 1u;
    case NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL:
        if (len != 5u) {
            return 0;
        }
        delay24 = ((uint32_t)tx[2] << 16) | ((uint32_t)tx[3] << 8)
            | (uint32_t)tx[4];
        return ninlil_sx1262_tcxo_voltage_mv(tx[1]) != 0u && delay24 != 0u
            && (delay24 & 0xFF000000u) == 0u;
    default:
        return 0;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_CMD_H */
