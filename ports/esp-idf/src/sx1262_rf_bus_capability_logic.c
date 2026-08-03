/*
 * Pure SX1262 bus SPI capability policy (host + ESP).
 */

#include "sx1262_rf_bus_capability_logic.h"

#include "ninlil_sx1262_cmd.h"

int ninlil_sx1262_cmd_is_r9_rf_allowed(uint8_t opcode)
{
    switch (opcode) {
    case 0x8Au: /* SetPacketType */
    case NINLIL_SX1262_CMD_SET_RF_FREQUENCY:
    case 0x95u: /* SetPaConfig */
    case NINLIL_SX1262_CMD_SET_TX_PARAMS:
    case 0x8Fu: /* SetBufferBaseAddress */
    case 0x8Bu: /* SetModulationParams */
    case 0x8Cu: /* SetPacketParams */
    case 0x08u: /* SetDioIrqParams */
    case 0x12u: /* GetIrqStatus */
    case 0x02u: /* ClrIrqStatus */
    case NINLIL_SX1262_CMD_WRITE_BUFFER:
    case 0x1Eu: /* ReadBuffer */
    case 0x13u: /* GetRxBufferStatus */
    case 0x14u: /* GetPacketStatus */
    case NINLIL_SX1262_CMD_SET_TX:
    case NINLIL_SX1262_CMD_SET_RX:
    case NINLIL_SX1262_CMD_SET_CAD:
    case 0x88u: /* SetCadParams */
    case 0x98u: /* CalibrateImage */
    case NINLIL_SX1262_CMD_SET_STANDBY: /* phy also issues STDBY */
    case NINLIL_SX1262_CMD_GET_STATUS:
        return 1;
    default:
        return 0;
    }
}

int ninlil_sx1262_bus_spi_xfer_admitted(
    uint32_t capability_mode,
    uint8_t opcode,
    size_t len)
{
    if (len == 0u || len > NINLIL_SX1262_BUS_RF_SPI_MAX_LEN) {
        return 0;
    }
    if (capability_mode == NINLIL_SX1262_BUS_CAP_CONTROL_ONLY) {
        /*
         * R4 control-only: closed allowlist, no RF banlist opcodes.
         * Frame parameter schema is validated by R4 backend separately;
         * bus denies non-allowlisted / RF-banned opcodes at the wire edge.
         */
        if (ninlil_sx1262_cmd_is_rf_banned(opcode)) {
            return 0;
        }
        if (!ninlil_sx1262_cmd_is_allowlisted(opcode)) {
            return 0;
        }
        return 1;
    }
    if (capability_mode == NINLIL_SX1262_BUS_CAP_RF_SOLE) {
        /* R4 control opcodes remain legal; R9 closed RF set also legal. */
        if (ninlil_sx1262_cmd_is_allowlisted(opcode)) {
            return 1;
        }
        if (ninlil_sx1262_cmd_is_r9_rf_allowed(opcode)) {
            return 1;
        }
        return 0;
    }
    /* Unknown mode: fail closed. */
    return 0;
}

int ninlil_sx1262_bus_cap_grant_rf_sole(uint32_t *cap)
{
    if (cap == NULL) {
        return 1;
    }
    if (*cap != NINLIL_SX1262_BUS_CAP_CONTROL_ONLY) {
        return 1; /* already RF or unknown — single-shot only */
    }
    *cap = NINLIL_SX1262_BUS_CAP_RF_SOLE;
    return 0;
}

int ninlil_sx1262_bus_cap_revoke_rf(uint32_t *cap)
{
    if (cap == NULL) {
        return 1;
    }
    *cap = NINLIL_SX1262_BUS_CAP_CONTROL_ONLY;
    return 0;
}

int ninlil_sx1262_bus_cap_is_rf_sole(uint32_t cap)
{
    return cap == NINLIL_SX1262_BUS_CAP_RF_SOLE ? 1 : 0;
}
