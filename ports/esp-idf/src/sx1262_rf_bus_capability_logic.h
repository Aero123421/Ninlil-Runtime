#ifndef NINLIL_SX1262_RF_BUS_CAPABILITY_LOGIC_H
#define NINLIL_SX1262_RF_BUS_CAPABILITY_LOGIC_H

/*
 * Pure SPI transfer admit policy for ESP SX1262 bus (host + ESP).
 *
 * Modes:
 *   CONTROL_ONLY (default) — R4 closed allowlist only; RF emission opcodes denied.
 *   RF_SOLE      — R4 allowlist + closed R9 physical opcode set (SetTx etc.).
 *
 * RF_SOLE is granted only via explicit private grant API used by R9 sole-edge
 * composition. R4 control-plane deny is not weakened for CONTROL_ONLY.
 * No FreeRTOS / ESP-IDF headers.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_BUS_CAP_CONTROL_ONLY ((uint32_t)0u)
#define NINLIL_SX1262_BUS_CAP_RF_SOLE ((uint32_t)1u)

/* Max SPI frame on RF_SOLE path (WriteBuffer + payload; matches phy SPI_CAP). */
#define NINLIL_SX1262_BUS_RF_SPI_MAX_LEN ((size_t)280u)

/*
 * Closed R9 physical opcode set (DS opcodes used by ninlil_sx1262_phy).
 * Distinct from R4 control allowlist; includes RF emission class.
 * Returns 1 if opcode is in the R9 closed set.
 */
int ninlil_sx1262_cmd_is_r9_rf_allowed(uint8_t opcode);

/*
 * Admit SPI transfer under capability mode.
 * CONTROL_ONLY: R4 allowlist + frame_valid + !rf_banned (fail closed).
 * RF_SOLE: R4 allowlist OR R9 RF set; len in 1..RF_SPI_MAX_LEN.
 * Returns 1 admit, 0 deny.
 */
int ninlil_sx1262_bus_spi_xfer_admitted(
    uint32_t capability_mode,
    uint8_t opcode,
    size_t len);

/*
 * Grant state machine (pure): single-shot RF_SOLE grant.
 * *cap starts CONTROL_ONLY after bus init.
 * grant: CONTROL→RF_SOLE once; re-grant fail; revoke → CONTROL.
 */
int ninlil_sx1262_bus_cap_grant_rf_sole(uint32_t *cap);
int ninlil_sx1262_bus_cap_revoke_rf(uint32_t *cap);
int ninlil_sx1262_bus_cap_is_rf_sole(uint32_t cap);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_RF_BUS_CAPABILITY_LOGIC_H */
