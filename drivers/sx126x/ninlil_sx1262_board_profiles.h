#ifndef NINLIL_SX1262_BOARD_PROFILES_H
#define NINLIL_SX1262_BOARD_PROFILES_H

/*
 * Immutable SX1262 board profiles for release HIL composition.
 * Not public OSS ABI. Not RF HIL PASS / Japan legal / TELEC / physical PASS.
 *
 * Profile: Seeed XIAO ESP32-S3 + Wio-SX1262
 *   - DIO3 TCXO control at 3.0 V (radio-powered)
 *   - DIO2 RF-switch control = true
 *   - GPIO ANT_SW (active-high) = host RF_SW receive control already wired
 *   - Init must execute SetDio2AsRfSwitchCtrl → SetDio3AsTcxoCtrl → CAL_ALL
 *
 * Primary source (informative; not a field verification claim):
 *   Seeed Studio, "Wio-SX1262" datasheet, version 1.0
 *   - Module supply VCC 3.3 V typical
 *   - TCXO powered by SX1262 DIO3; set TCXO voltage at least 200 mV below VCC
 *     → release encodes TCXO 3.0 V with vdd_op_mv=3300 (margin ≥ 200 mV)
 *   - DIO2 internally connected to the module RF switch
 *     → release enables SetDio2AsRfSwitchCtrl (enable=1)
 *   - External RF_SW GPIO remains host-driven ANT_SW on this carrier
 */

#include "ninlil_sx1262_backend.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_BOARD_PROFILE_XIAO_WIO_SX1262_V1_ID \
    "xiao_esp32s3_wio_sx1262_v1"

/*
 * Exact release pin map (must match radio_hil sdkconfig / Kconfig defaults).
 * Integer-literal form (no 'u' suffix) so #if CONFIG_* comparisons work.
 */
#define NINLIL_SX1262_XIAO_WIO_PIN_NSS 41
#define NINLIL_SX1262_XIAO_WIO_PIN_SCK 7
#define NINLIL_SX1262_XIAO_WIO_PIN_MOSI 9
#define NINLIL_SX1262_XIAO_WIO_PIN_MISO 8
#define NINLIL_SX1262_XIAO_WIO_PIN_RESET 42
#define NINLIL_SX1262_XIAO_WIO_PIN_BUSY 40
#define NINLIL_SX1262_XIAO_WIO_PIN_DIO1 39
#define NINLIL_SX1262_XIAO_WIO_PIN_ANT_SW 38

/*
 * DIO3 TCXO: 3.0 V code (datasheet: TCXO via DIO3, ≥200 mV below 3.3 V VCC).
 * Delay 5000 RTC steps (~78.125 ms @ 15.625 us).
 */
#define NINLIL_SX1262_XIAO_WIO_TCXO_VOLTAGE NINLIL_SX1262_TCXO_3_0V
#define NINLIL_SX1262_XIAO_WIO_TCXO_DELAY_RTC_STEPS 5000
#define NINLIL_SX1262_XIAO_WIO_TCXO_BUSY_TIMEOUT_MS 200
/* Module VCC typical 3.3 V (datasheet); used for TCXO VDD margin check. */
#define NINLIL_SX1262_XIAO_WIO_VDD_OP_MV 3300

#define NINLIL_SX1262_XIAO_WIO_FEATURE_FLAGS \
    (NINLIL_SX1262_FEATURE_TCXO_PRESENT \
     | NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH \
     | NINLIL_SX1262_FEATURE_ANT_SW_PRESENT)

/* Wire-level proof constants for bus-spy / evidence (Semtech opcodes). */
#define NINLIL_SX1262_XIAO_WIO_OPCODE_SET_DIO2 0x9Du
#define NINLIL_SX1262_XIAO_WIO_OPCODE_SET_DIO3 0x97u
#define NINLIL_SX1262_XIAO_WIO_OPCODE_CALIBRATE 0x89u
#define NINLIL_SX1262_XIAO_WIO_CAL_PARAM NINLIL_SX1262_CAL_ALL
#define NINLIL_SX1262_XIAO_WIO_DIO2_ENABLE 1u

/**
 * Immutable board profile (statically allocated; do not free).
 * Always returns non-NULL.
 */
const ninlil_sx1262_board_config_t *
ninlil_sx1262_board_profile_xiao_wio_sx1262_v1(void);

/**
 * Copy profile into caller buffer (struct_size/abi validated).
 * Returns 0 on success, -1 on null/size mismatch.
 */
int ninlil_sx1262_board_profile_copy_xiao_wio_sx1262_v1(
    ninlil_sx1262_board_config_t *out);

/**
 * Returns 1 if pins match the immutable XIAO+Wio map (release binding).
 * pin_ant_sw may be compared as signed int (-1 not allowed for this profile).
 */
int ninlil_sx1262_board_profile_xiao_wio_pins_match(
    uint32_t pin_nss,
    uint32_t pin_sck,
    uint32_t pin_mosi,
    uint32_t pin_miso,
    uint32_t pin_reset,
    uint32_t pin_busy,
    uint32_t pin_dio1,
    uint32_t pin_ant_sw);

/**
 * Returns 1 if config carries full Wio TCXO/DIO2/ANT feature set and voltage.
 */
int ninlil_sx1262_board_profile_xiao_wio_features_match(
    const ninlil_sx1262_board_config_t *cfg);

/**
 * Expected post-regulator SPI opcodes for Wio TCXO path (DIO2, DIO3, CAL).
 * out_n set to 3. For evidence / host tests.
 */
int ninlil_sx1262_board_profile_xiao_wio_tcxo_opcodes(
    uint8_t *out_opcodes,
    size_t out_cap,
    size_t *out_n);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_BOARD_PROFILES_H */
