#ifndef NINLIL_SX1262_BACKEND_H
#define NINLIL_SX1262_BACKEND_H

/*
 * R4: SX1262 production-private control-plane backend (D1).
 *
 * Normative:
 *   docs/28-r4-sx1262-control-plane-backend.md
 *   docs/adr/0008-r4-sx1262-control-plane-backend.md
 * Primary: DS.SX1261-2.W.APP Rev2.2; sx126x_driver v2.3.2; SWSD003 v2.3.0
 *
 * Nonclaims:
 *   Not R4 complete / Not R9 SPI TX path / not RF TX-RX / not HIL / not legal /
 *   not R1/R2 complete / not public ABI / not SX1261 vs SX1262 SKU ID.
 */

#include "ninlil_sx1262_bus.h"
#include "ninlil_sx1262_cmd.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_HINT_BYTES ((size_t)160u)
#define NINLIL_SX1262_OBJECT_BYTES ((size_t)768u)
#define NINLIL_SX1262_OBJECT_ALIGN ((size_t)8u)
#define NINLIL_SX1262_PIN_UNSET ((uint32_t)0xFFFFFFFFu)
#define NINLIL_SX1262_ABI_VERSION ((uint16_t)0x0003u)

#define NINLIL_SX1262_FEATURE_NONE ((uint32_t)0u)
#define NINLIL_SX1262_FEATURE_TCXO_PRESENT ((uint32_t)1u)
#define NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH ((uint32_t)2u)
#define NINLIL_SX1262_FEATURE_ANT_SW_PRESENT ((uint32_t)4u)

#define NINLIL_SX1262_TCXO_1_6V ((uint8_t)0x00u)
#define NINLIL_SX1262_TCXO_1_7V ((uint8_t)0x01u)
#define NINLIL_SX1262_TCXO_1_8V ((uint8_t)0x02u)
#define NINLIL_SX1262_TCXO_2_2V ((uint8_t)0x03u)
#define NINLIL_SX1262_TCXO_2_4V ((uint8_t)0x04u)
#define NINLIL_SX1262_TCXO_2_7V ((uint8_t)0x05u)
#define NINLIL_SX1262_TCXO_3_0V ((uint8_t)0x06u)
#define NINLIL_SX1262_TCXO_3_3V ((uint8_t)0x07u)

#define NINLIL_SX1262_BUSY_POLL_INTERVAL_MIN_US ((uint32_t)1u)
#define NINLIL_SX1262_BUSY_POLL_INTERVAL_MAX_US ((uint32_t)1000000u)
#define NINLIL_SX1262_BUSY_POLL_SLACK_MIN ((uint32_t)1u)
#define NINLIL_SX1262_BUSY_POLL_SLACK_MAX ((uint32_t)16u)
#define NINLIL_SX1262_TIMEOUT_MS_MAX ((uint32_t)600000u)

typedef uint32_t ninlil_sx1262_status_t;

#define NINLIL_SX1262_OK ((ninlil_sx1262_status_t)0u)
#define NINLIL_SX1262_INVALID_ARGUMENT ((ninlil_sx1262_status_t)1u)
#define NINLIL_SX1262_INVALID_STATE ((ninlil_sx1262_status_t)2u)
#define NINLIL_SX1262_BUSY ((ninlil_sx1262_status_t)3u)
#define NINLIL_SX1262_BUSY_TIMEOUT ((ninlil_sx1262_status_t)4u)
#define NINLIL_SX1262_SPI_ERROR ((ninlil_sx1262_status_t)5u)
#define NINLIL_SX1262_SPI_TIMEOUT ((ninlil_sx1262_status_t)6u)
#define NINLIL_SX1262_DEVICE_ERROR ((ninlil_sx1262_status_t)7u)
#define NINLIL_SX1262_STATUS_INVALID ((ninlil_sx1262_status_t)8u)
#define NINLIL_SX1262_TX_DENIED ((ninlil_sx1262_status_t)9u)
#define NINLIL_SX1262_UNSUPPORTED ((ninlil_sx1262_status_t)10u)
#define NINLIL_SX1262_BUS_ERROR ((ninlil_sx1262_status_t)11u)

typedef uint32_t ninlil_sx1262_stage_t;

#define NINLIL_SX1262_STAGE_NONE ((ninlil_sx1262_stage_t)0u)
#define NINLIL_SX1262_STAGE_CONFIG ((ninlil_sx1262_stage_t)1u)
#define NINLIL_SX1262_STAGE_RESET ((ninlil_sx1262_stage_t)2u)
#define NINLIL_SX1262_STAGE_BUSY_WAIT ((ninlil_sx1262_stage_t)3u)
#define NINLIL_SX1262_STAGE_SPI ((ninlil_sx1262_stage_t)4u)
#define NINLIL_SX1262_STAGE_STATUS ((ninlil_sx1262_stage_t)5u)
#define NINLIL_SX1262_STAGE_STANDBY ((ninlil_sx1262_stage_t)6u)
#define NINLIL_SX1262_STAGE_TX_DENY ((ninlil_sx1262_stage_t)7u)
#define NINLIL_SX1262_STAGE_OWNER ((ninlil_sx1262_stage_t)8u)
#define NINLIL_SX1262_STAGE_SHUTDOWN ((ninlil_sx1262_stage_t)9u)
#define NINLIL_SX1262_STAGE_INIT ((ninlil_sx1262_stage_t)10u)
#define NINLIL_SX1262_STAGE_ERRORS ((ninlil_sx1262_stage_t)11u)
#define NINLIL_SX1262_STAGE_CAL ((ninlil_sx1262_stage_t)12u)

typedef uint32_t ninlil_sx1262_reason_t;

#define NINLIL_SX1262_REASON_NONE ((ninlil_sx1262_reason_t)0u)
#define NINLIL_SX1262_REASON_NULL_ARG ((ninlil_sx1262_reason_t)1u)
#define NINLIL_SX1262_REASON_BAD_HEADER ((ninlil_sx1262_reason_t)2u)
#define NINLIL_SX1262_REASON_PIN_UNSET ((ninlil_sx1262_reason_t)3u)
#define NINLIL_SX1262_REASON_PIN_DUP ((ninlil_sx1262_reason_t)4u)
#define NINLIL_SX1262_REASON_FEATURE_MISMATCH ((ninlil_sx1262_reason_t)5u)
#define NINLIL_SX1262_REASON_TIMING_ZERO ((ninlil_sx1262_reason_t)6u)
#define NINLIL_SX1262_REASON_RESERVED ((ninlil_sx1262_reason_t)7u)
#define NINLIL_SX1262_REASON_OPS_NULL ((ninlil_sx1262_reason_t)8u)
#define NINLIL_SX1262_REASON_NOT_FRESH ((ninlil_sx1262_reason_t)9u)
#define NINLIL_SX1262_REASON_REENTRANT ((ninlil_sx1262_reason_t)10u)
#define NINLIL_SX1262_REASON_RESET_FAIL ((ninlil_sx1262_reason_t)11u)
#define NINLIL_SX1262_REASON_BUSY_STUCK ((ninlil_sx1262_reason_t)12u)
#define NINLIL_SX1262_REASON_SPI_FAIL ((ninlil_sx1262_reason_t)13u)
#define NINLIL_SX1262_REASON_SPI_TIMEOUT ((ninlil_sx1262_reason_t)14u)
#define NINLIL_SX1262_REASON_DEVICE_ERRORS ((ninlil_sx1262_reason_t)15u)
#define NINLIL_SX1262_REASON_BAD_CHIP_MODE ((ninlil_sx1262_reason_t)16u)
#define NINLIL_SX1262_REASON_OPCODE_DENIED ((ninlil_sx1262_reason_t)17u)
#define NINLIL_SX1262_REASON_TX_DENIED ((ninlil_sx1262_reason_t)18u)
#define NINLIL_SX1262_REASON_NOT_READY ((ninlil_sx1262_reason_t)19u)
#define NINLIL_SX1262_REASON_SHUTDOWN ((ninlil_sx1262_reason_t)20u)
#define NINLIL_SX1262_REASON_BAD_CMD_STATUS ((ninlil_sx1262_reason_t)21u)
#define NINLIL_SX1262_REASON_REGULATOR ((ninlil_sx1262_reason_t)22u)
#define NINLIL_SX1262_REASON_RESET_PULSE_SHORT ((ninlil_sx1262_reason_t)23u)
#define NINLIL_SX1262_REASON_TCXO_VDD ((ninlil_sx1262_reason_t)24u)
#define NINLIL_SX1262_REASON_TCXO_DELAY ((ninlil_sx1262_reason_t)25u)
/* Historical alias: cold path may latch XOSC and/or IMG (DS §9.2.1). */
#define NINLIL_SX1262_REASON_EXPECTED_COLD ((ninlil_sx1262_reason_t)26u)
#define NINLIL_SX1262_REASON_EXPECTED_XOSC NINLIL_SX1262_REASON_EXPECTED_COLD
#define NINLIL_SX1262_REASON_OVERFLOW ((ninlil_sx1262_reason_t)27u)

typedef struct ninlil_sx1262_error {
    ninlil_sx1262_status_t status;
    ninlil_sx1262_stage_t stage;
    ninlil_sx1262_reason_t reason;
    uint32_t reserved_zero;
    char hint[NINLIL_SX1262_HINT_BYTES];
} ninlil_sx1262_error_t;

typedef struct ninlil_sx1262_stats {
    uint64_t init_attempts;
    uint64_t init_ok;
    uint64_t init_fail;
    uint64_t config_reject;
    uint64_t spi_xfers;
    uint64_t spi_errors;
    uint64_t busy_timeouts;
    uint64_t tx_deny;
    uint64_t reentrant;
    uint64_t shutdowns;
    uint64_t opcode_denied;
    uint64_t expected_cold_errors_seen;
    uint64_t status_checks;
} ninlil_sx1262_stats_t;

typedef struct ninlil_sx1262_board_config {
    uint16_t abi_version;
    uint16_t struct_size;

    uint32_t pin_nss;
    uint32_t pin_sck;
    uint32_t pin_mosi;
    uint32_t pin_miso;
    uint32_t pin_reset;
    uint32_t pin_busy;
    uint32_t pin_dio1;
    uint32_t pin_ant_sw;

    uint32_t feature_flags;
    uint32_t reset_pulse_us;
    uint32_t busy_timeout_ms;
    uint32_t spi_busy_timeout_ms;
    uint32_t post_spi_busy_guard_us;
    uint32_t busy_poll_interval_us; /* delay between BUSY samples */
    uint32_t busy_poll_slack;       /* 1..16 added to ceil polls */
    uint32_t tcxo_delay_rtc_steps;
    uint32_t tcxo_busy_timeout_ms;
    uint16_t vdd_op_mv;
    uint8_t tcxo_voltage;
    uint8_t regulator_mode;
    /* 1 = active-high ANT_SW, 0 = active-low; must be 0 when ANT_SW absent. */
    uint8_t ant_sw_active_high;
    uint8_t reserved0;
    uint32_t reserved_zero;
} ninlil_sx1262_board_config_t;

struct ninlil_sx1262_backend {
    uint32_t magic;
    uint32_t lifecycle;
    uint32_t in_flight;
    uint32_t expected_cold_errors_latched; /* TCXO cold mask bits seen */
    uint32_t post_reset_status_seen;

    ninlil_sx1262_bus_ops_t bus_ops;
    void *bus_ctx;
    ninlil_sx1262_board_config_t board;

    uint8_t last_status_byte;
    uint8_t last_chip_mode;
    uint8_t last_cmd_status;
    uint8_t pad0;
    uint16_t last_device_errors;
    uint16_t first_device_errors;

    ninlil_sx1262_stats_t stats;
    ninlil_sx1262_error_t last_error;
};

typedef struct ninlil_sx1262_backend ninlil_sx1262_backend_t;
typedef ninlil_sx1262_backend_t ninlil_sx1262_backend_object_t;

/*
 * Caller MUST zero-init storage with OBJECT_INIT before first init.
 * First-init gate is sentinel (magic==0, lifecycle==0) only — not a claim
 * that uninitialized garbage is safely detectable (C UB to read garbage).
 */
#define NINLIL_SX1262_OBJECT_INIT {0}
#define NINLIL_SX1262_MAGIC ((uint32_t)0x52345358u)

_Static_assert(
    sizeof(ninlil_sx1262_backend_t) <= NINLIL_SX1262_OBJECT_BYTES,
    "sx1262 backend exceeds OBJECT_BYTES");
_Static_assert(
    _Alignof(ninlil_sx1262_backend_t) >= NINLIL_SX1262_OBJECT_ALIGN,
    "sx1262 backend align");

size_t ninlil_sx1262_object_size(void);
size_t ninlil_sx1262_object_align(void);

/*
 * Overflow-safe max_polls for BUSY wait (docs/28 §6.2).
 * Returns 0 on overflow/invalid; 1 and *out_max_polls on OK.
 */
int ninlil_sx1262_calc_busy_max_polls(
    uint32_t timeout_ms,
    uint32_t interval_us,
    uint32_t slack,
    uint64_t *out_max_polls);

/*
 * Pure BUSY deadline predicate (docs/28 §6.2): wrap-safe
 *   expired iff (now_ms - start_ms) >= timeout_ms
 * before: elapsed < timeout → 0; exact/after: elapsed >= timeout → 1
 */
int ninlil_sx1262_busy_deadline_reached(
    uint64_t start_ms,
    uint64_t now_ms,
    uint32_t timeout_ms);

ninlil_sx1262_status_t ninlil_sx1262_validate_board_config(
    const ninlil_sx1262_board_config_t *config,
    const ninlil_sx1262_bus_ops_t *ops,
    ninlil_sx1262_error_t *out_error);

ninlil_sx1262_status_t ninlil_sx1262_init(
    ninlil_sx1262_backend_object_t *object,
    const ninlil_sx1262_board_config_t *config,
    const ninlil_sx1262_bus_ops_t *ops,
    void *bus_ctx,
    ninlil_sx1262_backend_t **out_backend,
    ninlil_sx1262_error_t *out_error);

ninlil_sx1262_status_t ninlil_sx1262_request_transmit(
    ninlil_sx1262_backend_t *backend,
    const uint8_t *frame,
    uint32_t frame_len,
    ninlil_sx1262_error_t *out_error);

void ninlil_sx1262_stats(
    const ninlil_sx1262_backend_t *backend,
    ninlil_sx1262_stats_t *out_stats);

void ninlil_sx1262_last_error(
    const ninlil_sx1262_backend_t *backend,
    ninlil_sx1262_error_t *out_error);

ninlil_sx1262_status_t ninlil_sx1262_shutdown(
    ninlil_sx1262_backend_t *backend,
    ninlil_sx1262_error_t *out_error);

static inline uint64_t ninlil_sx1262_sat_add_u64(uint64_t a, uint64_t b)
{
    uint64_t sum;

    if (a == UINT64_MAX || b == UINT64_MAX) {
        return UINT64_MAX;
    }
    sum = a + b;
    if (sum < a) {
        return UINT64_MAX;
    }
    return sum;
}

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_BACKEND_H */
