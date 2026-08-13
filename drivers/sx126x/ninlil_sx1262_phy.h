/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_SX1262_PHY_H
#define NINLIL_SX1262_PHY_H

/*
 * R9 SX1262 physical TX/RX path (Proposed ADR-0025).
 * Production-private. Not public ABI. Default-OFF composition.
 *
 * Sole SetTx issuer: ninlil_sx1262_phy_arm_tx (production via R1 HAL + R9 edge).
 * Legacy request_transmit_with_permit is fixture-only and calls arm_tx.
 * Bare R4 request_transmit remains deny (docs/28 / ADR-0008).
 *
 * Nonclaims: RF HIL PASS, Japan legal certification, R4 complete rewrite.
 */

#include "ninlil_sx1262_backend.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_PHY_ABI_VERSION ((uint16_t)0x0001u)
#define NINLIL_SX1262_PHY_MAX_FRAME ((uint32_t)255u)
#define NINLIL_SX1262_PHY_DIGEST_BYTES ((size_t)32u)

/* Closed LAB-facing RF profile bounds (not Japan legal tables). */
typedef struct ninlil_sx1262_rf_profile {
    uint16_t abi_version;
    uint16_t struct_size;
    uint32_t freq_hz_min;
    uint32_t freq_hz_max;
    uint32_t bandwidth_hz; /* exact match required */
    uint8_t sf_min;
    uint8_t sf_max;
    uint8_t cr_denom_min; /* coding rate 4/denom */
    uint8_t cr_denom_max;
    uint16_t preamble_min;
    uint16_t preamble_max;
    int32_t tx_power_mdb_min;
    int32_t tx_power_mdb_max;
    uint32_t max_airtime_us_ceiling;
    uint32_t reserved_zero;
} ninlil_sx1262_rf_profile_t;

/*
 * Exact TxPermit binding for physical arming (portable; R2-compatible fields).
 * Generation is radio phy generation (stale reject), not application generation.
 */
typedef struct ninlil_sx1262_tx_permit {
    uint16_t abi_version;
    uint16_t struct_size;
    uint64_t permit_sequence; /* nonzero; one-shot watermark local to phy */
    uint64_t attempt_id;      /* nonzero */
    uint64_t radio_generation; /* must match phy live generation */
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    uint32_t frequency_hz;
    uint32_t bandwidth_hz;
    uint8_t spreading_factor;
    uint8_t coding_rate_denom;
    uint16_t preamble_symbols;
    int32_t tx_power_mdb;
    uint32_t max_airtime_us;
    uint32_t frame_byte_length;
    uint8_t frame_digest[NINLIL_SX1262_PHY_DIGEST_BYTES];
    uint32_t reserved_zero;
} ninlil_sx1262_tx_permit_t;

typedef uint32_t ninlil_sx1262_phy_state_t;

#define NINLIL_SX1262_PHY_STATE_IDLE ((ninlil_sx1262_phy_state_t)0u)
#define NINLIL_SX1262_PHY_STATE_CONFIGURING ((ninlil_sx1262_phy_state_t)1u)
#define NINLIL_SX1262_PHY_STATE_TX_ARMED ((ninlil_sx1262_phy_state_t)2u)
#define NINLIL_SX1262_PHY_STATE_TX_ACTIVE ((ninlil_sx1262_phy_state_t)3u)
#define NINLIL_SX1262_PHY_STATE_RX_ACTIVE ((ninlil_sx1262_phy_state_t)4u)
#define NINLIL_SX1262_PHY_STATE_RECOVERY ((ninlil_sx1262_phy_state_t)5u)
#define NINLIL_SX1262_PHY_STATE_FAULT ((ninlil_sx1262_phy_state_t)6u)

typedef uint32_t ninlil_sx1262_rx_class_t;

#define NINLIL_SX1262_RX_OK ((ninlil_sx1262_rx_class_t)0u)
#define NINLIL_SX1262_RX_CRC_ERROR ((ninlil_sx1262_rx_class_t)1u)
#define NINLIL_SX1262_RX_HEADER_ERROR ((ninlil_sx1262_rx_class_t)2u)
#define NINLIL_SX1262_RX_TIMEOUT ((ninlil_sx1262_rx_class_t)3u)
#define NINLIL_SX1262_RX_BUSY_STUCK ((ninlil_sx1262_rx_class_t)4u)
#define NINLIL_SX1262_RX_STALE_GEN ((ninlil_sx1262_rx_class_t)5u)
#define NINLIL_SX1262_RX_EMPTY ((ninlil_sx1262_rx_class_t)6u)

typedef struct ninlil_sx1262_rx_meta {
    uint32_t length;
    int16_t rssi_dbm;
    int8_t snr_db;
    uint8_t reserved0;
    ninlil_sx1262_rx_class_t classification;
    uint64_t radio_generation;
    uint32_t irq_status;
    uint32_t reserved_zero;
} ninlil_sx1262_rx_meta_t;

typedef struct ninlil_sx1262_phy_stats {
    uint64_t tx_attempts;
    uint64_t tx_ok;
    uint64_t tx_deny;
    uint64_t tx_timeout;
    uint64_t rx_starts;
    uint64_t rx_ok;
    uint64_t rx_crc_err;
    uint64_t rx_header_err;
    uint64_t recoveries;
    uint64_t stale_gen_reject;
    uint64_t busy_stuck;
    uint64_t settx_commands;
    uint64_t setrx_commands;
    uint64_t status_reject;
    uint64_t lbt_busy;
    uint64_t lbt_clear;
    uint64_t lbt_timeout;
    uint64_t ant_sw_tx;
    uint64_t ant_sw_rx;
    uint64_t seal_reject;
} ninlil_sx1262_phy_stats_t;

/* R3 AUTO LDRO effective bit: 1 iff Tsym >= 16.38 ms (2^SF*1e5 >= BW*1638). */
int ninlil_sx1262_phy_ldro_auto_effective(uint8_t sf, uint32_t bw_hz);

/*
 * Optional DIO1 sample (IRQ). If NULL, phy falls back to status/IRQ register
 * polls only (host spy can inject IRQ via SPI responses).
 */
typedef struct ninlil_sx1262_phy_irq_ops {
    int (*dio1_is_high)(void *ctx, int *out_high);
} ninlil_sx1262_phy_irq_ops_t;

#define NINLIL_SX1262_PHY_OBJECT_BYTES ((size_t)1536u)
#define NINLIL_SX1262_PHY_OBJECT_ALIGN ((size_t)8u)

typedef struct ninlil_sx1262_phy ninlil_sx1262_phy_t;

/* Opaque caller storage (R4-style). Zero-init before first phy_init. */
typedef struct ninlil_sx1262_phy_object {
    _Alignas(NINLIL_SX1262_PHY_OBJECT_ALIGN) uint8_t
        storage[NINLIL_SX1262_PHY_OBJECT_BYTES];
} ninlil_sx1262_phy_object_t;

#define NINLIL_SX1262_PHY_OBJECT_INIT \
    {                                 \
        {                             \
            0                         \
        }                             \
    }

size_t ninlil_sx1262_phy_object_size(void);
size_t ninlil_sx1262_phy_object_align(void);

/* RF profile helper for declared ESP32-S3 + SX1262 LAB composition (not legal). */
void ninlil_sx1262_rf_profile_lab_default(ninlil_sx1262_rf_profile_t *out);

/*
 * Attach phy to an initialized R4 backend (READY). Fails if backend not ready.
 * generation starts at 1; recovery bumps generation.
 */
ninlil_sx1262_status_t ninlil_sx1262_phy_init(
    ninlil_sx1262_phy_object_t *object,
    ninlil_sx1262_backend_t *backend,
    const ninlil_sx1262_rf_profile_t *profile,
    const ninlil_sx1262_phy_irq_ops_t *irq_ops,
    void *irq_ctx,
    ninlil_sx1262_phy_t **out_phy,
    ninlil_sx1262_error_t *out_error);

uint64_t ninlil_sx1262_phy_generation(const ninlil_sx1262_phy_t *phy);
ninlil_sx1262_phy_state_t ninlil_sx1262_phy_state(const ninlil_sx1262_phy_t *phy);

/*
 * Low-level RF arm after R1 sole-edge authority has already validated+consumed
 * the permit and the R9 edge adapter has recomputed digest/airtime.
 * Does NOT implement permit policy (no parallel authority).
 * settx_timeout_steps: SX1262 15.625µs RTC units, 1..0xFFFFFF.
 *
 * Seal fields (frame_byte_length/digest/max_airtime/window/ldro/lbt) are bound
 * at arm_tx entry; payload/context cannot change after the plan is accepted.
 */
typedef struct ninlil_sx1262_phy_tx_plan {
    uint32_t frequency_hz;
    uint32_t bandwidth_hz;
    uint8_t spreading_factor;
    uint8_t coding_rate_denom; /* 5..8 → LoRa CR 4/5..4/8 */
    uint16_t preamble_symbols;
    int32_t tx_power_mdb;
    uint32_t settx_timeout_steps;
    uint64_t expected_radio_generation;
    /* Immutable post-permit seal (edge fills; arm_tx rechecks). */
    uint32_t frame_byte_length;
    uint8_t frame_digest[NINLIL_SX1262_PHY_DIGEST_BYTES];
    uint32_t max_airtime_us;
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    uint64_t permit_sequence; /* nonzero when sealed from authority path */
    uint8_t ldro_effective;   /* 0/1 for SetModulationParams (R3 AUTO result) */
    uint8_t require_lbt;      /* 1 = CAD/LBT before SetTx */
    uint8_t reserved0[2];
    uint32_t lbt_timeout_ms;  /* CAD poll deadline; 0 → default 50 ms */
} ninlil_sx1262_phy_tx_plan_t;

ninlil_sx1262_status_t ninlil_sx1262_phy_arm_tx(
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_phy_tx_plan_t *plan,
    const uint8_t *frame,
    uint32_t frame_len,
    ninlil_sx1262_error_t *out_error);

/*
 * Legacy thin wrapper — host unit fixtures only.
 * Production / ESP / HIL builds define NINLIL_SX1262_PRODUCTION_BUILD so this
 * symbol is absent. Production MUST use radio_hal_transmit_with_permit → R9 edge.
 */
#if !defined(NINLIL_SX1262_PRODUCTION_BUILD)
ninlil_sx1262_status_t ninlil_sx1262_request_transmit_with_permit(
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_tx_permit_t *permit,
    const uint8_t *frame,
    uint32_t frame_len,
    ninlil_sx1262_error_t *out_error);
#endif

/* Nonblocking progress: DIO1/IRQ/BUSY/deadlines. */
ninlil_sx1262_status_t ninlil_sx1262_phy_poll(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error);

/* Continuous RX arm (scheduled timeout_ms; 0 = use profile default 5000). */
ninlil_sx1262_status_t ninlil_sx1262_phy_start_rx(
    ninlil_sx1262_phy_t *phy,
    uint32_t timeout_ms,
    ninlil_sx1262_error_t *out_error);

/*
 * Copy last RX payload (if any) into caller buffer. No allocation.
 * out_meta always written when non-NULL.
 */
ninlil_sx1262_status_t ninlil_sx1262_phy_take_rx(
    ninlil_sx1262_phy_t *phy,
    uint8_t *out_frame,
    uint32_t out_capacity,
    ninlil_sx1262_rx_meta_t *out_meta,
    ninlil_sx1262_error_t *out_error);

/* Explicit reset/recovery: STDBY_RC + ClearIrq + generation++. */
ninlil_sx1262_status_t ninlil_sx1262_phy_recover(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error);

void ninlil_sx1262_phy_stats(
    const ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_phy_stats_t *out_stats);

ninlil_sx1262_status_t ninlil_sx1262_phy_shutdown(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error);

/* Frequency word: freq_hz * 2^25 / 32000000 (DS RF frequency). */
int ninlil_sx1262_rf_freq_to_reg(uint32_t freq_hz, uint32_t *out_reg);
/* Closed PA/power composition for power_mdb (LAB; not legal table). */
int ninlil_sx1262_compose_pa_tx_params(
    int32_t power_mdb,
    uint8_t *out_pa_duty,
    uint8_t *out_hp_max,
    uint8_t *out_device_sel,
    uint8_t *out_pa_lut,
    int8_t *out_power_dbm,
    uint8_t *out_ramp);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_PHY_H */
