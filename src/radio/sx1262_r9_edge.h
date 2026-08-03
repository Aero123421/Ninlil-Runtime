#ifndef NINLIL_RADIO_SX1262_R9_EDGE_H
#define NINLIL_RADIO_SX1262_R9_EDGE_H

/*
 * R9 production sole physical TX edge adapter (Proposed ADR-0025).
 *
 * Binds ninlil_radio_hal edge to SX1262 phy after R1 digest/validate/consume.
 * MUST be the only production path that issues SetTx.
 * Bare ninlil_sx1262_request_transmit remains R4 deny.
 *
 * Pre-SetTx rechecks (defense in depth after R1):
 *   - SHA-256 recompute of sealed frame vs permit.frame_digest (constant-time)
 *   - R3 airtime recompute vs permit.max_airtime_us + RF profile ceiling
 *   - channel→frequency + PHY within bound RF profile
 *   - radio generation (stale reject after recover)
 *
 * Sequence/single-use watermark authority remains R1 HAL (not re-issued here).
 */

#include "ninlil_sx1262_phy.h"
#include "radio_hal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SX1262_R9_EDGE_OBJECT_BYTES ((size_t)512u)
#define NINLIL_SX1262_R9_EDGE_OBJECT_ALIGN ((size_t)8u)
#define NINLIL_SX1262_R9_EDGE_OBJECT_INIT \
    {                                     \
        {                                 \
            0                             \
        }                                 \
    }

typedef struct ninlil_sx1262_r9_edge ninlil_sx1262_r9_edge_t;

typedef struct ninlil_sx1262_r9_edge_object {
    _Alignas(NINLIL_SX1262_R9_EDGE_OBJECT_ALIGN) uint8_t
        storage[NINLIL_SX1262_R9_EDGE_OBJECT_BYTES];
} ninlil_sx1262_r9_edge_object_t;

typedef struct ninlil_sx1262_r9_edge_stats {
    uint64_t edge_calls;
    uint64_t edge_ok;
    uint64_t digest_reject;
    uint64_t airtime_reject;
    uint64_t profile_reject;
    uint64_t gen_reject;
    uint64_t phy_reject;
} ninlil_sx1262_r9_edge_stats_t;

size_t ninlil_sx1262_r9_edge_object_size(void);

/*
 * Bind edge to ready phy + RF profile. out_edge is opaque storage.
 * Returns radio_hal edge_ops + ctx for ninlil_radio_hal_bind_edge.
 */
ninlil_radio_hal_status_t ninlil_sx1262_r9_edge_init(
    ninlil_sx1262_r9_edge_object_t *object,
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_rf_profile_t *profile,
    ninlil_sx1262_r9_edge_t **out_edge,
    const ninlil_radio_hal_edge_ops_t **out_ops,
    void **out_ctx,
    ninlil_radio_hal_error_t *out_error);

void ninlil_sx1262_r9_edge_stats(
    const ninlil_sx1262_r9_edge_t *edge,
    ninlil_sx1262_r9_edge_stats_t *out_stats);

/* Map channel_id → frequency_hz using profile LAB map (not Japan legal table). */
int ninlil_sx1262_r9_channel_to_freq_hz(
    const ninlil_sx1262_rf_profile_t *profile,
    uint32_t channel_id,
    uint32_t *out_freq_hz);

/* SetTx timeout: RTC steps = ceil(timeout_us / 15.625µs), 24-bit max. */
int ninlil_sx1262_r9_airtime_to_settx_steps(
    uint32_t airtime_us,
    uint32_t margin_us,
    uint32_t *out_steps);

/* Constant-time 32-byte compare: 0 equal, 1 differ. */
int ninlil_sx1262_r9_digest_ct_neq(
    const uint8_t a[32],
    const uint8_t b[32]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_SX1262_R9_EDGE_H */
