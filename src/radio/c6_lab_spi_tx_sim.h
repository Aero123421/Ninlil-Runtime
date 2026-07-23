#ifndef NINLIL_RADIO_C6_LAB_SPI_TX_SIM_H
#define NINLIL_RADIO_C6_LAB_SPI_TX_SIM_H

/*
 * R9 host SPI TX simulation for V1-LAB C6 enforcement.
 *
 * Physical SPI emission is simulated by bounded trace records only.
 * Not RF / not HIL / not public ABI / not production radio complete.
 *
 * SEMANTIC: R9_HOST_SPI_SIM_ONLY
 * SEMANTIC: SOLE_EDGE_VIA_HAL_CALLBACK
 */

#include "radio_hal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_C6_LAB_SPI_TX_SAMPLE_BYTES ((size_t)16u)
#define NINLIL_C6_LAB_SPI_TX_TRACE_CAP ((size_t)32u)

typedef struct ninlil_c6_lab_spi_tx_trace {
    uint64_t sequence;
    uint32_t frame_length;
    uint8_t sample[NINLIL_C6_LAB_SPI_TX_SAMPLE_BYTES];
    uint8_t sample_len;
    uint8_t reserved0[3];
} ninlil_c6_lab_spi_tx_trace_t;

typedef struct ninlil_c6_lab_spi_tx_sim {
    uint64_t spi_tx_count;
    uint64_t bypass_attempt_count;
    uint32_t trace_len;
    uint32_t trace_overflow;
    ninlil_c6_lab_spi_tx_trace_t trace[NINLIL_C6_LAB_SPI_TX_TRACE_CAP];
} ninlil_c6_lab_spi_tx_sim_t;

void ninlil_c6_lab_spi_tx_sim_init(ninlil_c6_lab_spi_tx_sim_t *sim);

/*
 * HAL edge callback — sole authorized production path to SPI TX simulation.
 * Bound via ninlil_c6_lab_spi_tx_sim_edge_ops().
 */
ninlil_radio_hal_status_t ninlil_c6_lab_spi_tx_sim_edge(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error);

const ninlil_radio_hal_edge_ops_t *ninlil_c6_lab_spi_tx_sim_edge_ops(void);

/*
 * Test-only bypass symbol. Production gate requires call sites == 0 outside
 * tests/radio/c6_lab_enforcement_test.c (structural bypass=0 on success path).
 */
ninlil_radio_hal_status_t ninlil_c6_lab_spi_tx_bypass_direct(
    ninlil_c6_lab_spi_tx_sim_t *sim,
    const uint8_t *frame,
    uint32_t frame_len);

void ninlil_c6_lab_spi_tx_sim_stats(
    const ninlil_c6_lab_spi_tx_sim_t *sim,
    uint64_t *out_spi_tx_count,
    uint64_t *out_bypass_attempt_count);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_C6_LAB_SPI_TX_SIM_H */
