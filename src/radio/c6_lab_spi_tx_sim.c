#include "c6_lab_spi_tx_sim.h"

#include <string.h>

static const ninlil_radio_hal_edge_ops_t g_c6_spi_edge_ops = {
    ninlil_c6_lab_spi_tx_sim_edge
};

void ninlil_c6_lab_spi_tx_sim_init(ninlil_c6_lab_spi_tx_sim_t *sim)
{
    if (sim == NULL) {
        return;
    }
    (void)memset(sim, 0, sizeof(*sim));
}

static void record_spi_tx(
    ninlil_c6_lab_spi_tx_sim_t *sim,
    const uint8_t *bytes,
    uint32_t length)
{
    ninlil_c6_lab_spi_tx_trace_t *rec;
    uint32_t copy;
    uint32_t i;

    if (sim == NULL) {
        return;
    }
    sim->spi_tx_count += 1u;
    if (sim->trace_len >= NINLIL_C6_LAB_SPI_TX_TRACE_CAP) {
        sim->trace_overflow = 1u;
        return;
    }
    rec = &sim->trace[sim->trace_len];
    sim->trace_len += 1u;
    rec->sequence = sim->spi_tx_count;
    rec->frame_length = length;
    copy = length;
    if (copy > NINLIL_C6_LAB_SPI_TX_SAMPLE_BYTES) {
        copy = (uint32_t)NINLIL_C6_LAB_SPI_TX_SAMPLE_BYTES;
    }
    rec->sample_len = (uint8_t)copy;
    for (i = 0u; i < copy; ++i) {
        rec->sample[i] = bytes[i];
    }
}

ninlil_radio_hal_status_t ninlil_c6_lab_spi_tx_sim_edge(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_c6_lab_spi_tx_sim_t *sim = (ninlil_c6_lab_spi_tx_sim_t *)ctx;

    (void)permit;
    if (sim == NULL || frame == NULL || frame->bytes == NULL
        || frame->length == 0u) {
        if (out_error != NULL) {
            out_error->status = NINLIL_RADIO_HAL_INVALID_ARGUMENT;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_EDGE;
            out_error->reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
            out_error->reserved_zero = 0u;
            (void)memset(out_error->hint, 0, sizeof(out_error->hint));
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    record_spi_tx(sim, frame->bytes, frame->length);
    if (out_error != NULL) {
        out_error->status = NINLIL_RADIO_HAL_OK;
        out_error->stage = NINLIL_RADIO_HAL_STAGE_NONE;
        out_error->reason = NINLIL_RADIO_HAL_REASON_NONE;
        out_error->reserved_zero = 0u;
        (void)memset(out_error->hint, 0, sizeof(out_error->hint));
    }
    return NINLIL_RADIO_HAL_OK;
}

const ninlil_radio_hal_edge_ops_t *ninlil_c6_lab_spi_tx_sim_edge_ops(void)
{
    return &g_c6_spi_edge_ops;
}

ninlil_radio_hal_status_t ninlil_c6_lab_spi_tx_bypass_direct(
    ninlil_c6_lab_spi_tx_sim_t *sim,
    const uint8_t *frame,
    uint32_t frame_len)
{
    if (sim == NULL || frame == NULL || frame_len == 0u) {
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    sim->bypass_attempt_count += 1u;
    record_spi_tx(sim, frame, frame_len);
    return NINLIL_RADIO_HAL_OK;
}

void ninlil_c6_lab_spi_tx_sim_stats(
    const ninlil_c6_lab_spi_tx_sim_t *sim,
    uint64_t *out_spi_tx_count,
    uint64_t *out_bypass_attempt_count)
{
    if (out_spi_tx_count != NULL) {
        *out_spi_tx_count = sim == NULL ? 0u : sim->spi_tx_count;
    }
    if (out_bypass_attempt_count != NULL) {
        *out_bypass_attempt_count =
            sim == NULL ? 0u : sim->bypass_attempt_count;
    }
}
