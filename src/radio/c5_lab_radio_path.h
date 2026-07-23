#ifndef NINLIL_RADIO_C5_LAB_RADIO_PATH_H
#define NINLIL_RADIO_C5_LAB_RADIO_PATH_H

/*
 * C5-LAB SX1262 software path (V1 item 9; R1..R9 closure).
 *
 * TX: immutable plan -> R5 bind -> R2 permit -> R1 consume -> R9 SPI sim
 *     (sole-edge via ninlil_c6_lab_transmit; item 10a gate).
 * RX: host IRQ/FIFO/radio simulation -> C3 secure wire auth/replay admission.
 * R8 MAC layer is NOT adopted; MAC owner is explicit NONE.
 *
 * Not RF / not HIL / not public ABI / not production radio complete.
 *
 * SEMANTIC: C5_LAB_HOST_SPI_RADIO_SIM_ONLY
 * SEMANTIC: R8_MAC_OWNER_NONE
 * SEMANTIC: SOLE_EDGE_VIA_C6_LAB
 */

#include "c3_lab_context_lifecycle.h"
#include "c3_lab_secure_wire.h"
#include "c6_lab_enforcement.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_C5_LAB_RADIO_OBJECT_BYTES ((size_t)16384u)
#define NINLIL_C5_LAB_RADIO_FIFO_DEPTH ((uint32_t)16u)
#define NINLIL_C5_LAB_RADIO_FIFO_FRAME_MAX ((uint32_t)255u)
#define NINLIL_C5_LAB_MAC_OWNER_LABEL "NONE_R8_NOT_ADOPTED"

typedef uint32_t ninlil_c5_lab_radio_status_t;

#define NINLIL_C5_LAB_RADIO_OK ((ninlil_c5_lab_radio_status_t)0u)
#define NINLIL_C5_LAB_RADIO_INVALID_ARGUMENT ((ninlil_c5_lab_radio_status_t)1u)
#define NINLIL_C5_LAB_RADIO_INVALID_STATE ((ninlil_c5_lab_radio_status_t)2u)
#define NINLIL_C5_LAB_RADIO_PERMIT_DENIED ((ninlil_c5_lab_radio_status_t)3u)
#define NINLIL_C5_LAB_RADIO_AUTH_FAILED ((ninlil_c5_lab_radio_status_t)4u)
#define NINLIL_C5_LAB_RADIO_REPLAY ((ninlil_c5_lab_radio_status_t)5u)
#define NINLIL_C5_LAB_RADIO_FIFO_EMPTY ((ninlil_c5_lab_radio_status_t)6u)
#define NINLIL_C5_LAB_RADIO_UNSUPPORTED ((ninlil_c5_lab_radio_status_t)7u)

typedef struct ninlil_c5_lab_radio_channel {
    uint8_t frames[NINLIL_C5_LAB_RADIO_FIFO_DEPTH][NINLIL_C5_LAB_RADIO_FIFO_FRAME_MAX];
    uint32_t frame_lens[NINLIL_C5_LAB_RADIO_FIFO_DEPTH];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    uint64_t irq_raise_count;
    uint64_t overflow_count;
} ninlil_c5_lab_radio_channel_t;

typedef struct ninlil_c5_lab_radio_stats {
    uint64_t tx_attempts;
    uint64_t tx_ok;
    uint64_t spi_tx_count;
    uint64_t rx_irq;
    uint64_t rx_admit_ok;
    uint64_t rx_auth_fail;
    uint64_t rx_replay;
    uint64_t permit_fail;
} ninlil_c5_lab_radio_stats_t;

typedef struct ninlil_c5_lab_radio_object {
    uint8_t storage[NINLIL_C5_LAB_RADIO_OBJECT_BYTES];
} ninlil_c5_lab_radio_object_t;

typedef struct ninlil_c5_lab_radio ninlil_c5_lab_radio_t;

#define NINLIL_C5_LAB_RADIO_OBJECT_INIT {{0}}

const char *ninlil_c5_lab_mac_owner_label(void);

void ninlil_c5_lab_radio_channel_init(ninlil_c5_lab_radio_channel_t *channel);

int ninlil_c5_lab_radio_channel_deliver(
    ninlil_c5_lab_radio_channel_t *channel,
    const uint8_t *frame,
    uint32_t frame_len);

size_t ninlil_c5_lab_radio_object_size(void);

ninlil_c5_lab_radio_status_t ninlil_c5_lab_radio_init_object(
    ninlil_c5_lab_radio_object_t *object,
    ninlil_c3_lab_context_store_t *store,
    ninlil_c6_lab_t *c6,
    ninlil_c5_lab_radio_channel_t *rx_channel,
    ninlil_c5_lab_radio_t **out_radio);

/*
 * Seal payload with C3 secure wire, transmit via C6 sole-edge (R7_HOP_DATA).
 * Delivers sealed wire frame to optional peer channel (host radio sim).
 */
ninlil_c5_lab_radio_status_t ninlil_c5_lab_radio_tx_data(
    ninlil_c5_lab_radio_t *radio,
    const uint8_t *payload,
    size_t payload_len,
    ninlil_c5_lab_radio_channel_t *peer_channel);

/*
 * Host IRQ/FIFO poll: pop one frame from rx_channel and admit via C3 wire open.
 */
ninlil_c5_lab_radio_status_t ninlil_c5_lab_radio_irq_rx_admit(
    ninlil_c5_lab_radio_t *radio,
    uint8_t *out_payload,
    size_t out_capacity,
    size_t *out_payload_len);

void ninlil_c5_lab_radio_stats_snapshot(
    const ninlil_c5_lab_radio_t *radio,
    ninlil_c5_lab_radio_stats_t *out_stats);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_C5_LAB_RADIO_PATH_H */
