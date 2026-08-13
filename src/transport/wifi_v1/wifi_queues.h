/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_QUEUES_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_QUEUES_H

#include "wifi_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_TX_QUEUE_DEPTH NINLIL_WIFI_HOST_TX_TOKEN_PER_SESSION
#define NINLIL_WIFI_RX_QUEUE_DEPTH NINLIL_WIFI_HOST_RX_RECORD_PER_SESSION

typedef struct ninlil_wifi_record_slot {
    uint8_t bytes[NINLIL_WIFI_NWB1_TOTAL_MAX];
    uint16_t length;
    uint8_t in_use;
    uint8_t reserved;
} ninlil_wifi_record_slot_t;

typedef struct ninlil_wifi_record_queue {
    ninlil_wifi_record_slot_t slots[NINLIL_WIFI_TX_QUEUE_DEPTH];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
    uint8_t reserved;
} ninlil_wifi_record_queue_t;

void ninlil_wifi_queue_init(ninlil_wifi_record_queue_t *q);
int ninlil_wifi_queue_is_full(const ninlil_wifi_record_queue_t *q);
int ninlil_wifi_queue_is_empty(const ninlil_wifi_record_queue_t *q);

/* Copy-in enqueue. CAPACITY if full (backpressure). */
ninlil_wifi_status_t ninlil_wifi_queue_push(
    ninlil_wifi_record_queue_t *q,
    const uint8_t *record,
    size_t length);

/* Peek head without pop. */
ninlil_wifi_status_t ninlil_wifi_queue_peek(
    const ninlil_wifi_record_queue_t *q,
    const uint8_t **record_out,
    size_t *length_out);

ninlil_wifi_status_t ninlil_wifi_queue_pop(ninlil_wifi_record_queue_t *q);

/*
 * Drop all queued records whose NWB1 sequence (header offset 32 BE) matches.
 * Returns number of records removed (0 if none). Used by fabric cancel/close.
 */
uint32_t ninlil_wifi_queue_drop_sequence(
    ninlil_wifi_record_queue_t *q,
    uint32_t sequence);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_QUEUES_H */
