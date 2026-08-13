/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_queues.h"

#include <string.h>

void ninlil_wifi_queue_init(ninlil_wifi_record_queue_t *q)
{
    if (q == NULL) {
        return;
    }
    (void)memset(q, 0, sizeof(*q));
}

int ninlil_wifi_queue_is_full(const ninlil_wifi_record_queue_t *q)
{
    return q != NULL && q->count >= NINLIL_WIFI_TX_QUEUE_DEPTH;
}

int ninlil_wifi_queue_is_empty(const ninlil_wifi_record_queue_t *q)
{
    return q == NULL || q->count == 0u;
}

ninlil_wifi_status_t ninlil_wifi_queue_push(
    ninlil_wifi_record_queue_t *q,
    const uint8_t *record,
    size_t length)
{
    ninlil_wifi_record_slot_t *slot;
    if (q == NULL || record == NULL || length == 0u
        || length > NINLIL_WIFI_NWB1_TOTAL_MAX) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_queue_is_full(q)) {
        return NINLIL_WIFI_BACKPRESSURE;
    }
    slot = &q->slots[q->tail];
    (void)memcpy(slot->bytes, record, length);
    slot->length = (uint16_t)length;
    slot->in_use = 1u;
    q->tail = (uint8_t)((q->tail + 1u) % NINLIL_WIFI_TX_QUEUE_DEPTH);
    q->count = (uint8_t)(q->count + 1u);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_queue_peek(
    const ninlil_wifi_record_queue_t *q,
    const uint8_t **record_out,
    size_t *length_out)
{
    const ninlil_wifi_record_slot_t *slot;
    if (q == NULL || record_out == NULL || length_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_queue_is_empty(q)) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    slot = &q->slots[q->head];
    *record_out = slot->bytes;
    *length_out = slot->length;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_queue_pop(ninlil_wifi_record_queue_t *q)
{
    if (q == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_queue_is_empty(q)) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    q->slots[q->head].in_use = 0u;
    q->slots[q->head].length = 0u;
    q->head = (uint8_t)((q->head + 1u) % NINLIL_WIFI_TX_QUEUE_DEPTH);
    q->count = (uint8_t)(q->count - 1u);
    return NINLIL_WIFI_OK;
}

static uint32_t nwb1_seq_be(const uint8_t *rec, uint16_t length)
{
    if (rec == NULL || length < 36u) {
        return 0xffffffffu;
    }
    return ((uint32_t)rec[32] << 24) | ((uint32_t)rec[33] << 16)
        | ((uint32_t)rec[34] << 8) | (uint32_t)rec[35];
}

/*
 * Drop matching NWB1 sequences; compact survivors to head=0 linear form.
 * Wrap-safe with one slot temporary (~2 KiB) — never a DEPTH-wide stack array.
 */
uint32_t ninlil_wifi_queue_drop_sequence(
    ninlil_wifi_record_queue_t *q,
    uint32_t sequence)
{
    uint32_t removed = 0u;
    uint8_t old_count;
    uint8_t i;
    uint8_t n_keep = 0u;
    uint8_t keep_src[NINLIL_WIFI_TX_QUEUE_DEPTH];
    ninlil_wifi_record_slot_t temp;
    uint8_t dst;

    if (q == NULL || q->count == 0u) {
        return 0u;
    }
    old_count = q->count;
    for (i = 0u; i < old_count; ++i) {
        uint8_t src = (uint8_t)((q->head + i) % NINLIL_WIFI_TX_QUEUE_DEPTH);
        if (q->slots[src].in_use == 0u) {
            continue;
        }
        if (nwb1_seq_be(q->slots[src].bytes, q->slots[src].length)
            == sequence) {
            removed += 1u;
            q->slots[src].in_use = 0u;
            q->slots[src].length = 0u;
            continue;
        }
        keep_src[n_keep] = src;
        n_keep = (uint8_t)(n_keep + 1u);
    }

    (void)memset(&temp, 0, sizeof(temp));
    for (dst = 0u; dst < n_keep; ++dst) {
        uint8_t src = keep_src[dst];
        uint8_t k;
        if (src == dst) {
            continue;
        }
        /* If dest holds a later survivor, swap via temp and fix keep_src. */
        if (q->slots[dst].in_use != 0u) {
            int dest_is_later_keep = 0;
            for (k = (uint8_t)(dst + 1u); k < n_keep; ++k) {
                if (keep_src[k] == dst) {
                    dest_is_later_keep = 1;
                    break;
                }
            }
            if (dest_is_later_keep) {
                (void)memcpy(&temp, &q->slots[dst], sizeof(temp));
                (void)memcpy(&q->slots[dst], &q->slots[src], sizeof(q->slots[0]));
                (void)memcpy(&q->slots[src], &temp, sizeof(temp));
                for (k = (uint8_t)(dst + 1u); k < n_keep; ++k) {
                    if (keep_src[k] == dst) {
                        keep_src[k] = src;
                    } else if (keep_src[k] == src) {
                        keep_src[k] = dst;
                    }
                }
                keep_src[dst] = dst;
                continue;
            }
        }
        (void)memcpy(&q->slots[dst], &q->slots[src], sizeof(q->slots[0]));
        if (src != dst) {
            q->slots[src].in_use = 0u;
            q->slots[src].length = 0u;
        }
        keep_src[dst] = dst;
    }
    for (i = n_keep; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        q->slots[i].in_use = 0u;
        q->slots[i].length = 0u;
    }
    q->head = 0u;
    q->count = n_keep;
    q->tail = (n_keep == NINLIL_WIFI_TX_QUEUE_DEPTH) ? 0u : n_keep;
    return removed;
}
