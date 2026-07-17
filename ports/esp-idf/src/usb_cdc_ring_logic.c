#include "usb_cdc_ring_logic.h"

#include <string.h>

void ninlil_usb_cdc_ring_reset(ninlil_usb_cdc_ring_t *ring)
{
    if (ring == NULL) {
        return;
    }
    ring->head = 0u;
    ring->tail = 0u;
    ring->len = 0u;
}

uint32_t ninlil_usb_cdc_ring_free(const ninlil_usb_cdc_ring_t *ring)
{
    if (ring == NULL || ring->capacity == 0u) {
        return 0u;
    }
    if (ring->len >= ring->capacity) {
        return 0u;
    }
    return ring->capacity - ring->len;
}

uint32_t ninlil_usb_cdc_ring_push(
    ninlil_usb_cdc_ring_t *ring,
    const uint8_t *data,
    uint32_t n)
{
    uint32_t free_space;
    uint32_t i;

    if (ring == NULL || ring->bytes == NULL || ring->capacity == 0u) {
        return 0u;
    }
    if (data == NULL || n == 0u) {
        return 0u;
    }
    free_space = ninlil_usb_cdc_ring_free(ring);
    if (n > free_space) {
        n = free_space;
    }
    for (i = 0u; i < n; ++i) {
        ring->bytes[ring->tail] = data[i];
        ring->tail = (ring->tail + 1u) % ring->capacity;
    }
    ring->len += n;
    return n;
}

uint32_t ninlil_usb_cdc_ring_pop(
    ninlil_usb_cdc_ring_t *ring,
    uint8_t *out,
    uint32_t cap)
{
    uint32_t n;
    uint32_t i;

    if (ring == NULL || ring->bytes == NULL || out == NULL) {
        return 0u;
    }
    n = ring->len;
    if (n > cap) {
        n = cap;
    }
    for (i = 0u; i < n; ++i) {
        out[i] = ring->bytes[ring->head];
        ring->head = (ring->head + 1u) % ring->capacity;
    }
    ring->len -= n;
    return n;
}

uint32_t ninlil_usb_cdc_ring_peek(
    const ninlil_usb_cdc_ring_t *ring,
    uint8_t *out,
    uint32_t cap)
{
    uint32_t n;
    uint32_t i;
    uint32_t head;

    if (ring == NULL || ring->bytes == NULL || out == NULL) {
        return 0u;
    }
    n = ring->len;
    if (n > cap) {
        n = cap;
    }
    head = ring->head;
    for (i = 0u; i < n; ++i) {
        out[i] = ring->bytes[head];
        head = (head + 1u) % ring->capacity;
    }
    return n;
}

void ninlil_usb_cdc_ring_consume(ninlil_usb_cdc_ring_t *ring, uint32_t n)
{
    if (ring == NULL || ring->capacity == 0u) {
        return;
    }
    if (n > ring->len) {
        n = ring->len;
    }
    ring->head = (ring->head + n) % ring->capacity;
    ring->len -= n;
}
