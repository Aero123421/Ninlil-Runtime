/*
 * Pure fixed ring helpers for A2 ESP CDC (and host tests).
 * Allocation-free, no platform types, no heap, no logging.
 */

#ifndef NINLIL_ESP_IDF_USB_CDC_RING_LOGIC_H
#define NINLIL_ESP_IDF_USB_CDC_RING_LOGIC_H

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_usb_cdc_ring {
    uint8_t *bytes;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t len;
} ninlil_usb_cdc_ring_t;

void ninlil_usb_cdc_ring_reset(ninlil_usb_cdc_ring_t *ring);

uint32_t ninlil_usb_cdc_ring_free(const ninlil_usb_cdc_ring_t *ring);

/* Push up to n bytes; returns accepted count (may be partial). */
uint32_t ninlil_usb_cdc_ring_push(
    ninlil_usb_cdc_ring_t *ring,
    const uint8_t *data,
    uint32_t n);

/* Pop up to cap bytes into out; returns popped count. */
uint32_t ninlil_usb_cdc_ring_pop(
    ninlil_usb_cdc_ring_t *ring,
    uint8_t *out,
    uint32_t cap);

/* Peek up to cap bytes without consuming. */
uint32_t ninlil_usb_cdc_ring_peek(
    const ninlil_usb_cdc_ring_t *ring,
    uint8_t *out,
    uint32_t cap);

void ninlil_usb_cdc_ring_consume(ninlil_usb_cdc_ring_t *ring, uint32_t n);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_USB_CDC_RING_LOGIC_H */
