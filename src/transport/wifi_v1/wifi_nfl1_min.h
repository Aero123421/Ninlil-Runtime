#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_NFL1_MIN_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_NFL1_MIN_H

#include "wifi_nwb1.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal structural NFL1 builder for Host tests (not fabric semantic encode).
 * Produces a valid structural 587-byte NFL1 for NWB1 payload tests.
 */
ninlil_wifi_status_t ninlil_wifi_nfl1_min_encode(
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    uint32_t marker);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_NFL1_MIN_H */
