/*
 * NWB1 private framing (ADR-0018). Payload = exact 1 structural NFL1.
 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_NWB1_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_NWB1_H

#include "wifi_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_NWB1_MAGIC_0 ((uint8_t)'N')
#define NINLIL_WIFI_NWB1_MAGIC_1 ((uint8_t)'W')
#define NINLIL_WIFI_NWB1_MAGIC_2 ((uint8_t)'B')
#define NINLIL_WIFI_NWB1_MAGIC_3 ((uint8_t)'1')
#define NINLIL_WIFI_NWB1_VERSION ((uint16_t)1u)

uint32_t ninlil_wifi_crc32c(const uint8_t *data, size_t length);

/*
 * Encode one NWB1 record into out[0..total).
 * payload must be structural NFL1 (587..1925).
 * session_id[16], sequence u32.
 */
ninlil_wifi_status_t ninlil_wifi_nwb1_encode(
    const uint8_t session_id[16],
    uint32_t sequence,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

/*
 * Classify framing. expected_session may be NULL.
 * has_expected_sequence=0 ignores sequence match.
 */
ninlil_wifi_status_t ninlil_wifi_nwb1_classify(
    const uint8_t *record,
    size_t length,
    const uint8_t *expected_session_or_null,
    int has_expected_sequence,
    uint32_t expected_sequence,
    const uint8_t **payload_out,
    uint32_t *payload_len_out,
    uint32_t *sequence_out);

/* Structural NFL1 check (header 584, CRC, bounds). Not full fabric semantic. */
int ninlil_wifi_nfl1_structural_ok(const uint8_t *packet, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_NWB1_H */
