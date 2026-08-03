#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_STREAM_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_STREAM_H

#include "wifi_nwb1.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Nonblocking NWB1 reassembly buffer. Partial reads accumulate until one
 * complete record is available. Oversize / malformed length fields fence.
 *
 * Host session: 2-record buffer for coalesced streams (default).
 * ESP owner / ESP_PLATFORM: single-record (12 KiB workspace contract).
 * Callers may pre-define NINLIL_WIFI_RX_STREAM_BUF_BYTES before include.
 */
#ifndef NINLIL_WIFI_RX_STREAM_BUF_BYTES
#if defined(ESP_PLATFORM) || defined(NINLIL_WIFI_RX_STREAM_SINGLE_RECORD)
#define NINLIL_WIFI_RX_STREAM_BUF_BYTES NINLIL_WIFI_NWB1_TOTAL_MAX
#else
#define NINLIL_WIFI_RX_STREAM_BUF_BYTES (NINLIL_WIFI_NWB1_TOTAL_MAX * 2u)
#endif
#endif

typedef struct ninlil_wifi_rx_stream {
    uint8_t buf[NINLIL_WIFI_RX_STREAM_BUF_BYTES];
    size_t used;
    size_t pending_record_len; /* >0 => record at buf[0] must be consumed next */
    uint8_t session_id[16];
    int has_session;
    uint32_t expected_sequence;
    int has_expected_sequence;
} ninlil_wifi_rx_stream_t;

void ninlil_wifi_rx_stream_init(ninlil_wifi_rx_stream_t *stream);
void ninlil_wifi_rx_stream_set_session(
    ninlil_wifi_rx_stream_t *stream,
    const uint8_t session_id[16],
    uint32_t next_sequence);

/*
 * Feed raw TLS/TCP bytes. On complete record: NINLIL_WIFI_OK and fills
 * record_view/len. On need more: WOULD_BLOCK. On corrupt framing: CORRUPT
 * and stream is drained of the bad prefix when possible.
 */
ninlil_wifi_status_t ninlil_wifi_rx_stream_feed(
    ninlil_wifi_rx_stream_t *stream,
    const uint8_t *chunk,
    size_t chunk_len,
    const uint8_t **record_out,
    size_t *record_len_out,
    uint32_t *sequence_out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_STREAM_H */
