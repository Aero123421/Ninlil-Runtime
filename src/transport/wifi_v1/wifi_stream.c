/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_stream.h"

#include <string.h>

static uint32_t wifi_rd_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

void ninlil_wifi_rx_stream_init(ninlil_wifi_rx_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }
    (void)memset(stream, 0, sizeof(*stream));
}

void ninlil_wifi_rx_stream_set_session(
    ninlil_wifi_rx_stream_t *stream,
    const uint8_t session_id[16],
    uint32_t next_sequence)
{
    size_t i;
    if (stream == NULL || session_id == NULL) {
        return;
    }
    for (i = 0u; i < 16u; ++i) {
        stream->session_id[i] = session_id[i];
    }
    stream->has_session = 1;
    stream->expected_sequence = next_sequence;
    stream->has_expected_sequence = 1;
    stream->used = 0u;
    stream->pending_record_len = 0u;
}

ninlil_wifi_status_t ninlil_wifi_rx_stream_feed(
    ninlil_wifi_rx_stream_t *stream,
    const uint8_t *chunk,
    size_t chunk_len,
    const uint8_t **record_out,
    size_t *record_len_out,
    uint32_t *sequence_out)
{
    uint32_t total_length;
    ninlil_wifi_status_t st;
    uint32_t sequence = 0u;

    if (stream == NULL || (chunk == NULL && chunk_len != 0u) || record_out == NULL
        || record_len_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *record_out = NULL;
    *record_len_out = 0u;

    /* Consume previous delivered record before accepting new bytes. */
    if (stream->pending_record_len > 0u) {
        size_t drop = stream->pending_record_len;
        if (stream->used > drop) {
            size_t rem = stream->used - drop;
            (void)memmove(stream->buf, stream->buf + drop, rem);
            stream->used = rem;
        } else {
            stream->used = 0u;
        }
        stream->pending_record_len = 0u;
    }

    if (chunk_len > 0u) {
        if (stream->used > sizeof(stream->buf)
            || chunk_len > sizeof(stream->buf) - stream->used) {
            stream->used = 0u;
            stream->pending_record_len = 0u;
            return NINLIL_WIFI_CAPACITY;
        }
        (void)memcpy(stream->buf + stream->used, chunk, chunk_len);
        stream->used += chunk_len;
    }

    if (stream->used < NINLIL_WIFI_NWB1_HEADER_BYTES) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    total_length = wifi_rd_u32(stream->buf + 8);
    if (total_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || total_length > NINLIL_WIFI_NWB1_TOTAL_MAX) {
        stream->used = 0u;
        return NINLIL_WIFI_CORRUPT;
    }
    if (stream->used < (size_t)total_length) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }

    st = ninlil_wifi_nwb1_classify(
        stream->buf,
        (size_t)total_length,
        stream->has_session ? stream->session_id : NULL,
        stream->has_expected_sequence,
        stream->expected_sequence,
        NULL,
        NULL,
        &sequence);
    if (st != NINLIL_WIFI_OK) {
        stream->used = 0u;
        stream->pending_record_len = 0u;
        return st;
    }

    *record_out = stream->buf;
    *record_len_out = (size_t)total_length;
    stream->pending_record_len = (size_t)total_length;
    if (sequence_out != NULL) {
        *sequence_out = sequence;
    }
    if (stream->has_expected_sequence) {
        stream->expected_sequence = sequence + 1u;
    }
    return NINLIL_WIFI_OK;
}
