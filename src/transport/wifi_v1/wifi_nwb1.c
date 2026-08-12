/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_nwb1.h"

#include <string.h>

static uint16_t wifi_rd_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t wifi_rd_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

static void wifi_wr_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wifi_wr_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

uint32_t ninlil_wifi_crc32c(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    unsigned bit;
    if (data == NULL && length != 0u) {
        return 0u;
    }
    for (i = 0u; i < length; ++i) {
        crc ^= (uint32_t)data[i];
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1)
                ^ ((crc & 1u) != 0u ? 0x82f63b78u : 0u);
        }
    }
    return crc ^ 0xffffffffu;
}

int ninlil_wifi_nfl1_structural_ok(const uint8_t *packet, size_t length)
{
    uint8_t scratch[1925];
    uint16_t version;
    uint16_t header_length;
    uint32_t total_length;
    uint32_t stored_crc;
    uint16_t ns_len;
    uint16_t svc_len;
    uint16_t schema_len;
    uint32_t payload_len;
    uint32_t evidence_len;
    size_t i;

    if (packet == NULL || length < NINLIL_WIFI_NFL1_HEADER_BYTES || length > 1925u) {
        return 0;
    }
    if (packet[0] != (uint8_t)'N' || packet[1] != (uint8_t)'F'
        || packet[2] != (uint8_t)'L' || packet[3] != (uint8_t)'1') {
        return 0;
    }
    version = wifi_rd_u16(packet + 4);
    header_length = wifi_rd_u16(packet + 6);
    total_length = wifi_rd_u32(packet + 8);
    stored_crc = wifi_rd_u32(packet + 12);
    if (header_length != NINLIL_WIFI_NFL1_HEADER_BYTES
        || total_length != (uint32_t)length) {
        return 0;
    }
    if (total_length < 587u || total_length > 1925u || version != 1u) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        scratch[i] = packet[i];
    }
    scratch[12] = 0u;
    scratch[13] = 0u;
    scratch[14] = 0u;
    scratch[15] = 0u;
    if (ninlil_wifi_crc32c(scratch, length) != stored_crc) {
        return 0;
    }
    ns_len = wifi_rd_u16(packet + 570);
    svc_len = wifi_rd_u16(packet + 572);
    schema_len = wifi_rd_u16(packet + 574);
    payload_len = wifi_rd_u32(packet + 576);
    evidence_len = wifi_rd_u32(packet + 580);
    if (ns_len > 63u || svc_len > 63u || schema_len > 63u) {
        return 0;
    }
    if (NINLIL_WIFI_NFL1_HEADER_BYTES + (uint32_t)ns_len + (uint32_t)svc_len
            + (uint32_t)schema_len + payload_len + evidence_len
        != total_length) {
        return 0;
    }
    if ((wifi_rd_u32(packet + 20) & 0xffff0000u) != 0u) {
        return 0;
    }
    return 1;
}

ninlil_wifi_status_t ninlil_wifi_nwb1_encode(
    const uint8_t session_id[16],
    uint32_t sequence,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    size_t total;
    uint32_t crc;
    size_t i;

    if (session_id == NULL || payload == NULL || out == NULL || out_len == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    {
        size_t zi;
        int all_zero = 1;
        for (zi = 0u; zi < 16u; ++zi) {
            if (session_id[zi] != 0u) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            return NINLIL_WIFI_WRONG_SESSION;
        }
    }
    if (payload_len < NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || payload_len > NINLIL_WIFI_NWB1_PAYLOAD_MAX) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (sequence == 0xffffffffu) {
        return NINLIL_WIFI_SEQUENCE_REJECT;
    }
    if (!ninlil_wifi_nfl1_structural_ok(payload, payload_len)) {
        return NINLIL_WIFI_CORRUPT;
    }
    total = (size_t)NINLIL_WIFI_NWB1_HEADER_BYTES + (size_t)payload_len;
    if (out_cap < total) {
        return NINLIL_WIFI_CAPACITY;
    }
    out[0] = NINLIL_WIFI_NWB1_MAGIC_0;
    out[1] = NINLIL_WIFI_NWB1_MAGIC_1;
    out[2] = NINLIL_WIFI_NWB1_MAGIC_2;
    out[3] = NINLIL_WIFI_NWB1_MAGIC_3;
    wifi_wr_u16(out + 4, NINLIL_WIFI_NWB1_VERSION);
    wifi_wr_u16(out + 6, (uint16_t)NINLIL_WIFI_NWB1_HEADER_BYTES);
    wifi_wr_u32(out + 8, (uint32_t)total);
    wifi_wr_u32(out + 12, payload_len);
    for (i = 0u; i < 16u; ++i) {
        out[16u + i] = session_id[i];
    }
    wifi_wr_u32(out + 32, sequence);
    out[36] = 0u;
    out[37] = 0u;
    out[38] = 0u;
    out[39] = 0u;
    (void)memcpy(out + NINLIL_WIFI_NWB1_HEADER_BYTES, payload, payload_len);
    crc = ninlil_wifi_crc32c(out, total);
    wifi_wr_u32(out + 36, crc);
    *out_len = total;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_nwb1_classify(
    const uint8_t *record,
    size_t length,
    const uint8_t *expected_session_or_null,
    int has_expected_sequence,
    uint32_t expected_sequence,
    const uint8_t **payload_out,
    uint32_t *payload_len_out,
    uint32_t *sequence_out)
{
    uint8_t scratch[NINLIL_WIFI_NWB1_TOTAL_MAX];
    uint16_t version;
    uint16_t header_length;
    uint32_t total_length;
    uint32_t payload_length;
    uint32_t sequence;
    uint32_t stored_crc;
    size_t i;
    int any = 0;

    if (record == NULL || length == 0u) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (length < NINLIL_WIFI_NWB1_HEADER_BYTES) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (record[0] != NINLIL_WIFI_NWB1_MAGIC_0 || record[1] != NINLIL_WIFI_NWB1_MAGIC_1
        || record[2] != NINLIL_WIFI_NWB1_MAGIC_2
        || record[3] != NINLIL_WIFI_NWB1_MAGIC_3) {
        return NINLIL_WIFI_CORRUPT;
    }
    version = wifi_rd_u16(record + 4);
    header_length = wifi_rd_u16(record + 6);
    total_length = wifi_rd_u32(record + 8);
    payload_length = wifi_rd_u32(record + 12);
    sequence = wifi_rd_u32(record + 32);
    stored_crc = wifi_rd_u32(record + 36);
    if (header_length != NINLIL_WIFI_NWB1_HEADER_BYTES) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (total_length != (uint32_t)length
        || payload_length != (uint32_t)length - NINLIL_WIFI_NWB1_HEADER_BYTES) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (payload_length < NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || payload_length > NINLIL_WIFI_NWB1_PAYLOAD_MAX
        || total_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || total_length > NINLIL_WIFI_NWB1_TOTAL_MAX) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (length > sizeof(scratch)) {
        return NINLIL_WIFI_CORRUPT;
    }
    for (i = 0u; i < length; ++i) {
        scratch[i] = record[i];
    }
    scratch[36] = 0u;
    scratch[37] = 0u;
    scratch[38] = 0u;
    scratch[39] = 0u;
    if (ninlil_wifi_crc32c(scratch, length) != stored_crc) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (version > 1u) {
        return NINLIL_WIFI_UNSUPPORTED;
    }
    if (version != 1u) {
        return NINLIL_WIFI_CORRUPT;
    }
    for (i = 0u; i < 16u; ++i) {
        if (record[16u + i] != 0u) {
            any = 1;
            break;
        }
    }
    if (!any) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (expected_session_or_null != NULL
        && memcmp(record + 16, expected_session_or_null, 16u) != 0) {
        return NINLIL_WIFI_WRONG_SESSION;
    }
    if (sequence == 0xffffffffu) {
        return NINLIL_WIFI_SEQUENCE_REJECT;
    }
    if (has_expected_sequence && sequence != expected_sequence) {
        return NINLIL_WIFI_SEQUENCE_REJECT;
    }
    if (!ninlil_wifi_nfl1_structural_ok(
            record + NINLIL_WIFI_NWB1_HEADER_BYTES, payload_length)) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (payload_out != NULL) {
        *payload_out = record + NINLIL_WIFI_NWB1_HEADER_BYTES;
    }
    if (payload_len_out != NULL) {
        *payload_len_out = payload_length;
    }
    if (sequence_out != NULL) {
        *sequence_out = sequence;
    }
    return NINLIL_WIFI_OK;
}
