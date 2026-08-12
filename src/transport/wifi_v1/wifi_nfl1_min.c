/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_nfl1_min.h"

#include <string.h>

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

ninlil_wifi_status_t ninlil_wifi_nfl1_min_encode(
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    uint32_t marker)
{
    const uint32_t total = 587u;
    uint32_t crc;
    if (out == NULL || out_len == NULL || out_cap < total) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, total);
    out[0] = (uint8_t)'N';
    out[1] = (uint8_t)'F';
    out[2] = (uint8_t)'L';
    out[3] = (uint8_t)'1';
    wr16(out + 4, 1u);
    wr16(out + 6, 584u);
    wr32(out + 8, total);
    /* CRC field zero for computation */
    wr32(out + 12, 0u);
    /* ns/svc/schema lens 0; payload 3; evidence 0 at end of header */
    wr16(out + 570, 0u);
    wr16(out + 572, 0u);
    wr16(out + 574, 0u);
    wr32(out + 576, 3u);
    wr32(out + 580, 0u);
    /* 3-byte payload carries marker low bytes */
    out[584] = (uint8_t)(marker >> 16);
    out[585] = (uint8_t)(marker >> 8);
    out[586] = (uint8_t)marker;
    crc = ninlil_wifi_crc32c(out, total);
    wr32(out + 12, crc);
    if (!ninlil_wifi_nfl1_structural_ok(out, total)) {
        return NINLIL_WIFI_CORRUPT;
    }
    *out_len = total;
    return NINLIL_WIFI_OK;
}
