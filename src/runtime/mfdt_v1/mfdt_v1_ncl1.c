/* SPDX-License-Identifier: Apache-2.0
 * Private NCL1 framing for MFN1 0x34..0x35 and MFDT 0x36..0x43 over NCG1
 * DATA.
 */
#include "mfdt_v1_ncl1.h"

#include <string.h>

int ninlil_mfdt_v1_ncl1_is_transfer_type(uint8_t message_type)
{
    return message_type >= 0x36u && message_type <= 0x43u;
}

int ninlil_mfdt_v1_ncl1_is_mfdt_type(uint8_t message_type)
{
    return message_type == 0x34u || message_type == 0x35u ||
           ninlil_mfdt_v1_ncl1_is_transfer_type(message_type);
}

int ninlil_mfdt_v1_ncl1_binding_ok(uint8_t ncg1_type, uint8_t mfdt_type)
{
    if (!ninlil_mfdt_v1_ncl1_is_mfdt_type(mfdt_type)) {
        return 0;
    }
    return ncg1_type == 0u || ncg1_type == NINLIL_MFDT_V1_NCG1_DATA;
}

int ninlil_mfdt_v1_ncl1_encode(
    uint8_t mfdt_message_type, uint32_t request_id, uint32_t session_generation,
    uint64_t session_cookie, const uint8_t *mfdt_body, uint16_t body_len,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t total;
    if (out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!ninlil_mfdt_v1_ncl1_is_mfdt_type(mfdt_message_type)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (body_len == 0u || body_len > NINLIL_MFDT_V1_NCL1_MAX_BODY) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (mfdt_body == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (request_id == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM; /* MFDT requests non-zero request_id */
    }
    total = (size_t)NINLIL_MFDT_V1_NCL1_HEADER_BYTES + (size_t)body_len;
    if (total > out_cap || total > NINLIL_MFDT_V1_NCL1_MAX_MSG) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    out[0] = (uint8_t)'N';
    out[1] = (uint8_t)'C';
    out[2] = (uint8_t)'L';
    out[3] = (uint8_t)'1';
    out[4] = NINLIL_MFDT_V1_NCL1_LOGICAL_VER;
    out[5] = mfdt_message_type;
    ninlil_mfdt_v1_put_u16(out + 6, 0u); /* flags */
    ninlil_mfdt_v1_put_u32(out + 8, request_id);
    ninlil_mfdt_v1_put_u32(out + 12, session_generation);
    ninlil_mfdt_v1_put_u64(out + 16, session_cookie);
    ninlil_mfdt_v1_put_u16(out + 24, body_len);
    (void)memcpy(out + 26, mfdt_body, body_len);
    *out_len = total;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_ncl1_decode(
    const uint8_t *payload, size_t payload_len, uint8_t ncg1_type,
    uint8_t *mfdt_type, uint32_t *request_id, uint32_t *session_generation,
    uint64_t *session_cookie, const uint8_t **body, uint16_t *body_len)
{
    uint16_t blen;
    uint16_t flags;
    if (payload == NULL || mfdt_type == NULL || request_id == NULL ||
        session_generation == NULL || session_cookie == NULL || body == NULL ||
        body_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (payload_len < NINLIL_MFDT_V1_NCL1_HEADER_BYTES) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (payload[0] != (uint8_t)'N' || payload[1] != (uint8_t)'C' ||
        payload[2] != (uint8_t)'L' || payload[3] != (uint8_t)'1') {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (payload[4] != NINLIL_MFDT_V1_NCL1_LOGICAL_VER) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    *mfdt_type = payload[5];
    if (!ninlil_mfdt_v1_ncl1_is_mfdt_type(*mfdt_type)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (!ninlil_mfdt_v1_ncl1_binding_ok(ncg1_type, *mfdt_type)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    flags = ninlil_mfdt_v1_get_u16(payload + 6);
    if (flags != 0u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    *request_id = ninlil_mfdt_v1_get_u32(payload + 8);
    *session_generation = ninlil_mfdt_v1_get_u32(payload + 12);
    *session_cookie = ninlil_mfdt_v1_get_u64(payload + 16);
    blen = ninlil_mfdt_v1_get_u16(payload + 24);
    if (blen == 0u || blen > NINLIL_MFDT_V1_NCL1_MAX_BODY) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (payload_len != (size_t)NINLIL_MFDT_V1_NCL1_HEADER_BYTES + (size_t)blen) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (*request_id == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    *body = payload + 26;
    *body_len = blen;
    return NINLIL_MFDT_V1_OK;
}
