#include "ncl1_codec.h"

#include <string.h>

/*
 * U4 NCL1 pure codec. Portable C11. No heap / no VLA / no platform headers.
 *
 * Decode implements §8.1 steps 2–5 only (header/type/binding/body layout).
 * Reserved (step 7) is checked by ninlil_ncl1_check_reserved after step 6
 * semantic fields are applied by the session layer — pure decode must not
 * reject reserved before body layout completes.
 */

_Static_assert(
    NINLIL_NCL1_HEADER_BYTES == 26u, "NCL1 header must be exact 26");
_Static_assert(
    NINLIL_NCL1_MAX_BODY_BYTES == 998u, "NCL1 max body must be 998");
_Static_assert(
    NINLIL_NCL1_MAX_MESSAGE_BYTES == 1024u, "NCL1 max message must be 1024");
_Static_assert(
    (uint32_t)NINLIL_NCL1_HEADER_BYTES + (uint32_t)NINLIL_NCL1_MAX_BODY_BYTES
        == (uint32_t)NINLIL_NCL1_MAX_MESSAGE_BYTES,
    "header+body budget drift");

static void encode_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)((value >> 8) & 0xffu);
    out[1] = (uint8_t)(value & 0xffu);
}

static void encode_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

static void encode_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)((value >> 56) & 0xffu);
    out[1] = (uint8_t)((value >> 48) & 0xffu);
    out[2] = (uint8_t)((value >> 40) & 0xffu);
    out[3] = (uint8_t)((value >> 32) & 0xffu);
    out[4] = (uint8_t)((value >> 24) & 0xffu);
    out[5] = (uint8_t)((value >> 16) & 0xffu);
    out[6] = (uint8_t)((value >> 8) & 0xffu);
    out[7] = (uint8_t)(value & 0xffu);
}

static uint16_t decode_u16_be(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t decode_u32_be(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint64_t decode_u64_be(const uint8_t *bytes)
{
    return ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48)
        | ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32)
        | ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16)
        | ((uint64_t)bytes[6] << 8) | (uint64_t)bytes[7];
}

uint16_t ninlil_ncl1_exact_body_length(uint8_t message_type)
{
    switch (message_type) {
    case NINLIL_NCL1_MSG_HELLO:
        return NINLIL_NCL1_BODY_HELLO_BYTES;
    case NINLIL_NCL1_MSG_HELLO_ACK:
        return NINLIL_NCL1_BODY_HELLO_ACK_BYTES;
    case NINLIL_NCL1_MSG_CTRL_ERROR:
        return NINLIL_NCL1_BODY_CTRL_ERROR_BYTES;
    case NINLIL_NCL1_MSG_PING_BODY:
        return NINLIL_NCL1_BODY_PING_BYTES;
    case NINLIL_NCL1_MSG_PONG_BODY:
        return NINLIL_NCL1_BODY_PONG_BYTES;
    case NINLIL_NCL1_MSG_RESET_BODY:
        return NINLIL_NCL1_BODY_RESET_BYTES;
    default:
        return 0u;
    }
}

int ninlil_ncl1_message_type_is_known(uint8_t message_type)
{
    return ninlil_ncl1_exact_body_length(message_type) != 0u;
}

uint8_t ninlil_ncl1_required_ncg1_type(uint8_t message_type)
{
    switch (message_type) {
    case NINLIL_NCL1_MSG_HELLO:
    case NINLIL_NCL1_MSG_HELLO_ACK:
    case NINLIL_NCL1_MSG_CTRL_ERROR:
        return NINLIL_NCL1_NCG1_TYPE_DATA;
    case NINLIL_NCL1_MSG_PING_BODY:
        return NINLIL_NCL1_NCG1_TYPE_PING;
    case NINLIL_NCL1_MSG_PONG_BODY:
        return NINLIL_NCL1_NCG1_TYPE_PONG;
    case NINLIL_NCL1_MSG_RESET_BODY:
        return NINLIL_NCL1_NCG1_TYPE_RESET;
    default:
        return 0u;
    }
}

int ninlil_ncl1_type_binding_ok(uint8_t ncg1_type, uint8_t ncl1_message_type)
{
    uint8_t required = ninlil_ncl1_required_ncg1_type(ncl1_message_type);
    if (required == 0u) {
        return 0;
    }
    return ncg1_type == required;
}

int ninlil_ncl1_error_code_is_closed(uint16_t error_code)
{
    return error_code >= NINLIL_NCL1_ERR_INVALID_NCL1
        && error_code <= NINLIL_NCL1_ERR_TYPE_BINDING;
}

int ninlil_ncl1_reset_code_is_closed(uint8_t reset_code)
{
    return reset_code == NINLIL_NCL1_RESET_SESSION
        || reset_code == NINLIL_NCL1_RESET_PARSER
        || reset_code == NINLIL_NCL1_RESET_LINK;
}

/*
 * §8.1 step 7: reserved fields exact 0. Called after step 6 by session.
 */
ninlil_ncl1_status_t ninlil_ncl1_check_reserved(const ninlil_ncl1_message_t *msg)
{
    if (msg == NULL) {
        return NINLIL_NCL1_INVALID_ARGUMENT;
    }
    switch (msg->header.message_type) {
    case NINLIL_NCL1_MSG_HELLO:
        if (msg->body.hello.reserved != 0u) {
            return NINLIL_NCL1_REJECT_RESERVED;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_HELLO_ACK:
        if (msg->body.hello_ack.reserved != 0u) {
            return NINLIL_NCL1_REJECT_RESERVED;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_CTRL_ERROR:
        if (msg->body.ctrl_error.reserved != 0u) {
            return NINLIL_NCL1_REJECT_RESERVED;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_RESET_BODY:
        if (msg->body.reset.reserved0 != 0u || msg->body.reset.reserved1 != 0u
            || msg->body.reset.reserved2 != 0u) {
            return NINLIL_NCL1_REJECT_RESERVED;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_PING_BODY:
    case NINLIL_NCL1_MSG_PONG_BODY:
        return NINLIL_NCL1_OK;
    default:
        return NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE;
    }
}

/* Encode body into scratch; does not check reserved (caller may). */
static ninlil_ncl1_status_t encode_body_layout(
    const ninlil_ncl1_message_t *msg, uint8_t *body_out)
{
    switch (msg->header.message_type) {
    case NINLIL_NCL1_MSG_HELLO:
        if (msg->header.body_length != NINLIL_NCL1_BODY_HELLO_BYTES) {
            return NINLIL_NCL1_REJECT_BODY_LEN;
        }
        if (msg->body.hello.min_control_version
            > msg->body.hello.max_control_version) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        encode_u16_be(body_out + 0, msg->body.hello.min_control_version);
        encode_u16_be(body_out + 2, msg->body.hello.max_control_version);
        encode_u16_be(body_out + 4, msg->body.hello.flags_supported);
        encode_u16_be(body_out + 6, msg->body.hello.reserved);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_HELLO_ACK:
        if (msg->header.body_length != NINLIL_NCL1_BODY_HELLO_ACK_BYTES) {
            return NINLIL_NCL1_REJECT_BODY_LEN;
        }
        if (msg->body.hello_ack.result_code != NINLIL_NCL1_HELLO_OK
            && msg->body.hello_ack.result_code
                != NINLIL_NCL1_HELLO_VERSION_MISMATCH
            && msg->body.hello_ack.result_code != NINLIL_NCL1_HELLO_BUSY
            && msg->body.hello_ack.result_code != NINLIL_NCL1_HELLO_DENIED) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        encode_u16_be(body_out + 0, msg->body.hello_ack.selected_control_version);
        encode_u16_be(body_out + 2, msg->body.hello_ack.flags_selected);
        encode_u16_be(body_out + 4, msg->body.hello_ack.result_code);
        encode_u16_be(body_out + 6, msg->body.hello_ack.reserved);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_CTRL_ERROR:
        if (msg->header.body_length != NINLIL_NCL1_BODY_CTRL_ERROR_BYTES) {
            return NINLIL_NCL1_REJECT_BODY_LEN;
        }
        if (!ninlil_ncl1_error_code_is_closed(msg->body.ctrl_error.error_code)) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        encode_u16_be(body_out + 0, msg->body.ctrl_error.error_code);
        encode_u16_be(body_out + 2, msg->body.ctrl_error.reserved);
        encode_u32_be(body_out + 4, msg->body.ctrl_error.related_request_id);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_PING_BODY:
        if (msg->header.body_length != NINLIL_NCL1_BODY_PING_BYTES) {
            return NINLIL_NCL1_REJECT_BODY_LEN;
        }
        encode_u64_be(body_out, msg->body.ping.opaque_echo_token);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_PONG_BODY:
        if (msg->header.body_length != NINLIL_NCL1_BODY_PONG_BYTES) {
            return NINLIL_NCL1_REJECT_BODY_LEN;
        }
        encode_u64_be(body_out, msg->body.pong.opaque_echo_token);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_RESET_BODY:
        if (msg->header.body_length != NINLIL_NCL1_BODY_RESET_BYTES) {
            return NINLIL_NCL1_REJECT_BODY_LEN;
        }
        if (!ninlil_ncl1_reset_code_is_closed(msg->body.reset.reset_code)) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        body_out[0] = msg->body.reset.reset_code;
        body_out[1] = msg->body.reset.reserved0;
        body_out[2] = msg->body.reset.reserved1;
        body_out[3] = msg->body.reset.reserved2;
        return NINLIL_NCL1_OK;
    default:
        return NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE;
    }
}

/* §8.1 step 5 body layout only — does not reject reserved. */
static ninlil_ncl1_status_t decode_body_layout(
    uint8_t message_type, const uint8_t *body, uint16_t body_len,
    ninlil_ncl1_message_t *out_msg)
{
    uint16_t exact = ninlil_ncl1_exact_body_length(message_type);
    if (exact == 0u) {
        return NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE;
    }
    if (body_len != exact) {
        return NINLIL_NCL1_REJECT_BODY_LAYOUT;
    }
    switch (message_type) {
    case NINLIL_NCL1_MSG_HELLO:
        out_msg->body.hello.min_control_version = decode_u16_be(body + 0);
        out_msg->body.hello.max_control_version = decode_u16_be(body + 2);
        out_msg->body.hello.flags_supported = decode_u16_be(body + 4);
        out_msg->body.hello.reserved = decode_u16_be(body + 6);
        if (out_msg->body.hello.min_control_version
            > out_msg->body.hello.max_control_version) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_HELLO_ACK:
        out_msg->body.hello_ack.selected_control_version =
            decode_u16_be(body + 0);
        out_msg->body.hello_ack.flags_selected = decode_u16_be(body + 2);
        out_msg->body.hello_ack.result_code = decode_u16_be(body + 4);
        out_msg->body.hello_ack.reserved = decode_u16_be(body + 6);
        if (out_msg->body.hello_ack.result_code != NINLIL_NCL1_HELLO_OK
            && out_msg->body.hello_ack.result_code
                != NINLIL_NCL1_HELLO_VERSION_MISMATCH
            && out_msg->body.hello_ack.result_code != NINLIL_NCL1_HELLO_BUSY
            && out_msg->body.hello_ack.result_code
                != NINLIL_NCL1_HELLO_DENIED) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_CTRL_ERROR:
        out_msg->body.ctrl_error.error_code = decode_u16_be(body + 0);
        out_msg->body.ctrl_error.reserved = decode_u16_be(body + 2);
        out_msg->body.ctrl_error.related_request_id = decode_u32_be(body + 4);
        if (!ninlil_ncl1_error_code_is_closed(
                out_msg->body.ctrl_error.error_code)) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_PING_BODY:
        out_msg->body.ping.opaque_echo_token = decode_u64_be(body);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_PONG_BODY:
        out_msg->body.pong.opaque_echo_token = decode_u64_be(body);
        return NINLIL_NCL1_OK;
    case NINLIL_NCL1_MSG_RESET_BODY:
        out_msg->body.reset.reset_code = body[0];
        out_msg->body.reset.reserved0 = body[1];
        out_msg->body.reset.reserved1 = body[2];
        out_msg->body.reset.reserved2 = body[3];
        if (!ninlil_ncl1_reset_code_is_closed(body[0])) {
            return NINLIL_NCL1_REJECT_BODY_LAYOUT;
        }
        return NINLIL_NCL1_OK;
    default:
        return NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE;
    }
}

ninlil_ncl1_status_t ninlil_ncl1_encode(
    const ninlil_ncl1_message_t *msg,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len)
{
    size_t total;
    ninlil_ncl1_status_t st;
    uint8_t scratch[NINLIL_NCL1_MAX_MESSAGE_BYTES];

    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (msg == NULL || out_buf == NULL || out_len == NULL) {
        return NINLIL_NCL1_INVALID_ARGUMENT;
    }
    if (msg->header.logical_version != NINLIL_NCL1_LOGICAL_VERSION) {
        return NINLIL_NCL1_REJECT_VERSION;
    }
    if (msg->header.flags != 0u) {
        return NINLIL_NCL1_REJECT_FLAGS;
    }
    if (msg->header.body_length > NINLIL_NCL1_MAX_BODY_BYTES) {
        return NINLIL_NCL1_REJECT_BODY_LEN;
    }
    if (!ninlil_ncl1_message_type_is_known(msg->header.message_type)) {
        return NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE;
    }
    /* Production encode requires reserved exact 0 (never emit illegal wire). */
    st = ninlil_ncl1_check_reserved(msg);
    if (st != NINLIL_NCL1_OK) {
        return st;
    }
    total = (size_t)NINLIL_NCL1_HEADER_BYTES + (size_t)msg->header.body_length;
    if (out_cap < total) {
        return NINLIL_NCL1_BUFFER_TOO_SMALL;
    }

    /* Fully encode into scratch first — out_buf unchanged on failure. */
    (void)memset(scratch, 0, total);
    scratch[0] = NINLIL_NCL1_MAGIC0;
    scratch[1] = NINLIL_NCL1_MAGIC1;
    scratch[2] = NINLIL_NCL1_MAGIC2;
    scratch[3] = NINLIL_NCL1_MAGIC3;
    scratch[4] = msg->header.logical_version;
    scratch[5] = msg->header.message_type;
    encode_u16_be(scratch + 6, msg->header.flags);
    encode_u32_be(scratch + 8, msg->header.request_id);
    encode_u32_be(scratch + 12, msg->header.session_generation);
    encode_u64_be(scratch + 16, msg->header.session_cookie);
    encode_u16_be(scratch + 24, msg->header.body_length);

    st = encode_body_layout(msg, scratch + NINLIL_NCL1_HEADER_BYTES);
    if (st != NINLIL_NCL1_OK) {
        return st;
    }

    (void)memcpy(out_buf, scratch, total);
    *out_len = total;
    return NINLIL_NCL1_OK;
}

ninlil_ncl1_status_t ninlil_ncl1_peek_header(
    const uint8_t *payload,
    size_t payload_len,
    ninlil_ncl1_header_t *out_header)
{
    uint16_t body_len;
    size_t need;

    if (out_header != NULL) {
        (void)memset(out_header, 0, sizeof(*out_header));
    }
    if (payload == NULL || out_header == NULL) {
        return NINLIL_NCL1_INVALID_ARGUMENT;
    }
    if (payload_len < (size_t)NINLIL_NCL1_HEADER_BYTES) {
        return NINLIL_NCL1_REJECT_SHORT;
    }
    if (payload[0] != NINLIL_NCL1_MAGIC0 || payload[1] != NINLIL_NCL1_MAGIC1
        || payload[2] != NINLIL_NCL1_MAGIC2
        || payload[3] != NINLIL_NCL1_MAGIC3) {
        return NINLIL_NCL1_REJECT_MAGIC;
    }
    if (payload[4] != NINLIL_NCL1_LOGICAL_VERSION) {
        return NINLIL_NCL1_REJECT_VERSION;
    }
    if (decode_u16_be(payload + 6) != 0u) {
        return NINLIL_NCL1_REJECT_FLAGS;
    }
    body_len = decode_u16_be(payload + 24);
    if (body_len > NINLIL_NCL1_MAX_BODY_BYTES) {
        return NINLIL_NCL1_REJECT_BODY_LEN;
    }
    need = (size_t)NINLIL_NCL1_HEADER_BYTES + (size_t)body_len;
    if (payload_len != need) {
        return NINLIL_NCL1_REJECT_BODY_LEN;
    }
    out_header->logical_version = payload[4];
    out_header->message_type = payload[5];
    out_header->flags = 0u;
    out_header->request_id = decode_u32_be(payload + 8);
    out_header->session_generation = decode_u32_be(payload + 12);
    out_header->session_cookie = decode_u64_be(payload + 16);
    out_header->body_length = body_len;
    return NINLIL_NCL1_OK;
}

ninlil_ncl1_status_t ninlil_ncl1_decode(
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ncg1_type,
    ninlil_ncl1_message_t *out_msg)
{
    ninlil_ncl1_status_t st;
    ninlil_ncl1_header_t hdr;

    if (out_msg != NULL) {
        (void)memset(out_msg, 0, sizeof(*out_msg));
    }
    if (payload == NULL || out_msg == NULL) {
        return NINLIL_NCL1_INVALID_ARGUMENT;
    }

    /* §8.1 steps 2–3 (partial): header + known type */
    st = ninlil_ncl1_peek_header(payload, payload_len, &hdr);
    if (st != NINLIL_NCL1_OK) {
        return st;
    }
    if (!ninlil_ncl1_message_type_is_known(hdr.message_type)) {
        return NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE;
    }
    /* step 4 binding */
    if (ncg1_type != 0u
        && !ninlil_ncl1_type_binding_ok(ncg1_type, hdr.message_type)) {
        return NINLIL_NCL1_REJECT_TYPE_BINDING;
    }

    out_msg->header = hdr;
    /* step 5 body layout only — reserved NOT rejected here */
    return decode_body_layout(
        hdr.message_type,
        payload + NINLIL_NCL1_HEADER_BYTES,
        hdr.body_length,
        out_msg);
}

/*
 * Valid HELLO bootstrap for SBR / half-open / BOOTSTRAP_EPOCH_RESTART.
 * U4 exact: min=max=1, flags_supported=0, reserved=0, gen=0, cookie=0,
 * request_id≠0. Invalid HELLO must not pass SBR/bootstrap peeks.
 */
int ninlil_ncl1_is_valid_hello_bootstrap(const ninlil_ncl1_message_t *msg)
{
    if (msg == NULL) {
        return 0;
    }
    if (msg->header.message_type != NINLIL_NCL1_MSG_HELLO) {
        return 0;
    }
    if (msg->header.logical_version != NINLIL_NCL1_LOGICAL_VERSION) {
        return 0;
    }
    if (msg->header.flags != 0u) {
        return 0;
    }
    if (msg->header.session_generation != 0u || msg->header.session_cookie != 0u) {
        return 0;
    }
    if (msg->header.request_id == 0u) {
        return 0;
    }
    if (msg->header.body_length != NINLIL_NCL1_BODY_HELLO_BYTES) {
        return 0;
    }
    /* U4 exact control versions and flags */
    if (msg->body.hello.min_control_version != NINLIL_NCL1_CONTROL_VERSION_V1
        || msg->body.hello.max_control_version != NINLIL_NCL1_CONTROL_VERSION_V1) {
        return 0;
    }
    if (msg->body.hello.flags_supported != 0u) {
        return 0;
    }
    if (msg->body.hello.reserved != 0u) {
        return 0;
    }
    return 1;
}

/*
 * Structural HELLO_ACK (layout + OK/error header conventions + U4 flags).
 * OK: selected_control_version==1, flags_selected==0, gen≠0, cookie≠0.
 * error: gen=0, cookie=0, flags_selected==0, reserved==0.
 */
int ninlil_ncl1_is_structurally_valid_hello_ack(const ninlil_ncl1_message_t *msg)
{
    if (msg == NULL) {
        return 0;
    }
    if (msg->header.message_type != NINLIL_NCL1_MSG_HELLO_ACK) {
        return 0;
    }
    if (msg->header.logical_version != NINLIL_NCL1_LOGICAL_VERSION) {
        return 0;
    }
    if (msg->header.flags != 0u || msg->header.request_id == 0u) {
        return 0;
    }
    if (msg->header.body_length != NINLIL_NCL1_BODY_HELLO_ACK_BYTES) {
        return 0;
    }
    if (msg->body.hello_ack.flags_selected != 0u) {
        return 0;
    }
    if (msg->body.hello_ack.reserved != 0u) {
        return 0;
    }
    if (msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_OK) {
        if (msg->header.session_generation == 0u
            || msg->header.session_cookie == 0u) {
            return 0;
        }
        /* U4: selected version must be 1 */
        if (msg->body.hello_ack.selected_control_version
            != NINLIL_NCL1_CONTROL_VERSION_V1) {
            return 0;
        }
    } else if (
        msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_VERSION_MISMATCH
        || msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_BUSY
        || msg->body.hello_ack.result_code == NINLIL_NCL1_HELLO_DENIED) {
        if (msg->header.session_generation != 0u
            || msg->header.session_cookie != 0u) {
            return 0;
        }
    } else {
        return 0;
    }
    return 1;
}
