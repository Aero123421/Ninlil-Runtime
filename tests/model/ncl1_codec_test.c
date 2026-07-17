/*
 * U4 NCL1 pure codec host tests.
 * §8.1 steps 2–5; reserved is NOT rejected by pure decode.
 * Does not claim U4 series complete / HIL / assignment.
 */

#include "ncl1_codec.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "%s:%d: fail: %s\n", __FILE__, __LINE__,     \
                #cond);                                                        \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_hello_roundtrip_u4_exact(void)
{
    ninlil_ncl1_message_t msg;
    ninlil_ncl1_message_t out;
    uint8_t buf[64];
    size_t len = 0u;
    uint8_t poison[64];

    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = NINLIL_NCL1_LOGICAL_VERSION;
    msg.header.message_type = NINLIL_NCL1_MSG_HELLO;
    msg.header.request_id = 0x1001u;
    msg.header.body_length = NINLIL_NCL1_BODY_HELLO_BYTES;
    msg.body.hello.min_control_version = 1u;
    msg.body.hello.max_control_version = 1u;
    msg.body.hello.flags_supported = 0u;

    REQUIRE(
        ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len) == NINLIL_NCL1_OK);
    REQUIRE(len == 34u);
    REQUIRE(ninlil_ncl1_is_valid_hello_bootstrap(&msg));
    REQUIRE(
        ninlil_ncl1_decode(buf, len, NINLIL_NCL1_NCG1_TYPE_DATA, &out)
        == NINLIL_NCL1_OK);
    REQUIRE(out.body.hello.min_control_version == 1u);
    REQUIRE(out.body.hello.max_control_version == 1u);
    REQUIRE(out.body.hello.flags_supported == 0u);

    /* Encode failure must not leave partial mutation. */
    (void)memset(poison, 0xA5, sizeof(poison));
    msg.header.flags = 1u;
    REQUIRE(
        ninlil_ncl1_encode(&msg, poison, sizeof(poison), &len)
        == NINLIL_NCL1_REJECT_FLAGS);
    REQUIRE(poison[0] == 0xA5);
    REQUIRE(poison[1] == 0xA5);
    return 0;
}

static int test_reserved_not_in_pure_decode(void)
{
    ninlil_ncl1_message_t msg;
    ninlil_ncl1_message_t out;
    uint8_t buf[64];
    size_t len = 0u;

    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = NINLIL_NCL1_LOGICAL_VERSION;
    msg.header.message_type = NINLIL_NCL1_MSG_HELLO;
    msg.header.request_id = 1u;
    msg.header.body_length = 8u;
    msg.body.hello.min_control_version = 1u;
    msg.body.hello.max_control_version = 1u;
    msg.body.hello.reserved = 1u;

    /* Encode rejects reserved (production never emits illegal reserved). */
    REQUIRE(
        ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len)
        == NINLIL_NCL1_REJECT_RESERVED);

    /* Craft wire with reserved=1 via manual layout after encode of clean. */
    msg.body.hello.reserved = 0u;
    REQUIRE(ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len) == NINLIL_NCL1_OK);
    buf[32] = 0u;
    buf[33] = 1u; /* reserved u16 BE = 1 */

    REQUIRE(
        ninlil_ncl1_decode(buf, len, NINLIL_NCL1_NCG1_TYPE_DATA, &out)
        == NINLIL_NCL1_OK);
    REQUIRE(out.body.hello.reserved == 1u);
    REQUIRE(
        ninlil_ncl1_check_reserved(&out) == NINLIL_NCL1_REJECT_RESERVED);
    REQUIRE(!ninlil_ncl1_is_valid_hello_bootstrap(&out));
    return 0;
}

static int test_type_binding(void)
{
    ninlil_ncl1_message_t msg;
    ninlil_ncl1_message_t out;
    uint8_t buf[64];
    size_t len = 0u;

    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = 1u;
    msg.header.message_type = NINLIL_NCL1_MSG_PING_BODY;
    msg.header.request_id = 1u;
    msg.header.session_generation = 1u;
    msg.header.session_cookie = 1u;
    msg.header.body_length = 8u;
    msg.body.ping.opaque_echo_token = 9u;
    REQUIRE(ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len) == NINLIL_NCL1_OK);
    REQUIRE(
        ninlil_ncl1_decode(buf, len, NINLIL_NCL1_NCG1_TYPE_DATA, &out)
        == NINLIL_NCL1_REJECT_TYPE_BINDING);
    REQUIRE(
        ninlil_ncl1_decode(buf, len, NINLIL_NCL1_NCG1_TYPE_PING, &out)
        == NINLIL_NCL1_OK);
    return 0;
}

static int test_ctrl_error_closed(void)
{
    ninlil_ncl1_message_t msg;
    uint8_t buf[64];
    size_t len = 0u;
    uint16_t code;

    for (code = 1u; code <= 7u; ++code) {
        (void)memset(&msg, 0, sizeof(msg));
        msg.header.logical_version = 1u;
        msg.header.message_type = NINLIL_NCL1_MSG_CTRL_ERROR;
        msg.header.body_length = 8u;
        msg.body.ctrl_error.error_code = code;
        REQUIRE(
            ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len) == NINLIL_NCL1_OK);
        REQUIRE(ninlil_ncl1_error_code_is_closed(code));
    }
    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = 1u;
    msg.header.message_type = NINLIL_NCL1_MSG_CTRL_ERROR;
    msg.header.body_length = 8u;
    msg.body.ctrl_error.error_code = 0u;
    REQUIRE(
        ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len)
        == NINLIL_NCL1_REJECT_BODY_LAYOUT);
    msg.body.ctrl_error.error_code = 0x0008u;
    REQUIRE(
        ninlil_ncl1_encode(&msg, buf, sizeof(buf), &len)
        == NINLIL_NCL1_REJECT_BODY_LAYOUT);
    return 0;
}

static int test_hello_ack_structural(void)
{
    ninlil_ncl1_message_t msg;

    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = 1u;
    msg.header.message_type = NINLIL_NCL1_MSG_HELLO_ACK;
    msg.header.request_id = 1u;
    msg.header.session_generation = 3u;
    msg.header.session_cookie = 9u;
    msg.header.body_length = 8u;
    msg.body.hello_ack.selected_control_version = 1u;
    msg.body.hello_ack.flags_selected = 0u;
    msg.body.hello_ack.result_code = NINLIL_NCL1_HELLO_OK;
    REQUIRE(ninlil_ncl1_is_structurally_valid_hello_ack(&msg));

    msg.body.hello_ack.flags_selected = 1u;
    REQUIRE(!ninlil_ncl1_is_structurally_valid_hello_ack(&msg));
    msg.body.hello_ack.flags_selected = 0u;
    msg.body.hello_ack.selected_control_version = 2u;
    REQUIRE(!ninlil_ncl1_is_structurally_valid_hello_ack(&msg));
    msg.body.hello_ack.selected_control_version = 1u;
    msg.header.session_cookie = 0u;
    REQUIRE(!ninlil_ncl1_is_structurally_valid_hello_ack(&msg));
    return 0;
}

static int test_invalid_hello_not_bootstrap(void)
{
    ninlil_ncl1_message_t msg;

    (void)memset(&msg, 0, sizeof(msg));
    msg.header.logical_version = 1u;
    msg.header.message_type = NINLIL_NCL1_MSG_HELLO;
    msg.header.request_id = 1u;
    msg.header.body_length = 8u;
    msg.body.hello.min_control_version = 1u;
    msg.body.hello.max_control_version = 2u; /* not U4 exact */
    REQUIRE(!ninlil_ncl1_is_valid_hello_bootstrap(&msg));
    msg.body.hello.max_control_version = 1u;
    msg.body.hello.flags_supported = 1u;
    REQUIRE(!ninlil_ncl1_is_valid_hello_bootstrap(&msg));
    msg.body.hello.flags_supported = 0u;
    msg.header.session_generation = 1u;
    REQUIRE(!ninlil_ncl1_is_valid_hello_bootstrap(&msg));
    return 0;
}

int main(void)
{
    if (test_hello_roundtrip_u4_exact() != 0) {
        return 1;
    }
    if (test_reserved_not_in_pure_decode() != 0) {
        return 1;
    }
    if (test_type_binding() != 0) {
        return 1;
    }
    if (test_ctrl_error_closed() != 0) {
        return 1;
    }
    if (test_hello_ack_structural() != 0) {
        return 1;
    }
    if (test_invalid_hello_not_bootstrap() != 0) {
        return 1;
    }
    (void)printf("ncl1_codec_test: OK\n");
    return 0;
}
