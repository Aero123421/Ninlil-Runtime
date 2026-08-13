/* SPDX-License-Identifier: Apache-2.0 */
#include "nvb1_codec.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_binding_round_trip(void)
{
    uint8_t payload[NINLIL_NVB1_BINDING_MIN];
    uint8_t encoded[NINLIL_NVB1_ENVELOPE_MAX];
    ninlil_nvb1_envelope_t in;
    ninlil_nvb1_envelope_t out;
    size_t length = 0u;
    size_t i;

    for (i = 0u; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }
    (void)memset(&in, 0, sizeof(in));
    in.kind = NINLIL_NVB1_KIND_BINDING_SET;
    in.operation_id = UINT64_C(0x0102030405060708);
    in.payload = payload;
    in.payload_length = sizeof(payload);
    REQUIRE(ninlil_nvb1_encode(
                &in, encoded, sizeof(encoded), &length)
        == NINLIL_NVB1_OK);
    REQUIRE(length == NINLIL_NVB1_HEADER_BYTES + sizeof(payload));
    REQUIRE(memcmp(encoded, "NVB1\x01\x01\0\0", 8u) == 0);
    REQUIRE(encoded[8] == 1u && encoded[15] == 8u);
    (void)memset(&out, 0, sizeof(out));
    REQUIRE(ninlil_nvb1_decode(encoded, length, &out) == NINLIL_NVB1_OK);
    REQUIRE(out.kind == in.kind && out.operation_id == in.operation_id);
    REQUIRE(out.payload_length == sizeof(payload));
    REQUIRE(memcmp(out.payload, payload, sizeof(payload)) == 0);
    return 0;
}

static int test_closed_lengths_and_fields(void)
{
    uint8_t payload[NINLIL_NVB1_BINDING_MAX + 1u];
    uint8_t encoded[NINLIL_NVB1_ENVELOPE_MAX];
    ninlil_nvb1_envelope_t in;
    ninlil_nvb1_envelope_t out;
    size_t length = 77u;
    size_t required;

    (void)memset(payload, 0x5a, sizeof(payload));
    (void)memset(&in, 0, sizeof(in));
    in.kind = NINLIL_NVB1_KIND_BINDING_SET;
    in.operation_id = 1u;
    in.payload = payload;
    in.payload_length = NINLIL_NVB1_BINDING_MIN - 1u;
    REQUIRE(ninlil_nvb1_encode(
                &in, encoded, sizeof(encoded), &length)
        == NINLIL_NVB1_STRUCTURAL);
    REQUIRE(length == 0u);
    in.payload_length = NINLIL_NVB1_BINDING_MAX + 1u;
    REQUIRE(ninlil_nvb1_encode(
                &in, encoded, sizeof(encoded), &length)
        == NINLIL_NVB1_STRUCTURAL);
    in.payload_length = NINLIL_NVB1_BINDING_MIN;
    required = NINLIL_NVB1_HEADER_BYTES + in.payload_length;
    REQUIRE(ninlil_nvb1_encode(&in, encoded, required - 1u, &length)
        == NINLIL_NVB1_CAPACITY);
    REQUIRE(length == required);
    REQUIRE(ninlil_nvb1_encode(&in, encoded, sizeof(encoded), &length)
        == NINLIL_NVB1_OK);
    encoded[4] = 2u;
    REQUIRE(ninlil_nvb1_decode(encoded, length, &out)
        == NINLIL_NVB1_STRUCTURAL);
    encoded[4] = 1u;
    encoded[6] = 1u;
    REQUIRE(ninlil_nvb1_decode(encoded, length, &out)
        == NINLIL_NVB1_STRUCTURAL);
    encoded[6] = 0u;
    (void)memset(encoded + 8u, 0, 8u);
    REQUIRE(ninlil_nvb1_decode(encoded, length, &out)
        == NINLIL_NVB1_STRUCTURAL);
    return 0;
}

static int test_status_and_alias(void)
{
    union {
        ninlil_nvb1_local_status_t status;
        uint8_t bytes[32];
    } alias;
    uint8_t encoded[NINLIL_NVB1_STATUS_BYTES];
    ninlil_nvb1_local_status_t in;
    ninlil_nvb1_local_status_t out;

    in.code = NINLIL_NVB1_STATUS_INSTALLED;
    in.pair_generation = UINT64_C(0x1122334455667788);
    REQUIRE(ninlil_nvb1_status_encode(&in, encoded) == NINLIL_NVB1_OK);
    REQUIRE(encoded[0] == 0u && encoded[3] == 1u);
    REQUIRE(encoded[4] == 0u && encoded[7] == 0u);
    REQUIRE(ninlil_nvb1_status_decode(encoded, &out) == NINLIL_NVB1_OK);
    REQUIRE(out.code == in.code && out.pair_generation == in.pair_generation);
    encoded[4] = 1u;
    REQUIRE(ninlil_nvb1_status_decode(encoded, &out)
        == NINLIL_NVB1_STRUCTURAL);
    in.code = 8u;
    REQUIRE(ninlil_nvb1_status_encode(&in, encoded)
        == NINLIL_NVB1_STRUCTURAL);
    (void)memset(&alias, 0, sizeof(alias));
    alias.status.code = NINLIL_NVB1_STATUS_BUSY;
    REQUIRE(ninlil_nvb1_status_encode(&alias.status, alias.bytes)
        == NINLIL_NVB1_ALIAS);
    return 0;
}

static int test_board_info_round_trip(void)
{
    union {
        ninlil_nvb1_board_info_t info;
        uint8_t bytes[64];
    } alias;
    ninlil_nvb1_board_info_t in;
    ninlil_nvb1_board_info_t out;
    ninlil_nvb1_envelope_t envelope;
    ninlil_nvb1_envelope_t decoded;
    uint8_t payload[NINLIL_NVB1_BOARD_INFO_BYTES];
    uint8_t wire[NINLIL_NVB1_HEADER_BYTES + NINLIL_NVB1_BOARD_INFO_BYTES];
    size_t length = 0u;
    size_t i;

    (void)memset(&in, 0, sizeof(in));
    for (i = 0u; i < sizeof(in.clock_epoch_id); ++i) {
        in.clock_epoch_id[i] = (uint8_t)(0x20u + i);
    }
    in.clock_now_ms = UINT64_C(0x0102030405060708);
    in.clock_trust = 1u;
    REQUIRE(ninlil_nvb1_board_info_encode(&in, payload) == NINLIL_NVB1_OK);
    REQUIRE(payload[16] == 1u && payload[23] == 8u);
    REQUIRE(payload[24] == 0u && payload[27] == 1u);
    REQUIRE(payload[28] == 0u && payload[31] == 0u);
    REQUIRE(ninlil_nvb1_board_info_decode(payload, &out) == NINLIL_NVB1_OK);
    REQUIRE(memcmp(&in, &out, sizeof(in)) == 0);

    (void)memset(&envelope, 0, sizeof(envelope));
    envelope.kind = NINLIL_NVB1_KIND_BOARD_INFO;
    envelope.operation_id = 9u;
    envelope.payload = payload;
    envelope.payload_length = sizeof(payload);
    REQUIRE(ninlil_nvb1_encode(&envelope, wire, sizeof(wire), &length)
        == NINLIL_NVB1_OK);
    REQUIRE(ninlil_nvb1_decode(wire, length, &decoded) == NINLIL_NVB1_OK);
    REQUIRE(decoded.kind == NINLIL_NVB1_KIND_BOARD_INFO
        && decoded.operation_id == 9u
        && decoded.payload_length == NINLIL_NVB1_BOARD_INFO_BYTES);

    payload[31] = 1u;
    REQUIRE(ninlil_nvb1_board_info_decode(payload, &out)
        == NINLIL_NVB1_STRUCTURAL);
    payload[31] = 0u;
    (void)memset(payload, 0, 16u);
    REQUIRE(ninlil_nvb1_board_info_decode(payload, &out)
        == NINLIL_NVB1_STRUCTURAL);
    (void)memset(&alias, 0, sizeof(alias));
    alias.info.clock_epoch_id[0] = 1u;
    alias.info.clock_trust = 1u;
    REQUIRE(ninlil_nvb1_board_info_encode(&alias.info, alias.bytes)
        == NINLIL_NVB1_ALIAS);
    return 0;
}

int main(void)
{
    REQUIRE(test_binding_round_trip() == 0);
    REQUIRE(test_closed_lengths_and_fields() == 0);
    REQUIRE(test_status_and_alias() == 0);
    REQUIRE(test_board_info_round_trip() == 0);
    (void)fprintf(stdout, "nvb1_codec_test OK\n");
    return 0;
}
