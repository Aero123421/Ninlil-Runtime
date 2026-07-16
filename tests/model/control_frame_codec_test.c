#include "control_frame_codec.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static uint8_t hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (uint8_t)(value - 'a' + 10);
    }
    return (uint8_t)(value - 'A' + 10);
}

static size_t decode_hex(const char *hex, uint8_t *out)
{
    size_t index;
    size_t length = strlen(hex) / 2u;
    for (index = 0u; index < length; ++index) {
        out[index] = (uint8_t)((hex_nibble(hex[index * 2u]) << 4u)
            | hex_nibble(hex[index * 2u + 1u]));
    }
    return length;
}

static int feed_stream(
    ninlil_model_control_frame_parser_t *parser,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_frames)
{
    uint32_t offset = 0u;
    *out_frames = 0u;
    while (offset < length) {
        uint32_t consumed = 0u;
        ninlil_model_control_frame_result_t result =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                parser, data + offset, length - offset, &consumed, &result)
            == NINLIL_OK);
        if (consumed == 0u && !parser->frame_ready) {
            break;
        }
        offset += consumed;
        if (parser->frame_ready) {
            *out_frames += 1u;
        }
    }
    return 0;
}

static int test_crc32c_golden(void)
{
    static const uint8_t ascii[] = "123456789";
    REQUIRE(ninlil_model_control_frame_crc32c(ascii, 9u) == 0xe3069283u);
    REQUIRE(ninlil_model_control_frame_crc32c(NULL, 0u) == 0u);
    return 0;
}

static int test_type_catalog(void)
{
    REQUIRE(ninlil_model_control_frame_type_is_known(
        NINLIL_MODEL_CONTROL_FRAME_TYPE_PING));
    REQUIRE(ninlil_model_control_frame_type_is_known(
        NINLIL_MODEL_CONTROL_FRAME_TYPE_PONG));
    REQUIRE(ninlil_model_control_frame_type_is_known(
        NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA));
    REQUIRE(ninlil_model_control_frame_type_is_known(
        NINLIL_MODEL_CONTROL_FRAME_TYPE_RESET));
    REQUIRE(!ninlil_model_control_frame_type_is_known(0u));
    REQUIRE(!ninlil_model_control_frame_type_is_known(0x05u));
    REQUIRE(!ninlil_model_control_frame_type_is_known(0xffu));
    return 0;
}

static int test_encode_decode_roundtrip(void)
{
    uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t length = 0u;
    ninlil_model_control_frame_fields_t fields;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    ninlil_bytes_view_t encoded;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.flags = 0u;
    fields.stream_or_cell_id = 0x0a0b0c0du;
    fields.sequence = 0x11223344u;
    fields.payload.data = payload;
    fields.payload.length = (uint32_t)sizeof(payload);

    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_OK);
    REQUIRE(length
        == NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES + sizeof(payload));

    encoded.data = frame;
    encoded.length = length;
    (void)memset(&view, 0, sizeof(view));
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
    REQUIRE(view.type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA);
    REQUIRE(view.stream_or_cell_id == 0x0a0b0c0du);
    REQUIRE(view.sequence == 0x11223344u);
    REQUIRE(view.payload_length == sizeof(payload));
    REQUIRE(view.payload != NULL);
    REQUIRE(memcmp(view.payload, payload, sizeof(payload)) == 0);
    return 0;
}

static int test_independent_golden_empty_and_ping(void)
{
    static const char *empty_data_hex =
        "4e4347310103000001020304000000010000a40548e72848073e";
    static const char *ping_4_hex =
        "4e4347310101000000000000000000000004ff19de30deadbeef916bc1fb";

    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t expected[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t payload4[] = {0xde, 0xad, 0xbe, 0xef};
    uint32_t length = 0u;
    ninlil_model_control_frame_fields_t fields;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result;
    ninlil_bytes_view_t encoded;
    size_t n;

    n = decode_hex(empty_data_hex, expected);
    REQUIRE(n == 26u);
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 0x01020304u;
    fields.sequence = 1u;
    fields.payload.data = NULL;
    fields.payload.length = 0u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_OK);
    REQUIRE(length == 26u);
    REQUIRE(memcmp(frame, expected, 26u) == 0);
    encoded.data = expected;
    encoded.length = 26u;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);

    n = decode_hex(ping_4_hex, expected);
    REQUIRE(n == 30u);
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.stream_or_cell_id = 0u;
    fields.sequence = 0u;
    fields.payload.data = payload4;
    fields.payload.length = 4u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_OK);
    REQUIRE(length == 30u);
    REQUIRE(memcmp(frame, expected, 30u) == 0);
    return 0;
}

static int test_negative_one_shot(void)
{
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t length = 0u;
    ninlil_model_control_frame_fields_t fields;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result;
    ninlil_bytes_view_t encoded;
    uint8_t payload[] = {1, 2, 3};

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.payload.data = payload;
    fields.payload.length = 3u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_OK);

    encoded.data = frame;
    encoded.length = length - 1u;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_TRUNCATED);

    frame[0] ^= 0x01u;
    encoded.length = length;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC);
    frame[0] ^= 0x01u;

    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_OK);
    frame[length - 1u] ^= 0xffu;
    encoded.length = length;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC);

    /* zero-length view with non-NULL data is invalid shape */
    fields.payload.data = payload;
    fields.payload.length = 0u;
    length = 0xdeadbeefu;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 0u);
    fields.payload.data = payload;
    fields.payload.length = 3u;

    fields.payload.length = NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES + 1u;
    length = 99u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 0u);
    return 0;
}

/*
 * Table-driven alias negatives for every declared participating pair.
 * Alias returns INVALID_ARGUMENT and leaves outs / parser / storage unchanged.
 */
static int test_alias_table_driven(void)
{
    uint8_t out_buf[128];
    uint8_t out_buf_snapshot[128];
    uint8_t payload_ok[] = {1, 2, 3};
    uint8_t ping_payload[] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t good_frame[64];
    uint32_t good_len = 0u;
    ninlil_model_control_frame_fields_t fields;
    uint32_t length_poison = 0x11111111u;
    uint32_t length_ok = 0u;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result =
        (ninlil_model_control_frame_result_t)0xabcdefu;
    uint32_t frame_length = 0x22222222u;
    ninlil_bytes_view_t encoded;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    uint8_t storage_snap[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_parser_t parser_snap;
    uint32_t consumed = 0x33333333u;
    uint8_t input_buf[64];

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.payload.data = payload_ok;
    fields.payload.length = 3u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good_frame, sizeof(good_frame), &good_len)
        == NINLIL_OK);
    (void)memcpy(input_buf, good_frame, good_len);

    /* --- encode pairs --- */
    /* out_bytes × out_length */
    length_poison = 0x11111111u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, (uint8_t *)&length_poison, sizeof(length_poison),
            &length_poison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length_poison == 0x11111111u);

    /* fields × out_length */
    {
        ninlil_model_control_frame_fields_t fields_snapshot;
        (void)memcpy(&fields_snapshot, &fields, sizeof(fields_snapshot));
        (void)memset(out_buf, 0xa6, sizeof(out_buf));
        (void)memcpy(out_buf_snapshot, out_buf, sizeof(out_buf_snapshot));
        REQUIRE(ninlil_model_control_frame_encode(
                &fields,
                out_buf,
                sizeof(out_buf),
                (uint32_t *)(void *)&fields)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&fields, &fields_snapshot, sizeof(fields)) == 0);
        REQUIRE(memcmp(out_buf, out_buf_snapshot, sizeof(out_buf)) == 0);
    }

    /* fields × out_bytes: fields object overlaps out_bytes */
    length_poison = 0x11111111u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, (uint8_t *)&fields, sizeof(fields), &length_poison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length_poison == 0x11111111u);

    /* fields.payload × fields */
    fields.payload.data = (const uint8_t *)&fields;
    fields.payload.length = 4u;
    length_poison = 0x11111111u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, out_buf, sizeof(out_buf), &length_poison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length_poison == 0x11111111u);
    fields.payload.data = payload_ok;
    fields.payload.length = 3u;

    /* fields.payload × out_bytes */
    fields.payload.data = out_buf;
    fields.payload.length = 3u;
    length_poison = 0x11111111u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, out_buf, sizeof(out_buf), &length_poison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length_poison == 0x11111111u);
    fields.payload.data = payload_ok;

    /* fields.payload × out_length */
    fields.payload.data = (const uint8_t *)&length_poison;
    fields.payload.length = 4u;
    length_poison = 0x11111111u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, out_buf, sizeof(out_buf), &length_poison)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length_poison == 0x11111111u);
    fields.payload.data = payload_ok;
    fields.payload.length = 3u;

    /* --- decode_prefix pairs: every output is snapshotted --- */
    encoded.data = good_frame;
    encoded.length = good_len;

    /* out_view × out_result */
    {
        union {
            ninlil_model_control_frame_view_t view;
            ninlil_model_control_frame_result_t result;
        } shared;
        unsigned char shared_snapshot[sizeof(shared)];
        frame_length = 0x22222222u;
        (void)memset(&shared, 0x5a, sizeof(shared));
        (void)memcpy(shared_snapshot, &shared, sizeof(shared_snapshot));
        REQUIRE(ninlil_model_control_frame_decode_prefix(
                encoded, &shared.view, &frame_length, &shared.result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&shared, shared_snapshot, sizeof(shared)) == 0);
        REQUIRE(frame_length == 0x22222222u);
    }

    /* encoded × out_view */
    (void)memset(&view, 0x5a, sizeof(view));
    {
        ninlil_model_control_frame_view_t view_snapshot;
        (void)memcpy(&view_snapshot, &view, sizeof(view_snapshot));
        encoded.data = (const uint8_t *)&view;
        encoded.length = (uint32_t)sizeof(view);
        result = (ninlil_model_control_frame_result_t)0xabcdefu;
        frame_length = 0x22222222u;
        REQUIRE(ninlil_model_control_frame_decode_prefix(
                encoded, &view, &frame_length, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&view, &view_snapshot, sizeof(view)) == 0);
        REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
        REQUIRE(frame_length == 0x22222222u);
    }

    /* encoded × out_result */
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    encoded.data = (const uint8_t *)&result;
    encoded.length = (uint32_t)sizeof(result);
    frame_length = 0x22222222u;
    (void)memset(&view, 0x5a, sizeof(view));
    {
        ninlil_model_control_frame_view_t view_snapshot;
        (void)memcpy(&view_snapshot, &view, sizeof(view_snapshot));
        REQUIRE(ninlil_model_control_frame_decode_prefix(
                encoded, &view, &frame_length, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&view, &view_snapshot, sizeof(view)) == 0);
        REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
        REQUIRE(frame_length == 0x22222222u);
    }

    /* encoded × out_frame_length */
    frame_length = 0x22222222u;
    encoded.data = (const uint8_t *)&frame_length;
    encoded.length = (uint32_t)sizeof(frame_length);
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    (void)memset(&view, 0x5a, sizeof(view));
    {
        ninlil_model_control_frame_view_t view_snapshot;
        (void)memcpy(&view_snapshot, &view, sizeof(view_snapshot));
        REQUIRE(ninlil_model_control_frame_decode_prefix(
                encoded, &view, &frame_length, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&view, &view_snapshot, sizeof(view)) == 0);
        REQUIRE(frame_length == 0x22222222u);
        REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    }

    /* out_view × out_frame_length */
    encoded.data = good_frame;
    encoded.length = good_len;
    {
        union {
            ninlil_model_control_frame_view_t view;
            uint32_t frame_length;
        } shared;
        unsigned char shared_snapshot[sizeof(shared)];
        result = (ninlil_model_control_frame_result_t)0xabcdefu;
        (void)memset(&shared, 0x5a, sizeof(shared));
        (void)memcpy(shared_snapshot, &shared, sizeof(shared_snapshot));
        REQUIRE(ninlil_model_control_frame_decode_prefix(
                encoded, &shared.view, &shared.frame_length, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&shared, shared_snapshot, sizeof(shared)) == 0);
        REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    }

    /* out_frame_length × out_result */
    {
        union {
            uint32_t frame_length;
            ninlil_model_control_frame_result_t result;
        } shared;
        unsigned char shared_snapshot[sizeof(shared)];
        ninlil_model_control_frame_view_t view_snapshot;
        (void)memset(&shared, 0x5a, sizeof(shared));
        (void)memcpy(shared_snapshot, &shared, sizeof(shared_snapshot));
        (void)memset(&view, 0x5a, sizeof(view));
        (void)memcpy(&view_snapshot, &view, sizeof(view_snapshot));
        REQUIRE(ninlil_model_control_frame_decode_prefix(
                encoded, &view, &shared.frame_length, &shared.result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&shared, shared_snapshot, sizeof(shared)) == 0);
        REQUIRE(memcmp(&view, &view_snapshot, sizeof(view)) == 0);
    }

    /* --- exact decode pairs (separate public entry point) --- */
    (void)memset(&view, 0x5a, sizeof(view));
    {
        ninlil_model_control_frame_view_t view_snapshot;
        (void)memcpy(&view_snapshot, &view, sizeof(view_snapshot));
        encoded.data = (const uint8_t *)&view;
        encoded.length = (uint32_t)sizeof(view);
        result = (ninlil_model_control_frame_result_t)0xabcdefu;
        REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&view, &view_snapshot, sizeof(view)) == 0);
        REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    }

    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    encoded.data = (const uint8_t *)&result;
    encoded.length = (uint32_t)sizeof(result);
    (void)memset(&view, 0x5a, sizeof(view));
    {
        ninlil_model_control_frame_view_t view_snapshot;
        (void)memcpy(&view_snapshot, &view, sizeof(view_snapshot));
        REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&view, &view_snapshot, sizeof(view)) == 0);
        REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    }

    encoded.data = good_frame;
    encoded.length = good_len;
    {
        union {
            ninlil_model_control_frame_view_t view;
            ninlil_model_control_frame_result_t result;
        } shared;
        unsigned char shared_snapshot[sizeof(shared)];
        (void)memset(&shared, 0x5a, sizeof(shared));
        (void)memcpy(shared_snapshot, &shared, sizeof(shared_snapshot));
        REQUIRE(ninlil_model_control_frame_decode(
                encoded, &shared.view, &shared.result)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&shared, shared_snapshot, sizeof(shared)) == 0);
    }

    /* --- feed pairs --- */
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.payload.data = ping_payload;
    fields.payload.length = 4u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good_frame, sizeof(good_frame), &length_ok)
        == NINLIL_OK);
    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    (void)memset(payload_storage, 0xa5, sizeof(payload_storage));
    (void)memcpy(storage_snap, payload_storage, sizeof(storage_snap));
    (void)memcpy(&parser_snap, &parser, sizeof(parser_snap));
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;

    /* parser × out_consumed */
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, good_frame, length_ok, (uint32_t *)&parser, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    REQUIRE(memcmp(&parser, &parser_snap, sizeof(parser)) == 0);

    /* payload_storage × out_consumed (deadbeef LE trap) */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, good_frame, length_ok,
            (uint32_t *)(void *)payload_storage, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(consumed == 0x33333333u);
    REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    REQUIRE(memcmp(payload_storage, storage_snap, sizeof(payload_storage))
        == 0);
    REQUIRE(memcmp(&parser, &parser_snap, sizeof(parser)) == 0);
    REQUIRE(consumed != 0xefbeaddeu);

    /* payload_storage × out_result */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, good_frame, length_ok, &consumed,
            (ninlil_model_control_frame_result_t *)(void *)payload_storage)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(consumed == 0x33333333u);
    REQUIRE(memcmp(payload_storage, storage_snap, sizeof(payload_storage))
        == 0);

    /* out_consumed × out_result */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, good_frame, length_ok, (uint32_t *)&result, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);

    /* input × parser */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, (const uint8_t *)&parser, length_ok, &consumed, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(consumed == 0x33333333u);
    REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);
    REQUIRE(memcmp(&parser, &parser_snap, sizeof(parser)) == 0);

    /* input × payload_storage */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, payload_storage, length_ok, &consumed, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(consumed == 0x33333333u);
    REQUIRE(memcmp(payload_storage, storage_snap, sizeof(payload_storage))
        == 0);

    /* input × out_consumed */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, (const uint8_t *)&consumed, sizeof(consumed), &consumed,
            &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(consumed == 0x33333333u);

    /* input × out_result */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, (const uint8_t *)&result, sizeof(result), &consumed,
            &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result == (ninlil_model_control_frame_result_t)0xabcdefu);

    /* parser × out_result */
    consumed = 0x33333333u;
    result = (ninlil_model_control_frame_result_t)0xabcdefu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, good_frame, length_ok, &consumed,
            (ninlil_model_control_frame_result_t *)&parser)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(consumed == 0x33333333u);
    REQUIRE(memcmp(&parser, &parser_snap, sizeof(parser)) == 0);

    (void)input_buf;
    return 0;
}

static int test_ranges_overlap_boundaries(void)
{
    /*
     * Exercise ranges_overlap through encode: adjacent vs overlapping
     * buffers, zero-length vacuous disjoint, and unrepresentable end
     * via high uintptr (treated as reject without mutating *out_length).
     */
    uint8_t buf[32];
    uint8_t payload[] = {7};
    uint32_t length = 0x55aa55aau;
    ninlil_model_control_frame_fields_t fields;
    void *high;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.payload.data = payload;
    fields.payload.length = 1u;

    /* Adjacent non-overlapping: encode into buf[0..), length after buffer. */
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, buf, 32u, &length)
        == NINLIL_OK);
    REQUIRE(length == NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES + 1u);

    /* Overlap: payload view points into out_bytes. */
    fields.payload.data = buf;
    fields.payload.length = 1u;
    length = 0x55aa55aau;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, buf, 32u, &length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 0x55aa55aau);

    /* Zero-length payload (NULL) does not alias. */
    fields.payload.data = NULL;
    fields.payload.length = 0u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, buf, 32u, &length)
        == NINLIL_OK);

    /* Unrepresentable range: base near UINTPTR_MAX with large length. */
    high = (void *)(uintptr_t)(UINTPTR_MAX - 3u);
    fields.payload.data = (const uint8_t *)high;
    fields.payload.length = 16u;
    length = 0x55aa55aau;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, buf, 32u, &length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 0x55aa55aau);
    return 0;
}

static int test_concat_and_incremental(void)
{
    uint8_t frame_a[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t frame_b[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t stream[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES * 2u + 16u];
    uint32_t len_a = 0u;
    uint32_t len_b = 0u;
    uint32_t stream_len;
    uint32_t frames = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint8_t pa[] = {0x11};
    uint8_t pb[] = {0x22, 0x33};
    uint32_t i;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 1u;
    fields.sequence = 1u;
    fields.payload.data = pa;
    fields.payload.length = 1u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame_a, sizeof(frame_a), &len_a)
        == NINLIL_OK);
    fields.sequence = 2u;
    fields.payload.data = pb;
    fields.payload.length = 2u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame_b, sizeof(frame_b), &len_b)
        == NINLIL_OK);

    (void)memcpy(stream, frame_a, len_a);
    (void)memcpy(stream + len_a, frame_b, len_b);
    stream_len = len_a + len_b;

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    REQUIRE(feed_stream(&parser, stream, stream_len, &frames) == 0);
    REQUIRE(frames == 2u);

    ninlil_model_control_frame_parser_reset(&parser);
    frames = 0u;
    for (i = 0u; i < stream_len; ++i) {
        uint32_t consumed = 0u;
        ninlil_model_control_frame_result_t result =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser, &stream[i], 1u, &consumed, &result)
            == NINLIL_OK);
        REQUIRE(consumed == 1u);
        if (parser.frame_ready) {
            frames += 1u;
        }
    }
    REQUIRE(frames == 2u);
    return 0;
}

static int test_noise_resync(void)
{
    uint8_t good[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t stream[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES + 32u];
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint8_t payload[] = {0x55};
    uint32_t frames = 0u;
    uint32_t noise_len = 7u;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.stream_or_cell_id = 9u;
    fields.sequence = 3u;
    fields.payload.data = payload;
    fields.payload.length = 1u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);

    stream[0] = 0x00u;
    stream[1] = 0xffu;
    stream[2] = (uint8_t)'N';
    stream[3] = (uint8_t)'C';
    stream[4] = (uint8_t)'X';
    stream[5] = 0x11u;
    stream[6] = 0x22u;
    (void)memcpy(stream + noise_len, good, good_len);

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    REQUIRE(feed_stream(&parser, stream, noise_len + good_len, &frames) == 0);
    REQUIRE(frames == 1u);
    REQUIRE(parser.stats.resync_skips > 0u);
    return 0;
}

/*
 * Bad header after full magic, with another full magic embedded later in
 * the corrupt header region + a valid frame. Untrusted resync must find
 * the embedded magic path or the trailing valid frame.
 */
static int test_header_embedded_magic_resync(void)
{
    uint8_t good[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t stream[128];
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint8_t payload[] = {0xaa};
    uint32_t frames = 0u;
    uint32_t i;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 5u;
    fields.payload.data = payload;
    fields.payload.length = 1u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);

    /* Corrupt candidate: NCG1 + bad body that embeds another NCG1 at offset 6. */
    stream[0] = (uint8_t)'N';
    stream[1] = (uint8_t)'C';
    stream[2] = (uint8_t)'G';
    stream[3] = (uint8_t)'1';
    stream[4] = 1u; /* version */
    stream[5] = 0xffu; /* bad type */
    stream[6] = (uint8_t)'N';
    stream[7] = (uint8_t)'C';
    stream[8] = (uint8_t)'G';
    stream[9] = (uint8_t)'1';
    for (i = 10u; i < 22u; ++i) {
        stream[i] = 0x5au;
    }
    (void)memcpy(stream + 22u, good, good_len);

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    REQUIRE(feed_stream(&parser, stream, 22u + good_len, &frames) == 0);
    REQUIRE(frames == 1u);
    REQUIRE(parser.last_frame.sequence == 5u);
    REQUIRE(parser.stats.rejects_bad_type > 0u
        || parser.stats.rejects_bad_header > 0u);
    return 0;
}

/*
 * Trusted frame_crc failure discards entire candidate; immediately
 * following valid concatenated frame must still be accepted.
 * resync_skips must equal bad_len (bytes), not 1 event.
 */
static int test_frame_crc_discard_keeps_following_frame(void)
{
    uint8_t bad[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t good[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t stream[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES * 2u];
    uint32_t bad_len = 0u;
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint8_t pa[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t pb[] = {0x99};
    uint32_t frames = 0u;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 1u;
    fields.payload.data = pa;
    fields.payload.length = 4u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, bad, sizeof(bad), &bad_len)
        == NINLIL_OK);
    /* Corrupt trailing frame CRC only; header_crc remains valid. */
    bad[bad_len - 1u] ^= 0xffu;

    fields.sequence = 2u;
    fields.payload.data = pb;
    fields.payload.length = 1u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);

    (void)memcpy(stream, bad, bad_len);
    (void)memcpy(stream + bad_len, good, good_len);

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    REQUIRE(feed_stream(&parser, stream, bad_len + good_len, &frames) == 0);
    REQUIRE(frames == 1u);
    REQUIRE(parser.last_frame.sequence == 2u);
    REQUIRE(parser.last_frame.payload_length == 1u);
    REQUIRE(parser.last_frame.payload[0] == 0x99u);
    REQUIRE(parser.stats.rejects_bad_frame_crc >= 1u);
    /*
     * Residual after discard starts with good magic → compact drops 0.
     * resync_skips unit is discarded bytes: exact bad_len.
     */
    REQUIRE(parser.stats.resync_skips == bad_len);
    return 0;
}

/*
 * Exact resync_skips arithmetic: trusted discard of empty-payload frame
 * (overhead only) + residual already aligned.
 */
static int test_resync_skips_trusted_exact_bytes(void)
{
    uint8_t bad[64];
    uint8_t good[64];
    uint8_t stream[128];
    uint32_t bad_len = 0u;
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint32_t frames = 0u;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 1u;
    fields.payload.data = NULL;
    fields.payload.length = 0u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, bad, sizeof(bad), &bad_len)
        == NINLIL_OK);
    REQUIRE(bad_len == NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES);
    bad[bad_len - 1u] ^= 0x01u;

    fields.sequence = 2u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);

    (void)memcpy(stream, bad, bad_len);
    (void)memcpy(stream + bad_len, good, good_len);

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    REQUIRE(feed_stream(&parser, stream, bad_len + good_len, &frames) == 0);
    REQUIRE(frames == 1u);
    REQUIRE(parser.stats.resync_skips == bad_len);
    REQUIRE(parser.stats.rejects_bad_frame_crc == 1u);
    return 0;
}

/*
 * Untrusted: single leading non-magic byte then valid frame.
 * resync_skips must be exactly 1 (discarded noise byte).
 */
static int test_resync_skips_untrusted_exact_bytes(void)
{
    uint8_t good[64];
    uint8_t stream[80];
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint32_t frames = 0u;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_PING;
    fields.sequence = 9u;
    fields.payload.data = NULL;
    fields.payload.length = 0u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);

    stream[0] = 0x00u;
    (void)memcpy(stream + 1u, good, good_len);

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    REQUIRE(feed_stream(&parser, stream, 1u + good_len, &frames) == 0);
    REQUIRE(frames == 1u);
    REQUIRE(parser.stats.resync_skips == 1u);
    return 0;
}

static int test_parser_memory_budget(void)
{
    size_t parser_size = sizeof(ninlil_model_control_frame_parser_t);

    REQUIRE(parser_size >= NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES);
    REQUIRE(parser_size
        <= NINLIL_MODEL_CONTROL_FRAME_PARSER_OBJECT_CEILING_BYTES);
    REQUIRE(NINLIL_MODEL_CONTROL_FRAME_PARSER_WORKING_SET_CEILING_BYTES
        == NINLIL_MODEL_CONTROL_FRAME_PARSER_OBJECT_CEILING_BYTES
            + NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES);
    REQUIRE(NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES
        == NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES);
    /* Working set must cover object + separate payload storage. */
    REQUIRE(parser_size
            + NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES
        <= NINLIL_MODEL_CONTROL_FRAME_PARSER_WORKING_SET_CEILING_BYTES);
    return 0;
}

/*
 * Long noise > FEED_GUARD_ITERS forces partial consumption in one feed.
 * Re-feed loop must still recover a trailing valid frame.
 * Fixed buffer (no heap) so the test stays portable.
 */
static int test_feed_guard_partial_consumption(void)
{
    enum {
        NOISE_LEN = (int)(NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS + 512u)
    };
    static uint8_t stream[NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS + 512u
        + 64u];
    uint8_t good[64];
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint32_t total_len;
    uint32_t offset;
    uint32_t frames = 0u;
    uint32_t partial_hits = 0u;
    uint32_t i;
    int saw_partial = 0;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 77u;
    fields.payload.data = NULL;
    fields.payload.length = 0u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);

    for (i = 0u; i < (uint32_t)NOISE_LEN; ++i) {
        stream[i] = 0x00u;
    }
    (void)memcpy(stream + (uint32_t)NOISE_LEN, good, good_len);
    total_len = (uint32_t)NOISE_LEN + good_len;

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);

    offset = 0u;
    while (offset < total_len) {
        uint32_t consumed = 0u;
        ninlil_model_control_frame_result_t result =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser,
                stream + offset,
                total_len - offset,
                &consumed,
                &result)
            == NINLIL_OK);
        if (consumed == 0u && !parser.frame_ready) {
            REQUIRE(0);
            return 1;
        }
        if (consumed > 0u && consumed < (total_len - offset)) {
            saw_partial = 1;
            partial_hits += 1u;
        }
        offset += consumed;
        if (parser.frame_ready) {
            frames += 1u;
            REQUIRE(parser.last_frame.sequence == 77u);
        }
    }
    REQUIRE(saw_partial);
    REQUIRE(partial_hits >= 1u);
    REQUIRE(frames == 1u);
    return 0;
}

/*
 * Concrete QA case: noise 2087 + empty valid frame 26 = 2113.
 * Must emit in the same feed (or leave strict residual); must not leave a
 * complete frame stranded until zero-length feed.
 */
static int test_guard_noise2087_empty_frame(void)
{
    enum { NOISE = 2087 };
    static uint8_t stream[NOISE + 64];
    uint8_t good[64];
    uint32_t good_len = 0u;
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_fields_t fields;
    uint32_t total;
    uint32_t offset;
    uint32_t frames = 0u;
    uint32_t i;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.sequence = 42u;
    fields.payload.data = NULL;
    fields.payload.length = 0u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, good, sizeof(good), &good_len)
        == NINLIL_OK);
    REQUIRE(good_len == 26u);

    for (i = 0u; i < (uint32_t)NOISE; ++i) {
        stream[i] = 0x00u;
    }
    (void)memcpy(stream + NOISE, good, good_len);
    total = (uint32_t)NOISE + good_len;
    REQUIRE(total == 2113u);

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);

    offset = 0u;
    while (offset < total) {
        uint32_t consumed = 0u;
        ninlil_model_control_frame_result_t result =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        uint32_t remain = total - offset;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser, stream + offset, remain, &consumed, &result)
            == NINLIL_OK);
        /*
         * Forbidden: full consume of this call's input with NEED_MORE while a
         * complete frame is stranded in the window (frame_ready=0).
         */
        if (consumed == remain
            && result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE
            && !parser.frame_ready
            && parser.window_length
                >= NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES) {
            REQUIRE(0);
        }
        if (consumed == 0u && !parser.frame_ready) {
            REQUIRE(0);
        }
        if (consumed > 0u && consumed < remain) {
            /* residual re-feed path — allowed */
        }
        offset += consumed;
        if (parser.frame_ready) {
            frames += 1u;
            REQUIRE(parser.last_frame.sequence == 42u);
        }
    }
    REQUIRE(frames == 1u);
    return 0;
}

/*
 * Actual algorithm pin: pure 0x00 noise costs ~1 input byte / guard iteration.
 * First feed of (noise || empty_frame) with noise in {G-1, G, G+1}:
 *   pins first-call residual, frame_ready, window, bytes_consumed, resync_skips,
 *   result; then re-feed loop must deliver exactly one final frame.
 */
static int test_guard_boundary_matrix(void)
{
    const uint32_t G = NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS;
    const uint32_t noise_cases[3] = {G - 1u, G, G + 1u};
    uint32_t c;

    for (c = 0u; c < 3u; ++c) {
        uint32_t noise = noise_cases[c];
        /* G+1 + 26 fits in G+64 */
        static uint8_t stream[NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS + 64u];
        uint8_t good[64];
        uint32_t good_len = 0u;
        uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
        ninlil_model_control_frame_parser_t parser;
        ninlil_model_control_frame_fields_t fields;
        uint32_t total;
        uint32_t offset;
        uint32_t frames = 0u;
        uint32_t i;
        uint32_t first_consumed = 0u;
        ninlil_model_control_frame_result_t first_result =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        uint32_t first_window;
        uint32_t first_bytes;
        uint32_t first_resync;
        uint8_t first_ready;

        (void)memset(&fields, 0, sizeof(fields));
        fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
        fields.sequence = 200u + c;
        fields.payload.data = NULL;
        fields.payload.length = 0u;
        REQUIRE(ninlil_model_control_frame_encode(
                &fields, good, sizeof(good), &good_len)
            == NINLIL_OK);
        REQUIRE(good_len == 26u);
        REQUIRE(noise + good_len
            <= NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS + 64u);

        for (i = 0u; i < noise; ++i) {
            stream[i] = 0x00u;
        }
        (void)memcpy(stream + noise, good, good_len);
        total = noise + good_len;

        REQUIRE(ninlil_model_control_frame_parser_init(
                &parser, payload_storage, sizeof(payload_storage))
            == NINLIL_OK);

        /* --- first feed: pin boundary behaviour --- */
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser, stream, total, &first_consumed, &first_result)
            == NINLIL_OK);
        first_window = parser.window_length;
        first_bytes = parser.stats.bytes_consumed;
        first_resync = parser.stats.resync_skips;
        first_ready = parser.frame_ready;

        /* Always consume something on long pure-noise prefix; never strand. */
        REQUIRE(first_consumed > 0u);
        REQUIRE(first_consumed <= total);
        REQUIRE(first_bytes == first_consumed);
        if (first_ready) {
            REQUIRE(first_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
            REQUIRE(parser.last_frame.sequence == 200u + c);
            frames = 1u;
            offset = first_consumed;
        } else {
            /* Residual must remain for re-feed when frame not yet emitted. */
            REQUIRE(first_consumed < total);
            REQUIRE(first_result != NINLIL_MODEL_CONTROL_FRAME_RESULT_OK
                || first_ready);
            /* Forbidden stranded complete frame. */
            REQUIRE(!(first_consumed == total
                && first_result
                    == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE
                && first_window
                    >= NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES
                && !first_ready));
            offset = first_consumed;
        }

        /* Exact algorithm pins for the pure-noise one-byte/iteration model. */
        REQUIRE(first_consumed == G);
        REQUIRE(first_bytes == G);
        REQUIRE(!first_ready);
        REQUIRE(first_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE);
        if (noise == G - 1u) {
            REQUIRE(first_window == 1u);
            REQUIRE(parser.window[0] == (uint8_t)'N');
            REQUIRE(first_resync == G - 1u);
        } else {
            REQUIRE(first_window == 0u);
            REQUIRE(first_resync == G);
        }

        /* --- re-feed residual until EOF; deliver exactly one frame --- */
        while (offset < total) {
            uint32_t consumed = 0u;
            ninlil_model_control_frame_result_t result =
                NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
            uint32_t remain = total - offset;
            REQUIRE(ninlil_model_control_frame_parser_feed(
                    &parser, stream + offset, remain, &consumed, &result)
                == NINLIL_OK);
            if (consumed == 0u && !parser.frame_ready) {
                REQUIRE(0);
            }
            if (consumed == remain
                && result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE
                && !parser.frame_ready
                && parser.window_length
                    >= NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES) {
                REQUIRE(0);
            }
            offset += consumed;
            if (parser.frame_ready) {
                frames += 1u;
                REQUIRE(parser.last_frame.sequence == 200u + c);
            }
        }
        REQUIRE(frames == 1u);
        /* No force-progress: never saw consumed==0 with residual on fresh path */
        REQUIRE(parser.stats.bytes_consumed == total);
    }
    return 0;
}

/*
 * Zero-length feed: consumed 0, NEED_MORE, window/stats invariant for
 * empty window, single 'N' prefix, and "NCG" prefix.
 */
static int test_zero_length_feed_invariants(void)
{
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    ninlil_model_control_frame_parser_stats_t stats_before;
    uint8_t window_before[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t window_len_before;
    uint32_t consumed = 0xffffffffu;
    ninlil_model_control_frame_result_t result =
        (ninlil_model_control_frame_result_t)0xeeeeeeeeu;
    uint8_t ready_before;
    const uint8_t *null_in = NULL;

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);

    /* empty window */
    stats_before = parser.stats;
    window_len_before = parser.window_length;
    ready_before = parser.frame_ready;
    consumed = 0xffffffffu;
    result = (ninlil_model_control_frame_result_t)0xeeeeeeeeu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, null_in, 0u, &consumed, &result)
        == NINLIL_OK);
    REQUIRE(consumed == 0u);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE);
    REQUIRE(parser.window_length == window_len_before);
    REQUIRE(parser.frame_ready == 0u);
    REQUIRE(parser.stats.bytes_consumed == stats_before.bytes_consumed);
    REQUIRE(parser.stats.resync_skips == stats_before.resync_skips);
    REQUIRE(parser.stats.frames_accepted == stats_before.frames_accepted);
    (void)ready_before;

    /* single 'N' in window */
    {
        uint8_t n = (uint8_t)'N';
        uint32_t c = 0u;
        ninlil_model_control_frame_result_t r =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser, &n, 1u, &c, &r)
            == NINLIL_OK);
        REQUIRE(c == 1u);
        REQUIRE(parser.window_length == 1u);
        REQUIRE(parser.window[0] == (uint8_t)'N');
    }
    stats_before = parser.stats;
    window_len_before = parser.window_length;
    (void)memcpy(window_before, parser.window, window_len_before);
    consumed = 0xffffffffu;
    result = (ninlil_model_control_frame_result_t)0xeeeeeeeeu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, null_in, 0u, &consumed, &result)
        == NINLIL_OK);
    REQUIRE(consumed == 0u);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE);
    REQUIRE(parser.window_length == window_len_before);
    REQUIRE(memcmp(parser.window, window_before, window_len_before) == 0);
    REQUIRE(parser.stats.bytes_consumed == stats_before.bytes_consumed);
    REQUIRE(parser.stats.resync_skips == stats_before.resync_skips);

    /* extend to "NCG" prefix */
    {
        uint8_t cg[2] = {(uint8_t)'C', (uint8_t)'G'};
        uint32_t c = 0u;
        ninlil_model_control_frame_result_t r =
            NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser, cg, 2u, &c, &r)
            == NINLIL_OK);
        REQUIRE(c == 2u);
        REQUIRE(parser.window_length == 3u);
        REQUIRE(parser.window[0] == (uint8_t)'N');
        REQUIRE(parser.window[1] == (uint8_t)'C');
        REQUIRE(parser.window[2] == (uint8_t)'G');
    }
    stats_before = parser.stats;
    window_len_before = parser.window_length;
    (void)memcpy(window_before, parser.window, window_len_before);
    consumed = 0xffffffffu;
    result = (ninlil_model_control_frame_result_t)0xeeeeeeeeu;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, null_in, 0u, &consumed, &result)
        == NINLIL_OK);
    REQUIRE(consumed == 0u);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE);
    REQUIRE(parser.window_length == window_len_before);
    REQUIRE(memcmp(parser.window, window_before, window_len_before) == 0);
    REQUIRE(parser.stats.bytes_consumed == stats_before.bytes_consumed);
    REQUIRE(parser.stats.resync_skips == stats_before.resync_skips);
    REQUIRE(parser.frame_ready == 0u);
    return 0;
}

/* Invariant: fresh parser + positive input never returns consumed==0. */
static int test_no_force_progress_needed(void)
{
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    uint8_t noise = 0x00u;
    uint32_t consumed = 0u;
    ninlil_model_control_frame_result_t result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    uint32_t i;

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    for (i = 0u; i < 64u; ++i) {
        consumed = 0u;
        result = NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        REQUIRE(ninlil_model_control_frame_parser_feed(
                &parser, &noise, 1u, &consumed, &result)
            == NINLIL_OK);
        REQUIRE(consumed == 1u);
    }
    return 0;
}

/* Production C bridge: each negative mutation independently. */
static int test_reject_mutations_independent(void)
{
    uint8_t base[64];
    uint8_t mut[64];
    uint32_t base_len = 0u;
    ninlil_model_control_frame_fields_t fields;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result;
    ninlil_bytes_view_t encoded;
    uint8_t payload[] = {'x', 'y'};
    uint32_t header_crc;
    uint32_t i;

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 1u;
    fields.sequence = 2u;
    fields.payload.data = payload;
    fields.payload.length = 2u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, base, sizeof(base), &base_len)
        == NINLIL_OK);

    /* BAD_MAGIC */
    (void)memcpy(mut, base, base_len);
    mut[0] ^= 1u;
    encoded.data = mut;
    encoded.length = base_len;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC);

    /* BAD_VERSION (checked before header CRC) */
    (void)memcpy(mut, base, base_len);
    mut[4] = 2u;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_VERSION);

    /* BAD_TYPE */
    (void)memcpy(mut, base, base_len);
    mut[5] = 0xffu;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_TYPE);

    /* BAD_FLAGS */
    (void)memcpy(mut, base, base_len);
    mut[7] = 1u;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FLAGS);

    /* BAD_LENGTH: oversize payload_length with valid header CRC */
    (void)memcpy(mut, base, base_len);
    mut[16] = (uint8_t)((NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES + 1u) >> 8);
    mut[17] = (uint8_t)((NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES + 1u) & 0xffu);
    header_crc = ninlil_model_control_frame_crc32c(
        mut, NINLIL_MODEL_CONTROL_FRAME_HEADER_PREFIX_BYTES);
    mut[18] = (uint8_t)(header_crc >> 24);
    mut[19] = (uint8_t)(header_crc >> 16);
    mut[20] = (uint8_t)(header_crc >> 8);
    mut[21] = (uint8_t)header_crc;
    /* exact length still base_len; decoder hits BAD_LENGTH before needing body */
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_LENGTH);

    /* BAD_HEADER_CRC */
    (void)memcpy(mut, base, base_len);
    mut[18] ^= 1u;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_HEADER_CRC);

    /* BAD_FRAME_CRC */
    (void)memcpy(mut, base, base_len);
    mut[base_len - 1u] ^= 0xffu;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC);

    (void)i;
    return 0;
}

static int test_stats_saturate(void)
{
    uint8_t payload_storage[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    ninlil_model_control_frame_parser_t parser;
    uint8_t noise = 0x00u;
    uint32_t consumed = 0u;
    ninlil_model_control_frame_result_t result =
        NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;

    REQUIRE(ninlil_model_control_frame_parser_init(
            &parser, payload_storage, sizeof(payload_storage))
        == NINLIL_OK);
    parser.stats.resync_skips = UINT32_MAX;
    parser.stats.bytes_consumed = UINT32_MAX;
    parser.stats.rejects_bad_header = UINT32_MAX;
    REQUIRE(ninlil_model_control_frame_parser_feed(
            &parser, &noise, 1u, &consumed, &result)
        == NINLIL_OK);
    REQUIRE(parser.stats.resync_skips == UINT32_MAX);
    REQUIRE(parser.stats.bytes_consumed == UINT32_MAX);
    REQUIRE(parser.stats.rejects_bad_header == UINT32_MAX);
    return 0;
}

static int test_max_payload_and_buffer_too_small(void)
{
    uint8_t payload[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
    uint8_t frame[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint8_t small[16];
    uint32_t length = 0u;
    ninlil_model_control_frame_fields_t fields;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result;
    ninlil_bytes_view_t encoded;
    uint32_t i;

    for (i = 0u; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)0xa5u;
    }
    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.stream_or_cell_id = 42u;
    fields.sequence = 1000u;
    fields.payload.data = payload;
    fields.payload.length = sizeof(payload);

    REQUIRE(ninlil_model_control_frame_encode(
            &fields, small, sizeof(small), &length)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(length == NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES);

    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame, sizeof(frame), &length)
        == NINLIL_OK);
    encoded.data = frame;
    encoded.length = length;
    REQUIRE(ninlil_model_control_frame_decode(encoded, &view, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
    return 0;
}

static int test_decode_prefix_concat(void)
{
    uint8_t frame_a[128];
    uint8_t frame_b[128];
    uint8_t both[256];
    uint32_t len_a = 0u;
    uint32_t len_b = 0u;
    uint32_t first_len = 0u;
    ninlil_model_control_frame_fields_t fields;
    ninlil_model_control_frame_view_t view;
    ninlil_model_control_frame_result_t result;
    ninlil_bytes_view_t encoded;
    uint8_t pa[] = {1};
    uint8_t pb[] = {2};

    (void)memset(&fields, 0, sizeof(fields));
    fields.type = NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA;
    fields.payload.data = pa;
    fields.payload.length = 1u;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame_a, sizeof(frame_a), &len_a)
        == NINLIL_OK);
    fields.payload.data = pb;
    REQUIRE(ninlil_model_control_frame_encode(
            &fields, frame_b, sizeof(frame_b), &len_b)
        == NINLIL_OK);
    (void)memcpy(both, frame_a, len_a);
    (void)memcpy(both + len_a, frame_b, len_b);
    encoded.data = both;
    encoded.length = len_a + len_b;
    REQUIRE(ninlil_model_control_frame_decode_prefix(
            encoded, &view, &first_len, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK);
    REQUIRE(first_len == len_a);
    return 0;
}

int main(void)
{
    if (test_crc32c_golden() != 0
        || test_type_catalog() != 0
        || test_encode_decode_roundtrip() != 0
        || test_independent_golden_empty_and_ping() != 0
        || test_negative_one_shot() != 0
        || test_alias_table_driven() != 0
        || test_ranges_overlap_boundaries() != 0
        || test_concat_and_incremental() != 0
        || test_noise_resync() != 0
        || test_header_embedded_magic_resync() != 0
        || test_frame_crc_discard_keeps_following_frame() != 0
        || test_resync_skips_trusted_exact_bytes() != 0
        || test_resync_skips_untrusted_exact_bytes() != 0
        || test_parser_memory_budget() != 0
        || test_feed_guard_partial_consumption() != 0
        || test_guard_noise2087_empty_frame() != 0
        || test_guard_boundary_matrix() != 0
        || test_zero_length_feed_invariants() != 0
        || test_no_force_progress_needed() != 0
        || test_reject_mutations_independent() != 0
        || test_stats_saturate() != 0
        || test_max_payload_and_buffer_too_small() != 0
        || test_decode_prefix_concat() != 0) {
        return 1;
    }
    return 0;
}
