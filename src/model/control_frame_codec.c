#include "control_frame_codec.h"

#include <string.h>

/*
 * Portable sizeof ceiling for the parser object alone (ILP32 and LP64).
 * C11 _Static_assert; fails the build if layout drifts above the budget.
 */
_Static_assert(
    sizeof(ninlil_model_control_frame_parser_t)
        <= NINLIL_MODEL_CONTROL_FRAME_PARSER_OBJECT_CEILING_BYTES,
    "control frame parser exceeds portable object ceiling");
_Static_assert(
    sizeof(ninlil_model_control_frame_parser_t)
        >= NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES,
    "control frame parser smaller than window (layout anomaly)");
_Static_assert(
    NINLIL_MODEL_CONTROL_FRAME_PARSER_WORKING_SET_CEILING_BYTES
        == NINLIL_MODEL_CONTROL_FRAME_PARSER_OBJECT_CEILING_BYTES
            + NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES,
    "working-set ceiling arithmetic drift");
_Static_assert(
    NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES
        == NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES,
    "caller payload storage must match MAX_PAYLOAD");

static const uint8_t MAGIC_BYTES[4] = {
    NINLIL_MODEL_CONTROL_FRAME_MAGIC0,
    NINLIL_MODEL_CONTROL_FRAME_MAGIC1,
    NINLIL_MODEL_CONTROL_FRAME_MAGIC2,
    NINLIL_MODEL_CONTROL_FRAME_MAGIC3
};

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

static uint16_t decode_u16_be(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t decode_u32_be(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24)
        | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8)
        | (uint32_t)bytes[3];
}

/*
 * Pure range helper: convert to uintptr_t and use checked end via
 * UINTPTR_MAX subtraction. Never forms one-past-end object pointers via
 * pointer arithmetic on unrelated objects.
 *
 * Returns 1 if ranges must be rejected as overlapping or unrepresentable.
 * Returns 0 if either length is 0 (vacuously disjoint) or ranges are
 * disjoint in the uintptr address space.
 */
static int ranges_overlap(
    const void *a,
    size_t a_len,
    const void *b,
    size_t b_len)
{
    uintptr_t a_start;
    uintptr_t b_start;
    uintptr_t a_end;
    uintptr_t b_end;

    if (a_len == 0u || b_len == 0u) {
        return 0;
    }
    if (a == NULL || b == NULL) {
        return 1;
    }
    a_start = (uintptr_t)a;
    b_start = (uintptr_t)b;
    if (a_len > UINTPTR_MAX - a_start || b_len > UINTPTR_MAX - b_start) {
        return 1;
    }
    a_end = a_start + a_len;
    b_end = b_start + b_len;
    return !(a_end <= b_start || b_end <= a_start);
}

/* length==0 requires data==NULL; length>0 requires data!=NULL. */
static int bytes_view_shape_is_valid(ninlil_bytes_view_t view)
{
    return (view.length == 0u && view.data == NULL)
        || (view.length > 0u && view.data != NULL);
}

static void sat_inc_u32(uint32_t *counter)
{
    if (*counter < UINT32_MAX) {
        *counter += 1u;
    }
}

static void sat_add_u32(uint32_t *counter, uint32_t delta)
{
    if (delta == 0u) {
        return;
    }
    if (*counter > UINT32_MAX - delta) {
        *counter = UINT32_MAX;
    } else {
        *counter += delta;
    }
}

uint32_t ninlil_model_control_frame_crc32c(
    const uint8_t *bytes,
    uint32_t length)
{
    uint32_t crc = UINT32_MAX;
    uint32_t index;

    if (bytes == NULL && length != 0u) {
        return 0u;
    }
    for (index = 0u; index < length; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

int ninlil_model_control_frame_type_is_known(uint8_t type)
{
    return type == NINLIL_MODEL_CONTROL_FRAME_TYPE_PING
        || type == NINLIL_MODEL_CONTROL_FRAME_TYPE_PONG
        || type == NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA
        || type == NINLIL_MODEL_CONTROL_FRAME_TYPE_RESET;
}

static int magic_matches(const uint8_t *bytes)
{
    return bytes[0] == MAGIC_BYTES[0]
        && bytes[1] == MAGIC_BYTES[1]
        && bytes[2] == MAGIC_BYTES[2]
        && bytes[3] == MAGIC_BYTES[3];
}

static int magic_prefix_matches(const uint8_t *bytes, uint32_t prefix_len)
{
    uint32_t i;
    if (prefix_len == 0u || prefix_len > 4u) {
        return 0;
    }
    for (i = 0u; i < prefix_len; ++i) {
        if (bytes[i] != MAGIC_BYTES[i]) {
            return 0;
        }
    }
    return 1;
}

static ninlil_model_control_frame_result_t validate_header_fields(
    const uint8_t *header,
    uint16_t *out_payload_length)
{
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint16_t payload_length;
    uint32_t stored_header_crc;
    uint32_t computed_header_crc;

    if (!magic_matches(header)) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC;
    }
    version = header[4];
    type = header[5];
    flags = decode_u16_be(&header[6]);
    payload_length = decode_u16_be(&header[16]);
    stored_header_crc = decode_u32_be(&header[18]);
    computed_header_crc = ninlil_model_control_frame_crc32c(
        header, NINLIL_MODEL_CONTROL_FRAME_HEADER_PREFIX_BYTES);

    if (version != NINLIL_MODEL_CONTROL_FRAME_VERSION) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_VERSION;
    }
    if (!ninlil_model_control_frame_type_is_known(type)) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_TYPE;
    }
    if (flags != 0u) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FLAGS;
    }
    if ((uint32_t)payload_length
        > NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_LENGTH;
    }
    if (stored_header_crc != computed_header_crc) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_HEADER_CRC;
    }
    *out_payload_length = payload_length;
    return NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
}

static void fill_view_from_parts(
    ninlil_model_control_frame_view_t *out_view,
    const uint8_t *header,
    const uint8_t *payload,
    uint16_t payload_length,
    uint32_t frame_crc)
{
    out_view->version = header[4];
    out_view->type = header[5];
    out_view->flags = decode_u16_be(&header[6]);
    out_view->stream_or_cell_id = decode_u32_be(&header[8]);
    out_view->sequence = decode_u32_be(&header[12]);
    out_view->payload_length = payload_length;
    out_view->header_crc32c = decode_u32_be(&header[18]);
    out_view->frame_crc32c = frame_crc;
    out_view->payload = payload_length == 0u ? NULL : payload;
}

ninlil_status_t ninlil_model_control_frame_encode(
    const ninlil_model_control_frame_fields_t *fields,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    uint32_t header_crc;
    uint32_t frame_crc;
    uint32_t payload_length;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (fields == NULL) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Alias among control objects first (no attacker-controlled payload
     * length in the arithmetic). Bound payload length before using it as a
     * range size so a huge declared length cannot spuriously alias via
     * uintptr wrap/span, and so *out_length is still zeroed on that path.
     */
    if (ranges_overlap(fields, sizeof(*fields), out_length, sizeof(*out_length))
        || ranges_overlap(fields, sizeof(*fields), out_bytes, capacity)
        || ranges_overlap(out_bytes, capacity, out_length, sizeof(*out_length))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (!bytes_view_shape_is_valid(fields->payload)
        || (capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !ninlil_model_control_frame_type_is_known(fields->type)
        || fields->flags != 0u
        || fields->payload.length
            > NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES) {
        *out_length = 0u;
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /*
     * All participating payload ranges after length is known to be <= MAX:
     * fields.payload vs fields object, out_length, out_bytes.
     */
    if (ranges_overlap(fields, sizeof(*fields),
            fields->payload.data, fields->payload.length)
        || ranges_overlap(fields->payload.data, fields->payload.length,
            out_length, sizeof(*out_length))
        || ranges_overlap(fields->payload.data, fields->payload.length,
            out_bytes, capacity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    payload_length = fields->payload.length;
    required = NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES + payload_length;
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }

    out_bytes[0] = MAGIC_BYTES[0];
    out_bytes[1] = MAGIC_BYTES[1];
    out_bytes[2] = MAGIC_BYTES[2];
    out_bytes[3] = MAGIC_BYTES[3];
    out_bytes[4] = NINLIL_MODEL_CONTROL_FRAME_VERSION;
    out_bytes[5] = fields->type;
    encode_u16_be(&out_bytes[6], fields->flags);
    encode_u32_be(&out_bytes[8], fields->stream_or_cell_id);
    encode_u32_be(&out_bytes[12], fields->sequence);
    encode_u16_be(&out_bytes[16], (uint16_t)payload_length);
    header_crc = ninlil_model_control_frame_crc32c(
        out_bytes, NINLIL_MODEL_CONTROL_FRAME_HEADER_PREFIX_BYTES);
    encode_u32_be(&out_bytes[18], header_crc);
    if (payload_length != 0u) {
        (void)memcpy(
            &out_bytes[NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES],
            fields->payload.data,
            payload_length);
    }
    frame_crc = ninlil_model_control_frame_crc32c(
        out_bytes, NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES + payload_length);
    encode_u32_be(
        &out_bytes[NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES + payload_length],
        frame_crc);
    *out_length = required;
    return NINLIL_OK;
}

static ninlil_status_t decode_prefix_impl(
    ninlil_bytes_view_t encoded,
    ninlil_model_control_frame_view_t *out_view,
    uint32_t *out_frame_length,
    ninlil_model_control_frame_result_t *out_result,
    int require_exact)
{
    ninlil_model_control_frame_result_t result;
    uint16_t payload_length;
    uint32_t frame_length;
    uint32_t stored_frame_crc;
    uint32_t computed_frame_crc;
    const uint8_t *payload_ptr;

    if (out_result == NULL || out_view == NULL || out_frame_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Alias first: leave all outs unchanged. */
    if (ranges_overlap(encoded.data, encoded.length, out_view, sizeof(*out_view))
        || ranges_overlap(
            encoded.data, encoded.length, out_frame_length, sizeof(*out_frame_length))
        || ranges_overlap(
            encoded.data, encoded.length, out_result, sizeof(*out_result))
        || ranges_overlap(out_view, sizeof(*out_view),
            out_frame_length, sizeof(*out_frame_length))
        || ranges_overlap(out_view, sizeof(*out_view),
            out_result, sizeof(*out_result))
        || ranges_overlap(out_frame_length, sizeof(*out_frame_length),
            out_result, sizeof(*out_result))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_view, 0, sizeof(*out_view));
        *out_frame_length = 0u;
        *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_TRUNCATED;
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(out_view, 0, sizeof(*out_view));
    *out_frame_length = 0u;
    *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;

    if (encoded.length < NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES) {
        *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_TRUNCATED;
        return NINLIL_OK;
    }

    result = validate_header_fields(encoded.data, &payload_length);
    if (result != NINLIL_MODEL_CONTROL_FRAME_RESULT_OK) {
        *out_result = result;
        return NINLIL_OK;
    }

    frame_length = NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES
        + (uint32_t)payload_length;
    if (encoded.length < frame_length) {
        *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_TRUNCATED;
        return NINLIL_OK;
    }
    if (require_exact && encoded.length != frame_length) {
        *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_LENGTH;
        return NINLIL_OK;
    }

    stored_frame_crc = decode_u32_be(
        &encoded.data[NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES + payload_length]);
    computed_frame_crc = ninlil_model_control_frame_crc32c(
        encoded.data,
        NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES + (uint32_t)payload_length);
    if (stored_frame_crc != computed_frame_crc) {
        *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC;
        return NINLIL_OK;
    }

    payload_ptr = payload_length == 0u
        ? NULL
        : &encoded.data[NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES];
    fill_view_from_parts(
        out_view, encoded.data, payload_ptr, payload_length, stored_frame_crc);
    *out_frame_length = frame_length;
    *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_control_frame_decode(
    ninlil_bytes_view_t encoded,
    ninlil_model_control_frame_view_t *out_view,
    ninlil_model_control_frame_result_t *out_result)
{
    uint32_t frame_length;
    return decode_prefix_impl(
        encoded, out_view, &frame_length, out_result, 1);
}

ninlil_status_t ninlil_model_control_frame_decode_prefix(
    ninlil_bytes_view_t encoded,
    ninlil_model_control_frame_view_t *out_view,
    uint32_t *out_frame_length,
    ninlil_model_control_frame_result_t *out_result)
{
    return decode_prefix_impl(
        encoded, out_view, out_frame_length, out_result, 0);
}

static void parser_note_reject(
    ninlil_model_control_frame_parser_t *parser,
    ninlil_model_control_frame_result_t result)
{
    switch (result) {
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_VERSION:
        sat_inc_u32(&parser->stats.rejects_bad_version);
        sat_inc_u32(&parser->stats.rejects_bad_header);
        break;
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_TYPE:
        sat_inc_u32(&parser->stats.rejects_bad_type);
        sat_inc_u32(&parser->stats.rejects_bad_header);
        break;
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FLAGS:
        sat_inc_u32(&parser->stats.rejects_bad_flags);
        sat_inc_u32(&parser->stats.rejects_bad_header);
        break;
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_LENGTH:
        sat_inc_u32(&parser->stats.rejects_bad_length);
        sat_inc_u32(&parser->stats.rejects_bad_header);
        break;
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_HEADER_CRC:
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC:
        sat_inc_u32(&parser->stats.rejects_bad_header);
        break;
    case NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC:
        sat_inc_u32(&parser->stats.rejects_bad_frame_crc);
        break;
    default:
        break;
    }
}

static void parser_drop_front(
    ninlil_model_control_frame_parser_t *parser,
    uint32_t count)
{
    if (count == 0u) {
        return;
    }
    if (count >= parser->window_length) {
        parser->window_length = 0u;
        return;
    }
    (void)memmove(
        parser->window,
        &parser->window[count],
        (size_t)(parser->window_length - count));
    parser->window_length -= count;
}

/*
 * Compact window to the earliest full magic, else the longest proper
 * magic-prefix suffix. Returns bytes dropped from the previous front.
 * Deterministic; no heap.
 */
static uint32_t parser_compact_to_magic_or_prefix(
    ninlil_model_control_frame_parser_t *parser)
{
    uint32_t length = parser->window_length;
    uint32_t i;
    uint32_t keep;
    uint32_t dropped;

    if (length == 0u) {
        return 0u;
    }

    for (i = 0u; i + 4u <= length; ++i) {
        if (magic_matches(&parser->window[i])) {
            if (i == 0u) {
                return 0u;
            }
            parser_drop_front(parser, i);
            return i;
        }
    }

    keep = 0u;
    for (i = 3u; i >= 1u; --i) {
        if (i > length) {
            continue;
        }
        if (magic_prefix_matches(&parser->window[length - i], i)) {
            keep = i;
            break;
        }
        if (i == 1u) {
            break;
        }
    }
    dropped = length - keep;
    if (dropped == 0u) {
        return 0u;
    }
    if (keep == 0u) {
        parser->window_length = 0u;
    } else {
        (void)memmove(parser->window, &parser->window[dropped], keep);
        parser->window_length = keep;
    }
    return dropped;
}

/*
 * Untrusted reject: drop candidate front byte, then compact residual to the
 * next full magic or longest magic-prefix suffix.
 */
static void parser_resync_untrusted(
    ninlil_model_control_frame_parser_t *parser)
{
    uint32_t dropped;

    if (parser->window_length == 0u) {
        return;
    }
    parser_drop_front(parser, 1u);
    dropped = 1u + parser_compact_to_magic_or_prefix(parser);
    sat_add_u32(&parser->stats.resync_skips, dropped);
}

/*
 * Trusted frame_crc failure: header_crc already fixed length. Discard the
 * entire declared candidate so a following concatenated valid frame is kept.
 * resync_skips counts bytes: frame_length + residual compact drops.
 */
static void parser_discard_trusted_candidate(
    ninlil_model_control_frame_parser_t *parser,
    uint32_t frame_length)
{
    uint32_t discarded;
    uint32_t compact_dropped;

    if (frame_length == 0u) {
        return;
    }
    discarded = frame_length;
    if (discarded > parser->window_length) {
        discarded = parser->window_length;
    }
    parser_drop_front(parser, discarded);

    compact_dropped = 0u;
    if (parser->window_length > 0u) {
        if (parser->window_length >= 4u && magic_matches(parser->window)) {
            /* Residual already aligned. */
        } else if (parser->window_length < 4u
            && magic_prefix_matches(parser->window, parser->window_length)) {
            /* Valid short magic prefix; wait for more bytes. */
        } else {
            compact_dropped = parser_compact_to_magic_or_prefix(parser);
            discarded += compact_dropped;
        }
    }
    sat_add_u32(&parser->stats.resync_skips, discarded);
}

/*
 * Try to extract one frame from window[0..).
 * OK           -> frame emitted
 * NEED_MORE    -> wait for more bytes
 * other        -> resync already applied
 */
static ninlil_model_control_frame_result_t parser_try_window(
    ninlil_model_control_frame_parser_t *parser)
{
    ninlil_model_control_frame_result_t result;
    uint16_t payload_length;
    uint32_t frame_length;
    uint32_t stored_frame_crc;
    uint32_t computed_frame_crc;
    uint32_t dropped;

    if (parser->window_length == 0u) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    }

    if (parser->window_length < 4u) {
        if (!magic_prefix_matches(parser->window, parser->window_length)) {
            dropped = parser_compact_to_magic_or_prefix(parser);
            sat_add_u32(&parser->stats.resync_skips, dropped);
            if (parser->window_length == 0u) {
                return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC;
            }
        }
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    }

    if (!magic_matches(parser->window)) {
        dropped = parser_compact_to_magic_or_prefix(parser);
        sat_add_u32(&parser->stats.resync_skips, dropped);
        sat_inc_u32(&parser->stats.rejects_bad_header);
        if (parser->window_length == 0u) {
            return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC;
        }
        if (parser->window_length < 4u
            || !magic_matches(parser->window)) {
            return NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
        }
        /* Compact found a later full magic; fall through to validate. */
    }

    if (parser->window_length < NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    }

    result = validate_header_fields(parser->window, &payload_length);
    if (result != NINLIL_MODEL_CONTROL_FRAME_RESULT_OK) {
        parser_note_reject(parser, result);
        parser_resync_untrusted(parser);
        return result;
    }

    frame_length = NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES
        + (uint32_t)payload_length;
    if (parser->window_length < frame_length) {
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    }

    stored_frame_crc = decode_u32_be(
        &parser->window[NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES + payload_length]);
    computed_frame_crc = ninlil_model_control_frame_crc32c(
        parser->window,
        NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES + (uint32_t)payload_length);
    if (stored_frame_crc != computed_frame_crc) {
        parser_note_reject(
            parser, NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC);
        parser_discard_trusted_candidate(parser, frame_length);
        return NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC;
    }

    if (payload_length != 0u) {
        (void)memcpy(
            parser->payload_storage,
            &parser->window[NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES],
            payload_length);
    }
    fill_view_from_parts(
        &parser->last_frame,
        parser->window,
        payload_length == 0u ? NULL : parser->payload_storage,
        payload_length,
        stored_frame_crc);
    parser->frame_ready = 1u;
    sat_inc_u32(&parser->stats.frames_accepted);
    parser_drop_front(parser, frame_length);
    return NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
}

ninlil_status_t ninlil_model_control_frame_parser_init(
    ninlil_model_control_frame_parser_t *parser,
    uint8_t *payload_storage,
    uint32_t payload_capacity)
{
    if (parser == NULL
        || payload_storage == NULL
        || payload_capacity < NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES
        || ranges_overlap(parser, sizeof(*parser),
            payload_storage, payload_capacity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(parser, 0, sizeof(*parser));
    parser->payload_storage = payload_storage;
    parser->payload_capacity = payload_capacity;
    return NINLIL_OK;
}

void ninlil_model_control_frame_parser_reset(
    ninlil_model_control_frame_parser_t *parser)
{
    uint8_t *payload_storage;
    uint32_t payload_capacity;

    if (parser == NULL) {
        return;
    }
    payload_storage = parser->payload_storage;
    payload_capacity = parser->payload_capacity;
    (void)memset(parser, 0, sizeof(*parser));
    parser->payload_storage = payload_storage;
    parser->payload_capacity = payload_capacity;
}

ninlil_status_t ninlil_model_control_frame_parser_feed(
    ninlil_model_control_frame_parser_t *parser,
    const uint8_t *input,
    uint32_t input_length,
    uint32_t *out_consumed,
    ninlil_model_control_frame_result_t *out_result)
{
    uint32_t index;
    ninlil_model_control_frame_result_t last_result;
    uint32_t guard;

    if (parser == NULL || out_consumed == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (parser->payload_storage == NULL
        || parser->payload_capacity
            < NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input_length > 0u && input == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Alias first (leave outs AND parser unchanged).
     * Must cover payload_storage vs out_consumed/out_result: writing
     * *out_consumed=0 then memcpy payload can otherwise leave
     * little-endian payload bytes readable as a forged out_consumed.
     */
    if (ranges_overlap(parser, sizeof(*parser), out_consumed, sizeof(*out_consumed))
        || ranges_overlap(parser, sizeof(*parser), out_result, sizeof(*out_result))
        || ranges_overlap(
            out_consumed, sizeof(*out_consumed), out_result, sizeof(*out_result))
        || ranges_overlap(
            parser->payload_storage, parser->payload_capacity,
            out_consumed, sizeof(*out_consumed))
        || ranges_overlap(
            parser->payload_storage, parser->payload_capacity,
            out_result, sizeof(*out_result))
        || ranges_overlap(input, input_length, parser, sizeof(*parser))
        || ranges_overlap(
            input, input_length, parser->payload_storage, parser->payload_capacity)
        || ranges_overlap(input, input_length, out_consumed, sizeof(*out_consumed))
        || ranges_overlap(input, input_length, out_result, sizeof(*out_result))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    *out_consumed = 0u;
    *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
    parser->frame_ready = 0u;
    (void)memset(&parser->last_frame, 0, sizeof(parser->last_frame));

    index = 0u;
    last_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;

    /*
     * Each iteration: try_window, then optionally append one input byte and
     * try_window again so a complete frame assembled by the last append is
     * emitted in the same call (never left stranded until a zero-length feed).
     *
     * Guard exhaustion: after a final try_window, if input remains unconsumed
     * then 0 < *out_consumed < input_length (caller re-feeds residual).
     */
    for (guard = 0u; guard < NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS;
         ++guard) {
        last_result = parser_try_window(parser);
        if (last_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK) {
            *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
            return NINLIL_OK;
        }
        if (last_result != NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE) {
            if (parser->window_length == 0u && index >= input_length) {
                *out_result = last_result;
                return NINLIL_OK;
            }
            /* Residual window after reject: keep draining without new input. */
            continue;
        }

        if (index >= input_length) {
            *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE;
            return NINLIL_OK;
        }
        if (parser->window_length >= NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES) {
            parser_resync_untrusted(parser);
            last_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_LENGTH;
            continue;
        }

        parser->window[parser->window_length] = input[index];
        parser->window_length += 1u;
        sat_inc_u32(&parser->stats.bytes_consumed);
        index += 1u;
        *out_consumed = index;

        /* Immediate try after append — critical for last-byte-of-frame. */
        last_result = parser_try_window(parser);
        if (last_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK) {
            *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
            return NINLIL_OK;
        }
        if (last_result != NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE
            && parser->window_length == 0u
            && index >= input_length) {
            *out_result = last_result;
            return NINLIL_OK;
        }
    }

    /* Guard exhausted: one final try so a complete frame is not stranded. */
    last_result = parser_try_window(parser);
    if (last_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_OK) {
        *out_result = NINLIL_MODEL_CONTROL_FRAME_RESULT_OK;
        return NINLIL_OK;
    }

    if (index < input_length) {
        /*
         * Residual re-feed path: 0 < *out_consumed < input_length.
         *
         * Invariant (well-formed call): this feed started with a need to
         * consume input, and every NEED_MORE path with room appends exactly
         * one byte then try_window. Therefore index==0 with residual input
         * is unreachable after FEED_GUARD_ITERS iterations — do not invent
         * a force-progress append here (would skip the post-append try and
         * break docs §9.6). Tests pin this invariant.
         */
        *out_result = last_result;
        return NINLIL_OK;
    }

    *out_result = (last_result == NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE)
        ? NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE
        : last_result;
    return NINLIL_OK;
}
