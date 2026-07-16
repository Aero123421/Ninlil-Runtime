#ifndef NINLIL_MODEL_CONTROL_FRAME_CODEC_H
#define NINLIL_MODEL_CONTROL_FRAME_CODEC_H

/*
 * M3-slice: Controller↔Cell Agent control byte-stream framing (NCG1).
 *
 * Production-candidate portable implementation, kept production-private
 * (not installed; not a public C ABI). Wire layout and this header are not
 * publicized; see docs/19 for publicization conditions.
 *
 * Normative layout / resync / memory: docs/19-m3-control-byte-stream-framing.md
 *
 * Framing success is not transport custody, Application Receipt, or
 * cryptographic authenticity. Does not claim USB/TCP transport, Cell Agent
 * task, security, or M3 complete.
 *
 * Output / alias contract (all encode/decode/feed entry points):
 * - Participating input and output ranges must be pairwise disjoint.
 * - Alias or address-overflow on any participating range:
 *     return NINLIL_E_INVALID_ARGUMENT without modifying any output object
 *     (including *out_length / *out_consumed / *out_result / view).
 * - After alias is ruled out, non-alias INVALID_ARGUMENT / framing results
 *   may zero or set documented outputs.
 */

#include <stddef.h>
#include <stdint.h>

#include <ninlil/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MODEL_CONTROL_FRAME_MAGIC0 ((uint8_t)'N')
#define NINLIL_MODEL_CONTROL_FRAME_MAGIC1 ((uint8_t)'C')
#define NINLIL_MODEL_CONTROL_FRAME_MAGIC2 ((uint8_t)'G')
#define NINLIL_MODEL_CONTROL_FRAME_MAGIC3 ((uint8_t)'1')

#define NINLIL_MODEL_CONTROL_FRAME_VERSION ((uint8_t)1u)

#define NINLIL_MODEL_CONTROL_FRAME_TYPE_PING  ((uint8_t)0x01u)
#define NINLIL_MODEL_CONTROL_FRAME_TYPE_PONG  ((uint8_t)0x02u)
#define NINLIL_MODEL_CONTROL_FRAME_TYPE_DATA  ((uint8_t)0x03u)
#define NINLIL_MODEL_CONTROL_FRAME_TYPE_RESET ((uint8_t)0x04u)

#define NINLIL_MODEL_CONTROL_FRAME_HEADER_PREFIX_BYTES ((uint32_t)18u)
#define NINLIL_MODEL_CONTROL_FRAME_HEADER_BYTES ((uint32_t)22u)
#define NINLIL_MODEL_CONTROL_FRAME_CRC_BYTES ((uint32_t)4u)
#define NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES ((uint32_t)26u)
#define NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES ((uint32_t)1024u)
#define NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES \
    (NINLIL_MODEL_CONTROL_FRAME_OVERHEAD_BYTES \
        + NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES)

/*
 * Fixed memory budget (portable; no heap / no VLA):
 * - PARSER_OBJECT_CEILING_BYTES: sizeof(parser) upper bound on ILP32/LP64.
 *   Measured LP64 sizeof is 1144; ILP32 estimate ≤1132. Ceiling 1152.
 * - CALLER_PAYLOAD_STORAGE_BYTES: separate caller-owned buffer (≥ MAX_PAYLOAD).
 * - WORKING_SET_CEILING = object ceiling + payload storage (parser does not
 *   embed the payload copy buffer).
 */
#define NINLIL_MODEL_CONTROL_FRAME_PARSER_OBJECT_CEILING_BYTES ((size_t)1152u)
#define NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES \
    ((size_t)NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES)
#define NINLIL_MODEL_CONTROL_FRAME_PARSER_WORKING_SET_CEILING_BYTES \
    (NINLIL_MODEL_CONTROL_FRAME_PARSER_OBJECT_CEILING_BYTES \
        + NINLIL_MODEL_CONTROL_FRAME_CALLER_PAYLOAD_STORAGE_BYTES)

/*
 * Single feed() iteration budget. Exhaustion may leave
 * 0 < *out_consumed < input_length; caller must re-feed residual.
 */
#define NINLIL_MODEL_CONTROL_FRAME_FEED_GUARD_ITERS \
    (NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES * 4u)

/* Detailed framing outcomes (private). API misuse still uses ninlil_status_t. */
typedef uint32_t ninlil_model_control_frame_result_t;

#define NINLIL_MODEL_CONTROL_FRAME_RESULT_OK \
    ((ninlil_model_control_frame_result_t)0u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_NEED_MORE \
    ((ninlil_model_control_frame_result_t)1u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_MAGIC \
    ((ninlil_model_control_frame_result_t)2u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_VERSION \
    ((ninlil_model_control_frame_result_t)3u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_TYPE \
    ((ninlil_model_control_frame_result_t)4u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FLAGS \
    ((ninlil_model_control_frame_result_t)5u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_LENGTH \
    ((ninlil_model_control_frame_result_t)6u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_HEADER_CRC \
    ((ninlil_model_control_frame_result_t)7u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_BAD_FRAME_CRC \
    ((ninlil_model_control_frame_result_t)8u)
#define NINLIL_MODEL_CONTROL_FRAME_RESULT_TRUNCATED \
    ((ninlil_model_control_frame_result_t)9u)

typedef struct ninlil_model_control_frame_view {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    uint16_t payload_length;
    uint32_t header_crc32c;
    uint32_t frame_crc32c;
    /* Points into caller-owned encode buffer or parser payload buffer. */
    const uint8_t *payload;
} ninlil_model_control_frame_view_t;

typedef struct ninlil_model_control_frame_fields {
    uint8_t type;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    ninlil_bytes_view_t payload;
} ninlil_model_control_frame_fields_t;

/*
 * Long-running counters saturate at UINT32_MAX (no wrap).
 *
 * resync_skips: total bytes discarded by resync paths (unit = bytes, not
 * events). Untrusted: 1 + residual compact drops. Trusted frame_crc fail:
 * frame_length + residual compact drops.
 */
typedef struct ninlil_model_control_frame_parser_stats {
    uint32_t frames_accepted;
    uint32_t bytes_consumed;
    uint32_t resync_skips;
    uint32_t rejects_bad_header;
    uint32_t rejects_bad_frame_crc;
    uint32_t rejects_bad_type;
    uint32_t rejects_bad_version;
    uint32_t rejects_bad_flags;
    uint32_t rejects_bad_length;
} ninlil_model_control_frame_parser_stats_t;

/*
 * Incremental parser with fixed sliding window (no heap / no VLA).
 * Accepted payload is copied into caller-owned payload_storage
 * (capacity >= MAX_PAYLOAD_BYTES). That storage is NOT inside this object;
 * see WORKING_SET_CEILING_BYTES.
 *
 * Resync (docs/19):
 * - Untrusted reject: drop leading candidate byte then compact residual to
 *   next full magic or longest magic-prefix suffix; resync_skips += bytes.
 * - Trusted frame_crc failure: discard entire declared candidate then compact
 *   residual if needed; resync_skips += frame_length + compact drops.
 */
typedef struct ninlil_model_control_frame_parser {
    uint8_t window[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t window_length;
    uint8_t *payload_storage;
    uint32_t payload_capacity;
    ninlil_model_control_frame_parser_stats_t stats;
    ninlil_model_control_frame_view_t last_frame;
    uint8_t frame_ready;
    uint8_t reserved_zero[3];
} ninlil_model_control_frame_parser_t;

/* Castagnoli CRC32C; same polynomial as Runtime/Domain store envelopes. */
uint32_t ninlil_model_control_frame_crc32c(
    const uint8_t *bytes,
    uint32_t length);

int ninlil_model_control_frame_type_is_known(uint8_t type);

/*
 * Encode one complete frame into out_bytes.
 * Ranges must be pairwise disjoint. No heap.
 * On alias: leave *out_length unchanged.
 * On other INVALID after alias check: *out_length = 0.
 * On BUFFER_TOO_SMALL: *out_length = required size.
 */
ninlil_status_t ninlil_model_control_frame_encode(
    const ninlil_model_control_frame_fields_t *fields,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * One-shot decode of exact one complete frame (no trailing bytes).
 * On success, out_view->payload borrows encoded[header..).
 * On alias: leave out_view / *out_result unchanged.
 */
ninlil_status_t ninlil_model_control_frame_decode(
    ninlil_bytes_view_t encoded,
    ninlil_model_control_frame_view_t *out_view,
    ninlil_model_control_frame_result_t *out_result);

/*
 * One-shot decode that tolerates trailing bytes after the first frame.
 * *out_frame_length is set to consumed frame size on OK.
 * On alias: leave all outs unchanged.
 */
ninlil_status_t ninlil_model_control_frame_decode_prefix(
    ninlil_bytes_view_t encoded,
    ninlil_model_control_frame_view_t *out_view,
    uint32_t *out_frame_length,
    ninlil_model_control_frame_result_t *out_result);

ninlil_status_t ninlil_model_control_frame_parser_init(
    ninlil_model_control_frame_parser_t *parser,
    uint8_t *payload_storage,
    uint32_t payload_capacity);

void ninlil_model_control_frame_parser_reset(
    ninlil_model_control_frame_parser_t *parser);

/*
 * Feed 0..n bytes. May accept at most one frame per call.
 * Residual input is unconsumed when:
 * - a frame was accepted mid-buffer, or
 * - FEED_GUARD_ITERS was exhausted (long noise / pathological resync);
 *   then 0 < *out_consumed < input_length and the caller must re-feed.
 *
 * On alias: leave *out_consumed / *out_result unchanged.
 * When a frame is ready, parser->frame_ready != 0 and last_frame is valid
 * until the next feed/reset (payload points at payload_storage).
 */
ninlil_status_t ninlil_model_control_frame_parser_feed(
    ninlil_model_control_frame_parser_t *parser,
    const uint8_t *input,
    uint32_t input_length,
    uint32_t *out_consumed,
    ninlil_model_control_frame_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MODEL_CONTROL_FRAME_CODEC_H */
