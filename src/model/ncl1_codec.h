#ifndef NINLIL_MODEL_NCL1_CODEC_H
#define NINLIL_MODEL_NCL1_CODEC_H

/*
 * U4: NCL1 pure logical-control envelope codec (production-private).
 *
 * Normative layout / catalog / binding:
 *   docs/23-usb-radio-boundary.md §7, §8.1–§8.6
 *   NCG1 payload carrier: docs/19-m3-control-byte-stream-framing.md
 *
 * Exact 26-byte header, max body 998, big-endian, closed message catalog,
 * closed NCG1×NCL1 type binding matrix. Zero heap / VLA. C11.
 *
 * Not public include/ninlil ABI. Not installed. Not authentication.
 * Framing/codec success is not Transport Custody or Application Receipt.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_NCL1_MAGIC0 ((uint8_t)'N')
#define NINLIL_NCL1_MAGIC1 ((uint8_t)'C')
#define NINLIL_NCL1_MAGIC2 ((uint8_t)'L')
#define NINLIL_NCL1_MAGIC3 ((uint8_t)'1')

#define NINLIL_NCL1_LOGICAL_VERSION ((uint8_t)1u)

#define NINLIL_NCL1_HEADER_BYTES ((uint16_t)26u)
#define NINLIL_NCL1_MAX_BODY_BYTES ((uint16_t)998u)
#define NINLIL_NCL1_MAX_MESSAGE_BYTES ((uint16_t)1024u)

/* NCL1 message_type catalog (docs/23 §7.3.1). Independent of NCG1 type. */
#define NINLIL_NCL1_MSG_HELLO ((uint8_t)0x01u)
#define NINLIL_NCL1_MSG_HELLO_ACK ((uint8_t)0x02u)
#define NINLIL_NCL1_MSG_CTRL_ERROR ((uint8_t)0x03u)
#define NINLIL_NCL1_MSG_PING_BODY ((uint8_t)0x10u)
#define NINLIL_NCL1_MSG_PONG_BODY ((uint8_t)0x11u)
#define NINLIL_NCL1_MSG_RESET_BODY ((uint8_t)0x12u)

/* Exact body lengths. */
#define NINLIL_NCL1_BODY_HELLO_BYTES ((uint16_t)8u)
#define NINLIL_NCL1_BODY_HELLO_ACK_BYTES ((uint16_t)8u)
#define NINLIL_NCL1_BODY_CTRL_ERROR_BYTES ((uint16_t)8u)
#define NINLIL_NCL1_BODY_PING_BYTES ((uint16_t)8u)
#define NINLIL_NCL1_BODY_PONG_BYTES ((uint16_t)8u)
#define NINLIL_NCL1_BODY_RESET_BYTES ((uint16_t)4u)

/* HELLO result_code (docs/23 §8.4.1). */
#define NINLIL_NCL1_HELLO_OK ((uint16_t)0x0000u)
#define NINLIL_NCL1_HELLO_VERSION_MISMATCH ((uint16_t)0x0001u)
#define NINLIL_NCL1_HELLO_BUSY ((uint16_t)0x0002u)
#define NINLIL_NCL1_HELLO_DENIED ((uint16_t)0x0003u)

/* RESET reset_code (docs/23 §8.3.1). */
#define NINLIL_NCL1_RESET_SESSION ((uint8_t)0x01u)
#define NINLIL_NCL1_RESET_PARSER ((uint8_t)0x02u)
#define NINLIL_NCL1_RESET_LINK ((uint8_t)0x03u)

/* CTRL_ERROR error_code (docs/23 §8.6.1). */
#define NINLIL_NCL1_ERR_INVALID_NCL1 ((uint16_t)0x0001u)
#define NINLIL_NCL1_ERR_UNKNOWN_MESSAGE ((uint16_t)0x0002u)
#define NINLIL_NCL1_ERR_SESSION_MISMATCH ((uint16_t)0x0003u)
#define NINLIL_NCL1_ERR_STATE ((uint16_t)0x0004u)
#define NINLIL_NCL1_ERR_CAPACITY ((uint16_t)0x0005u)
#define NINLIL_NCL1_ERR_VERSION ((uint16_t)0x0006u)
#define NINLIL_NCL1_ERR_TYPE_BINDING ((uint16_t)0x0007u)

/* NCG1 type values mirrored for binding checks (docs/19). */
#define NINLIL_NCL1_NCG1_TYPE_PING ((uint8_t)0x01u)
#define NINLIL_NCL1_NCG1_TYPE_PONG ((uint8_t)0x02u)
#define NINLIL_NCL1_NCG1_TYPE_DATA ((uint8_t)0x03u)
#define NINLIL_NCL1_NCG1_TYPE_RESET ((uint8_t)0x04u)

/* U4 control protocol version domain (HELLO body; not logical_version). */
#define NINLIL_NCL1_CONTROL_VERSION_V1 ((uint16_t)1u)

typedef uint32_t ninlil_ncl1_status_t;

#define NINLIL_NCL1_OK ((ninlil_ncl1_status_t)0u)
#define NINLIL_NCL1_INVALID_ARGUMENT ((ninlil_ncl1_status_t)1u)
#define NINLIL_NCL1_REJECT_SHORT ((ninlil_ncl1_status_t)2u)
#define NINLIL_NCL1_REJECT_MAGIC ((ninlil_ncl1_status_t)3u)
#define NINLIL_NCL1_REJECT_VERSION ((ninlil_ncl1_status_t)4u)
#define NINLIL_NCL1_REJECT_FLAGS ((ninlil_ncl1_status_t)5u)
#define NINLIL_NCL1_REJECT_BODY_LEN ((ninlil_ncl1_status_t)6u)
#define NINLIL_NCL1_REJECT_UNKNOWN_MESSAGE ((ninlil_ncl1_status_t)7u)
#define NINLIL_NCL1_REJECT_TYPE_BINDING ((ninlil_ncl1_status_t)8u)
#define NINLIL_NCL1_REJECT_BODY_LAYOUT ((ninlil_ncl1_status_t)9u)
#define NINLIL_NCL1_REJECT_RESERVED ((ninlil_ncl1_status_t)10u)
#define NINLIL_NCL1_BUFFER_TOO_SMALL ((ninlil_ncl1_status_t)11u)

typedef struct ninlil_ncl1_header {
    uint8_t logical_version;
    uint8_t message_type;
    uint16_t flags;
    uint32_t request_id;
    uint32_t session_generation;
    uint64_t session_cookie;
    uint16_t body_length;
} ninlil_ncl1_header_t;

typedef struct ninlil_ncl1_hello_body {
    uint16_t min_control_version;
    uint16_t max_control_version;
    uint16_t flags_supported;
    uint16_t reserved;
} ninlil_ncl1_hello_body_t;

typedef struct ninlil_ncl1_hello_ack_body {
    uint16_t selected_control_version;
    uint16_t flags_selected;
    uint16_t result_code;
    uint16_t reserved;
} ninlil_ncl1_hello_ack_body_t;

typedef struct ninlil_ncl1_ping_body {
    uint64_t opaque_echo_token;
} ninlil_ncl1_ping_body_t;

typedef struct ninlil_ncl1_pong_body {
    uint64_t opaque_echo_token;
} ninlil_ncl1_pong_body_t;

typedef struct ninlil_ncl1_reset_body {
    uint8_t reset_code;
    uint8_t reserved0;
    uint8_t reserved1;
    uint8_t reserved2;
} ninlil_ncl1_reset_body_t;

typedef struct ninlil_ncl1_ctrl_error_body {
    uint16_t error_code;
    uint16_t reserved;
    uint32_t related_request_id;
} ninlil_ncl1_ctrl_error_body_t;

typedef struct ninlil_ncl1_message {
    ninlil_ncl1_header_t header;
    union {
        ninlil_ncl1_hello_body_t hello;
        ninlil_ncl1_hello_ack_body_t hello_ack;
        ninlil_ncl1_ping_body_t ping;
        ninlil_ncl1_pong_body_t pong;
        ninlil_ncl1_reset_body_t reset;
        ninlil_ncl1_ctrl_error_body_t ctrl_error;
        /* Opaque for tests; body_length governs when used with raw encode. */
        uint8_t raw[NINLIL_NCL1_MAX_BODY_BYTES];
    } body;
} ninlil_ncl1_message_t;

/* Exact body length for a known message_type; 0 if unknown. */
uint16_t ninlil_ncl1_exact_body_length(uint8_t message_type);

/* 1 if message_type is in the closed catalog. */
int ninlil_ncl1_message_type_is_known(uint8_t message_type);

/*
 * Closed binding matrix §7.3.2: 1 if (ncg1_type, ncl1_message_type) is allowed.
 * Unknown message_type returns 0.
 */
int ninlil_ncl1_type_binding_ok(uint8_t ncg1_type, uint8_t ncl1_message_type);

/* NCG1 type required by message_type; 0 if unknown message_type. */
uint8_t ninlil_ncl1_required_ncg1_type(uint8_t message_type);

/*
 * Encode header+body into out_buf. Writes exactly 26+body_length bytes.
 * Validates body_length against catalog exact lengths and reserved fields
 * for structured messages. Does not check session/request semantic rules.
 */
ninlil_ncl1_status_t ninlil_ncl1_encode(
    const ninlil_ncl1_message_t *msg,
    uint8_t *out_buf,
    size_t out_cap,
    size_t *out_len);

/*
 * Decode exact NCL1 message from payload bytes (NCG1 payload).
 * payload_len must equal 26+body_length from header.
 * Stops at first failing §8.1 steps 2–5 (layout only; no session/state).
 * ncg1_type: if non-zero, also enforce type binding (step 4). Pass 0 to skip
 * binding (pure header/body decode for unit tests).
 */
ninlil_ncl1_status_t ninlil_ncl1_decode(
    const uint8_t *payload,
    size_t payload_len,
    uint8_t ncg1_type,
    ninlil_ncl1_message_t *out_msg);

/*
 * Peek message_type after magic/version/flags/body_length checks only.
 * Used by sequence-layer limited HELLO/ACK peeks. Does not bind type or
 * fully parse body. On OK, *out_type and *out_body_len are set.
 */
ninlil_ncl1_status_t ninlil_ncl1_peek_header(
    const uint8_t *payload,
    size_t payload_len,
    ninlil_ncl1_header_t *out_header);

/*
 * §8.1 step 7: reserved fields exact 0. Pure decode does NOT apply this —
 * session layer calls after step 6 (gen/cookie/request).
 */
ninlil_ncl1_status_t ninlil_ncl1_check_reserved(const ninlil_ncl1_message_t *msg);

/* CTRL_ERROR error_code closed catalog 0x0001..0x0007. */
int ninlil_ncl1_error_code_is_closed(uint16_t error_code);

/* RESET reset_code closed catalog. */
int ninlil_ncl1_reset_code_is_closed(uint8_t reset_code);

/*
 * Valid HELLO bootstrap for SBR / half-open / BOOTSTRAP_EPOCH_RESTART.
 * U4 exact: min=max=1, flags_supported=0, reserved=0, gen=0, cookie=0,
 * request_id≠0. Invalid HELLO must not pass SBR/bootstrap peeks.
 */
int ninlil_ncl1_is_valid_hello_bootstrap(const ninlil_ncl1_message_t *msg);

/*
 * Valid HELLO_ACK structural: flags_selected=0, result/header gen+cookie
 * conventions, OK requires selected_control_version==1.
 */
int ninlil_ncl1_is_structurally_valid_hello_ack(const ninlil_ncl1_message_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MODEL_NCL1_CODEC_H */
