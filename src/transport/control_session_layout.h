#ifndef NINLIL_TRANSPORT_CONTROL_SESSION_LAYOUT_H
#define NINLIL_TRANSPORT_CONTROL_SESSION_LAYOUT_H

/*
 * Production-private complete layout for U3 control_session.
 * Not an installed public ABI. Enables typed object embedding without
 * unsigned-char storage casts (C11 effective type).
 *
 * Sentinel contract: include only via control_session.h (which defines
 * NINLIL_CTRL_SESSION_LAYOUT_ALLOW after public types/macros). Do not
 * include control_session.h from this file (would cycle).
 */
#ifndef NINLIL_CTRL_SESSION_LAYOUT_ALLOW
#error "control_session_layout.h is private; include control_session.h only"
#endif

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"
#include "control_frame_codec.h"

/* Private constants shared by layout and .c (not public ABI). */
#ifndef NINLIL_CS_PRIV_CONSTANTS
#define NINLIL_CS_PRIV_CONSTANTS
#define NINLIL_CS_RX_CHUNK_BYTES ((uint32_t)256u)
#define NINLIL_CS_TRACKED_PHASE_NONE ((uint8_t)0u)
#define NINLIL_CS_TRACKED_PHASE_INTENT ((uint8_t)1u)
#define NINLIL_CS_TRACKED_PHASE_WIRE ((uint8_t)2u)
#define NINLIL_CS_TRACKED_PHASE_TERMINAL ((uint8_t)3u)
#endif

typedef struct ninlil_cs_ingress_entry {
    uint8_t type;
    uint8_t reserved0;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    uint16_t payload_length;
    uint16_t payload_off;
} ninlil_cs_ingress_entry_t;

typedef struct ninlil_cs_intent_entry {
    uint8_t type;
    uint8_t reserved0;
    uint16_t flags;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
    uint16_t payload_length;
    uint16_t payload_off;
    uint64_t tracked_token; /* 0 = legacy untracked intent */
} ninlil_cs_intent_entry_t;

struct ninlil_ctrl_session {
    uint32_t magic;
    ninlil_ctrl_session_state_t state;
    uint32_t reserved_pad;
    ninlil_byte_stream_t *stream;
    uint64_t bound_generation;

    ninlil_model_control_frame_parser_t parser;
    uint8_t parser_payload[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];

    ninlil_cs_ingress_entry_t ingress[NINLIL_CTRL_SESSION_INGRESS_MAX_ENTRIES];
    uint8_t ingress_pool[NINLIL_CTRL_SESSION_INGRESS_BYTE_CAP];
    uint32_t ingress_head;
    uint32_t ingress_count;
    uint32_t ingress_bytes;

    ninlil_cs_intent_entry_t intent[NINLIL_CTRL_SESSION_TX_INTENT_MAX_ENTRIES];
    uint8_t intent_pool[NINLIL_CTRL_SESSION_TX_INTENT_BYTE_CAP];
    uint32_t intent_head;
    uint32_t intent_count;
    uint32_t intent_bytes;

    /* Full encoded frame owned until all-or-none C1 write accepts it. */
    uint8_t tx_wire[NINLIL_MODEL_CONTROL_FRAME_MAX_BYTES];
    uint32_t tx_wire_len;
    uint32_t tx_wire_off;
    uint64_t tx_wire_tracked_token; /* nonzero if wire holds tracked frame */

    uint8_t rx_chunk[NINLIL_CS_RX_CHUNK_BYTES];

    /* Logical epoch claim (0 epoch_active / claimed=0 ⇒ no claim). */
    uint8_t epoch_claimed;
    uint8_t reserved_epoch[7];
    uint64_t epoch_active;
    uint64_t epoch_bound_gen;
    uint64_t epoch_next; /* next id to mint; 0 ⇒ exhausted */

    /* Tracked TX slot (raw outstanding max 1). */
    uint8_t tracked_phase;
    uint8_t reserved_tracked[3];
    ninlil_ctrl_session_tx_resolution_t tracked_resolution;
    uint64_t tracked_token;
    uint64_t token_next; /* next token to mint; 0 ⇒ exhausted */

    ninlil_ctrl_session_stats_t stats;
    ninlil_ctrl_session_error_t last_error;
    uint8_t had_prior_fence;
    uint8_t reserved_tail[7];
};

#endif /* NINLIL_TRANSPORT_CONTROL_SESSION_LAYOUT_H */
