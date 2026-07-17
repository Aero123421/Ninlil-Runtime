#ifndef NINLIL_TRANSPORT_LOGICAL_SESSION_LAYOUT_H
#define NINLIL_TRANSPORT_LOGICAL_SESSION_LAYOUT_H

/*
 * Production-private complete layout for U4 logical_session.
 * Not an installed public ABI. Enables typed object embedding without
 * unsigned-char storage casts (C11 effective type).
 *
 * Sentinel contract: include only via logical_session.h (which defines
 * NINLIL_LOGICAL_SESSION_LAYOUT_ALLOW after public types/macros).
 *
 * All private constants/types use NINLIL_LS_* / ninlil_ls_* prefixes
 * (OSS namespace hygiene; no global-generic names).
 */
#ifndef NINLIL_LOGICAL_SESSION_LAYOUT_ALLOW
#error "logical_session_layout.h is private; include logical_session.h only"
#endif

#include <stddef.h>
#include <stdint.h>

#include "control_session.h"
#include "control_frame_codec.h"
#include "ncl1_codec.h"

/* Private constants shared by layout and .c (not public ABI). */
#ifndef NINLIL_LS_PRIV_CONSTANTS
#define NINLIL_LS_PRIV_CONSTANTS
#define NINLIL_LS_INFLIGHT_NONE ((uint8_t)0u)
#define NINLIL_LS_INFLIGHT_HELLO ((uint8_t)1u)
#define NINLIL_LS_INFLIGHT_PING ((uint8_t)2u)
#define NINLIL_LS_NOTICE_EMPTY ((uint8_t)0u)
#define NINLIL_LS_NOTICE_PENDING ((uint8_t)1u)
#define NINLIL_LS_NOTICE_ACCEPTED ((uint8_t)2u)
#define NINLIL_LS_TRACKED_NONE ((uint8_t)0u)
#define NINLIL_LS_TRACKED_ORDINARY ((uint8_t)1u)
#define NINLIL_LS_TRACKED_NOTICE ((uint8_t)2u)
#define NINLIL_LS_ACTION_META_BYTES ((size_t)48u)
#endif

typedef struct ninlil_ls_inflight_slot {
    uint8_t kind;
    uint8_t reserved0;
    uint16_t reserved1;
    uint32_t request_id;
    uint64_t deadline_ms;
    uint64_t opaque; /* PING token */
} ninlil_ls_inflight_slot_t;

typedef struct ninlil_ls_tx_action {
    ninlil_logical_session_tx_kind_t kind;
    uint8_t ncg1_type;
    uint8_t reserved0;
    uint16_t reserved1;
    uint32_t sequence; /* assigned at submit from next_tx_seq; commit later */
    uint32_t request_id;
    uint32_t session_generation;
    uint64_t session_cookie;
    uint16_t body_length;
    uint8_t body[32]; /* max structured body used here is 8 */
    uint8_t message_type;
    uint8_t gen_burned; /* HELLO_ACK OK: generation already burned */
    uint16_t hello_result;
    uint64_t opaque;
    uint8_t reset_code;
    uint8_t continuity_notice; /* 1 if this ordinary path is NOT used for notice */
    uint8_t reserved2[2];
} ninlil_ls_tx_action_t;

typedef struct ninlil_ls_notice_slot {
    uint8_t phase; /* NINLIL_LS_NOTICE_* */
    uint8_t reset_code;
    uint16_t reserved0;
    uint32_t request_id;
    uint32_t session_generation;
    uint64_t session_cookie;
    uint32_t sequence; /* assigned at submit */
} ninlil_ls_notice_slot_t;

struct ninlil_logical_session {
    uint32_t magic;
    ninlil_logical_session_role_t role;
    ninlil_logical_session_state_t state;

    ninlil_logical_session_cookie_rng_fn cookie_rng;
    void *cookie_rng_ctx;
    ninlil_logical_session_jitter_fn jitter_fn;
    void *jitter_ctx;

    uint64_t now_ms;
    int have_now; /* 0 until first successful step clock accept */

    /* Sequence epochs (local). */
    uint32_t next_tx_seq;
    int have_rx_seq;
    uint32_t last_rx_seq;

    /* Active session (0/0 when not ACTIVE). */
    uint32_t active_generation;
    uint64_t active_cookie;
    uint32_t last_issued_generation;
    uint32_t burned_generation_count;

    /* Request allocator (skips 0). */
    uint32_t request_next;

    ninlil_ls_inflight_slot_t inflight[NINLIL_LOGICAL_SESSION_INFLIGHT_MAX];
    uint32_t inflight_count;

    /* Ordinary TX action ring. */
    ninlil_ls_tx_action_t actions[NINLIL_LOGICAL_SESSION_TX_ACTION_MAX];
    uint32_t action_head;
    uint32_t action_count;

    ninlil_ls_notice_slot_t notice;

    /* Engine-owned tracked TX. */
    uint8_t tracked_kind; /* NINLIL_LS_TRACKED_* */
    uint8_t tracked_tx_kind; /* logical kind for commit side-effects */
    uint8_t reserved_tr[2];
    ninlil_ctrl_session_tx_token_t tracked_token;
    uint32_t tracked_sequence;
    uint32_t tracked_request_id;
    uint32_t tracked_generation;
    uint64_t tracked_cookie;
    uint16_t tracked_hello_result;
    uint8_t tracked_gen_burned;
    uint8_t tracked_reset_code;
    uint64_t tracked_opaque;

    ninlil_logical_session_tx_commit_t last_tx_commit;
    ninlil_logical_session_tx_kind_t last_tx_kind;
    uint32_t last_tx_sequence;

    /* Liveness / HELLO timers (monotonic ms). 0 = inactive where noted. */
    int hello_timer_armed;
    uint64_t hello_deadline_ms;
    uint32_t hello_retry_delay_ms;
    int rehello_armed;
    uint64_t rehello_deadline_ms;

    int ping_inflight;
    uint64_t ping_deadline_ms; /* pong timeout */
    uint64_t ping_eligible_at_ms;
    uint32_t pong_miss_streak;
    int first_ping_armed; /* ACTIVE just entered */

    /* CTRL_ERROR rate window (sliding 1s, max 8). */
    uint64_t ctrl_error_times[NINLIL_LOGICAL_SESSION_CTRL_ERROR_RATE_MAX];
    uint32_t ctrl_error_count;
    uint32_t logical_reject_streak;

    ninlil_logical_session_counters_t counters;

    /* Embedded U3 (sole ownership). */
    ninlil_ctrl_session_object_t u3_obj;
    ninlil_ctrl_session_t *u3;
    ninlil_ctrl_session_logical_epoch_t epoch;
    int epoch_claimed;

    /* Scratch for encode / take_rx. */
    uint8_t ncl1_scratch[NINLIL_NCL1_MAX_MESSAGE_BYTES];
    uint8_t rx_payload[NINLIL_MODEL_CONTROL_FRAME_MAX_PAYLOAD_BYTES];
};

#endif /* NINLIL_TRANSPORT_LOGICAL_SESSION_LAYOUT_H */
