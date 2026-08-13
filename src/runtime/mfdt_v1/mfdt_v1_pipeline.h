/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Multi-frame pipeline: real outbound ownership + inbound-driven progress.
 * No local echo / fake completion. Private, default-OFF.
 */
#ifndef NINLIL_MFDT_V1_PIPELINE_H
#define NINLIL_MFDT_V1_PIPELINE_H

#include "mfdt_v1.h"
#include "mfdt_v1_ncl1.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* U6 single-frame ApplicationData upper bound (ADR-0021). Above ⇒ MFDT. */
#define NINLIL_MFDT_V1_U6_SINGLE_FRAME_MAX ((uint32_t)926u)

/* send_fn return: 0 OK, NINLIL_MFDT_V1_ERR_BUSY = WOULD_BLOCK, other error. */
typedef int (*ninlil_mfdt_v1_wire_send_fn)(void *user, const uint8_t *ncl1_msg,
                                           size_t ncl1_len);

typedef enum ninlil_mfdt_v1_pipeline_action {
    NINLIL_MFDT_V1_PIPE_ACTION_NONE = 0,
    NINLIL_MFDT_V1_PIPE_ACTION_CONTROL = 1,
    NINLIL_MFDT_V1_PIPE_ACTION_CHUNK = 2
} ninlil_mfdt_v1_pipeline_action_t;

/* Sender wire phases (await remote accept before advance). */
#define NINLIL_MFDT_V1_PHASE_IDLE            ((uint8_t)0u)
#define NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC   ((uint8_t)1u)
#define NINLIL_MFDT_V1_PHASE_SEND_PAGES      ((uint8_t)2u)
#define NINLIL_MFDT_V1_PHASE_WAIT_PAGE_ACC   ((uint8_t)3u)
#define NINLIL_MFDT_V1_PHASE_SEND_CHUNKS     ((uint8_t)4u)
#define NINLIL_MFDT_V1_PHASE_WAIT_CHUNK_ACC  ((uint8_t)5u)
#define NINLIL_MFDT_V1_PHASE_SEND_FIN        ((uint8_t)6u)
#define NINLIL_MFDT_V1_PHASE_WAIT_XFER_ACC   ((uint8_t)7u)
#define NINLIL_MFDT_V1_PHASE_COMPLETE        ((uint8_t)8u)
#define NINLIL_MFDT_V1_PHASE_REISSUE_OPEN     ((uint8_t)9u)

/* Deterministic private default; callers may lower/raise for their bearer. */
#define NINLIL_MFDT_V1_RESPONSE_TIMEOUT_MS ((uint64_t)5000ull)

typedef struct ninlil_mfdt_v1_pipeline {
    ninlil_mfdt_v1_engine_t *tx; /* local sender engine (nullable) */
    ninlil_mfdt_v1_engine_t *rx; /* local receiver engine (nullable) */
    ninlil_mfdt_v1_wire_send_fn send_fn; /* optional immediate sink */
    void *send_user;
    uint32_t session_generation;
    uint64_t session_cookie;
    uint64_t next_request_id;
    uint8_t transfer_id[16];
    uint8_t publication_token[16];
    uint8_t complete; /* 1 only after real TRANSFER_ACCEPT / handoff */
    uint8_t aborted;
    /* Single-frame outbound ownership (producer fills; take/send_fn drains). */
    uint8_t outbox[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint16_t outbox_len;
    uint8_t outbox_valid;
    /*
     * Exact metadata for the response produced by the most recent admitted
     * receiver ingress.  The Host coordinator must never infer an NRC1 replay
     * merely because no FULL happened.
     */
    uint8_t last_ingress_response_valid;
    uint8_t last_ingress_response_from_nrc1_hit;
    uint8_t last_ingress_response_state_mutation;
    uint8_t last_ingress_response_full_count;
    /* Exact terminal REJECT left an outstanding CHUNK wait. */
    uint8_t last_chunk_fence_released;
    /* Sender step state */
    uint8_t phase;
    uint16_t next_page;
    uint16_t next_chunk;
    ninlil_mfdt_v1_geometry_t geo;
    /*
     * Outstanding request awaiting accept: rid + type + index must match
     * inbound NCL1 exactly or phase/progress/durable stay unchanged.
     */
    uint8_t has_outstanding;
    uint8_t outstanding_type; /* NINLIL_MFDT_V1_MSG_* of request */
    uint16_t outstanding_index; /* page or chunk index when applicable */
    uint64_t outstanding_rid;
    uint64_t now_ms;
    uint64_t response_timeout_ms;
    uint64_t outstanding_deadline_ms;
    /*
     * Exact last semantic request frame. It is volatile retransmission
     * material only; durable progress remains in NM3S. A cold OPEN restart
     * reconstructs this from the durable OPEN body.
     */
    uint8_t retry_frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint16_t retry_frame_len;
} ninlil_mfdt_v1_pipeline_t;

void ninlil_mfdt_v1_pipeline_init(ninlil_mfdt_v1_pipeline_t *p,
                                  ninlil_mfdt_v1_engine_t *tx,
                                  ninlil_mfdt_v1_engine_t *rx,
                                  ninlil_mfdt_v1_wire_send_fn send_fn,
                                  void *send_user, uint32_t session_generation,
                                  uint64_t session_cookie);

int ninlil_mfdt_v1_pipeline_requires_mfdt(const ninlil_mfdt_v1_config_t *cfg,
                                          uint32_t application_data_len);

/*
 * Sender begin: durable OPEN (NM3S FULL) + queue first OPEN frame.
 * Does NOT complete transfer. Does NOT feed local rx.
 * complete remains 0 until remote TRANSFER_ACCEPT.
 */
int ninlil_mfdt_v1_pipeline_sender_begin(
    ninlil_mfdt_v1_pipeline_t *p, const uint8_t transfer_id[16],
    const uint8_t *data, uint32_t data_len);
int ninlil_mfdt_v1_pipeline_sender_begin_with_metadata(
    ninlil_mfdt_v1_pipeline_t *p, const uint8_t transfer_id[16],
    const uint8_t *data, uint32_t data_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata);

/*
 * Produce next outbound frame when not awaiting accept and outbox empty.
 * Returns 0 if progress or waiting; ERR_BUSY if outbox still owned;
 * ERR_STATE if not a sender session.
 */
int ninlil_mfdt_v1_pipeline_sender_pump(ninlil_mfdt_v1_pipeline_t *p);

/*
 * Host coordinator scheduling boundary. Control pumping may advance into
 * SEND_CHUNKS but never emits a CHUNK_OFFER. Only emit_selected_chunk emits
 * one selected CHUNK_OFFER, and one call emits at most one.
 */
ninlil_mfdt_v1_pipeline_action_t
ninlil_mfdt_v1_pipeline_next_action(
    const ninlil_mfdt_v1_pipeline_t *pipeline);
int ninlil_mfdt_v1_pipeline_pump_control(
    ninlil_mfdt_v1_pipeline_t *pipeline);
int ninlil_mfdt_v1_pipeline_emit_selected_chunk(
    ninlil_mfdt_v1_pipeline_t *pipeline);

/*
 * Advance the deterministic response timer. A timeout retry first FULLs the
 * owner retry-budget decrement, then emits the same semantic request with a
 * fresh request ID. No charge occurs while an outbox frame is still owned.
 */
void ninlil_mfdt_v1_pipeline_set_response_timeout(
    ninlil_mfdt_v1_pipeline_t *p, uint64_t timeout_ms);
int ninlil_mfdt_v1_pipeline_tick(ninlil_mfdt_v1_pipeline_t *p,
                                 uint64_t now_ms);

/* 1 if outbox holds a frame ready for bearer dispatch. */
int ninlil_mfdt_v1_pipeline_outbox_pending(const ninlil_mfdt_v1_pipeline_t *p);

/*
 * Copy+clear owned outbox frame. Returns 0; *out_len=0 if empty.
 * ERR_CAPACITY if cap too small (frame retained).
 */
int ninlil_mfdt_v1_pipeline_take_outbound(ninlil_mfdt_v1_pipeline_t *p,
                                          uint8_t *out, size_t cap,
                                          size_t *out_len);

/*
 * Alias: historical name — now only begins (NM3S + OPEN queue). Not complete-all.
 * Prefer sender_begin + pump + real inbound accepts.
 */
int ninlil_mfdt_v1_pipeline_send_application_data(
    ninlil_mfdt_v1_pipeline_t *p, const uint8_t transfer_id[16],
    const uint8_t *data, uint32_t data_len);

/*
 * Ingress one real NCL1 payload. Requests → local rx; responses → local tx.
 * Receiver responses are queued to outbox (never auto-applied to peer).
 * A receiver semantic error may coexist with an exact owned REJECT/BUSY
 * outbox; Host coordination treats ownership of that protocol outcome as
 * successful transport processing.
 */
int ninlil_mfdt_v1_pipeline_on_ncl1_ingress(ninlil_mfdt_v1_pipeline_t *p,
                                            const uint8_t *ncl1_payload,
                                            size_t ncl1_len);

/* Terminal after real complete on the role that is ready. */
int ninlil_mfdt_v1_pipeline_finish_terminal(ninlil_mfdt_v1_pipeline_t *p);

/*
 * Cold-process sender rehydrate after engine restart_scan_transfer.
 * Derives phase/next_page/next_chunk/geo/next_request_id solely from durable
 * engine state (page/chunk bitmaps + state_code + content length + NRC1).
 * Zero copy from a previous pipeline process image.
 */
int ninlil_mfdt_v1_pipeline_sender_rehydrate(ninlil_mfdt_v1_pipeline_t *p,
                                             ninlil_mfdt_v1_engine_t *tx,
                                             const uint8_t transfer_id[16],
                                             uint32_t session_generation,
                                             uint64_t session_cookie);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_PIPELINE_H */
