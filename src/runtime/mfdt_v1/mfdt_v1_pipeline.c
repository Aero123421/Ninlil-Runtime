/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Real outbound ownership + inbound-driven progress. No local echo.
 */
#include "mfdt_v1_pipeline.h"

#include <string.h>
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
#include <stdio.h>
#endif

void ninlil_mfdt_v1_pipeline_init(ninlil_mfdt_v1_pipeline_t *p,
                                  ninlil_mfdt_v1_engine_t *tx,
                                  ninlil_mfdt_v1_engine_t *rx,
                                  ninlil_mfdt_v1_wire_send_fn send_fn,
                                  void *send_user, uint32_t session_generation,
                                  uint64_t session_cookie)
{
    if (p == NULL) {
        return;
    }
    ninlil_mfdt_v1_memzero(p, sizeof(*p));
    p->tx = tx;
    p->rx = rx;
    p->send_fn = send_fn;
    p->send_user = send_user;
    p->session_generation = session_generation;
    p->session_cookie = session_cookie;
    p->next_request_id = 1ull;
    p->phase = NINLIL_MFDT_V1_PHASE_IDLE;
    p->response_timeout_ms = NINLIL_MFDT_V1_RESPONSE_TIMEOUT_MS;
}

int ninlil_mfdt_v1_pipeline_requires_mfdt(const ninlil_mfdt_v1_config_t *cfg,
                                          uint32_t application_data_len)
{
    if (cfg == NULL) {
        return 0;
    }
    if (cfg->policy != NINLIL_MFDT_V1_POLICY_ON) {
        return 0;
    }
    if (cfg->mfdt_admission_version !=
        NINLIL_MFDT_V1_ADMISSION_VERSION) {
        return 0;
    }
    if (cfg->mfdt_capability == 0u) {
        return 0;
    }
    return application_data_len > NINLIL_MFDT_V1_U6_SINGLE_FRAME_MAX ? 1 : 0;
}

static uint64_t next_rid(ninlil_mfdt_v1_pipeline_t *p)
{
    uint64_t r = p->next_request_id;
    if (p->next_request_id != UINT64_MAX) {
        p->next_request_id += 1ull;
    }
    return r;
}

static void set_outstanding(ninlil_mfdt_v1_pipeline_t *p, uint8_t type,
                            uint64_t rid, uint16_t index)
{
    p->has_outstanding = 1u;
    p->outstanding_type = type;
    p->outstanding_rid = rid;
    p->outstanding_index = index;
    if (UINT64_MAX - p->now_ms < p->response_timeout_ms) {
        p->outstanding_deadline_ms = UINT64_MAX;
    } else {
        p->outstanding_deadline_ms = p->now_ms + p->response_timeout_ms;
    }
}

static int check_outstanding(const ninlil_mfdt_v1_pipeline_t *p, uint8_t type,
                             uint64_t rid, int check_index, uint16_t index)
{
    if (p == NULL || !p->has_outstanding) {
        return 0;
    }
    if (p->outstanding_type != type || p->outstanding_rid != rid) {
        return 0;
    }
    if (check_index && p->outstanding_index != index) {
        return 0;
    }
    return 1;
}

static uint16_t request_stage(uint8_t request_type)
{
    switch (request_type) {
    case NINLIL_MFDT_V1_MSG_OPEN:
        return 1u;
    case NINLIL_MFDT_V1_MSG_MANIFEST_PAGE:
        return 2u;
    case NINLIL_MFDT_V1_MSG_CHUNK_OFFER:
        return 3u;
    case NINLIL_MFDT_V1_MSG_FINALIZE:
        return 4u;
    case NINLIL_MFDT_V1_MSG_RESUME_QUERY:
        return 5u;
    case NINLIL_MFDT_V1_MSG_ABORT:
        return 6u;
    default:
        return 0u;
    }
}

static int response_matches_outstanding_bind(
    const ninlil_mfdt_v1_pipeline_t *p, uint64_t rid,
    const uint8_t *body, uint16_t body_len)
{
    uint8_t retry_type = 0u;
    uint32_t retry_rid = 0u;
    uint32_t retry_generation = 0u;
    uint64_t retry_cookie = 0ull;
    const uint8_t *retry_body = NULL;
    uint16_t retry_body_len = 0u;
    int rc;
    if (p == NULL || body == NULL || body_len < 52u ||
        !p->has_outstanding || p->outstanding_rid != rid ||
        p->retry_frame_len == 0u) {
        return 0;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(
        p->retry_frame, p->retry_frame_len, NINLIL_MFDT_V1_NCG1_DATA,
        &retry_type, &retry_rid, &retry_generation, &retry_cookie,
        &retry_body, &retry_body_len);
    return rc == NINLIL_MFDT_V1_OK &&
           retry_type == p->outstanding_type &&
           (uint64_t)retry_rid == p->outstanding_rid &&
           retry_generation == p->session_generation &&
           retry_cookie == p->session_cookie &&
           retry_body != NULL && retry_body_len >= 52u &&
           ninlil_mfdt_v1_memeq(body, retry_body, 52u);
}

static void clear_outstanding(ninlil_mfdt_v1_pipeline_t *p)
{
    p->has_outstanding = 0u;
    p->outstanding_type = 0u;
    p->outstanding_rid = 0ull;
    p->outstanding_index = 0u;
    p->outstanding_deadline_ms = 0ull;
}

static int is_sender_request_type(uint8_t type)
{
    return type == NINLIL_MFDT_V1_MSG_OPEN ||
           type == NINLIL_MFDT_V1_MSG_MANIFEST_PAGE ||
           type == NINLIL_MFDT_V1_MSG_CHUNK_OFFER ||
           type == NINLIL_MFDT_V1_MSG_RESUME_QUERY ||
           type == NINLIL_MFDT_V1_MSG_FINALIZE ||
           type == NINLIL_MFDT_V1_MSG_ABORT;
}

/*
 * Encode + place frame: send_fn if set, else single outbox ownership.
 * NEVER feeds local rx (no self-loop / fake completion).
 */
static int emit_outbound(ninlil_mfdt_v1_pipeline_t *p, uint8_t mfdt_type,
                         uint64_t request_id, const uint8_t *body,
                         uint16_t body_len)
{
    uint8_t ncl1[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t nlen = 0u;
    int rc;
    uint32_t rid32 = (uint32_t)(request_id & 0xffffffffull);

    if (request_id > 0xffffffffull && rid32 == 0u) {
        rid32 = 1u;
    }
    if (p->outbox_valid) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    rc = ninlil_mfdt_v1_ncl1_encode(mfdt_type, rid32, p->session_generation,
                                    p->session_cookie, body, body_len, ncl1,
                                    sizeof(ncl1), &nlen);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (p->tx != NULL && is_sender_request_type(mfdt_type)) {
        if (nlen > sizeof(p->retry_frame)) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        (void)memcpy(p->retry_frame, ncl1, nlen);
        p->retry_frame_len = (uint16_t)nlen;
    }
    if (p->send_fn != NULL) {
        rc = p->send_fn(p->send_user, ncl1, nlen);
        if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
            /* WOULD_BLOCK: retain ownership in outbox for later take. */
            if (nlen > sizeof(p->outbox)) {
                return NINLIL_MFDT_V1_ERR_CAPACITY;
            }
            (void)memcpy(p->outbox, ncl1, nlen);
            p->outbox_len = (uint16_t)nlen;
            p->outbox_valid = 1u;
            return NINLIL_MFDT_V1_ERR_BUSY;
        }
        if (rc != 0) {
            return (rc < 0) ? rc : NINLIL_MFDT_V1_ERR_STORAGE;
        }
        return NINLIL_MFDT_V1_OK;
    }
    if (nlen > sizeof(p->outbox)) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    (void)memcpy(p->outbox, ncl1, nlen);
    p->outbox_len = (uint16_t)nlen;
    p->outbox_valid = 1u;
    return NINLIL_MFDT_V1_OK;
}

static int emit_response(ninlil_mfdt_v1_pipeline_t *p,
                         const ninlil_mfdt_v1_response_t *resp,
                         uint64_t request_id)
{
    if (resp == NULL || resp->body_len == 0u) {
        return NINLIL_MFDT_V1_OK;
    }
    return emit_outbound(p, resp->message_type, request_id, resp->body,
                         resp->body_len);
}

int ninlil_mfdt_v1_pipeline_outbox_pending(const ninlil_mfdt_v1_pipeline_t *p)
{
    return (p != NULL && p->outbox_valid) ? 1 : 0;
}

int ninlil_mfdt_v1_pipeline_take_outbound(ninlil_mfdt_v1_pipeline_t *p,
                                          uint8_t *out, size_t cap,
                                          size_t *out_len)
{
    if (p == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!p->outbox_valid) {
        *out_len = 0u;
        return NINLIL_MFDT_V1_OK;
    }
    if (out == NULL || cap < (size_t)p->outbox_len) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    (void)memcpy(out, p->outbox, p->outbox_len);
    *out_len = p->outbox_len;
    p->outbox_valid = 0u;
    p->outbox_len = 0u;
    return NINLIL_MFDT_V1_OK;
}

static int pipeline_sender_begin_internal(
    ninlil_mfdt_v1_pipeline_t *p,
    const uint8_t transfer_id[16],
    const uint8_t *data, uint32_t data_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata)
{
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    uint64_t rid;
    int rc;

    if (p == NULL || p->tx == NULL || transfer_id == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (data_len > 0u && data == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (data_len > NINLIL_MFDT_V1_MAX_CONTENT) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (p->phase != NINLIL_MFDT_V1_PHASE_IDLE &&
        p->phase != NINLIL_MFDT_V1_PHASE_COMPLETE) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    rc = ninlil_mfdt_v1_geometry(data_len, &p->geo);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    (void)memcpy(p->transfer_id, transfer_id, 16u);
    p->complete = 0u;
    p->aborted = 0u;
    p->next_page = 0u;
    p->next_chunk = 0u;
    rid = next_rid(p);
    if (metadata != NULL) {
        rc = ninlil_mfdt_v1_sender_open_with_metadata(
            p->tx, transfer_id, data, data_len, metadata, open, &open_len,
            rid);
    } else {
        rc = ninlil_mfdt_v1_sender_open(
            p->tx, transfer_id, data, data_len, open, &open_len, rid);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = emit_outbound(p, NINLIL_MFDT_V1_MSG_OPEN, rid, open, open_len);
    if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
        return rc;
    }
    set_outstanding(p, NINLIL_MFDT_V1_MSG_OPEN, rid, 0u);
    p->phase = NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_pipeline_sender_begin(ninlil_mfdt_v1_pipeline_t *p,
                                         const uint8_t transfer_id[16],
                                         const uint8_t *data, uint32_t data_len)
{
    return pipeline_sender_begin_internal(
        p, transfer_id, data, data_len, NULL);
}

int ninlil_mfdt_v1_pipeline_sender_begin_with_metadata(
    ninlil_mfdt_v1_pipeline_t *p, const uint8_t transfer_id[16],
    const uint8_t *data, uint32_t data_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata)
{
    if (metadata == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    return pipeline_sender_begin_internal(
        p, transfer_id, data, data_len, metadata);
}

int ninlil_mfdt_v1_pipeline_send_application_data(
    ninlil_mfdt_v1_pipeline_t *p, const uint8_t transfer_id[16],
    const uint8_t *data, uint32_t data_len)
{
    return ninlil_mfdt_v1_pipeline_sender_begin(p, transfer_id, data, data_len);
}

static int pipeline_sender_pump_internal(
    ninlil_mfdt_v1_pipeline_t *p, int allow_chunk)
{
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t page[1024];
    uint8_t offer[1024];
    uint8_t fin[128];
    uint16_t blen = 0u;
    uint64_t rid;
    int rc;

    if (p == NULL || p->tx == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (p->outbox_valid) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (p->complete || p->phase == NINLIL_MFDT_V1_PHASE_COMPLETE) {
        return NINLIL_MFDT_V1_OK;
    }
    switch (p->phase) {
    case NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC:
    case NINLIL_MFDT_V1_PHASE_WAIT_PAGE_ACC:
    case NINLIL_MFDT_V1_PHASE_WAIT_CHUNK_ACC:
    case NINLIL_MFDT_V1_PHASE_WAIT_XFER_ACC:
        return NINLIL_MFDT_V1_OK; /* wait real inbound accept */
    case NINLIL_MFDT_V1_PHASE_REISSUE_OPEN:
        /*
         * A cold process has no volatile request ID/frame. Charge the durable
         * new-ID retry before reconstructing and exposing the OPEN to wire.
         */
        rc = ninlil_mfdt_v1_owner_timeout_retry_charge(p->tx);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rid = next_rid(p);
        rc = ninlil_mfdt_v1_sender_reissue_open(p->tx, open, &blen);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = emit_outbound(p, NINLIL_MFDT_V1_MSG_OPEN, rid, open, blen);
        if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
        set_outstanding(p, NINLIL_MFDT_V1_MSG_OPEN, rid, 0u);
        p->phase = NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC;
        return NINLIL_MFDT_V1_OK;
    case NINLIL_MFDT_V1_PHASE_SEND_PAGES:
        if (p->next_page >= p->geo.page_count) {
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_CHUNKS;
            p->next_chunk = 0u;
            return pipeline_sender_pump_internal(p, allow_chunk);
        }
        rid = next_rid(p);
        rc = ninlil_mfdt_v1_sender_offer_page(p->tx, p->next_page, rid, page,
                                              &blen);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = emit_outbound(p, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE, rid, page, blen);
        if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
        set_outstanding(p, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE, rid, p->next_page);
        p->phase = NINLIL_MFDT_V1_PHASE_WAIT_PAGE_ACC;
        return NINLIL_MFDT_V1_OK;
    case NINLIL_MFDT_V1_PHASE_SEND_CHUNKS:
        if (p->next_chunk >= p->geo.chunk_count) {
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_FIN;
            return pipeline_sender_pump_internal(p, allow_chunk);
        }
        if (!allow_chunk) {
            return NINLIL_MFDT_V1_OK;
        }
        rid = next_rid(p);
        rc = ninlil_mfdt_v1_sender_offer_chunk(p->tx, p->next_chunk, rid, offer,
                                               &blen);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = emit_outbound(p, NINLIL_MFDT_V1_MSG_CHUNK_OFFER, rid, offer, blen);
        if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
        set_outstanding(p, NINLIL_MFDT_V1_MSG_CHUNK_OFFER, rid, p->next_chunk);
        p->phase = NINLIL_MFDT_V1_PHASE_WAIT_CHUNK_ACC;
        return NINLIL_MFDT_V1_OK;
    case NINLIL_MFDT_V1_PHASE_SEND_FIN:
        rid = next_rid(p);
        rc = ninlil_mfdt_v1_sender_finalize(p->tx, rid, fin, &blen);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = emit_outbound(p, NINLIL_MFDT_V1_MSG_FINALIZE, rid, fin, blen);
        if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return rc;
        }
        set_outstanding(p, NINLIL_MFDT_V1_MSG_FINALIZE, rid, 0u);
        p->phase = NINLIL_MFDT_V1_PHASE_WAIT_XFER_ACC;
        return NINLIL_MFDT_V1_OK;
    default:
        return NINLIL_MFDT_V1_ERR_STATE;
    }
}

ninlil_mfdt_v1_pipeline_action_t
ninlil_mfdt_v1_pipeline_next_action(
    const ninlil_mfdt_v1_pipeline_t *p)
{
    if (p == NULL || p->outbox_valid != 0u || p->complete != 0u ||
        p->phase == NINLIL_MFDT_V1_PHASE_COMPLETE ||
        p->phase == NINLIL_MFDT_V1_PHASE_IDLE ||
        p->phase == NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC ||
        p->phase == NINLIL_MFDT_V1_PHASE_WAIT_PAGE_ACC ||
        p->phase == NINLIL_MFDT_V1_PHASE_WAIT_CHUNK_ACC ||
        p->phase == NINLIL_MFDT_V1_PHASE_WAIT_XFER_ACC) {
        return NINLIL_MFDT_V1_PIPE_ACTION_NONE;
    }
    if (p->phase == NINLIL_MFDT_V1_PHASE_SEND_CHUNKS &&
        p->next_chunk < p->geo.chunk_count) {
        return NINLIL_MFDT_V1_PIPE_ACTION_CHUNK;
    }
    return NINLIL_MFDT_V1_PIPE_ACTION_CONTROL;
}

int ninlil_mfdt_v1_pipeline_pump_control(
    ninlil_mfdt_v1_pipeline_t *p)
{
    return pipeline_sender_pump_internal(p, 0);
}

int ninlil_mfdt_v1_pipeline_emit_selected_chunk(
    ninlil_mfdt_v1_pipeline_t *p)
{
    if (ninlil_mfdt_v1_pipeline_next_action(p) !=
        NINLIL_MFDT_V1_PIPE_ACTION_CHUNK) {
        return p == NULL ? NINLIL_MFDT_V1_ERR_PARAM
                         : NINLIL_MFDT_V1_ERR_STATE;
    }
    return pipeline_sender_pump_internal(p, 1);
}

int ninlil_mfdt_v1_pipeline_sender_pump(ninlil_mfdt_v1_pipeline_t *p)
{
    return pipeline_sender_pump_internal(p, 1);
}

void ninlil_mfdt_v1_pipeline_set_response_timeout(
    ninlil_mfdt_v1_pipeline_t *p, uint64_t timeout_ms)
{
    if (p == NULL) {
        return;
    }
    p->response_timeout_ms =
        timeout_ms != 0ull ? timeout_ms : NINLIL_MFDT_V1_RESPONSE_TIMEOUT_MS;
    if (p->has_outstanding != 0u) {
        if (UINT64_MAX - p->now_ms < p->response_timeout_ms) {
            p->outstanding_deadline_ms = UINT64_MAX;
        } else {
            p->outstanding_deadline_ms = p->now_ms + p->response_timeout_ms;
        }
    }
}

int ninlil_mfdt_v1_pipeline_tick(ninlil_mfdt_v1_pipeline_t *p,
                                 uint64_t now_ms)
{
    uint8_t mtype = 0u;
    uint32_t old_rid = 0u;
    uint32_t sgen = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *body = NULL;
    uint16_t body_len = 0u;
    uint64_t new_rid;
    uint16_t index;
    uint8_t type;
    int rc;

    if (p == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    p->now_ms = now_ms;
    if (p->tx != NULL) {
        ninlil_mfdt_v1_engine_set_now(p->tx, now_ms);
    }
    if (p->rx != NULL) {
        ninlil_mfdt_v1_engine_set_now(p->rx, now_ms);
    }
    if (p->tx == NULL || p->has_outstanding == 0u ||
        now_ms < p->outstanding_deadline_ms) {
        return NINLIL_MFDT_V1_OK;
    }
    /*
     * The bearer/caller still owns an unsent frame. Waiting is not a response
     * timeout and must not consume the durable retry budget.
     */
    if (p->outbox_valid != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (p->retry_frame_len == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(
        p->retry_frame, p->retry_frame_len, NINLIL_MFDT_V1_NCG1_DATA, &mtype,
        &old_rid, &sgen, &cookie, &body, &body_len);
    if (rc != NINLIL_MFDT_V1_OK || mtype != p->outstanding_type ||
        (uint64_t)old_rid != p->outstanding_rid ||
        sgen != p->session_generation || cookie != p->session_cookie) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    type = p->outstanding_type;
    index = p->outstanding_index;
    rc = ninlil_mfdt_v1_owner_timeout_retry_charge(p->tx);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    new_rid = next_rid(p);
    rc = emit_outbound(p, type, new_rid, body, body_len);
    if (rc != NINLIL_MFDT_V1_OK && rc != NINLIL_MFDT_V1_ERR_BUSY) {
        return rc;
    }
    set_outstanding(p, type, new_rid, index);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_pipeline_on_ncl1_ingress(ninlil_mfdt_v1_pipeline_t *p,
                                            const uint8_t *ncl1_payload,
                                            size_t ncl1_len)
{
    uint8_t mtype = 0u;
    uint32_t rid = 0u;
    uint32_t sgen = 0u;
    uint64_t cookie = 0ull;
    const uint8_t *body = NULL;
    uint16_t blen = 0u;
    ninlil_mfdt_v1_response_t resp;
    int rc;
    uint64_t rid64;

    if (p == NULL || ncl1_payload == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(ncl1_payload, ncl1_len,
                                    NINLIL_MFDT_V1_NCG1_DATA, &mtype, &rid,
                                    &sgen, &cookie, &body, &blen);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (sgen != p->session_generation || cookie != p->session_cookie) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    rid64 = (uint64_t)rid;
    p->last_ingress_response_valid = 0u;
    p->last_ingress_response_from_nrc1_hit = 0u;
    p->last_ingress_response_state_mutation = 0u;
    p->last_ingress_response_full_count = 0u;
    p->last_chunk_fence_released = 0u;
    /*
     * A receiver owns exactly one outbound frame.  Refuse another request
     * before touching durable or volatile transfer state; otherwise the new
     * response could be silently replaced by the prior outbox frame.
     */
    if (is_sender_request_type(mtype) && p->outbox_valid != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    ninlil_mfdt_v1_memzero(&resp, sizeof(resp));

    /* Response path → local sender only (real remote peer). */
    switch (mtype) {
    case NINLIL_MFDT_V1_MSG_OPEN_ACCEPT:
        if (p->tx == NULL) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (!check_outstanding(p, NINLIL_MFDT_V1_MSG_OPEN, rid64, 0, 0u)) {
            return NINLIL_MFDT_V1_ERR_STATE; /* wrong/stale rid: no mutation */
        }
        rc = ninlil_mfdt_v1_sender_on_open_accept(p->tx, body, blen, rid64);
        if (rc == NINLIL_MFDT_V1_OK &&
            p->phase == NINLIL_MFDT_V1_PHASE_WAIT_OPEN_ACC) {
            clear_outstanding(p);
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_PAGES;
            p->next_page = 0u;
        }
        return rc;
    case NINLIL_MFDT_V1_MSG_PAGE_ACCEPT:
        if (p->tx == NULL) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        {
            uint16_t pidx =
                (body != NULL && blen >= 54u) ? ninlil_mfdt_v1_get_u16(body + 52)
                                             : 0xffffu;
            if (!check_outstanding(p, NINLIL_MFDT_V1_MSG_MANIFEST_PAGE, rid64, 1,
                                   pidx)) {
                return NINLIL_MFDT_V1_ERR_STATE;
            }
        }
        rc = ninlil_mfdt_v1_sender_on_page_accept(p->tx, body, blen, rid64);
        if (rc == NINLIL_MFDT_V1_OK &&
            p->phase == NINLIL_MFDT_V1_PHASE_WAIT_PAGE_ACC) {
            clear_outstanding(p);
            p->next_page = (uint16_t)(p->next_page + 1u);
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_PAGES;
        }
        return rc;
    case NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT:
        if (p->tx == NULL) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        {
            uint16_t cidx =
                (body != NULL && blen >= 54u) ? ninlil_mfdt_v1_get_u16(body + 52)
                                             : 0xffffu;
            if (!check_outstanding(p, NINLIL_MFDT_V1_MSG_CHUNK_OFFER, rid64, 1,
                                   cidx)) {
                return NINLIL_MFDT_V1_ERR_STATE;
            }
        }
        rc = ninlil_mfdt_v1_sender_on_chunk_accept(p->tx, body, blen, rid64);
        if (rc == NINLIL_MFDT_V1_OK &&
            p->phase == NINLIL_MFDT_V1_PHASE_WAIT_CHUNK_ACC) {
            clear_outstanding(p);
            p->next_chunk = (uint16_t)(p->next_chunk + 1u);
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_CHUNKS;
        }
        return rc;
    case NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT:
        if (p->tx == NULL) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (!check_outstanding(p, NINLIL_MFDT_V1_MSG_FINALIZE, rid64, 0, 0u)) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        rc = ninlil_mfdt_v1_sender_on_transfer_accept(p->tx, body, blen, rid64);
        if (rc == NINLIL_MFDT_V1_OK) {
            clear_outstanding(p);
            p->phase = NINLIL_MFDT_V1_PHASE_COMPLETE;
            p->complete = 1u;
        }
        return rc;
    case NINLIL_MFDT_V1_MSG_REJECT:
        if (p->tx == NULL || blen != 60u ||
            !response_matches_outstanding_bind(p, rid64, body, blen) ||
            ninlil_mfdt_v1_get_u16(body + 52) !=
                request_stage(p->outstanding_type) ||
            ninlil_mfdt_v1_get_u16(body + 54) == 0u ||
            ninlil_mfdt_v1_get_u16(body + 54) >
                NINLIL_MFDT_V1_REJ_ABORT_DENIED) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (p->outstanding_type ==
                NINLIL_MFDT_V1_MSG_CHUNK_OFFER &&
            p->phase == NINLIL_MFDT_V1_PHASE_WAIT_CHUNK_ACC) {
            p->last_chunk_fence_released = 1u;
        }
        clear_outstanding(p);
        p->phase = NINLIL_MFDT_V1_PHASE_COMPLETE;
        p->aborted = 1u;
        return NINLIL_MFDT_V1_OK;
    case NINLIL_MFDT_V1_MSG_BUSY:
        if (p->tx == NULL || blen != 60u ||
            !response_matches_outstanding_bind(p, rid64, body, blen) ||
            ninlil_mfdt_v1_get_u16(body + 52) !=
                request_stage(p->outstanding_type) ||
            ninlil_mfdt_v1_get_u16(body + 54) != 0u) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        return NINLIL_MFDT_V1_OK;
    case NINLIL_MFDT_V1_MSG_ABORT_ACK:
        if (p->tx == NULL || blen != 92u ||
            p->outstanding_type != NINLIL_MFDT_V1_MSG_ABORT ||
            !response_matches_outstanding_bind(p, rid64, body, blen)) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        clear_outstanding(p);
        p->phase = NINLIL_MFDT_V1_PHASE_COMPLETE;
        p->aborted = 1u;
        return NINLIL_MFDT_V1_OK;
    default:
        break;
    }

    /* Request path → local receiver only; response goes to outbox. */
    if (p->rx == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    switch (mtype) {
    case NINLIL_MFDT_V1_MSG_OPEN:
        rc = ninlil_mfdt_v1_receiver_on_open(p->rx, body, blen, rid64, &resp);
        break;
    case NINLIL_MFDT_V1_MSG_MANIFEST_PAGE:
        rc = ninlil_mfdt_v1_receiver_on_page(p->rx, body, blen, rid64, &resp);
        break;
    case NINLIL_MFDT_V1_MSG_CHUNK_OFFER:
        rc = ninlil_mfdt_v1_receiver_on_chunk(p->rx, body, blen, rid64, &resp);
        break;
    case NINLIL_MFDT_V1_MSG_FINALIZE:
        rc = ninlil_mfdt_v1_receiver_on_finalize(p->rx, body, blen, rid64, &resp);
        break;
    case NINLIL_MFDT_V1_MSG_RESUME_QUERY:
        rc = ninlil_mfdt_v1_receiver_on_resume(p->rx, body, blen, rid64, &resp);
        break;
    case NINLIL_MFDT_V1_MSG_ABORT:
        rc = ninlil_mfdt_v1_receiver_on_abort(p->rx, body, blen, rid64, &resp);
        break;
    default:
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (resp.body_len > 0u) {
        const int response_rc = emit_response(p, &resp, rid64);
        if (response_rc != NINLIL_MFDT_V1_OK &&
            response_rc != NINLIL_MFDT_V1_ERR_BUSY) {
            return response_rc;
        }
        p->last_ingress_response_valid = 1u;
        p->last_ingress_response_from_nrc1_hit =
            resp.from_nrc1_hit;
        p->last_ingress_response_state_mutation =
            resp.state_mutation;
        p->last_ingress_response_full_count = resp.full_count;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
        (void)fprintf(
            stderr,
            "mfdt pipeline: receiver request failed rc=%d type=%u rid=%u "
            "body_len=%u response_len=%u phase=%u\n",
            rc,
            (unsigned)mtype,
            (unsigned)rid,
            (unsigned)blen,
            (unsigned)resp.body_len,
            (unsigned)p->phase);
#endif
        return rc;
    }
    if (p->rx->publication_ready) {
        (void)memcpy(p->publication_token, p->rx->publication_token, 16u);
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_pipeline_sender_rehydrate(ninlil_mfdt_v1_pipeline_t *p,
                                             ninlil_mfdt_v1_engine_t *tx,
                                             const uint8_t transfer_id[16],
                                             uint32_t session_generation,
                                             uint64_t session_cookie)
{
    ninlil_mfdt_v1_active_snapshot_t snap;
    uint16_t i;
    int rc;

    if (p == NULL || tx == NULL || transfer_id == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_pipeline_init(p, tx, NULL, NULL, NULL, session_generation,
                                 session_cookie);
    rc = ninlil_mfdt_v1_engine_active_snapshot(tx, &snap);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (snap.role != 1u ||
        !ninlil_mfdt_v1_memeq(snap.transfer_id, transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    (void)memcpy(p->transfer_id, transfer_id, 16u);
    rc = ninlil_mfdt_v1_geometry(snap.total_length, &p->geo);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    /* Prefer durable geometry counts when present. */
    if (snap.page_count > 0u) {
        p->geo.page_count = snap.page_count;
    }
    if (snap.chunk_count > 0u) {
        p->geo.chunk_count = snap.chunk_count;
    }
    /* First incomplete page / chunk from bitmaps (durable accepts only). */
    p->next_page = p->geo.page_count;
    for (i = 0u; i < p->geo.page_count && i < 8u; ++i) {
        if ((snap.page_bitmap & (uint8_t)(1u << i)) == 0u) {
            p->next_page = i;
            break;
        }
    }
    p->next_chunk = p->geo.chunk_count;
    for (i = 0u; i < p->geo.chunk_count && i < 64u; ++i) {
        if ((snap.chunk_bitmap & ((uint64_t)1u << i)) == 0u) {
            p->next_chunk = i;
            break;
        }
    }
    /*
     * Map durable state_code → wire phase. Prefer SEND_* so cold restart
     * re-offers (at-least-once) rather than waiting forever without outbox.
     */
    p->complete = 0u;
    p->aborted = 0u;
    if (snap.state_code == NINLIL_MFDT_V1_S_ACCEPT_RX) {
        p->phase = NINLIL_MFDT_V1_PHASE_COMPLETE;
        p->complete = 1u;
    } else if (snap.state_code == NINLIL_MFDT_V1_S_OPEN_PENDING) {
        p->phase = NINLIL_MFDT_V1_PHASE_REISSUE_OPEN;
    } else if (snap.state_code == NINLIL_MFDT_V1_S_OPEN_ACCEPTED ||
               snap.state_code == NINLIL_MFDT_V1_S_MANIFEST_ACCEPTED) {
        if (p->next_page < p->geo.page_count) {
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_PAGES;
        } else {
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_CHUNKS;
        }
    } else if (snap.state_code == NINLIL_MFDT_V1_S_CHUNKS_PARTIAL) {
        if (p->next_chunk < p->geo.chunk_count) {
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_CHUNKS;
        } else {
            p->phase = NINLIL_MFDT_V1_PHASE_SEND_FIN;
        }
    } else if (snap.state_code == NINLIL_MFDT_V1_S_FINAL_WAIT) {
        p->phase = NINLIL_MFDT_V1_PHASE_SEND_FIN;
    } else {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    /*
     * next_request_id: record_generation is durable; advance past it so new
     * offers never collide with pre-crash NRC1 slots.
     */
    p->next_request_id =
        (snap.record_generation > 0ull)
            ? (uint64_t)(0x40000000u +
                         (uint32_t)(snap.record_generation & 0x1fffffffull))
            : 0x40000000ull;
    if (snap.publication_state != 0u) {
        (void)memcpy(p->publication_token, snap.publication_token, 16u);
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_pipeline_finish_terminal(ninlil_mfdt_v1_pipeline_t *p)
{
    int rc;
    if (p == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (p->rx != NULL && p->rx->publication_ready) {
        /*
         * Terminalization is not an upper-layer effect.  A production upper
         * adapter must first durably prepare/commit via
         * receiver_commit_publication(); never invent evidence here.
         */
        if (p->rx->handoff_complete == 0u) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        rc = ninlil_mfdt_v1_terminal_complete(p->rx);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    if (p->tx != NULL && p->complete) {
        rc = ninlil_mfdt_v1_terminal_complete(p->tx);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    return NINLIL_MFDT_V1_OK;
}
