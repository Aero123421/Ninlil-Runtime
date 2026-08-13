/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_session.h"

#include "wifi_nwb1.h"

#include <stdint.h>
#include <string.h>

/* Cast tls_storage → ninlil_wifi_tls_t* only when max_align_t-aligned. */
static ninlil_wifi_tls_t *session_tls_from_storage(ninlil_wifi_session_t *session)
{
    uintptr_t addr;
    if (session == NULL) {
        return NULL;
    }
    addr = (uintptr_t)(void *)&session->tls_storage[0];
    if ((addr % (uintptr_t)_Alignof(max_align_t)) != 0u) {
        /* Misaligned storage: never hand a bad pointer to OpenSSL casts. */
        return NULL;
    }
    return (ninlil_wifi_tls_t *)(void *)&session->tls_storage[0];
}

static int is_all_zero16(const uint8_t *p)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static uint64_t session_mono_ms(const ninlil_wifi_session_t *session)
{
    if (session != NULL && session->mono_ms != NULL) {
        return session->mono_ms(session->mono_user);
    }
    return 0u;
}

static ninlil_wifi_status_t journal_write_point_values(
    ninlil_wifi_session_t *session,
    uint8_t write_point,
    uint8_t phase,
    uint64_t attempt_id,
    uint32_t generation,
    uint32_t endpoint_index,
    const ninlil_wifi_endpoint_t *endpoint,
    const uint8_t session_id[16],
    int session_id_valid)
{
    ninlil_wifi_journal_attempt_t attempt;
    ninlil_wifi_status_t st;
    if (session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (!session->journal_enabled) {
        session->last_journal_status = NINLIL_WIFI_OK;
        return NINLIL_WIFI_OK;
    }
    if (endpoint == NULL) {
        endpoint = &session->endpoint;
    }
    (void)memset(&attempt, 0, sizeof(attempt));
    attempt.attempt_id = attempt_id;
    attempt.mono_ms = session_mono_ms(session);
    attempt.endpoint_index = endpoint_index;
    attempt.generation = generation;
    attempt.phase = phase;
    attempt.write_point = write_point;
    if (session_id_valid != 0 && session_id != NULL) {
        (void)memcpy(attempt.session_id, session_id, 16u);
    } else if (session->attached_session_valid) {
        (void)memcpy(
            attempt.session_id, session->ids.attached_session_id, 16u);
    } else if (session->peer_session_valid) {
        (void)memcpy(attempt.session_id, session->ids.peer_session_id, 16u);
    }
    if (session->credentials.committed.valid) {
        (void)memcpy(
            attempt.secret_ref_digest,
            session->credentials.committed.secret_ref_digest,
            32u);
    }
    (void)memcpy(attempt.endpoint_digest, endpoint->address, 16u);
    attempt.endpoint_digest[16] = (uint8_t)(endpoint->port >> 8);
    attempt.endpoint_digest[17] = (uint8_t)(endpoint->port & 0xffu);
    st = ninlil_wifi_journal_put_attempt(&session->journal, &attempt);
    session->last_journal_status = st;
    return st;
}

static ninlil_wifi_status_t journal_write_point(
    ninlil_wifi_session_t *session,
    uint8_t write_point,
    uint8_t phase)
{
    return journal_write_point_values(
        session,
        write_point,
        phase,
        session != NULL ? session->attempt_id : 0u,
        session != NULL ? session->session_fence_generation : 0u,
        session != NULL ? session->reconnect.endpoints.index : 0u,
        session != NULL ? &session->endpoint : NULL,
        NULL,
        0);
}

static void session_runtime_fence(
    ninlil_wifi_session_t *session,
    int schedule_reconnect)
{
    if (session == NULL) {
        return;
    }
    if (session->phase != NINLIL_WIFI_PHASE_FENCED) {
        if (session->session_fence_generation != UINT32_MAX) {
            session->session_fence_generation += 1u;
        } else {
            session->availability_epoch_exhausted = 1;
        }
        if (session->availability_epoch != UINT64_MAX) {
            session->availability_epoch += 1u;
        } else {
            session->availability_epoch_exhausted = 1;
        }
    }
    session->phase = NINLIL_WIFI_PHASE_FENCED;
    session->tx_partial_len = 0u;
    session->tx_partial_off = 0u;
    session->peer_context_valid = 0;
    session->attached_context_valid = 0;
    session->peer_session_valid = 0;
    session->attached_session_valid = 0;
    session->m4_pa_full_confirmed = 0;
    session->last_tx_completed_valid = 0;
    (void)memset(session->ids.peer_session_id, 0, 16u);
    (void)memset(session->ids.attached_session_id, 0, 16u);
    if (session->tls != NULL) {
        ninlil_wifi_tls_close(session->tls);
        (void)memset(session->tls_storage, 0, sizeof(session->tls_storage));
        session->tls = session_tls_from_storage(session);
    }
    ninlil_wifi_tcp_close(&session->tcp);
    ninlil_wifi_queue_init(&session->txq);
    ninlil_wifi_queue_init(&session->rxq);
    if (schedule_reconnect != 0 && session->auto_reconnect
        && !session->is_server) {
        ninlil_wifi_reconnect_note_failure(
            &session->reconnect, session_mono_ms(session));
        session->phase = NINLIL_WIFI_PHASE_RECONNECT_WAIT;
    }
}

static void session_fail_journal(
    ninlil_wifi_session_t *session,
    ninlil_wifi_status_t journal_status)
{
    if (session == NULL) {
        return;
    }
    session->last_journal_status = journal_status;
    /*
     * Do not attempt another journal write after uncertain/failed persistence.
     * Close all I/O and remain fenced; automatic reconnect is forbidden until
     * the caller creates/reconciles a fresh session.
     */
    session_runtime_fence(session, 0);
}

static ninlil_wifi_status_t fence_then_return(
    ninlil_wifi_session_t *session,
    ninlil_wifi_status_t cause)
{
    ninlil_wifi_status_t journal_status =
        ninlil_wifi_session_fence(session);
    return journal_status != NINLIL_WIFI_OK ? journal_status : cause;
}

void ninlil_wifi_session_force_blackhole(ninlil_wifi_session_t *session)
{
    if (session == NULL) {
        return;
    }
    session->blackhole_force = 1;
    session->liveness_enabled = 1;
}

void ninlil_wifi_session_init(ninlil_wifi_session_t *session)
{
    if (session == NULL) {
        return;
    }
    (void)memset(session, 0, sizeof(*session));
    ninlil_wifi_tcp_init(&session->tcp);
    ninlil_wifi_rx_stream_init(&session->rx);
    ninlil_wifi_queue_init(&session->txq);
    ninlil_wifi_queue_init(&session->rxq);
    ninlil_wifi_credential_store_init(&session->credentials);
    ninlil_wifi_reconnect_init(&session->reconnect);
    ninlil_wifi_journal_init(&session->journal);
    /* Fabric availability epochs are non-zero and never wrap. */
    session->availability_epoch = 1u;
    if (ninlil_wifi_tls_sizeof() > sizeof(session->tls_storage)) {
        session->tls = NULL;
        return;
    }
    (void)memset(session->tls_storage, 0, sizeof(session->tls_storage));
    session->tls = session_tls_from_storage(session);
}

void ninlil_wifi_session_set_mono_clock(
    ninlil_wifi_session_t *session,
    ninlil_wifi_mono_ms_fn fn,
    void *user)
{
    if (session == NULL) {
        return;
    }
    session->mono_ms = fn;
    session->mono_user = user;
    if (fn != NULL) {
        session->liveness_enabled = 1;
    }
}

void ninlil_wifi_session_set_auto_reconnect(
    ninlil_wifi_session_t *session,
    int enabled)
{
    if (session == NULL) {
        return;
    }
    session->auto_reconnect = enabled ? 1 : 0;
}

void ninlil_wifi_session_require_credentials(
    ninlil_wifi_session_t *session,
    int required)
{
    if (session == NULL) {
        return;
    }
    session->credentials_required = required ? 1 : 0;
}

ninlil_wifi_status_t ninlil_wifi_session_bind_journal(
    ninlil_wifi_session_t *session,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8)
{
    ninlil_wifi_status_t st;
    if (session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    st = ninlil_wifi_journal_open(
        &session->journal, storage, storage_user, path_utf8);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    session->journal_enabled = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_journal_recover(
    ninlil_wifi_session_t *session,
    ninlil_wifi_journal_attempt_t *out_attempt)
{
    if (session == NULL || out_attempt == NULL || !session->journal_enabled) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    return ninlil_wifi_journal_recover(&session->journal, out_attempt);
}

ninlil_wifi_status_t ninlil_wifi_session_set_peer_context_inputs(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_peer_context_inputs_t *inputs)
{
    if (session == NULL || inputs == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    session->peer_inputs = *inputs;
    session->peer_inputs_set = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_set_attachment_expectation(
    ninlil_wifi_session_t *session,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32])
{
    if (session == NULL || attachment_authority_id == NULL
        || active_attachment_binding_digest == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memcpy(
        session->expected_attachment_authority_id,
        attachment_authority_id,
        16u);
    (void)memcpy(
        session->expected_attachment_binding,
        active_attachment_binding_digest,
        32u);
    session->attachment_expectation_set = 1;
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_session_close(ninlil_wifi_session_t *session)
{
    if (session == NULL) {
        return;
    }
    if (session->tls != NULL) {
        ninlil_wifi_tls_close(session->tls);
    }
    ninlil_wifi_tcp_close(&session->tcp);
    if (session->journal_enabled) {
        ninlil_wifi_journal_close(&session->journal);
        session->journal_enabled = 0;
    }
    session->phase = NINLIL_WIFI_PHASE_CLOSED;
    session->tx_partial_len = 0u;
    session->tx_partial_off = 0u;
    session->last_tx_completed_valid = 0;
    session->peer_context_valid = 0;
    session->attached_context_valid = 0;
    session->peer_session_valid = 0;
    session->attached_session_valid = 0;
    session->m4_pa_full_confirmed = 0;
    ninlil_wifi_queue_init(&session->txq);
    ninlil_wifi_queue_init(&session->rxq);
    ninlil_wifi_rx_stream_init(&session->rx);
}

ninlil_wifi_status_t ninlil_wifi_session_fence(
    ninlil_wifi_session_t *session)
{
    ninlil_wifi_status_t journal_status;
    uint32_t prospective_generation;
    if (session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    /*
     * A repeated observation of the already-published fence is idempotent.
     * This also prevents a cancel path and its caller from double-counting the
     * same stream fence.
     */
    if (session->phase == NINLIL_WIFI_PHASE_FENCED) {
        session_runtime_fence(session, 0);
        return session->last_journal_status;
    }
    prospective_generation = session->session_fence_generation;
    if (prospective_generation != UINT32_MAX) {
        prospective_generation += 1u;
    }
    /*
     * Point 4 is persisted before publishing the fenced phase/generation and
     * before closing/reconnecting transport. Even if persistence is unknown,
     * runtime I/O is still closed and no reconnect is scheduled.
     */
    journal_status = journal_write_point_values(
        session,
        4u,
        (uint8_t)NINLIL_WIFI_PHASE_FENCED,
        session->attempt_id,
        prospective_generation,
        session->reconnect.endpoints.index,
        &session->endpoint,
        NULL,
        0);
    session_runtime_fence(
        session, journal_status == NINLIL_WIFI_OK ? 1 : 0);
    return journal_status;
}

ninlil_wifi_status_t ninlil_wifi_session_last_journal_status(
    const ninlil_wifi_session_t *session)
{
    return session == NULL
        ? NINLIL_WIFI_INVALID_ARGUMENT
        : session->last_journal_status;
}

ninlil_wifi_status_t ninlil_wifi_session_set_failover(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *endpoint)
{
    if (session == NULL || endpoint == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    session->failover_endpoint = *endpoint;
    session->has_failover = 1;
    return ninlil_wifi_endpoint_list_push(&session->reconnect.endpoints, endpoint);
}

ninlil_wifi_status_t ninlil_wifi_session_add_endpoint(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *endpoint)
{
    if (session == NULL || endpoint == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    return ninlil_wifi_endpoint_list_push(
        &session->reconnect.endpoints, endpoint);
}

ninlil_wifi_status_t ninlil_wifi_session_configure_tls(
    ninlil_wifi_session_t *session,
    int is_server,
    const ninlil_wifi_tls_paths_t *paths)
{
    if (session == NULL || paths == NULL || session->tls == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    session->is_server = is_server ? 1 : 0;
    session->tls_paths = *paths;
    session->tls_paths_set = 1;
    return ninlil_wifi_tls_init(session->tls, is_server, paths);
}

static ninlil_wifi_status_t wifi_attach_tls_after_tcp(
    ninlil_wifi_session_t *session)
{
    ninlil_wifi_status_t st;
    st = journal_write_point(session, 1u, (uint8_t)NINLIL_WIFI_PHASE_CONNECTING);
    if (st != NINLIL_WIFI_OK) {
        /* No TLS attach/I/O after an unrecorded TCP-success boundary. */
        session_fail_journal(session, st);
        return st;
    }
    st = ninlil_wifi_tls_attach_fd(session->tls, session->tcp.fd);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    session->phase = NINLIL_WIFI_PHASE_HANDSHAKING;
    session->next_tx_sequence = 0u;
    session->last_tx_completed_valid = 0;
    return NINLIL_WIFI_OK;
}

static uint32_t nwb1_sequence_from_record(const uint8_t *record, size_t length)
{
    if (record == NULL || length < 36u) {
        return UINT32_MAX;
    }
    return ((uint32_t)record[32] << 24) | ((uint32_t)record[33] << 16)
        | ((uint32_t)record[34] << 8) | (uint32_t)record[35];
}

static ninlil_wifi_status_t note_tx_record_completed(
    ninlil_wifi_session_t *session,
    const uint8_t *record,
    size_t length)
{
    uint32_t sequence;
    if (session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    sequence = nwb1_sequence_from_record(record, length);
    if (sequence == UINT32_MAX) {
        /* UINT32_MAX is forbidden on the wire; a malformed record fences. */
        return fence_then_return(session, NINLIL_WIFI_CORRUPT);
    }
    session->last_tx_completed_sequence = sequence;
    session->last_tx_completed_valid = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_connect(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *endpoint)
{
    ninlil_wifi_status_t st;
    uint64_t next_attempt;
    uint32_t endpoint_index;
    if (session == NULL || endpoint == NULL || session->tls == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (session->credentials_required
        && !ninlil_wifi_credential_is_active(&session->credentials)) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (session->attempt_id == UINT64_MAX) {
        return fence_then_return(session, NINLIL_WIFI_CAPACITY);
    }
    next_attempt = session->attempt_id + 1u;
    endpoint_index = session->reconnect.endpoints.index;
    st = journal_write_point_values(
        session,
        0u,
        (uint8_t)NINLIL_WIFI_PHASE_CONNECTING,
        next_attempt,
        session->session_fence_generation,
        endpoint_index,
        endpoint,
        NULL,
        0);
    if (st != NINLIL_WIFI_OK) {
        /* No socket creation or state publication after uncertain storage. */
        session_fail_journal(session, st);
        return st;
    }
    session->endpoint = *endpoint;
    if (session->reconnect.endpoints.count == 0u) {
        st = ninlil_wifi_endpoint_list_push(
            &session->reconnect.endpoints, endpoint);
        if (st != NINLIL_WIFI_OK) {
            return fence_then_return(session, st);
        }
    }
    session->attempt_id = next_attempt;
    session->phase = NINLIL_WIFI_PHASE_CONNECTING;
    /* Never accept caller session_id as identity. */
    (void)memset(session->ids.peer_session_id, 0, 16u);
    (void)memset(session->ids.attached_session_id, 0, 16u);
    session->peer_session_valid = 0;
    session->attached_session_valid = 0;
    session->m4_pa_full_confirmed = 0;
    st = ninlil_wifi_tcp_connect(&session->tcp, endpoint);
    if (st == NINLIL_WIFI_OK) {
        return wifi_attach_tls_after_tcp(session);
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    return fence_then_return(session, st);
}

static void close_unowned_fd(int fd)
{
    ninlil_wifi_tcp_t incoming;
    if (fd < 0) {
        return;
    }
    ninlil_wifi_tcp_init(&incoming);
    incoming.fd = fd;
    incoming.connected = 1;
    ninlil_wifi_tcp_close(&incoming);
}

ninlil_wifi_status_t ninlil_wifi_session_accept_fd(
    ninlil_wifi_session_t *session,
    int fd)
{
    ninlil_wifi_status_t st;
    uint64_t next_attempt;
    if (session == NULL || fd < 0 || session->tls == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (session->attempt_id == UINT64_MAX) {
        close_unowned_fd(fd);
        return fence_then_return(session, NINLIL_WIFI_CAPACITY);
    }
    next_attempt = session->attempt_id + 1u;
    st = journal_write_point_values(
        session,
        0u,
        (uint8_t)NINLIL_WIFI_PHASE_CONNECTING,
        next_attempt,
        session->session_fence_generation,
        session->reconnect.endpoints.index,
        &session->endpoint,
        NULL,
        0);
    if (st != NINLIL_WIFI_OK) {
        close_unowned_fd(fd);
        session_fail_journal(session, st);
        return st;
    }
    ninlil_wifi_tcp_close(&session->tcp);
    session->tcp.fd = fd;
    session->tcp.connected = 1;
    session->attempt_id = next_attempt;
    session->phase = NINLIL_WIFI_PHASE_CONNECTING;
    (void)memset(session->ids.peer_session_id, 0, 16u);
    (void)memset(session->ids.attached_session_id, 0, 16u);
    session->peer_session_valid = 0;
    session->attached_session_valid = 0;
    session->m4_pa_full_confirmed = 0;
    return wifi_attach_tls_after_tcp(session);
}

static ninlil_wifi_status_t pump_tx(ninlil_wifi_session_t *session)
{
    const uint8_t *rec = NULL;
    size_t rec_len = 0u;
    size_t wrote = 0u;
    ninlil_wifi_status_t st;

    if (session->tx_partial_len > 0u) {
        size_t partial_length = session->tx_partial_len;
        st = ninlil_wifi_tls_write(
            session->tls,
            session->tx_partial_buf + session->tx_partial_off,
            session->tx_partial_len - session->tx_partial_off,
            &wrote);
        if (st == NINLIL_WIFI_OK
            || (st == NINLIL_WIFI_WOULD_BLOCK && wrote > 0u)) {
            session->tx_partial_off += wrote;
            if (session->tx_partial_off >= session->tx_partial_len) {
                st = note_tx_record_completed(
                    session, session->tx_partial_buf, partial_length);
                if (st != NINLIL_WIFI_OK) {
                    return st;
                }
                session->tx_partial_len = 0u;
                session->tx_partial_off = 0u;
            }
            return NINLIL_WIFI_OK;
        }
        return st;
    }

    st = ninlil_wifi_queue_peek(&session->txq, &rec, &rec_len);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    st = ninlil_wifi_tls_write(session->tls, rec, rec_len, &wrote);
    if (st == NINLIL_WIFI_OK) {
        st = note_tx_record_completed(session, rec, rec_len);
        if (st != NINLIL_WIFI_OK) {
            return st;
        }
        (void)ninlil_wifi_queue_pop(&session->txq);
        return NINLIL_WIFI_OK;
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK && wrote > 0u) {
        (void)memcpy(session->tx_partial_buf, rec, rec_len);
        session->tx_partial_len = rec_len;
        session->tx_partial_off = wrote;
        (void)ninlil_wifi_queue_pop(&session->txq);
        return NINLIL_WIFI_OK;
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_WIFI_BACKPRESSURE;
    }
    return st;
}

static ninlil_wifi_status_t pump_rx(ninlil_wifi_session_t *session)
{
    uint8_t chunk[512];
    size_t got = 0u;
    ninlil_wifi_status_t st;
    const uint8_t *record = NULL;
    size_t record_len = 0u;
    uint32_t sequence = 0u;

    /* Never TLS-read/decode when RX queue has no capacity. */
    if (ninlil_wifi_queue_is_full(&session->rxq)) {
        return NINLIL_WIFI_BACKPRESSURE;
    }

    st = ninlil_wifi_tls_read(session->tls, chunk, sizeof(chunk), &got);
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        got = 0u;
        st = NINLIL_WIFI_OK;
    } else if (st != NINLIL_WIFI_OK) {
        return st;
    }

    for (;;) {
        st = ninlil_wifi_rx_stream_feed(
            &session->rx,
            got > 0u ? chunk : NULL,
            got,
            &record,
            &record_len,
            &sequence);
        got = 0u;
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            return NINLIL_WIFI_OK;
        }
        if (st != NINLIL_WIFI_OK) {
            return fence_then_return(session, st);
        }
        st = ninlil_wifi_queue_push(&session->rxq, record, record_len);
        if (st == NINLIL_WIFI_BACKPRESSURE) {
            return NINLIL_WIFI_BACKPRESSURE;
        }
        if (st != NINLIL_WIFI_OK) {
            return st;
        }
        /* RX activity advances blackhole watermark. */
        if (session->mono_ms != NULL) {
            session->last_rx_activity_ms = session_mono_ms(session);
            session->missed_probes = 0u;
        }
    }
}

static ninlil_wifi_status_t reinit_tls_for_reconnect(
    ninlil_wifi_session_t *session)
{
    if (session->tls == NULL || !session->tls_paths_set) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    ninlil_wifi_tls_close(session->tls);
    (void)memset(session->tls_storage, 0, sizeof(session->tls_storage));
    session->tls = session_tls_from_storage(session);
    if (session->tls == NULL) {
        return NINLIL_WIFI_CORRUPT;
    }
    return ninlil_wifi_tls_init(
        session->tls, session->is_server, &session->tls_paths);
}

static ninlil_wifi_status_t try_auto_reconnect(ninlil_wifi_session_t *session)
{
    ninlil_wifi_endpoint_t ep;
    ninlil_wifi_status_t st;
    uint64_t now;
    if (!session->auto_reconnect || session->is_server) {
        return NINLIL_WIFI_FENCED;
    }
    now = session_mono_ms(session);
    if (!ninlil_wifi_reconnect_ready(&session->reconnect, now)) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    st = ninlil_wifi_reconnect_current_endpoint(&session->reconnect, &ep);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    st = reinit_tls_for_reconnect(session);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    session->endpoint = ep;
    session->use_failover =
        (session->reconnect.endpoints.index != 0u) ? 1 : 0;
    return ninlil_wifi_session_connect(session, &ep);
}

static ninlil_wifi_status_t enter_peer_session(ninlil_wifi_session_t *session)
{
    ninlil_wifi_status_t st;
    ninlil_wifi_leaf_binding_t peer_bind;
    ninlil_wifi_leaf_binding_t local_bind;
    ninlil_wifi_peer_context_inputs_t leaf_in;
    const ninlil_wifi_leaf_binding_t *client_bind;
    const ninlil_wifi_leaf_binding_t *server_bind;
    st = ninlil_wifi_tls_post_handshake_accept(session->tls);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    st = journal_write_point(
        session, 2u, (uint8_t)NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED);
    if (st != NINLIL_WIFI_OK) {
        /* Do not publish authenticated state or perform exporter work. */
        session_fail_journal(session, st);
        return st;
    }
    session->phase = NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED;

    /*
     * Peer_context authority/runtime_ids come from leaf OID bindings + SPKI
     * path (already enforced at handshake). Caller free-assertion alone is
     * not authority: assignment_epoch may be provisioned; authority/runtimes
     * must match leaf material.
     */
    st = ninlil_wifi_tls_peer_leaf_binding(session->tls, &peer_bind);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    st = ninlil_wifi_tls_local_leaf_binding(session->tls, &local_bind);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    if (session->is_server) {
        server_bind = &local_bind;
        client_bind = &peer_bind;
    } else {
        client_bind = &local_bind;
        server_bind = &peer_bind;
    }
    (void)memset(&leaf_in, 0, sizeof(leaf_in));
    (void)memcpy(leaf_in.authority_id, client_bind->authority_id, 16u);
    leaf_in.authority_term = client_bind->authority_term;
    (void)memcpy(
        leaf_in.tls_client_runtime_id, client_bind->runtime_id, 16u);
    (void)memcpy(
        leaf_in.tls_server_runtime_id, server_bind->runtime_id, 16u);
    if (session->peer_inputs_set) {
        /*
         * Provisioned inputs may supply assignment_epoch only when authority
         * group and runtimes match leaf (no free rewrite of identity).
         */
        if (memcmp(
                session->peer_inputs.authority_id, leaf_in.authority_id, 16u)
                != 0
            || session->peer_inputs.authority_term != leaf_in.authority_term
            || memcmp(
                   session->peer_inputs.tls_client_runtime_id,
                   leaf_in.tls_client_runtime_id,
                   16u)
                != 0
            || memcmp(
                   session->peer_inputs.tls_server_runtime_id,
                   leaf_in.tls_server_runtime_id,
                   16u)
                != 0) {
            return fence_then_return(session, NINLIL_WIFI_DENIED);
        }
        leaf_in.assignment_epoch = session->peer_inputs.assignment_epoch;
        leaf_in.allow_all_zero_authority =
            session->peer_inputs.allow_all_zero_authority;
    } else {
        /* Epoch must be non-zero for ALL_NONZERO bound group. */
        leaf_in.assignment_epoch = 1u;
        leaf_in.allow_all_zero_authority = 0u;
    }
    if (leaf_in.assignment_epoch == 0u
        && leaf_in.allow_all_zero_authority == 0u) {
        return fence_then_return(session, NINLIL_WIFI_DENIED);
    }
    st = ninlil_wifi_build_peer_context(&leaf_in, session->peer_context);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    /* Seal derived inputs as the session peer_inputs (leaf-bound). */
    session->peer_inputs = leaf_in;
    session->peer_inputs_set = 1;
    session->peer_context_valid = 1;
    st = ninlil_wifi_tls_export_peer_session_id(
        session->tls, session->peer_context, session->ids.peer_session_id);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    session->peer_session_valid = 1;
    session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
    ninlil_wifi_reconnect_note_success(&session->reconnect);
    /*
     * PEER_SESSION only: NWB1 send/recv remain 0 until M4 PA FULL + exporter2.
     * Do not transition to ATTACHED here.
     */
    if (session->attachment_expectation_set) {
        session->phase = NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_set_fabric_descriptor(
    ninlil_wifi_session_t *session,
    const uint8_t fabric_descriptor[32])
{
    if (session == NULL || fabric_descriptor == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (is_all_zero16(fabric_descriptor)
        && is_all_zero16(fabric_descriptor + 16)) {
        return NINLIL_WIFI_DENIED;
    }
    (void)memcpy(session->fabric_descriptor, fabric_descriptor, 32u);
    session->fabric_descriptor_set = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_confirm_m4_pa_full(
    ninlil_wifi_session_t *session,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32])
{
    /* Free-assertion path removed (P0-1). */
    (void)session;
    (void)attachment_authority_id;
    (void)active_attachment_binding_digest;
    return NINLIL_WIFI_DENIED;
}

ninlil_wifi_status_t ninlil_wifi_session_accept_m4_full_evidence(
    ninlil_wifi_session_t *session,
    ninlil_wifi_m4_full_evidence_t *evidence)
{
    ninlil_wifi_status_t st;
    ninlil_wifi_attached_context_inputs_t att_in;
    ninlil_wifi_m4_attach_material_t mat;
    uint8_t attached_context_candidate[NINLIL_WIFI_ATTACHED_CONTEXT_BYTES];
    uint8_t attached_id_candidate[16];
    if (session == NULL || evidence == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (session->phase != NINLIL_WIFI_PHASE_PEER_SESSION
        && session->phase != NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (!session->peer_session_valid
        || is_all_zero16(session->ids.peer_session_id)) {
        return NINLIL_WIFI_INVALID_STATE;
    }

    /*
     * Incomplete live evidence (membership/lease/durable FULL/Fabric registry):
     * ADR — remain PEER_SESSION, NWB1 publish 0. Not free-assertion booleans.
     */
    st = ninlil_wifi_m4_evidence_ready_for_attach(evidence);
    if (st != NINLIL_WIFI_OK) {
        session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        session->m4_pa_full_confirmed = 0;
        session->attached_session_valid = 0;
        return NINLIL_WIFI_OK;
    }
    st = ninlil_wifi_m4_evidence_export_attach_material(evidence, &mat);
    if (st != NINLIL_WIFI_OK) {
        session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        return NINLIL_WIFI_DENIED;
    }
    if (memcmp(mat.peer_session_id, session->ids.peer_session_id, 16u) != 0) {
        session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        return NINLIL_WIFI_DENIED;
    }

    st = ninlil_wifi_tls_post_handshake_accept(session->tls);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    if (!session->fabric_descriptor_set
        || memcmp(session->fabric_descriptor, mat.fabric_descriptor, 32u) != 0) {
        session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        return NINLIL_WIFI_DENIED;
    }
    if (session->credentials_required
        || ninlil_wifi_credential_is_active(&session->credentials)) {
        if (!ninlil_wifi_credential_is_active(&session->credentials)
            || memcmp(
                   session->credentials.committed.secret_ref_digest,
                   mat.credential_candidate_digest,
                   32u)
                != 0) {
            session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
            return NINLIL_WIFI_CREDENTIAL;
        }
    }
    if (session->attachment_expectation_set) {
        if (memcmp(
                session->expected_attachment_authority_id,
                mat.attachment_authority_id,
                16u)
                != 0
            || memcmp(
                   session->expected_attachment_binding,
                   mat.active_attachment_binding_digest,
                   32u)
                != 0) {
            session->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
            return NINLIL_WIFI_DENIED;
        }
    }

    (void)memset(&att_in, 0, sizeof(att_in));
    (void)memset(attached_context_candidate, 0, sizeof(attached_context_candidate));
    (void)memset(attached_id_candidate, 0, sizeof(attached_id_candidate));
    (void)memcpy(att_in.peer_session_id, session->ids.peer_session_id, 16u);
    (void)memcpy(
        att_in.attachment_authority_id, mat.attachment_authority_id, 16u);
    (void)memcpy(
        att_in.active_attachment_binding_digest,
        mat.active_attachment_binding_digest,
        32u);
    st = ninlil_wifi_build_attached_context(
        &att_in, attached_context_candidate);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    st = ninlil_wifi_tls_export_attached_session_id(
        session->tls,
        attached_context_candidate,
        attached_id_candidate);
    if (st != NINLIL_WIFI_OK) {
        return fence_then_return(session, st);
    }
    if (is_all_zero16(attached_id_candidate)) {
        return fence_then_return(session, NINLIL_WIFI_CORRUPT);
    }
    if (memcmp(
            session->ids.peer_session_id,
            attached_id_candidate,
            16u)
        == 0) {
        return fence_then_return(session, NINLIL_WIFI_CORRUPT);
    }
    /*
     * Persist point 3 before publishing ATTACHED, initializing NWB1, or
     * consuming the linear evidence. The session-id override is the exporter2
     * candidate, not mutable live state.
     */
    st = journal_write_point_values(
        session,
        3u,
        (uint8_t)NINLIL_WIFI_PHASE_ATTACHED,
        session->attempt_id,
        session->session_fence_generation,
        session->reconnect.endpoints.index,
        &session->endpoint,
        attached_id_candidate,
        1);
    if (st != NINLIL_WIFI_OK) {
        ninlil_wifi_m4_evidence_consume(evidence);
        (void)memset(
            attached_context_candidate, 0, sizeof(attached_context_candidate));
        (void)memset(attached_id_candidate, 0, sizeof(attached_id_candidate));
        session_fail_journal(session, st);
        return st;
    }
    session->phase = NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING;
    (void)memcpy(
        session->attached_context,
        attached_context_candidate,
        sizeof(attached_context_candidate));
    (void)memcpy(
        session->ids.attached_session_id, attached_id_candidate, 16u);
    session->attached_context_valid = 1;
    session->m4_pa_full_confirmed = 1;
    session->attached_session_valid = 1;
    ninlil_wifi_rx_stream_set_session(
        &session->rx, session->ids.attached_session_id, 0u);
    session->phase = NINLIL_WIFI_PHASE_ATTACHED;
    session->next_tx_sequence = 0u;
    session->last_tx_completed_valid = 0;
    session->sequence_rollover_close = 0;
    /* Ownership transfer: evidence capability is single-use after accept. */
    ninlil_wifi_m4_evidence_consume(evidence);
    (void)memset(
        attached_context_candidate, 0, sizeof(attached_context_candidate));
    (void)memset(attached_id_candidate, 0, sizeof(attached_id_candidate));
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_poll(ninlil_wifi_session_t *session)
{
    ninlil_wifi_status_t st;
    if (session == NULL || session->tls == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }

    if (session->phase == NINLIL_WIFI_PHASE_RECONNECT_WAIT) {
        return try_auto_reconnect(session);
    }

    if (session->phase == NINLIL_WIFI_PHASE_CONNECTING) {
        st = ninlil_wifi_tcp_poll_connected(&session->tcp);
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            return st;
        }
        if (st != NINLIL_WIFI_OK) {
            if (session->has_failover && !session->use_failover
                && !session->auto_reconnect) {
                session->use_failover = 1;
                return ninlil_wifi_session_connect(
                    session, &session->failover_endpoint);
            }
            return fence_then_return(session, st);
        }
        st = wifi_attach_tls_after_tcp(session);
        if (st != NINLIL_WIFI_OK) {
            return st;
        }
    }

    if (session->phase == NINLIL_WIFI_PHASE_HANDSHAKING) {
        st = ninlil_wifi_tls_handshake(session->tls);
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            return st;
        }
        if (st != NINLIL_WIFI_OK) {
            return fence_then_return(session, st);
        }
        return enter_peer_session(session);
    }

    if (session->phase == NINLIL_WIFI_PHASE_PEER_SESSION
        || session->phase == NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING
        || session->phase == NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED) {
        /* Waiting for M4 PA FULL — NWB1 0. */
        return NINLIL_WIFI_OK;
    }

    if (session->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        return NINLIL_WIFI_INVALID_STATE;
    }

    ninlil_wifi_reconnect_note_attached_stable(
        &session->reconnect, session_mono_ms(session));

    /*
     * Liveness (ADR-0018): blackhole detect via mono clock.
     * When last RX activity exceeds BLACKHOLE_DETECT_MS, fence once.
     */
    if (session->liveness_enabled && session->mono_ms != NULL) {
        uint64_t now = session_mono_ms(session);
        if (session->last_rx_activity_ms == 0u) {
            session->last_rx_activity_ms = now;
        }
        if (session->blackhole_force
            || (now > session->last_rx_activity_ms
                && (now - session->last_rx_activity_ms)
                    >= NINLIL_WIFI_BLACKHOLE_DETECT_MS)) {
            session->blackhole_force = 0;
            session->missed_probes = NINLIL_WIFI_MISSED_RESPONSE_THRESHOLD;
            return fence_then_return(session, NINLIL_WIFI_FENCED);
        }
        if (session->last_keepalive_tx_ms == 0u) {
            session->last_keepalive_tx_ms = now;
        } else if (
            now > session->last_keepalive_tx_ms
            && (now - session->last_keepalive_tx_ms)
                >= NINLIL_WIFI_KEEPALIVE_INTERVAL_MS) {
            /* Keepalive tick: record exclusive deadline window. */
            session->last_keepalive_tx_ms = now;
            session->missed_probes += 1u;
            if (session->missed_probes
                >= NINLIL_WIFI_MISSED_RESPONSE_THRESHOLD) {
                return fence_then_return(session, NINLIL_WIFI_FENCED);
            }
        }
    }

    st = pump_tx(session);
    if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
        && st != NINLIL_WIFI_BACKPRESSURE) {
        return fence_then_return(session, st);
    }
    st = pump_rx(session);
    if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
        && st != NINLIL_WIFI_BACKPRESSURE) {
        return fence_then_return(session, st);
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_send_payload(
    ninlil_wifi_session_t *session,
    const uint8_t *nfl1_payload,
    uint32_t payload_len)
{
    uint8_t record[NINLIL_WIFI_NWB1_TOTAL_MAX];
    size_t record_len = 0u;
    ninlil_wifi_status_t st;
    if (session == NULL || nfl1_payload == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    /* Fail closed: no NWB1 before M4 PA FULL + exporter2 ATTACHED. */
    if (session->phase != NINLIL_WIFI_PHASE_ATTACHED
        || !session->attached_session_valid
        || !session->m4_pa_full_confirmed) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (session->sequence_rollover_close) {
        return NINLIL_WIFI_CLOSED;
    }
    if (session->credentials_required
        && !ninlil_wifi_credential_is_active(&session->credentials)) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    /* UINT32_MAX is never sent; UINT32_MAX-1 is last sequence then clean close. */
    if (session->next_tx_sequence == UINT32_MAX) {
        session->sequence_rollover_close = 1;
        return fence_then_return(session, NINLIL_WIFI_CLOSED);
    }
    st = ninlil_wifi_nwb1_encode(
        session->ids.attached_session_id,
        session->next_tx_sequence,
        nfl1_payload,
        payload_len,
        record,
        sizeof(record),
        &record_len);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    st = ninlil_wifi_queue_push(&session->txq, record, record_len);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    if (session->next_tx_sequence == UINT32_MAX - 1u) {
        session->sequence_rollover_close = 1;
        session->next_tx_sequence = UINT32_MAX; /* mark exhausted */
    } else {
        session->next_tx_sequence += 1u;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_cancel_tx_sequence(
    ninlil_wifi_session_t *session,
    uint32_t sequence)
{
    uint32_t dropped;
    int partial_hit = 0;
    if (session == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    /* Drop partial in-flight buffer if it matches sequence (offset 32 BE). */
    if (session->tx_partial_len >= 36u) {
        uint32_t seq = ((uint32_t)session->tx_partial_buf[32] << 24)
            | ((uint32_t)session->tx_partial_buf[33] << 16)
            | ((uint32_t)session->tx_partial_buf[34] << 8)
            | (uint32_t)session->tx_partial_buf[35];
        if (seq == sequence) {
            session->tx_partial_len = 0u;
            session->tx_partial_off = 0u;
            partial_hit = 1;
        }
    }
    dropped = ninlil_wifi_queue_drop_sequence(&session->txq, sequence);
    /*
     * Partial-send cancel: fence so the next record is never written on this
     * stream (connection ownership reclaimed). Queued-only cancel does not
     * fence (record never left the host buffer).
     */
    if (partial_hit) {
        return ninlil_wifi_session_fence(session);
    }
    return (dropped > 0u) ? NINLIL_WIFI_OK : NINLIL_WIFI_UNAVAILABLE;
}

int ninlil_wifi_session_tx_sequence_completed(
    const ninlil_wifi_session_t *session,
    uint32_t sequence)
{
    if (session == NULL || !session->last_tx_completed_valid
        || sequence == UINT32_MAX) {
        return 0;
    }
    /*
     * NWB1 sequence never wraps within a session and TX is ordered, therefore
     * a later completed sequence proves every earlier non-cancelled sequence
     * reached the same transport-complete boundary.
     */
    return sequence <= session->last_tx_completed_sequence;
}

ninlil_wifi_status_t ninlil_wifi_session_recv_record(
    ninlil_wifi_session_t *session,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    uint32_t *sequence_out)
{
    const uint8_t *rec = NULL;
    size_t rec_len = 0u;
    ninlil_wifi_status_t st;
    uint32_t sequence = 0u;
    if (session == NULL || out == NULL || out_len == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (session->phase != NINLIL_WIFI_PHASE_ATTACHED
        || !session->attached_session_valid) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    st = ninlil_wifi_queue_peek(&session->rxq, &rec, &rec_len);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    if (out_cap < rec_len) {
        return NINLIL_WIFI_CAPACITY;
    }
    (void)memcpy(out, rec, rec_len);
    *out_len = rec_len;
    if (sequence_out != NULL) {
        sequence = ((uint32_t)rec[32] << 24) | ((uint32_t)rec[33] << 16)
            | ((uint32_t)rec[34] << 8) | (uint32_t)rec[35];
        *sequence_out = sequence;
    }
    return ninlil_wifi_queue_pop(&session->rxq);
}

ninlil_wifi_status_t ninlil_wifi_session_get_session_ids(
    const ninlil_wifi_session_t *session,
    uint8_t peer_session_id_out[16],
    uint8_t attached_session_id_out[16])
{
    if (session == NULL || peer_session_id_out == NULL
        || attached_session_id_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (!session->peer_session_valid) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    (void)memcpy(peer_session_id_out, session->ids.peer_session_id, 16u);
    if (session->attached_session_valid) {
        (void)memcpy(
            attached_session_id_out, session->ids.attached_session_id, 16u);
    } else {
        /* PEER_SESSION: attached id not yet exported — return zeros, OK. */
        (void)memset(attached_session_id_out, 0, 16u);
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_session_get_contexts(
    const ninlil_wifi_session_t *session,
    uint8_t peer_context_out[62],
    uint8_t attached_context_out[64])
{
    if (session == NULL || peer_context_out == NULL
        || attached_context_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (!session->peer_context_valid) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    (void)memcpy(
        peer_context_out, session->peer_context, NINLIL_WIFI_PEER_CONTEXT_BYTES);
    if (!session->attached_context_valid) {
        (void)memset(attached_context_out, 0, 64u);
        return NINLIL_WIFI_INVALID_STATE;
    }
    (void)memcpy(
        attached_context_out,
        session->attached_context,
        NINLIL_WIFI_ATTACHED_CONTEXT_BYTES);
    return NINLIL_WIFI_OK;
}
