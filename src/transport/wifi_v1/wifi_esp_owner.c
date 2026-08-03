#include "wifi_esp_owner.h"

#include "wifi_nwb1.h"

#include <stdint.h>
#include <string.h>

#if defined(ESP_PLATFORM)
/* event_lock is portMUX_TYPE in the owner struct. */
#else
#include <pthread.h>
_Static_assert(
    sizeof(pthread_mutex_t) <= 64u,
    "host event_lock_storage too small for pthread_mutex_t");
#endif

uint32_t ninlil_wifi_esp_owner_measured_workspace_bytes(void)
{
    return (uint32_t)sizeof(ninlil_wifi_esp_owner_t);
}

static void event_lock_init(ninlil_wifi_esp_owner_t *owner)
{
#if defined(ESP_PLATFORM)
    portMUX_INITIALIZE(&owner->event_lock);
#else
    pthread_mutex_t *m =
        (pthread_mutex_t *)(void *)owner->event_lock_storage;
    (void)memset(owner->event_lock_storage, 0, sizeof(owner->event_lock_storage));
    (void)pthread_mutex_init(m, NULL);
    owner->event_lock = m;
#endif
}

static void event_lock_enter(ninlil_wifi_esp_owner_t *owner)
{
#if defined(ESP_PLATFORM)
    portENTER_CRITICAL(&owner->event_lock);
#else
    if (owner->event_lock != NULL) {
        (void)pthread_mutex_lock((pthread_mutex_t *)owner->event_lock);
    }
#endif
}

static void event_lock_exit(ninlil_wifi_esp_owner_t *owner)
{
#if defined(ESP_PLATFORM)
    portEXIT_CRITICAL(&owner->event_lock);
#else
    if (owner->event_lock != NULL) {
        (void)pthread_mutex_unlock((pthread_mutex_t *)owner->event_lock);
    }
#endif
}

void ninlil_wifi_esp_owner_init(ninlil_wifi_esp_owner_t *owner)
{
    if (owner == NULL) {
        return;
    }
    (void)memset(owner, 0, sizeof(*owner));
    ninlil_wifi_esp_tcp_init(&owner->tcp);
    ninlil_wifi_rx_stream_init(&owner->rx);
    owner->tx_count = 0u;
    owner->rx_count = 0u;
    owner->tx_head = 0u;
    owner->rx_head = 0u;
    ninlil_wifi_reconnect_init(&owner->reconnect);
    ninlil_wifi_credential_store_init(&owner->credentials);
    owner->availability_epoch = 1u;
    owner->measured_workspace_bytes =
        ninlil_wifi_esp_owner_measured_workspace_bytes();
    owner->tls = NULL;
    owner->sta = NULL;
    event_lock_init(owner);
}

void ninlil_wifi_esp_owner_bind_tls(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_esp_tls_t *tls)
{
    if (owner == NULL) {
        return;
    }
    owner->tls = tls;
}

void ninlil_wifi_esp_owner_bind_sta(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_esp_sta_t *sta)
{
    if (owner == NULL) {
        return;
    }
    owner->sta = sta;
    if (sta != NULL) {
        ninlil_wifi_esp_sta_bind_event_sink(
            sta, ninlil_wifi_esp_owner_event_sink, owner);
    }
}

void ninlil_wifi_esp_owner_close(ninlil_wifi_esp_owner_t *owner)
{
    if (owner == NULL) {
        return;
    }
    if (owner->tls != NULL) {
        ninlil_wifi_esp_tls_close(owner->tls);
        owner->tls = NULL;
    }
    owner->tls_configured = 0u;
    ninlil_wifi_esp_tcp_close(&owner->tcp);
    owner->phase = NINLIL_WIFI_PHASE_CLOSED;
    owner->tx_partial_len = 0u;
    owner->tx_partial_off = 0u;
    owner->got_ip = 0;
    owner->associated = 0;
}

void ninlil_wifi_esp_owner_fence(ninlil_wifi_esp_owner_t *owner)
{
    if (owner == NULL) {
        return;
    }
    /*
     * One stream failure publishes one fence. Re-observing the already fenced
     * state is idempotent and cannot consume another generation.
     */
    if (owner->phase != NINLIL_WIFI_PHASE_FENCED) {
        if (owner->session_fence_generation != UINT32_MAX) {
            owner->session_fence_generation += 1u;
        } else {
            owner->availability_epoch_exhausted = 1u;
        }
        if (owner->availability_epoch != UINT64_MAX) {
            owner->availability_epoch += 1u;
        } else {
            owner->availability_epoch_exhausted = 1u;
        }
    }
    owner->phase = NINLIL_WIFI_PHASE_FENCED;
    owner->tx_partial_len = 0u;
    owner->tx_partial_off = 0u;
    owner->peer_session_valid = 0;
    owner->attached_session_valid = 0;
    owner->m4_pa_full_confirmed = 0;
    owner->last_tx_completed_valid = 0u;
    (void)memset(owner->ids.peer_session_id, 0, 16u);
    (void)memset(owner->ids.attached_session_id, 0, 16u);
    if (owner->tls != NULL) {
        ninlil_wifi_esp_tls_close(owner->tls);
    }
    owner->tls_configured = 0u;
    ninlil_wifi_esp_tcp_close(&owner->tcp);
    owner->tx_count = 0u;
    owner->rx_count = 0u;
    owner->tx_head = 0u;
    owner->rx_head = 0u;
    ninlil_wifi_rx_stream_init(&owner->rx);
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_event_sink(
    void *owner_user,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change,
    const uint8_t *ip4)
{
    return ninlil_wifi_esp_owner_enqueue_event_ip(
        (ninlil_wifi_esp_owner_t *)owner_user,
        kind,
        disconnect_reason,
        ip_change,
        ip4);
}

/*
 * Copy-only enqueue under dual-core lock.
 * MUST NOT call owner_fence / TLS close / TCP close / phase mutation.
 * Overflow or generation wrap → set event_overflow for owner_step.
 */
ninlil_wifi_status_t ninlil_wifi_esp_owner_enqueue_event_ip(
    ninlil_wifi_esp_owner_t *owner,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change,
    const uint8_t *ip4)
{
    ninlil_wifi_esp_event_record_t rec;
    if (owner == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(&rec, 0, sizeof(rec));
    rec.kind = kind;
    rec.disconnect_reason = disconnect_reason;
    rec.ip_change = ip_change;
    if (ip4 != NULL) {
        rec.has_ip4 = 1u;
        (void)memcpy(rec.ip4, ip4, 4u);
    }

    event_lock_enter(owner);
    if (owner->event_count >= NINLIL_WIFI_ESP_EVENT_QUEUE_MAX
        || owner->event_generation == UINT64_MAX) {
        owner->event_overflow = 1u;
        event_lock_exit(owner);
        /* Deferred fence: owner_step alone mutates phase/TLS/TCP. */
        return NINLIL_WIFI_CAPACITY;
    }
    owner->event_generation += 1u;
    rec.generation = owner->event_generation;
    owner->event_q[owner->event_tail] = rec;
    owner->event_tail =
        (uint8_t)((owner->event_tail + 1u) % NINLIL_WIFI_ESP_EVENT_QUEUE_MAX);
    owner->event_count = (uint8_t)(owner->event_count + 1u);
    event_lock_exit(owner);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_enqueue_event(
    ninlil_wifi_esp_owner_t *owner,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change)
{
    return ninlil_wifi_esp_owner_enqueue_event_ip(
        owner, kind, disconnect_reason, ip_change, NULL);
}

static ninlil_wifi_status_t pop_event(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_esp_event_record_t *out)
{
    ninlil_wifi_status_t st = NINLIL_WIFI_WOULD_BLOCK;
    event_lock_enter(owner);
    if (owner->event_count > 0u) {
        *out = owner->event_q[owner->event_head];
        owner->event_head = (uint8_t)(
            (owner->event_head + 1u) % NINLIL_WIFI_ESP_EVENT_QUEUE_MAX);
        owner->event_count = (uint8_t)(owner->event_count - 1u);
        st = NINLIL_WIFI_OK;
    }
    event_lock_exit(owner);
    return st;
}

static void process_event(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_esp_event_record_t *ev)
{
    uint8_t ip_change = ev->ip_change;
    if (ev->generation <= owner->last_processed_generation) {
        return; /* old/duplicate */
    }
    if (owner->last_processed_generation == UINT64_MAX ||
        ev->generation != owner->last_processed_generation + 1u) {
        /*
         * A missing callback record means the owner cannot prove the order in
         * which association/IP authority changed.  Never skip across that
         * hole: invalidate the transport/session in the sole-owner context.
         */
        ninlil_wifi_esp_owner_fence(owner);
        return;
    }
    owner->last_processed_generation = ev->generation;
    switch (ev->kind) {
    case NINLIL_WIFI_ESP_EV_STA_START:
        /* Owner step alone requests connect (not in callback). */
        if (owner->sta != NULL) {
            (void)ninlil_wifi_esp_sta_request_connect(owner->sta);
        }
        break;
    case NINLIL_WIFI_ESP_EV_STA_CONNECTED:
        owner->associated = 1;
        break;
    case NINLIL_WIFI_ESP_EV_GOT_IP:
        /* Owner-task IP authority + STA observational mirror. */
        if (ev->has_ip4 != 0u) {
            if (owner->has_last_got_ip4 != 0u
                && memcmp(owner->last_got_ip4, ev->ip4, 4u) != 0) {
                ip_change = 1u;
            }
            (void)memcpy(owner->last_got_ip4, ev->ip4, 4u);
            owner->has_last_got_ip4 = 1u;
            if (owner->sta != NULL) {
                ninlil_wifi_esp_sta_owner_note_got_ip(owner->sta, ev->ip4);
            }
        } else if (owner->sta != NULL) {
            uint8_t zero_ip[4] = {0, 0, 0, 0};
            ninlil_wifi_esp_sta_owner_note_got_ip(owner->sta, zero_ip);
        }
        owner->got_ip = 1;
        owner->got_ip_generation = ev->generation;
        break;
    case NINLIL_WIFI_ESP_EV_STA_DISCONNECTED:
        if (owner->sta != NULL) {
            ninlil_wifi_esp_sta_owner_note_fail(owner->sta);
        }
        owner->got_ip = 0;
        owner->associated = 0;
        owner->has_last_got_ip4 = 0u;
        ninlil_wifi_esp_owner_fence(owner);
        break;
    case NINLIL_WIFI_ESP_EV_LOST_IP:
        if (owner->sta != NULL) {
            ninlil_wifi_esp_sta_owner_note_lost_ip(owner->sta);
        }
        owner->got_ip = 0;
        owner->associated = 0;
        owner->has_last_got_ip4 = 0u;
        ninlil_wifi_esp_owner_fence(owner);
        break;
    case NINLIL_WIFI_ESP_EV_FENCE:
        ninlil_wifi_esp_owner_fence(owner);
        break;
    default:
        break;
    }
    if (ip_change != 0u && owner->got_ip) {
        ninlil_wifi_esp_owner_fence(owner);
        owner->got_ip = 0;
        owner->has_last_got_ip4 = 0u;
    }
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_peer_context_inputs(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_peer_context_inputs_t *inputs)
{
    if (owner == NULL || inputs == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    owner->peer_inputs = *inputs;
    owner->peer_inputs_set = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_attachment_expectation(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32])
{
    if (owner == NULL || attachment_authority_id == NULL
        || active_attachment_binding_digest == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memcpy(
        owner->expected_attachment_authority_id, attachment_authority_id, 16u);
    (void)memcpy(
        owner->expected_attachment_binding,
        active_attachment_binding_digest,
        32u);
    owner->attachment_expectation_set = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_configure_tls(
    ninlil_wifi_esp_owner_t *owner,
    int is_server,
    const ninlil_wifi_esp_tls_pem_t *pems)
{
    ninlil_wifi_status_t status;
    if (owner == NULL || pems == NULL || owner->tls == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    owner->tls_configured = 0u;
    status = ninlil_wifi_esp_tls_init(owner->tls, is_server, pems);
    if (status == NINLIL_WIFI_OK) {
        owner->tls_is_server = is_server ? 1u : 0u;
        owner->tls_configured = 1u;
    }
    return status;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_tls_identity_expectation(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation)
{
    if (owner == NULL || owner->tls == NULL || !owner->tls_configured
        || expectation == NULL) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    return ninlil_wifi_esp_tls_set_identity_expectation(
        owner->tls, expectation);
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_connect(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_endpoint_t *endpoint)
{
    ninlil_wifi_status_t st;
    if (owner == NULL || endpoint == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (owner->availability_epoch_exhausted != 0u
        || owner->availability_epoch == 0u) {
        return NINLIL_WIFI_FENCED;
    }
    /* Exact GOT_IP + generation before any TCP/TLS (ADR-0018 IP_READY). */
    if (!owner->got_ip || owner->got_ip_generation == 0u) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (owner->tls == NULL || !owner->tls_configured) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    owner->endpoint = *endpoint;
    owner->phase = NINLIL_WIFI_PHASE_CONNECTING;
    st = owner->tls_is_server
        ? ninlil_wifi_esp_tcp_listen(&owner->tcp, endpoint)
        : ninlil_wifi_esp_tcp_connect(&owner->tcp, endpoint);
    if (owner->tls_is_server && st == NINLIL_WIFI_OK) {
        return NINLIL_WIFI_OK; /* stay CONNECTING until accept */
    }
    if (st == NINLIL_WIFI_OK) {
        st = ninlil_wifi_esp_tls_attach_fd(owner->tls, owner->tcp.fd);
        if (st != NINLIL_WIFI_OK) {
            return st;
        }
        owner->phase = NINLIL_WIFI_PHASE_HANDSHAKING;
        return NINLIL_WIFI_OK;
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_WIFI_OK; /* stay CONNECTING; step polls */
    }
    return st;
}

static int is_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static ninlil_wifi_status_t drive_handshake(ninlil_wifi_esp_owner_t *owner)
{
    ninlil_wifi_status_t st;
    if (owner->phase == NINLIL_WIFI_PHASE_CONNECTING) {
        st = owner->tls_is_server
            ? ninlil_wifi_esp_tcp_poll_accepted(&owner->tcp)
            : ninlil_wifi_esp_tcp_poll_connected(&owner->tcp);
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            return st;
        }
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        st = ninlil_wifi_esp_tls_attach_fd(owner->tls, owner->tcp.fd);
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        owner->phase = NINLIL_WIFI_PHASE_HANDSHAKING;
    }
    if (owner->phase == NINLIL_WIFI_PHASE_HANDSHAKING) {
        const ninlil_wifi_leaf_binding_t *client_leaf;
        const ninlil_wifi_leaf_binding_t *server_leaf;
        ninlil_wifi_esp_tls_verified_identity_t verified;
        ninlil_wifi_peer_context_inputs_t authenticated_inputs;
        st = ninlil_wifi_esp_tls_handshake(owner->tls);
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            return st;
        }
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        st = ninlil_wifi_esp_tls_post_handshake_accept(owner->tls);
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        st = ninlil_wifi_esp_tls_verified_identity(owner->tls, &verified);
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        owner->phase = NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED;
        if (!owner->peer_inputs_set) {
            ninlil_wifi_esp_owner_fence(owner);
            return NINLIL_WIFI_INVALID_STATE;
        }
        client_leaf = owner->tls_is_server
            ? &verified.peer_leaf
            : &verified.local_leaf;
        server_leaf = owner->tls_is_server
            ? &verified.local_leaf
            : &verified.peer_leaf;
        /*
         * assignment_epoch is not a certificate field. It remains a durable
         * provisioning input; every identity-bearing field is derived from
         * the verified leaves and caller values are accepted only if exact.
         */
        if (memcmp(
                owner->peer_inputs.authority_id,
                verified.local_leaf.authority_id,
                16u)
                != 0
            || owner->peer_inputs.authority_term
                != verified.local_leaf.authority_term
            || memcmp(
                   owner->peer_inputs.tls_client_runtime_id,
                   client_leaf->runtime_id,
                   16u)
                != 0
            || memcmp(
                   owner->peer_inputs.tls_server_runtime_id,
                   server_leaf->runtime_id,
                   16u)
                != 0) {
            ninlil_wifi_esp_owner_fence(owner);
            return NINLIL_WIFI_CREDENTIAL;
        }
        if (owner->attachment_expectation_set) {
            if (memcmp(
                    owner->expected_attachment_authority_id,
                    verified.local_leaf.authority_id,
                    16u)
                    != 0
                || memcmp(
                       owner->expected_attachment_binding,
                       verified.local_leaf
                           .authorized_attachment_binding_digest,
                       32u)
                    != 0) {
                ninlil_wifi_esp_owner_fence(owner);
                return NINLIL_WIFI_CREDENTIAL;
            }
        } else {
            (void)memcpy(
                owner->expected_attachment_authority_id,
                verified.local_leaf.authority_id,
                16u);
            (void)memcpy(
                owner->expected_attachment_binding,
                verified.local_leaf.authorized_attachment_binding_digest,
                32u);
            owner->attachment_expectation_set = 1;
        }
        (void)memset(&authenticated_inputs, 0, sizeof(authenticated_inputs));
        (void)memcpy(
            authenticated_inputs.authority_id,
            verified.local_leaf.authority_id,
            16u);
        authenticated_inputs.authority_term =
            verified.local_leaf.authority_term;
        authenticated_inputs.assignment_epoch =
            owner->peer_inputs.assignment_epoch;
        (void)memcpy(
            authenticated_inputs.tls_client_runtime_id,
            client_leaf->runtime_id,
            16u);
        (void)memcpy(
            authenticated_inputs.tls_server_runtime_id,
            server_leaf->runtime_id,
            16u);
        st = ninlil_wifi_build_peer_context(
            &authenticated_inputs, owner->peer_context);
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        st = ninlil_wifi_esp_tls_export_peer_session_id(
            owner->tls, owner->peer_context, owner->ids.peer_session_id);
        if (st != NINLIL_WIFI_OK) {
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        owner->peer_session_valid = 1;
        owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        if (owner->attachment_expectation_set) {
            owner->phase = NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING;
        }
        return NINLIL_WIFI_OK;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_fabric_descriptor(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t fabric_descriptor[32])
{
    if (owner == NULL || fabric_descriptor == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (is_all_zero(fabric_descriptor, 32u)) {
        return NINLIL_WIFI_DENIED;
    }
    (void)memcpy(owner->fabric_descriptor, fabric_descriptor, 32u);
    owner->fabric_descriptor_set = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_confirm_m4_pa_full(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32])
{
    (void)owner;
    (void)attachment_authority_id;
    (void)active_attachment_binding_digest;
    return NINLIL_WIFI_DENIED;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_accept_m4_full_evidence(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_m4_full_evidence_t *evidence)
{
    ninlil_wifi_status_t st;
    ninlil_wifi_attached_context_inputs_t att_in;
    ninlil_wifi_m4_attach_material_t mat;
    if (owner == NULL || evidence == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (owner->phase != NINLIL_WIFI_PHASE_PEER_SESSION
        && owner->phase != NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (!owner->peer_session_valid
        || is_all_zero(owner->ids.peer_session_id, 16u) || owner->tls == NULL) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    st = ninlil_wifi_m4_evidence_ready_for_attach(evidence);
    if (st != NINLIL_WIFI_OK) {
        owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        owner->m4_pa_full_confirmed = 0;
        owner->attached_session_valid = 0;
        return NINLIL_WIFI_OK;
    }
    st = ninlil_wifi_m4_evidence_export_attach_material(evidence, &mat);
    if (st != NINLIL_WIFI_OK) {
        owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        return NINLIL_WIFI_DENIED;
    }
    if (memcmp(mat.peer_session_id, owner->ids.peer_session_id, 16u) != 0) {
        owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        return NINLIL_WIFI_DENIED;
    }
    st = ninlil_wifi_esp_tls_post_handshake_accept(owner->tls);
    if (st != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_fence(owner);
        return st;
    }
    if (!owner->fabric_descriptor_set
        || memcmp(owner->fabric_descriptor, mat.fabric_descriptor, 32u) != 0) {
        owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
        return NINLIL_WIFI_DENIED;
    }
    if (owner->credentials_required
        || ninlil_wifi_credential_is_active(&owner->credentials)) {
        if (!ninlil_wifi_credential_is_active(&owner->credentials)
            || memcmp(
                   owner->credentials.committed.secret_ref_digest,
                   mat.credential_candidate_digest,
                   32u)
                != 0) {
            owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
            return NINLIL_WIFI_CREDENTIAL;
        }
    }
    if (owner->attachment_expectation_set) {
        if (memcmp(
                owner->expected_attachment_authority_id,
                mat.attachment_authority_id,
                16u)
                != 0
            || memcmp(
                   owner->expected_attachment_binding,
                   mat.active_attachment_binding_digest,
                   32u)
                != 0) {
            owner->phase = NINLIL_WIFI_PHASE_PEER_SESSION;
            return NINLIL_WIFI_DENIED;
        }
    }
    (void)memset(&att_in, 0, sizeof(att_in));
    (void)memcpy(att_in.peer_session_id, owner->ids.peer_session_id, 16u);
    (void)memcpy(
        att_in.attachment_authority_id, mat.attachment_authority_id, 16u);
    (void)memcpy(
        att_in.active_attachment_binding_digest,
        mat.active_attachment_binding_digest,
        32u);
    st = ninlil_wifi_build_attached_context(&att_in, owner->attached_context);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    st = ninlil_wifi_esp_tls_export_attached_session_id(
        owner->tls, owner->attached_context, owner->ids.attached_session_id);
    if (st != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_fence(owner);
        return st;
    }
    if (is_all_zero(owner->ids.attached_session_id, 16u)) {
        ninlil_wifi_esp_owner_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    owner->m4_pa_full_confirmed = 1;
    owner->attached_session_valid = 1;
    ninlil_wifi_rx_stream_set_session(
        &owner->rx, owner->ids.attached_session_id, 0u);
    owner->phase = NINLIL_WIFI_PHASE_ATTACHED;
    owner->next_tx_sequence = 0u;
    owner->last_tx_completed_valid = 0u;
    ninlil_wifi_m4_evidence_consume(evidence);
    return NINLIL_WIFI_OK;
}

static ninlil_wifi_status_t pump_tx(ninlil_wifi_esp_owner_t *owner)
{
    ninlil_wifi_status_t st;
    size_t wrote = 0u;
    ninlil_wifi_record_slot_t *slot;

    if (owner->phase != NINLIL_WIFI_PHASE_ATTACHED || owner->tls == NULL) {
        return NINLIL_WIFI_INVALID_STATE;
    }

    if (owner->tx_partial_len > 0u) {
        st = ninlil_wifi_esp_tls_write(
            owner->tls,
            owner->tx_partial_buf + owner->tx_partial_off,
            owner->tx_partial_len - owner->tx_partial_off,
            &wrote);
        if (st == NINLIL_WIFI_OK
            || (st == NINLIL_WIFI_WOULD_BLOCK && wrote > 0u)) {
            owner->tx_partial_off += wrote;
            if (owner->tx_partial_off >= owner->tx_partial_len) {
                owner->last_tx_completed_sequence =
                    ((uint32_t)owner->tx_partial_buf[32] << 24)
                    | ((uint32_t)owner->tx_partial_buf[33] << 16)
                    | ((uint32_t)owner->tx_partial_buf[34] << 8)
                    | (uint32_t)owner->tx_partial_buf[35];
                owner->last_tx_completed_valid = 1u;
                owner->tx_partial_len = 0u;
                owner->tx_partial_off = 0u;
                if (owner->sequence_close_after_drain != 0u &&
                    owner->tx_count == 0u) {
                    goto sequence_drained;
                }
            }
            return NINLIL_WIFI_OK;
        }
        if (st == NINLIL_WIFI_WOULD_BLOCK) {
            return NINLIL_WIFI_WOULD_BLOCK;
        }
        ninlil_wifi_esp_owner_fence(owner);
        return st;
    }

    if (owner->tx_count == 0u) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    slot = &owner->tx_slots[owner->tx_head];
    if (!slot->in_use || slot->length == 0u) {
        return NINLIL_WIFI_CORRUPT;
    }
    st = ninlil_wifi_esp_tls_write(
        owner->tls, slot->bytes, slot->length, &wrote);
    if (st == NINLIL_WIFI_OK && wrote == slot->length) {
        owner->last_tx_completed_sequence =
            ((uint32_t)slot->bytes[32] << 24)
            | ((uint32_t)slot->bytes[33] << 16)
            | ((uint32_t)slot->bytes[34] << 8)
            | (uint32_t)slot->bytes[35];
        owner->last_tx_completed_valid = 1u;
        slot->in_use = 0u;
        owner->tx_head =
            (uint8_t)((owner->tx_head + 1u) % NINLIL_WIFI_ESP_TX_TOKEN_MAX);
        owner->tx_count = (uint8_t)(owner->tx_count - 1u);
        if (owner->sequence_close_after_drain != 0u &&
            owner->tx_count == 0u) {
            goto sequence_drained;
        }
        return NINLIL_WIFI_OK;
    }
    if ((st == NINLIL_WIFI_OK || st == NINLIL_WIFI_WOULD_BLOCK) && wrote > 0u
        && wrote < slot->length) {
        (void)memcpy(owner->tx_partial_buf, slot->bytes, slot->length);
        owner->tx_partial_len = slot->length;
        owner->tx_partial_off = wrote;
        slot->in_use = 0u;
        owner->tx_head =
            (uint8_t)((owner->tx_head + 1u) % NINLIL_WIFI_ESP_TX_TOKEN_MAX);
        owner->tx_count = (uint8_t)(owner->tx_count - 1u);
        return NINLIL_WIFI_OK;
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_WIFI_BACKPRESSURE;
    }
    ninlil_wifi_esp_owner_fence(owner);
    return st;

sequence_drained:
    /*
     * UINT32_MAX is never emitted.  After UINT32_MAX-1 is fully written,
     * close this authenticated session cleanly so the caller must establish a
     * fresh full handshake/M4 session whose sequence restarts at zero.
     */
    owner->sequence_close_after_drain = 0u;
    owner->peer_session_valid = 0;
    owner->attached_session_valid = 0;
    owner->m4_pa_full_confirmed = 0;
    (void)memset(owner->ids.peer_session_id, 0, 16u);
    (void)memset(owner->ids.attached_session_id, 0, 16u);
    if (owner->tls != NULL) {
        ninlil_wifi_esp_tls_close(owner->tls);
    }
    owner->tls_configured = 0u;
    ninlil_wifi_esp_tcp_close(&owner->tcp);
    ninlil_wifi_rx_stream_init(&owner->rx);
    owner->rx_count = 0u;
    owner->rx_head = 0u;
    if (owner->availability_epoch == UINT64_MAX) {
        owner->availability_epoch_exhausted = 1u;
        owner->phase = NINLIL_WIFI_PHASE_FENCED;
        return NINLIL_WIFI_FENCED;
    }
    owner->availability_epoch += 1u;
    owner->phase = NINLIL_WIFI_PHASE_CLOSED;
    return NINLIL_WIFI_CLOSED;
}

static ninlil_wifi_status_t pump_rx(ninlil_wifi_esp_owner_t *owner)
{
    uint8_t chunk[512];
    size_t got = 0u;
    ninlil_wifi_status_t st;
    const uint8_t *record = NULL;
    size_t record_len = 0u;
    uint32_t sequence = 0u;
    uint8_t slot_i;

    if (owner->phase != NINLIL_WIFI_PHASE_ATTACHED || owner->tls == NULL) {
        return NINLIL_WIFI_INVALID_STATE;
    }

    /* Never TLS-read/decode when RX slot capacity is exhausted. */
    if (owner->rx_count >= NINLIL_WIFI_ESP_RX_RECORD_MAX) {
        return NINLIL_WIFI_BACKPRESSURE;
    }

    st = ninlil_wifi_esp_tls_read(owner->tls, chunk, sizeof(chunk), &got);
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        got = 0u;
        st = NINLIL_WIFI_OK;
    } else if (st != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_fence(owner);
        return st;
    }

    for (;;) {
        st = ninlil_wifi_rx_stream_feed(
            &owner->rx,
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
            ninlil_wifi_esp_owner_fence(owner);
            return st;
        }
        if (owner->rx_count >= NINLIL_WIFI_ESP_RX_RECORD_MAX) {
            return NINLIL_WIFI_BACKPRESSURE;
        }
        slot_i = (uint8_t)((owner->rx_head + owner->rx_count)
            % NINLIL_WIFI_ESP_RX_RECORD_MAX);
        if (record_len > sizeof(owner->rx_slots[slot_i].bytes)) {
            ninlil_wifi_esp_owner_fence(owner);
            return NINLIL_WIFI_CORRUPT;
        }
        (void)memcpy(owner->rx_slots[slot_i].bytes, record, record_len);
        owner->rx_slots[slot_i].length = (uint16_t)record_len;
        owner->rx_slots[slot_i].in_use = 1u;
        owner->rx_count = (uint8_t)(owner->rx_count + 1u);
    }
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_step(
    ninlil_wifi_esp_owner_t *owner,
    uint32_t max_work,
    uint32_t *out_work_done)
{
    uint32_t done = 0u;
    uint8_t overflowed = 0u;
    if (out_work_done != NULL) {
        *out_work_done = 0u;
    }
    if (owner == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (owner->availability_epoch_exhausted != 0u
        || owner->availability_epoch == 0u) {
        return NINLIL_WIFI_FENCED;
    }
    /*
     * Callback producers never mutate owner phase/TLS/TCP. Convert a queue
     * overflow or generation-wrap marker into a fence only on the owner step,
     * and discard every queued event from the compromised generation.
     */
    event_lock_enter(owner);
    if (owner->event_overflow != 0u) {
        overflowed = 1u;
        owner->event_overflow = 0u;
        owner->event_head = 0u;
        owner->event_tail = 0u;
        owner->event_count = 0u;
    }
    event_lock_exit(owner);
    if (overflowed != 0u) {
        ninlil_wifi_esp_owner_fence(owner);
        if (out_work_done != NULL) {
            *out_work_done = 1u;
        }
        return NINLIL_WIFI_FENCED;
    }
    if (max_work == 0u || max_work > 64u) {
        max_work = 1u;
    }
    while (done < max_work) {
        ninlil_wifi_esp_event_record_t ev;
        if (pop_event(owner, &ev) == NINLIL_WIFI_OK) {
            process_event(owner, &ev);
            done += 1u;
            continue;
        }
        if (owner->phase == NINLIL_WIFI_PHASE_CONNECTING
            || owner->phase == NINLIL_WIFI_PHASE_HANDSHAKING) {
            ninlil_wifi_status_t handshake_status = drive_handshake(owner);
            done += 1u;
            if (handshake_status != NINLIL_WIFI_OK
                && handshake_status != NINLIL_WIFI_WOULD_BLOCK) {
                if (out_work_done != NULL) {
                    *out_work_done = done;
                }
                return handshake_status;
            }
            continue;
        }
        if (owner->phase == NINLIL_WIFI_PHASE_ATTACHED) {
            ninlil_wifi_status_t tx_st;
            ninlil_wifi_status_t rx_st;
            tx_st = pump_tx(owner);
            rx_st = pump_rx(owner);
            done += 1u;
            if (tx_st != NINLIL_WIFI_OK && tx_st != NINLIL_WIFI_WOULD_BLOCK
                && tx_st != NINLIL_WIFI_BACKPRESSURE
                && tx_st != NINLIL_WIFI_INVALID_STATE) {
                if (out_work_done != NULL) {
                    *out_work_done = done;
                }
                return tx_st;
            }
            if (rx_st != NINLIL_WIFI_OK && rx_st != NINLIL_WIFI_WOULD_BLOCK
                && rx_st != NINLIL_WIFI_BACKPRESSURE) {
                if (out_work_done != NULL) {
                    *out_work_done = done;
                }
                return rx_st;
            }
            /* One ATTACHED tick per step iteration; avoid spin. */
            break;
        }
        break;
    }
    if (out_work_done != NULL) {
        *out_work_done = done;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_send_payload(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t *nfl1_payload,
    uint32_t payload_len)
{
    uint8_t record[NINLIL_WIFI_NWB1_TOTAL_MAX];
    size_t record_len = 0u;
    ninlil_wifi_status_t st;
    uint8_t slot;
    if (owner == NULL || nfl1_payload == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (owner->phase != NINLIL_WIFI_PHASE_ATTACHED
        || !owner->attached_session_valid || !owner->m4_pa_full_confirmed) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (owner->sequence_close_after_drain != 0u ||
        owner->next_tx_sequence == UINT32_MAX) {
        return NINLIL_WIFI_SEQUENCE_REJECT;
    }
    if (owner->tx_count >= NINLIL_WIFI_ESP_TX_TOKEN_MAX) {
        return NINLIL_WIFI_BACKPRESSURE;
    }
    st = ninlil_wifi_nwb1_encode(
        owner->ids.attached_session_id,
        owner->next_tx_sequence,
        nfl1_payload,
        payload_len,
        record,
        sizeof(record),
        &record_len);
    if (st != NINLIL_WIFI_OK) {
        return st;
    }
    slot = (uint8_t)((owner->tx_head + owner->tx_count)
        % NINLIL_WIFI_ESP_TX_TOKEN_MAX);
    (void)memcpy(owner->tx_slots[slot].bytes, record, record_len);
    owner->tx_slots[slot].length = (uint16_t)record_len;
    owner->tx_slots[slot].in_use = 1u;
    owner->tx_count = (uint8_t)(owner->tx_count + 1u);
    if (owner->next_tx_sequence == UINT32_MAX - 1u) {
        owner->sequence_close_after_drain = 1u;
    }
    owner->next_tx_sequence += 1u;
    return NINLIL_WIFI_OK;
}

int ninlil_wifi_esp_owner_tx_sequence_completed(
    const ninlil_wifi_esp_owner_t *owner,
    uint32_t sequence)
{
    return owner != NULL && owner->last_tx_completed_valid != 0u
        && owner->last_tx_completed_sequence == sequence;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_cancel_tx_sequence(
    ninlil_wifi_esp_owner_t *owner,
    uint32_t sequence)
{
    uint32_t queued_sequence;
    uint32_t partial_sequence;
    ninlil_wifi_record_slot_t *slot;
    if (owner == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_esp_owner_tx_sequence_completed(owner, sequence)) {
        return NINLIL_WIFI_OK;
    }
    if (owner->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (owner->tx_partial_len >= NINLIL_WIFI_NWB1_HEADER_BYTES) {
        partial_sequence =
            ((uint32_t)owner->tx_partial_buf[32] << 24)
            | ((uint32_t)owner->tx_partial_buf[33] << 16)
            | ((uint32_t)owner->tx_partial_buf[34] << 8)
            | (uint32_t)owner->tx_partial_buf[35];
        if (partial_sequence == sequence) {
            ninlil_wifi_esp_owner_fence(owner);
            return NINLIL_WIFI_FENCED;
        }
    }
    if (owner->tx_count == 0u) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    slot = &owner->tx_slots[owner->tx_head];
    if (!slot->in_use || slot->length < NINLIL_WIFI_NWB1_HEADER_BYTES) {
        ninlil_wifi_esp_owner_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    queued_sequence = ((uint32_t)slot->bytes[32] << 24)
        | ((uint32_t)slot->bytes[33] << 16)
        | ((uint32_t)slot->bytes[34] << 8)
        | (uint32_t)slot->bytes[35];
    if (queued_sequence != sequence) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    (void)memset(slot, 0, sizeof(*slot));
    owner->tx_count = 0u;
    owner->tx_head = 0u;
    owner->sequence_close_after_drain = 0u;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_owner_recv_record(
    ninlil_wifi_esp_owner_t *owner,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    uint32_t *sequence_out)
{
    ninlil_wifi_record_slot_t *slot;
    if (owner == NULL || out == NULL || out_len == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (owner->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (owner->rx_count == 0u) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    slot = &owner->rx_slots[owner->rx_head];
    if (out_cap < slot->length) {
        return NINLIL_WIFI_CAPACITY;
    }
    (void)memcpy(out, slot->bytes, slot->length);
    *out_len = slot->length;
    if (sequence_out != NULL) {
        *sequence_out = ((uint32_t)slot->bytes[32] << 24)
            | ((uint32_t)slot->bytes[33] << 16)
            | ((uint32_t)slot->bytes[34] << 8)
            | (uint32_t)slot->bytes[35];
    }
    slot->in_use = 0u;
    owner->rx_head =
        (uint8_t)((owner->rx_head + 1u) % NINLIL_WIFI_ESP_RX_RECORD_MAX);
    owner->rx_count = (uint8_t)(owner->rx_count - 1u);
    return NINLIL_WIFI_OK;
}
