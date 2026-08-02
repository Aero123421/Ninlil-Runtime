#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_SESSION_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_SESSION_H

#include <stddef.h>

#include "wifi_attachment_m4.h"
#include "wifi_credentials.h"
#include "wifi_journal.h"
#include "wifi_queues.h"
#include "wifi_reconnect.h"
#include "wifi_stream.h"
#include "wifi_tcp_posix.h"
#include "wifi_tls_export.h"
#include "wifi_tls_host.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Optional monotonic clock for reconnect backoff (ms). NULL = no auto wait. */
typedef uint64_t (*ninlil_wifi_mono_ms_fn)(void *user);

/*
 * Host OpenSSL TLS object is cast from this byte storage (wifi_tls_host.c /
 * wifi_tls_export.c). Storage must be max_align_t-aligned so pointer members
 * (SSL*, SSL_CTX*) are well-defined; plain uint8_t[] is only 1-byte aligned
 * and triggers UBSan misaligned-pointer-use under real sanitizer runs.
 */
#define NINLIL_WIFI_TLS_STORAGE_BYTES 2048u

typedef struct ninlil_wifi_session {
    ninlil_wifi_phase_t phase;
    uint64_t availability_epoch;
    uint32_t session_fence_generation;
    uint32_t next_tx_sequence;
    uint32_t last_tx_completed_sequence;
    uint32_t missed_probes;
    ninlil_wifi_endpoint_t endpoint;
    ninlil_wifi_endpoint_t failover_endpoint;
    int has_failover;
    ninlil_wifi_session_ids_t ids;
    ninlil_wifi_tcp_t tcp;
    _Alignas(max_align_t) uint8_t tls_storage[NINLIL_WIFI_TLS_STORAGE_BYTES];
    ninlil_wifi_tls_t *tls;
    ninlil_wifi_rx_stream_t rx;
    ninlil_wifi_record_queue_t txq;
    ninlil_wifi_record_queue_t rxq;
    ninlil_wifi_credential_store_t credentials;
    ninlil_wifi_reconnect_t reconnect;
    ninlil_wifi_journal_t journal;
    int journal_enabled;
    /*
     * Last checked journal result. In particular COMMIT_UNKNOWN remains
     * observable after the session has closed/fenced its transport.
     */
    ninlil_wifi_status_t last_journal_status;
    uint64_t attempt_id;
    /* Exporter *contexts* (inputs) and *ids* (16-byte outputs). */
    uint8_t peer_context[NINLIL_WIFI_PEER_CONTEXT_BYTES];
    uint8_t attached_context[NINLIL_WIFI_ATTACHED_CONTEXT_BYTES];
    int peer_context_valid;
    int attached_context_valid;
    int peer_session_valid;
    int attached_session_valid;
    int m4_pa_full_confirmed;
    ninlil_wifi_peer_context_inputs_t peer_inputs;
    int peer_inputs_set;
    uint8_t expected_attachment_authority_id[16];
    uint8_t expected_attachment_binding[32];
    int attachment_expectation_set;
    /* Provisioned Fabric descriptor for M4 bit-exact match (required for ATTACHED). */
    uint8_t fabric_descriptor[NINLIL_WIFI_M4_FABRIC_DESCRIPTOR_BYTES];
    int fabric_descriptor_set;
    ninlil_wifi_mono_ms_fn mono_ms;
    void *mono_user;
    int auto_reconnect;
    size_t tx_partial_off;
    uint8_t tx_partial_buf[NINLIL_WIFI_NWB1_TOTAL_MAX];
    size_t tx_partial_len;
    int use_failover;
    ninlil_wifi_tls_paths_t tls_paths;
    int tls_paths_set;
    int is_server;
    int credentials_required;
    /* After sending sequence UINT32_MAX-1: clean close, require fresh handshake. */
    int sequence_rollover_close;
    /*
     * Completion/epoch authority is session-local and monotonic.
     * completed_valid is reset for every fresh TLS/NWB1 session.
     * availability_epoch_exhausted prevents UINT64 wrap from re-publishing
     * an apparently fresh link.
     */
    int last_tx_completed_valid;
    int availability_epoch_exhausted;
    /* Liveness (ADR-0018): keepalive / blackhole use mono_ms when set. */
    uint64_t last_rx_activity_ms;
    uint64_t last_keepalive_tx_ms;
    int liveness_enabled;
    /* Test/inject: force blackhole threshold evaluation on next poll. */
    int blackhole_force;
} ninlil_wifi_session_t;

/* Compile-time: storage size, max_align_t placement, object alignment. */
_Static_assert(
    sizeof(((ninlil_wifi_session_t *)0)->tls_storage)
        == NINLIL_WIFI_TLS_STORAGE_BYTES,
    "wifi_session tls_storage size");
_Static_assert(
    (offsetof(ninlil_wifi_session_t, tls_storage) % _Alignof(max_align_t))
        == 0u,
    "wifi_session tls_storage offset must be max_align_t-aligned");
_Static_assert(
    _Alignof(ninlil_wifi_session_t) >= _Alignof(max_align_t),
    "wifi_session object must preserve max_align_t for tls_storage");
_Static_assert(
    NINLIL_WIFI_TLS_STORAGE_BYTES >= 64u,
    "wifi_session tls_storage must fit host OpenSSL adapter");

void ninlil_wifi_session_init(ninlil_wifi_session_t *session);

/* Test/inject: force blackhole fence on next ATTACHED poll (exact path). */
void ninlil_wifi_session_force_blackhole(ninlil_wifi_session_t *session);

void ninlil_wifi_session_close(ninlil_wifi_session_t *session);

void ninlil_wifi_session_set_mono_clock(
    ninlil_wifi_session_t *session,
    ninlil_wifi_mono_ms_fn fn,
    void *user);

void ninlil_wifi_session_set_auto_reconnect(
    ninlil_wifi_session_t *session,
    int enabled);

ninlil_wifi_status_t ninlil_wifi_session_bind_journal(
    ninlil_wifi_session_t *session,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8);

/* Authority/runtime inputs for peer_context construction (required for export). */
ninlil_wifi_status_t ninlil_wifi_session_set_peer_context_inputs(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_peer_context_inputs_t *inputs);

/*
 * Provision expected Fabric descriptor (32B). Required for M4 FULL accept.
 * Bit-exact match against evidence.fabric_descriptor.
 */
ninlil_wifi_status_t ninlil_wifi_session_set_fabric_descriptor(
    ninlil_wifi_session_t *session,
    const uint8_t fabric_descriptor[32]);

/*
 * Optional: pin expected authority/binding that evidence must also match
 * (provisioned verify). Not a substitute for durable evidence.
 */
ninlil_wifi_status_t ninlil_wifi_session_set_attachment_expectation(
    ninlil_wifi_session_t *session,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32]);

/*
 * Accept M4 PA FULL from completed-path evidence only.
 * - carrier unavailable => stay PEER_SESSION, NWB1 publish remains 0, return OK
 * - missing FULL durable / credential / fabric match => DENIED / stay PEER_SESSION
 * - success => second exporter + ATTACHED
 * Caller free-assertion digests without durable seal are rejected.
 */
ninlil_wifi_status_t ninlil_wifi_session_accept_m4_full_evidence(
    ninlil_wifi_session_t *session,
    ninlil_wifi_m4_full_evidence_t *evidence);

/*
 * Removed free-assertion path: always DENIED. Use accept_m4_full_evidence.
 */
ninlil_wifi_status_t ninlil_wifi_session_confirm_m4_pa_full(
    ninlil_wifi_session_t *session,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32]);

ninlil_wifi_status_t ninlil_wifi_session_configure_tls(
    ninlil_wifi_session_t *session,
    int is_server,
    const ninlil_wifi_tls_paths_t *paths);

ninlil_wifi_status_t ninlil_wifi_session_add_endpoint(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *endpoint);

/* Connect: no caller session_id identity. NWB1 id comes only from exporters. */
ninlil_wifi_status_t ninlil_wifi_session_connect(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *endpoint);

ninlil_wifi_status_t ninlil_wifi_session_accept_fd(
    ninlil_wifi_session_t *session,
    int fd);

ninlil_wifi_status_t ninlil_wifi_session_poll(ninlil_wifi_session_t *session);

/* NWB1 only when ATTACHED (M4 PA FULL + exporter2). */
ninlil_wifi_status_t ninlil_wifi_session_send_payload(
    ninlil_wifi_session_t *session,
    const uint8_t *nfl1_payload,
    uint32_t payload_len);

/*
 * Cancel a queued (or partial) TX record by NWB1 sequence. Used by Fabric
 * cancel/close to reclaim ownership before release. Returns OK if dropped.
 */
ninlil_wifi_status_t ninlil_wifi_session_cancel_tx_sequence(
    ninlil_wifi_session_t *session,
    uint32_t sequence);

/* Exact per-record transport completion; never aliases whole-queue emptiness. */
int ninlil_wifi_session_tx_sequence_completed(
    const ninlil_wifi_session_t *session,
    uint32_t sequence);

ninlil_wifi_status_t ninlil_wifi_session_recv_record(
    ninlil_wifi_session_t *session,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    uint32_t *sequence_out);

/*
 * Fence and close transport. Returns a checked point-4 journal result;
 * COMMIT_UNKNOWN is never hidden even though the runtime still fences.
 */
ninlil_wifi_status_t ninlil_wifi_session_fence(
    ninlil_wifi_session_t *session);

ninlil_wifi_status_t ninlil_wifi_session_last_journal_status(
    const ninlil_wifi_session_t *session);

ninlil_wifi_status_t ninlil_wifi_session_set_failover(
    ninlil_wifi_session_t *session,
    const ninlil_wifi_endpoint_t *endpoint);

/* 16-byte exporter IDs (not 62/64 contexts). */
ninlil_wifi_status_t ninlil_wifi_session_get_session_ids(
    const ninlil_wifi_session_t *session,
    uint8_t peer_session_id_out[16],
    uint8_t attached_session_id_out[16]);

/* Context builders (KAT surface). */
ninlil_wifi_status_t ninlil_wifi_session_get_contexts(
    const ninlil_wifi_session_t *session,
    uint8_t peer_context_out[62],
    uint8_t attached_context_out[64]);

ninlil_wifi_status_t ninlil_wifi_session_journal_recover(
    ninlil_wifi_session_t *session,
    ninlil_wifi_journal_attempt_t *out_attempt);

void ninlil_wifi_session_require_credentials(
    ninlil_wifi_session_t *session,
    int required);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_SESSION_H */
