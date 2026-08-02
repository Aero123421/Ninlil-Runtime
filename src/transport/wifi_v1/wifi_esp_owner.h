#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_OWNER_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_OWNER_H

/*
 * ESP sole-owner async event/state model (ADR-0018).
 * Callbacks only enqueue fixed records; owner step alone drives Wi-Fi/socket/TLS.
 * GOT_IP + current generation required before TCP/TLS.
 *
 * Dual-core: callback producer and owner consumer share a locked ring
 * (FreeRTOS portMUX on ESP, pthread on host). Callbacks never call fence /
 * TLS close / TCP close / phase mutation.
 */
#include "wifi_attachment_m4.h"
#include "wifi_budget.h"
#include "wifi_credentials.h"
#include "wifi_esp_events.h"
#include "wifi_esp_sta.h"
#include "wifi_esp_tcp.h"
#include "wifi_esp_tls_mbedtls.h"
#include "wifi_private_types.h"
#include "wifi_queues.h" /* ninlil_wifi_record_slot_t */
#include "wifi_reconnect.h"

#if defined(ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#endif
/* ESP owner always single-record stream (even when measured on Host). */
#ifndef NINLIL_WIFI_RX_STREAM_SINGLE_RECORD
#define NINLIL_WIFI_RX_STREAM_SINGLE_RECORD 1
#endif
#include "wifi_stream.h"
#include "wifi_tls_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_esp_owner {
    ninlil_wifi_phase_t phase;
    uint64_t availability_epoch;
    uint32_t session_fence_generation;
    uint32_t next_tx_sequence;
    uint32_t last_tx_completed_sequence;
    uint8_t last_tx_completed_valid;
    uint8_t reserved_tx_completion[3];
    uint64_t event_generation;
    uint64_t last_processed_generation;
    uint64_t got_ip_generation; /* generation of last accepted GOT_IP */
    int got_ip;
    int associated;
    ninlil_wifi_endpoint_t endpoint;
    ninlil_wifi_session_ids_t ids;
    ninlil_wifi_esp_tcp_t tcp;
    /* TLS object is external (heap/static outside 12 KiB owner workspace). */
    ninlil_wifi_esp_tls_t *tls;
    uint8_t tls_is_server;
    uint8_t tls_configured;
    uint8_t reserved_tls_state[2];
    ninlil_wifi_rx_stream_t rx;
    /* ESP-depth record slots (not Host 8-deep queues). */
    ninlil_wifi_record_slot_t tx_slots[NINLIL_WIFI_ESP_TX_TOKEN_MAX];
    ninlil_wifi_record_slot_t rx_slots[NINLIL_WIFI_ESP_RX_RECORD_MAX];
    uint8_t tx_count;
    uint8_t rx_count;
    uint8_t tx_head;
    uint8_t rx_head;
    ninlil_wifi_reconnect_t reconnect;
    ninlil_wifi_esp_sta_t *sta;
    ninlil_wifi_peer_context_inputs_t peer_inputs;
    int peer_inputs_set;
    uint8_t peer_context[62];
    uint8_t attached_context[64];
    int peer_session_valid;
    int attached_session_valid;
    int m4_pa_full_confirmed;
    uint8_t expected_attachment_authority_id[16];
    uint8_t expected_attachment_binding[32];
    int attachment_expectation_set;
    uint8_t fabric_descriptor[NINLIL_WIFI_M4_FABRIC_DESCRIPTOR_BYTES];
    int fabric_descriptor_set;
    ninlil_wifi_credential_store_t credentials;
    int credentials_required;
    size_t tx_partial_off;
    uint8_t tx_partial_buf[NINLIL_WIFI_NWB1_TOTAL_MAX];
    size_t tx_partial_len;
    /*
     * Callback producer / owner consumer ring.
     * Synchronized by FreeRTOS portMUX (ESP) or pthread mutex (host).
     * Callbacks may only copy-enqueue; never fence/TLS/TCP/phase.
     */
    ninlil_wifi_esp_event_record_t event_q[NINLIL_WIFI_ESP_EVENT_QUEUE_MAX];
    uint8_t event_head;
    uint8_t event_tail;
    uint8_t event_count;
    uint8_t event_overflow; /* set by callback; owner_step alone fences */
    uint8_t sequence_close_after_drain;
    uint8_t last_got_ip4[4]; /* owner-task IP authority for change detect */
    uint8_t has_last_got_ip4;
    /*
     * Permanent fail-closed marker: availability/fence generations never
     * wrap and therefore can never make a stale capability current again.
     */
    uint8_t availability_epoch_exhausted;
#if defined(ESP_PLATFORM)
    portMUX_TYPE event_lock;
#else
    void *event_lock; /* pthread_mutex_t* storage, owner-owned */
    uint8_t event_lock_storage[64]; /* opaque pthread_mutex_t room */
#endif
    /* Measured static footprint for budget gate (not just header constants). */
    uint32_t measured_workspace_bytes;
} ninlil_wifi_esp_owner_t;

/* Compile-time proof that owner workspace fits ESP 12 KiB contract. */
_Static_assert(
    sizeof(ninlil_wifi_esp_owner_t) <= NINLIL_WIFI_ESP_SESSION_WORKSPACE_BYTES,
    "esp owner exceeds session workspace budget");
/* Host-measured stamp for map/resource gate (updated when layout changes). */
/* Host-measured with single-record stream + durable credential bind fields. */
#define NINLIL_WIFI_ESP_OWNER_MEASURED_BYTES 9088u
_Static_assert(
    sizeof(ninlil_wifi_esp_owner_t) == NINLIL_WIFI_ESP_OWNER_MEASURED_BYTES
        || sizeof(ninlil_wifi_esp_owner_t) <= NINLIL_WIFI_ESP_SESSION_WORKSPACE_BYTES,
    "remeasure owner bytes and update NINLIL_WIFI_ESP_OWNER_MEASURED_BYTES");

void ninlil_wifi_esp_owner_init(ninlil_wifi_esp_owner_t *owner);

/* Bind external TLS object (must outlive owner; not counted in 12 KiB). */
void ninlil_wifi_esp_owner_bind_tls(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_esp_tls_t *tls);

/* Bind STA control block; owner step drives request_connect after STA_START. */
void ninlil_wifi_esp_owner_bind_sta(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_esp_sta_t *sta);

void ninlil_wifi_esp_owner_close(ninlil_wifi_esp_owner_t *owner);

/* Event sink for STA callbacks: copy-only enqueue (ip4 optional for GOT_IP). */
ninlil_wifi_status_t ninlil_wifi_esp_owner_event_sink(
    void *owner_user,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change,
    const uint8_t *ip4);

/*
 * Callback-safe: copy-only enqueue under lock.
 * Never fences / closes TLS-TCP / mutates phase (overflow defers to owner_step).
 * ip4 non-NULL only for GOT_IP (exactly 4 bytes).
 */
ninlil_wifi_status_t ninlil_wifi_esp_owner_enqueue_event(
    ninlil_wifi_esp_owner_t *owner,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change);

ninlil_wifi_status_t ninlil_wifi_esp_owner_enqueue_event_ip(
    ninlil_wifi_esp_owner_t *owner,
    uint8_t kind,
    uint8_t disconnect_reason,
    uint8_t ip_change,
    const uint8_t *ip4);

/* Owner loop: process up to max_work events/steps. */
ninlil_wifi_status_t ninlil_wifi_esp_owner_step(
    ninlil_wifi_esp_owner_t *owner,
    uint32_t max_work,
    uint32_t *out_work_done);

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_peer_context_inputs(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_peer_context_inputs_t *inputs);

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_attachment_expectation(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32]);

ninlil_wifi_status_t ninlil_wifi_esp_owner_set_fabric_descriptor(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t fabric_descriptor[32]);

/* Free-assertion path removed — always DENIED. */
ninlil_wifi_status_t ninlil_wifi_esp_owner_confirm_m4_pa_full(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t attachment_authority_id[16],
    const uint8_t active_attachment_binding_digest[32]);

/* M4 FULL from completed-path evidence only (carrier/durable/cred/fabric). */
ninlil_wifi_status_t ninlil_wifi_esp_owner_accept_m4_full_evidence(
    ninlil_wifi_esp_owner_t *owner,
    ninlil_wifi_m4_full_evidence_t *evidence);

ninlil_wifi_status_t ninlil_wifi_esp_owner_configure_tls(
    ninlil_wifi_esp_owner_t *owner,
    int is_server,
    const ninlil_wifi_esp_tls_pem_t *pems);

/* Exact durable leaf pins; must be installed before connect/handshake. */
ninlil_wifi_status_t ninlil_wifi_esp_owner_set_tls_identity_expectation(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation);

/* Requires GOT_IP and current generation; no TCP before IP_READY. */
ninlil_wifi_status_t ninlil_wifi_esp_owner_connect(
    ninlil_wifi_esp_owner_t *owner,
    const ninlil_wifi_endpoint_t *endpoint);

ninlil_wifi_status_t ninlil_wifi_esp_owner_send_payload(
    ninlil_wifi_esp_owner_t *owner,
    const uint8_t *nfl1_payload,
    uint32_t payload_len);

int ninlil_wifi_esp_owner_tx_sequence_completed(
    const ninlil_wifi_esp_owner_t *owner,
    uint32_t sequence);

/*
 * Cancels an unstarted queued record. A partially written record fences the
 * stream because removing its suffix would corrupt NWB1 framing.
 */
ninlil_wifi_status_t ninlil_wifi_esp_owner_cancel_tx_sequence(
    ninlil_wifi_esp_owner_t *owner,
    uint32_t sequence);

ninlil_wifi_status_t ninlil_wifi_esp_owner_recv_record(
    ninlil_wifi_esp_owner_t *owner,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    uint32_t *sequence_out);

void ninlil_wifi_esp_owner_fence(ninlil_wifi_esp_owner_t *owner);

/* Actual measured workspace size for resource gate. */
uint32_t ninlil_wifi_esp_owner_measured_workspace_bytes(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_OWNER_H */
