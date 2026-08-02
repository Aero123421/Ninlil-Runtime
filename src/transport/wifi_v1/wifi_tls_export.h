#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_EXPORT_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_EXPORT_H

/*
 * ADR-0018 TLS exporter identity (exact):
 *
 *   peer_context[62] =
 *     authority_id[16] || authority_term_u64_be || assignment_epoch_u32_be ||
 *     0x01 || tls_client_runtime_id[16] || 0x02 || tls_server_runtime_id[16]
 *   peer_session_id[16] =
 *     TLS-Exporter("EXPORTER-Ninlil-PeerSession-v1", peer_context, 16)
 *
 *   attached_context[64] =
 *     peer_session_id[16] || attachment_authority_id[16] ||
 *     active_attachment_binding_digest[32]
 *   session_id[16] =
 *     TLS-Exporter("EXPORTER-Ninlil-NWB1-Attached-v1", attached_context, 16)
 *
 * Contexts are exporter *inputs* (62/64). IDs are exporter *outputs* (16/16).
 * Never export 62/64 bytes as identity.
 */
#if !defined(ESP_PLATFORM)
#include "wifi_tls_host.h"
#else
/* ESP uses wifi_esp_tls_mbedtls exporters; host TLS types are absent. */
#include "wifi_private_types.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_EXPORTER_PEER_LABEL "EXPORTER-Ninlil-PeerSession-v1"
#define NINLIL_WIFI_EXPORTER_ATTACHED_LABEL "EXPORTER-Ninlil-NWB1-Attached-v1"
#define NINLIL_WIFI_PEER_CONTEXT_BYTES 62u
#define NINLIL_WIFI_ATTACHED_CONTEXT_BYTES 64u
#define NINLIL_WIFI_PEER_SESSION_ID_BYTES 16u
#define NINLIL_WIFI_ATTACHED_SESSION_ID_BYTES 16u
#define NINLIL_WIFI_TLS_ROLE_CLIENT 0x01u
#define NINLIL_WIFI_TLS_ROLE_SERVER 0x02u

typedef struct ninlil_wifi_peer_context_inputs {
    uint8_t authority_id[16];
    uint64_t authority_term;
    uint32_t assignment_epoch;
    uint8_t tls_client_runtime_id[16];
    uint8_t tls_server_runtime_id[16];
    /*
     * Controllerless ALL_ZERO authority is DENIED unless this is 1.
     * BOUND profiles (default) require ALL_NONZERO authority group.
     */
    uint8_t allow_all_zero_authority;
    uint8_t reserved_pad[7];
} ninlil_wifi_peer_context_inputs_t;

typedef struct ninlil_wifi_attached_context_inputs {
    uint8_t peer_session_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t active_attachment_binding_digest[32];
} ninlil_wifi_attached_context_inputs_t;

/*
 * Build exact 62-byte peer_context.
 * Rejects: MIXED authority; ALL_ZERO without allow_all_zero_authority;
 * all-zero client or server runtime_id.
 */
ninlil_wifi_status_t ninlil_wifi_build_peer_context(
    const ninlil_wifi_peer_context_inputs_t *in,
    uint8_t peer_context_out[62]);

/* Build exact 64-byte attached_context. Requires non-zero peer_session_id. */
ninlil_wifi_status_t ninlil_wifi_build_attached_context(
    const ninlil_wifi_attached_context_inputs_t *in,
    uint8_t attached_context_out[64]);

#if !defined(ESP_PLATFORM)
/*
 * Host OpenSSL exporters. ESP uses wifi_esp_tls_mbedtls exporters.
 */
ninlil_wifi_status_t ninlil_wifi_tls_export_peer_session_id(
    ninlil_wifi_tls_t *tls,
    const uint8_t peer_context[62],
    uint8_t peer_session_id_out[16]);

ninlil_wifi_status_t ninlil_wifi_tls_export_attached_session_id(
    ninlil_wifi_tls_t *tls,
    const uint8_t attached_context[64],
    uint8_t session_id_out[16]);

ninlil_wifi_status_t ninlil_wifi_tls_post_handshake_accept(
    ninlil_wifi_tls_t *tls);
#endif

/* Authority group: ALL_NONZERO, ALL_ZERO, or MIXED (reject for session). */
typedef uint32_t ninlil_wifi_authority_group_t;
#define NINLIL_WIFI_AUTHORITY_ALL_NONZERO 1u
#define NINLIL_WIFI_AUTHORITY_ALL_ZERO 2u
#define NINLIL_WIFI_AUTHORITY_MIXED 3u

ninlil_wifi_authority_group_t ninlil_wifi_classify_authority_group(
    const uint8_t authority_id[16],
    uint64_t authority_term,
    uint32_t assignment_epoch);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_EXPORT_H */
