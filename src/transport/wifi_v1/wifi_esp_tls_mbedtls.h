/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TLS_MBEDTLS_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TLS_MBEDTLS_H

/*
 * ESP direct mbedTLS TLS1.3 mutual-auth path (ADR-0018).
 * Does not use esp_tls public API. Secrets never logged.
 */
#include "wifi_private_types.h"
#include "wifi_tls_leaf_binding.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_esp_tls_pem {
    const uint8_t *ca_pem;
    size_t ca_pem_len;
    const uint8_t *cert_pem;
    size_t cert_pem_len;
    const uint8_t *key_pem;
    size_t key_pem_len;
} ninlil_wifi_esp_tls_pem_t;

typedef struct ninlil_wifi_esp_tls ninlil_wifi_esp_tls_t;

/*
 * Durable provisioning pins both role-specific leaves bit-for-bit at the
 * binding level.  The TLS backend derives the authenticated identity from the
 * certificates and compares it with this record; callers cannot assert a
 * runtime/role/authority tuple after the handshake.
 */
typedef struct ninlil_wifi_esp_tls_identity_expectation {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_wifi_leaf_binding_t local_leaf;
    ninlil_wifi_leaf_binding_t peer_leaf;
    uint8_t reserved_zero[4];
} ninlil_wifi_esp_tls_identity_expectation_t;

#define NINLIL_WIFI_ESP_TLS_IDENTITY_EXPECTATION_VERSION 1u

typedef struct ninlil_wifi_esp_tls_verified_identity {
    ninlil_wifi_leaf_binding_t local_leaf;
    ninlil_wifi_leaf_binding_t peer_leaf;
} ninlil_wifi_esp_tls_verified_identity_t;

size_t ninlil_wifi_esp_tls_sizeof(void);

ninlil_wifi_status_t ninlil_wifi_esp_tls_init(
    ninlil_wifi_esp_tls_t *tls,
    int is_server,
    const ninlil_wifi_esp_tls_pem_t *pems);

/*
 * Must be called after init and before attach/handshake.  The expectation is
 * copied.  Both local and peer leaves are exact-pinned, including credential
 * and revocation generations.
 */
ninlil_wifi_status_t ninlil_wifi_esp_tls_set_identity_expectation(
    ninlil_wifi_esp_tls_t *tls,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation);

void ninlil_wifi_esp_tls_close(ninlil_wifi_esp_tls_t *tls);

ninlil_wifi_status_t ninlil_wifi_esp_tls_attach_fd(
    ninlil_wifi_esp_tls_t *tls,
    int fd);

ninlil_wifi_status_t ninlil_wifi_esp_tls_handshake(ninlil_wifi_esp_tls_t *tls);

ninlil_wifi_status_t ninlil_wifi_esp_tls_write(
    ninlil_wifi_esp_tls_t *tls,
    const uint8_t *data,
    size_t len,
    size_t *written_out);

ninlil_wifi_status_t ninlil_wifi_esp_tls_read(
    ninlil_wifi_esp_tls_t *tls,
    uint8_t *data,
    size_t cap,
    size_t *read_out);

/* Exporter outputs are exact 16-byte IDs; contexts are 62/64-byte inputs. */
ninlil_wifi_status_t ninlil_wifi_esp_tls_export_peer_session_id(
    ninlil_wifi_esp_tls_t *tls,
    const uint8_t peer_context[62],
    uint8_t peer_session_id_out[16]);

ninlil_wifi_status_t ninlil_wifi_esp_tls_export_attached_session_id(
    ninlil_wifi_esp_tls_t *tls,
    const uint8_t attached_context[64],
    uint8_t session_id_out[16]);

ninlil_wifi_status_t ninlil_wifi_esp_tls_post_handshake_accept(
    ninlil_wifi_esp_tls_t *tls);

/* Available only after the post-handshake identity check succeeds. */
ninlil_wifi_status_t ninlil_wifi_esp_tls_verified_identity(
    ninlil_wifi_esp_tls_t *tls,
    ninlil_wifi_esp_tls_verified_identity_t *out);

/*
 * Pure, backend-independent exact-match predicate used by Host negative
 * matrices and by the ESP mbedTLS path after extracting both leaf bindings.
 */
ninlil_wifi_status_t ninlil_wifi_esp_tls_identity_match(
    int is_server,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation,
    const ninlil_wifi_leaf_binding_t *local_leaf,
    const ninlil_wifi_leaf_binding_t *peer_leaf,
    ninlil_wifi_esp_tls_verified_identity_t *out);

#if !defined(ESP_PLATFORM)
/*
 * Host software path only: pair two TLS objects for owner SM tests (loopback
 * byte pipes). Not physical radio, not real TLS exporter authority.
 */
void ninlil_wifi_esp_tls_host_pair(
    ninlil_wifi_esp_tls_t *a,
    ninlil_wifi_esp_tls_t *b);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TLS_MBEDTLS_H */
