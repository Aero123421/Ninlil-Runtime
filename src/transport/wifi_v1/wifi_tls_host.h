#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_HOST_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_HOST_H

/*
 * Host OpenSSL 3 TLS1.3 mutual-auth adapter (ADR-0018 Host pin path).
 * Secrets are never logged. PEM paths are process-local file paths only.
 */
#include "wifi_tcp_posix.h"
#include "wifi_tls_leaf_binding.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_tls_paths {
    const char *ca_pem_path;
    const char *cert_pem_path;
    const char *key_pem_path;
} ninlil_wifi_tls_paths_t;

typedef struct ninlil_wifi_tls ninlil_wifi_tls_t;

size_t ninlil_wifi_tls_sizeof(void);

/*
 * 1 only when build/link authority is pinned static OpenSSL 3.5.7 and the
 * runtime identity also matches.  A system library with the same version is
 * not authority.
 */
int ninlil_wifi_tls_host_profile_authority(void);

ninlil_wifi_status_t ninlil_wifi_tls_init(
    ninlil_wifi_tls_t *tls,
    int is_server,
    const ninlil_wifi_tls_paths_t *paths);

void ninlil_wifi_tls_close(ninlil_wifi_tls_t *tls);

/* Attach already-connected nonblocking TCP fd. Takes ownership of transport
 * lifetime only for SSL BIO; caller still closes tcp on teardown after TLS. */
ninlil_wifi_status_t ninlil_wifi_tls_attach_fd(
    ninlil_wifi_tls_t *tls,
    int fd);

ninlil_wifi_status_t ninlil_wifi_tls_handshake(ninlil_wifi_tls_t *tls);

/*
 * After successful handshake: SHA-256 of peer leaf SPKI (SubjectPublicKeyInfo).
 * Binds peer identity to attachment path. DENIED if no peer cert.
 */
ninlil_wifi_status_t ninlil_wifi_tls_peer_leaf_spki_sha256(
    ninlil_wifi_tls_t *tls,
    uint8_t out_spki_sha256[32]);

/* Same exact SPKI digest for the configured local leaf. */
ninlil_wifi_status_t ninlil_wifi_tls_local_leaf_spki_sha256(
    ninlil_wifi_tls_t *tls,
    uint8_t out_spki_sha256[32]);

/*
 * Extract ADR-0018 §14.2 leaf binding (OID SAN / GeneralNames) from peer or
 * local leaf. Required for runtime/authority binding — free caller assertion
 * of peer_context without matching leaf is DENIED at session entry.
 */
ninlil_wifi_status_t ninlil_wifi_tls_peer_leaf_binding(
    ninlil_wifi_tls_t *tls,
    ninlil_wifi_leaf_binding_t *out);

ninlil_wifi_status_t ninlil_wifi_tls_local_leaf_binding(
    ninlil_wifi_tls_t *tls,
    ninlil_wifi_leaf_binding_t *out);

ninlil_wifi_status_t ninlil_wifi_tls_write(
    ninlil_wifi_tls_t *tls,
    const uint8_t *data,
    size_t len,
    size_t *written_out);

ninlil_wifi_status_t ninlil_wifi_tls_read(
    ninlil_wifi_tls_t *tls,
    uint8_t *data,
    size_t cap,
    size_t *read_out);

int ninlil_wifi_tls_is_ready(const ninlil_wifi_tls_t *tls);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_HOST_H */
