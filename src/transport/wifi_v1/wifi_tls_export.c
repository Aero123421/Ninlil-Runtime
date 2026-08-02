#include "wifi_tls_export.h"

#include <string.h>

#if !defined(ESP_PLATFORM)
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "wifi_tls_host_internal.h"
#endif

static void write_be_u64(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

static void write_be_u32(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
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

ninlil_wifi_authority_group_t ninlil_wifi_classify_authority_group(
    const uint8_t authority_id[16],
    uint64_t authority_term,
    uint32_t assignment_epoch)
{
    int id_zero;
    int term_zero;
    int epoch_zero;
    if (authority_id == NULL) {
        return NINLIL_WIFI_AUTHORITY_MIXED;
    }
    id_zero = is_all_zero(authority_id, 16u);
    term_zero = (authority_term == 0u) ? 1 : 0;
    epoch_zero = (assignment_epoch == 0u) ? 1 : 0;
    if (id_zero && term_zero && epoch_zero) {
        return NINLIL_WIFI_AUTHORITY_ALL_ZERO;
    }
    if (!id_zero && !term_zero && !epoch_zero) {
        return NINLIL_WIFI_AUTHORITY_ALL_NONZERO;
    }
    return NINLIL_WIFI_AUTHORITY_MIXED;
}

ninlil_wifi_status_t ninlil_wifi_build_peer_context(
    const ninlil_wifi_peer_context_inputs_t *in,
    uint8_t peer_context_out[62])
{
    ninlil_wifi_authority_group_t g;
    if (in == NULL || peer_context_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    g = ninlil_wifi_classify_authority_group(
        in->authority_id, in->authority_term, in->assignment_epoch);
    if (g == NINLIL_WIFI_AUTHORITY_MIXED) {
        return NINLIL_WIFI_DENIED;
    }
    /*
     * BOUND (default): ALL_NONZERO only.
     * Controllerless ALL_ZERO requires explicit allow_all_zero_authority=1.
     */
    if (g == NINLIL_WIFI_AUTHORITY_ALL_ZERO) {
        if (in->allow_all_zero_authority == 0u) {
            return NINLIL_WIFI_DENIED;
        }
    } else if (g != NINLIL_WIFI_AUTHORITY_ALL_NONZERO) {
        return NINLIL_WIFI_DENIED;
    }
    /* Runtime ids are identity material — never all-zero. */
    if (is_all_zero(in->tls_client_runtime_id, 16u)
        || is_all_zero(in->tls_server_runtime_id, 16u)) {
        return NINLIL_WIFI_DENIED;
    }
    (void)memset(peer_context_out, 0, NINLIL_WIFI_PEER_CONTEXT_BYTES);
    (void)memcpy(peer_context_out, in->authority_id, 16u);
    write_be_u64(peer_context_out + 16, in->authority_term);
    write_be_u32(peer_context_out + 24, in->assignment_epoch);
    peer_context_out[28] = NINLIL_WIFI_TLS_ROLE_CLIENT;
    (void)memcpy(peer_context_out + 29, in->tls_client_runtime_id, 16u);
    peer_context_out[45] = NINLIL_WIFI_TLS_ROLE_SERVER;
    (void)memcpy(peer_context_out + 46, in->tls_server_runtime_id, 16u);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_build_attached_context(
    const ninlil_wifi_attached_context_inputs_t *in,
    uint8_t attached_context_out[64])
{
    if (in == NULL || attached_context_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (is_all_zero(in->peer_session_id, 16u)) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    (void)memset(attached_context_out, 0, NINLIL_WIFI_ATTACHED_CONTEXT_BYTES);
    (void)memcpy(attached_context_out, in->peer_session_id, 16u);
    (void)memcpy(attached_context_out + 16, in->attachment_authority_id, 16u);
    (void)memcpy(
        attached_context_out + 32, in->active_attachment_binding_digest, 32u);
    return NINLIL_WIFI_OK;
}

#if !defined(ESP_PLATFORM)

ninlil_wifi_status_t ninlil_wifi_tls_post_handshake_accept(
    ninlil_wifi_tls_t *tls_opaque)
{
    struct ninlil_wifi_tls *tls = (struct ninlil_wifi_tls *)tls_opaque;
    uint8_t probe[1];
    int rc;
    if (tls == NULL || tls->ssl == NULL || tls->ready != 1) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (SSL_get_verify_result(tls->ssl) != X509_V_OK) {
        tls->ready = -1;
        return NINLIL_WIFI_CREDENTIAL;
    }
    {
        X509 *peer = SSL_get1_peer_certificate(tls->ssl);
        if (peer == NULL) {
            tls->ready = -1;
            return NINLIL_WIFI_CREDENTIAL;
        }
        /* Peer leaf notBefore/notAfter must still be current. */
        if (X509_cmp_current_time(X509_get0_notBefore(peer)) > 0
            || X509_cmp_current_time(X509_get0_notAfter(peer)) < 0) {
            X509_free(peer);
            tls->ready = -1;
            return NINLIL_WIFI_CREDENTIAL;
        }
        X509_free(peer);
    }
    /*
     * Delayed fatal alert fail-closed (client and server): TLS1.3 mTLS may
     * report local handshake complete before peer CertificateVerify/alert is
     * seen. SSL_ERROR_SSL / SSL_ERROR_SYSCALL are always fatal — never
     * ERR_clear_error + soft-OK (P0). Idle WANT_READ after a complete
     * handshake with X509_V_OK is normal (no app data yet).
     */
    ERR_clear_error();
    rc = SSL_peek(tls->ssl, probe, 1);
    if (rc > 0) {
        return NINLIL_WIFI_OK;
    }
    {
        int err = SSL_get_error(tls->ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* No alert / no app data yet — channel idle after good verify. */
            return NINLIL_WIFI_OK;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            tls->ready = -1;
            return NINLIL_WIFI_CREDENTIAL;
        }
        /*
         * SSL_ERROR_SSL / SSL_ERROR_SYSCALL / other: fatal.
         * Covers server client-cert reject alert — ATTACHED must not proceed.
         */
        tls->ready = -1;
        return NINLIL_WIFI_CREDENTIAL;
    }
}

ninlil_wifi_status_t ninlil_wifi_tls_export_peer_session_id(
    ninlil_wifi_tls_t *tls_opaque,
    const uint8_t peer_context[62],
    uint8_t peer_session_id_out[16])
{
    struct ninlil_wifi_tls *tls = (struct ninlil_wifi_tls *)tls_opaque;
    if (peer_session_id_out != NULL) {
        (void)memset(
            peer_session_id_out, 0, NINLIL_WIFI_PEER_SESSION_ID_BYTES);
    }
    if (tls == NULL || tls->ssl == NULL || tls->ready != 1
        || peer_context == NULL
        || peer_session_id_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_tls_post_handshake_accept(tls_opaque) != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    /* Output is exact 16; context is exact 62 domain-separated input. */
    if (SSL_export_keying_material(
            tls->ssl,
            peer_session_id_out,
            NINLIL_WIFI_PEER_SESSION_ID_BYTES,
            NINLIL_WIFI_EXPORTER_PEER_LABEL,
            sizeof(NINLIL_WIFI_EXPORTER_PEER_LABEL) - 1u,
            peer_context,
            NINLIL_WIFI_PEER_CONTEXT_BYTES,
            1)
        != 1) {
        tls->ready = -1;
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (is_all_zero(peer_session_id_out, 16u)) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tls_export_attached_session_id(
    ninlil_wifi_tls_t *tls_opaque,
    const uint8_t attached_context[64],
    uint8_t session_id_out[16])
{
    struct ninlil_wifi_tls *tls = (struct ninlil_wifi_tls *)tls_opaque;
    if (session_id_out != NULL) {
        (void)memset(
            session_id_out, 0, NINLIL_WIFI_ATTACHED_SESSION_ID_BYTES);
    }
    if (tls == NULL || tls->ssl == NULL || tls->ready != 1
        || attached_context == NULL
        || session_id_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_tls_post_handshake_accept(tls_opaque) != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (SSL_export_keying_material(
            tls->ssl,
            session_id_out,
            NINLIL_WIFI_ATTACHED_SESSION_ID_BYTES,
            NINLIL_WIFI_EXPORTER_ATTACHED_LABEL,
            sizeof(NINLIL_WIFI_EXPORTER_ATTACHED_LABEL) - 1u,
            attached_context,
            NINLIL_WIFI_ATTACHED_CONTEXT_BYTES,
            1)
        != 1) {
        tls->ready = -1;
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (is_all_zero(session_id_out, 16u)) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}

#endif /* !ESP_PLATFORM */
