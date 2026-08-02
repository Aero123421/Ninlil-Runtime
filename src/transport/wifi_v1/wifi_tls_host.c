#include "wifi_tls_host.h"
#include "wifi_tls_host_internal.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>

size_t ninlil_wifi_tls_sizeof(void)
{
    return sizeof(struct ninlil_wifi_tls);
}

/*
 * ADR-0018 Host pin: openssl-3.5.7 exact for authoritative acceptance.
 * Non-matching runtime → fail closed (no Host TLS authority claim).
 */
#if defined(NINLIL_WIFI_HOST_OPENSSL_STATIC_AUTHORITY)
static int wifi_openssl_pin_ok(void)
{
    unsigned int maj = OPENSSL_version_major();
    unsigned int min = OPENSSL_version_minor();
    unsigned int pat = OPENSSL_version_patch();
    /* Exact 3.5.7 only (ADR-0018 Host authority pin). */
    return (maj == 3u && min == 5u && pat == 7u) ? 1 : 0;
}
#endif

int ninlil_wifi_tls_host_profile_authority(void)
{
#if defined(NINLIL_WIFI_HOST_OPENSSL_STATIC_AUTHORITY)
    return wifi_openssl_pin_ok();
#elif defined(NINLIL_POSIX_TLS_V1_BUILD)
    return OPENSSL_version_major() == 3u;
#else
    return 0;
#endif
}

static ninlil_wifi_status_t tls_terminal(
    ninlil_wifi_tls_t *tls,
    ninlil_wifi_status_t status)
{
    if (tls != NULL) {
        /*
         * -1 permanently poisons the current SSL object. attach_fd() may
         * create a fresh SSL object and reset it to the handshaking state.
         */
        tls->ready = -1;
    }
    return status;
}

static ninlil_wifi_status_t map_ssl_io(ninlil_wifi_tls_t *tls, int rc)
{
    int err = SSL_get_error(tls->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    if (err == SSL_ERROR_ZERO_RETURN) {
        return tls_terminal(tls, NINLIL_WIFI_CLOSED);
    }
    /*
     * Fatal alert, protocol error, syscall error, and every unknown class are
     * terminal. Clearing ERR and continuing on this SSL object is forbidden.
     */
    return tls_terminal(tls, NINLIL_WIFI_TLS_FAILED);
}

/* 1 if leaf is currently within notBefore/notAfter. */
static int leaf_time_valid_now(X509 *leaf)
{
    const ASN1_TIME *nb;
    const ASN1_TIME *na;
    if (leaf == NULL) {
        return 0;
    }
    nb = X509_get0_notBefore(leaf);
    na = X509_get0_notAfter(leaf);
    if (nb == NULL || na == NULL) {
        return 0;
    }
    /* notBefore must be <= now (cmp <= 0 means notBefore is not later). */
    if (X509_cmp_current_time(nb) > 0) {
        return 0;
    }
    /* notAfter must be >= now (cmp >= 0 means notAfter is not earlier). */
    if (X509_cmp_current_time(na) < 0) {
        return 0;
    }
    return 1;
}

static ninlil_wifi_status_t x509_leaf_binding(
    X509 *cert,
    ninlil_wifi_leaf_binding_t *out);
static int local_leaf_preflight_exact(SSL_CTX *ctx, int is_server);
static int peer_verified_chain_exact(SSL *ssl);

ninlil_wifi_status_t ninlil_wifi_tls_init(
    ninlil_wifi_tls_t *tls,
    int is_server,
    const ninlil_wifi_tls_paths_t *paths)
{
    const SSL_METHOD *method;
    long opts;
    if (tls == NULL || paths == NULL || paths->ca_pem_path == NULL
        || paths->cert_pem_path == NULL || paths->key_pem_path == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(tls, 0, sizeof(*tls));
    tls->fd = -1;
    tls->is_server = is_server ? 1 : 0;
    /*
     * Fail closed when pin is absent: LAB may still build against other OpenSSL 3
     * for compile smoke only if NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=1 is defined
     * at compile time. Default: deny init (no authoritative Host TLS).
     */
    if (!ninlil_wifi_tls_host_profile_authority()) {
#if !defined(NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL)
        return NINLIL_WIFI_UNSUPPORTED;
#else
        tls->profile_authority = 0;
#endif
    } else {
        tls->profile_authority = 1;
    }
    /*
     * Wi-Fi owns a non-default library context.  Explicitly load and constrain
     * the built-in default provider so process-global config/provider state
     * (including R7's generic OpenSSL usage) cannot select this channel's
     * algorithms.
     */
    tls->libctx = OSSL_LIB_CTX_new();
    if (tls->libctx == NULL) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    tls->default_provider = OSSL_PROVIDER_load(tls->libctx, "default");
    if (tls->default_provider == NULL
        || EVP_set_default_properties(tls->libctx, "provider=default") != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    method = is_server ? TLS_server_method() : TLS_client_method();
    tls->ctx = SSL_CTX_new_ex(tls->libctx, "provider=default", method);
    if (tls->ctx == NULL) {
        return NINLIL_WIFI_TLS_FAILED;
    }
    /* Exact TLS1.3 only. */
    if (SSL_CTX_set_min_proto_version(tls->ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(tls->ctx, TLS1_3_VERSION) != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    /* Suite pin: TLS_AES_128_GCM_SHA256 only. */
    if (SSL_CTX_set_ciphersuites(tls->ctx, "TLS_AES_128_GCM_SHA256") != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    /* Group pin: secp256r1 / P-256 only. */
    if (SSL_CTX_set1_groups_list(tls->ctx, "P-256") != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    /* Signature pin: ecdsa_secp256r1_sha256. */
    if (SSL_CTX_set1_sigalgs_list(tls->ctx, "ecdsa_secp256r1_sha256") != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (is_server
        && SSL_CTX_set1_client_sigalgs_list(
               tls->ctx, "ecdsa_secp256r1_sha256")
            != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    opts = SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION;
    if ((SSL_CTX_set_options(tls->ctx, (uint64_t)opts) & (uint64_t)opts)
        != (uint64_t)opts) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    SSL_CTX_set_post_handshake_auth(tls->ctx, 0);
    if (SSL_CTX_set_num_tickets(tls->ctx, 0u) != 1
        || SSL_CTX_set_max_early_data(tls->ctx, 0u) != 1
        || SSL_CTX_set_recv_max_early_data(tls->ctx, 0u) != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    (void)SSL_CTX_set_session_cache_mode(tls->ctx, SSL_SESS_CACHE_OFF);
    (void)SSL_CTX_set_max_cert_list(tls->ctx, 4110L);
    if (SSL_CTX_get_session_cache_mode(tls->ctx) != SSL_SESS_CACHE_OFF
        || SSL_CTX_get_max_cert_list(tls->ctx) != 4110L
        || SSL_CTX_set_max_send_fragment(tls->ctx, 4096L) != 1L) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_TLS_FAILED;
    }
    {
        long required_mode =
            SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
        if ((SSL_CTX_set_mode(tls->ctx, required_mode) & required_mode)
            != required_mode) {
            ninlil_wifi_tls_close(tls);
            return NINLIL_WIFI_TLS_FAILED;
        }
    }
    if (SSL_CTX_load_verify_locations(tls->ctx, paths->ca_pem_path, NULL) != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (SSL_CTX_use_certificate_file(
            tls->ctx, paths->cert_pem_path, SSL_FILETYPE_PEM)
        != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (SSL_CTX_use_PrivateKey_file(
            tls->ctx, paths->key_pem_path, SSL_FILETYPE_PEM)
        != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (SSL_CTX_check_private_key(tls->ctx) != 1) {
        ninlil_wifi_tls_close(tls);
        return NINLIL_WIFI_CREDENTIAL;
    }
    /*
     * Fail closed on expired/not-yet-valid local leaf. TLS1.3 mutual auth can
     * otherwise complete on the peer side before the rejecting alert is seen.
     */
    {
        X509 *own = SSL_CTX_get0_certificate(tls->ctx);
        if (own == NULL || !leaf_time_valid_now(own)
            || !local_leaf_preflight_exact(tls->ctx, tls->is_server)) {
            ninlil_wifi_tls_close(tls);
            return NINLIL_WIFI_CREDENTIAL;
        }
    }
    SSL_CTX_set_verify(
        tls->ctx,
        is_server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                  : SSL_VERIFY_PEER,
        NULL);
    SSL_CTX_set_verify_depth(tls->ctx, 1);
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_tls_close(ninlil_wifi_tls_t *tls)
{
    if (tls == NULL) {
        return;
    }
    if (tls->ssl != NULL) {
        SSL_free(tls->ssl);
        tls->ssl = NULL;
    }
    if (tls->ctx != NULL) {
        SSL_CTX_free(tls->ctx);
        tls->ctx = NULL;
    }
    if (tls->default_provider != NULL) {
        (void)OSSL_PROVIDER_unload(tls->default_provider);
        tls->default_provider = NULL;
    }
    if (tls->libctx != NULL) {
        OPENSSL_thread_stop_ex(tls->libctx);
        OSSL_LIB_CTX_free(tls->libctx);
        tls->libctx = NULL;
    }
    tls->ready = 0;
    tls->fd = -1;
}

ninlil_wifi_status_t ninlil_wifi_tls_attach_fd(ninlil_wifi_tls_t *tls, int fd)
{
    if (tls == NULL || tls->ctx == NULL || fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tls->ssl != NULL) {
        SSL_free(tls->ssl);
        tls->ssl = NULL;
    }
    tls->ssl = SSL_new(tls->ctx);
    if (tls->ssl == NULL) {
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (SSL_set_fd(tls->ssl, fd) != 1) {
        SSL_free(tls->ssl);
        tls->ssl = NULL;
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (tls->is_server) {
        SSL_set_accept_state(tls->ssl);
    } else {
        SSL_set_connect_state(tls->ssl);
    }
    tls->fd = fd;
    tls->ready = 0;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tls_handshake(ninlil_wifi_tls_t *tls)
{
    int rc;
    if (tls == NULL || tls->ssl == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tls->ready < 0) {
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (tls->ready == 1) {
        return NINLIL_WIFI_OK;
    }
    rc = SSL_do_handshake(tls->ssl);
    if (rc == 1) {
        const SSL_CIPHER *cipher;
        int nid;
        long vfy;
        X509 *peer;
        vfy = SSL_get_verify_result(tls->ssl);
        if (vfy != X509_V_OK) {
            return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
        }
        peer = SSL_get1_peer_certificate(tls->ssl);
        if (peer == NULL) {
            return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
        }
        if (!leaf_time_valid_now(peer)) {
            X509_free(peer);
            return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
        }
        if (!peer_verified_chain_exact(tls->ssl)) {
            X509_free(peer);
            return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
        }
        X509_free(peer);
        /* Post-handshake exact profile: TLS1.3 + AES128-GCM + P-256. */
        if (SSL_version(tls->ssl) != TLS1_3_VERSION) {
            return tls_terminal(tls, NINLIL_WIFI_TLS_FAILED);
        }
        cipher = SSL_get_current_cipher(tls->ssl);
        if (cipher == NULL
            || SSL_CIPHER_get_protocol_id(cipher) != 0x1301u) {
            return tls_terminal(tls, NINLIL_WIFI_TLS_FAILED);
        }
        nid = SSL_get_negotiated_group(tls->ssl);
        if (nid != NID_X9_62_prime256v1) {
            return tls_terminal(tls, NINLIL_WIFI_TLS_FAILED);
        }
        if (SSL_session_reused(tls->ssl) != 0) {
            return tls_terminal(tls, NINLIL_WIFI_TLS_FAILED);
        }
        /* Require peer leaf SPKI + OID SAN binding (identity, not free assert). */
        {
            uint8_t spki[32];
            ninlil_wifi_leaf_binding_t peer_bind;
            ninlil_wifi_leaf_binding_t local_bind;
            if (ninlil_wifi_tls_peer_leaf_spki_sha256(tls, spki)
                != NINLIL_WIFI_OK) {
                return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
            }
            if (ninlil_wifi_tls_peer_leaf_binding(tls, &peer_bind)
                != NINLIL_WIFI_OK) {
                return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
            }
            if (ninlil_wifi_tls_local_leaf_binding(tls, &local_bind)
                != NINLIL_WIFI_OK) {
                return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
            }
            /* Role: local cert role must match is_server; peer the opposite. */
            if (tls->is_server) {
                if (local_bind.role != NINLIL_WIFI_LEAF_ROLE_SERVER
                    || peer_bind.role != NINLIL_WIFI_LEAF_ROLE_CLIENT) {
                    return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
                }
            } else {
                if (local_bind.role != NINLIL_WIFI_LEAF_ROLE_CLIENT
                    || peer_bind.role != NINLIL_WIFI_LEAF_ROLE_SERVER) {
                    return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
                }
            }
            /* Authority identity must agree across both leaves. */
            if (memcmp(local_bind.authority_id, peer_bind.authority_id, 16u)
                    != 0
                || local_bind.authority_term != peer_bind.authority_term) {
                return tls_terminal(tls, NINLIL_WIFI_CREDENTIAL);
            }
        }
        tls->ready = 1;
        return NINLIL_WIFI_OK;
    }
    return map_ssl_io(tls, rc);
}

static int leaf_extension_nid_allowed(int nid)
{
    return nid == NID_basic_constraints || nid == NID_key_usage
        || nid == NID_ext_key_usage || nid == NID_subject_alt_name
        || nid == NID_subject_key_identifier
        || nid == NID_authority_key_identifier;
}

static int leaf_spki_and_extensions_exact(
    X509 *cert,
    const ninlil_wifi_leaf_binding_t *binding)
{
    static const uint8_t p256_spki_prefix[27] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
    };
    EVP_PKEY *pkey = NULL;
    unsigned char *spki_der = NULL;
    uint8_t spki_digest[32];
    BASIC_CONSTRAINTS *bc = NULL;
    ASN1_BIT_STRING *ku = NULL;
    EXTENDED_KEY_USAGE *eku = NULL;
    ASN1_OCTET_STRING *ski = NULL;
    AUTHORITY_KEYID *aki = NULL;
    int seen_basic = 0;
    int seen_ku = 0;
    int seen_eku = 0;
    int seen_san = 0;
    int seen_ski = 0;
    int seen_aki = 0;
    int ok = 0;
    int i;
    int spki_len;

    if (cert == NULL || binding == NULL || X509_get_version(cert) != 2L
        || X509_get_signature_nid(cert) != NID_ecdsa_with_SHA256
        || i2d_X509(cert, NULL) <= 0 || i2d_X509(cert, NULL) > 2048
        || X509_get_ext_count(cert) != 6) {
        goto out;
    }
    for (i = 0; i < X509_get_ext_count(cert); ++i) {
        X509_EXTENSION *extension = X509_get_ext(cert, i);
        int nid;
        int critical;
        if (extension == NULL) {
            goto out;
        }
        nid = OBJ_obj2nid(X509_EXTENSION_get_object(extension));
        critical = X509_EXTENSION_get_critical(extension);
        if (!leaf_extension_nid_allowed(nid)) {
            goto out;
        }
        if (nid == NID_basic_constraints) {
            if (seen_basic++ != 0 || critical != 1) {
                goto out;
            }
        } else if (nid == NID_key_usage) {
            if (seen_ku++ != 0 || critical != 1) {
                goto out;
            }
        } else if (nid == NID_ext_key_usage) {
            if (seen_eku++ != 0 || critical != 1) {
                goto out;
            }
        } else if (nid == NID_subject_alt_name) {
            if (seen_san++ != 0 || critical != 1) {
                goto out;
            }
        } else if (nid == NID_subject_key_identifier) {
            if (seen_ski++ != 0 || critical != 0) {
                goto out;
            }
        } else if (nid == NID_authority_key_identifier) {
            if (seen_aki++ != 0 || critical != 0) {
                goto out;
            }
        }
    }
    if (seen_basic != 1 || seen_ku != 1 || seen_eku != 1 || seen_san != 1
        || seen_ski != 1 || seen_aki != 1) {
        goto out;
    }

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        goto out;
    }
    spki_len = i2d_PUBKEY(pkey, &spki_der);
    if (spki_len != 91 || spki_der == NULL
        || memcmp(spki_der, p256_spki_prefix, sizeof(p256_spki_prefix)) != 0) {
        goto out;
    }
    (void)SHA256(spki_der, (size_t)spki_len, spki_digest);

    bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (bc == NULL || bc->ca != 0 || bc->pathlen != NULL) {
        goto out;
    }
    ku = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (ku == NULL || ASN1_STRING_length((ASN1_STRING *)ku) != 1
        || ASN1_STRING_get0_data((ASN1_STRING *)ku)[0] != 0x80u
        || ASN1_BIT_STRING_get_bit(ku, 0) != 1) {
        goto out;
    }
    eku = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
    if (eku == NULL || sk_ASN1_OBJECT_num(eku) != 1) {
        goto out;
    }
    {
        int expected_eku = binding->role == NINLIL_WIFI_LEAF_ROLE_CLIENT
            ? NID_client_auth
            : NID_server_auth;
        if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, 0)) != expected_eku) {
            goto out;
        }
    }
    ski = X509_get_ext_d2i(cert, NID_subject_key_identifier, NULL, NULL);
    if (ski == NULL || ASN1_STRING_length(ski) != 20
        || memcmp(ASN1_STRING_get0_data(ski), spki_digest, 20u) != 0) {
        goto out;
    }
    aki = X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
    if (aki == NULL || aki->keyid == NULL
        || ASN1_STRING_length(aki->keyid) != 20 || aki->issuer != NULL
        || aki->serial != NULL) {
        goto out;
    }
    ok = 1;

out:
    AUTHORITY_KEYID_free(aki);
    ASN1_OCTET_STRING_free(ski);
    EXTENDED_KEY_USAGE_free(eku);
    ASN1_BIT_STRING_free(ku);
    BASIC_CONSTRAINTS_free(bc);
    OPENSSL_free(spki_der);
    EVP_PKEY_free(pkey);
    return ok;
}

static ninlil_wifi_status_t x509_leaf_binding(
    X509 *cert,
    ninlil_wifi_leaf_binding_t *out)
{
    static const uint8_t san_extension_prefix[12] = {
        0x30, 0x7a, 0x06, 0x03, 0x55, 0x1d,
        0x11, 0x01, 0x01, 0xff, 0x04, 0x70
    };
    int loc;
    X509_EXTENSION *ex;
    ASN1_OCTET_STRING *os;
    unsigned char *extension_der = NULL;
    int extension_der_len;
    ninlil_wifi_leaf_binding_t parsed;
    ninlil_wifi_status_t status;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (cert == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (loc < 0) {
        return NINLIL_WIFI_DENIED;
    }
    if (X509_get_ext_by_NID(cert, NID_subject_alt_name, loc) >= 0) {
        return NINLIL_WIFI_DENIED;
    }
    ex = X509_get_ext(cert, loc);
    if (ex == NULL || X509_EXTENSION_get_critical(ex) != 1) {
        return NINLIL_WIFI_DENIED;
    }
    os = X509_EXTENSION_get_data(ex);
    if (os == NULL || ASN1_STRING_get0_data(os) == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    extension_der_len = i2d_X509_EXTENSION(ex, &extension_der);
    if (extension_der_len != NINLIL_WIFI_LEAF_SAN_EXT_TOTAL_LEN
        || extension_der == NULL
        || memcmp(
               extension_der,
               san_extension_prefix,
               sizeof(san_extension_prefix))
            != 0
        || ASN1_STRING_length(os) != NINLIL_WIFI_LEAF_SAN_GN_LEN
        || memcmp(
               extension_der + NINLIL_WIFI_LEAF_SAN_EXT_PREFIX_LEN,
               ASN1_STRING_get0_data(os),
               NINLIL_WIFI_LEAF_SAN_GN_LEN)
            != 0) {
        OPENSSL_free(extension_der);
        return NINLIL_WIFI_DENIED;
    }
    OPENSSL_free(extension_der);
    (void)memset(&parsed, 0, sizeof(parsed));
    status = ninlil_wifi_leaf_binding_parse_general_names(
        ASN1_STRING_get0_data(os), (size_t)ASN1_STRING_length(os), &parsed);
    if (status != NINLIL_WIFI_OK
        || !leaf_spki_and_extensions_exact(cert, &parsed)) {
        return NINLIL_WIFI_DENIED;
    }
    *out = parsed;
    return NINLIL_WIFI_OK;
}

static int cert_uses_p256_and_ecdsa_sha256(X509 *cert)
{
    static const uint8_t p256_spki_prefix[27] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
    };
    EVP_PKEY *pkey = NULL;
    unsigned char *der = NULL;
    int der_len;
    int ok = 0;
    if (cert == NULL || X509_get_signature_nid(cert) != NID_ecdsa_with_SHA256
        || i2d_X509(cert, NULL) <= 0 || i2d_X509(cert, NULL) > 2048) {
        return 0;
    }
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        goto out;
    }
    der_len = i2d_PUBKEY(pkey, &der);
    ok = der_len == 91 && der != NULL
        && memcmp(der, p256_spki_prefix, sizeof(p256_spki_prefix)) == 0;
out:
    OPENSSL_free(der);
    EVP_PKEY_free(pkey);
    return ok;
}

static int authority_key_id_matches_issuer(X509 *cert, X509 *issuer)
{
    AUTHORITY_KEYID *aki = NULL;
    ASN1_OCTET_STRING *issuer_ski = NULL;
    int ok = 0;
    if (cert == NULL || issuer == NULL) {
        return 0;
    }
    aki = X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
    issuer_ski =
        X509_get_ext_d2i(issuer, NID_subject_key_identifier, NULL, NULL);
    if (aki != NULL && aki->keyid != NULL && aki->issuer == NULL
        && aki->serial == NULL && issuer_ski != NULL
        && ASN1_STRING_length(aki->keyid) == 20
        && ASN1_STRING_length(issuer_ski) == 20
        && memcmp(
               ASN1_STRING_get0_data(aki->keyid),
               ASN1_STRING_get0_data(issuer_ski),
               20u)
            == 0) {
        ok = 1;
    }
    ASN1_OCTET_STRING_free(issuer_ski);
    AUTHORITY_KEYID_free(aki);
    return ok;
}

static int certificate_signed_by(X509 *cert, X509 *issuer)
{
    EVP_PKEY *issuer_key;
    int ok;
    if (cert == NULL || issuer == NULL
        || X509_NAME_cmp(
               X509_get_issuer_name(cert), X509_get_subject_name(issuer))
            != 0) {
        return 0;
    }
    issuer_key = X509_get_pubkey(issuer);
    if (issuer_key == NULL) {
        return 0;
    }
    ok = X509_verify(cert, issuer_key) == 1;
    EVP_PKEY_free(issuer_key);
    return ok;
}

static int verified_chain_linkage_exact(STACK_OF(X509) *chain)
{
    int count;
    int i;
    int presented_der_sum;
    X509 *root;
    if (chain == NULL) {
        return 0;
    }
    count = sk_X509_num(chain);
    if (count != 2 && count != 3) {
        return 0;
    }
    presented_der_sum = i2d_X509(sk_X509_value(chain, 0), NULL);
    if (count == 3) {
        int intermediate_len = i2d_X509(sk_X509_value(chain, 1), NULL);
        if (intermediate_len <= 0) {
            return 0;
        }
        presented_der_sum += intermediate_len;
    }
    if (presented_der_sum <= 0 || presented_der_sum > 4096) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (!cert_uses_p256_and_ecdsa_sha256(sk_X509_value(chain, i))) {
            return 0;
        }
    }
    for (i = 0; i < count - 1; ++i) {
        X509 *cert = sk_X509_value(chain, i);
        X509 *issuer = sk_X509_value(chain, i + 1);
        if (!authority_key_id_matches_issuer(cert, issuer)
            || !certificate_signed_by(cert, issuer)) {
            return 0;
        }
    }
    root = sk_X509_value(chain, count - 1);
    if (!authority_key_id_matches_issuer(root, root)
        || !certificate_signed_by(root, root)) {
        return 0;
    }
    return 1;
}

static int local_leaf_preflight_exact(SSL_CTX *ctx, int is_server)
{
    X509 *own;
    ninlil_wifi_leaf_binding_t binding;
    X509_STORE_CTX *verify_ctx = NULL;
    STACK_OF(X509) *chain = NULL;
    int ok = 0;
    if (ctx == NULL) {
        return 0;
    }
    own = SSL_CTX_get0_certificate(ctx);
    if (own == NULL
        || x509_leaf_binding(own, &binding) != NINLIL_WIFI_OK
        || (is_server && binding.role != NINLIL_WIFI_LEAF_ROLE_SERVER)
        || (!is_server && binding.role != NINLIL_WIFI_LEAF_ROLE_CLIENT)) {
        return 0;
    }
    verify_ctx = X509_STORE_CTX_new();
    if (verify_ctx == NULL
        || X509_STORE_CTX_init(
               verify_ctx, SSL_CTX_get_cert_store(ctx), own, NULL)
            != 1) {
        goto out;
    }
    X509_STORE_CTX_set_depth(verify_ctx, 1);
    if (X509_verify_cert(verify_ctx) != 1) {
        goto out;
    }
    chain = X509_STORE_CTX_get1_chain(verify_ctx);
    ok = verified_chain_linkage_exact(chain);
out:
    sk_X509_pop_free(chain, X509_free);
    X509_STORE_CTX_free(verify_ctx);
    return ok;
}

static int peer_verified_chain_exact(SSL *ssl)
{
    STACK_OF(X509) *chain;
    if (ssl == NULL) {
        return 0;
    }
    chain = SSL_get0_verified_chain(ssl);
    return verified_chain_linkage_exact(chain);
}

ninlil_wifi_status_t ninlil_wifi_tls_peer_leaf_spki_sha256(
    ninlil_wifi_tls_t *tls,
    uint8_t out_spki_sha256[32])
{
    X509 *peer = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *der = NULL;
    int der_len;
    if (out_spki_sha256 != NULL) {
        (void)memset(out_spki_sha256, 0, 32u);
    }
    if (tls == NULL || tls->ssl == NULL || out_spki_sha256 == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    peer = SSL_get1_peer_certificate(tls->ssl);
    if (peer == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    pkey = X509_get_pubkey(peer);
    if (pkey == NULL) {
        X509_free(peer);
        return NINLIL_WIFI_CREDENTIAL;
    }
    der_len = i2d_PUBKEY(pkey, &der);
    EVP_PKEY_free(pkey);
    X509_free(peer);
    if (der_len <= 0 || der == NULL) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    (void)SHA256(der, (size_t)der_len, out_spki_sha256);
    OPENSSL_free(der);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tls_local_leaf_spki_sha256(
    ninlil_wifi_tls_t *tls,
    uint8_t out_spki_sha256[32])
{
    X509 *own;
    EVP_PKEY *pkey = NULL;
    unsigned char *der = NULL;
    int der_len;
    if (out_spki_sha256 != NULL) {
        (void)memset(out_spki_sha256, 0, 32u);
    }
    if (tls == NULL || tls->ssl == NULL || out_spki_sha256 == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    own = SSL_get_certificate(tls->ssl);
    if (own == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    pkey = X509_get_pubkey(own);
    if (pkey == NULL) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    der_len = i2d_PUBKEY(pkey, &der);
    EVP_PKEY_free(pkey);
    if (der_len <= 0 || der == NULL) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    (void)SHA256(der, (size_t)der_len, out_spki_sha256);
    OPENSSL_free(der);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_tls_peer_leaf_binding(
    ninlil_wifi_tls_t *tls,
    ninlil_wifi_leaf_binding_t *out)
{
    X509 *peer;
    ninlil_wifi_status_t st;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (tls == NULL || tls->ssl == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    peer = SSL_get1_peer_certificate(tls->ssl);
    if (peer == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    st = x509_leaf_binding(peer, out);
    X509_free(peer);
    return st;
}

ninlil_wifi_status_t ninlil_wifi_tls_local_leaf_binding(
    ninlil_wifi_tls_t *tls,
    ninlil_wifi_leaf_binding_t *out)
{
    X509 *own;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (tls == NULL || tls->ssl == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    own = SSL_get_certificate(tls->ssl);
    if (own == NULL) {
        return NINLIL_WIFI_DENIED;
    }
    /* SSL_get_certificate does not bump refcount. */
    return x509_leaf_binding(own, out);
}

ninlil_wifi_status_t ninlil_wifi_tls_write(
    ninlil_wifi_tls_t *tls,
    const uint8_t *data,
    size_t len,
    size_t *written_out)
{
    int rc;
    if (written_out != NULL) {
        *written_out = 0u;
    }
    if (tls == NULL || tls->ssl == NULL || data == NULL || written_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tls->ready != 1) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    rc = SSL_write(tls->ssl, data, (int)len);
    if (rc > 0) {
        *written_out = (size_t)rc;
        return (*written_out < len) ? NINLIL_WIFI_WOULD_BLOCK : NINLIL_WIFI_OK;
    }
    return map_ssl_io(tls, rc);
}

ninlil_wifi_status_t ninlil_wifi_tls_read(
    ninlil_wifi_tls_t *tls,
    uint8_t *data,
    size_t cap,
    size_t *read_out)
{
    int rc;
    if (read_out != NULL) {
        *read_out = 0u;
    }
    if (tls == NULL || tls->ssl == NULL || data == NULL || read_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tls->ready != 1) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    rc = SSL_read(tls->ssl, data, (int)cap);
    if (rc > 0) {
        *read_out = (size_t)rc;
        return NINLIL_WIFI_OK;
    }
    return map_ssl_io(tls, rc);
}

int ninlil_wifi_tls_is_ready(const ninlil_wifi_tls_t *tls)
{
    return tls != NULL && tls->ready == 1;
}
