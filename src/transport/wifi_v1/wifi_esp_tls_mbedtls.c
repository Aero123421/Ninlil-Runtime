#include "wifi_esp_tls_mbedtls.h"

#include "wifi_tls_export.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int bytes_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    if (p == NULL) {
        return 1;
    }
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int expectation_header_valid(
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation)
{
    return expectation != NULL
        && expectation->api_version
            == NINLIL_WIFI_ESP_TLS_IDENTITY_EXPECTATION_VERSION
        && expectation->struct_size == (uint16_t)sizeof(*expectation)
        && bytes_all_zero(
               expectation->reserved_zero,
               sizeof(expectation->reserved_zero));
}

static int leaf_binding_equal(
    const ninlil_wifi_leaf_binding_t *a,
    const ninlil_wifi_leaf_binding_t *b)
{
    uint8_t a_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    uint8_t b_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    if (a == NULL || b == NULL
        || ninlil_wifi_leaf_binding_encode(a, a_wire) != NINLIL_WIFI_OK
        || ninlil_wifi_leaf_binding_encode(b, b_wire) != NINLIL_WIFI_OK) {
        return 0;
    }
    return memcmp(a_wire, b_wire, sizeof(a_wire)) == 0;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_identity_match(
    int is_server,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation,
    const ninlil_wifi_leaf_binding_t *local_leaf,
    const ninlil_wifi_leaf_binding_t *peer_leaf,
    ninlil_wifi_esp_tls_verified_identity_t *out)
{
    const uint8_t local_role = is_server
        ? NINLIL_WIFI_LEAF_ROLE_SERVER
        : NINLIL_WIFI_LEAF_ROLE_CLIENT;
    const uint8_t peer_role = is_server
        ? NINLIL_WIFI_LEAF_ROLE_CLIENT
        : NINLIL_WIFI_LEAF_ROLE_SERVER;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (!expectation_header_valid(expectation) || local_leaf == NULL
        || peer_leaf == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (local_leaf->role != local_role || peer_leaf->role != peer_role
        || !leaf_binding_equal(local_leaf, &expectation->local_leaf)
        || !leaf_binding_equal(peer_leaf, &expectation->peer_leaf)
        || memcmp(local_leaf->authority_id, peer_leaf->authority_id, 16u) != 0
        || local_leaf->authority_term != peer_leaf->authority_term
        || memcmp(
               local_leaf->authorized_attachment_binding_digest,
               peer_leaf->authorized_attachment_binding_digest,
               32u)
            != 0) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    out->local_leaf = *local_leaf;
    out->peer_leaf = *peer_leaf;
    return NINLIL_WIFI_OK;
}

#if defined(ESP_PLATFORM)

#include "wifi_esp_tls_allocator.h"

#include "mbedtls/asn1.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"

struct ninlil_wifi_esp_tls {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_net_context net;
    int is_server;
    int ready;
    int inited;
    int identity_expectation_set;
    int identity_verified;
    uint32_t allocator_owner;
    int allocator_registered;
    ninlil_wifi_esp_tls_identity_expectation_t identity_expectation;
    ninlil_wifi_esp_tls_verified_identity_t verified_identity;
};

size_t ninlil_wifi_esp_tls_sizeof(void)
{
    return sizeof(struct ninlil_wifi_esp_tls);
}

static ninlil_wifi_status_t map_mbed(int rc)
{
    if (rc == 0) {
        return NINLIL_WIFI_OK;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_READ
        || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return NINLIL_WIFI_CLOSED;
    }
    return NINLIL_WIFI_TLS_FAILED;
}

typedef struct der_view {
    const uint8_t *p;
    size_t len;
} der_view_t;

static int der_read_length(
    const uint8_t **cursor,
    const uint8_t *end,
    size_t *out_len)
{
    uint8_t first;
    size_t value = 0u;
    size_t count;
    size_t i;
    if (cursor == NULL || *cursor == NULL || *cursor >= end
        || out_len == NULL) {
        return 0;
    }
    first = *(*cursor)++;
    if ((first & 0x80u) == 0u) {
        value = first;
    } else {
        count = (size_t)(first & 0x7fu);
        if (count == 0u || count > sizeof(size_t)
            || (size_t)(end - *cursor) < count || (*cursor)[0] == 0u) {
            return 0;
        }
        for (i = 0u; i < count; ++i) {
            if (value > (SIZE_MAX >> 8)) {
                return 0;
            }
            value = (value << 8) | (size_t)(*cursor)[i];
        }
        *cursor += count;
        if (value < 128u) {
            return 0; /* non-minimal DER length */
        }
    }
    if (value > (size_t)(end - *cursor)) {
        return 0;
    }
    *out_len = value;
    return 1;
}

static int der_read_tlv(
    const uint8_t **cursor,
    const uint8_t *end,
    uint8_t tag,
    der_view_t *out)
{
    size_t length;
    if (cursor == NULL || *cursor == NULL || *cursor >= end || out == NULL
        || *(*cursor)++ != tag
        || !der_read_length(cursor, end, &length)) {
        return 0;
    }
    out->p = *cursor;
    out->len = length;
    *cursor += length;
    return 1;
}

static int der_equals(
    const der_view_t *view, const uint8_t *expected, size_t expected_len)
{
    return view != NULL && expected != NULL && view->len == expected_len
        && memcmp(view->p, expected, expected_len) == 0;
}

static ninlil_wifi_status_t mbed_leaf_binding_exact(
    const mbedtls_x509_crt *cert,
    ninlil_wifi_leaf_binding_t *out)
{
    static const uint8_t oid_basic[] = {0x55u, 0x1du, 0x13u};
    static const uint8_t oid_key_usage[] = {0x55u, 0x1du, 0x0fu};
    static const uint8_t oid_eku[] = {0x55u, 0x1du, 0x25u};
    static const uint8_t oid_san[] = {0x55u, 0x1du, 0x11u};
    static const uint8_t oid_ski[] = {0x55u, 0x1du, 0x0eu};
    static const uint8_t oid_aki[] = {0x55u, 0x1du, 0x23u};
    static const uint8_t basic_value[] = {0x30u, 0x00u};
    static const uint8_t ku_value[] = {0x03u, 0x02u, 0x07u, 0x80u};
    static const uint8_t eku_client[] = {
        0x30u, 0x0au, 0x06u, 0x08u, 0x2bu, 0x06u,
        0x01u, 0x05u, 0x05u, 0x07u, 0x03u, 0x02u
    };
    static const uint8_t eku_server[] = {
        0x30u, 0x0au, 0x06u, 0x08u, 0x2bu, 0x06u,
        0x01u, 0x05u, 0x05u, 0x07u, 0x03u, 0x01u
    };
    const uint8_t *cursor;
    const uint8_t *end;
    uint8_t seen = 0u;
    uint8_t eku_role = 0u;
    der_view_t ext;
    ninlil_wifi_leaf_binding_t binding;
    mbedtls_ecp_keypair *ec;

    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (cert == NULL || out == NULL || cert->version != 3
        || cert->v3_ext.p == NULL || cert->v3_ext.len == 0u
        || cert->raw.len == 0u || cert->raw.len > 2048u
        || mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_ECKEY
        || cert->MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256
        || cert->MBEDTLS_PRIVATE(sig_pk) != MBEDTLS_PK_ECDSA) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    ec = mbedtls_pk_ec(cert->pk);
    if (ec == NULL
        || ec->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP256R1) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    cursor = cert->v3_ext.p;
    end = cursor + cert->v3_ext.len;
    while (cursor < end) {
        const uint8_t *ep;
        const uint8_t *ee;
        der_view_t oid;
        der_view_t value;
        int critical = 0;
        if (!der_read_tlv(&cursor, end, 0x30u, &ext)) {
            return NINLIL_WIFI_CREDENTIAL;
        }
        ep = ext.p;
        ee = ext.p + ext.len;
        if (!der_read_tlv(&ep, ee, 0x06u, &oid)) {
            return NINLIL_WIFI_CREDENTIAL;
        }
        if (ep < ee && *ep == 0x01u) {
            der_view_t boolean;
            if (!der_read_tlv(&ep, ee, 0x01u, &boolean)
                || boolean.len != 1u || boolean.p[0] != 0xffu) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            critical = 1;
        }
        if (!der_read_tlv(&ep, ee, 0x04u, &value) || ep != ee) {
            return NINLIL_WIFI_CREDENTIAL;
        }
        if (der_equals(&oid, oid_basic, sizeof(oid_basic))) {
            if ((seen & 0x01u) != 0u || !critical
                || !der_equals(&value, basic_value, sizeof(basic_value))) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            seen |= 0x01u;
        } else if (der_equals(&oid, oid_key_usage, sizeof(oid_key_usage))) {
            if ((seen & 0x02u) != 0u || !critical
                || !der_equals(&value, ku_value, sizeof(ku_value))) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            seen |= 0x02u;
        } else if (der_equals(&oid, oid_eku, sizeof(oid_eku))) {
            if ((seen & 0x04u) != 0u || !critical
                || (!der_equals(&value, eku_client, sizeof(eku_client))
                    && !der_equals(
                        &value, eku_server, sizeof(eku_server)))) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            eku_role = der_equals(&value, eku_client, sizeof(eku_client))
                ? NINLIL_WIFI_LEAF_ROLE_CLIENT
                : NINLIL_WIFI_LEAF_ROLE_SERVER;
            seen |= 0x04u;
        } else if (der_equals(&oid, oid_san, sizeof(oid_san))) {
            if ((seen & 0x08u) != 0u || !critical
                || ninlil_wifi_leaf_binding_parse_general_names(
                       value.p, value.len, &binding)
                    != NINLIL_WIFI_OK) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            seen |= 0x08u;
        } else if (der_equals(&oid, oid_ski, sizeof(oid_ski))) {
            if ((seen & 0x10u) != 0u || critical || value.len != 22u
                || value.p[0] != 0x04u || value.p[1] != 0x14u) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            seen |= 0x10u;
        } else if (der_equals(&oid, oid_aki, sizeof(oid_aki))) {
            if ((seen & 0x20u) != 0u || critical || value.len != 24u
                || value.p[0] != 0x30u || value.p[1] != 0x16u
                || value.p[2] != 0x80u || value.p[3] != 0x14u) {
                return NINLIL_WIFI_CREDENTIAL;
            }
            seen |= 0x20u;
        } else {
            return NINLIL_WIFI_CREDENTIAL;
        }
    }
    if (cursor != end || seen != 0x3fu) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (binding.role != eku_role || bytes_all_zero(binding.runtime_id, 16u)) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    *out = binding;
    return NINLIL_WIFI_OK;
}

static int tls_verify_callback(
    void *ctx,
    mbedtls_x509_crt *crt,
    int depth,
    uint32_t *flags)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)ctx;
    ninlil_wifi_leaf_binding_t binding;
    if (tls == NULL || crt == NULL || flags == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if (depth == 0
        && (mbed_leaf_binding_exact(crt, &binding) != NINLIL_WIFI_OK
            || !tls->identity_expectation_set
            || !leaf_binding_equal(
                &binding, &tls->identity_expectation.peer_leaf))) {
        *flags |= MBEDTLS_X509_BADCERT_OTHER;
    }
    return 0;
}

static ninlil_wifi_status_t tls_allocator_enter(
    struct ninlil_wifi_esp_tls *tls)
{
    if (tls == NULL || tls->allocator_registered == 0) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    return ninlil_wifi_esp_tls_allocator_owner_enter(tls->allocator_owner);
}

static void tls_allocator_leave(struct ninlil_wifi_esp_tls *tls)
{
    if (tls != NULL && tls->allocator_registered != 0) {
        ninlil_wifi_esp_tls_allocator_owner_leave(tls->allocator_owner);
    }
}

static void tls_free_mbed_owned(struct ninlil_wifi_esp_tls *tls)
{
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    mbedtls_x509_crt_free(&tls->ca);
    mbedtls_x509_crt_free(&tls->cert);
    mbedtls_pk_free(&tls->key);
    mbedtls_ctr_drbg_free(&tls->ctr_drbg);
    mbedtls_entropy_free(&tls->entropy);
    tls->net.fd = -1;
    tls->ready = 0;
    tls->identity_verified = 0;
    tls->inited = 0;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_init(
    ninlil_wifi_esp_tls_t *tls_opaque,
    int is_server,
    const ninlil_wifi_esp_tls_pem_t *pems)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    static const int ciphersuites[] = {
        MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
        0
    };
    static const uint16_t groups[] = {
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
        0u
    };
    static const uint16_t signature_algorithms[] = {
        MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
        MBEDTLS_TLS1_3_SIG_NONE
    };
    ninlil_wifi_status_t status;
    ninlil_wifi_leaf_binding_t local_binding;
    uint32_t allocator_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    int rc;
    const char *pers = "ninlil-wifi-v1";
    if (tls == NULL || pems == NULL || pems->ca_pem == NULL
        || pems->cert_pem == NULL || pems->key_pem == NULL
        || pems->ca_pem_len == 0u || pems->cert_pem_len == 0u
        || pems->key_pem_len == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    status = ninlil_wifi_esp_tls_allocator_bootstrap();
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    status =
        ninlil_wifi_esp_tls_allocator_session_register(&allocator_owner);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    (void)memset(tls, 0, sizeof(*tls));
    tls->is_server = is_server ? 1 : 0;
    tls->allocator_owner = allocator_owner;
    tls->allocator_registered = 1;
    status = tls_allocator_enter(tls);
    if (status != NINLIL_WIFI_OK) {
        (void)ninlil_wifi_esp_tls_allocator_session_release(allocator_owner);
        (void)memset(tls, 0, sizeof(*tls));
        return status;
    }
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_x509_crt_init(&tls->ca);
    mbedtls_x509_crt_init(&tls->cert);
    mbedtls_pk_init(&tls->key);
    mbedtls_entropy_init(&tls->entropy);
    mbedtls_ctr_drbg_init(&tls->ctr_drbg);
    mbedtls_net_init(&tls->net);
    tls->inited = 1;

    rc = mbedtls_ctr_drbg_seed(
        &tls->ctr_drbg,
        mbedtls_entropy_func,
        &tls->entropy,
        (const unsigned char *)pers,
        strlen(pers));
    if (rc != 0) {
        status = NINLIL_WIFI_TLS_FAILED;
        goto fail;
    }
    rc = mbedtls_x509_crt_parse(
        &tls->ca, pems->ca_pem, pems->ca_pem_len);
    if (rc != 0) {
        status = NINLIL_WIFI_CREDENTIAL;
        goto fail;
    }
    rc = mbedtls_x509_crt_parse(
        &tls->cert, pems->cert_pem, pems->cert_pem_len);
    if (rc != 0) {
        status = NINLIL_WIFI_CREDENTIAL;
        goto fail;
    }
    if (mbed_leaf_binding_exact(&tls->cert, &local_binding)
            != NINLIL_WIFI_OK
        || (tls->is_server
                && local_binding.role != NINLIL_WIFI_LEAF_ROLE_SERVER)
        || (!tls->is_server
            && local_binding.role != NINLIL_WIFI_LEAF_ROLE_CLIENT)) {
        status = NINLIL_WIFI_CREDENTIAL;
        goto fail;
    }
    rc = mbedtls_pk_parse_key(
        &tls->key,
        pems->key_pem,
        pems->key_pem_len,
        NULL,
        0,
        mbedtls_ctr_drbg_random,
        &tls->ctr_drbg);
    if (rc != 0) {
        status = NINLIL_WIFI_CREDENTIAL;
        goto fail;
    }
    rc = mbedtls_ssl_config_defaults(
        &tls->conf,
        is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        status = NINLIL_WIFI_TLS_FAILED;
        goto fail;
    }
    /* Exact TLS1.3/P-256/ECDSA-SHA256 profile, both roles. */
    mbedtls_ssl_conf_min_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ciphersuites(&tls->conf, ciphersuites);
    mbedtls_ssl_conf_groups(&tls->conf, groups);
    mbedtls_ssl_conf_sig_algs(&tls->conf, signature_algorithms);
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->ca, NULL);
    mbedtls_ssl_conf_verify(&tls->conf, tls_verify_callback, tls);
    rc = mbedtls_ssl_conf_own_cert(&tls->conf, &tls->cert, &tls->key);
    if (rc != 0) {
        status = NINLIL_WIFI_CREDENTIAL;
        goto fail;
    }
    mbedtls_ssl_conf_rng(
        &tls->conf, mbedtls_ctr_drbg_random, &tls->ctr_drbg);
    status = ninlil_wifi_esp_tls_allocator_io_begin(allocator_owner);
    if (status != NINLIL_WIFI_OK) {
        goto fail;
    }
    rc = mbedtls_ssl_setup(&tls->ssl, &tls->conf);
    status = ninlil_wifi_esp_tls_allocator_io_finish(
        allocator_owner,
        tls->ssl.MBEDTLS_PRIVATE(in_buf),
        NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES,
        tls->ssl.MBEDTLS_PRIVATE(out_buf),
        NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES);
    if (rc != 0 || status != NINLIL_WIFI_OK) {
        status = NINLIL_WIFI_TLS_FAILED;
        goto fail;
    }
    rc = mbedtls_ssl_set_hostname(&tls->ssl, NULL);
    if (rc != 0) {
        status = NINLIL_WIFI_TLS_FAILED;
        goto fail;
    }
    tls_allocator_leave(tls);
    return NINLIL_WIFI_OK;

fail:
    tls_free_mbed_owned(tls);
    tls_allocator_leave(tls);
    (void)ninlil_wifi_esp_tls_allocator_session_release(allocator_owner);
    (void)memset(tls, 0, sizeof(*tls));
    return status;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_set_identity_expectation(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    ninlil_wifi_leaf_binding_t local_binding;
    ninlil_wifi_esp_tls_verified_identity_t ignored;
    if (tls == NULL || !tls->inited || tls->ready
        || !expectation_header_valid(expectation)
        || mbed_leaf_binding_exact(&tls->cert, &local_binding)
            != NINLIL_WIFI_OK
        || ninlil_wifi_esp_tls_identity_match(
               tls->is_server,
               expectation,
               &local_binding,
               &expectation->peer_leaf,
               &ignored)
            != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    tls->identity_expectation = *expectation;
    tls->identity_expectation_set = 1;
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_tls_close(ninlil_wifi_esp_tls_t *tls_opaque)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    uint32_t owner;
    if (tls == NULL || !tls->inited || tls->allocator_registered == 0) {
        return;
    }
    owner = tls->allocator_owner;
    if (tls_allocator_enter(tls) != NINLIL_WIFI_OK) {
        return;
    }
    tls_free_mbed_owned(tls);
    tls_allocator_leave(tls);
    if (ninlil_wifi_esp_tls_allocator_session_release(owner)
        != NINLIL_WIFI_OK) {
        return;
    }
    (void)memset(tls, 0, sizeof(*tls));
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_attach_fd(
    ninlil_wifi_esp_tls_t *tls_opaque,
    int fd)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    ninlil_wifi_status_t status;
    if (tls == NULL || !tls->inited || fd < 0) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    status = tls_allocator_enter(tls);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    tls->net.fd = fd;
    mbedtls_ssl_set_bio(
        &tls->ssl,
        &tls->net,
        mbedtls_net_send,
        mbedtls_net_recv,
        NULL);
    tls->ready = 0;
    tls->identity_verified = 0;
    tls_allocator_leave(tls);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_handshake(
    ninlil_wifi_esp_tls_t *tls_opaque)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    ninlil_wifi_status_t status;
    int rc;
    if (tls == NULL || !tls->inited) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (tls->ready) {
        return NINLIL_WIFI_OK;
    }
    if (!tls->identity_expectation_set) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    status = tls_allocator_enter(tls);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    rc = mbedtls_ssl_handshake(&tls->ssl);
    tls_allocator_leave(tls);
    if (rc == 0) {
        tls->ready = 1;
        status = ninlil_wifi_esp_tls_post_handshake_accept(tls_opaque);
        if (status != NINLIL_WIFI_OK) {
            tls->ready = 0;
        }
        return status;
    }
    return map_mbed(rc);
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_write(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const uint8_t *data,
    size_t len,
    size_t *written_out)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    ninlil_wifi_status_t status;
    int rc;
    if (tls == NULL || data == NULL || written_out == NULL || !tls->ready) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *written_out = 0u;
    status = tls_allocator_enter(tls);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    rc = mbedtls_ssl_write(&tls->ssl, data, len);
    tls_allocator_leave(tls);
    if (rc > 0) {
        *written_out = (size_t)rc;
        return (*written_out < len) ? NINLIL_WIFI_WOULD_BLOCK : NINLIL_WIFI_OK;
    }
    return map_mbed(rc);
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_read(
    ninlil_wifi_esp_tls_t *tls_opaque,
    uint8_t *data,
    size_t cap,
    size_t *read_out)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    ninlil_wifi_status_t status;
    int rc;
    if (tls == NULL || data == NULL || read_out == NULL || !tls->ready) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *read_out = 0u;
    status = tls_allocator_enter(tls);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    rc = mbedtls_ssl_read(&tls->ssl, data, cap);
    tls_allocator_leave(tls);
    if (rc > 0) {
        *read_out = (size_t)rc;
        return NINLIL_WIFI_OK;
    }
    return map_mbed(rc);
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_post_handshake_accept(
    ninlil_wifi_esp_tls_t *tls_opaque)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    const mbedtls_x509_crt *peer;
    ninlil_wifi_leaf_binding_t local_binding;
    ninlil_wifi_leaf_binding_t peer_binding;
    ninlil_wifi_esp_tls_verified_identity_t verified;
    ninlil_wifi_status_t status;
    int cipher_id;
    mbedtls_ssl_protocol_version version;
    uint32_t flags;
    if (tls == NULL || !tls->ready) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    status = tls_allocator_enter(tls);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    flags = mbedtls_ssl_get_verify_result(&tls->ssl);
    peer = mbedtls_ssl_get_peer_cert(&tls->ssl);
    cipher_id = mbedtls_ssl_get_ciphersuite_id_from_ssl(&tls->ssl);
    version = mbedtls_ssl_get_version_number(&tls->ssl);
    tls_allocator_leave(tls);
    if (flags != 0u) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    if (peer == NULL || cipher_id != MBEDTLS_TLS1_3_AES_128_GCM_SHA256
        || version != MBEDTLS_SSL_VERSION_TLS1_3
        || mbed_leaf_binding_exact(&tls->cert, &local_binding)
            != NINLIL_WIFI_OK
        || mbed_leaf_binding_exact(peer, &peer_binding) != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    status = ninlil_wifi_esp_tls_identity_match(
        tls->is_server,
        &tls->identity_expectation,
        &local_binding,
        &peer_binding,
        &verified);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    tls->verified_identity = verified;
    tls->identity_verified = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_verified_identity(
    ninlil_wifi_esp_tls_t *tls_opaque,
    ninlil_wifi_esp_tls_verified_identity_t *out)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (tls == NULL || out == NULL || !tls->ready
        || !tls->identity_verified) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    *out = tls->verified_identity;
    return NINLIL_WIFI_OK;
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

ninlil_wifi_status_t ninlil_wifi_esp_tls_export_peer_session_id(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const uint8_t peer_context[62],
    uint8_t peer_session_id_out[16])
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    int rc;
    if (tls == NULL || peer_context == NULL || peer_session_id_out == NULL
        || !tls->ready) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_esp_tls_post_handshake_accept(tls_opaque)
        != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    /*
     * mbedTLS TLS-Exporter (RFC 5705 / 8446 §7.5). Prototype is gated in
     * mbedtls/ssl.h by MBEDTLS_SSL_KEYING_MATERIAL_EXPORT, which ESP-IDF
     * maps from CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT.
     *
     * Feature OFF: fail closed. Never synthesize peer_session_id.
     */
#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    if (tls_allocator_enter(tls) != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    rc = mbedtls_ssl_export_keying_material(
        &tls->ssl,
        peer_session_id_out,
        16u,
        NINLIL_WIFI_EXPORTER_PEER_LABEL,
        sizeof(NINLIL_WIFI_EXPORTER_PEER_LABEL) - 1u,
        peer_context,
        NINLIL_WIFI_PEER_CONTEXT_BYTES,
        1);
    tls_allocator_leave(tls);
    if (rc != 0) {
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (is_all_zero16(peer_session_id_out)) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
#else
    (void)tls;
    (void)peer_context;
    (void)peer_session_id_out;
    return NINLIL_WIFI_TLS_FAILED;
#endif
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_export_attached_session_id(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const uint8_t attached_context[64],
    uint8_t session_id_out[16])
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    int rc;
    if (tls == NULL || attached_context == NULL || session_id_out == NULL
        || !tls->ready) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (ninlil_wifi_esp_tls_post_handshake_accept(tls_opaque)
        != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    /*
     * Same KEYING_MATERIAL_EXPORT gate as peer export. Feature OFF: fail
     * closed — never synthesize attached session_id.
     */
#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    if (tls_allocator_enter(tls) != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    rc = mbedtls_ssl_export_keying_material(
        &tls->ssl,
        session_id_out,
        16u,
        NINLIL_WIFI_EXPORTER_ATTACHED_LABEL,
        sizeof(NINLIL_WIFI_EXPORTER_ATTACHED_LABEL) - 1u,
        attached_context,
        NINLIL_WIFI_ATTACHED_CONTEXT_BYTES,
        1);
    tls_allocator_leave(tls);
    if (rc != 0) {
        return NINLIL_WIFI_TLS_FAILED;
    }
    if (is_all_zero16(session_id_out)) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
#else
    (void)tls;
    (void)attached_context;
    (void)session_id_out;
    return NINLIL_WIFI_TLS_FAILED;
#endif
}

#else /* !ESP_PLATFORM */

/*
 * Host software path for ESP owner state-machine tests.
 * Loopback byte pipes + domain-separated SHA-256 ID derivation (not mbedTLS
 * TLS-Exporter, not physical AP). Exact 62/64 context sizes preserved.
 */
#include "wifi_sha256.h"

#define NINLIL_WIFI_ESP_TLS_HOST_RING 2048u

struct ninlil_wifi_esp_tls {
    int is_server;
    int ready;
    int inited;
    int identity_expectation_set;
    int identity_verified;
    int fd;
    struct ninlil_wifi_esp_tls *peer;
    ninlil_wifi_esp_tls_identity_expectation_t identity_expectation;
    ninlil_wifi_esp_tls_verified_identity_t verified_identity;
    uint8_t rx[NINLIL_WIFI_ESP_TLS_HOST_RING];
    size_t rx_r;
    size_t rx_w;
    size_t rx_used;
};

size_t ninlil_wifi_esp_tls_sizeof(void)
{
    return sizeof(struct ninlil_wifi_esp_tls);
}

void ninlil_wifi_esp_tls_host_pair(
    ninlil_wifi_esp_tls_t *a_opaque,
    ninlil_wifi_esp_tls_t *b_opaque)
{
    struct ninlil_wifi_esp_tls *a = (struct ninlil_wifi_esp_tls *)a_opaque;
    struct ninlil_wifi_esp_tls *b = (struct ninlil_wifi_esp_tls *)b_opaque;
    if (a == NULL || b == NULL) {
        return;
    }
    a->peer = b;
    b->peer = a;
}

static size_t ring_space(const struct ninlil_wifi_esp_tls *t)
{
    return NINLIL_WIFI_ESP_TLS_HOST_RING - t->rx_used;
}

static size_t ring_push(
    struct ninlil_wifi_esp_tls *t, const uint8_t *data, size_t len)
{
    size_t n = len;
    size_t i;
    if (n > ring_space(t)) {
        n = ring_space(t);
    }
    for (i = 0u; i < n; ++i) {
        t->rx[t->rx_w] = data[i];
        t->rx_w = (t->rx_w + 1u) % NINLIL_WIFI_ESP_TLS_HOST_RING;
    }
    t->rx_used += n;
    return n;
}

static size_t ring_pop(
    struct ninlil_wifi_esp_tls *t, uint8_t *data, size_t cap)
{
    size_t n = cap;
    size_t i;
    if (n > t->rx_used) {
        n = t->rx_used;
    }
    for (i = 0u; i < n; ++i) {
        data[i] = t->rx[t->rx_r];
        t->rx_r = (t->rx_r + 1u) % NINLIL_WIFI_ESP_TLS_HOST_RING;
    }
    t->rx_used -= n;
    return n;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_init(
    ninlil_wifi_esp_tls_t *tls_opaque,
    int is_server,
    const ninlil_wifi_esp_tls_pem_t *pems)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL || pems == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(tls, 0, sizeof(*tls));
    tls->is_server = is_server ? 1 : 0;
    tls->fd = -1;
    tls->inited = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_set_identity_expectation(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    ninlil_wifi_esp_tls_verified_identity_t verified;
    ninlil_wifi_status_t status;
    if (tls == NULL || !tls->inited || tls->ready) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    status = ninlil_wifi_esp_tls_identity_match(
        tls->is_server,
        expectation,
        expectation != NULL ? &expectation->local_leaf : NULL,
        expectation != NULL ? &expectation->peer_leaf : NULL,
        &verified);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    tls->identity_expectation = *expectation;
    tls->identity_expectation_set = 1;
    tls->identity_verified = 0;
    (void)memset(&tls->verified_identity, 0, sizeof(tls->verified_identity));
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_tls_close(ninlil_wifi_esp_tls_t *tls_opaque)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL) {
        return;
    }
    if (tls->peer != NULL && tls->peer->peer == tls) {
        tls->peer->peer = NULL;
    }
    (void)memset(tls, 0, sizeof(*tls));
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_attach_fd(
    ninlil_wifi_esp_tls_t *tls_opaque, int fd)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL || !tls->inited) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    tls->fd = fd;
    tls->ready = 0;
    tls->identity_verified = 0;
    (void)memset(&tls->verified_identity, 0, sizeof(tls->verified_identity));
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_handshake(
    ninlil_wifi_esp_tls_t *tls_opaque)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL || !tls->inited) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (!tls->identity_expectation_set) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    /*
     * The Host double has no certificate parser. Its credential authority is
     * therefore the exact provisioned leaf pair. If paired, both ends must
     * pin the same leaves in opposite order before the semantic handshake may
     * complete. An unpaired instance is only a deterministic owner-SM seam,
     * never real-TLS or HIL evidence.
     */
    if (tls->peer != NULL
        && (!tls->peer->inited || !tls->peer->identity_expectation_set
            || tls->is_server == tls->peer->is_server
            || !leaf_binding_equal(
                &tls->identity_expectation.local_leaf,
                &tls->peer->identity_expectation.peer_leaf)
            || !leaf_binding_equal(
                &tls->identity_expectation.peer_leaf,
                &tls->peer->identity_expectation.local_leaf))) {
        return NINLIL_WIFI_CREDENTIAL;
    }
    tls->verified_identity.local_leaf =
        tls->identity_expectation.local_leaf;
    tls->verified_identity.peer_leaf =
        tls->identity_expectation.peer_leaf;
    tls->identity_verified = 1;
    tls->ready = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_write(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const uint8_t *data,
    size_t len,
    size_t *written_out)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    size_t n;
    if (tls == NULL || data == NULL || written_out == NULL || !tls->ready) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *written_out = 0u;
    if (tls->peer == NULL) {
        /* Solo: accept full write (black-hole) for TX pump unit paths. */
        *written_out = len;
        return NINLIL_WIFI_OK;
    }
    n = ring_push(tls->peer, data, len);
    *written_out = n;
    if (n == 0u) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    return (n < len) ? NINLIL_WIFI_WOULD_BLOCK : NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_read(
    ninlil_wifi_esp_tls_t *tls_opaque,
    uint8_t *data,
    size_t cap,
    size_t *read_out)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    size_t n;
    if (tls == NULL || data == NULL || read_out == NULL || !tls->ready) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *read_out = 0u;
    n = ring_pop(tls, data, cap);
    if (n == 0u) {
        return NINLIL_WIFI_WOULD_BLOCK;
    }
    *read_out = n;
    return NINLIL_WIFI_OK;
}

static int host_is_all_zero16(const uint8_t *p)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static ninlil_wifi_status_t host_export_id(
    const char *label,
    size_t label_len,
    const uint8_t *context,
    size_t context_len,
    uint8_t out[16])
{
    uint8_t buf[128];
    uint8_t dig[32];
    size_t i;
    if (label == NULL || context == NULL || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (label_len + context_len > sizeof(buf)) {
        return NINLIL_WIFI_CAPACITY;
    }
    for (i = 0u; i < label_len; ++i) {
        buf[i] = (uint8_t)label[i];
    }
    for (i = 0u; i < context_len; ++i) {
        buf[label_len + i] = context[i];
    }
    ninlil_wifi_sha256(buf, label_len + context_len, dig);
    (void)memcpy(out, dig, 16u);
    if (host_is_all_zero16(out)) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_export_peer_session_id(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const uint8_t peer_context[62],
    uint8_t peer_session_id_out[16])
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL || !tls->ready || !tls->identity_verified
        || peer_context == NULL
        || peer_session_id_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    return host_export_id(
        NINLIL_WIFI_EXPORTER_PEER_LABEL,
        sizeof(NINLIL_WIFI_EXPORTER_PEER_LABEL) - 1u,
        peer_context,
        NINLIL_WIFI_PEER_CONTEXT_BYTES,
        peer_session_id_out);
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_export_attached_session_id(
    ninlil_wifi_esp_tls_t *tls_opaque,
    const uint8_t attached_context[64],
    uint8_t session_id_out[16])
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL || !tls->ready || !tls->identity_verified
        || attached_context == NULL
        || session_id_out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    return host_export_id(
        NINLIL_WIFI_EXPORTER_ATTACHED_LABEL,
        sizeof(NINLIL_WIFI_EXPORTER_ATTACHED_LABEL) - 1u,
        attached_context,
        NINLIL_WIFI_ATTACHED_CONTEXT_BYTES,
        session_id_out);
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_post_handshake_accept(
    ninlil_wifi_esp_tls_t *tls_opaque)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (tls == NULL || !tls->ready || !tls->identity_verified) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_verified_identity(
    ninlil_wifi_esp_tls_t *tls_opaque,
    ninlil_wifi_esp_tls_verified_identity_t *out)
{
    struct ninlil_wifi_esp_tls *tls = (struct ninlil_wifi_esp_tls *)tls_opaque;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (tls == NULL || out == NULL || !tls->ready
        || !tls->identity_verified) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    *out = tls->verified_identity;
    return NINLIL_WIFI_OK;
}

#endif /* ESP_PLATFORM */
