#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_HOST_INTERNAL_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_HOST_INTERNAL_H

/*
 * Private Host TLS object authority shared by wifi_tls_host.c and the Host
 * exporter implementation.  Keeping one definition prevents opaque-layout
 * drift across translation units.  Never install this header.
 */
#if !defined(ESP_PLATFORM)

#include <openssl/provider.h>
#include <openssl/ssl.h>

struct ninlil_wifi_tls {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *default_provider;
    SSL_CTX *ctx;
    SSL *ssl;
    int is_server;
    int ready;
    int fd;
    int profile_authority;
};

#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_TLS_HOST_INTERNAL_H */
