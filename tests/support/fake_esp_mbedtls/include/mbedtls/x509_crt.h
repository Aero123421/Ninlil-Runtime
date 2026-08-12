/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_MBEDTLS_X509_CRT_H
#define NINLIL_TEST_FAKE_MBEDTLS_X509_CRT_H

typedef struct mbedtls_x509_crt {
    unsigned char active;
} mbedtls_x509_crt;

void mbedtls_x509_crt_init(mbedtls_x509_crt *certificate);
void mbedtls_x509_crt_free(mbedtls_x509_crt *certificate);

#endif
