#ifndef NINLIL_TEST_FAKE_MBEDTLS_MD_H
#define NINLIL_TEST_FAKE_MBEDTLS_MD_H

typedef struct mbedtls_md_info_t {
    unsigned char size;
    unsigned char block_size;
} mbedtls_md_info_t;

#define MBEDTLS_MD_SHA256 6

const mbedtls_md_info_t *mbedtls_md_info_from_type(int type);

#endif
