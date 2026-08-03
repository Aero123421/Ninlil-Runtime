#ifndef NINLIL_TEST_FAKE_MBEDTLS_ECP_H
#define NINLIL_TEST_FAKE_MBEDTLS_ECP_H

#define MBEDTLS_ECP_DP_SECP256R1 3

typedef struct mbedtls_ecp_group {
    unsigned char active;
} mbedtls_ecp_group;

void mbedtls_ecp_group_init(mbedtls_ecp_group *group);
void mbedtls_ecp_group_free(mbedtls_ecp_group *group);
int mbedtls_ecp_group_load(mbedtls_ecp_group *group, int id);

#endif
