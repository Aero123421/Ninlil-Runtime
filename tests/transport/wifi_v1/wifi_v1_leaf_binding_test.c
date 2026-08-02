/*
 * ADR-0018 §14.2 leaf binding_value[82] codec + GeneralNames nest KAT.
 */
#include "wifi_tls_leaf_binding.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);          \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

/* WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT client_binding_hex */
static const uint8_t k_client_bind[82] = {
    0x01, 0x01, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
    0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0xf6, 0x26, 0x90, 0x83, 0x3a, 0x93,
    0xfd, 0x5d, 0xdf, 0x54, 0x48, 0x31, 0xe6, 0x15, 0x72, 0xd8, 0x79, 0xd6,
    0x56, 0x76, 0x55, 0x37, 0x14, 0x3f, 0x3f, 0x3e, 0x29, 0x26, 0xf6, 0xf0,
    0xf4, 0x9c, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
    0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05
};

static const uint8_t k_server_bind[82] = {
    0x01, 0x02, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0xf6, 0x26, 0x90, 0x83, 0x3a, 0x93,
    0xfd, 0x5d, 0xdf, 0x54, 0x48, 0x31, 0xe6, 0x15, 0x72, 0xd8, 0x79, 0xd6,
    0x56, 0x76, 0x55, 0x37, 0x14, 0x3f, 0x3f, 0x3e, 0x29, 0x26, 0xf6, 0xf0,
    0xf4, 0x9c, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
    0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05
};

int main(void)
{
    ninlil_wifi_leaf_binding_t b;
    uint8_t enc[82];
    uint8_t gn[112];
    failures = 0;

    CHECK(ninlil_wifi_leaf_binding_decode(k_client_bind, &b) == NINLIL_WIFI_OK);
    CHECK(b.version == 1u);
    CHECK(b.role == NINLIL_WIFI_LEAF_ROLE_CLIENT);
    CHECK(b.authority_term == 7u);
    CHECK(b.credential_generation == 3u);
    CHECK(b.revocation_generation == 5u);
    CHECK(ninlil_wifi_leaf_binding_encode(&b, enc) == NINLIL_WIFI_OK);
    CHECK(memcmp(enc, k_client_bind, 82u) == 0);

    CHECK(ninlil_wifi_leaf_binding_decode(k_server_bind, &b) == NINLIL_WIFI_OK);
    CHECK(b.role == NINLIL_WIFI_LEAF_ROLE_SERVER);
    CHECK(ninlil_wifi_leaf_binding_encode(&b, enc) == NINLIL_WIFI_OK);
    CHECK(memcmp(enc, k_server_bind, 82u) == 0);

    /* Build exact GeneralNames nest and parse. */
    (void)memset(gn, 0, sizeof(gn));
    gn[0] = 0x30;
    gn[1] = 0x6e;
    gn[2] = 0xa0;
    gn[3] = 0x6c;
    gn[4] = 0x06;
    gn[5] = 0x14;
    (void)memcpy(gn + 6, ninlil_wifi_leaf_binding_oid_der, 20u);
    gn[26] = 0xa0;
    gn[27] = 0x54;
    gn[28] = 0x04;
    gn[29] = 0x52;
    (void)memcpy(gn + 30, k_client_bind, 82u);
    CHECK(ninlil_wifi_leaf_binding_parse_general_names(gn, 112u, &b)
        == NINLIL_WIFI_OK);
    CHECK(b.role == NINLIL_WIFI_LEAF_ROLE_CLIENT);

    /* Negative: zero authority_term. */
    {
        uint8_t bad[82];
        (void)memcpy(bad, k_client_bind, 82u);
        (void)memset(bad + 66, 0, 8u);
        CHECK(ninlil_wifi_leaf_binding_decode(bad, &b) == NINLIL_WIFI_DENIED);
    }

    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_leaf_binding_test PASS\n");
    return 0;
}
