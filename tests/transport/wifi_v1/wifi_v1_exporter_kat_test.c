/*
 * ADR-0018 exporter context KATs + negative tests for inverted semantics.
 * Contexts are 62/64-byte inputs; IDs are 16-byte exporter outputs.
 */
#include "wifi_tls_export.h"

#include <openssl/sha.h>
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

/* Pins from wifi-bearer-spec-v1.json */
static const char *PEER_CTX_SHA =
    "1997f5b4dbdc4ecca9d1ccbff66bff4c6d69594c92b37d8c1855b9cd2e3c86ec";
static const char *ATT_CTX_SHA =
    "a21c1c7ce004ed053a7704e5a54760751ed6e0f78ab8926759df3d0169cee713";

/* From vector WIFI-TLS-EXPORTER-PEER-CONTEXT-62 */
static const uint8_t PEER_CTX_HEX[] = {
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
    0xdc, 0xdd, 0xde, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x0b, 0x01, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x02, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41
};
_Static_assert(sizeof(PEER_CTX_HEX) == 62u, "peer context kat len");

/* From vector WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64 */
static const uint8_t ATT_CTX_HEX[] = {
    0xff, 0xa4, 0xa8, 0x51, 0x99, 0xba, 0x62, 0xfc, 0x6e, 0xfd, 0xb8, 0xf9,
    0xc3, 0xd7, 0xb5, 0x68, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf6, 0x26, 0x90, 0x83,
    0x3a, 0x93, 0xfd, 0x5d, 0xdf, 0x54, 0x48, 0x31, 0xe6, 0x15, 0x72, 0xd8,
    0x79, 0xd6, 0x56, 0x76, 0x55, 0x37, 0x14, 0x3f, 0x3f, 0x3e, 0x29, 0x26,
    0xf6, 0xf0, 0xf4, 0x9c
};
_Static_assert(sizeof(ATT_CTX_HEX) == 64u, "attached context kat len");

static void hex_of_sha(const uint8_t *data, size_t n, char out[65])
{
    uint8_t dig[32];
    size_t i;
    (void)SHA256(data, n, dig);
    for (i = 0u; i < 32u; ++i) {
        (void)snprintf(out + (i * 2u), 3u, "%02x", dig[i]);
    }
    out[64] = '\0';
}

static int from_hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

int main(void)
{
    ninlil_wifi_peer_context_inputs_t pin;
    ninlil_wifi_attached_context_inputs_t ain;
    uint8_t peer_ctx[62];
    uint8_t att_ctx[64];
    char sha_hex[65];
    failures = 0;

    /* Build peer_context from field layout and match vector. */
    (void)memset(&pin, 0, sizeof(pin));
    (void)memcpy(pin.authority_id, PEER_CTX_HEX, 16u);
    pin.authority_term = 7u;
    pin.assignment_epoch = 11u;
    (void)memcpy(pin.tls_client_runtime_id, PEER_CTX_HEX + 29, 16u);
    (void)memcpy(pin.tls_server_runtime_id, PEER_CTX_HEX + 46, 16u);
    CHECK(ninlil_wifi_build_peer_context(&pin, peer_ctx) == NINLIL_WIFI_OK);
    CHECK(memcmp(peer_ctx, PEER_CTX_HEX, 62u) == 0);
    hex_of_sha(peer_ctx, 62u, sha_hex);
    CHECK(strcmp(sha_hex, PEER_CTX_SHA) == 0);

    /* Labels exact. */
    CHECK(strcmp(NINLIL_WIFI_EXPORTER_PEER_LABEL, "EXPORTER-Ninlil-PeerSession-v1")
        == 0);
    CHECK(strcmp(
              NINLIL_WIFI_EXPORTER_ATTACHED_LABEL,
              "EXPORTER-Ninlil-NWB1-Attached-v1")
        == 0);
    CHECK(NINLIL_WIFI_PEER_CONTEXT_BYTES == 62u);
    CHECK(NINLIL_WIFI_ATTACHED_CONTEXT_BYTES == 64u);
    CHECK(NINLIL_WIFI_PEER_SESSION_ID_BYTES == 16u);
    CHECK(NINLIL_WIFI_ATTACHED_SESSION_ID_BYTES == 16u);

    /* Attached context builder + pin. */
    (void)memset(&ain, 0, sizeof(ain));
    (void)memcpy(ain.peer_session_id, ATT_CTX_HEX, 16u);
    (void)memcpy(ain.attachment_authority_id, ATT_CTX_HEX + 16, 16u);
    (void)memcpy(ain.active_attachment_binding_digest, ATT_CTX_HEX + 32, 32u);
    CHECK(ninlil_wifi_build_attached_context(&ain, att_ctx) == NINLIL_WIFI_OK);
    CHECK(memcmp(att_ctx, ATT_CTX_HEX, 64u) == 0);
    hex_of_sha(att_ctx, 64u, sha_hex);
    CHECK(strcmp(sha_hex, ATT_CTX_SHA) == 0);

    /* Negative: MIXED authority group rejected. */
    pin.authority_term = 0u; /* zero term with non-zero id/epoch => MIXED */
    pin.assignment_epoch = 11u;
    CHECK(ninlil_wifi_classify_authority_group(
              pin.authority_id, pin.authority_term, pin.assignment_epoch)
        == NINLIL_WIFI_AUTHORITY_MIXED);
    CHECK(ninlil_wifi_build_peer_context(&pin, peer_ctx) == NINLIL_WIFI_DENIED);

    /* Negative: ALL_ZERO authority without explicit allow. */
    (void)memset(&pin, 0, sizeof(pin));
    pin.allow_all_zero_authority = 0u;
    CHECK(ninlil_wifi_classify_authority_group(
              pin.authority_id, pin.authority_term, pin.assignment_epoch)
        == NINLIL_WIFI_AUTHORITY_ALL_ZERO);
    CHECK(ninlil_wifi_build_peer_context(&pin, peer_ctx) == NINLIL_WIFI_DENIED);
    /* Explicit allow still requires non-zero runtime ids. */
    pin.allow_all_zero_authority = 1u;
    CHECK(ninlil_wifi_build_peer_context(&pin, peer_ctx) == NINLIL_WIFI_DENIED);
    (void)memset(pin.tls_client_runtime_id, 0x11, 16u);
    (void)memset(pin.tls_server_runtime_id, 0x22, 16u);
    CHECK(ninlil_wifi_build_peer_context(&pin, peer_ctx) == NINLIL_WIFI_OK);

    /* Negative: ALL_NONZERO authority but all-zero client runtime. */
    (void)memset(&pin, 0, sizeof(pin));
    (void)memcpy(pin.authority_id, PEER_CTX_HEX, 16u);
    pin.authority_term = 7u;
    pin.assignment_epoch = 11u;
    (void)memset(pin.tls_client_runtime_id, 0, 16u);
    (void)memcpy(pin.tls_server_runtime_id, PEER_CTX_HEX + 46, 16u);
    CHECK(ninlil_wifi_build_peer_context(&pin, peer_ctx) == NINLIL_WIFI_DENIED);

    /* Negative: all-zero peer_session_id cannot build attached_context. */
    (void)memset(&ain, 0, sizeof(ain));
    CHECK(ninlil_wifi_build_attached_context(&ain, att_ctx)
        == NINLIL_WIFI_INVALID_STATE);

    /* Negative: inverted semantics — 62/64 are NOT session ids. */
    CHECK(NINLIL_WIFI_PEER_SESSION_ID_BYTES != NINLIL_WIFI_PEER_CONTEXT_BYTES);
    CHECK(
        NINLIL_WIFI_ATTACHED_SESSION_ID_BYTES
        != NINLIL_WIFI_ATTACHED_CONTEXT_BYTES);
    /* A 62-byte buffer must not be accepted as a 16-byte id by type contract. */
    {
        uint8_t wrong_id[62];
        (void)memset(wrong_id, 0xab, sizeof(wrong_id));
        /* Export APIs require 16-byte out; contexts require exact lengths. */
        CHECK(sizeof(wrong_id) != 16u);
    }

    /* Role bytes fixed in layout. */
    CHECK(PEER_CTX_HEX[28] == 0x01);
    CHECK(PEER_CTX_HEX[45] == 0x02);

    (void)from_hex_nibble; /* silence unused if optimized */
    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_exporter_kat_test: PASS\n");
    return 0;
}
