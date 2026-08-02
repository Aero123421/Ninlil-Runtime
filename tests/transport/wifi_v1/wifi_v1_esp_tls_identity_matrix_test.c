#include "wifi_esp_tls_mbedtls.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(condition_)                                                      \
    do {                                                                       \
        if (!(condition_)) {                                                   \
            (void)fprintf(                                                     \
                stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #condition_);  \
            failures += 1;                                                     \
        }                                                                      \
    } while (0)

static ninlil_wifi_leaf_binding_t leaf(uint8_t role, uint8_t runtime_byte)
{
    ninlil_wifi_leaf_binding_t value;
    (void)memset(&value, 0, sizeof(value));
    value.version = NINLIL_WIFI_LEAF_BINDING_VERSION;
    value.role = role;
    (void)memset(value.runtime_id, runtime_byte, 16u);
    (void)memset(value.authorized_attachment_binding_digest, 0xa1, 32u);
    (void)memset(value.authority_id, 0xd0, 16u);
    value.authority_term = 7u;
    value.credential_generation = 3u;
    value.revocation_generation = 5u;
    return value;
}

static void expect_reject(
    int is_server,
    const ninlil_wifi_esp_tls_identity_expectation_t *expectation,
    const ninlil_wifi_leaf_binding_t *local,
    const ninlil_wifi_leaf_binding_t *peer)
{
    ninlil_wifi_esp_tls_verified_identity_t out;
    (void)memset(&out, 0xa5, sizeof(out));
    CHECK(ninlil_wifi_esp_tls_identity_match(
              is_server, expectation, local, peer, &out)
        != NINLIL_WIFI_OK);
}

int main(void)
{
    ninlil_wifi_esp_tls_identity_expectation_t expectation;
    ninlil_wifi_esp_tls_verified_identity_t verified;
    ninlil_wifi_leaf_binding_t local;
    ninlil_wifi_leaf_binding_t peer;
    ninlil_wifi_leaf_binding_t mutated;
    failures = 0;

    (void)memset(&expectation, 0, sizeof(expectation));
    expectation.api_version =
        NINLIL_WIFI_ESP_TLS_IDENTITY_EXPECTATION_VERSION;
    expectation.struct_size = (uint16_t)sizeof(expectation);
    local = leaf(NINLIL_WIFI_LEAF_ROLE_CLIENT, 0x31u);
    peer = leaf(NINLIL_WIFI_LEAF_ROLE_SERVER, 0x32u);
    expectation.local_leaf = local;
    expectation.peer_leaf = peer;
    CHECK(ninlil_wifi_esp_tls_identity_match(
              0, &expectation, &local, &peer, &verified)
        == NINLIL_WIFI_OK);
    CHECK(memcmp(&verified.local_leaf, &local, sizeof(local)) == 0);
    CHECK(memcmp(&verified.peer_leaf, &peer, sizeof(peer)) == 0);

    {
        ninlil_wifi_esp_tls_identity_expectation_t bad = expectation;
        bad.api_version += 1u;
        expect_reject(0, &bad, &local, &peer);
        bad = expectation;
        bad.struct_size -= 1u;
        expect_reject(0, &bad, &local, &peer);
        bad = expectation;
        bad.reserved_zero[0] = 1u;
        expect_reject(0, &bad, &local, &peer);
    }

#define MUTATE_AND_REJECT(statement_)                                          \
    do {                                                                       \
        mutated = local;                                                       \
        statement_;                                                            \
        expect_reject(0, &expectation, &mutated, &peer);                       \
    } while (0)
    MUTATE_AND_REJECT(mutated.version ^= 1u);
    MUTATE_AND_REJECT(mutated.role = NINLIL_WIFI_LEAF_ROLE_SERVER);
    MUTATE_AND_REJECT(mutated.runtime_id[0] ^= 1u);
    MUTATE_AND_REJECT(
        mutated.authorized_attachment_binding_digest[0] ^= 1u);
    MUTATE_AND_REJECT(mutated.authority_id[0] ^= 1u);
    MUTATE_AND_REJECT(mutated.authority_term += 1u);
    MUTATE_AND_REJECT(mutated.credential_generation += 1u);
    MUTATE_AND_REJECT(mutated.revocation_generation += 1u);
#undef MUTATE_AND_REJECT

#define MUTATE_PEER_AND_REJECT(statement_)                                     \
    do {                                                                       \
        mutated = peer;                                                        \
        statement_;                                                            \
        expect_reject(0, &expectation, &local, &mutated);                      \
    } while (0)
    MUTATE_PEER_AND_REJECT(mutated.version ^= 1u);
    MUTATE_PEER_AND_REJECT(mutated.role = NINLIL_WIFI_LEAF_ROLE_CLIENT);
    MUTATE_PEER_AND_REJECT(mutated.runtime_id[0] ^= 1u);
    MUTATE_PEER_AND_REJECT(
        mutated.authorized_attachment_binding_digest[0] ^= 1u);
    MUTATE_PEER_AND_REJECT(mutated.authority_id[0] ^= 1u);
    MUTATE_PEER_AND_REJECT(mutated.authority_term += 1u);
    MUTATE_PEER_AND_REJECT(mutated.credential_generation += 1u);
    MUTATE_PEER_AND_REJECT(mutated.revocation_generation += 1u);
#undef MUTATE_PEER_AND_REJECT

    mutated = local;
    (void)memset(&mutated, 0, sizeof(mutated));
    expect_reject(0, &expectation, &mutated, &peer);
    mutated = peer;
    (void)memset(&mutated, 0, sizeof(mutated));
    expect_reject(0, &expectation, &local, &mutated);
    expect_reject(1, &expectation, &local, &peer);

    /* The same pair in the opposite order is the exact server profile. */
    expectation.local_leaf = peer;
    expectation.peer_leaf = local;
    CHECK(ninlil_wifi_esp_tls_identity_match(
              1, &expectation, &peer, &local, &verified)
        == NINLIL_WIFI_OK);

    if (failures != 0) {
        (void)fprintf(
            stderr,
            "wifi_v1_esp_tls_identity_matrix_test FAIL %d\n",
            failures);
        return 1;
    }
    (void)printf("wifi_v1_esp_tls_identity_matrix_test PASS\n");
    return 0;
}
