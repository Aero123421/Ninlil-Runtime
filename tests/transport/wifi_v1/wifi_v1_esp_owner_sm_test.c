/*
 * ESP owner SM (host): STA enqueue, GOT_IP gate, RX capacity, M4 incomplete
 * evidence. LAB path uses host TLS loopback; not physical AP HIL.
 */
#include "wifi_attachment_m4.h"
#include "wifi_esp_owner.h"
#include "wifi_esp_sta.h"
#include "wifi_esp_tls_mbedtls.h"
#include "wifi_nfl1_min.h"
#include "wifi_sha256.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c);   \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

typedef struct credential_provider_fixture {
    wifi_network_credential_metadata_v1_t metadata;
    uint8_t secret[WIFI_NETCRED_SECRET_BYTES];
    uint32_t get_calls;
    uint32_t release_calls;
    int release_received_zero;
    wifi_network_credential_status_v1_t get_status;
    int poison_non_ok;
} credential_provider_fixture_t;

static int test_bytes_zero(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void test_put_u64_be(uint8_t *p, uint64_t value)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[7u - i] = (uint8_t)(value >> (8u * i));
    }
}

static void test_profile_digest(
    const wifi_network_credential_metadata_v1_t *metadata,
    uint8_t out[32])
{
    static const uint8_t tag[] = "NINLIL-WIFI-NETWORK-PROFILE-V1";
    uint8_t canonical[192];
    size_t n = 0u;
    (void)memset(canonical, 0, sizeof(canonical));
    (void)memcpy(canonical + n, tag, sizeof(tag) - 1u);
    n += sizeof(tag) - 1u;
    (void)memcpy(canonical + n, metadata->profile_id.bytes, 16u);
    n += 16u;
    test_put_u64_be(canonical + n, metadata->revision);
    n += 8u;
    n += 32u; /* digest is zero in the canonical preimage */
    (void)memcpy(
        canonical + n, metadata->credential_binding_id.bytes, 16u);
    n += 16u;
    canonical[n++] = metadata->ssid_length;
    (void)memcpy(canonical + n, metadata->ssid, 32u);
    n += 32u;
    canonical[n++] = metadata->auth_mode;
    canonical[n++] = metadata->password_length;
    canonical[n++] = metadata->pmf_required;
    canonical[n++] = metadata->optional_bssid_present;
    (void)memcpy(canonical + n, metadata->bssid, 6u);
    n += 6u;
    canonical[n++] = metadata->channel;
    (void)memcpy(canonical + n, metadata->reserved_zero, 7u);
    n += 7u;
    ninlil_wifi_sha256(canonical, n, out);
    (void)memset(canonical, 0, sizeof(canonical));
}

static wifi_network_credential_status_v1_t test_credential_get(
    void *user,
    const ninlil_id128_t *profile_id,
    uint64_t revision,
    const uint8_t digest[32],
    wifi_network_credential_metadata_v1_t *out_metadata,
    uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES])
{
    credential_provider_fixture_t *fixture =
        (credential_provider_fixture_t *)user;
    (void)memset(out_metadata, 0, sizeof(*out_metadata));
    (void)memset(secret_buffer, 0, WIFI_NETCRED_SECRET_BYTES);
    fixture->get_calls += 1u;
    if (fixture->get_status != WIFI_NETCRED_OK) {
        if (fixture->poison_non_ok != 0) {
            out_metadata->api_version = 0xffffu;
            secret_buffer[0] = 0xa5u;
        }
        return fixture->get_status;
    }
    if (memcmp(
            profile_id->bytes, fixture->metadata.profile_id.bytes, 16u)
            != 0
        || revision != fixture->metadata.revision
        || memcmp(digest, fixture->metadata.digest, 32u) != 0) {
        return WIFI_NETCRED_PERMANENT;
    }
    *out_metadata = fixture->metadata;
    (void)memcpy(
        secret_buffer,
        fixture->secret,
        fixture->metadata.password_length);
    return WIFI_NETCRED_OK;
}

static void test_credential_release(
    void *user,
    const ninlil_id128_t *profile_id,
    uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES])
{
    credential_provider_fixture_t *fixture =
        (credential_provider_fixture_t *)user;
    fixture->release_calls += 1u;
    fixture->release_received_zero =
        memcmp(profile_id->bytes, fixture->metadata.profile_id.bytes, 16u) == 0
        && test_bytes_zero(secret_buffer, WIFI_NETCRED_SECRET_BYTES);
}

int main(void)
{
    ninlil_wifi_m4_owner_t m4_owner;
    ninlil_wifi_m4_owner_init(&m4_owner);

    ninlil_wifi_esp_owner_t owner;
    _Alignas(max_align_t) uint8_t tls_store[8192];
    _Alignas(max_align_t) uint8_t sta_store[NINLIL_WIFI_ESP_STA_STORAGE_BYTES];
    ninlil_wifi_esp_tls_t *tls;
    ninlil_wifi_esp_sta_t *sta;
    ninlil_wifi_esp_tls_pem_t pems;
    ninlil_wifi_esp_tls_identity_expectation_t tls_identity;
    ninlil_wifi_peer_context_inputs_t pin;
    ninlil_wifi_m4_full_evidence_t empty;
    uint32_t work = 0u;
    uint8_t nfl1[587];
    size_t nfl1_len = 0u;
    credential_provider_fixture_t credential_fixture;
    wifi_network_credential_provider_ops_v1_t credential_provider;
    failures = 0;

    CHECK(ninlil_wifi_esp_tls_sizeof() <= sizeof(tls_store));
    tls = (ninlil_wifi_esp_tls_t *)(void *)tls_store;
    sta = (ninlil_wifi_esp_sta_t *)(void *)sta_store;

    ninlil_wifi_esp_owner_init(&owner);
    ninlil_wifi_esp_owner_bind_tls(&owner, tls);
    pems.ca_pem = (const uint8_t *)"ca";
    pems.ca_pem_len = 2u;
    pems.cert_pem = (const uint8_t *)"cert";
    pems.cert_pem_len = 4u;
    pems.key_pem = (const uint8_t *)"key";
    pems.key_pem_len = 3u;
    CHECK(ninlil_wifi_esp_owner_configure_tls(&owner, 0, &pems)
        == NINLIL_WIFI_OK);

    CHECK(ninlil_wifi_esp_sta_init(sta) == NINLIL_WIFI_OK);
    ninlil_wifi_esp_owner_bind_sta(&owner, sta);
    {
        ninlil_wifi_esp_sta_config_t cfg;
        (void)memset(&credential_fixture, 0, sizeof(credential_fixture));
        credential_fixture.metadata.api_version =
            NINLIL_WIFI_PRIVATE_API_VERSION;
        credential_fixture.metadata.struct_size =
            (uint16_t)sizeof(credential_fixture.metadata);
        (void)memset(
            credential_fixture.metadata.profile_id.bytes, 0x11, 16u);
        credential_fixture.metadata.revision = 1u;
        (void)memset(
            credential_fixture.metadata.credential_binding_id.bytes,
            0x22,
            16u);
        credential_fixture.metadata.ssid_length = 4u;
        (void)memcpy(credential_fixture.metadata.ssid, "test", 4u);
        credential_fixture.metadata.auth_mode = WIFI_NETCRED_AUTH_WPA2_PSK;
        credential_fixture.metadata.password_length = 8u;
        credential_fixture.metadata.pmf_required = 1u;
        (void)memcpy(credential_fixture.secret, "password", 8u);
        test_profile_digest(
            &credential_fixture.metadata,
            credential_fixture.metadata.digest);
        (void)memset(&credential_provider, 0, sizeof(credential_provider));
        credential_provider.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
        credential_provider.struct_size =
            (uint16_t)sizeof(credential_provider);
        credential_provider.user = &credential_fixture;
        credential_provider.get = test_credential_get;
        credential_provider.release = test_credential_release;
        (void)memset(&cfg, 0, sizeof(cfg));
        cfg.network_profile_id = credential_fixture.metadata.profile_id;
        cfg.network_profile_revision = credential_fixture.metadata.revision;
        (void)memcpy(
            cfg.network_profile_digest,
            credential_fixture.metadata.digest,
            sizeof(cfg.network_profile_digest));
        cfg.credential_provider = &credential_provider;
        cfg.connect_timeout_ms = 0u;
        CHECK(ninlil_wifi_esp_sta_start(sta, &cfg) == NINLIL_WIFI_OK);
        CHECK(credential_fixture.get_calls == 1u);
        CHECK(credential_fixture.release_calls == 1u);
        CHECK(credential_fixture.release_received_zero == 1);

        /* Non-OK provider output must be all-zero; poison is CORRUPT. */
        credential_fixture.get_status = WIFI_NETCRED_TEMPORARY;
        credential_fixture.poison_non_ok = 1;
        CHECK(ninlil_wifi_esp_sta_start(sta, &cfg) == NINLIL_WIFI_CORRUPT);
        CHECK(credential_fixture.get_calls == 2u);
        CHECK(credential_fixture.release_calls == 1u);

        /* OK with malformed metadata releases exactly once after zeroization. */
        credential_fixture.get_status = WIFI_NETCRED_OK;
        credential_fixture.poison_non_ok = 0;
        credential_fixture.metadata.pmf_required = 0u;
        test_profile_digest(
            &credential_fixture.metadata,
            credential_fixture.metadata.digest);
        (void)memcpy(
            cfg.network_profile_digest,
            credential_fixture.metadata.digest,
            sizeof(cfg.network_profile_digest));
        CHECK(ninlil_wifi_esp_sta_start(sta, &cfg)
            == NINLIL_WIFI_CREDENTIAL);
        CHECK(credential_fixture.get_calls == 3u);
        CHECK(credential_fixture.release_calls == 2u);
        CHECK(credential_fixture.release_received_zero == 1);

        /* Blocking waits are rejected before a provider callback. */
        cfg.connect_timeout_ms = 1u;
        CHECK(ninlil_wifi_esp_sta_start(sta, &cfg)
            == NINLIL_WIFI_INVALID_ARGUMENT);
        CHECK(credential_fixture.get_calls == 3u);
    }
    CHECK(ninlil_wifi_esp_owner_step(&owner, 16u, &work) == NINLIL_WIFI_OK);
    CHECK(owner.got_ip == 1);

    (void)memset(&pin, 0, sizeof(pin));
    (void)memset(pin.authority_id, 0xd0, 16u);
    pin.authority_term = 7u;
    pin.assignment_epoch = 11u;
    (void)memset(pin.tls_client_runtime_id, 0x31, 16u);
    (void)memset(pin.tls_server_runtime_id, 0x32, 16u);
    CHECK(ninlil_wifi_esp_owner_set_peer_context_inputs(&owner, &pin)
        == NINLIL_WIFI_OK);
    (void)memset(&tls_identity, 0, sizeof(tls_identity));
    tls_identity.api_version =
        NINLIL_WIFI_ESP_TLS_IDENTITY_EXPECTATION_VERSION;
    tls_identity.struct_size = (uint16_t)sizeof(tls_identity);
    tls_identity.local_leaf.version = NINLIL_WIFI_LEAF_BINDING_VERSION;
    tls_identity.local_leaf.role = NINLIL_WIFI_LEAF_ROLE_CLIENT;
    (void)memcpy(
        tls_identity.local_leaf.runtime_id, pin.tls_client_runtime_id, 16u);
    (void)memset(
        tls_identity.local_leaf.authorized_attachment_binding_digest,
        0xa1,
        32u);
    (void)memcpy(
        tls_identity.local_leaf.authority_id, pin.authority_id, 16u);
    tls_identity.local_leaf.authority_term = pin.authority_term;
    tls_identity.local_leaf.credential_generation = 1u;
    tls_identity.local_leaf.revocation_generation = 1u;
    tls_identity.peer_leaf = tls_identity.local_leaf;
    tls_identity.peer_leaf.role = NINLIL_WIFI_LEAF_ROLE_SERVER;
    (void)memcpy(
        tls_identity.peer_leaf.runtime_id, pin.tls_server_runtime_id, 16u);
    CHECK(ninlil_wifi_esp_owner_set_tls_identity_expectation(
              &owner, &tls_identity)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_esp_tls_attach_fd(tls, 1) == NINLIL_WIFI_OK);
    owner.phase = NINLIL_WIFI_PHASE_HANDSHAKING;
    CHECK(ninlil_wifi_esp_owner_step(&owner, 4u, &work) == NINLIL_WIFI_OK);
    CHECK(owner.peer_session_valid == 1);

    CHECK(ninlil_wifi_m4_evidence_reset(&m4_owner, &empty) == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_esp_owner_accept_m4_full_evidence(&owner, &empty)
        == NINLIL_WIFI_OK);
    CHECK(owner.phase == NINLIL_WIFI_PHASE_PEER_SESSION);

    /* Free assertion denied. */
    {
        uint8_t a[16];
        uint8_t b[32];
        (void)memset(a, 1, sizeof(a));
        (void)memset(b, 2, sizeof(b));
        CHECK(ninlil_wifi_esp_owner_confirm_m4_pa_full(&owner, a, b)
            == NINLIL_WIFI_DENIED);
    }

    CHECK(ninlil_wifi_nfl1_min_encode(nfl1, sizeof(nfl1), &nfl1_len, 1u)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_esp_owner_send_payload(&owner, nfl1, (uint32_t)nfl1_len)
        == NINLIL_WIFI_INVALID_STATE);

    /* Callback side reports capacity; the sole owner step applies the fence. */
    ninlil_wifi_esp_owner_init(&owner);
    {
        uint32_t i;
        ninlil_wifi_status_t last = NINLIL_WIFI_OK;
        for (i = 0u; i < NINLIL_WIFI_ESP_EVENT_QUEUE_MAX + 2u; ++i) {
            last = ninlil_wifi_esp_owner_enqueue_event(
                &owner, NINLIL_WIFI_ESP_EV_STEP, 0u, 0u);
        }
        CHECK(last == NINLIL_WIFI_CAPACITY);
        CHECK(ninlil_wifi_esp_owner_step(&owner, 1u, &work)
            == NINLIL_WIFI_FENCED);
        CHECK(owner.phase == NINLIL_WIFI_PHASE_FENCED);
    }

    if (failures != 0) {
        (void)fprintf(stderr, "wifi_v1_esp_owner_sm_test FAIL %d\n", failures);
        return 1;
    }
    (void)printf("wifi_v1_esp_owner_sm_test PASS\n");
    return 0;
}
