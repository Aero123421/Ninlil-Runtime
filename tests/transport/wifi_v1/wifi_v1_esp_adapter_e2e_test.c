#define _POSIX_C_SOURCE 200112L

#include "wifi_adapter_v1.h"
#include "wifi_esp_sta.h"
#include "wifi_esp_tls_mbedtls.h"
#include "wifi_nfl1_min.h"
#include "wifi_sha256.h"

#include "in_memory_storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Minimal Fabric registry double for this Wi-Fi adapter test.  It exercises
 * the real wifi_fabric_register_v1()/unregister_* composition without pulling
 * Fabric core into the ESP-host adapter target.  Fabric's own lifecycle and
 * durable semantics remain covered by its dedicated suite.
 */
#if !defined(NINLIL_WIFI_ACTUAL_FABRIC_HELPERS_ONLY)
struct ninlil_fabric_link_registration_v1 {
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_packet_link_handle_t handle;
    struct ninlil_fabric_v1 *fabric;
    uint32_t active;
    uint32_t draining;
};

struct ninlil_fabric_v1 {
    struct ninlil_fabric_link_registration_v1 registration;
    ninlil_fabric_link_status_t precommit_start_status;
    ninlil_fabric_packet_token_t precommit_token;
};

ninlil_fabric_private_status_t ninlil_fabric_private_register_link_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_registration_private_t **out_registration)
{
    ninlil_fabric_link_state_v1_t state;
    ninlil_fabric_packet_view_v1_t packet;
    uint8_t byte = 0u;
    if (out_registration != NULL) {
        *out_registration = NULL;
    }
    if (fabric == NULL || descriptor == NULL || ops == NULL
        || out_registration == NULL || fabric->registration.active) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    (void)memset(&fabric->registration, 0, sizeof(fabric->registration));
    fabric->registration.ops = *ops;
    if (ops->open(
            ops->user, &fabric->registration.handle)
        != NINLIL_FABRIC_LINK_OK
        || fabric->registration.handle == NULL) {
        return NINLIL_FABRIC_PRIVATE_UNAVAILABLE;
    }
    (void)memset(&state, 0, sizeof(state));
    if (ops->state(
            ops->user, fabric->registration.handle, &state)
            != NINLIL_FABRIC_LINK_OK
        || state.availability_epoch == 0u) {
        ops->close(ops->user, fabric->registration.handle);
        fabric->registration.handle = NULL;
        return NINLIL_FABRIC_PRIVATE_CORRUPT;
    }
    /*
     * Fabric registration has opened the provider, but adapter commit has not
     * happened yet.  New TX must still be exact DENIED/TX0.
     */
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = 1u;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = &byte;
    packet.length = 1u;
    fabric->precommit_token =
        (ninlil_fabric_packet_token_t)(uintptr_t)1u;
    fabric->precommit_start_status = ops->start_send(
        ops->user,
        fabric->registration.handle,
        &packet,
        &fabric->precommit_token);
    fabric->registration.fabric = fabric;
    fabric->registration.active = 1u;
    *out_registration = &fabric->registration;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_unregister_begin_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration)
{
    if (fabric == NULL || registration == NULL
        || registration != &fabric->registration
        || !registration->active || registration->draining) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    registration->draining = 1u;
    return NINLIL_FABRIC_PRIVATE_OK;
}

ninlil_fabric_private_status_t ninlil_fabric_private_unregister_poll_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration,
    uint32_t *out_done)
{
    if (out_done != NULL) {
        *out_done = 0u;
    }
    if (fabric == NULL || registration == NULL || out_done == NULL
        || registration != &fabric->registration
        || !registration->active || !registration->draining) {
        return NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT;
    }
    registration->ops.close(
        registration->ops.user, registration->handle);
    registration->handle = NULL;
    registration->active = 0u;
    registration->draining = 0u;
    *out_done = 1u;
    return NINLIL_FABRIC_PRIVATE_OK;
}
#endif

static int failures;
#define CHECK(condition_)                                                      \
    do {                                                                       \
        if (!(condition_)) {                                                   \
            (void)fprintf(                                                     \
                stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #condition_);  \
            failures += 1;                                                     \
        }                                                                      \
    } while (0)

typedef struct network_fixture {
    wifi_network_credential_metadata_v1_t metadata;
    uint8_t secret[WIFI_NETCRED_SECRET_BYTES];
    uint32_t get_calls;
    uint32_t release_calls;
} network_fixture_t;

typedef struct clock_fixture {
    uint64_t now_ms;
    uint8_t epoch[16];
} clock_fixture_t;

typedef struct m4_fixture {
    ninlil_wifi_m4_owner_t owner;
    const ninlil_storage_ops_t *storage;
    void *storage_user;
    const char *path;
    const wifi_adapter_config_v1_t *config;
    uint8_t local_runtime[16];
    uint8_t authority[16];
    uint8_t binding[32];
    uint8_t credential[32];
    uint8_t fabric_descriptor[32];
    uint8_t clock_epoch[16];
    uint8_t registry_epoch[16];
} m4_fixture_t;

typedef struct side {
    wifi_adapter_config_v1_t config;
    wifi_esp_session_provision_v1_t provision;
    wifi_m4_attachment_carrier_ops_v1_t carrier_ops;
    m4_fixture_t carrier;
    _Alignas(max_align_t) uint8_t tls_storage[8192];
    _Alignas(max_align_t)
        uint8_t sta_storage[NINLIL_WIFI_ESP_STA_STORAGE_BYTES];
    void *adapter_workspace;
    uint32_t adapter_workspace_bytes;
    wifi_adapter_private_v1_t *adapter;
} side_t;

static void put_u16_be(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void put_u32_be(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void put_u64_be(uint8_t *p, uint64_t value)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[7u - i] = (uint8_t)(value >> (8u * i));
    }
}

static void network_digest(
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
    put_u64_be(canonical + n, metadata->revision);
    n += 8u;
    n += 32u;
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
}

static void config_digest(
    const wifi_adapter_config_v1_t *config,
    uint8_t out[32])
{
    static const uint8_t tag[] = "NINLIL-WIFI-ADAPTER-CONFIG-V1";
    uint8_t canonical[256];
    size_t n = 0u;
    (void)memset(canonical, 0, sizeof(canonical));
    (void)memcpy(canonical + n, tag, sizeof(tag) - 1u);
    n += sizeof(tag) - 1u;
    put_u32_be(canonical + n, config->adapter_kind);
    n += 4u;
    put_u32_be(canonical + n, config->tls_role);
    n += 4u;
    (void)memcpy(canonical + n, config->instance_id.bytes, 16u);
    n += 16u;
    put_u64_be(canonical + n, config->configuration_revision);
    n += 8u;
    n += 32u;
    (void)memcpy(canonical + n, config->local_runtime_id.bytes, 16u);
    n += 16u;
    (void)memcpy(
        canonical + n, config->expected_peer_runtime_id.bytes, 16u);
    n += 16u;
    put_u32_be(canonical + n, config->endpoint_address_kind);
    n += 4u;
    (void)memcpy(canonical + n, config->endpoint_address, 16u);
    n += 16u;
    put_u16_be(canonical + n, config->endpoint_port);
    n += 2u;
    put_u16_be(canonical + n, config->reserved_zero_u16);
    n += 2u;
    (void)memcpy(canonical + n, config->network_profile_id.bytes, 16u);
    n += 16u;
    put_u64_be(canonical + n, config->network_profile_revision);
    n += 8u;
    (void)memcpy(canonical + n, config->network_profile_digest, 32u);
    n += 32u;
    put_u32_be(canonical + n, config->reconnect_profile_id);
    n += 4u;
    put_u32_be(canonical + n, config->reserved_zero_u32);
    n += 4u;
    ninlil_wifi_sha256(canonical, n, out);
}

static void provision_digest(
    const wifi_esp_session_provision_v1_t *provision,
    uint8_t out[32])
{
    static const uint8_t tag[] = "NINLIL-WIFI-ESP-PROVISION-V1";
    uint8_t canonical[384];
    uint8_t local_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    uint8_t peer_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    uint8_t peer_context[NINLIL_WIFI_PEER_CONTEXT_BYTES];
    size_t n = 0u;
    CHECK(ninlil_wifi_leaf_binding_encode(
              &provision->tls_identity.local_leaf, local_wire)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_leaf_binding_encode(
              &provision->tls_identity.peer_leaf, peer_wire)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_build_peer_context(
              &provision->peer_context, peer_context)
        == NINLIL_WIFI_OK);
    (void)memset(canonical, 0, sizeof(canonical));
    (void)memcpy(canonical + n, tag, sizeof(tag) - 1u);
    n += sizeof(tag) - 1u;
    put_u16_be(canonical + n, provision->api_version);
    n += 2u;
    put_u16_be(canonical + n, provision->struct_size);
    n += 2u;
    put_u32_be(canonical + n, provision->tls_workspace_bytes);
    n += 4u;
    put_u32_be(canonical + n, provision->sta_workspace_bytes);
    n += 4u;
    (void)memcpy(canonical + n, local_wire, sizeof(local_wire));
    n += sizeof(local_wire);
    (void)memcpy(canonical + n, peer_wire, sizeof(peer_wire));
    n += sizeof(peer_wire);
    (void)memcpy(canonical + n, peer_context, sizeof(peer_context));
    n += sizeof(peer_context);
    (void)memcpy(
        canonical + n, provision->expected_fabric_descriptor, 32u);
    n += 32u;
    n += 32u;
    (void)memcpy(canonical + n, provision->reserved_zero, 8u);
    n += 8u;
    ninlil_wifi_sha256(canonical, n, out);
}

static wifi_network_credential_status_v1_t network_get(
    void *opaque,
    const ninlil_id128_t *profile_id,
    uint64_t revision,
    const uint8_t digest[32],
    wifi_network_credential_metadata_v1_t *out_metadata,
    uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES])
{
    network_fixture_t *fixture = (network_fixture_t *)opaque;
    fixture->get_calls += 1u;
    (void)memset(out_metadata, 0, sizeof(*out_metadata));
    (void)memset(secret_buffer, 0, WIFI_NETCRED_SECRET_BYTES);
    if (memcmp(profile_id->bytes, fixture->metadata.profile_id.bytes, 16u) != 0
        || revision != fixture->metadata.revision
        || memcmp(digest, fixture->metadata.digest, 32u) != 0) {
        return WIFI_NETCRED_NOT_FOUND;
    }
    *out_metadata = fixture->metadata;
    (void)memcpy(
        secret_buffer, fixture->secret, fixture->metadata.password_length);
    return WIFI_NETCRED_OK;
}

static void network_release(
    void *opaque,
    const ninlil_id128_t *profile_id,
    uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES])
{
    network_fixture_t *fixture = (network_fixture_t *)opaque;
    (void)profile_id;
    fixture->release_calls += 1u;
    CHECK(memcmp(
              secret_buffer,
              (const uint8_t[WIFI_NETCRED_SECRET_BYTES]){0},
              WIFI_NETCRED_SECRET_BYTES)
        == 0);
}

static uint64_t current_context(void *opaque)
{
    (void)opaque;
    return 1u;
}

static ninlil_port_status_t clock_now(
    void *opaque,
    ninlil_time_sample_t *out)
{
    clock_fixture_t *clock = (clock_fixture_t *)opaque;
    if (clock == NULL || out == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    (void)memset(out, 0, sizeof(*out));
    out->abi_version = NINLIL_ABI_VERSION;
    out->struct_size = (uint16_t)sizeof(*out);
    (void)memcpy(out->clock_epoch_id.bytes, clock->epoch, 16u);
    out->now_ms = clock->now_ms;
    out->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static wifi_private_adapter_status_v1_t m4_poll_full(
    void *opaque,
    const uint8_t peer_session_id[16],
    uint64_t trusted_now_ms,
    ninlil_wifi_m4_full_evidence_t *out_evidence,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor)
{
    m4_fixture_t *fixture = (m4_fixture_t *)opaque;
    ninlil_wifi_m4_membership_lease_t lease;
    ninlil_wifi_m4_fabric_registry_t registry;
    if (fixture == NULL || peer_session_id == NULL || out_evidence == NULL
        || out_descriptor == NULL) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    (void)memset(&lease, 0, sizeof(lease));
    /*
     * M4 membership is bound to the live peer-session capability, not to the
     * long-lived local runtime identifier.
     */
    (void)memcpy(lease.member_runtime_id, peer_session_id, 16u);
    lease.lease_not_before_ms = 1u;
    lease.lease_not_after_ms = trusted_now_ms + 100000u;
    (void)memcpy(lease.authority_id, fixture->authority, 16u);
    (void)memcpy(lease.binding_digest, fixture->binding, 32u);
    if (ninlil_wifi_m4_membership_store_full(
            fixture->storage,
            fixture->storage_user,
            fixture->path,
            &lease)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_credential_store_full(
               fixture->storage,
               fixture->storage_user,
               fixture->path,
               fixture->credential,
               1u)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_attachment_store_full(
               fixture->storage,
               fixture->storage_user,
               fixture->path,
               peer_session_id,
               fixture->authority,
               fixture->binding,
               fixture->credential,
               fixture->fabric_descriptor)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_reset(
               &fixture->owner, out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_membership_load_classify(
               &fixture->owner,
               fixture->storage,
               fixture->storage_user,
               fixture->path,
               trusted_now_ms,
               out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_credential_load_classify(
               &fixture->owner,
               fixture->storage,
               fixture->storage_user,
               fixture->path,
               out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_attachment_load_classify(
               &fixture->owner,
               fixture->storage,
               fixture->storage_user,
               fixture->path,
               peer_session_id,
               out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_fabric_registry_bind(
               &registry,
               fixture->fabric_descriptor,
               fixture->authority,
               fixture->registry_epoch)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_apply_fabric_registry(
               out_evidence, &registry)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_mark_session_authority(out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_ready_for_attach(out_evidence)
            != NINLIL_WIFI_OK) {
        ninlil_wifi_m4_evidence_consume(out_evidence);
        return WIFI_PRIVATE_DENIED;
    }
    (void)memset(out_descriptor, 0, sizeof(*out_descriptor));
    out_descriptor->api_version = 1u;
    out_descriptor->struct_size = (uint16_t)sizeof(*out_descriptor);
    out_descriptor->instance_id = fixture->config->instance_id;
    out_descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    out_descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    out_descriptor->capability_flags =
        NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE | NINLIL_FABRIC_CAP_UNICAST
        | NINLIL_FABRIC_CAP_RESERVATION;
    out_descriptor->descriptor_revision = 1u;
    (void)memcpy(
        out_descriptor->descriptor_digest,
        fixture->fabric_descriptor,
        32u);
    (void)memset(out_descriptor->security_profile_id.bytes, 0x55, 16u);
    out_descriptor->security_capability_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    (void)memset(out_descriptor->security_binding_digest, 0x66, 32u);
    out_descriptor->attestation_epoch = 1u;
    (void)memcpy(
        out_descriptor->attestation_clock_epoch_id.bytes,
        fixture->clock_epoch,
        16u);
    out_descriptor->attestation_expires_at_ms = trusted_now_ms + 100000u;
    (void)memset(out_descriptor->attestation_digest, 0x77, 32u);
    out_descriptor->authenticated_peer_runtime_id =
        fixture->config->expected_peer_runtime_id;
    (void)memcpy(
        out_descriptor->attachment_authority_id.bytes,
        fixture->authority,
        16u);
    (void)memcpy(
        out_descriptor->attachment_binding_digest, fixture->binding, 32u);
    out_descriptor->maximum_packet_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    out_descriptor->maximum_transfer_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    out_descriptor->latency_class = 1u;
    out_descriptor->cost_class = 1u;
    out_descriptor->reservation_capacity = 1u;
    out_descriptor->peer_nfl1_version = 1u;
    out_descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    out_descriptor->configuration_revision =
        fixture->config->configuration_revision;
    (void)memcpy(
        out_descriptor->configuration_digest,
        fixture->config->configuration_digest,
        32u);
    return WIFI_PRIVATE_OK;
}

static uint16_t free_loopback_port(void)
{
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    uint16_t port = 0u;
    if (fd < 0) {
        return 0u;
    }
    (void)memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(UINT32_C(0x7f000001));
    address.sin_port = 0;
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) == 0
        && getsockname(fd, (struct sockaddr *)&address, &length) == 0) {
        port = ntohs(address.sin_port);
    }
    (void)close(fd);
    return port;
}

static ninlil_wifi_leaf_binding_t make_leaf(
    uint8_t role,
    uint8_t runtime,
    const uint8_t authority[16],
    const uint8_t binding[32])
{
    ninlil_wifi_leaf_binding_t leaf;
    (void)memset(&leaf, 0, sizeof(leaf));
    leaf.version = NINLIL_WIFI_LEAF_BINDING_VERSION;
    leaf.role = role;
    (void)memset(leaf.runtime_id, runtime, 16u);
    (void)memcpy(leaf.authorized_attachment_binding_digest, binding, 32u);
    (void)memcpy(leaf.authority_id, authority, 16u);
    leaf.authority_term = 7u;
    leaf.credential_generation = 3u;
    leaf.revocation_generation = 5u;
    return leaf;
}

static void setup_side(
    side_t *side,
    int is_server,
    uint16_t port,
    const ninlil_wifi_leaf_binding_t *client_leaf,
    const ninlil_wifi_leaf_binding_t *server_leaf,
    const wifi_network_credential_provider_ops_v1_t *network_ops,
    const ninlil_storage_ops_t *storage,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    const char *m4_path,
    uint8_t instance_byte,
    uint8_t fabric_byte,
    const uint8_t credential[32],
    const uint8_t registry_epoch[16])
{
    uint32_t alignment = 0u;
    (void)memset(side, 0, sizeof(*side));
    side->provision.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    side->provision.struct_size = (uint16_t)sizeof(side->provision);
    side->provision.tls_workspace = side->tls_storage;
    side->provision.tls_workspace_bytes = sizeof(side->tls_storage);
    side->provision.sta_workspace = side->sta_storage;
    side->provision.sta_workspace_bytes = sizeof(side->sta_storage);
    side->provision.tls_pems.ca_pem = (const uint8_t *)"ca";
    side->provision.tls_pems.ca_pem_len = 2u;
    side->provision.tls_pems.cert_pem = (const uint8_t *)"cert";
    side->provision.tls_pems.cert_pem_len = 4u;
    side->provision.tls_pems.key_pem = (const uint8_t *)"key";
    side->provision.tls_pems.key_pem_len = 3u;
    side->provision.tls_identity.api_version =
        NINLIL_WIFI_ESP_TLS_IDENTITY_EXPECTATION_VERSION;
    side->provision.tls_identity.struct_size =
        (uint16_t)sizeof(side->provision.tls_identity);
    side->provision.tls_identity.local_leaf =
        is_server ? *server_leaf : *client_leaf;
    side->provision.tls_identity.peer_leaf =
        is_server ? *client_leaf : *server_leaf;
    (void)memcpy(
        side->provision.peer_context.authority_id,
        client_leaf->authority_id,
        16u);
    side->provision.peer_context.authority_term =
        client_leaf->authority_term;
    side->provision.peer_context.assignment_epoch = 11u;
    (void)memcpy(
        side->provision.peer_context.tls_client_runtime_id,
        client_leaf->runtime_id,
        16u);
    (void)memcpy(
        side->provision.peer_context.tls_server_runtime_id,
        server_leaf->runtime_id,
        16u);
    (void)memset(
        side->provision.expected_fabric_descriptor, fabric_byte, 32u);
    provision_digest(
        &side->provision, side->provision.provision_digest);

    side->carrier_ops.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    side->carrier_ops.struct_size = (uint16_t)sizeof(side->carrier_ops);
    side->carrier_ops.user = &side->carrier;
    side->carrier_ops.poll_full = m4_poll_full;

    side->config.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    side->config.struct_size = (uint16_t)sizeof(side->config);
    side->config.adapter_kind = WIFI_ADAPTER_KIND_ESP32S3_STA_TCP;
    side->config.tls_role =
        is_server ? WIFI_TLS_ROLE_SERVER : WIFI_TLS_ROLE_CLIENT;
    (void)memset(side->config.instance_id.bytes, instance_byte, 16u);
    side->config.configuration_revision = 1u;
    (void)memcpy(
        side->config.local_runtime_id.bytes,
        is_server ? server_leaf->runtime_id : client_leaf->runtime_id,
        16u);
    (void)memcpy(
        side->config.expected_peer_runtime_id.bytes,
        is_server ? client_leaf->runtime_id : server_leaf->runtime_id,
        16u);
    side->config.endpoint_address_kind =
        is_server ? WIFI_ENDPOINT_LOCAL_ANY : WIFI_ENDPOINT_IPV4;
    if (!is_server) {
        side->config.endpoint_address[0] = 127u;
        side->config.endpoint_address[3] = 1u;
    }
    side->config.endpoint_port = port;
    (void)memset(side->config.network_profile_id.bytes, 0x11, 16u);
    side->config.network_profile_revision = 1u;
    (void)memcpy(
        side->config.network_profile_digest,
        ((network_fixture_t *)network_ops->user)->metadata.digest,
        32u);
    side->config.reconnect_profile_id = WIFI_RECONNECT_PROFILE_1;
    side->config.storage = storage;
    side->config.clock = clock;
    side->config.execution = execution;
    side->config.network_credential_provider = network_ops;
    side->config.m4_attachment_carrier_ops = &side->carrier_ops;
    side->config.esp_session_provision = &side->provision;
    config_digest(&side->config, side->config.configuration_digest);

    ninlil_wifi_m4_owner_init(&side->carrier.owner);
    side->carrier.storage = storage;
    side->carrier.storage_user = storage->user;
    side->carrier.path = m4_path;
    side->carrier.config = &side->config;
    (void)memcpy(
        side->carrier.local_runtime,
        side->config.local_runtime_id.bytes,
        16u);
    (void)memcpy(
        side->carrier.authority, client_leaf->authority_id, 16u);
    (void)memcpy(
        side->carrier.binding,
        client_leaf->authorized_attachment_binding_digest,
        32u);
    (void)memcpy(side->carrier.credential, credential, 32u);
    (void)memset(side->carrier.fabric_descriptor, fabric_byte, 32u);
    (void)memcpy(
        side->carrier.clock_epoch,
        ((clock_fixture_t *)clock->user)->epoch,
        16u);
    (void)memcpy(
        side->carrier.registry_epoch, registry_epoch, 16u);

    CHECK(wifi_workspace_required_v1(
              WIFI_ADAPTER_KIND_ESP32S3_STA_TCP,
              &side->adapter_workspace_bytes,
              &alignment)
        == WIFI_PRIVATE_OK);
    CHECK(posix_memalign(
              &side->adapter_workspace,
              alignment,
              side->adapter_workspace_bytes)
        == 0);
    CHECK(wifi_create_v1(
              &side->config,
              side->adapter_workspace,
              side->adapter_workspace_bytes,
              &side->adapter)
        == WIFI_PRIVATE_OK);
}

#if !defined(NINLIL_WIFI_ACTUAL_FABRIC_HELPERS_ONLY)
int main(void)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_storage_t *storage_fixture;
    const ninlil_storage_ops_t *storage;
    network_fixture_t network;
    wifi_network_credential_provider_ops_v1_t network_ops;
    clock_fixture_t clock_fixture;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_wifi_leaf_binding_t client_leaf;
    ninlil_wifi_leaf_binding_t server_leaf;
    uint8_t authority[16];
    uint8_t binding[32];
    uint8_t credential[32];
    uint8_t registry_epoch[16];
    side_t server;
    side_t client;
    uint16_t port;
    uint32_t i;
    wifi_operational_state_v1_t client_state = 0u;
    wifi_operational_state_v1_t server_state = 0u;
    uint32_t reason;
    uint64_t epoch;
    const ninlil_fabric_packet_link_ops_v1_t *client_ops = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *server_ops = NULL;
    const ninlil_fabric_link_descriptor_v1_t *descriptor = NULL;
    ninlil_fabric_private_t client_fabric;
    ninlil_fabric_private_t server_fabric;
    ninlil_fabric_private_t other_fabric;
    ninlil_fabric_registration_private_t *client_registration = NULL;
    ninlil_fabric_registration_private_t *server_registration = NULL;
    ninlil_fabric_packet_link_ops_v1_t client_registered_ops;
    ninlil_fabric_packet_link_ops_v1_t server_registered_ops;
    ninlil_fabric_packet_link_handle_t client_handle = NULL;
    ninlil_fabric_packet_link_handle_t server_handle = NULL;
    ninlil_fabric_packet_view_v1_t packet;
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    uint8_t nfl1[NINLIL_WIFI_NWB1_PAYLOAD_MIN];
    size_t nfl1_length = 0u;
    const uint8_t *received = NULL;
    uint32_t received_length = 0u;
    void *receive_token = NULL;
    failures = 0;
    (void)memset(&client_fabric, 0, sizeof(client_fabric));
    (void)memset(&server_fabric, 0, sizeof(server_fabric));
    (void)memset(&other_fabric, 0, sizeof(other_fabric));
    (void)memset(&client_registered_ops, 0, sizeof(client_registered_ops));
    (void)memset(&server_registered_ops, 0, sizeof(server_registered_ops));

    (void)memset(authority, 0xd0, sizeof(authority));
    (void)memset(binding, 0xa1, sizeof(binding));
    (void)memset(credential, 0xc1, sizeof(credential));
    (void)memset(registry_epoch, 0xe1, sizeof(registry_epoch));
    client_leaf = make_leaf(
        NINLIL_WIFI_LEAF_ROLE_CLIENT, 0x31, authority, binding);
    server_leaf = make_leaf(
        NINLIL_WIFI_LEAF_ROLE_SERVER, 0x32, authority, binding);

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 8u;
    storage_config.max_entries_per_namespace = 32u;
    storage_config.max_bytes_per_namespace = 65536u;
    storage_fixture = ninlil_test_storage_create(&storage_config);
    CHECK(storage_fixture != NULL);
    storage = ninlil_test_storage_ops(storage_fixture);

    (void)memset(&network, 0, sizeof(network));
    network.metadata.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    network.metadata.struct_size = (uint16_t)sizeof(network.metadata);
    (void)memset(network.metadata.profile_id.bytes, 0x11, 16u);
    network.metadata.revision = 1u;
    (void)memset(network.metadata.credential_binding_id.bytes, 0x22, 16u);
    network.metadata.ssid_length = 4u;
    (void)memcpy(network.metadata.ssid, "test", 4u);
    network.metadata.auth_mode = WIFI_NETCRED_AUTH_WPA2_PSK;
    network.metadata.password_length = 8u;
    network.metadata.pmf_required = 1u;
    (void)memcpy(network.secret, "password", 8u);
    network_digest(&network.metadata, network.metadata.digest);
    (void)memset(&network_ops, 0, sizeof(network_ops));
    network_ops.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    network_ops.struct_size = (uint16_t)sizeof(network_ops);
    network_ops.user = &network;
    network_ops.get = network_get;
    network_ops.release = network_release;

    (void)memset(&clock_fixture, 0, sizeof(clock_fixture));
    clock_fixture.now_ms = 5000u;
    (void)memset(clock_fixture.epoch, 0xe2, 16u);
    (void)memset(&clock, 0, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.user = &clock_fixture;
    clock.now = clock_now;
    (void)memset(&execution, 0, sizeof(execution));
    execution.abi_version = NINLIL_ABI_VERSION;
    execution.struct_size = (uint16_t)sizeof(execution);
    execution.current_context_id = current_context;

    port = free_loopback_port();
    CHECK(port != 0u);
    setup_side(
        &server,
        1,
        port,
        &client_leaf,
        &server_leaf,
        &network_ops,
        storage,
        &clock,
        &execution,
        "m4-server",
        0x41,
        0xf1,
        credential,
        registry_epoch);
    setup_side(
        &client,
        0,
        port,
        &client_leaf,
        &server_leaf,
        &network_ops,
        storage,
        &clock,
        &execution,
        "m4-client",
        0x42,
        0xf2,
        credential,
        registry_epoch);
    CHECK(server.adapter != NULL && client.adapter != NULL);
    ninlil_wifi_esp_tls_host_pair(
        (ninlil_wifi_esp_tls_t *)(void *)server.tls_storage,
        (ninlil_wifi_esp_tls_t *)(void *)client.tls_storage);

    for (i = 0u; i < 10000u; ++i) {
        uint32_t work = 0u;
        wifi_private_adapter_status_v1_t server_step =
            wifi_step_v1(server.adapter, 16u, &work);
        wifi_private_adapter_status_v1_t client_step =
            wifi_step_v1(client.adapter, 16u, &work);
        CHECK(wifi_state_v1(
                  server.adapter, &server_state, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        CHECK(wifi_state_v1(
                  client.adapter, &client_state, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        if (server_step != WIFI_PRIVATE_OK
            || client_step != WIFI_PRIVATE_OK) {
            (void)fprintf(
                stderr,
                "adapter step failed: iteration=%u server_status=%u "
                "server_state=%u client_status=%u client_state=%u\n",
                (unsigned)i,
                (unsigned)server_step,
                (unsigned)server_state,
                (unsigned)client_step,
                (unsigned)client_state);
            CHECK(server_step == WIFI_PRIVATE_OK);
            CHECK(client_step == WIFI_PRIVATE_OK);
            break;
        }
        if (server_state == WIFI_OPERATIONAL_ATTACHED
            && client_state == WIFI_OPERATIONAL_ATTACHED) {
            break;
        }
    }
    CHECK(server_state == WIFI_OPERATIONAL_ATTACHED);
    CHECK(client_state == WIFI_OPERATIONAL_ATTACHED);
    CHECK(network.get_calls == 2u);
    CHECK(network.release_calls == 2u);

    CHECK(wifi_packet_link_descriptor_v1(client.adapter, &descriptor)
        == WIFI_PRIVATE_OK);
    CHECK(descriptor != NULL
        && descriptor->link_kind == NINLIL_FABRIC_LINK_KIND_WIFI);
    CHECK(wifi_packet_link_ops_v1(client.adapter, &client_ops)
        == WIFI_PRIVATE_OK);
    CHECK(wifi_packet_link_ops_v1(server.adapter, &server_ops)
        == WIFI_PRIVATE_OK);
    CHECK(client_ops != NULL && server_ops != NULL);

    /* Standalone access is never an outer durable-permit authority. */
    CHECK(client_ops->open(client_ops->user, &client_handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(client_handle == NULL);
    CHECK(server_ops->open(server_ops->user, &server_handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(server_handle == NULL);
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = 1u;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = nfl1;
    packet.length = 1u;
    token = (ninlil_fabric_packet_token_t)(uintptr_t)1u;
    CHECK(client_ops->start_send(
              client_ops->user,
              (ninlil_fabric_packet_link_handle_t)(uintptr_t)1u,
              &packet,
              &token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);

    /* Exact production adapter -> Fabric registration path. */
    CHECK(wifi_fabric_register_v1(
              client.adapter, &client_fabric, &client_registration)
        == WIFI_PRIVATE_OK);
    CHECK(wifi_fabric_register_v1(
              server.adapter, &server_fabric, &server_registration)
        == WIFI_PRIVATE_OK);
    CHECK(client_registration != NULL && server_registration != NULL);
    CHECK(client_fabric.precommit_start_status
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(client_fabric.precommit_token == NULL);
    CHECK(server_fabric.precommit_start_status
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(server_fabric.precommit_token == NULL);
    client_registered_ops = client_registration->ops;
    server_registered_ops = server_registration->ops;
    client_handle = client_registration->handle;
    server_handle = server_registration->handle;
    CHECK(client_handle != NULL && server_handle != NULL);

    /* One adapter cannot be rebound under a different Fabric cookie. */
    {
        ninlil_fabric_registration_private_t *other_registration =
            (ninlil_fabric_registration_private_t *)(uintptr_t)1u;
        CHECK(wifi_fabric_register_v1(
                  client.adapter, &other_fabric, &other_registration)
            == WIFI_PRIVATE_DENIED);
        CHECK(other_registration == NULL);
    }

    CHECK(ninlil_wifi_nfl1_min_encode(
              nfl1, sizeof(nfl1), &nfl1_length, 0x1234u)
        == NINLIL_WIFI_OK);
    (void)memset(&permit, 0, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    (void)memset(permit.permit_id.bytes, 0x91, 16u);
    (void)memset(permit.attempt_id.bytes, 0x92, 16u);
    (void)memcpy(
        permit.clock_epoch_id.bytes, clock_fixture.epoch, 16u);
    permit.expires_at_ms = clock_fixture.now_ms + 10000u;
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = 1u;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = nfl1;
    packet.length = (uint32_t)nfl1_length;
    packet.attempt_id = permit.attempt_id;

    /* The cached standalone table stays denied after registration. */
    packet.permit = &permit;
    CHECK(client_ops->start_send(
              client_ops->user, client_handle, &packet, &token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);
    packet.permit = NULL;
    CHECK(client_registered_ops.start_send(
              client_registered_ops.user,
              client_handle,
              &packet,
              &token)
        == NINLIL_FABRIC_LINK_DENIED);
    packet.permit = &permit;
    CHECK(client_registered_ops.start_send(
              client_registered_ops.user,
              client_handle,
              &packet,
              &token)
        == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(token != NULL);

    (void)memset(&completion, 0, sizeof(completion));
    for (i = 0u; i < 1000u; ++i) {
        CHECK(client_registered_ops.poll_send(
                  client_registered_ops.user,
                  client_handle,
                  token,
                  &completion)
            == NINLIL_FABRIC_LINK_OK);
        if (completion.kind
            == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE) {
            break;
        }
    }
    CHECK(completion.kind
        == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
    for (i = 0u; i < 1000u; ++i) {
        ninlil_fabric_link_status_t receive_status =
            server_registered_ops.receive_next(
                server_registered_ops.user,
                server_handle,
                &received,
                &received_length,
                &receive_token);
        if (receive_status == NINLIL_FABRIC_LINK_OK) {
            break;
        }
        CHECK(receive_status == NINLIL_FABRIC_LINK_EMPTY);
    }
    CHECK(received != NULL);
    CHECK(received_length == nfl1_length);
    CHECK(memcmp(received, nfl1, nfl1_length) == 0);
    server_registered_ops.release_received(
        server_registered_ops.user, server_handle, receive_token);
    client_registered_ops.release_send(
        client_registered_ops.user, client_handle, token);

    CHECK(wifi_fabric_unregister_begin_v1(
              client.adapter, &other_fabric, client_registration)
        == WIFI_PRIVATE_DENIED);
    CHECK(wifi_fabric_unregister_begin_v1(
              client.adapter, &client_fabric, client_registration)
        == WIFI_PRIVATE_OK);
    CHECK(wifi_fabric_unregister_begin_v1(
              server.adapter, &server_fabric, server_registration)
        == WIFI_PRIVATE_OK);
    {
        uint32_t done = 0u;
        CHECK(wifi_fabric_unregister_poll_v1(
                  client.adapter,
                  &client_fabric,
                  client_registration,
                  &done)
            == WIFI_PRIVATE_OK);
        CHECK(done == 1u);
    }
    {
        uint32_t done = 0u;
        CHECK(wifi_fabric_unregister_poll_v1(
                  server.adapter,
                  &server_fabric,
                  server_registration,
                  &done)
            == WIFI_PRIVATE_OK);
        CHECK(done == 1u);
    }

    /* Old authorized ops copy is generation-fenced after unregister. */
    token = NULL;
    CHECK(client_registered_ops.start_send(
              client_registered_ops.user,
              client_handle,
              &packet,
              &token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(token == NULL);
    CHECK(client_registered_ops.open(
              client_registered_ops.user, &client_handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(client_handle == NULL);

    /*
     * Re-registration uses a fresh immutable scope.  Reusing the adapter or a
     * same-address Fabric cookie can never revive the old copied ops table.
     */
    {
        ninlil_fabric_registration_private_t *next_registration = NULL;
        ninlil_fabric_packet_link_handle_t stale_handle = NULL;
        uint32_t done = 0u;
        CHECK(wifi_fabric_register_v1(
                  client.adapter, &other_fabric, &next_registration)
            == WIFI_PRIVATE_OK);
        CHECK(next_registration != NULL);
        CHECK(client_registered_ops.open(
                  client_registered_ops.user, &stale_handle)
            == NINLIL_FABRIC_LINK_DENIED);
        CHECK(stale_handle == NULL);
        CHECK(wifi_fabric_unregister_begin_v1(
                  client.adapter, &other_fabric, next_registration)
            == WIFI_PRIVATE_OK);
        CHECK(wifi_fabric_unregister_poll_v1(
                  client.adapter,
                  &other_fabric,
                  next_registration,
                  &done)
            == WIFI_PRIVATE_OK);
        CHECK(done == 1u);
    }

    /* The production wrapper rejects a consumed registration relationship. */
    {
        uint32_t done = 99u;
        CHECK(wifi_fabric_unregister_poll_v1(
                  client.adapter,
                  &client_fabric,
                  client_registration,
                  &done)
            == WIFI_PRIVATE_DENIED);
        CHECK(done == 0u);
    }

    CHECK(wifi_drain_begin_v1(client.adapter) == WIFI_PRIVATE_OK);
    CHECK(wifi_drain_begin_v1(server.adapter) == WIFI_PRIVATE_OK);
    for (i = 0u; i < 16u; ++i) {
        uint32_t work = 0u;
        uint32_t done_client = 0u;
        uint32_t done_server = 0u;
        CHECK(wifi_step_v1(client.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(server.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_drain_poll_v1(client.adapter, &done_client)
            == WIFI_PRIVATE_OK);
        CHECK(wifi_drain_poll_v1(server.adapter, &done_server)
            == WIFI_PRIVATE_OK);
        if (done_client && done_server) {
            break;
        }
    }
    CHECK(wifi_destroy_v1(client.adapter) == WIFI_PRIVATE_OK);
    CHECK(wifi_destroy_v1(server.adapter) == WIFI_PRIVATE_OK);
    free(client.adapter_workspace);
    free(server.adapter_workspace);
    ninlil_test_storage_destroy(storage_fixture);

    if (failures != 0) {
        (void)fprintf(
            stderr, "wifi_v1_esp_adapter_e2e_test FAIL %d\n", failures);
        return 1;
    }
    (void)printf(
        "wifi_v1_esp_adapter_e2e_test PASS "
        "create->STA->TCP(client/server)->TLS->M4 FULL->ATTACHED->Fabric\n");
    return 0;
}
#endif
