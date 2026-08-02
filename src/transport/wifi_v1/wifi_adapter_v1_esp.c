#include "wifi_adapter_v1.h"

#if (defined(ESP_PLATFORM) || defined(NINLIL_WIFI_ESP_ADAPTER_HOST_TEST))    \
    && defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1)                              \
    && NINLIL_ENABLE_PRIVATE_FABRIC_V1

#include "wifi_esp_fabric_link_ops.h"
#include "wifi_esp_owner.h"
#include "wifi_esp_sta.h"
#include "wifi_sha256.h"

#include <ninlil/version.h>

#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#define WIFI_ESP_ADAPTER_MAGIC UINT32_C(0x57414531) /* WAE1 */
#define WIFI_ESP_LIFECYCLE_OPEN 1u
#define WIFI_ESP_LIFECYCLE_DRAINING 2u
#define WIFI_ESP_LIFECYCLE_CLOSED 3u

struct wifi_adapter_private_v1 {
    uint32_t magic;
    uint32_t lifecycle;
    uint64_t owner_context_id;
    uint8_t in_call;
    uint8_t descriptor_ready;
    uint8_t connect_started;
    uint8_t reserved0;
    uint32_t reason;
    wifi_adapter_config_v1_t config;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    wifi_network_credential_provider_ops_v1_t network_provider;
    wifi_m4_attachment_carrier_ops_v1_t m4_carrier;
    wifi_esp_session_provision_v1_t provision;
    ninlil_wifi_esp_owner_t owner;
    ninlil_wifi_esp_tls_t *tls;
    ninlil_wifi_esp_sta_t *sta;
    ninlil_wifi_esp_fabric_link_user_t link_user;
    ninlil_fabric_packet_link_ops_v1_t standalone_link_ops;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_wifi_fabric_call_scope_v1_t standalone_scope;
    ninlil_wifi_fabric_call_scope_v1_t registered_scopes[
        NINLIL_WIFI_FABRIC_REGISTRATION_SCOPE_MAX];
    uint32_t registered_scope_count;
    const void *fabric_cookie;
    ninlil_fabric_registration_private_t *fabric_registration;
    uint8_t fabric_registration_state;
    uint8_t reserved_registration[7];
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_wifi_m4_full_evidence_t m4_evidence;
    ninlil_wifi_endpoint_t endpoint;
    uint64_t trusted_now_ms;
};

#define WIFI_FABRIC_REG_NONE 0u
#define WIFI_FABRIC_REG_PREPARED 1u
#define WIFI_FABRIC_REG_ACTIVE 2u
#define WIFI_FABRIC_REG_DRAINING 3u

static int bytes_zero(const uint8_t *p, size_t length)
{
    size_t i;
    if (p == NULL) {
        return 1;
    }
    for (i = 0u; i < length; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

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

static int config_digest_matches(const wifi_adapter_config_v1_t *config)
{
    static const uint8_t tag[] = "NINLIL-WIFI-ADAPTER-CONFIG-V1";
    uint8_t canonical[256];
    uint8_t digest[32];
    size_t n = 0u;
#define APPEND(src_, length_)                                                  \
    do {                                                                       \
        size_t append_length_ = (size_t)(length_);                             \
        if (append_length_ > sizeof(canonical) - n) {                          \
            return 0;                                                          \
        }                                                                      \
        (void)memcpy(canonical + n, (src_), append_length_);                   \
        n += append_length_;                                                   \
    } while (0)
    APPEND(tag, sizeof(tag) - 1u);
    put_u32_be(canonical + n, config->adapter_kind);
    n += 4u;
    put_u32_be(canonical + n, config->tls_role);
    n += 4u;
    APPEND(config->instance_id.bytes, 16u);
    put_u64_be(canonical + n, config->configuration_revision);
    n += 8u;
    (void)memset(canonical + n, 0, 32u);
    n += 32u;
    APPEND(config->local_runtime_id.bytes, 16u);
    APPEND(config->expected_peer_runtime_id.bytes, 16u);
    put_u32_be(canonical + n, config->endpoint_address_kind);
    n += 4u;
    APPEND(config->endpoint_address, 16u);
    put_u16_be(canonical + n, config->endpoint_port);
    n += 2u;
    put_u16_be(canonical + n, config->reserved_zero_u16);
    n += 2u;
    APPEND(config->network_profile_id.bytes, 16u);
    put_u64_be(canonical + n, config->network_profile_revision);
    n += 8u;
    APPEND(config->network_profile_digest, 32u);
    put_u32_be(canonical + n, config->reconnect_profile_id);
    n += 4u;
    put_u32_be(canonical + n, config->reserved_zero_u32);
    n += 4u;
    ninlil_wifi_sha256(canonical, n, digest);
    (void)memset(canonical, 0, sizeof(canonical));
    return memcmp(digest, config->configuration_digest, 32u) == 0;
#undef APPEND
}

static int provision_digest_matches(
    const wifi_esp_session_provision_v1_t *provision)
{
    static const uint8_t tag[] = "NINLIL-WIFI-ESP-PROVISION-V1";
    uint8_t canonical[384];
    uint8_t local_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    uint8_t peer_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    uint8_t peer_context[NINLIL_WIFI_PEER_CONTEXT_BYTES];
    uint8_t digest[32];
    size_t n = 0u;
    if (provision == NULL
        || ninlil_wifi_leaf_binding_encode(
               &provision->tls_identity.local_leaf, local_wire)
            != NINLIL_WIFI_OK
        || ninlil_wifi_leaf_binding_encode(
               &provision->tls_identity.peer_leaf, peer_wire)
            != NINLIL_WIFI_OK
        || ninlil_wifi_build_peer_context(
               &provision->peer_context, peer_context)
            != NINLIL_WIFI_OK) {
        return 0;
    }
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
    (void)memset(canonical + n, 0, 32u);
    n += 32u;
    (void)memcpy(canonical + n, provision->reserved_zero, 8u);
    n += 8u;
    ninlil_wifi_sha256(canonical, n, digest);
    (void)memset(canonical, 0, sizeof(canonical));
    (void)memset(local_wire, 0, sizeof(local_wire));
    (void)memset(peer_wire, 0, sizeof(peer_wire));
    (void)memset(peer_context, 0, sizeof(peer_context));
    return memcmp(digest, provision->provision_digest, 32u) == 0;
}

static int ranges_overlap(
    const void *a,
    size_t a_length,
    const void *b,
    size_t b_length)
{
    uintptr_t a0 = (uintptr_t)a;
    uintptr_t b0 = (uintptr_t)b;
    uintptr_t a1;
    uintptr_t b1;
    if (a == NULL || b == NULL || a_length == 0u || b_length == 0u
        || a0 > UINTPTR_MAX - a_length || b0 > UINTPTR_MAX - b_length) {
        return 1;
    }
    a1 = a0 + a_length;
    b1 = b0 + b_length;
    return a0 < b1 && b0 < a1;
}

static int base_ops_valid(const wifi_adapter_config_v1_t *config)
{
    const ninlil_storage_ops_t *storage = config->storage;
    const ninlil_clock_ops_t *clock = config->clock;
    const ninlil_execution_ops_t *execution = config->execution;
    return storage != NULL && clock != NULL && execution != NULL
        && storage->abi_version == NINLIL_ABI_VERSION
        && storage->struct_size == (uint16_t)sizeof(*storage)
        && storage->open != NULL && storage->close != NULL
        && storage->begin != NULL && storage->get != NULL
        && storage->put != NULL && storage->commit != NULL
        && clock->abi_version == NINLIL_ABI_VERSION
        && clock->struct_size == (uint16_t)sizeof(*clock)
        && clock->now != NULL
        && execution->abi_version == NINLIL_ABI_VERSION
        && execution->struct_size == (uint16_t)sizeof(*execution)
        && execution->current_context_id != NULL;
}

static wifi_private_adapter_status_v1_t validate_config(
    const wifi_adapter_config_v1_t *config)
{
    const wifi_network_credential_provider_ops_v1_t *provider;
    const wifi_m4_attachment_carrier_ops_v1_t *carrier;
    const wifi_esp_session_provision_v1_t *provision;
    int is_server;
    if (config == NULL
        || config->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || config->struct_size != (uint16_t)sizeof(*config)
        || config->adapter_kind != WIFI_ADAPTER_KIND_ESP32S3_STA_TCP
        || (config->tls_role != WIFI_TLS_ROLE_CLIENT
            && config->tls_role != WIFI_TLS_ROLE_SERVER)
        || config->configuration_revision == 0u
        || bytes_zero(config->instance_id.bytes, 16u)
        || bytes_zero(config->configuration_digest, 32u)
        || bytes_zero(config->local_runtime_id.bytes, 16u)
        || bytes_zero(config->expected_peer_runtime_id.bytes, 16u)
        || config->endpoint_port == 0u
        || config->reserved_zero_u16 != 0u
        || config->reserved_zero_u32 != 0u
        || config->reconnect_profile_id != WIFI_RECONNECT_PROFILE_1
        || bytes_zero(config->network_profile_id.bytes, 16u)
        || config->network_profile_revision == 0u
        || bytes_zero(config->network_profile_digest, 32u)
        || !base_ops_valid(config) || !config_digest_matches(config)) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    is_server = config->tls_role == WIFI_TLS_ROLE_SERVER;
    if (config->endpoint_address_kind == WIFI_ENDPOINT_IPV4) {
        if ((!is_server && bytes_zero(config->endpoint_address, 4u))
            || !bytes_zero(config->endpoint_address + 4u, 12u)) {
            return WIFI_PRIVATE_INVALID_ARGUMENT;
        }
    } else if (config->endpoint_address_kind == WIFI_ENDPOINT_IPV6) {
        if (bytes_zero(config->endpoint_address, 16u)
            || (config->endpoint_address[0] == 0xfeu
                && (config->endpoint_address[1] & 0xc0u) == 0x80u)) {
            return WIFI_PRIVATE_UNSUPPORTED;
        }
    } else if (config->endpoint_address_kind != WIFI_ENDPOINT_LOCAL_ANY
        || !is_server || !bytes_zero(config->endpoint_address, 16u)) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    provider = config->network_credential_provider;
    carrier = config->m4_attachment_carrier_ops;
    provision = config->esp_session_provision;
    if (provider == NULL
        || provider->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || provider->struct_size != (uint16_t)sizeof(*provider)
        || provider->get == NULL || provider->release == NULL
        || carrier == NULL
        || carrier->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || carrier->struct_size != (uint16_t)sizeof(*carrier)
        || carrier->poll_full == NULL || provision == NULL
        || provision->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || provision->struct_size != (uint16_t)sizeof(*provision)
        || provision->tls_workspace == NULL
        || provision->sta_workspace == NULL
        || provision->tls_workspace_bytes < ninlil_wifi_esp_tls_sizeof()
        || provision->sta_workspace_bytes < ninlil_wifi_esp_sta_sizeof()
        || ((uintptr_t)provision->tls_workspace % alignof(max_align_t)) != 0u
        || ((uintptr_t)provision->sta_workspace % alignof(max_align_t)) != 0u
        || ranges_overlap(
               provision->tls_workspace,
               provision->tls_workspace_bytes,
               provision->sta_workspace,
               provision->sta_workspace_bytes)
        || provision->tls_pems.ca_pem == NULL
        || provision->tls_pems.cert_pem == NULL
        || provision->tls_pems.key_pem == NULL
        || provision->tls_pems.ca_pem_len == 0u
        || provision->tls_pems.cert_pem_len == 0u
        || provision->tls_pems.key_pem_len == 0u
        || bytes_zero(provision->expected_fabric_descriptor, 32u)
        || !bytes_zero(
            provision->reserved_zero, sizeof(provision->reserved_zero))
        || !provision_digest_matches(provision)) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (memcmp(
            config->local_runtime_id.bytes,
            provision->tls_identity.local_leaf.runtime_id,
            16u)
            != 0
        || memcmp(
               config->expected_peer_runtime_id.bytes,
               provision->tls_identity.peer_leaf.runtime_id,
               16u)
            != 0
        || (is_server
            && provision->tls_identity.local_leaf.role
                != NINLIL_WIFI_LEAF_ROLE_SERVER)
        || (!is_server
            && provision->tls_identity.local_leaf.role
                != NINLIL_WIFI_LEAF_ROLE_CLIENT)
        || ninlil_wifi_esp_tls_identity_match(
               is_server,
               &provision->tls_identity,
               &provision->tls_identity.local_leaf,
               &provision->tls_identity.peer_leaf,
               &(ninlil_wifi_esp_tls_verified_identity_t){0})
            != NINLIL_WIFI_OK) {
        return WIFI_PRIVATE_DENIED;
    }
    return WIFI_PRIVATE_OK;
}

static wifi_private_adapter_status_v1_t adapter_enter(
    wifi_adapter_private_v1_t *adapter,
    int permit_closed)
{
    uint64_t current;
    if (adapter == NULL || adapter->magic != WIFI_ESP_ADAPTER_MAGIC) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (adapter->in_call) {
        return WIFI_PRIVATE_REENTRANT;
    }
    if (!permit_closed
        && adapter->lifecycle == WIFI_ESP_LIFECYCLE_CLOSED) {
        return WIFI_PRIVATE_CLOSED;
    }
    adapter->in_call = 1u;
    current = adapter->execution.current_context_id(
        adapter->execution.user);
    if (current == 0u || current != adapter->owner_context_id) {
        adapter->in_call = 0u;
        return WIFI_PRIVATE_WRONG_THREAD;
    }
    return WIFI_PRIVATE_OK;
}

static void adapter_leave(wifi_adapter_private_v1_t *adapter)
{
    adapter->in_call = 0u;
}

static wifi_private_adapter_status_v1_t map_wifi(
    ninlil_wifi_status_t status)
{
    if (status == NINLIL_WIFI_OK || status == NINLIL_WIFI_WOULD_BLOCK
        || status == NINLIL_WIFI_BACKPRESSURE
        || status == NINLIL_WIFI_INVALID_STATE) {
        return WIFI_PRIVATE_OK;
    }
    if (status == NINLIL_WIFI_CAPACITY) {
        return WIFI_PRIVATE_CAPACITY;
    }
    if (status == NINLIL_WIFI_DENIED || status == NINLIL_WIFI_CREDENTIAL) {
        return WIFI_PRIVATE_DENIED;
    }
    if (status == NINLIL_WIFI_CORRUPT) {
        return WIFI_PRIVATE_CORRUPT;
    }
    if (status == NINLIL_WIFI_CLOSED) {
        return WIFI_PRIVATE_CLOSED;
    }
    if (status == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN) {
        return WIFI_PRIVATE_STORAGE_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_WIFI_IO_ERROR) {
        return WIFI_PRIVATE_STORAGE;
    }
    if (status == NINLIL_WIFI_UNSUPPORTED) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
    return WIFI_PRIVATE_UNAVAILABLE;
}

static wifi_private_adapter_status_v1_t refresh_clock(
    wifi_adapter_private_v1_t *adapter,
    ninlil_time_sample_t *out)
{
    ninlil_time_sample_t sample;
    (void)memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    if (adapter->clock.now(adapter->clock.user, &sample) != NINLIL_PORT_OK
        || sample.trust != NINLIL_CLOCK_TRUSTED
        || sample.reserved_zero != 0u
        || bytes_zero(sample.clock_epoch_id.bytes, 16u)
        || ninlil_wifi_esp_fabric_bind_trusted_clock(
               &adapter->link_user, &sample)
            != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_fence(&adapter->owner);
        adapter->reason = WIFI_REASON_TRUSTED_CLOCK_INVALID;
        return WIFI_PRIVATE_DENIED;
    }
    adapter->trusted_now_ms = sample.now_ms;
    if (out != NULL) {
        *out = sample;
    }
    return WIFI_PRIVATE_OK;
}

static int descriptor_valid(
    const wifi_adapter_private_v1_t *adapter,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_time_sample_t *now)
{
    uint32_t required_security = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    return descriptor != NULL && now != NULL
        && descriptor->api_version == 1u
        && descriptor->struct_size == (uint16_t)sizeof(*descriptor)
        && memcmp(
               descriptor->instance_id.bytes,
               adapter->config.instance_id.bytes,
               16u)
            == 0
        && descriptor->link_kind == NINLIL_FABRIC_LINK_KIND_WIFI
        && (descriptor->capability_flags & NINLIL_FABRIC_CAP_CUSTODY) == 0u
        && (descriptor->direction_mask
                & (NINLIL_FABRIC_LINK_DIRECTION_SEND
                    | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE))
            == (NINLIL_FABRIC_LINK_DIRECTION_SEND
                | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE)
        && descriptor->descriptor_revision != 0u
        && memcmp(
               descriptor->descriptor_digest,
               adapter->provision.expected_fabric_descriptor,
               32u)
            == 0
        && !bytes_zero(descriptor->security_profile_id.bytes, 16u)
        && (descriptor->security_capability_flags & required_security)
            == required_security
        && !bytes_zero(descriptor->security_binding_digest, 32u)
        && descriptor->attestation_epoch != 0u
        && memcmp(
               descriptor->attestation_clock_epoch_id.bytes,
               now->clock_epoch_id.bytes,
               16u)
            == 0
        && descriptor->attestation_expires_at_ms > now->now_ms
        && !bytes_zero(descriptor->attestation_digest, 32u)
        && memcmp(
               descriptor->authenticated_peer_runtime_id.bytes,
               adapter->config.expected_peer_runtime_id.bytes,
               16u)
            == 0
        && memcmp(
               descriptor->attachment_authority_id.bytes,
               adapter->provision.tls_identity.local_leaf.authority_id,
               16u)
            == 0
        && memcmp(
               descriptor->attachment_binding_digest,
               adapter->provision.tls_identity.local_leaf
                   .authorized_attachment_binding_digest,
               32u)
            == 0
        && descriptor->maximum_packet_bytes
            >= NINLIL_WIFI_NWB1_PAYLOAD_MIN
        && descriptor->maximum_packet_bytes
            <= NINLIL_WIFI_NWB1_PAYLOAD_MAX
        && descriptor->maximum_transfer_bytes
            >= descriptor->maximum_packet_bytes
        && descriptor->reserved_zero_u16 == 0u
        && descriptor->peer_nfl1_version == 1u
        && descriptor->reserved_zero_peer_u16 == 0u
        && (descriptor->peer_fabric_capability_flags
                & NINLIL_FABRIC_PEER_CAP_NFL1_V1)
            != 0u
        && descriptor->configuration_revision
            == adapter->config.configuration_revision
        && memcmp(
               descriptor->configuration_digest,
               adapter->config.configuration_digest,
               32u)
            == 0;
}

wifi_private_adapter_status_v1_t wifi_workspace_required_v1(
    uint32_t adapter_kind,
    uint32_t *out_bytes,
    uint32_t *out_alignment)
{
    if (out_bytes != NULL) {
        *out_bytes = 0u;
    }
    if (out_alignment != NULL) {
        *out_alignment = 0u;
    }
    if (out_bytes == NULL || out_alignment == NULL) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (adapter_kind != WIFI_ADAPTER_KIND_ESP32S3_STA_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
    if (sizeof(wifi_adapter_private_v1_t) > UINT32_MAX) {
        return WIFI_PRIVATE_CAPACITY;
    }
    *out_bytes = (uint32_t)sizeof(wifi_adapter_private_v1_t);
    *out_alignment = (uint32_t)alignof(wifi_adapter_private_v1_t);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_create_v1(
    const wifi_adapter_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    wifi_adapter_private_v1_t **out_adapter)
{
    wifi_adapter_private_v1_t *adapter;
    wifi_private_adapter_status_v1_t status;
    ninlil_wifi_esp_sta_config_t sta_config;
    ninlil_time_sample_t now;
    ninlil_wifi_status_t wifi_status;
    uint64_t owner_context;
    if (out_adapter != NULL) {
        *out_adapter = NULL;
    }
    status = validate_config(config);
    if (status != WIFI_PRIVATE_OK || workspace == NULL || out_adapter == NULL
        || workspace_bytes < sizeof(wifi_adapter_private_v1_t)
        || ((uintptr_t)workspace % alignof(wifi_adapter_private_v1_t)) != 0u) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    owner_context = config->execution->current_context_id(
        config->execution->user);
    if (owner_context == 0u) {
        return WIFI_PRIVATE_WRONG_THREAD;
    }
    adapter = (wifi_adapter_private_v1_t *)workspace;
    (void)memset(adapter, 0, sizeof(*adapter));
    adapter->magic = WIFI_ESP_ADAPTER_MAGIC;
    adapter->lifecycle = WIFI_ESP_LIFECYCLE_OPEN;
    adapter->owner_context_id = owner_context;
    adapter->config = *config;
    adapter->storage = *config->storage;
    adapter->clock = *config->clock;
    adapter->execution = *config->execution;
    adapter->network_provider = *config->network_credential_provider;
    adapter->m4_carrier = *config->m4_attachment_carrier_ops;
    adapter->provision = *config->esp_session_provision;
    adapter->config.storage = &adapter->storage;
    adapter->config.clock = &adapter->clock;
    adapter->config.execution = &adapter->execution;
    adapter->config.network_credential_provider = &adapter->network_provider;
    adapter->config.m4_attachment_carrier_ops = &adapter->m4_carrier;
    adapter->config.esp_session_provision = &adapter->provision;
    adapter->tls =
        (ninlil_wifi_esp_tls_t *)adapter->provision.tls_workspace;
    adapter->sta =
        (ninlil_wifi_esp_sta_t *)adapter->provision.sta_workspace;
    adapter->endpoint.address_kind =
        config->endpoint_address_kind == WIFI_ENDPOINT_IPV6 ? 2u : 1u;
    adapter->endpoint.port = config->endpoint_port;
    (void)memcpy(
        adapter->endpoint.address, config->endpoint_address, 16u);

    ninlil_wifi_esp_owner_init(&adapter->owner);
    ninlil_wifi_esp_owner_bind_tls(&adapter->owner, adapter->tls);
    wifi_status = ninlil_wifi_esp_owner_configure_tls(
        &adapter->owner,
        config->tls_role == WIFI_TLS_ROLE_SERVER,
        &adapter->provision.tls_pems);
    if (wifi_status != NINLIL_WIFI_OK
        || ninlil_wifi_esp_owner_set_tls_identity_expectation(
               &adapter->owner, &adapter->provision.tls_identity)
            != NINLIL_WIFI_OK
        || ninlil_wifi_esp_owner_set_peer_context_inputs(
               &adapter->owner, &adapter->provision.peer_context)
            != NINLIL_WIFI_OK
        || ninlil_wifi_esp_owner_set_attachment_expectation(
               &adapter->owner,
               adapter->provision.tls_identity.local_leaf.authority_id,
               adapter->provision.tls_identity.local_leaf
                   .authorized_attachment_binding_digest)
            != NINLIL_WIFI_OK
        || ninlil_wifi_esp_owner_set_fabric_descriptor(
               &adapter->owner,
               adapter->provision.expected_fabric_descriptor)
            != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_close(&adapter->owner);
        (void)memset(adapter, 0, sizeof(*adapter));
        return WIFI_PRIVATE_DENIED;
    }
    if (ninlil_wifi_esp_sta_init(adapter->sta) != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_close(&adapter->owner);
        (void)memset(adapter, 0, sizeof(*adapter));
        return WIFI_PRIVATE_UNAVAILABLE;
    }
    ninlil_wifi_esp_owner_bind_sta(&adapter->owner, adapter->sta);
    (void)memset(&sta_config, 0, sizeof(sta_config));
    sta_config.network_profile_id = config->network_profile_id;
    sta_config.network_profile_revision = config->network_profile_revision;
    (void)memcpy(
        sta_config.network_profile_digest,
        config->network_profile_digest,
        32u);
    sta_config.credential_provider = &adapter->network_provider;
    wifi_status = ninlil_wifi_esp_sta_start(adapter->sta, &sta_config);
    if (wifi_status != NINLIL_WIFI_OK) {
        ninlil_wifi_esp_owner_close(&adapter->owner);
        ninlil_wifi_esp_sta_stop(adapter->sta);
        (void)memset(adapter, 0, sizeof(*adapter));
        return map_wifi(wifi_status);
    }
    /*
     * PEM pointers are never retained after mbedTLS parses them. Keep only the
     * non-secret identity pins in the adapter copy.
     */
    (void)memset(
        &adapter->provision.tls_pems,
        0,
        sizeof(adapter->provision.tls_pems));
    ninlil_wifi_esp_fabric_packet_link_ops_init(
        &adapter->link_ops, &adapter->link_user, &adapter->owner);
    ninlil_wifi_esp_fabric_packet_link_ops_scoped_init(
        &adapter->standalone_link_ops,
        &adapter->link_user,
        &adapter->standalone_scope,
        NULL);
    status = refresh_clock(adapter, &now);
    if (status != WIFI_PRIVATE_OK) {
        ninlil_wifi_esp_sta_stop(adapter->sta);
        ninlil_wifi_esp_owner_close(&adapter->owner);
        (void)memset(adapter, 0, sizeof(*adapter));
        return status;
    }
    adapter->reason = WIFI_REASON_ATTACHMENT_AUTHORITY_UNAVAILABLE;
    *out_adapter = adapter;
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_packet_link_descriptor_v1(
    wifi_adapter_private_v1_t *adapter,
    const ninlil_fabric_link_descriptor_v1_t **out_descriptor)
{
    wifi_private_adapter_status_v1_t status;
    if (out_descriptor != NULL) {
        *out_descriptor = NULL;
    }
    status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK || out_descriptor == NULL) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    if (!adapter->descriptor_ready
        || adapter->owner.phase != NINLIL_WIFI_PHASE_ATTACHED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_UNAVAILABLE;
    }
    if ((adapter->descriptor.capability_flags
            & NINLIL_FABRIC_CAP_CUSTODY)
        != 0u) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    *out_descriptor = &adapter->descriptor;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_packet_link_ops_v1(
    wifi_adapter_private_v1_t *adapter,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops)
{
    wifi_private_adapter_status_v1_t status;
    if (out_ops != NULL) {
        *out_ops = NULL;
    }
    status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK || out_ops == NULL) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    /*
     * The raw accessor is a standalone, cookie-less scope.  Production
     * traffic is available only through wifi_fabric_register_v1().
     */
    *out_ops = &adapter->standalone_link_ops;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t
wifi_fabric_registration_prepare_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    const ninlil_fabric_link_descriptor_v1_t **out_descriptor,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops)
{
    wifi_private_adapter_status_v1_t status;
    if (out_descriptor != NULL) {
        *out_descriptor = NULL;
    }
    if (out_ops != NULL) {
        *out_ops = NULL;
    }
    status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK || fabric_cookie == NULL
        || out_descriptor == NULL || out_ops == NULL) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    if (adapter->fabric_registration_state != WIFI_FABRIC_REG_NONE) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    if (adapter->registered_scope_count
        >= NINLIL_WIFI_FABRIC_REGISTRATION_SCOPE_MAX) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_CAPACITY;
    }
    if (!adapter->descriptor_ready
        || adapter->owner.phase != NINLIL_WIFI_PHASE_ATTACHED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_UNAVAILABLE;
    }
    if ((adapter->descriptor.capability_flags
            & NINLIL_FABRIC_CAP_CUSTODY)
        != 0u) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    if (!ninlil_wifi_esp_fabric_packet_link_authority_prepare(
            &adapter->link_user, fabric_cookie)) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    ninlil_wifi_esp_fabric_packet_link_ops_scoped_init(
        &adapter->link_ops,
        &adapter->link_user,
        &adapter->registered_scopes[adapter->registered_scope_count],
        fabric_cookie);
    adapter->registered_scope_count += 1u;
    adapter->fabric_cookie = fabric_cookie;
    adapter->fabric_registration_state = WIFI_FABRIC_REG_PREPARED;
    *out_descriptor = &adapter->descriptor;
    *out_ops = &adapter->link_ops;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t
wifi_fabric_registration_commit_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (fabric_cookie == NULL || registration == NULL
        || adapter->fabric_registration_state != WIFI_FABRIC_REG_PREPARED
        || adapter->fabric_cookie != fabric_cookie
        || !ninlil_wifi_esp_fabric_packet_link_authority_activate(
            &adapter->link_user, fabric_cookie)) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    adapter->fabric_registration = registration;
    adapter->fabric_registration_state = WIFI_FABRIC_REG_ACTIVE;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t
wifi_fabric_registration_abort_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (fabric_cookie == NULL
        || adapter->fabric_registration_state != WIFI_FABRIC_REG_PREPARED
        || adapter->fabric_cookie != fabric_cookie) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    if (adapter->link_user.open) {
        adapter->link_ops.close(
            adapter->link_ops.user,
            (ninlil_fabric_packet_link_handle_t)(uintptr_t)
                adapter->link_user.open_generation);
    }
    if (!ninlil_wifi_esp_fabric_packet_link_authority_unbind(
            &adapter->link_user, fabric_cookie)) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    adapter->fabric_cookie = NULL;
    adapter->fabric_registration = NULL;
    adapter->fabric_registration_state = WIFI_FABRIC_REG_NONE;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t
wifi_fabric_registration_validate_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration,
    uint32_t required_state)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (fabric_cookie == NULL || registration == NULL
        || adapter->fabric_cookie != fabric_cookie
        || adapter->fabric_registration != registration
        || adapter->fabric_registration_state != required_state) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t
wifi_fabric_registration_drain_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (fabric_cookie == NULL || registration == NULL
        || adapter->fabric_cookie != fabric_cookie
        || adapter->fabric_registration != registration
        || adapter->fabric_registration_state != WIFI_FABRIC_REG_ACTIVE
        || !ninlil_wifi_esp_fabric_packet_link_authority_drain(
            &adapter->link_user, fabric_cookie)) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    adapter->fabric_registration_state = WIFI_FABRIC_REG_DRAINING;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t
wifi_fabric_registration_finish_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (fabric_cookie == NULL || registration == NULL
        || adapter->fabric_cookie != fabric_cookie
        || adapter->fabric_registration != registration
        || adapter->fabric_registration_state != WIFI_FABRIC_REG_DRAINING
        || adapter->link_user.open || adapter->link_user.send_in_use
        || adapter->link_user.rx_loan_active
        || !ninlil_wifi_esp_fabric_packet_link_authority_unbind(
            &adapter->link_user, fabric_cookie)) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    adapter->fabric_cookie = NULL;
    adapter->fabric_registration = NULL;
    adapter->fabric_registration_state = WIFI_FABRIC_REG_NONE;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_step_v1(
    wifi_adapter_private_v1_t *adapter,
    uint32_t max_work_1_to_64,
    uint32_t *out_work_done)
{
    wifi_private_adapter_status_v1_t status;
    ninlil_time_sample_t now;
    ninlil_wifi_status_t wifi_status;
    uint32_t work = 0u;
    uint32_t owner_work = 0u;
    if (out_work_done != NULL) {
        *out_work_done = 0u;
    }
    status = adapter_enter(adapter, 0);
    if (status != WIFI_PRIVATE_OK || out_work_done == NULL
        || max_work_1_to_64 == 0u || max_work_1_to_64 > 64u) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    status = refresh_clock(adapter, &now);
    if (status != WIFI_PRIVATE_OK) {
        adapter_leave(adapter);
        return status;
    }
    if (adapter->lifecycle == WIFI_ESP_LIFECYCLE_DRAINING) {
        if (adapter->link_user.open) {
            adapter->link_ops.close(
                adapter->link_ops.user,
                (ninlil_fabric_packet_link_handle_t)(uintptr_t)
                    adapter->link_user.open_generation);
            work += 1u;
        }
        if (!adapter->link_user.send_in_use
            && !adapter->link_user.rx_loan_active) {
            if (adapter->m4_carrier.cancel != NULL) {
                adapter->m4_carrier.cancel(adapter->m4_carrier.user);
            }
            ninlil_wifi_esp_sta_stop(adapter->sta);
            ninlil_wifi_esp_owner_close(&adapter->owner);
            adapter->lifecycle = WIFI_ESP_LIFECYCLE_CLOSED;
            work += 1u;
        }
        *out_work_done = work;
        adapter_leave(adapter);
        return WIFI_PRIVATE_OK;
    }
    wifi_status = ninlil_wifi_esp_owner_step(
        &adapter->owner, max_work_1_to_64, &owner_work);
    work += owner_work;
    status = map_wifi(wifi_status);
    if (status != WIFI_PRIVATE_OK) {
        adapter_leave(adapter);
        return status;
    }
    if (!adapter->connect_started && adapter->owner.got_ip
        && adapter->owner.phase == NINLIL_WIFI_PHASE_CLOSED
        && work < max_work_1_to_64) {
        wifi_status = ninlil_wifi_esp_owner_connect(
            &adapter->owner, &adapter->endpoint);
        if (wifi_status != NINLIL_WIFI_OK) {
            adapter_leave(adapter);
            return map_wifi(wifi_status);
        }
        adapter->connect_started = 1u;
        work += 1u;
    }
    if ((adapter->owner.phase == NINLIL_WIFI_PHASE_PEER_SESSION
            || adapter->owner.phase
                == NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING)
        && work < max_work_1_to_64) {
        (void)memset(&adapter->m4_evidence, 0, sizeof(adapter->m4_evidence));
        (void)memset(&adapter->descriptor, 0, sizeof(adapter->descriptor));
        status = adapter->m4_carrier.poll_full(
            adapter->m4_carrier.user,
            adapter->owner.ids.peer_session_id,
            now.now_ms,
            &adapter->m4_evidence,
            &adapter->descriptor);
        if (status == WIFI_PRIVATE_WOULD_BLOCK
            || status == WIFI_PRIVATE_UNAVAILABLE) {
            adapter->reason = WIFI_REASON_ATTACHMENT_AUTHORITY_UNAVAILABLE;
        } else if (status != WIFI_PRIVATE_OK
            || ninlil_wifi_m4_evidence_ready_for_attach(
                   &adapter->m4_evidence)
                != NINLIL_WIFI_OK
            || !descriptor_valid(adapter, &adapter->descriptor, &now)) {
            ninlil_wifi_m4_evidence_consume(&adapter->m4_evidence);
            (void)memset(
                &adapter->descriptor, 0, sizeof(adapter->descriptor));
            adapter_leave(adapter);
            return status == WIFI_PRIVATE_OK
                ? WIFI_PRIVATE_DENIED
                : status;
        } else {
            wifi_status = ninlil_wifi_esp_owner_accept_m4_full_evidence(
                &adapter->owner, &adapter->m4_evidence);
            if (wifi_status != NINLIL_WIFI_OK
                || adapter->owner.phase != NINLIL_WIFI_PHASE_ATTACHED) {
                ninlil_wifi_m4_evidence_consume(&adapter->m4_evidence);
                (void)memset(
                    &adapter->descriptor, 0, sizeof(adapter->descriptor));
                adapter_leave(adapter);
                return map_wifi(wifi_status);
            }
            adapter->descriptor_ready = 1u;
            adapter->reason = WIFI_REASON_NONE;
        }
        work += 1u;
    }
    *out_work_done = work;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

static wifi_operational_state_v1_t operational_state(
    const wifi_adapter_private_v1_t *adapter)
{
    if (adapter->lifecycle == WIFI_ESP_LIFECYCLE_DRAINING) {
        return WIFI_OPERATIONAL_DRAINING;
    }
    if (adapter->lifecycle == WIFI_ESP_LIFECYCLE_CLOSED) {
        return WIFI_OPERATIONAL_DISABLED;
    }
    if (adapter->owner.phase == NINLIL_WIFI_PHASE_CLOSED) {
        if (adapter->owner.got_ip) {
            return WIFI_OPERATIONAL_IP_READY;
        }
        if (adapter->owner.associated) {
            return WIFI_OPERATIONAL_ASSOCIATED;
        }
        return WIFI_OPERATIONAL_ASSOCIATING;
    }
    switch (adapter->owner.phase) {
    case NINLIL_WIFI_PHASE_CONNECTING:
        return WIFI_OPERATIONAL_TCP_READY;
    case NINLIL_WIFI_PHASE_HANDSHAKING:
        return WIFI_OPERATIONAL_TCP_READY;
    case NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED:
        return WIFI_OPERATIONAL_CHANNEL_AUTHENTICATED;
    case NINLIL_WIFI_PHASE_PEER_SESSION:
        return WIFI_OPERATIONAL_PEER_SESSION;
    case NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING:
        return WIFI_OPERATIONAL_ATTACHMENT_NEGOTIATING;
    case NINLIL_WIFI_PHASE_ATTACHED:
        return WIFI_OPERATIONAL_ATTACHED;
    case NINLIL_WIFI_PHASE_RECONNECT_WAIT:
        return WIFI_OPERATIONAL_BACKOFF;
    case NINLIL_WIFI_PHASE_FENCED:
        return WIFI_OPERATIONAL_FENCED;
    default:
        return WIFI_OPERATIONAL_RADIO_READY;
    }
}

wifi_private_adapter_status_v1_t wifi_state_v1(
    wifi_adapter_private_v1_t *adapter,
    wifi_operational_state_v1_t *out_operational_state,
    uint32_t *out_reason,
    uint64_t *out_epoch)
{
    wifi_private_adapter_status_v1_t status;
    if (out_operational_state != NULL) {
        *out_operational_state = WIFI_OPERATIONAL_DISABLED;
    }
    if (out_reason != NULL) {
        *out_reason = WIFI_REASON_NONE;
    }
    if (out_epoch != NULL) {
        *out_epoch = 0u;
    }
    status = adapter_enter(adapter, 1);
    if (status != WIFI_PRIVATE_OK || out_operational_state == NULL
        || out_reason == NULL || out_epoch == NULL) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    *out_operational_state = operational_state(adapter);
    *out_reason = adapter->owner.availability_epoch_exhausted
        ? WIFI_REASON_EPOCH_EXHAUSTED
        : adapter->reason;
    *out_epoch = adapter->owner.availability_epoch;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_drain_begin_v1(
    wifi_adapter_private_v1_t *adapter)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 1);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (adapter->lifecycle == WIFI_ESP_LIFECYCLE_CLOSED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_CLOSED;
    }
    if (adapter->fabric_registration_state != WIFI_FABRIC_REG_NONE) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_WOULD_BLOCK;
    }
    adapter->lifecycle = WIFI_ESP_LIFECYCLE_DRAINING;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_drain_poll_v1(
    wifi_adapter_private_v1_t *adapter,
    uint32_t *out_done)
{
    wifi_private_adapter_status_v1_t status;
    if (out_done != NULL) {
        *out_done = 0u;
    }
    status = adapter_enter(adapter, 1);
    if (status != WIFI_PRIVATE_OK || out_done == NULL) {
        return status == WIFI_PRIVATE_OK
            ? WIFI_PRIVATE_INVALID_ARGUMENT
            : status;
    }
    *out_done =
        adapter->lifecycle == WIFI_ESP_LIFECYCLE_CLOSED ? 1u : 0u;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_destroy_v1(
    wifi_adapter_private_v1_t *adapter)
{
    wifi_private_adapter_status_v1_t status = adapter_enter(adapter, 1);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    if (adapter->lifecycle != WIFI_ESP_LIFECYCLE_CLOSED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_WOULD_BLOCK;
    }
    (void)memset(adapter, 0, sizeof(*adapter));
    return WIFI_PRIVATE_OK;
}

#endif
