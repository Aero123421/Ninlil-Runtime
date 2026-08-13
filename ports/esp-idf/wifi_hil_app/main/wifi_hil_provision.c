/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_hil_provision.h"

#include "wifi_sha256.h"
#include "wifi_tls_leaf_binding.h"

#include "nvs.h"

#include <string.h>

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0u;
    size_t i;
    if (bytes == NULL) {
        return 1;
    }
    for (i = 0u; i < length; ++i) {
        aggregate |= bytes[i];
    }
    return aggregate == 0u;
}

static void put_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8u);
    out[1] = (uint8_t)value;
}

static void put_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24u);
    out[1] = (uint8_t)(value >> 16u);
    out[2] = (uint8_t)(value >> 8u);
    out[3] = (uint8_t)value;
}

static void put_u64_be(uint8_t *out, uint64_t value)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        out[7u - i] = (uint8_t)(value >> (8u * i));
    }
}

static int get_blob_exact(
    nvs_handle_t handle,
    const char *key,
    void *out,
    size_t expected)
{
    size_t length = expected;
    return nvs_get_blob(handle, key, out, &length) == ESP_OK
        && length == expected;
}

static int get_blob_bounded(
    nvs_handle_t handle,
    const char *key,
    uint8_t *out,
    size_t capacity,
    size_t minimum,
    size_t *out_length)
{
    size_t length = 0u;
    if (out == NULL || out_length == NULL
        || nvs_get_blob(handle, key, NULL, &length) != ESP_OK
        || length < minimum || length > capacity
        || nvs_get_blob(handle, key, out, &length) != ESP_OK) {
        return 0;
    }
    *out_length = length;
    return 1;
}

static int get_pem(
    nvs_handle_t handle,
    const char *key,
    uint8_t out[NINLIL_WIFI_HIL_PEM_MAX_BYTES],
    size_t *out_length)
{
    size_t stored = 0u;
    size_t i;
    if (!get_blob_bounded(
            handle,
            key,
            out,
            NINLIL_WIFI_HIL_PEM_MAX_BYTES - 1u,
            32u,
            &stored)) {
        return 0;
    }
    for (i = 0u; i < stored; ++i) {
        if (out[i] == 0u && i + 1u != stored) {
            return 0;
        }
    }
    if (out[stored - 1u] != 0u) {
        out[stored++] = 0u;
    }
    *out_length = stored;
    return 1;
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
    (void)memset(canonical, 0, sizeof(canonical));
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
    (void)memset(canonical, 0, sizeof(canonical));
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
    (void)memset(canonical, 0, sizeof(canonical));
    (void)ninlil_wifi_leaf_binding_encode(
        &provision->tls_identity.local_leaf, local_wire);
    (void)ninlil_wifi_leaf_binding_encode(
        &provision->tls_identity.peer_leaf, peer_wire);
    (void)ninlil_wifi_build_peer_context(
        &provision->peer_context, peer_context);
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
    n += 32u; /* provision_digest is encoded as zero. */
    (void)memcpy(canonical + n, provision->reserved_zero, 8u);
    n += 8u;
    ninlil_wifi_sha256(canonical, n, out);
    (void)memset(canonical, 0, sizeof(canonical));
    (void)memset(local_wire, 0, sizeof(local_wire));
    (void)memset(peer_wire, 0, sizeof(peer_wire));
    (void)memset(peer_context, 0, sizeof(peer_context));
}

static wifi_network_credential_status_v1_t network_get(
    void *user,
    const ninlil_id128_t *profile_id,
    uint64_t revision,
    const uint8_t digest[32],
    wifi_network_credential_metadata_v1_t *out_metadata,
    uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES])
{
    ninlil_wifi_hil_provision_t *provision =
        (ninlil_wifi_hil_provision_t *)user;
    if (provision == NULL || profile_id == NULL || digest == NULL
        || out_metadata == NULL || secret_buffer == NULL) {
        return WIFI_NETCRED_PERMANENT;
    }
    if (memcmp(
            profile_id->bytes,
            provision->network_metadata.profile_id.bytes,
            16u)
            != 0
        || revision != provision->network_metadata.revision
        || memcmp(digest, provision->network_metadata.digest, 32u) != 0) {
        return WIFI_NETCRED_NOT_FOUND;
    }
    *out_metadata = provision->network_metadata;
    (void)memcpy(
        secret_buffer,
        provision->network_secret,
        WIFI_NETCRED_SECRET_BYTES);
    return WIFI_NETCRED_OK;
}

static void network_release(
    void *user,
    const ninlil_id128_t *profile_id,
    uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES])
{
    (void)user;
    (void)profile_id;
    if (secret_buffer != NULL) {
        (void)memset(secret_buffer, 0, WIFI_NETCRED_SECRET_BYTES);
    }
}

ninlil_wifi_hil_provision_status_t ninlil_wifi_hil_provision_load(
    ninlil_wifi_hil_provision_t *provision,
    void *tls_workspace,
    uint32_t tls_workspace_bytes,
    void *sta_workspace,
    uint32_t sta_workspace_bytes)
{
    nvs_handle_t handle = 0u;
    uint32_t schema = 0u;
    uint8_t enabled = 0u;
    uint8_t role = 0u;
    uint8_t auth = 0u;
    uint8_t pmf = 0u;
    uint8_t channel = 0u;
    uint8_t address_kind = 0u;
    uint16_t port = 0u;
    uint64_t profile_revision = 0u;
    uint64_t config_revision = 0u;
    uint64_t assignment_epoch = 0u;
    uint8_t local_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    uint8_t peer_wire[NINLIL_WIFI_LEAF_BINDING_BYTES];
    size_t ssid_length = 0u;
    size_t secret_length = 0u;
    esp_err_t open_status;
    if (provision == NULL || tls_workspace == NULL || sta_workspace == NULL) {
        return NINLIL_WIFI_HIL_PROVISION_CORRUPT;
    }
    (void)memset(provision, 0, sizeof(*provision));
    open_status =
        nvs_open(NINLIL_WIFI_HIL_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (open_status == ESP_ERR_NVS_NOT_FOUND) {
        return NINLIL_WIFI_HIL_PROVISION_MISSING;
    }
    if (open_status != ESP_OK
        || nvs_get_u32(handle, "schema", &schema) != ESP_OK
        || nvs_get_u8(handle, "enabled", &enabled) != ESP_OK) {
        if (open_status == ESP_OK) {
            nvs_close(handle);
        }
        return NINLIL_WIFI_HIL_PROVISION_CORRUPT;
    }
    if (schema != NINLIL_WIFI_HIL_PROVISION_SCHEMA || enabled != 1u
        || nvs_get_u8(handle, "role", &role) != ESP_OK
        || nvs_get_u8(handle, "auth", &auth) != ESP_OK
        || nvs_get_u8(handle, "pmf", &pmf) != ESP_OK
        || nvs_get_u8(handle, "channel", &channel) != ESP_OK
        || nvs_get_u8(handle, "addr_kind", &address_kind) != ESP_OK
        || nvs_get_u16(handle, "peer_port", &port) != ESP_OK
        || nvs_get_u64(handle, "profile_rev", &profile_revision) != ESP_OK
        || nvs_get_u64(handle, "config_rev", &config_revision) != ESP_OK
        || nvs_get_u64(handle, "assign_epoch", &assignment_epoch) != ESP_OK
        || !get_blob_exact(handle, "profile_id",
            provision->network_metadata.profile_id.bytes, 16u)
        || !get_blob_exact(handle, "cred_bind",
            provision->network_metadata.credential_binding_id.bytes, 16u)
        || !get_blob_exact(handle, "instance_id",
            provision->adapter_config.instance_id.bytes, 16u)
        || !get_blob_exact(
            handle, "peer_addr", provision->adapter_config.endpoint_address, 16u)
        || !get_blob_exact(handle, "local_leaf", local_wire,
            NINLIL_WIFI_LEAF_BINDING_BYTES)
        || !get_blob_exact(handle, "peer_leaf", peer_wire,
            NINLIL_WIFI_LEAF_BINDING_BYTES)
        || !get_blob_exact(handle, "fabric_desc",
            provision->session.expected_fabric_descriptor, 32u)
        || !get_blob_exact(handle, "registry_epoch",
            provision->registry_epoch_id, 16u)
        || !get_blob_exact(handle, "credential",
            provision->credential_candidate_digest, 32u)
        || !get_blob_bounded(handle, "ssid",
            provision->network_metadata.ssid, 32u, 1u, &ssid_length)
        || !get_blob_bounded(handle, "psk", provision->network_secret,
            WIFI_NETCRED_SECRET_BYTES, 8u, &secret_length)
        || !get_pem(handle, "ca_pem", provision->ca_pem,
            &provision->ca_pem_length)
        || !get_pem(handle, "cert_pem", provision->cert_pem,
            &provision->cert_pem_length)
        || !get_pem(handle, "key_pem", provision->key_pem,
            &provision->key_pem_length)) {
        nvs_close(handle);
        (void)memset(provision, 0, sizeof(*provision));
        return NINLIL_WIFI_HIL_PROVISION_CORRUPT;
    }
    nvs_close(handle);

    if ((role != WIFI_TLS_ROLE_CLIENT && role != WIFI_TLS_ROLE_SERVER)
        || (auth != WIFI_NETCRED_AUTH_WPA2_PSK
            && auth != WIFI_NETCRED_AUTH_WPA3_SAE
            && auth != WIFI_NETCRED_AUTH_WPA2_WPA3_TRANSITION)
        || pmf != 1u || channel > 14u || ssid_length > 32u
        || secret_length > WIFI_NETCRED_SECRET_BYTES
        || port == 0u || profile_revision == 0u || config_revision == 0u
        || assignment_epoch == 0u
        || bytes_zero(provision->network_metadata.profile_id.bytes, 16u)
        || bytes_zero(
            provision->network_metadata.credential_binding_id.bytes, 16u)
        || bytes_zero(provision->adapter_config.instance_id.bytes, 16u)
        || bytes_zero(provision->session.expected_fabric_descriptor, 32u)
        || bytes_zero(provision->registry_epoch_id, 16u)
        || bytes_zero(provision->credential_candidate_digest, 32u)
        || ninlil_wifi_leaf_binding_decode(
               local_wire, &provision->session.tls_identity.local_leaf)
            != NINLIL_WIFI_OK
        || ninlil_wifi_leaf_binding_decode(
               peer_wire, &provision->session.tls_identity.peer_leaf)
            != NINLIL_WIFI_OK) {
        (void)memset(provision, 0, sizeof(*provision));
        return NINLIL_WIFI_HIL_PROVISION_CORRUPT;
    }
    if ((role == WIFI_TLS_ROLE_SERVER
            && (address_kind != WIFI_ENDPOINT_LOCAL_ANY
                || !bytes_zero(
                    provision->adapter_config.endpoint_address, 16u)))
        || (role == WIFI_TLS_ROLE_CLIENT
            && ((address_kind != WIFI_ENDPOINT_IPV4
                    && address_kind != WIFI_ENDPOINT_IPV6)
                || bytes_zero(
                    provision->adapter_config.endpoint_address,
                    address_kind == WIFI_ENDPOINT_IPV4 ? 4u : 16u)
                || (address_kind == WIFI_ENDPOINT_IPV4
                    && !bytes_zero(
                        provision->adapter_config.endpoint_address + 4u,
                        12u))
                || (address_kind == WIFI_ENDPOINT_IPV6
                    && provision->adapter_config.endpoint_address[0] == 0xfeu
                    && (provision->adapter_config.endpoint_address[1] & 0xc0u)
                        == 0x80u)))) {
        (void)memset(provision, 0, sizeof(*provision));
        return NINLIL_WIFI_HIL_PROVISION_CORRUPT;
    }

    provision->network_metadata.api_version =
        NINLIL_WIFI_PRIVATE_API_VERSION;
    provision->network_metadata.struct_size =
        (uint16_t)sizeof(provision->network_metadata);
    provision->network_metadata.revision = profile_revision;
    provision->network_metadata.ssid_length = (uint8_t)ssid_length;
    provision->network_metadata.auth_mode = auth;
    provision->network_metadata.password_length = (uint8_t)secret_length;
    provision->network_metadata.pmf_required = pmf;
    provision->network_metadata.channel = channel;
    network_digest(
        &provision->network_metadata, provision->network_metadata.digest);

    provision->network_provider.api_version =
        NINLIL_WIFI_PRIVATE_API_VERSION;
    provision->network_provider.struct_size =
        (uint16_t)sizeof(provision->network_provider);
    provision->network_provider.user = provision;
    provision->network_provider.get = network_get;
    provision->network_provider.release = network_release;

    provision->session.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    provision->session.struct_size =
        (uint16_t)sizeof(provision->session);
    provision->session.tls_workspace = tls_workspace;
    provision->session.tls_workspace_bytes = tls_workspace_bytes;
    provision->session.sta_workspace = sta_workspace;
    provision->session.sta_workspace_bytes = sta_workspace_bytes;
    provision->session.tls_pems.ca_pem = provision->ca_pem;
    provision->session.tls_pems.ca_pem_len = provision->ca_pem_length;
    provision->session.tls_pems.cert_pem = provision->cert_pem;
    provision->session.tls_pems.cert_pem_len = provision->cert_pem_length;
    provision->session.tls_pems.key_pem = provision->key_pem;
    provision->session.tls_pems.key_pem_len = provision->key_pem_length;
    provision->session.tls_identity.api_version =
        NINLIL_WIFI_ESP_TLS_IDENTITY_EXPECTATION_VERSION;
    provision->session.tls_identity.struct_size =
        (uint16_t)sizeof(provision->session.tls_identity);
    (void)memcpy(
        provision->session.peer_context.authority_id,
        provision->session.tls_identity.local_leaf.authority_id,
        16u);
    provision->session.peer_context.authority_term =
        provision->session.tls_identity.local_leaf.authority_term;
    provision->session.peer_context.assignment_epoch = assignment_epoch;
    if (role == WIFI_TLS_ROLE_CLIENT) {
        (void)memcpy(
            provision->session.peer_context.tls_client_runtime_id,
            provision->session.tls_identity.local_leaf.runtime_id,
            16u);
        (void)memcpy(
            provision->session.peer_context.tls_server_runtime_id,
            provision->session.tls_identity.peer_leaf.runtime_id,
            16u);
    } else {
        (void)memcpy(
            provision->session.peer_context.tls_client_runtime_id,
            provision->session.tls_identity.peer_leaf.runtime_id,
            16u);
        (void)memcpy(
            provision->session.peer_context.tls_server_runtime_id,
            provision->session.tls_identity.local_leaf.runtime_id,
            16u);
    }
    provision_digest(&provision->session, provision->session.provision_digest);

    provision->adapter_config.api_version =
        NINLIL_WIFI_PRIVATE_API_VERSION;
    provision->adapter_config.struct_size =
        (uint16_t)sizeof(provision->adapter_config);
    provision->adapter_config.adapter_kind =
        WIFI_ADAPTER_KIND_ESP32S3_STA_TCP;
    provision->adapter_config.tls_role = role;
    provision->adapter_config.configuration_revision = config_revision;
    (void)memcpy(
        provision->adapter_config.local_runtime_id.bytes,
        provision->session.tls_identity.local_leaf.runtime_id,
        16u);
    (void)memcpy(
        provision->adapter_config.expected_peer_runtime_id.bytes,
        provision->session.tls_identity.peer_leaf.runtime_id,
        16u);
    provision->adapter_config.endpoint_address_kind =
        role == WIFI_TLS_ROLE_SERVER
        ? WIFI_ENDPOINT_LOCAL_ANY
        : (uint32_t)address_kind;
    if (role == WIFI_TLS_ROLE_SERVER) {
        (void)memset(provision->adapter_config.endpoint_address, 0, 16u);
    }
    provision->adapter_config.endpoint_port = port;
    provision->adapter_config.network_profile_id =
        provision->network_metadata.profile_id;
    provision->adapter_config.network_profile_revision = profile_revision;
    (void)memcpy(
        provision->adapter_config.network_profile_digest,
        provision->network_metadata.digest,
        32u);
    provision->adapter_config.reconnect_profile_id =
        WIFI_RECONNECT_PROFILE_1;
    provision->adapter_config.network_credential_provider =
        &provision->network_provider;
    provision->adapter_config.esp_session_provision = &provision->session;
    config_digest(
        &provision->adapter_config,
        provision->adapter_config.configuration_digest);
    return NINLIL_WIFI_HIL_PROVISION_OK;
}

void ninlil_wifi_hil_provision_bind_runtime(
    ninlil_wifi_hil_provision_t *provision,
    const ninlil_storage_ops_t *storage,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    const wifi_m4_attachment_carrier_ops_v1_t *m4_carrier)
{
    if (provision == NULL) {
        return;
    }
    provision->adapter_config.storage = storage;
    provision->adapter_config.clock = clock;
    provision->adapter_config.execution = execution;
    provision->adapter_config.m4_attachment_carrier_ops = m4_carrier;
}

void ninlil_wifi_hil_provision_wipe_parsed_pems(
    ninlil_wifi_hil_provision_t *provision)
{
    if (provision == NULL) {
        return;
    }
    (void)memset(provision->ca_pem, 0, sizeof(provision->ca_pem));
    (void)memset(provision->cert_pem, 0, sizeof(provision->cert_pem));
    (void)memset(provision->key_pem, 0, sizeof(provision->key_pem));
    provision->ca_pem_length = 0u;
    provision->cert_pem_length = 0u;
    provision->key_pem_length = 0u;
    (void)memset(
        &provision->session.tls_pems,
        0,
        sizeof(provision->session.tls_pems));
}
