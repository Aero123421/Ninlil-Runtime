/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0018 private adapter lifecycle candidate.
 *
 * Source-only, default-OFF, not installed, not a stable ABI. ADR-0018 remains
 * Proposed; these names and layouts must not be promoted to public headers
 * without a separate compatibility review.
 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ADAPTER_V1_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ADAPTER_V1_H

#include "wifi_attachment_m4.h"
#include "wifi_esp_tls_mbedtls.h"
#include "wifi_private_types.h"
#include "wifi_tls_export.h"

#include <ninlil/platform.h>

#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1
#include "fabric_private_api.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_PRIVATE_API_VERSION 0x0001u

/*
 * Exact adapter-status catalog. This is intentionally distinct from the
 * pre-existing ninlil_wifi_status_t internal catalog.
 */
typedef uint32_t wifi_private_adapter_status_v1_t;
#define WIFI_PRIVATE_OK ((wifi_private_adapter_status_v1_t)0u)
#define WIFI_PRIVATE_INVALID_ARGUMENT ((wifi_private_adapter_status_v1_t)1u)
#define WIFI_PRIVATE_WRONG_THREAD ((wifi_private_adapter_status_v1_t)2u)
#define WIFI_PRIVATE_REENTRANT ((wifi_private_adapter_status_v1_t)3u)
#define WIFI_PRIVATE_UNSUPPORTED ((wifi_private_adapter_status_v1_t)4u)
#define WIFI_PRIVATE_WOULD_BLOCK ((wifi_private_adapter_status_v1_t)5u)
#define WIFI_PRIVATE_UNAVAILABLE ((wifi_private_adapter_status_v1_t)6u)
#define WIFI_PRIVATE_DENIED ((wifi_private_adapter_status_v1_t)7u)
#define WIFI_PRIVATE_CAPACITY ((wifi_private_adapter_status_v1_t)8u)
#define WIFI_PRIVATE_CORRUPT ((wifi_private_adapter_status_v1_t)9u)
#define WIFI_PRIVATE_CLOSED ((wifi_private_adapter_status_v1_t)10u)
#define WIFI_PRIVATE_STORAGE ((wifi_private_adapter_status_v1_t)11u)
#define WIFI_PRIVATE_STORAGE_COMMIT_UNKNOWN                                  \
    ((wifi_private_adapter_status_v1_t)12u)

#define WIFI_ADAPTER_KIND_POSIX_TCP 1u
#define WIFI_ADAPTER_KIND_ESP32S3_STA_TCP 2u
#define WIFI_TLS_ROLE_CLIENT 1u
#define WIFI_TLS_ROLE_SERVER 2u

#define WIFI_ENDPOINT_IPV4 1u
#define WIFI_ENDPOINT_IPV6 2u
#define WIFI_ENDPOINT_LOCAL_ANY 3u

#define WIFI_RECONNECT_PROFILE_1 1u

typedef uint32_t wifi_network_credential_status_v1_t;
#define WIFI_NETCRED_OK ((wifi_network_credential_status_v1_t)0u)
#define WIFI_NETCRED_NOT_FOUND ((wifi_network_credential_status_v1_t)1u)
#define WIFI_NETCRED_TEMPORARY ((wifi_network_credential_status_v1_t)2u)
#define WIFI_NETCRED_PERMANENT ((wifi_network_credential_status_v1_t)3u)
#define WIFI_NETCRED_CORRUPT ((wifi_network_credential_status_v1_t)4u)
#define WIFI_NETCRED_CAPACITY ((wifi_network_credential_status_v1_t)5u)

#define WIFI_NETCRED_AUTH_WPA2_PSK 1u
#define WIFI_NETCRED_AUTH_WPA3_SAE 2u
#define WIFI_NETCRED_AUTH_WPA2_WPA3_TRANSITION 3u
#define WIFI_NETCRED_SECRET_BYTES 64u

typedef struct wifi_network_credential_metadata_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_id128_t profile_id;
    uint64_t revision;
    uint8_t digest[32];
    ninlil_id128_t credential_binding_id;
    uint8_t ssid_length;
    uint8_t ssid[32];
    uint8_t auth_mode;
    uint8_t password_length;
    uint8_t pmf_required;
    uint8_t optional_bssid_present;
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t reserved_zero[7];
} wifi_network_credential_metadata_v1_t;

typedef struct wifi_network_credential_provider_ops_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    void *user;
    wifi_network_credential_status_v1_t (*get)(
        void *user,
        const ninlil_id128_t *profile_id,
        uint64_t revision,
        const uint8_t digest[32],
        wifi_network_credential_metadata_v1_t *out_metadata,
        uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES]);
    void (*release)(
        void *user,
        const ninlil_id128_t *profile_id,
        uint8_t secret_buffer[WIFI_NETCRED_SECRET_BYTES]);
} wifi_network_credential_provider_ops_v1_t;

/*
 * ESP-only resources and exact durable identity pins. PEM bytes are borrowed
 * only during create and parsed into the caller-provided TLS workspace;
 * neither this record nor the adapter logs or persists plaintext secrets.
 * The STA/TLS workspaces must outlive the adapter.
 */
typedef struct wifi_esp_session_provision_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    void *tls_workspace;
    uint32_t tls_workspace_bytes;
    void *sta_workspace;
    uint32_t sta_workspace_bytes;
    ninlil_wifi_esp_tls_pem_t tls_pems;
    ninlil_wifi_esp_tls_identity_expectation_t tls_identity;
    ninlil_wifi_peer_context_inputs_t peer_context;
    uint8_t expected_fabric_descriptor[32];
    uint8_t provision_digest[32];
    uint8_t reserved_zero[8];
} wifi_esp_session_provision_v1_t;

#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1
/*
 * Attachment authority bridge. poll_full must return a live subsystem-minted
 * M4 FULL evidence capability and its matching authenticated descriptor.
 * Raw caller bytes cannot mint ATTACHED because owner acceptance revalidates
 * the live linear capability.
 */
typedef struct wifi_m4_attachment_carrier_ops_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    void *user;
    wifi_private_adapter_status_v1_t (*poll_full)(
        void *user,
        const uint8_t peer_session_id[16],
        uint64_t trusted_now_ms,
        ninlil_wifi_m4_full_evidence_t *out_evidence,
        ninlil_fabric_link_descriptor_v1_t *out_descriptor);
    void (*cancel)(void *user);
} wifi_m4_attachment_carrier_ops_v1_t;
#endif

typedef struct wifi_adapter_config_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t adapter_kind;
    uint32_t tls_role;
    ninlil_id128_t instance_id;
    uint64_t configuration_revision;
    uint8_t configuration_digest[32];
    ninlil_id128_t local_runtime_id;
    ninlil_id128_t expected_peer_runtime_id;
    uint32_t endpoint_address_kind;
    uint8_t endpoint_address[16];
    uint16_t endpoint_port;
    uint16_t reserved_zero_u16;
    ninlil_id128_t network_profile_id;
    uint64_t network_profile_revision;
    uint8_t network_profile_digest[32];
    uint32_t reconnect_profile_id;
    uint32_t reserved_zero_u32;
    const ninlil_storage_ops_t *storage;
    const ninlil_clock_ops_t *clock;
    const ninlil_execution_ops_t *execution;
    const wifi_network_credential_provider_ops_v1_t
        *network_credential_provider;
#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1
    const wifi_m4_attachment_carrier_ops_v1_t *m4_attachment_carrier_ops;
#else
    const void *m4_attachment_carrier_ops;
#endif
    const wifi_esp_session_provision_v1_t *esp_session_provision;
} wifi_adapter_config_v1_t;

typedef struct wifi_adapter_private_v1 wifi_adapter_private_v1_t;

typedef uint32_t wifi_operational_state_v1_t;
#define WIFI_OPERATIONAL_DISABLED ((wifi_operational_state_v1_t)0u)
#define WIFI_OPERATIONAL_RADIO_READY ((wifi_operational_state_v1_t)1u)
#define WIFI_OPERATIONAL_ASSOCIATING ((wifi_operational_state_v1_t)2u)
#define WIFI_OPERATIONAL_ASSOCIATED ((wifi_operational_state_v1_t)3u)
#define WIFI_OPERATIONAL_IP_READY ((wifi_operational_state_v1_t)4u)
#define WIFI_OPERATIONAL_TCP_READY ((wifi_operational_state_v1_t)5u)
#define WIFI_OPERATIONAL_CHANNEL_AUTHENTICATED                              \
    ((wifi_operational_state_v1_t)6u)
#define WIFI_OPERATIONAL_PEER_SESSION ((wifi_operational_state_v1_t)7u)
#define WIFI_OPERATIONAL_ATTACHMENT_NEGOTIATING                             \
    ((wifi_operational_state_v1_t)8u)
#define WIFI_OPERATIONAL_ATTACHED ((wifi_operational_state_v1_t)9u)
#define WIFI_OPERATIONAL_BACKOFF ((wifi_operational_state_v1_t)10u)
#define WIFI_OPERATIONAL_FENCED ((wifi_operational_state_v1_t)11u)
#define WIFI_OPERATIONAL_DRAINING ((wifi_operational_state_v1_t)12u)

#define WIFI_REASON_NONE 0u
#define WIFI_REASON_RECOVERED_SESSION_FENCED 1u
#define WIFI_REASON_ATTACHMENT_AUTHORITY_UNAVAILABLE 2u
#define WIFI_REASON_EPOCH_EXHAUSTED 3u
#define WIFI_REASON_TRUSTED_CLOCK_INVALID 4u

#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1

wifi_private_adapter_status_v1_t wifi_workspace_required_v1(
    uint32_t adapter_kind,
    uint32_t *out_bytes,
    uint32_t *out_alignment);

wifi_private_adapter_status_v1_t wifi_create_v1(
    const wifi_adapter_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    wifi_adapter_private_v1_t **out_adapter);

wifi_private_adapter_status_v1_t wifi_packet_link_descriptor_v1(
    wifi_adapter_private_v1_t *adapter,
    const ninlil_fabric_link_descriptor_v1_t **out_descriptor);

wifi_private_adapter_status_v1_t wifi_packet_link_ops_v1(
    wifi_adapter_private_v1_t *adapter,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops);

/*
 * Internal halves used only by the inline production composition below.
 * Callers should use wifi_fabric_register_v1()/unregister_*(), never split
 * prepare/commit themselves.
 */
#define WIFI_FABRIC_REGISTRATION_ACTIVE_V1 2u
#define WIFI_FABRIC_REGISTRATION_DRAINING_V1 3u

wifi_private_adapter_status_v1_t
wifi_fabric_registration_prepare_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    const ninlil_fabric_link_descriptor_v1_t **out_descriptor,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops);

wifi_private_adapter_status_v1_t
wifi_fabric_registration_commit_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration);

wifi_private_adapter_status_v1_t
wifi_fabric_registration_abort_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie);

wifi_private_adapter_status_v1_t
wifi_fabric_registration_validate_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration,
    uint32_t required_state);

wifi_private_adapter_status_v1_t
wifi_fabric_registration_drain_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration);

wifi_private_adapter_status_v1_t
wifi_fabric_registration_finish_internal_v1(
    wifi_adapter_private_v1_t *adapter,
    const void *fabric_cookie,
    ninlil_fabric_registration_private_t *registration);

static inline wifi_private_adapter_status_v1_t
wifi_private_from_fabric_status_v1(ninlil_fabric_private_status_t status)
{
    switch (status) {
    case NINLIL_FABRIC_PRIVATE_OK:
        return WIFI_PRIVATE_OK;
    case NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT:
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    case NINLIL_FABRIC_PRIVATE_WRONG_THREAD:
        return WIFI_PRIVATE_WRONG_THREAD;
    case NINLIL_FABRIC_PRIVATE_REENTRANT:
        return WIFI_PRIVATE_REENTRANT;
    case NINLIL_FABRIC_PRIVATE_CLOSED:
        return WIFI_PRIVATE_CLOSED;
    case NINLIL_FABRIC_PRIVATE_CONFLICT:
    case NINLIL_FABRIC_PRIVATE_WOULD_BLOCK:
        return WIFI_PRIVATE_WOULD_BLOCK;
    case NINLIL_FABRIC_PRIVATE_UNSUPPORTED:
        return WIFI_PRIVATE_UNSUPPORTED;
    case NINLIL_FABRIC_PRIVATE_CORRUPT:
        return WIFI_PRIVATE_CORRUPT;
    case NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN:
        return WIFI_PRIVATE_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_FABRIC_PRIVATE_DENIED:
        return WIFI_PRIVATE_DENIED;
    case NINLIL_FABRIC_PRIVATE_CAPACITY:
        return WIFI_PRIVATE_CAPACITY;
    default:
        return WIFI_PRIVATE_UNAVAILABLE;
    }
}

/*
 * Sole production registration path.  The raw packet-link accessor returns a
 * cookie-less standalone scope; only this path installs the exact Fabric
 * cookie, lets Fabric perform open/state, and then activates new TX/RX.
 */
static inline wifi_private_adapter_status_v1_t wifi_fabric_register_v1(
    wifi_adapter_private_v1_t *adapter,
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t **out_registration)
{
    const ninlil_fabric_link_descriptor_v1_t *descriptor = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *ops = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_fabric_private_status_t fabric_status;
    wifi_private_adapter_status_v1_t status;
    if (out_registration != NULL) {
        *out_registration = NULL;
    }
    if (adapter == NULL || fabric == NULL || out_registration == NULL) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    status = wifi_fabric_registration_prepare_internal_v1(
        adapter, fabric, &descriptor, &ops);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    fabric_status = ninlil_fabric_private_register_link_v1(
        fabric, descriptor, ops, &registration);
    if (fabric_status != NINLIL_FABRIC_PRIVATE_OK) {
        (void)wifi_fabric_registration_abort_internal_v1(adapter, fabric);
        return wifi_private_from_fabric_status_v1(fabric_status);
    }
    status = wifi_fabric_registration_commit_internal_v1(
        adapter, fabric, registration);
    if (status != WIFI_PRIVATE_OK) {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_unregister_begin_v1(
            fabric, registration);
        (void)ninlil_fabric_private_unregister_poll_v1(
            fabric, registration, &done);
        (void)wifi_fabric_registration_abort_internal_v1(adapter, fabric);
        return status;
    }
    *out_registration = registration;
    return WIFI_PRIVATE_OK;
}

static inline wifi_private_adapter_status_v1_t
wifi_fabric_unregister_begin_v1(
    wifi_adapter_private_v1_t *adapter,
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration)
{
    ninlil_fabric_private_status_t fabric_status;
    wifi_private_adapter_status_v1_t status;
    status = wifi_fabric_registration_validate_internal_v1(
        adapter,
        fabric,
        registration,
        WIFI_FABRIC_REGISTRATION_ACTIVE_V1);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    fabric_status =
        ninlil_fabric_private_unregister_begin_v1(fabric, registration);
    if (fabric_status != NINLIL_FABRIC_PRIVATE_OK) {
        return wifi_private_from_fabric_status_v1(fabric_status);
    }
    status = wifi_fabric_registration_drain_internal_v1(
        adapter, fabric, registration);
    return status;
}

static inline wifi_private_adapter_status_v1_t
wifi_fabric_unregister_poll_v1(
    wifi_adapter_private_v1_t *adapter,
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration,
    uint32_t *out_done)
{
    ninlil_fabric_private_status_t fabric_status;
    wifi_private_adapter_status_v1_t status;
    uint32_t done = 0u;
    if (out_done != NULL) {
        *out_done = 0u;
    }
    if (out_done == NULL) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    status = wifi_fabric_registration_validate_internal_v1(
        adapter,
        fabric,
        registration,
        WIFI_FABRIC_REGISTRATION_DRAINING_V1);
    if (status != WIFI_PRIVATE_OK) {
        return status;
    }
    fabric_status = ninlil_fabric_private_unregister_poll_v1(
        fabric, registration, &done);
    if (fabric_status != NINLIL_FABRIC_PRIVATE_OK) {
        return wifi_private_from_fabric_status_v1(fabric_status);
    }
    if (done != 0u) {
        status = wifi_fabric_registration_finish_internal_v1(
            adapter, fabric, registration);
        if (status != WIFI_PRIVATE_OK) {
            return status;
        }
        *out_done = 1u;
    }
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_step_v1(
    wifi_adapter_private_v1_t *adapter,
    uint32_t max_work_1_to_64,
    uint32_t *out_work_done);

wifi_private_adapter_status_v1_t wifi_state_v1(
    wifi_adapter_private_v1_t *adapter,
    wifi_operational_state_v1_t *out_operational_state,
    uint32_t *out_reason,
    uint64_t *out_epoch);

wifi_private_adapter_status_v1_t wifi_drain_begin_v1(
    wifi_adapter_private_v1_t *adapter);

wifi_private_adapter_status_v1_t wifi_drain_poll_v1(
    wifi_adapter_private_v1_t *adapter,
    uint32_t *out_done);

wifi_private_adapter_status_v1_t wifi_destroy_v1(
    wifi_adapter_private_v1_t *adapter);

#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ADAPTER_V1_H */
