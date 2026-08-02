#include <ninlil/posix_tls_v1.h>

#include "posix_tls_v1_records.h"
#include "wifi_nwb1.h"
#include "wifi_reconnect.h"
#include "wifi_stream.h"
#include "wifi_tcp_posix.h"
#include "wifi_tls_export.h"
#include "wifi_tls_host.h"
#include "wifi_tls_leaf_binding.h"

#if defined(NINLIL_POSIX_TLS_V1_TEST_HOOKS)
#include "posix_tls_v1_test_hooks.h"
#endif

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define POSIX_TLS_MAGIC UINT32_C(0x50544c31) /* PTL1 */
#define POSIX_TLS_LIFECYCLE_OPEN UINT32_C(1)
#define POSIX_TLS_LIFECYCLE_DRAINING UINT32_C(2)
#define POSIX_TLS_LIFECYCLE_CLOSED UINT32_C(3)
#define POSIX_TLS_REGISTRATION_MAGIC UINT32_C(0x50545231) /* PTR1 */
#define POSIX_TLS_REGISTRATION_NONE UINT8_C(0)
#define POSIX_TLS_REGISTRATION_REGISTERING UINT8_C(1)
#define POSIX_TLS_REGISTRATION_ACTIVE UINT8_C(2)
#define POSIX_TLS_REGISTRATION_UNREGISTERING UINT8_C(3)
#define POSIX_TLS_REGISTRATION_CONSUMED UINT8_C(4)
#define POSIX_TLS_CONTROLLED_NONE UINT8_C(0)
#define POSIX_TLS_CONTROLLED_REGISTER UINT8_C(1)
#define POSIX_TLS_CONTROLLED_UNREGISTER UINT8_C(2)
#define POSIX_TLS_PROVIDER_CALLBACK_OPEN UINT8_C(1)
#define POSIX_TLS_PROVIDER_CALLBACK_STATE UINT8_C(2)
#define POSIX_TLS_PROVIDER_CALLBACK_CLOSE UINT8_C(3)
#define POSIX_TLS_PROVIDER_CALLBACK_IO UINT8_C(4)
#define POSIX_TLS_WORK_BUDGET_MAX UINT32_C(64)
#define POSIX_TLS_TLS_STORAGE_BYTES 2048u
#define POSIX_TLS_ATTACHMENT_RECORD_COUNT 4u
#define POSIX_TLS_MEMBERSHIP_PAYLOAD_BYTES 88u
#define POSIX_TLS_CREDENTIAL_PAYLOAD_BYTES 48u
#define POSIX_TLS_ATTACHMENT_PAYLOAD_BYTES 168u
#define POSIX_TLS_REGISTRY_PAYLOAD_BYTES 104u
#define POSIX_TLS_TX_TOKEN_TAG UINT8_C(0xa7)
#define POSIX_TLS_RX_TOKEN_TAG UINT8_C(0x5d)

#define POSIX_TLS_NWB1_PAYLOAD_MIN UINT32_C(587)
#define POSIX_TLS_NWB1_PAYLOAD_MAX UINT32_C(1925)
#define POSIX_TLS_DIRECTION_BIDIRECTIONAL                                  \
    (NINLIL_FABRIC_LINK_DIRECTION_SEND                                    \
     | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE)
#define POSIX_TLS_REQUIRED_SECURITY                                        \
    (NINLIL_FABRIC_SECURITY_INTEGRITY                                     \
     | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY                             \
     | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION                           \
     | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS)
#define POSIX_TLS_KNOWN_CAPABILITIES                                       \
    (NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE | NINLIL_FABRIC_CAP_UNICAST       \
     | NINLIL_FABRIC_CAP_BROADCAST | NINLIL_FABRIC_CAP_RESERVATION        \
     | NINLIL_FABRIC_CAP_REGULATED_RF | NINLIL_FABRIC_CAP_CUSTODY         \
     | NINLIL_FABRIC_CAP_EVIDENCE)

struct ninlil_posix_tls_registration_v1 {
    uint32_t magic;
    uint32_t reserved_zero;
    uint64_t generation;
    ninlil_posix_tls_v1_t *port;
    ninlil_fabric_v1_t *fabric;
    ninlil_fabric_link_registration_v1_t *fabric_registration;
};

struct ninlil_posix_tls_v1 {
    uint32_t magic;
    uint32_t lifecycle;
    uint32_t workspace_bytes;
    uint32_t reserved_zero;
    uint64_t owner_context_id;
    uint8_t in_call;
    uint8_t provider_in_call;
    uint8_t controlled_call;
    uint8_t provider_open;
    uint8_t fenced;
    uint8_t ever_registered;
    uint8_t registration_state;
    uint8_t reserved_u8;
    ninlil_posix_tls_config_v1_t config;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_posix_tls_state_v1_t state;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    struct ninlil_posix_tls_registration_v1 registration;
    /*
     * Compact C1 peer-session slice of the private wifi_session state.  The
     * full private object also embeds M4, NWB1 and payload queues and is not
     * suitable for this installed tranche.
     */
    ninlil_wifi_tcp_t listener;
    ninlil_wifi_tcp_t tcp;
    ninlil_wifi_endpoint_t endpoint;
    ninlil_wifi_reconnect_t reconnect;
    _Alignas(max_align_t) uint8_t tls_storage[POSIX_TLS_TLS_STORAGE_BYTES];
    ninlil_wifi_tls_t *tls;
    ninlil_wifi_tls_paths_t tls_paths;
    ninlil_wifi_session_ids_t session_ids;
    uint8_t peer_context[NINLIL_WIFI_PEER_CONTEXT_BYTES];
    uint32_t peer_phase;
    uint32_t next_tx_sequence;
    ninlil_wifi_rx_stream_t rx_stream;
    uint8_t tx_record[NINLIL_WIFI_NWB1_TOTAL_MAX];
    uint8_t rx_packet[NINLIL_WIFI_NWB1_PAYLOAD_MAX];
    size_t tx_record_length;
    size_t tx_record_offset;
    uint32_t tx_token_generation;
    uint32_t next_tx_token_generation;
    uint32_t tx_sequence;
    uint32_t tx_completion_kind;
    uint32_t rx_packet_length;
    uint32_t rx_sequence;
    uint32_t rx_loan_generation;
    uint32_t next_rx_loan_generation;
    uintptr_t tx_token_value;
    uintptr_t rx_token_value;
    uint8_t tls_configured;
    uint8_t tls_attached;
    uint8_t connection_live;
    uint8_t reconnect_pending;
    uint8_t close_network_done;
    uint8_t attachment_payloads_ready;
    uint8_t attachment_stage;
    uint8_t link_available;
    uint8_t restart_fenced;
    uint8_t close_clean_persisted;
    uint8_t close_marker_attempted;
    uint8_t close_marker_failed;
    uint8_t reserved_attachment_u8;
    uint32_t close_failure_status;
    uint8_t tx_in_use;
    uint8_t tx_terminal;
    uint8_t tx_crossed_uncertain_boundary;
    uint8_t tx_disconnect_requested;
    uint8_t rx_ready;
    uint8_t rx_loan_active;
    uint8_t reserved_data_u8[2];
    uint32_t attachment_payload_lengths[POSIX_TLS_ATTACHMENT_RECORD_COUNT];
    uint8_t membership_payload[POSIX_TLS_MEMBERSHIP_PAYLOAD_BYTES];
    uint8_t credential_payload[POSIX_TLS_CREDENTIAL_PAYLOAD_BYTES];
    uint8_t attachment_payload[POSIX_TLS_ATTACHMENT_PAYLOAD_BYTES];
    uint8_t registry_payload[POSIX_TLS_REGISTRY_PAYLOAD_BYTES];
    char ca_path[1024];
    char cert_path[1024];
    char key_path[1024];
    uint8_t storage_namespace[127];
#if defined(NINLIL_POSIX_TLS_V1_TEST_HOOKS)
    size_t test_tls_write_limit;
    uint8_t test_fail_next_write_before_positive;
#endif
};

static ninlil_posix_tls_status_t posix_tls_note_connection_loss(
    struct ninlil_posix_tls_v1 *port);

static int posix_tls_id128_is_zero(const ninlil_id128_t *id)
{
    static const ninlil_id128_t zero = {{0u}};
    return id == NULL || memcmp(id, &zero, sizeof(zero)) == 0;
}

static void posix_tls_store_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void posix_tls_store_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void posix_tls_store_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

static int posix_tls_bytes_are_zero(const uint8_t *bytes, size_t count)
{
    size_t i;

    if (bytes == NULL) {
        return 1;
    }
    for (i = 0u; i < count; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int posix_tls_utf8_path_valid(const char *text, size_t capacity)
{
    size_t i;

    if (text == NULL || capacity == 0u) {
        return 0;
    }
    i = 0u;
    while (i < capacity && text[i] != '\0') {
        const uint8_t c0 = (uint8_t)text[i];
        size_t sequence_length;
        size_t j;

        if (c0 <= UINT8_C(0x7f)) {
            ++i;
            continue;
        }
        if (c0 >= UINT8_C(0xc2) && c0 <= UINT8_C(0xdf)) {
            sequence_length = 2u;
        } else if (c0 >= UINT8_C(0xe0) && c0 <= UINT8_C(0xef)) {
            sequence_length = 3u;
        } else if (c0 >= UINT8_C(0xf0) && c0 <= UINT8_C(0xf4)) {
            sequence_length = 4u;
        } else {
            return 0;
        }
        if (sequence_length > capacity - i) {
            return 0;
        }
        for (j = 1u; j < sequence_length; ++j) {
            const uint8_t continuation = (uint8_t)text[i + j];
            if (continuation < UINT8_C(0x80)
                || continuation > UINT8_C(0xbf)) {
                return 0;
            }
        }
        if ((c0 == UINT8_C(0xe0) && (uint8_t)text[i + 1u] < UINT8_C(0xa0))
            || (c0 == UINT8_C(0xed)
                && (uint8_t)text[i + 1u] > UINT8_C(0x9f))
            || (c0 == UINT8_C(0xf0)
                && (uint8_t)text[i + 1u] < UINT8_C(0x90))
            || (c0 == UINT8_C(0xf4)
                && (uint8_t)text[i + 1u] > UINT8_C(0x8f))) {
            return 0;
        }
        i += sequence_length;
    }
    return i != 0u && i < capacity;
}

static int posix_tls_platform_ops_valid(
    const ninlil_posix_tls_config_v1_t *config)
{
    const ninlil_storage_ops_t *storage;
    const ninlil_clock_ops_t *clock;
    const ninlil_execution_ops_t *execution;

    if (config == NULL) {
        return 0;
    }
    storage = config->storage;
    clock = config->clock;
    execution = config->execution;
    return storage != NULL && clock != NULL && execution != NULL
        && storage->abi_version == NINLIL_ABI_VERSION
        && storage->struct_size == (uint16_t)sizeof(*storage)
        && storage->user != NULL && storage->open != NULL
        && storage->close != NULL && storage->begin != NULL
        && storage->get != NULL && storage->put != NULL
        && storage->erase != NULL && storage->iter_open != NULL
        && storage->iter_next != NULL && storage->iter_close != NULL
        && storage->capacity != NULL && storage->commit != NULL
        && storage->rollback != NULL
        && clock->abi_version == NINLIL_ABI_VERSION
        && clock->struct_size == (uint16_t)sizeof(*clock)
        && clock->user != NULL && clock->now != NULL
        && execution->abi_version == NINLIL_ABI_VERSION
        && execution->struct_size == (uint16_t)sizeof(*execution)
        && execution->user != NULL && execution->current_context_id != NULL;
}

static int posix_tls_leaf_valid(
    const ninlil_posix_tls_leaf_expectation_v1_t *leaf,
    uint32_t expected_role)
{
    return leaf != NULL
        && leaf->api_version == NINLIL_POSIX_TLS_API_VERSION
        && leaf->struct_size == (uint16_t)sizeof(*leaf)
        && leaf->role == expected_role
        && !posix_tls_id128_is_zero(&leaf->runtime_id)
        && !posix_tls_bytes_are_zero(leaf->leaf_spki_sha256, 32u)
        && !posix_tls_id128_is_zero(&leaf->authority_id)
        && leaf->authority_term != 0u
        && !posix_tls_bytes_are_zero(
            leaf->authorized_attachment_binding_digest, 32u)
        && leaf->credential_generation != 0u
        && leaf->revocation_generation != 0u;
}

static int posix_tls_config_valid(
    const ninlil_posix_tls_config_v1_t *config)
{
    uint32_t expected_peer_role;

    if (config == NULL
        || config->api_version != NINLIL_POSIX_TLS_API_VERSION
        || config->struct_size != sizeof(*config)
        || (config->role != NINLIL_POSIX_TLS_ROLE_CLIENT
            && config->role != NINLIL_POSIX_TLS_ROLE_SERVER)
        || config->flags != 0u
        || posix_tls_id128_is_zero(&config->instance_id)
        || !posix_tls_platform_ops_valid(config)
        || config->storage_namespace.data == NULL
        || config->storage_namespace.length == 0u
        || config->storage_namespace.length
            > sizeof(((struct ninlil_posix_tls_v1 *)0)->storage_namespace)) {
        return 0;
    }
    if (config->endpoint.api_version != NINLIL_POSIX_TLS_API_VERSION
        || config->endpoint.struct_size != sizeof(config->endpoint)
        || config->endpoint.reserved_zero_u16 != 0u
        || (config->endpoint.address_kind != NINLIL_POSIX_TLS_ADDRESS_IPV4
            && config->endpoint.address_kind != NINLIL_POSIX_TLS_ADDRESS_IPV6)
        || (config->role == NINLIL_POSIX_TLS_ROLE_CLIENT
            && config->endpoint.port == 0u)) {
        return 0;
    }
    if (config->endpoint.address_kind == NINLIL_POSIX_TLS_ADDRESS_IPV4) {
        if (config->endpoint.scope_id != 0u
            || !posix_tls_bytes_are_zero(config->endpoint.address + 4u, 12u)
            || (config->role == NINLIL_POSIX_TLS_ROLE_CLIENT
                && posix_tls_bytes_are_zero(
                    config->endpoint.address, 4u))) {
            return 0;
        }
    } else if (config->role == NINLIL_POSIX_TLS_ROLE_CLIENT
               && posix_tls_bytes_are_zero(
                   config->endpoint.address, 16u)) {
        return 0;
    }
    if (config->tls_paths.api_version != NINLIL_POSIX_TLS_API_VERSION
        || config->tls_paths.struct_size != sizeof(config->tls_paths)
        || !posix_tls_utf8_path_valid(
            config->tls_paths.ca_pem_path,
            sizeof(((struct ninlil_posix_tls_v1 *)0)->ca_path))
        || !posix_tls_utf8_path_valid(
            config->tls_paths.cert_pem_path,
            sizeof(((struct ninlil_posix_tls_v1 *)0)->cert_path))
        || !posix_tls_utf8_path_valid(
            config->tls_paths.key_pem_path,
            sizeof(((struct ninlil_posix_tls_v1 *)0)->key_path))) {
        return 0;
    }
    expected_peer_role = config->role == NINLIL_POSIX_TLS_ROLE_CLIENT
        ? NINLIL_POSIX_TLS_ROLE_SERVER : NINLIL_POSIX_TLS_ROLE_CLIENT;
    if (config->authorization.api_version != NINLIL_POSIX_TLS_API_VERSION
        || config->authorization.struct_size != sizeof(config->authorization)
        || config->authorization.assignment_epoch == 0u
        || config->authorization.reserved_zero != 0u
        || !posix_tls_leaf_valid(
            &config->authorization.local_leaf, config->role)
        || !posix_tls_leaf_valid(
            &config->authorization.peer_leaf, expected_peer_role)
        || memcmp(
               &config->authorization.local_leaf.authority_id,
               &config->authorization.peer_leaf.authority_id,
               sizeof(config->authorization.local_leaf.authority_id))
            != 0
        || config->authorization.local_leaf.authority_term
            != config->authorization.peer_leaf.authority_term
        || memcmp(
               config->authorization.local_leaf
                   .authorized_attachment_binding_digest,
               config->authorization.peer_leaf
                   .authorized_attachment_binding_digest,
               sizeof(config->authorization.local_leaf
                          .authorized_attachment_binding_digest))
            != 0
        || posix_tls_id128_is_zero(
            &config->authorization.registry_epoch_id)
        || posix_tls_bytes_are_zero(
            config->authorization.credential_reference_digest, 32u)
        || config->authorization.credential_revision == 0u
        || config->authorization.credential_revision > UINT32_MAX
        || config->authorization.credential_revision
            != config->authorization.local_leaf.credential_generation) {
        return 0;
    }
    return 1;
}

static int posix_tls_descriptor_valid(
    const ninlil_posix_tls_config_v1_t *config,
    const ninlil_time_sample_t *now)
{
    const ninlil_fabric_link_descriptor_v1_t *descriptor;

    if (config == NULL || now == NULL) {
        return 0;
    }
    descriptor = &config->link_descriptor;
    return descriptor->api_version == NINLIL_FABRIC_API_VERSION
        && descriptor->struct_size == (uint16_t)sizeof(*descriptor)
        && memcmp(&descriptor->instance_id, &config->instance_id,
                  sizeof(descriptor->instance_id)) == 0
        && descriptor->link_kind == NINLIL_FABRIC_LINK_KIND_WIFI
        && descriptor->direction_mask == POSIX_TLS_DIRECTION_BIDIRECTIONAL
        && (descriptor->capability_flags & ~POSIX_TLS_KNOWN_CAPABILITIES) == 0u
        && (descriptor->capability_flags & NINLIL_FABRIC_CAP_CUSTODY) == 0u
        && (descriptor->capability_flags & NINLIL_FABRIC_CAP_REGULATED_RF)
            == 0u
        && descriptor->descriptor_revision != 0u
        && !posix_tls_bytes_are_zero(descriptor->descriptor_digest, 32u)
        && !posix_tls_id128_is_zero(&descriptor->security_profile_id)
        && descriptor->security_capability_flags
            == POSIX_TLS_REQUIRED_SECURITY
        && !posix_tls_bytes_are_zero(
            descriptor->security_binding_digest, 32u)
        && descriptor->attestation_epoch != 0u
        && memcmp(&descriptor->attestation_clock_epoch_id,
                  &now->clock_epoch_id,
                  sizeof(descriptor->attestation_clock_epoch_id)) == 0
        && descriptor->attestation_expires_at_ms > now->now_ms
        && !posix_tls_bytes_are_zero(descriptor->attestation_digest, 32u)
        && memcmp(&descriptor->authenticated_peer_runtime_id,
                  &config->authorization.peer_leaf.runtime_id,
                  sizeof(descriptor->authenticated_peer_runtime_id)) == 0
        && memcmp(&descriptor->attachment_authority_id,
                  &config->authorization.local_leaf.authority_id,
                  sizeof(descriptor->attachment_authority_id)) == 0
        && memcmp(&descriptor->attachment_authority_id,
                  &config->authorization.peer_leaf.authority_id,
                  sizeof(descriptor->attachment_authority_id)) == 0
        && memcmp(descriptor->attachment_binding_digest,
                  config->authorization.local_leaf
                      .authorized_attachment_binding_digest,
                  sizeof(descriptor->attachment_binding_digest)) == 0
        && memcmp(descriptor->attachment_binding_digest,
                  config->authorization.peer_leaf
                      .authorized_attachment_binding_digest,
                  sizeof(descriptor->attachment_binding_digest)) == 0
        && descriptor->maximum_packet_bytes >= POSIX_TLS_NWB1_PAYLOAD_MIN
        && descriptor->maximum_packet_bytes <= POSIX_TLS_NWB1_PAYLOAD_MAX
        && descriptor->maximum_transfer_bytes
            >= descriptor->maximum_packet_bytes
        && descriptor->maximum_transfer_bytes <= POSIX_TLS_NWB1_PAYLOAD_MAX
        && descriptor->latency_class != UINT16_MAX
        && descriptor->cost_class != UINT16_MAX
        && descriptor->reserved_zero_u16 == 0u
        && descriptor->peer_nfl1_version == 1u
        && descriptor->reserved_zero_peer_u16 == 0u
        && descriptor->peer_fabric_capability_flags
            == NINLIL_FABRIC_PEER_CAP_NFL1_V1
        && ((descriptor->capability_flags
                 & NINLIL_FABRIC_CAP_RESERVATION)
                != 0u
            || descriptor->reservation_capacity == 0u)
        && descriptor->configuration_revision
            == config->authorization.credential_revision
        && memcmp(descriptor->configuration_digest,
                  config->authorization.credential_reference_digest,
                  sizeof(descriptor->configuration_digest)) == 0;
}

static ninlil_posix_tls_status_t posix_tls_map_fabric_status(
    ninlil_fabric_status_t status)
{
    switch (status) {
    case NINLIL_FABRIC_OK:
        return NINLIL_POSIX_TLS_OK;
    case NINLIL_FABRIC_INVALID_ARGUMENT:
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    case NINLIL_FABRIC_WRONG_THREAD:
        return NINLIL_POSIX_TLS_WRONG_THREAD;
    case NINLIL_FABRIC_REENTRANT:
        return NINLIL_POSIX_TLS_REENTRANT;
    case NINLIL_FABRIC_CLOSED:
        return NINLIL_POSIX_TLS_CLOSED;
    case NINLIL_FABRIC_CONFLICT:
    case NINLIL_FABRIC_DENIED:
        return NINLIL_POSIX_TLS_DENIED;
    case NINLIL_FABRIC_UNSUPPORTED:
        return NINLIL_POSIX_TLS_UNSUPPORTED;
    case NINLIL_FABRIC_CORRUPT:
        return NINLIL_POSIX_TLS_CORRUPT;
    case NINLIL_FABRIC_COMMIT_UNKNOWN:
        return NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_FABRIC_UNAVAILABLE:
        return NINLIL_POSIX_TLS_UNAVAILABLE;
    case NINLIL_FABRIC_CAPACITY:
        return NINLIL_POSIX_TLS_CAPACITY;
    case NINLIL_FABRIC_WOULD_BLOCK:
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    default:
        return NINLIL_POSIX_TLS_CORRUPT;
    }
}

static ninlil_posix_tls_status_t posix_tls_map_wifi_status(
    ninlil_wifi_status_t status)
{
    switch (status) {
    case NINLIL_WIFI_OK:
        return NINLIL_POSIX_TLS_OK;
    case NINLIL_WIFI_WOULD_BLOCK:
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    case NINLIL_WIFI_INVALID_ARGUMENT:
    case NINLIL_WIFI_INVALID_STATE:
    case NINLIL_WIFI_CORRUPT:
        return NINLIL_POSIX_TLS_CORRUPT;
    case NINLIL_WIFI_UNSUPPORTED:
        return NINLIL_POSIX_TLS_UNSUPPORTED;
    case NINLIL_WIFI_CAPACITY:
        return NINLIL_POSIX_TLS_CAPACITY;
    case NINLIL_WIFI_UNAVAILABLE:
        return NINLIL_POSIX_TLS_UNAVAILABLE;
    case NINLIL_WIFI_DENIED:
    case NINLIL_WIFI_CREDENTIAL:
        return NINLIL_POSIX_TLS_DENIED;
    case NINLIL_WIFI_CLOSED:
        return NINLIL_POSIX_TLS_CLOSED;
    case NINLIL_WIFI_TLS_FAILED:
        return NINLIL_POSIX_TLS_TLS;
    case NINLIL_WIFI_IO_ERROR:
        return NINLIL_POSIX_TLS_IO;
    case NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN:
        return NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN;
    default:
        return NINLIL_POSIX_TLS_CORRUPT;
    }
}

static void posix_tls_fence(
    struct ninlil_posix_tls_v1 *port, uint32_t reason)
{
    port->fenced = 1u;
    port->state.operational_state = NINLIL_POSIX_TLS_STATE_FENCED;
    port->state.reason = reason;
}

static uintptr_t posix_tls_make_token_value(
    const uint8_t session_id[16], uint32_t generation, uint8_t tag)
{
    uintptr_t value = sizeof(uintptr_t) >= 8u
        ? (uintptr_t)UINT64_C(1469598103934665603)
        : (uintptr_t)UINT32_C(2166136261);
    const uintptr_t prime = sizeof(uintptr_t) >= 8u
        ? (uintptr_t)UINT64_C(1099511628211)
        : (uintptr_t)UINT32_C(16777619);
    size_t i;

    for (i = 0u; i < 16u; ++i) {
        value ^= (uintptr_t)session_id[i];
        value *= prime;
    }
    for (i = 0u; i < sizeof(generation); ++i) {
        value ^= (uintptr_t)(uint8_t)(generation >> (i * 8u));
        value *= prime;
    }
    return (value & ~(uintptr_t)UINT8_MAX) | (uintptr_t)tag;
}

static ninlil_fabric_packet_token_t posix_tls_make_tx_token(
    const struct ninlil_posix_tls_v1 *port, uint32_t generation)
{
    return (ninlil_fabric_packet_token_t)posix_tls_make_token_value(
        port->session_ids.attached_session_id,
        generation,
        POSIX_TLS_TX_TOKEN_TAG);
}

static int posix_tls_tx_token_matches(
    const struct ninlil_posix_tls_v1 *port,
    ninlil_fabric_packet_token_t token)
{
    const uintptr_t value = (uintptr_t)token;

    return port != NULL && token != NULL && port->tx_in_use != 0u
        && value == port->tx_token_value;
}

static void *posix_tls_make_rx_token(
    const struct ninlil_posix_tls_v1 *port, uint32_t generation)
{
    return (void *)posix_tls_make_token_value(
        port->session_ids.attached_session_id,
        generation,
        POSIX_TLS_RX_TOKEN_TAG);
}

static int posix_tls_rx_token_matches(
    const struct ninlil_posix_tls_v1 *port, const void *token)
{
    const uintptr_t value = (uintptr_t)token;

    return port != NULL && token != NULL && port->rx_loan_active != 0u
        && value == port->rx_token_value;
}

static void posix_tls_terminalize_send_for_disconnect(
    struct ninlil_posix_tls_v1 *port)
{
    if (port->tx_in_use == 0u || port->tx_terminal != 0u) {
        return;
    }
    port->tx_terminal = 1u;
    port->tx_completion_kind = port->tx_crossed_uncertain_boundary != 0u
        ? NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN
        : NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
}

static void posix_tls_clear_peer_session(
    struct ninlil_posix_tls_v1 *port)
{
    memset(&port->session_ids, 0, sizeof(port->session_ids));
    memset(port->peer_context, 0, sizeof(port->peer_context));
    port->peer_phase = NINLIL_WIFI_PHASE_CLOSED;
    port->next_tx_sequence = 0u;
    port->tx_disconnect_requested = 0u;
    ninlil_wifi_rx_stream_init(&port->rx_stream);
    if (port->rx_loan_active == 0u) {
        memset(port->rx_packet, 0, sizeof(port->rx_packet));
        port->rx_packet_length = 0u;
        port->rx_sequence = 0u;
        port->rx_ready = 0u;
    }
    port->tls_attached = 0u;
    memset(
        port->attachment_payload_lengths,
        0,
        sizeof(port->attachment_payload_lengths));
    memset(port->membership_payload, 0, sizeof(port->membership_payload));
    memset(port->credential_payload, 0, sizeof(port->credential_payload));
    memset(port->attachment_payload, 0, sizeof(port->attachment_payload));
    memset(port->registry_payload, 0, sizeof(port->registry_payload));
    port->attachment_payloads_ready = 0u;
    port->attachment_stage = 0u;
}

static void posix_tls_close_connection(
    struct ninlil_posix_tls_v1 *port)
{
    posix_tls_terminalize_send_for_disconnect(port);
    if (port->tls_configured != 0u) {
        ninlil_wifi_tls_close(port->tls);
        memset(port->tls_storage, 0, sizeof(port->tls_storage));
        port->tls = (ninlil_wifi_tls_t *)(void *)port->tls_storage;
        port->tls_configured = 0u;
    }
    ninlil_wifi_tcp_close(&port->tcp);
    port->connection_live = 0u;
    posix_tls_clear_peer_session(port);
}

static void posix_tls_close_network(
    struct ninlil_posix_tls_v1 *port)
{
    posix_tls_close_connection(port);
    ninlil_wifi_tcp_close(&port->listener);
    port->reconnect_pending = 0u;
    port->close_network_done = 1u;
}

static ninlil_posix_tls_status_t posix_tls_clock_now_ms(
    struct ninlil_posix_tls_v1 *port, uint64_t *out_now_ms)
{
    ninlil_time_sample_t sample;

    if (out_now_ms == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    *out_now_ms = 0u;
    memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    if (port->clock.now(port->clock.user, &sample) != NINLIL_PORT_OK
        || sample.abi_version != NINLIL_ABI_VERSION
        || sample.struct_size != (uint16_t)sizeof(sample)
        || sample.trust != NINLIL_CLOCK_TRUSTED
        || sample.reserved_zero != 0u
        || memcmp(
               &sample.clock_epoch_id,
               &port->config.link_descriptor.attestation_clock_epoch_id,
               sizeof(sample.clock_epoch_id))
            != 0) {
        return NINLIL_POSIX_TLS_IO;
    }
    *out_now_ms = sample.now_ms;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_prepare_attachment_payloads(
    struct ninlil_posix_tls_v1 *port)
{
    const ninlil_posix_tls_authorization_v1_t *authorization;
    const ninlil_fabric_link_descriptor_v1_t *descriptor;
    const ninlil_posix_tls_leaf_expectation_v1_t *local_leaf;
    uint8_t *cursor;
    uint64_t now_ms;
    ninlil_posix_tls_status_t status;

    if (port->attachment_payloads_ready != 0u) {
        return NINLIL_POSIX_TLS_OK;
    }
    if (port->peer_phase != NINLIL_WIFI_PHASE_PEER_SESSION
        || posix_tls_bytes_are_zero(
            port->session_ids.peer_session_id,
            sizeof(port->session_ids.peer_session_id))) {
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    status = posix_tls_clock_now_ms(port, &now_ms);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    authorization = &port->config.authorization;
    descriptor = &port->config.link_descriptor;
    local_leaf = &authorization->local_leaf;
    if (now_ms >= descriptor->attestation_expires_at_ms) {
        return NINLIL_POSIX_TLS_DENIED;
    }

    cursor = port->membership_payload;
    memcpy(cursor, local_leaf->runtime_id.bytes, 16u);
    cursor += 16u;
    posix_tls_store_u64_be(cursor, now_ms);
    cursor += 8u;
    posix_tls_store_u64_be(cursor, descriptor->attestation_expires_at_ms);
    cursor += 8u;
    memcpy(cursor, local_leaf->authority_id.bytes, 16u);
    cursor += 16u;
    posix_tls_store_u64_be(cursor, local_leaf->authority_term);
    cursor += 8u;
    memcpy(
        cursor, local_leaf->authorized_attachment_binding_digest, 32u);

    cursor = port->credential_payload;
    memcpy(cursor, authorization->credential_reference_digest, 32u);
    cursor += 32u;
    posix_tls_store_u64_be(cursor, authorization->credential_revision);
    cursor += 8u;
    posix_tls_store_u32_be(cursor, local_leaf->credential_generation);
    cursor += 4u;
    posix_tls_store_u32_be(cursor, local_leaf->revocation_generation);

    cursor = port->attachment_payload;
    memcpy(cursor, port->session_ids.peer_session_id, 16u);
    cursor += 16u;
    memcpy(cursor, local_leaf->runtime_id.bytes, 16u);
    cursor += 16u;
    memcpy(cursor, authorization->peer_leaf.runtime_id.bytes, 16u);
    cursor += 16u;
    memcpy(cursor, local_leaf->authority_id.bytes, 16u);
    cursor += 16u;
    posix_tls_store_u64_be(cursor, local_leaf->authority_term);
    cursor += 8u;
    memcpy(
        cursor, local_leaf->authorized_attachment_binding_digest, 32u);
    cursor += 32u;
    memcpy(cursor, authorization->credential_reference_digest, 32u);
    cursor += 32u;
    memcpy(cursor, descriptor->descriptor_digest, 32u);

    cursor = port->registry_payload;
    memcpy(cursor, descriptor->descriptor_digest, 32u);
    cursor += 32u;
    memcpy(cursor, local_leaf->authority_id.bytes, 16u);
    cursor += 16u;
    memcpy(cursor, authorization->registry_epoch_id.bytes, 16u);
    cursor += 16u;
    posix_tls_store_u64_be(cursor, descriptor->configuration_revision);
    cursor += 8u;
    memcpy(cursor, descriptor->configuration_digest, 32u);

    port->attachment_payload_lengths[0] =
        POSIX_TLS_MEMBERSHIP_PAYLOAD_BYTES;
    port->attachment_payload_lengths[1] =
        POSIX_TLS_CREDENTIAL_PAYLOAD_BYTES;
    port->attachment_payload_lengths[2] =
        POSIX_TLS_ATTACHMENT_PAYLOAD_BYTES;
    port->attachment_payload_lengths[3] = POSIX_TLS_REGISTRY_PAYLOAD_BYTES;
    port->attachment_stage = 0u;
    port->attachment_payloads_ready = 1u;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_map_lifecycle_storage_status(
    ninlil_wifi_status_t status)
{
    switch (status) {
    case NINLIL_WIFI_OK:
        return NINLIL_POSIX_TLS_OK;
    case NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN:
        return NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_WIFI_CORRUPT:
        return NINLIL_POSIX_TLS_CORRUPT;
    case NINLIL_WIFI_CAPACITY:
        return NINLIL_POSIX_TLS_CAPACITY;
    case NINLIL_WIFI_UNSUPPORTED:
        return NINLIL_POSIX_TLS_UNSUPPORTED;
    case NINLIL_WIFI_IO_ERROR:
    case NINLIL_WIFI_UNAVAILABLE:
        return NINLIL_POSIX_TLS_STORAGE;
    default:
        return NINLIL_POSIX_TLS_CORRUPT;
    }
}

static ninlil_posix_tls_status_t posix_tls_persist_lifecycle(
    struct ninlil_posix_tls_v1 *port,
    uint64_t availability_epoch,
    uint8_t available,
    uint8_t clean)
{
    uint8_t payload[NINLIL_POSIX_TLS_V1_LIFECYCLE_PAYLOAD_BYTES];
    ninlil_bytes_view_t payload_view;
    uint8_t *cursor = payload;
    ninlil_wifi_status_t wifi_status;

    if (port == NULL || availability_epoch == 0u || available > 1u
        || clean > 1u) {
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    posix_tls_store_u16_be(
        cursor, NINLIL_POSIX_TLS_V1_LIFECYCLE_FORMAT_VERSION);
    cursor += 2u;
    *cursor++ = clean;
    *cursor++ = available;
    posix_tls_store_u64_be(cursor, availability_epoch);
    cursor += 8u;
    memcpy(cursor, port->config.instance_id.bytes, 16u);
    cursor += 16u;
    memcpy(
        cursor, port->config.link_descriptor.descriptor_digest, 32u);
    cursor += 32u;
    posix_tls_store_u64_be(
        cursor, port->config.link_descriptor.configuration_revision);
    cursor += 8u;
    memcpy(
        cursor, port->config.link_descriptor.configuration_digest, 32u);
    cursor += 32u;
    if ((size_t)(cursor - payload) != sizeof(payload)) {
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    payload_view.data = payload;
    payload_view.length = (uint32_t)sizeof(payload);
    wifi_status = ninlil_posix_tls_v1_record_put_full_verify(
        &port->storage,
        port->storage.user,
        port->config.storage_namespace,
        NINLIL_POSIX_TLS_V1_RECORD_LIFECYCLE,
        payload_view);
    memset(payload, 0, sizeof(payload));
    return posix_tls_map_lifecycle_storage_status(wifi_status);
}

static int posix_tls_lifecycle_identity_matches(
    const struct ninlil_posix_tls_v1 *port,
    const ninlil_posix_tls_v1_lifecycle_record_t *record)
{
    return port != NULL && record != NULL
        && memcmp(
               &record->instance_id,
               &port->config.instance_id,
               sizeof(record->instance_id)) == 0
        && memcmp(
               record->descriptor_digest,
               port->config.link_descriptor.descriptor_digest,
               sizeof(record->descriptor_digest)) == 0
        && record->configuration_revision
            == port->config.link_descriptor.configuration_revision
        && memcmp(
               record->configuration_digest,
               port->config.link_descriptor.configuration_digest,
               sizeof(record->configuration_digest)) == 0;
}

static ninlil_posix_tls_status_t posix_tls_availability_transition(
    struct ninlil_posix_tls_v1 *port, uint8_t available)
{
    ninlil_fabric_link_state_v1_t candidate;
    ninlil_fabric_status_t fabric_status;
    ninlil_posix_tls_status_t status;
    uint32_t reason;

    available = available != 0u ? 1u : 0u;
    if (port->link_available == available) {
        return NINLIL_POSIX_TLS_OK;
    }
    if (port->state.availability_epoch == UINT64_MAX) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return NINLIL_POSIX_TLS_CAPACITY;
    }
    memset(&candidate, 0, sizeof(candidate));
    candidate.api_version = NINLIL_FABRIC_API_VERSION;
    candidate.struct_size = (uint16_t)sizeof(candidate);
    candidate.availability_epoch = port->state.availability_epoch + 1u;
    candidate.availability_clock_epoch_id =
        port->config.link_descriptor.attestation_clock_epoch_id;
    candidate.available_until_ms = available != 0u
        ? port->config.link_descriptor.attestation_expires_at_ms : 0u;
    candidate.available = available;

    status = posix_tls_persist_lifecycle(
        port, candidate.availability_epoch, available, 0u);
    if (status != NINLIL_POSIX_TLS_OK) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_STORAGE);
        return status;
    }

    if (port->registration_state == POSIX_TLS_REGISTRATION_ACTIVE) {
        if (port->registration.fabric == NULL
            || port->registration.fabric_registration == NULL) {
            posix_tls_close_network(port);
            posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
            return NINLIL_POSIX_TLS_CORRUPT;
        }
        fabric_status = ninlil_fabric_v1_link_availability_update(
            port->registration.fabric,
            &port->config.instance_id,
            &candidate);
        status = posix_tls_map_fabric_status(fabric_status);
        if (status != NINLIL_POSIX_TLS_OK) {
            reason = fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
                ? NINLIL_POSIX_TLS_REASON_STORAGE
                : NINLIL_POSIX_TLS_REASON_CONFIG;
            posix_tls_close_network(port);
            posix_tls_fence(port, reason);
            return status;
        }
    } else if (port->registration_state
                   != POSIX_TLS_REGISTRATION_NONE
               && port->registration_state
                   != POSIX_TLS_REGISTRATION_CONSUMED) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return NINLIL_POSIX_TLS_CORRUPT;
    }

    port->state.availability_epoch = candidate.availability_epoch;
    port->link_available = available;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_attachment_record_step(
    struct ninlil_posix_tls_v1 *port)
{
    ninlil_bytes_view_t payload;
    ninlil_posix_tls_v1_record_kind_t kind;
    ninlil_wifi_status_t wifi_status;

    memset(&payload, 0, sizeof(payload));
    if (port->attachment_payloads_ready == 0u
        || port->attachment_stage >= POSIX_TLS_ATTACHMENT_RECORD_COUNT) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_STORAGE);
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    switch (port->attachment_stage) {
    case 0u:
        kind = NINLIL_POSIX_TLS_V1_RECORD_MEMBERSHIP;
        payload.data = port->membership_payload;
        break;
    case 1u:
        kind = NINLIL_POSIX_TLS_V1_RECORD_CREDENTIAL;
        payload.data = port->credential_payload;
        break;
    case 2u:
        kind = NINLIL_POSIX_TLS_V1_RECORD_ATTACHMENT;
        payload.data = port->attachment_payload;
        break;
    case 3u:
        kind = NINLIL_POSIX_TLS_V1_RECORD_FABRIC_REGISTRY;
        payload.data = port->registry_payload;
        break;
    default:
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_STORAGE);
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    payload.length =
        port->attachment_payload_lengths[port->attachment_stage];
    wifi_status = ninlil_posix_tls_v1_record_put_full_verify(
        &port->storage,
        port->storage.user,
        port->config.storage_namespace,
        kind,
        payload);
    if (wifi_status != NINLIL_WIFI_OK) {
        ninlil_posix_tls_status_t status =
            posix_tls_map_wifi_status(wifi_status);
        if (wifi_status == NINLIL_WIFI_IO_ERROR
            || wifi_status == NINLIL_WIFI_UNAVAILABLE) {
            status = NINLIL_POSIX_TLS_STORAGE;
        }
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_STORAGE);
        return status;
    }
    port->attachment_stage += 1u;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_finish_attachment(
    struct ninlil_posix_tls_v1 *port)
{
    ninlil_wifi_attached_context_inputs_t inputs;
    uint8_t attached_context[NINLIL_WIFI_ATTACHED_CONTEXT_BYTES];
    uint64_t now_ms;
    ninlil_wifi_status_t wifi_status;
    ninlil_posix_tls_status_t status;

    if (port->attachment_payloads_ready == 0u
        || port->attachment_stage != POSIX_TLS_ATTACHMENT_RECORD_COUNT
        || port->peer_phase != NINLIL_WIFI_PHASE_PEER_SESSION
        || port->link_available != 0u) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    status = posix_tls_clock_now_ms(port, &now_ms);
    if (status != NINLIL_POSIX_TLS_OK
        || now_ms >= port->config.link_descriptor.attestation_expires_at_ms) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return status != NINLIL_POSIX_TLS_OK
            ? status : NINLIL_POSIX_TLS_DENIED;
    }
    wifi_status = ninlil_wifi_tls_post_handshake_accept(port->tls);
    if (wifi_status != NINLIL_WIFI_OK) {
        return posix_tls_note_connection_loss(port);
    }
    memset(&inputs, 0, sizeof(inputs));
    memcpy(
        inputs.peer_session_id,
        port->session_ids.peer_session_id,
        sizeof(inputs.peer_session_id));
    memcpy(
        inputs.attachment_authority_id,
        port->config.authorization.local_leaf.authority_id.bytes,
        sizeof(inputs.attachment_authority_id));
    memcpy(
        inputs.active_attachment_binding_digest,
        port->config.authorization.local_leaf
            .authorized_attachment_binding_digest,
        sizeof(inputs.active_attachment_binding_digest));
    wifi_status = ninlil_wifi_build_attached_context(
        &inputs, attached_context);
    if (wifi_status == NINLIL_WIFI_OK) {
        wifi_status = ninlil_wifi_tls_export_attached_session_id(
            port->tls,
            attached_context,
            port->session_ids.attached_session_id);
    }
    if (wifi_status != NINLIL_WIFI_OK
        || posix_tls_bytes_are_zero(
            port->session_ids.attached_session_id,
            sizeof(port->session_ids.attached_session_id))) {
        status = posix_tls_map_wifi_status(wifi_status);
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_TLS);
        return wifi_status == NINLIL_WIFI_OK
            ? NINLIL_POSIX_TLS_CORRUPT : status;
    }
    port->peer_phase = NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING;
    status = posix_tls_availability_transition(port, 1u);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    port->peer_phase = NINLIL_WIFI_PHASE_ATTACHED;
    port->next_tx_sequence = 0u;
    ninlil_wifi_rx_stream_set_session(
        &port->rx_stream, port->session_ids.attached_session_id, 0u);
    port->state.operational_state = NINLIL_POSIX_TLS_STATE_ATTACHED;
    port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_configure_tls(
    struct ninlil_posix_tls_v1 *port)
{
    ninlil_wifi_status_t status;

    if (port->tls_configured != 0u) {
        return NINLIL_POSIX_TLS_OK;
    }
    if (ninlil_wifi_tls_sizeof() > sizeof(port->tls_storage)) {
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return NINLIL_POSIX_TLS_CAPACITY;
    }
    memset(port->tls_storage, 0, sizeof(port->tls_storage));
    port->tls = (ninlil_wifi_tls_t *)(void *)port->tls_storage;
    status = ninlil_wifi_tls_init(
        port->tls,
        port->config.role == NINLIL_POSIX_TLS_ROLE_SERVER,
        &port->tls_paths);
    if (status == NINLIL_WIFI_OK) {
        port->tls_configured = 1u;
        port->close_network_done = 0u;
        return NINLIL_POSIX_TLS_OK;
    }
    if (status == NINLIL_WIFI_UNSUPPORTED) {
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return NINLIL_POSIX_TLS_UNSUPPORTED;
    }
    if (status == NINLIL_WIFI_CREDENTIAL
        || status == NINLIL_WIFI_DENIED) {
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_PEER_AUTHORIZATION);
        return NINLIL_POSIX_TLS_DENIED;
    }
    posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_TLS);
    return status == NINLIL_WIFI_TLS_FAILED ? NINLIL_POSIX_TLS_TLS
                                            : NINLIL_POSIX_TLS_CORRUPT;
}

static int posix_tls_leaf_matches(
    const ninlil_posix_tls_leaf_expectation_v1_t *expected,
    const ninlil_wifi_leaf_binding_t *actual,
    const uint8_t actual_spki[32])
{
    return expected != NULL && actual != NULL && actual_spki != NULL
        && actual->version == NINLIL_WIFI_LEAF_BINDING_VERSION
        && actual->role == (uint8_t)expected->role
        && memcmp(actual->runtime_id, expected->runtime_id.bytes, 16u) == 0
        && memcmp(actual_spki, expected->leaf_spki_sha256, 32u) == 0
        && memcmp(actual->authority_id, expected->authority_id.bytes, 16u) == 0
        && actual->authority_term == expected->authority_term
        && memcmp(
               actual->authorized_attachment_binding_digest,
               expected->authorized_attachment_binding_digest,
               32u)
            == 0
        && actual->credential_generation == expected->credential_generation
        && actual->revocation_generation == expected->revocation_generation;
}

static ninlil_wifi_status_t posix_tls_enter_peer_session(
    struct ninlil_posix_tls_v1 *port)
{
    const ninlil_posix_tls_leaf_expectation_v1_t *client_leaf;
    const ninlil_posix_tls_leaf_expectation_v1_t *server_leaf;
    ninlil_wifi_leaf_binding_t local_binding;
    ninlil_wifi_leaf_binding_t peer_binding;
    ninlil_wifi_peer_context_inputs_t inputs;
    uint8_t local_spki[32];
    uint8_t peer_spki[32];
    ninlil_wifi_status_t status;

    status = ninlil_wifi_tls_post_handshake_accept(port->tls);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    status = ninlil_wifi_tls_local_leaf_binding(
        port->tls, &local_binding);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    status = ninlil_wifi_tls_peer_leaf_binding(port->tls, &peer_binding);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    status = ninlil_wifi_tls_local_leaf_spki_sha256(
        port->tls, local_spki);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    status = ninlil_wifi_tls_peer_leaf_spki_sha256(port->tls, peer_spki);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    if (!posix_tls_leaf_matches(
            &port->config.authorization.local_leaf,
            &local_binding,
            local_spki)) {
        /* Local static root/certificate disagreement is not peer-rejectable. */
        return NINLIL_WIFI_CORRUPT;
    }
    if (!posix_tls_leaf_matches(
            &port->config.authorization.peer_leaf,
            &peer_binding,
            peer_spki)) {
        return NINLIL_WIFI_DENIED;
    }

    if (port->config.role == NINLIL_POSIX_TLS_ROLE_CLIENT) {
        client_leaf = &port->config.authorization.local_leaf;
        server_leaf = &port->config.authorization.peer_leaf;
    } else {
        client_leaf = &port->config.authorization.peer_leaf;
        server_leaf = &port->config.authorization.local_leaf;
    }
    memset(&inputs, 0, sizeof(inputs));
    memcpy(inputs.authority_id, client_leaf->authority_id.bytes, 16u);
    inputs.authority_term = client_leaf->authority_term;
    inputs.assignment_epoch = port->config.authorization.assignment_epoch;
    memcpy(inputs.tls_client_runtime_id, client_leaf->runtime_id.bytes, 16u);
    memcpy(inputs.tls_server_runtime_id, server_leaf->runtime_id.bytes, 16u);
    status = ninlil_wifi_build_peer_context(&inputs, port->peer_context);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    status = ninlil_wifi_tls_export_peer_session_id(
        port->tls,
        port->peer_context,
        port->session_ids.peer_session_id);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    port->peer_phase = NINLIL_WIFI_PHASE_PEER_SESSION;
    port->next_tx_sequence = 0u;
    ninlil_wifi_reconnect_note_success(&port->reconnect);
    return NINLIL_WIFI_OK;
}

static ninlil_posix_tls_status_t posix_tls_handle_auth_failure(
    struct ninlil_posix_tls_v1 *port, ninlil_wifi_status_t status)
{
    ninlil_posix_tls_status_t public_status;
    uint32_t reason;

    if (status == NINLIL_WIFI_CREDENTIAL || status == NINLIL_WIFI_DENIED) {
        public_status = NINLIL_POSIX_TLS_DENIED;
        reason = NINLIL_POSIX_TLS_REASON_PEER_AUTHORIZATION;
    } else if (status == NINLIL_WIFI_TLS_FAILED) {
        public_status = NINLIL_POSIX_TLS_TLS;
        reason = NINLIL_POSIX_TLS_REASON_TLS;
    } else {
        public_status = NINLIL_POSIX_TLS_CORRUPT;
        reason = NINLIL_POSIX_TLS_REASON_PEER_AUTHORIZATION;
    }
    if (port->config.role == NINLIL_POSIX_TLS_ROLE_SERVER
        && (status == NINLIL_WIFI_CREDENTIAL
            || status == NINLIL_WIFI_DENIED
            || status == NINLIL_WIFI_TLS_FAILED)) {
        /*
         * A rejected accepted connection is not authority over the server
         * listener.  Drop only that peer and remain available to authenticate
         * the next client; the next step rebuilds a fresh TLS context.
         */
        posix_tls_close_connection(port);
        port->state.operational_state = NINLIL_POSIX_TLS_STATE_LISTENING;
        port->state.reason = reason;
    } else {
        posix_tls_close_network(port);
        posix_tls_fence(port, reason);
    }
    return public_status;
}

static ninlil_posix_tls_status_t posix_tls_note_connection_loss(
    struct ninlil_posix_tls_v1 *port)
{
    uint64_t now_ms;
    ninlil_posix_tls_status_t status;

    if (port->link_available != 0u) {
        status = posix_tls_availability_transition(port, 0u);
        if (status != NINLIL_POSIX_TLS_OK) {
            return status;
        }
    }
    posix_tls_close_connection(port);
    port->reconnect_pending = 1u;
    if (port->config.role == NINLIL_POSIX_TLS_ROLE_SERVER) {
        port->state.operational_state = NINLIL_POSIX_TLS_STATE_LISTENING;
        port->state.reason = NINLIL_POSIX_TLS_REASON_IO;
        return NINLIL_POSIX_TLS_OK;
    }
    status = posix_tls_clock_now_ms(port, &now_ms);
    if (status != NINLIL_POSIX_TLS_OK) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        return status;
    }
    ninlil_wifi_reconnect_note_failure(&port->reconnect, now_ms);
    if (port->reconnect.not_before_mono_ms == UINT64_MAX) {
        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_IO);
        return NINLIL_POSIX_TLS_CAPACITY;
    }
    port->peer_phase = NINLIL_WIFI_PHASE_RECONNECT_WAIT;
    port->state.operational_state = NINLIL_POSIX_TLS_STATE_BACKOFF;
    port->state.reason = NINLIL_POSIX_TLS_REASON_IO;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_fail_data_path(
    struct ninlil_posix_tls_v1 *port,
    ninlil_posix_tls_status_t public_status)
{
    ninlil_posix_tls_status_t status;

    if (port->link_available != 0u) {
        status = posix_tls_availability_transition(port, 0u);
        if (status != NINLIL_POSIX_TLS_OK) {
            return status;
        }
    }
    posix_tls_close_network(port);
    posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_TLS);
    return public_status;
}

static ninlil_posix_tls_status_t posix_tls_tx_step(
    struct ninlil_posix_tls_v1 *port, uint32_t *out_work_done)
{
    size_t remaining;
    size_t write_length;
    size_t wrote = 0u;
    ninlil_wifi_status_t wifi_status;

    *out_work_done = 0u;
    if (port->tx_in_use == 0u || port->tx_terminal != 0u) {
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->tx_record_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || port->tx_record_length > sizeof(port->tx_record)
        || port->tx_record_offset >= port->tx_record_length) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    remaining = port->tx_record_length - port->tx_record_offset;
#if defined(NINLIL_POSIX_TLS_V1_TEST_HOOKS)
    if (port->test_fail_next_write_before_positive != 0u) {
        port->test_fail_next_write_before_positive = 0u;
        *out_work_done = 1u;
        return posix_tls_note_connection_loss(port);
    }
#endif
    write_length = remaining;
#if defined(NINLIL_POSIX_TLS_V1_TEST_HOOKS)
    if (port->test_tls_write_limit != 0u
        && write_length > port->test_tls_write_limit) {
        write_length = port->test_tls_write_limit;
    }
#endif
    wifi_status = ninlil_wifi_tls_write(
        port->tls,
        port->tx_record + port->tx_record_offset,
        write_length,
        &wrote);
    if (wrote > write_length) {
        port->tx_crossed_uncertain_boundary = 1u;
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    if (wrote != 0u) {
        port->tx_crossed_uncertain_boundary = 1u;
        port->tx_record_offset += wrote;
        *out_work_done = 1u;
    }
    if (port->tx_record_offset == port->tx_record_length) {
        if (wifi_status != NINLIL_WIFI_OK
            && wifi_status != NINLIL_WIFI_WOULD_BLOCK) {
            return posix_tls_note_connection_loss(port);
        }
        port->tx_terminal = 1u;
        port->tx_completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        return NINLIL_POSIX_TLS_OK;
    }
    if (wifi_status == NINLIL_WIFI_WOULD_BLOCK) {
        return wrote != 0u ? NINLIL_POSIX_TLS_OK
                           : NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
#if defined(NINLIL_POSIX_TLS_V1_TEST_HOOKS)
    if (wifi_status == NINLIL_WIFI_OK && wrote == write_length
        && write_length < remaining) {
        return NINLIL_POSIX_TLS_OK;
    }
#endif
    if (wifi_status == NINLIL_WIFI_CLOSED
        || wifi_status == NINLIL_WIFI_IO_ERROR
        || wifi_status == NINLIL_WIFI_TLS_FAILED) {
        *out_work_done = 1u;
        return posix_tls_note_connection_loss(port);
    }
    return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
}

static ninlil_posix_tls_status_t posix_tls_stage_rx_record(
    struct ninlil_posix_tls_v1 *port,
    const uint8_t *record,
    size_t record_length,
    uint32_t sequence)
{
    const uint8_t *payload = NULL;
    uint32_t payload_length = 0u;
    ninlil_wifi_status_t wifi_status;

    if (record == NULL || record_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || record_length > NINLIL_WIFI_NWB1_TOTAL_MAX) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    wifi_status = ninlil_wifi_nwb1_classify(
        record,
        record_length,
        port->session_ids.attached_session_id,
        1,
        sequence,
        &payload,
        &payload_length,
        NULL);
    if (wifi_status != NINLIL_WIFI_OK || payload == NULL
        || payload_length < NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || payload_length > sizeof(port->rx_packet)) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    memcpy(port->rx_packet, payload, payload_length);
    port->rx_packet_length = payload_length;
    port->rx_sequence = sequence;
    port->rx_ready = 1u;
    return NINLIL_POSIX_TLS_OK;
}

static ninlil_posix_tls_status_t posix_tls_rx_step(
    struct ninlil_posix_tls_v1 *port, uint32_t *out_work_done)
{
    uint8_t chunk[512];
    const uint8_t *record = NULL;
    size_t record_length = 0u;
    size_t capacity;
    size_t got = 0u;
    uint32_t sequence = 0u;
    ninlil_wifi_status_t wifi_status;

    *out_work_done = 0u;
    if (port->rx_ready != 0u || port->rx_loan_active != 0u) {
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->rx_stream.used > NINLIL_WIFI_NWB1_TOTAL_MAX) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    if (port->rx_stream.pending_record_len != 0u) {
        wifi_status = ninlil_wifi_rx_stream_feed(
            &port->rx_stream,
            NULL,
            0u,
            &record,
            &record_length,
            &sequence);
        if (wifi_status == NINLIL_WIFI_OK) {
            *out_work_done = 1u;
            return posix_tls_stage_rx_record(
                port, record, record_length, sequence);
        }
        if (wifi_status != NINLIL_WIFI_WOULD_BLOCK) {
            return posix_tls_fail_data_path(
                port, NINLIL_POSIX_TLS_CORRUPT);
        }
    }
    capacity = NINLIL_WIFI_NWB1_TOTAL_MAX - port->rx_stream.used;
    if (capacity == 0u) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    if (capacity > sizeof(chunk)) {
        capacity = sizeof(chunk);
    }
    wifi_status = ninlil_wifi_tls_read(port->tls, chunk, capacity, &got);
    if (wifi_status == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (wifi_status == NINLIL_WIFI_CLOSED
        || wifi_status == NINLIL_WIFI_IO_ERROR
        || wifi_status == NINLIL_WIFI_TLS_FAILED) {
        *out_work_done = 1u;
        return posix_tls_note_connection_loss(port);
    }
    if (wifi_status != NINLIL_WIFI_OK || got == 0u || got > capacity) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    *out_work_done = 1u;
    wifi_status = ninlil_wifi_rx_stream_feed(
        &port->rx_stream,
        chunk,
        got,
        &record,
        &record_length,
        &sequence);
    if (wifi_status == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_POSIX_TLS_OK;
    }
    if (wifi_status != NINLIL_WIFI_OK) {
        return posix_tls_fail_data_path(port, NINLIL_POSIX_TLS_CORRUPT);
    }
    return posix_tls_stage_rx_record(
        port, record, record_length, sequence);
}

static int posix_tls_provider_enter(
    struct ninlil_posix_tls_v1 *port, uint8_t callback_kind)
{
    uint64_t context_id;

    if (port == NULL || port->magic != POSIX_TLS_MAGIC
        || port->provider_in_call != 0u) {
        return 0;
    }
    if (port->in_call != 0u
        && !((port->controlled_call == POSIX_TLS_CONTROLLED_REGISTER
              && (callback_kind == POSIX_TLS_PROVIDER_CALLBACK_OPEN
                  || callback_kind == POSIX_TLS_PROVIDER_CALLBACK_STATE))
             || (port->controlled_call == POSIX_TLS_CONTROLLED_UNREGISTER
                 && (callback_kind == POSIX_TLS_PROVIDER_CALLBACK_STATE
                     || callback_kind
                         == POSIX_TLS_PROVIDER_CALLBACK_CLOSE)))) {
        return 0;
    }
    port->provider_in_call = 1u;
    context_id = port->execution.current_context_id(port->execution.user);
    if (context_id == 0u || context_id != port->owner_context_id) {
        port->provider_in_call = 0u;
        return 0;
    }
    return 1;
}

static void posix_tls_provider_leave(struct ninlil_posix_tls_v1 *port)
{
    port->provider_in_call = 0u;
}

static int posix_tls_provider_live_handle(
    const struct ninlil_posix_tls_v1 *port,
    ninlil_fabric_packet_link_handle_t handle)
{
    return handle == (ninlil_fabric_packet_link_handle_t)port
        && port->provider_open != 0u
        && (port->registration_state == POSIX_TLS_REGISTRATION_REGISTERING
            || port->registration_state == POSIX_TLS_REGISTRATION_ACTIVE
            || port->registration_state
                == POSIX_TLS_REGISTRATION_UNREGISTERING);
}

static ninlil_fabric_link_status_t posix_tls_provider_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;

    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (out_handle == NULL
        || !posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_OPEN)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (port->controlled_call != POSIX_TLS_CONTROLLED_REGISTER
        || port->registration_state != POSIX_TLS_REGISTRATION_REGISTERING
        || port->provider_open != 0u) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    port->provider_open = 1u;
    *out_handle = (ninlil_fabric_packet_link_handle_t)port;
    posix_tls_provider_leave(port);
    return NINLIL_FABRIC_LINK_OK;
}

static void posix_tls_provider_close(
    void *user, ninlil_fabric_packet_link_handle_t handle)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;

    if (!posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_CLOSE)) {
        return;
    }
    if (posix_tls_provider_live_handle(port, handle)) {
        posix_tls_terminalize_send_for_disconnect(port);
        if (port->tx_crossed_uncertain_boundary != 0u) {
            port->tx_disconnect_requested = 1u;
        }
        port->provider_open = 0u;
    }
    posix_tls_provider_leave(port);
}

static ninlil_fabric_link_status_t posix_tls_provider_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;
    const ninlil_tx_permit_t *permit;
    size_t encoded_length = 0u;
    uint64_t now_ms = 0u;
    ninlil_wifi_status_t wifi_status;

    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (out_token == NULL
        || !posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_IO)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (!posix_tls_provider_live_handle(port, handle)) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (port->registration_state != POSIX_TLS_REGISTRATION_ACTIVE
        || packet == NULL || packet->bytes == NULL
        || packet->api_version != NINLIL_FABRIC_API_VERSION
        || packet->struct_size != (uint16_t)sizeof(*packet)
        || packet->reserved_zero != 0u
        || packet->length < NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || packet->length > NINLIL_WIFI_NWB1_PAYLOAD_MAX
        || packet->length > port->config.link_descriptor.maximum_packet_bytes
        || packet->length
            > port->config.link_descriptor.maximum_transfer_bytes
        || posix_tls_id128_is_zero(&packet->transaction_id)
        || posix_tls_id128_is_zero(&packet->attempt_id)
        || posix_tls_id128_is_zero(&packet->selected_path_id)
        || packet->path_selection_epoch == 0u) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (port->tx_in_use != 0u) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (port->fenced != 0u || port->link_available == 0u
        || port->state.operational_state != NINLIL_POSIX_TLS_STATE_ATTACHED
        || port->peer_phase != NINLIL_WIFI_PHASE_ATTACHED) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    permit = packet->permit;
    if (permit == NULL || permit->abi_version != NINLIL_ABI_VERSION
        || permit->struct_size != (uint16_t)sizeof(*permit)
        || posix_tls_id128_is_zero(&permit->permit_id)
        || memcmp(&permit->attempt_id, &packet->attempt_id,
                  sizeof(permit->attempt_id)) != 0
        || permit->expires_at_ms == 0u
        || memcmp(&permit->clock_epoch_id,
                  &port->config.link_descriptor.attestation_clock_epoch_id,
                  sizeof(permit->clock_epoch_id)) != 0
        || posix_tls_clock_now_ms(port, &now_ms) != NINLIL_POSIX_TLS_OK
        || now_ms >= permit->expires_at_ms) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (port->next_tx_sequence == UINT32_MAX
        || port->next_tx_token_generation == 0u
        || port->next_tx_token_generation == UINT32_MAX
        || port->state.accepted_send_count == UINT64_MAX) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    wifi_status = ninlil_wifi_nwb1_encode(
        port->session_ids.attached_session_id,
        port->next_tx_sequence,
        packet->bytes,
        packet->length,
        port->tx_record,
        sizeof(port->tx_record),
        &encoded_length);
    if (wifi_status != NINLIL_WIFI_OK
        || encoded_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || encoded_length > sizeof(port->tx_record)) {
        memset(port->tx_record, 0, sizeof(port->tx_record));
        posix_tls_provider_leave(port);
        return wifi_status == NINLIL_WIFI_CORRUPT
            || wifi_status == NINLIL_WIFI_INVALID_ARGUMENT
            ? NINLIL_FABRIC_LINK_DENIED : NINLIL_FABRIC_LINK_CORRUPT;
    }
    port->tx_record_length = encoded_length;
    port->tx_record_offset = 0u;
    port->tx_sequence = port->next_tx_sequence;
    port->next_tx_sequence += 1u;
    port->tx_token_generation = port->next_tx_token_generation;
    port->next_tx_token_generation += 1u;
    port->tx_completion_kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    port->tx_in_use = 1u;
    port->tx_terminal = 0u;
    port->tx_crossed_uncertain_boundary = 0u;
    port->tx_disconnect_requested = 0u;
    port->state.accepted_send_count += 1u;
    *out_token = posix_tls_make_tx_token(port, port->tx_token_generation);
    port->tx_token_value = (uintptr_t)*out_token;
    posix_tls_provider_leave(port);
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t posix_tls_provider_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;
    if (out_completion != NULL) {
        memset(out_completion, 0, sizeof(*out_completion));
    }
    if (out_completion == NULL
        || !posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_IO)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (!posix_tls_provider_live_handle(port, handle)
        || !posix_tls_tx_token_matches(port, token)) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    out_completion->api_version = NINLIL_FABRIC_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    out_completion->kind = port->tx_terminal != 0u
        ? port->tx_completion_kind
        : NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    posix_tls_provider_leave(port);
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t posix_tls_provider_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;
    if (!posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_IO)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (!posix_tls_provider_live_handle(port, handle)
        || !posix_tls_tx_token_matches(port, token)) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (port->tx_terminal != 0u) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_OK;
    }
    port->tx_terminal = 1u;
    if (port->tx_crossed_uncertain_boundary != 0u) {
        port->tx_completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
        port->tx_disconnect_requested = 1u;
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    }
    port->tx_completion_kind =
        NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
    if (port->next_tx_sequence == port->tx_sequence + 1u) {
        port->next_tx_sequence = port->tx_sequence;
    }
    posix_tls_provider_leave(port);
    return NINLIL_FABRIC_LINK_OK;
}

static void posix_tls_provider_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;
    if (posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_IO)) {
        if (posix_tls_provider_live_handle(port, handle)
            && posix_tls_tx_token_matches(port, token)
            && port->tx_terminal != 0u) {
            memset(port->tx_record, 0, sizeof(port->tx_record));
            port->tx_record_length = 0u;
            port->tx_record_offset = 0u;
            port->tx_sequence = 0u;
            port->tx_token_generation = 0u;
            port->tx_token_value = 0u;
            port->tx_completion_kind = 0u;
            port->tx_in_use = 0u;
            port->tx_terminal = 0u;
            port->tx_crossed_uncertain_boundary = 0u;
        }
        posix_tls_provider_leave(port);
    }
}

static ninlil_fabric_link_status_t posix_tls_provider_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;

    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (out_bytes == NULL || out_length == NULL || out_receive_token == NULL
        || !posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_IO)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (!posix_tls_provider_live_handle(port, handle)) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (port->registration_state != POSIX_TLS_REGISTRATION_ACTIVE) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (port->rx_loan_active != 0u) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (port->rx_ready == 0u) {
        const ninlil_fabric_link_status_t empty_status =
            port->link_available != 0u && port->fenced == 0u
                && port->state.operational_state
                    == NINLIL_POSIX_TLS_STATE_ATTACHED
            ? NINLIL_FABRIC_LINK_EMPTY
            : NINLIL_FABRIC_LINK_UNAVAILABLE;

        posix_tls_provider_leave(port);
        return empty_status;
    }
    if (port->rx_packet_length < NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || port->rx_packet_length > sizeof(port->rx_packet)
        || port->next_rx_loan_generation == 0u
        || port->next_rx_loan_generation == UINT32_MAX
        || port->state.accepted_receive_count == UINT64_MAX) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    port->rx_loan_generation = port->next_rx_loan_generation;
    port->next_rx_loan_generation += 1u;
    port->rx_loan_active = 1u;
    port->state.accepted_receive_count += 1u;
    *out_bytes = port->rx_packet;
    *out_length = port->rx_packet_length;
    *out_receive_token = posix_tls_make_rx_token(
        port, port->rx_loan_generation);
    port->rx_token_value = (uintptr_t)*out_receive_token;
    posix_tls_provider_leave(port);
    return NINLIL_FABRIC_LINK_OK;
}

static void posix_tls_provider_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;

    if (posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_IO)) {
        if (posix_tls_provider_live_handle(port, handle)
            && posix_tls_rx_token_matches(port, receive_token)) {
            memset(port->rx_packet, 0, sizeof(port->rx_packet));
            port->rx_packet_length = 0u;
            port->rx_sequence = 0u;
            port->rx_loan_generation = 0u;
            port->rx_token_value = 0u;
            port->rx_ready = 0u;
            port->rx_loan_active = 0u;
        }
        posix_tls_provider_leave(port);
    }
}

static ninlil_fabric_link_status_t posix_tls_provider_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    struct ninlil_posix_tls_v1 *port =
        (struct ninlil_posix_tls_v1 *)user;
    uint32_t available;

    if (out_state != NULL) {
        memset(out_state, 0, sizeof(*out_state));
    }
    if (out_state == NULL
        || !posix_tls_provider_enter(
            port, POSIX_TLS_PROVIDER_CALLBACK_STATE)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (!posix_tls_provider_live_handle(port, handle)) {
        posix_tls_provider_leave(port);
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    out_state->api_version = NINLIL_FABRIC_API_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch = port->state.availability_epoch;
    out_state->availability_clock_epoch_id =
        port->config.link_descriptor.attestation_clock_epoch_id;
    available = port->link_available != 0u && port->fenced == 0u
        && port->state.operational_state == NINLIL_POSIX_TLS_STATE_ATTACHED
        ? 1u : 0u;
    out_state->available_until_ms = available != 0u
        ? port->config.link_descriptor.attestation_expires_at_ms : 0u;
    out_state->available = available;
    posix_tls_provider_leave(port);
    return NINLIL_FABRIC_LINK_OK;
}

static void posix_tls_install_provider_ops(
    struct ninlil_posix_tls_v1 *port)
{
    memset(&port->link_ops, 0, sizeof(port->link_ops));
    port->link_ops.api_version = NINLIL_FABRIC_API_VERSION;
    port->link_ops.struct_size = (uint16_t)sizeof(port->link_ops);
    port->link_ops.user = port;
    port->link_ops.open = posix_tls_provider_open;
    port->link_ops.close = posix_tls_provider_close;
    port->link_ops.start_send = posix_tls_provider_start_send;
    port->link_ops.poll_send = posix_tls_provider_poll_send;
    port->link_ops.cancel_send = posix_tls_provider_cancel_send;
    port->link_ops.release_send = posix_tls_provider_release_send;
    port->link_ops.receive_next = posix_tls_provider_receive_next;
    port->link_ops.release_received = posix_tls_provider_release_received;
    port->link_ops.state = posix_tls_provider_state;
}

#if defined(NINLIL_POSIX_TLS_V1_TEST_HOOKS)
ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_start_send(
    ninlil_posix_tls_v1_t *port,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    return posix_tls_provider_start_send(
        port, (ninlil_fabric_packet_link_handle_t)port, packet, out_token);
}

ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_poll_send(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    return posix_tls_provider_poll_send(
        port,
        (ninlil_fabric_packet_link_handle_t)port,
        token,
        out_completion);
}

ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_cancel_send(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_packet_token_t token)
{
    return posix_tls_provider_cancel_send(
        port, (ninlil_fabric_packet_link_handle_t)port, token);
}

void ninlil_posix_tls_v1_test_release_send(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_packet_token_t token)
{
    posix_tls_provider_release_send(
        port, (ninlil_fabric_packet_link_handle_t)port, token);
}

ninlil_fabric_link_status_t ninlil_posix_tls_v1_test_receive_next(
    ninlil_posix_tls_v1_t *port,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    return posix_tls_provider_receive_next(
        port,
        (ninlil_fabric_packet_link_handle_t)port,
        out_bytes,
        out_length,
        out_receive_token);
}

void ninlil_posix_tls_v1_test_release_received(
    ninlil_posix_tls_v1_t *port,
    void *receive_token)
{
    posix_tls_provider_release_received(
        port, (ninlil_fabric_packet_link_handle_t)port, receive_token);
}

void ninlil_posix_tls_v1_test_set_write_limit(
    ninlil_posix_tls_v1_t *port, size_t write_limit)
{
    if (port != NULL && port->magic == POSIX_TLS_MAGIC) {
        port->test_tls_write_limit = write_limit;
    }
}

void ninlil_posix_tls_v1_test_fail_next_write_before_positive(
    ninlil_posix_tls_v1_t *port)
{
    if (port != NULL && port->magic == POSIX_TLS_MAGIC) {
        port->test_fail_next_write_before_positive = 1u;
    }
}

int ninlil_posix_tls_v1_test_corrupt_pending_record(
    ninlil_posix_tls_v1_t *port)
{
    if (port == NULL || port->magic != POSIX_TLS_MAGIC
        || port->tx_in_use == 0u || port->tx_terminal != 0u
        || port->tx_record_offset != 0u
        || port->tx_record_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || port->tx_record_length > sizeof(port->tx_record)) {
        return 0;
    }
    port->tx_record[port->tx_record_length - 1u] ^= UINT8_C(0x01);
    return 1;
}

int ninlil_posix_tls_v1_test_set_pending_sequence(
    ninlil_posix_tls_v1_t *port, uint32_t sequence)
{
    uint32_t crc;

    if (port == NULL || port->magic != POSIX_TLS_MAGIC
        || sequence == UINT32_MAX || port->tx_in_use == 0u
        || port->tx_terminal != 0u || port->tx_record_offset != 0u
        || port->tx_record_length < NINLIL_WIFI_NWB1_TOTAL_MIN
        || port->tx_record_length > sizeof(port->tx_record)) {
        return 0;
    }
    posix_tls_store_u32_be(port->tx_record + 32u, sequence);
    memset(port->tx_record + 36u, 0, 4u);
    crc = ninlil_wifi_crc32c(port->tx_record, port->tx_record_length);
    posix_tls_store_u32_be(port->tx_record + 36u, crc);
    return 1;
}

int ninlil_posix_tls_v1_test_session_snapshot(
    ninlil_posix_tls_v1_t *port,
    uint8_t out_attached_session_id[16],
    uint32_t *out_next_tx_sequence,
    size_t *out_tx_offset,
    uint32_t *out_crossed_uncertain_boundary)
{
    if (port == NULL || port->magic != POSIX_TLS_MAGIC
        || out_attached_session_id == NULL || out_next_tx_sequence == NULL
        || out_tx_offset == NULL
        || out_crossed_uncertain_boundary == NULL) {
        return 0;
    }
    memcpy(
        out_attached_session_id,
        port->session_ids.attached_session_id,
        16u);
    *out_next_tx_sequence = port->next_tx_sequence;
    *out_tx_offset = port->tx_record_offset;
    *out_crossed_uncertain_boundary =
        port->tx_crossed_uncertain_boundary != 0u ? 1u : 0u;
    return 1;
}

int ninlil_posix_tls_v1_test_prime_coalesced_rx(
    ninlil_posix_tls_v1_t *port,
    const uint8_t *first_packet,
    uint32_t first_length,
    const uint8_t *second_packet,
    uint32_t second_length)
{
    uint8_t records[NINLIL_WIFI_NWB1_TOTAL_MIN * 2u];
    const uint8_t *record = NULL;
    size_t first_record_length = 0u;
    size_t second_record_length = 0u;
    size_t record_length = 0u;
    uint32_t sequence;
    ninlil_wifi_status_t wifi_status;

    if (port == NULL || port->magic != POSIX_TLS_MAGIC
        || first_packet == NULL || second_packet == NULL
        || first_length != NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || second_length != NINLIL_WIFI_NWB1_PAYLOAD_MIN
        || port->peer_phase != NINLIL_WIFI_PHASE_ATTACHED
        || port->rx_ready != 0u || port->rx_loan_active != 0u
        || port->rx_stream.used != 0u
        || port->rx_stream.pending_record_len != 0u
        || port->rx_stream.expected_sequence >= UINT32_MAX - 1u) {
        return 0;
    }
    sequence = port->rx_stream.expected_sequence;
    wifi_status = ninlil_wifi_nwb1_encode(
        port->session_ids.attached_session_id,
        sequence,
        first_packet,
        first_length,
        records,
        NINLIL_WIFI_NWB1_TOTAL_MIN,
        &first_record_length);
    if (wifi_status != NINLIL_WIFI_OK
        || first_record_length != NINLIL_WIFI_NWB1_TOTAL_MIN) {
        return 0;
    }
    wifi_status = ninlil_wifi_nwb1_encode(
        port->session_ids.attached_session_id,
        sequence + 1u,
        second_packet,
        second_length,
        records + first_record_length,
        NINLIL_WIFI_NWB1_TOTAL_MIN,
        &second_record_length);
    if (wifi_status != NINLIL_WIFI_OK
        || second_record_length != NINLIL_WIFI_NWB1_TOTAL_MIN) {
        return 0;
    }
    wifi_status = ninlil_wifi_rx_stream_feed(
        &port->rx_stream,
        records,
        first_record_length + second_record_length,
        &record,
        &record_length,
        &sequence);
    return wifi_status == NINLIL_WIFI_OK
        && posix_tls_stage_rx_record(
               port, record, record_length, sequence)
            == NINLIL_POSIX_TLS_OK;
}

int ninlil_posix_tls_v1_test_abandon_without_clean_marker(
    ninlil_posix_tls_v1_t *port)
{
    if (port == NULL || port->magic != POSIX_TLS_MAGIC) {
        return 0;
    }
    posix_tls_close_network(port);
    port->provider_open = 0u;
    return 1;
}
#endif

static ninlil_posix_tls_status_t posix_tls_enter(
    struct ninlil_posix_tls_v1 *port)
{
    uint64_t context_id;

    if (port == NULL || port->magic != POSIX_TLS_MAGIC) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    if (port->in_call != 0u || port->provider_in_call != 0u) {
        return NINLIL_POSIX_TLS_REENTRANT;
    }
    if ((port->lifecycle != POSIX_TLS_LIFECYCLE_OPEN
         && port->lifecycle != POSIX_TLS_LIFECYCLE_DRAINING
         && port->lifecycle != POSIX_TLS_LIFECYCLE_CLOSED)
        || port->owner_context_id == 0u
        || port->execution.current_context_id == NULL) {
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    port->in_call = 1u;
    context_id = port->execution.current_context_id(port->execution.user);
    if (context_id == 0u || context_id != port->owner_context_id) {
        port->in_call = 0u;
        return NINLIL_POSIX_TLS_WRONG_THREAD;
    }
    return NINLIL_POSIX_TLS_OK;
}

static void posix_tls_leave(struct ninlil_posix_tls_v1 *port)
{
    port->in_call = 0u;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_workspace_required(
    uint32_t *out_bytes, uint32_t *out_alignment)
{
    if (out_bytes != NULL) {
        *out_bytes = 0u;
    }
    if (out_alignment != NULL) {
        *out_alignment = 0u;
    }
    if (out_bytes == NULL || out_alignment == NULL
        || sizeof(struct ninlil_posix_tls_v1) > UINT32_MAX
        || alignof(struct ninlil_posix_tls_v1) > UINT32_MAX) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    *out_bytes = (uint32_t)sizeof(struct ninlil_posix_tls_v1);
    *out_alignment = (uint32_t)alignof(struct ninlil_posix_tls_v1);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_create(
    const ninlil_posix_tls_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_posix_tls_v1_t **out_port)
{
    struct ninlil_posix_tls_v1 *port;
    ninlil_posix_tls_config_v1_t config_copy;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_time_sample_t sample;
    char ca_path[1024];
    char cert_path[1024];
    char key_path[1024];
    uint8_t storage_namespace[127];
    size_t ca_path_bytes;
    size_t cert_path_bytes;
    size_t key_path_bytes;
    uint64_t owner_context_id;
    ninlil_posix_tls_v1_lifecycle_record_t lifecycle_record;
    ninlil_wifi_status_t wifi_status;
    ninlil_posix_tls_status_t status;
    int lifecycle_present = 0;
    int existing_private_state = 0;

    if (out_port != NULL) {
        *out_port = NULL;
    }
    if (out_port == NULL || workspace == NULL
        || ((uintptr_t)workspace % alignof(struct ninlil_posix_tls_v1)) != 0u
        || workspace_bytes < sizeof(struct ninlil_posix_tls_v1)
        || !posix_tls_config_valid(config)) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }

    storage = *config->storage;
    clock = *config->clock;
    execution = *config->execution;
    owner_context_id = execution.current_context_id(execution.user);
    if (owner_context_id == 0u) {
        return NINLIL_POSIX_TLS_WRONG_THREAD;
    }
    memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    if (clock.now(clock.user, &sample) != NINLIL_PORT_OK
        || sample.abi_version != NINLIL_ABI_VERSION
        || sample.struct_size != (uint16_t)sizeof(sample)
        || sample.trust != NINLIL_CLOCK_TRUSTED
        || sample.reserved_zero != 0u
        || posix_tls_id128_is_zero(&sample.clock_epoch_id)
        || !posix_tls_config_valid(config)
        || !posix_tls_descriptor_valid(config, &sample)) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }

    config_copy = *config;
    ca_path_bytes = strlen(config->tls_paths.ca_pem_path) + 1u;
    cert_path_bytes = strlen(config->tls_paths.cert_pem_path) + 1u;
    key_path_bytes = strlen(config->tls_paths.key_pem_path) + 1u;
    memcpy(ca_path, config->tls_paths.ca_pem_path, ca_path_bytes);
    memcpy(cert_path, config->tls_paths.cert_pem_path, cert_path_bytes);
    memcpy(key_path, config->tls_paths.key_pem_path, key_path_bytes);
    memcpy(storage_namespace, config->storage_namespace.data,
           config->storage_namespace.length);

    memset(workspace, 0, workspace_bytes);
    port = (struct ninlil_posix_tls_v1 *)workspace;
    port->magic = POSIX_TLS_MAGIC;
    port->lifecycle = POSIX_TLS_LIFECYCLE_OPEN;
    port->workspace_bytes = workspace_bytes;
    port->owner_context_id = owner_context_id;
    port->storage = storage;
    port->clock = clock;
    port->execution = execution;
    port->config = config_copy;
    memcpy(port->ca_path, ca_path, ca_path_bytes);
    memcpy(port->cert_path, cert_path, cert_path_bytes);
    memcpy(port->key_path, key_path, key_path_bytes);
    memcpy(port->storage_namespace, storage_namespace,
           config_copy.storage_namespace.length);
    port->config.tls_paths.ca_pem_path = port->ca_path;
    port->config.tls_paths.cert_pem_path = port->cert_path;
    port->config.tls_paths.key_pem_path = port->key_path;
    port->config.storage_namespace.data = port->storage_namespace;
    port->config.storage = &port->storage;
    port->config.clock = &port->clock;
    port->config.execution = &port->execution;
    port->state.api_version = NINLIL_POSIX_TLS_API_VERSION;
    port->state.struct_size = sizeof(port->state);
    port->state.operational_state = NINLIL_POSIX_TLS_STATE_CREATED;
    port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
    port->state.availability_epoch = 1u;
    ninlil_wifi_tcp_init(&port->listener);
    ninlil_wifi_tcp_init(&port->tcp);
    port->endpoint.address_kind = (uint8_t)config_copy.endpoint.address_kind;
    port->endpoint.port = config_copy.endpoint.port;
    port->endpoint.scope_id_u32 = config_copy.endpoint.scope_id;
    memcpy(port->endpoint.address, config_copy.endpoint.address,
           sizeof(port->endpoint.address));
    ninlil_wifi_reconnect_init(&port->reconnect);
    ninlil_wifi_reconnect_set_instance_id(
        &port->reconnect, config_copy.instance_id.bytes);
    (void)ninlil_wifi_endpoint_list_push(
        &port->reconnect.endpoints, &port->endpoint);
    port->tls = (ninlil_wifi_tls_t *)(void *)port->tls_storage;
    port->tls_paths.ca_pem_path = port->ca_path;
    port->tls_paths.cert_pem_path = port->cert_path;
    port->tls_paths.key_pem_path = port->key_path;
    port->peer_phase = NINLIL_WIFI_PHASE_CLOSED;
    port->next_tx_token_generation = 1u;
    port->next_rx_loan_generation = 1u;
    ninlil_wifi_rx_stream_init(&port->rx_stream);
    port->close_network_done = 1u;
    posix_tls_install_provider_ops(port);

    memset(&lifecycle_record, 0, sizeof(lifecycle_record));
    wifi_status = ninlil_posix_tls_v1_record_read_lifecycle(
        &port->storage,
        port->storage.user,
        port->config.storage_namespace,
        &lifecycle_record,
        &lifecycle_present,
        &existing_private_state);
    if (wifi_status == NINLIL_WIFI_CORRUPT) {
        port->restart_fenced = 1u;
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_STORAGE);
        *out_port = port;
        return NINLIL_POSIX_TLS_OK;
    }
    if (wifi_status != NINLIL_WIFI_OK) {
        status = posix_tls_map_lifecycle_storage_status(wifi_status);
        memset(workspace, 0, workspace_bytes);
        return status;
    }
    if ((lifecycle_present != 0
         && (lifecycle_record.clean != 1u
             || lifecycle_record.available != 0u
             || !posix_tls_lifecycle_identity_matches(
                 port, &lifecycle_record)))
        || (lifecycle_present == 0 && existing_private_state != 0)) {
        port->restart_fenced = 1u;
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_STORAGE);
        *out_port = port;
        return NINLIL_POSIX_TLS_OK;
    }
    if (lifecycle_present != 0) {
        port->state.availability_epoch =
            lifecycle_record.availability_epoch;
        port->link_available = lifecycle_record.available;
    }
    status = posix_tls_persist_lifecycle(
        port,
        port->state.availability_epoch,
        port->link_available,
        0u);
    memset(&lifecycle_record, 0, sizeof(lifecycle_record));
    if (status != NINLIL_POSIX_TLS_OK) {
        memset(workspace, 0, workspace_bytes);
        return status;
    }
    *out_port = port;
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_descriptor_snapshot(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor)
{
    ninlil_posix_tls_status_t status;

    if (out_descriptor != NULL) {
        memset(out_descriptor, 0, sizeof(*out_descriptor));
    }
    if (out_descriptor == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    *out_descriptor = port->config.link_descriptor;
    posix_tls_leave(port);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_register_fabric(
    ninlil_posix_tls_v1_t *port,
    ninlil_fabric_v1_t *fabric,
    ninlil_posix_tls_registration_v1_t **out_registration)
{
    ninlil_fabric_link_registration_v1_t *fabric_registration = NULL;
    ninlil_fabric_status_t fabric_status;
    ninlil_posix_tls_status_t status;

    if (out_registration != NULL) {
        *out_registration = NULL;
    }
    if (fabric == NULL || out_registration == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (port->lifecycle != POSIX_TLS_LIFECYCLE_OPEN) {
        posix_tls_leave(port);
        return port->lifecycle == POSIX_TLS_LIFECYCLE_CLOSED
            ? NINLIL_POSIX_TLS_CLOSED : NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->fenced != 0u || port->ever_registered != 0u
        || port->registration_state != POSIX_TLS_REGISTRATION_NONE) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_DENIED;
    }

    port->registration_state = POSIX_TLS_REGISTRATION_REGISTERING;
    port->controlled_call = POSIX_TLS_CONTROLLED_REGISTER;
    fabric_status = ninlil_fabric_v1_register_link(
        fabric, &port->config.link_descriptor, &port->link_ops,
        &fabric_registration);
    port->controlled_call = POSIX_TLS_CONTROLLED_NONE;
    status = posix_tls_map_fabric_status(fabric_status);

    if (fabric_status != NINLIL_FABRIC_OK) {
        port->registration_state = POSIX_TLS_REGISTRATION_NONE;
        port->provider_open = 0u;
        if (fabric_registration != NULL) {
            posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
            posix_tls_leave(port);
            return NINLIL_POSIX_TLS_CORRUPT;
        }
        if (fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
            || status == NINLIL_POSIX_TLS_CORRUPT) {
            posix_tls_fence(
                port, fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
                    ? NINLIL_POSIX_TLS_REASON_STORAGE
                    : NINLIL_POSIX_TLS_REASON_CONFIG);
        }
        posix_tls_leave(port);
        return status;
    }
    if (fabric_registration == NULL || port->provider_open == 0u) {
        port->registration_state = POSIX_TLS_REGISTRATION_NONE;
        port->provider_open = 0u;
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_CORRUPT;
    }

    memset(&port->registration, 0, sizeof(port->registration));
    port->registration.magic = POSIX_TLS_REGISTRATION_MAGIC;
    port->registration.generation = 1u;
    port->registration.port = port;
    port->registration.fabric = fabric;
    port->registration.fabric_registration = fabric_registration;
    port->registration_state = POSIX_TLS_REGISTRATION_ACTIVE;
    port->ever_registered = 1u;
    *out_registration = &port->registration;
    posix_tls_leave(port);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_unregister_begin(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_registration_v1_t *registration)
{
    ninlil_fabric_status_t fabric_status;
    ninlil_posix_tls_status_t status;

    if (registration == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (registration != &port->registration
        || registration->magic != POSIX_TLS_REGISTRATION_MAGIC
        || registration->port != port || registration->fabric == NULL
        || registration->fabric_registration == NULL
        || port->registration_state != POSIX_TLS_REGISTRATION_ACTIVE) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_CLOSED) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_CLOSED;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_DRAINING
        && (port->tx_in_use != 0u || port->rx_loan_active != 0u)) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->link_available != 0u) {
        status = posix_tls_availability_transition(port, 0u);
        if (status != NINLIL_POSIX_TLS_OK) {
            posix_tls_leave(port);
            return status;
        }
    }

    port->controlled_call = POSIX_TLS_CONTROLLED_UNREGISTER;
    fabric_status = ninlil_fabric_v1_unregister_begin(
        registration->fabric, registration->fabric_registration);
    port->controlled_call = POSIX_TLS_CONTROLLED_NONE;
    status = posix_tls_map_fabric_status(fabric_status);
    if (fabric_status == NINLIL_FABRIC_OK) {
        port->registration_state = POSIX_TLS_REGISTRATION_UNREGISTERING;
    } else if (fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
               || status == NINLIL_POSIX_TLS_CORRUPT) {
        posix_tls_fence(
            port, fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
                ? NINLIL_POSIX_TLS_REASON_STORAGE
                : NINLIL_POSIX_TLS_REASON_CONFIG);
    }
    posix_tls_leave(port);
    return status;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_unregister_poll(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_registration_v1_t *registration,
    uint32_t *out_done)
{
    ninlil_fabric_status_t fabric_status;
    ninlil_posix_tls_status_t status;
    uint32_t fabric_done = 0u;

    if (out_done != NULL) {
        *out_done = 0u;
    }
    if (registration == NULL || out_done == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (registration != &port->registration
        || registration->magic != POSIX_TLS_REGISTRATION_MAGIC
        || registration->port != port || registration->fabric == NULL
        || registration->fabric_registration == NULL
        || port->registration_state
            != POSIX_TLS_REGISTRATION_UNREGISTERING) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }

    port->controlled_call = POSIX_TLS_CONTROLLED_UNREGISTER;
    fabric_status = ninlil_fabric_v1_unregister_poll(
        registration->fabric, registration->fabric_registration,
        &fabric_done);
    port->controlled_call = POSIX_TLS_CONTROLLED_NONE;
    status = posix_tls_map_fabric_status(fabric_status);
    if (fabric_done > 1u
        || (fabric_status != NINLIL_FABRIC_OK && fabric_done != 0u)
        || (fabric_done == 1u && port->provider_open != 0u)) {
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_CORRUPT;
    }
    if (fabric_status != NINLIL_FABRIC_OK) {
        if (fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
            || status == NINLIL_POSIX_TLS_CORRUPT) {
            posix_tls_fence(
                port, fabric_status == NINLIL_FABRIC_COMMIT_UNKNOWN
                    ? NINLIL_POSIX_TLS_REASON_STORAGE
                    : NINLIL_POSIX_TLS_REASON_CONFIG);
        }
        posix_tls_leave(port);
        return status;
    }
    if (fabric_done != 0u) {
        memset(&port->registration, 0, sizeof(port->registration));
        port->registration_state = POSIX_TLS_REGISTRATION_CONSUMED;
        *out_done = 1u;
    }
    posix_tls_leave(port);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_step(
    ninlil_posix_tls_v1_t *port,
    uint32_t work_budget,
    uint32_t *out_work_done)
{
    ninlil_posix_tls_status_t status;
    uint32_t work_done = 0u;

    if (out_work_done != NULL) {
        *out_work_done = 0u;
    }
    if (out_work_done == NULL || work_budget == 0u
        || work_budget > POSIX_TLS_WORK_BUDGET_MAX) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_CLOSED) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_CLOSED;
    }
    if (port->fenced != 0u
        && port->lifecycle != POSIX_TLS_LIFECYCLE_DRAINING) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_DENIED;
    }

    while (work_done < work_budget) {
        ninlil_wifi_status_t wifi_status;

        if (port->lifecycle == POSIX_TLS_LIFECYCLE_DRAINING) {
            if (port->restart_fenced != 0u) {
                break;
            }
            if (port->close_marker_failed != 0u) {
                status = (ninlil_posix_tls_status_t)port->close_failure_status;
                work_done = 0u;
                break;
            }
            if (port->registration_state
                    == POSIX_TLS_REGISTRATION_REGISTERING
                || port->registration_state
                    == POSIX_TLS_REGISTRATION_ACTIVE
                || port->registration_state
                    == POSIX_TLS_REGISTRATION_UNREGISTERING
                || port->tx_in_use != 0u
                || port->rx_loan_active != 0u) {
                break;
            }
            if (port->link_available != 0u) {
                status = posix_tls_availability_transition(port, 0u);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            if (port->close_network_done == 0u) {
                posix_tls_close_network(port);
                work_done += 1u;
                continue;
            }
            if (port->close_clean_persisted == 0u) {
                port->close_marker_attempted = 1u;
                status = posix_tls_persist_lifecycle(
                    port, port->state.availability_epoch, 0u, 1u);
                if (status != NINLIL_POSIX_TLS_OK) {
                    port->close_marker_failed = 1u;
                    port->close_failure_status = status;
                    posix_tls_fence(
                        port, NINLIL_POSIX_TLS_REASON_STORAGE);
                    work_done = 0u;
                    break;
                }
                port->close_clean_persisted = 1u;
                work_done += 1u;
            }
            break;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_BACKOFF) {
            uint64_t now_ms;

            status = posix_tls_clock_now_ms(port, &now_ms);
            if (status != NINLIL_POSIX_TLS_OK) {
                posix_tls_close_network(port);
                posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
                work_done = 0u;
                break;
            }
            if (!ninlil_wifi_reconnect_ready(&port->reconnect, now_ms)) {
                break;
            }
            if (port->tls_configured == 0u) {
                status = posix_tls_configure_tls(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            wifi_status = ninlil_wifi_tcp_connect(&port->tcp, &port->endpoint);
            if (wifi_status != NINLIL_WIFI_OK
                && wifi_status != NINLIL_WIFI_WOULD_BLOCK) {
                status = posix_tls_note_connection_loss(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            port->connection_live = 1u;
            port->close_network_done = 0u;
            port->peer_phase = NINLIL_WIFI_PHASE_CONNECTING;
            port->state.operational_state = NINLIL_POSIX_TLS_STATE_CONNECTING;
            port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
            if (port->reconnect_pending != 0u) {
                if (port->state.reconnect_count == UINT32_MAX) {
                    posix_tls_close_network(port);
                    posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_IO);
                    status = NINLIL_POSIX_TLS_CAPACITY;
                    work_done = 0u;
                    break;
                }
                port->state.reconnect_count += 1u;
                port->reconnect_pending = 0u;
            }
            work_done += 1u;
            continue;
        }

        if (port->tls_configured == 0u
            && (port->state.operational_state
                    == NINLIL_POSIX_TLS_STATE_CREATED
                || port->state.operational_state
                    == NINLIL_POSIX_TLS_STATE_LISTENING)) {
            status = posix_tls_configure_tls(port);
            if (status != NINLIL_POSIX_TLS_OK) {
                work_done = 0u;
                break;
            }
            work_done += 1u;
            continue;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_CREATED) {
            if (port->config.role == NINLIL_POSIX_TLS_ROLE_SERVER) {
                uint16_t bound_port = 0u;

                wifi_status = ninlil_wifi_tcp_listen(
                    &port->listener, &port->endpoint, &bound_port);
                if (wifi_status != NINLIL_WIFI_OK || bound_port == 0u) {
                    posix_tls_close_network(port);
                    posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_IO);
                    status = NINLIL_POSIX_TLS_IO;
                    work_done = 0u;
                    break;
                }
                port->state.local_port = bound_port;
                port->close_network_done = 0u;
                port->state.operational_state =
                    NINLIL_POSIX_TLS_STATE_LISTENING;
                port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
                work_done += 1u;
                continue;
            }

            wifi_status = ninlil_wifi_tcp_connect(&port->tcp, &port->endpoint);
            if (wifi_status != NINLIL_WIFI_OK
                && wifi_status != NINLIL_WIFI_WOULD_BLOCK) {
                status = posix_tls_note_connection_loss(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            port->connection_live = 1u;
            port->close_network_done = 0u;
            port->peer_phase = NINLIL_WIFI_PHASE_CONNECTING;
            port->state.operational_state = NINLIL_POSIX_TLS_STATE_CONNECTING;
            port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
            work_done += 1u;
            continue;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_LISTENING) {
            wifi_status = ninlil_wifi_tcp_accept(
                &port->listener, &port->tcp);
            if (wifi_status == NINLIL_WIFI_WOULD_BLOCK) {
                break;
            }
            if (wifi_status != NINLIL_WIFI_OK) {
                posix_tls_close_network(port);
                posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_IO);
                status = NINLIL_POSIX_TLS_IO;
                work_done = 0u;
                break;
            }
            port->connection_live = 1u;
            port->close_network_done = 0u;
            port->peer_phase = NINLIL_WIFI_PHASE_CONNECTING;
            port->state.operational_state = NINLIL_POSIX_TLS_STATE_CONNECTING;
            port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
            if (port->reconnect_pending != 0u) {
                if (port->state.reconnect_count == UINT32_MAX) {
                    posix_tls_close_network(port);
                    posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_IO);
                    status = NINLIL_POSIX_TLS_CAPACITY;
                    work_done = 0u;
                    break;
                }
                port->state.reconnect_count += 1u;
                port->reconnect_pending = 0u;
            }
            work_done += 1u;
            continue;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_CONNECTING) {
            if (port->tcp.connected == 0) {
                wifi_status = ninlil_wifi_tcp_poll_connected(&port->tcp);
                if (wifi_status == NINLIL_WIFI_WOULD_BLOCK) {
                    break;
                }
                if (wifi_status != NINLIL_WIFI_OK) {
                    status = posix_tls_note_connection_loss(port);
                    if (status != NINLIL_POSIX_TLS_OK) {
                        work_done = 0u;
                        break;
                    }
                    work_done += 1u;
                    continue;
                }
                work_done += 1u;
                if (work_done == work_budget) {
                    break;
                }
            }
            wifi_status = ninlil_wifi_tls_attach_fd(port->tls, port->tcp.fd);
            if (wifi_status != NINLIL_WIFI_OK) {
                posix_tls_close_network(port);
                posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_TLS);
                status = NINLIL_POSIX_TLS_TLS;
                work_done = 0u;
                break;
            }
            port->tls_attached = 1u;
            port->peer_phase = NINLIL_WIFI_PHASE_HANDSHAKING;
            port->state.operational_state = NINLIL_POSIX_TLS_STATE_HANDSHAKING;
            port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
            work_done += 1u;
            continue;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_HANDSHAKING) {
            wifi_status = ninlil_wifi_tls_handshake(port->tls);
            if (wifi_status == NINLIL_WIFI_WOULD_BLOCK) {
                break;
            }
            if (wifi_status == NINLIL_WIFI_CLOSED
                || wifi_status == NINLIL_WIFI_IO_ERROR) {
                status = posix_tls_note_connection_loss(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            if (wifi_status == NINLIL_WIFI_OK) {
                port->peer_phase =
                    NINLIL_WIFI_PHASE_CHANNEL_AUTHENTICATED;
                wifi_status = posix_tls_enter_peer_session(port);
            }
            if (wifi_status != NINLIL_WIFI_OK) {
                status = posix_tls_handle_auth_failure(port, wifi_status);
                work_done = 0u;
                break;
            }
            status = posix_tls_prepare_attachment_payloads(port);
            if (status != NINLIL_POSIX_TLS_OK) {
                posix_tls_close_network(port);
                posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
                work_done = 0u;
                break;
            }
            port->state.operational_state =
                NINLIL_POSIX_TLS_STATE_AUTHENTICATED;
            port->state.reason = NINLIL_POSIX_TLS_REASON_NONE;
            work_done += 1u;
            break;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_AUTHENTICATED) {
            wifi_status = ninlil_wifi_tls_post_handshake_accept(port->tls);
            if (wifi_status != NINLIL_WIFI_OK) {
                status = posix_tls_note_connection_loss(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            if (port->attachment_stage
                < POSIX_TLS_ATTACHMENT_RECORD_COUNT) {
                status = posix_tls_attachment_record_step(port);
            } else {
                status = posix_tls_finish_attachment(port);
            }
            if (status != NINLIL_POSIX_TLS_OK) {
                work_done = 0u;
                break;
            }
            work_done += 1u;
            continue;
        }

        if (port->state.operational_state
            == NINLIL_POSIX_TLS_STATE_ATTACHED) {
            uint32_t data_work = 0u;

            if (port->tx_disconnect_requested != 0u) {
                status = posix_tls_note_connection_loss(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }
            wifi_status = ninlil_wifi_tls_post_handshake_accept(port->tls);
            if (wifi_status != NINLIL_WIFI_OK) {
                status = posix_tls_note_connection_loss(port);
                if (status != NINLIL_POSIX_TLS_OK) {
                    work_done = 0u;
                    break;
                }
                work_done += 1u;
                continue;
            }

            status = posix_tls_tx_step(port, &data_work);
            if (status == NINLIL_POSIX_TLS_OK && data_work != 0u) {
                work_done += data_work;
                continue;
            }
            if (status != NINLIL_POSIX_TLS_OK
                && status != NINLIL_POSIX_TLS_WOULD_BLOCK) {
                work_done = 0u;
                break;
            }

            status = posix_tls_rx_step(port, &data_work);
            if (status == NINLIL_POSIX_TLS_OK && data_work != 0u) {
                work_done += data_work;
                continue;
            }
            if (status != NINLIL_POSIX_TLS_OK
                && status != NINLIL_POSIX_TLS_WOULD_BLOCK) {
                work_done = 0u;
                break;
            }
            status = NINLIL_POSIX_TLS_OK;
            break;
        }

        posix_tls_close_network(port);
        posix_tls_fence(port, NINLIL_POSIX_TLS_REASON_CONFIG);
        status = NINLIL_POSIX_TLS_CORRUPT;
        work_done = 0u;
        break;
    }

    if (status == NINLIL_POSIX_TLS_OK) {
        *out_work_done = work_done;
    }
    posix_tls_leave(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    return work_done == 0u ? NINLIL_POSIX_TLS_WOULD_BLOCK
                           : NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_state(
    ninlil_posix_tls_v1_t *port,
    ninlil_posix_tls_state_v1_t *out_state)
{
    ninlil_posix_tls_status_t status;

    if (out_state != NULL) {
        memset(out_state, 0, sizeof(*out_state));
    }
    if (out_state == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    *out_state = port->state;
    posix_tls_leave(port);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_close_begin(
    ninlil_posix_tls_v1_t *port)
{
    ninlil_posix_tls_status_t status = posix_tls_enter(port);

    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_CLOSED) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_CLOSED;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_OPEN) {
        port->lifecycle = POSIX_TLS_LIFECYCLE_DRAINING;
        port->state.operational_state = NINLIL_POSIX_TLS_STATE_DRAINING;
        port->state.reason = NINLIL_POSIX_TLS_REASON_LOCAL_CLOSE;
        posix_tls_terminalize_send_for_disconnect(port);
    }
    posix_tls_leave(port);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_close_poll(
    ninlil_posix_tls_v1_t *port, uint32_t *out_done)
{
    ninlil_posix_tls_status_t status;

    if (out_done != NULL) {
        *out_done = 0u;
    }
    if (out_done == NULL) {
        return NINLIL_POSIX_TLS_INVALID_ARGUMENT;
    }
    status = posix_tls_enter(port);
    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_OPEN) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->registration_state == POSIX_TLS_REGISTRATION_REGISTERING
        || port->registration_state == POSIX_TLS_REGISTRATION_ACTIVE
        || port->registration_state
            == POSIX_TLS_REGISTRATION_UNREGISTERING) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->tx_in_use != 0u || port->rx_loan_active != 0u) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->close_marker_failed != 0u) {
        status = (ninlil_posix_tls_status_t)port->close_failure_status;
        posix_tls_leave(port);
        return status;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_DRAINING
        && port->restart_fenced == 0u
        && (port->close_network_done == 0u
            || port->close_clean_persisted == 0u)) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    if (port->lifecycle == POSIX_TLS_LIFECYCLE_DRAINING) {
        port->lifecycle = POSIX_TLS_LIFECYCLE_CLOSED;
        port->state.operational_state = NINLIL_POSIX_TLS_STATE_CLOSED;
        port->state.reason = NINLIL_POSIX_TLS_REASON_LOCAL_CLOSE;
    }
    *out_done = 1u;
    posix_tls_leave(port);
    return NINLIL_POSIX_TLS_OK;
}

ninlil_posix_tls_status_t ninlil_posix_tls_v1_destroy(
    ninlil_posix_tls_v1_t *port)
{
    uint32_t workspace_bytes;
    ninlil_posix_tls_status_t status = posix_tls_enter(port);

    if (status != NINLIL_POSIX_TLS_OK) {
        return status;
    }
    if (port->lifecycle != POSIX_TLS_LIFECYCLE_CLOSED
        || port->registration_state == POSIX_TLS_REGISTRATION_REGISTERING
        || port->registration_state == POSIX_TLS_REGISTRATION_ACTIVE
        || port->registration_state
            == POSIX_TLS_REGISTRATION_UNREGISTERING) {
        posix_tls_leave(port);
        return NINLIL_POSIX_TLS_WOULD_BLOCK;
    }
    workspace_bytes = port->workspace_bytes;
    memset(port, 0, workspace_bytes);
    return NINLIL_POSIX_TLS_OK;
}
