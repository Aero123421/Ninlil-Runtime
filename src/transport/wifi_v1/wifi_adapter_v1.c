#include "wifi_adapter_v1.h"

#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1

#include "wifi_fabric_adapter.h"
#include "wifi_session.h"
#include "wifi_sha256.h"

#include <stdalign.h>
#include <string.h>

#define WIFI_ADAPTER_MAGIC UINT32_C(0x57413150) /* WA1P */
#define WIFI_ADAPTER_LIFECYCLE_OPEN 1u
#define WIFI_ADAPTER_LIFECYCLE_DRAINING 2u
#define WIFI_ADAPTER_LIFECYCLE_CLOSED 3u

struct wifi_adapter_private_v1 {
    uint32_t magic;
    uint32_t lifecycle;
    uint64_t owner_context_id;
    uint8_t in_call;
    uint8_t descriptor_ready;
    uint8_t recovered_fenced;
    uint8_t reserved0;
    uint32_t reason;
    wifi_adapter_config_v1_t config;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    wifi_network_credential_provider_ops_v1_t network_provider;
    ninlil_wifi_session_t session;
    ninlil_wifi_fabric_link_user_t link_user;
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
    unsigned i;
    for (i = 0u; i < 8u; ++i) {
        p[7u - i] = (uint8_t)(value >> (i * 8u));
    }
}

static int config_digest_matches(const wifi_adapter_config_v1_t *config)
{
    static const uint8_t tag[] = "NINLIL-WIFI-ADAPTER-CONFIG-V1";
    uint8_t canonical[256];
    uint8_t digest[32];
    size_t n = 0u;

#define APPEND_BYTES(src_, length_)                                             \
    do {                                                                        \
        size_t append_n_ = (size_t)(length_);                                   \
        if (append_n_ > sizeof(canonical) - n) {                                \
            return 0;                                                           \
        }                                                                       \
        (void)memcpy(canonical + n, (src_), append_n_);                         \
        n += append_n_;                                                         \
    } while (0)

    APPEND_BYTES(tag, sizeof(tag) - 1u);
    put_u32_be(canonical + n, config->adapter_kind);
    n += 4u;
    put_u32_be(canonical + n, config->tls_role);
    n += 4u;
    APPEND_BYTES(config->instance_id.bytes, 16u);
    put_u64_be(canonical + n, config->configuration_revision);
    n += 8u;
    (void)memset(canonical + n, 0, 32u);
    n += 32u;
    APPEND_BYTES(config->local_runtime_id.bytes, 16u);
    APPEND_BYTES(config->expected_peer_runtime_id.bytes, 16u);
    put_u32_be(canonical + n, config->endpoint_address_kind);
    n += 4u;
    APPEND_BYTES(config->endpoint_address, 16u);
    put_u16_be(canonical + n, config->endpoint_port);
    n += 2u;
    put_u16_be(canonical + n, config->reserved_zero_u16);
    n += 2u;
    APPEND_BYTES(config->network_profile_id.bytes, 16u);
    put_u64_be(canonical + n, config->network_profile_revision);
    n += 8u;
    APPEND_BYTES(config->network_profile_digest, 32u);
    put_u32_be(canonical + n, config->reconnect_profile_id);
    n += 4u;
    put_u32_be(canonical + n, config->reserved_zero_u32);
    n += 4u;
    ninlil_wifi_sha256(canonical, n, digest);
    (void)memset(canonical, 0, sizeof(canonical));
    return memcmp(digest, config->configuration_digest, 32u) == 0;

#undef APPEND_BYTES
}

static int public_ops_header_ok(uint16_t version, uint16_t size, size_t exact)
{
    return version == NINLIL_ABI_VERSION && size == (uint16_t)exact;
}

static int base_ops_valid(const wifi_adapter_config_v1_t *config)
{
    const ninlil_storage_ops_t *s = config->storage;
    const ninlil_clock_ops_t *c = config->clock;
    const ninlil_execution_ops_t *e = config->execution;
    if (s == NULL || c == NULL || e == NULL) {
        return 0;
    }
    if (!public_ops_header_ok(s->abi_version, s->struct_size, sizeof(*s))
        || !public_ops_header_ok(c->abi_version, c->struct_size, sizeof(*c))
        || !public_ops_header_ok(e->abi_version, e->struct_size, sizeof(*e))) {
        return 0;
    }
    return s->open != NULL && s->close != NULL && s->begin != NULL
        && s->get != NULL && s->put != NULL && s->commit != NULL
        && c->now != NULL && e->current_context_id != NULL;
}

static wifi_private_adapter_status_v1_t validate_config(
    const wifi_adapter_config_v1_t *config)
{
    int endpoint_zero;
    if (config == NULL
        || config->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
        || config->struct_size != (uint16_t)sizeof(*config)
        || config->reserved_zero_u16 != 0u
        || config->reserved_zero_u32 != 0u
        || config->configuration_revision == 0u
        || bytes_zero(config->instance_id.bytes, 16u)
        || bytes_zero(config->configuration_digest, 32u)
        || bytes_zero(config->local_runtime_id.bytes, 16u)
        || bytes_zero(config->expected_peer_runtime_id.bytes, 16u)
        || config->endpoint_port == 0u
        || config->reconnect_profile_id != WIFI_RECONNECT_PROFILE_1
        || !base_ops_valid(config)) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (config->adapter_kind != WIFI_ADAPTER_KIND_POSIX_TCP
        && config->adapter_kind != WIFI_ADAPTER_KIND_ESP32S3_STA_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
    if (config->tls_role != WIFI_TLS_ROLE_CLIENT
        && config->tls_role != WIFI_TLS_ROLE_SERVER) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
    endpoint_zero = bytes_zero(config->endpoint_address, 16u);
    if (config->endpoint_address_kind == WIFI_ENDPOINT_IPV4) {
        if (bytes_zero(config->endpoint_address, 4u)
            || !bytes_zero(config->endpoint_address + 4u, 12u)) {
            return WIFI_PRIVATE_INVALID_ARGUMENT;
        }
    } else if (config->endpoint_address_kind == WIFI_ENDPOINT_IPV6) {
        if (endpoint_zero
            || (config->endpoint_address[0] == 0xfeu
                && (config->endpoint_address[1] & 0xc0u) == 0x80u)) {
            /*
             * The Proposed config has no scope_id field. Link-local IPv6
             * cannot be represented without inventing an authority field.
             */
            return WIFI_PRIVATE_UNSUPPORTED;
        }
    } else if (config->endpoint_address_kind == WIFI_ENDPOINT_LOCAL_ANY) {
        if (config->tls_role != WIFI_TLS_ROLE_SERVER || !endpoint_zero) {
            return WIFI_PRIVATE_INVALID_ARGUMENT;
        }
    } else {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
    if (config->tls_role == WIFI_TLS_ROLE_CLIENT
        && config->endpoint_address_kind == WIFI_ENDPOINT_LOCAL_ANY) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (config->adapter_kind == WIFI_ADAPTER_KIND_POSIX_TCP) {
        if (!bytes_zero(config->network_profile_id.bytes, 16u)
            || config->network_profile_revision != 0u
            || !bytes_zero(config->network_profile_digest, 32u)
            || config->network_credential_provider != NULL) {
            return WIFI_PRIVATE_INVALID_ARGUMENT;
        }
    } else {
        const wifi_network_credential_provider_ops_v1_t *p =
            config->network_credential_provider;
        if (bytes_zero(config->network_profile_id.bytes, 16u)
            || config->network_profile_revision == 0u
            || bytes_zero(config->network_profile_digest, 32u) || p == NULL
            || p->api_version != NINLIL_WIFI_PRIVATE_API_VERSION
            || p->struct_size != (uint16_t)sizeof(*p) || p->get == NULL
            || p->release == NULL) {
            return WIFI_PRIVATE_INVALID_ARGUMENT;
        }
    }
    if (!config_digest_matches(config)) {
        return WIFI_PRIVATE_DENIED;
    }
#if !defined(ESP_PLATFORM)
    if (config->adapter_kind == WIFI_ADAPTER_KIND_ESP32S3_STA_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
#else
    if (config->adapter_kind == WIFI_ADAPTER_KIND_POSIX_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
#endif
    return WIFI_PRIVATE_OK;
}

static wifi_private_adapter_status_v1_t adapter_enter(
    wifi_adapter_private_v1_t *adapter,
    int allow_closed)
{
    uint64_t current;
    if (adapter == NULL || adapter->magic != WIFI_ADAPTER_MAGIC) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (adapter->in_call != 0u) {
        return WIFI_PRIVATE_REENTRANT;
    }
    if (!allow_closed && adapter->lifecycle == WIFI_ADAPTER_LIFECYCLE_CLOSED) {
        return WIFI_PRIVATE_CLOSED;
    }
    /*
     * Raise the re-entry guard before invoking the execution callback. A
     * malicious/buggy callback that calls back into this adapter must observe
     * REENTRANT rather than recursively entering owner validation.
     */
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

static wifi_private_adapter_status_v1_t map_session_status(
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
    if (status == NINLIL_WIFI_UNSUPPORTED) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
    if (status == NINLIL_WIFI_CORRUPT) {
        return WIFI_PRIVATE_CORRUPT;
    }
    if (status == NINLIL_WIFI_IO_ERROR) {
        return WIFI_PRIVATE_STORAGE;
    }
    if (status == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN) {
        return WIFI_PRIVATE_STORAGE_COMMIT_UNKNOWN;
    }
    return WIFI_PRIVATE_UNAVAILABLE;
}

static wifi_private_adapter_status_v1_t adapter_refresh_trusted_clock(
    wifi_adapter_private_v1_t *adapter)
{
    ninlil_time_sample_t sample;
    ninlil_port_status_t port_status;
    ninlil_wifi_status_t wifi_status;
    ninlil_wifi_status_t fence_status;
    if (adapter == NULL) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    (void)memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    port_status = adapter->clock.now(adapter->clock.user, &sample);
    if (port_status != NINLIL_PORT_OK) {
        fence_status = ninlil_wifi_session_fence(&adapter->session);
        adapter->reason = WIFI_REASON_TRUSTED_CLOCK_INVALID;
        if (fence_status != NINLIL_WIFI_OK) {
            return map_session_status(fence_status);
        }
        return WIFI_PRIVATE_UNAVAILABLE;
    }
    wifi_status =
        ninlil_wifi_fabric_bind_trusted_clock(&adapter->link_user, &sample);
    if (wifi_status != NINLIL_WIFI_OK) {
        fence_status = ninlil_wifi_session_fence(&adapter->session);
        adapter->reason = WIFI_REASON_TRUSTED_CLOCK_INVALID;
        if (fence_status != NINLIL_WIFI_OK) {
            return map_session_status(fence_status);
        }
        return WIFI_PRIVATE_DENIED;
    }
    return WIFI_PRIVATE_OK;
}

static wifi_operational_state_v1_t operational_state(
    const wifi_adapter_private_v1_t *adapter)
{
    if (adapter->lifecycle == WIFI_ADAPTER_LIFECYCLE_DRAINING) {
        return WIFI_OPERATIONAL_DRAINING;
    }
    if (adapter->lifecycle == WIFI_ADAPTER_LIFECYCLE_CLOSED) {
        return WIFI_OPERATIONAL_DISABLED;
    }
    switch (adapter->session.phase) {
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
        return WIFI_OPERATIONAL_DISABLED;
    }
}

static int retained_work(const wifi_adapter_private_v1_t *adapter)
{
    uint32_t i;
    if (adapter->link_user.rx_loan_active != 0u) {
        return 1;
    }
    for (i = 0u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        if (adapter->link_user.send_slots[i].in_use != 0u) {
            return 1;
        }
    }
    return 0;
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
    if (adapter_kind != WIFI_ADAPTER_KIND_POSIX_TCP
        && adapter_kind != WIFI_ADAPTER_KIND_ESP32S3_STA_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
#if !defined(ESP_PLATFORM)
    if (adapter_kind != WIFI_ADAPTER_KIND_POSIX_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
#else
    if (adapter_kind != WIFI_ADAPTER_KIND_ESP32S3_STA_TCP) {
        return WIFI_PRIVATE_UNSUPPORTED;
    }
#endif
    if (sizeof(wifi_adapter_private_v1_t) > UINT32_MAX
        || alignof(wifi_adapter_private_v1_t) > UINT32_MAX) {
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
    wifi_private_adapter_status_v1_t status;
    wifi_adapter_private_v1_t *adapter;
    ninlil_time_sample_t now;
    ninlil_port_status_t port_status;
    ninlil_wifi_status_t session_status;
    ninlil_wifi_journal_attempt_t recovered;
    uint64_t owner;

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
    owner = config->execution->current_context_id(config->execution->user);
    if (owner == 0u) {
        return WIFI_PRIVATE_WRONG_THREAD;
    }
    (void)memset(&now, 0, sizeof(now));
    now.abi_version = NINLIL_ABI_VERSION;
    now.struct_size = (uint16_t)sizeof(now);
    port_status = config->clock->now(config->clock->user, &now);
    if (port_status != NINLIL_PORT_OK || now.trust != NINLIL_CLOCK_TRUSTED
        || bytes_zero(now.clock_epoch_id.bytes, 16u)
        || now.reserved_zero != 0u) {
        return WIFI_PRIVATE_DENIED;
    }

    adapter = (wifi_adapter_private_v1_t *)workspace;
    (void)memset(adapter, 0, sizeof(*adapter));
    adapter->magic = WIFI_ADAPTER_MAGIC;
    adapter->lifecycle = WIFI_ADAPTER_LIFECYCLE_OPEN;
    adapter->owner_context_id = owner;
    adapter->config = *config;
    adapter->storage = *config->storage;
    adapter->clock = *config->clock;
    adapter->execution = *config->execution;
    adapter->config.storage = &adapter->storage;
    adapter->config.clock = &adapter->clock;
    adapter->config.execution = &adapter->execution;
    if (config->network_credential_provider != NULL) {
        adapter->network_provider = *config->network_credential_provider;
        adapter->config.network_credential_provider =
            &adapter->network_provider;
    }
    ninlil_wifi_session_init(&adapter->session);
    (void)memset(&adapter->descriptor, 0, sizeof(adapter->descriptor));
    ninlil_wifi_fabric_packet_link_ops_init(
        &adapter->link_ops, &adapter->link_user);
    adapter->link_user.session = &adapter->session;
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &adapter->standalone_link_ops,
        &adapter->link_user,
        &adapter->standalone_scope,
        NULL);
    session_status =
        ninlil_wifi_fabric_bind_trusted_clock(&adapter->link_user, &now);
    if (session_status != NINLIL_WIFI_OK) {
        (void)memset(adapter, 0, sizeof(*adapter));
        return WIFI_PRIVATE_DENIED;
    }

    /*
     * Durable recovery never restores TLS/socket/exporter identity. Any prior
     * record is evidence of an interrupted session and is fenced before new
     * connection work. NOT_FOUND is a clean first create.
     */
    session_status = ninlil_wifi_session_bind_journal(
        &adapter->session,
        &adapter->storage,
        adapter->storage.user,
        NINLIL_WIFI_JOURNAL_NS);
    if (session_status != NINLIL_WIFI_OK) {
        (void)memset(adapter, 0, sizeof(*adapter));
        return map_session_status(session_status);
    }
    (void)memset(&recovered, 0, sizeof(recovered));
    session_status =
        ninlil_wifi_session_journal_recover(&adapter->session, &recovered);
    if (session_status == NINLIL_WIFI_OK) {
        if (recovered.attempt_id == UINT64_MAX
            || recovered.generation == UINT32_MAX) {
            ninlil_wifi_session_close(&adapter->session);
            (void)memset(adapter, 0, sizeof(*adapter));
            return WIFI_PRIVATE_CORRUPT;
        }
        adapter->session.attempt_id = recovered.attempt_id + 1u;
        adapter->session.session_fence_generation = recovered.generation + 1u;
        adapter->session.phase = NINLIL_WIFI_PHASE_FENCED;
        adapter->session.availability_epoch = 2u;
        adapter->recovered_fenced = 1u;
        adapter->reason = WIFI_REASON_RECOVERED_SESSION_FENCED;
    } else if (session_status != NINLIL_WIFI_UNAVAILABLE) {
        ninlil_wifi_session_close(&adapter->session);
        (void)memset(adapter, 0, sizeof(*adapter));
        return map_session_status(session_status);
    } else {
        adapter->reason = WIFI_REASON_ATTACHMENT_AUTHORITY_UNAVAILABLE;
    }
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
    /*
     * No descriptor is published until real Attachment authority supplies the
     * non-zero authenticated peer/authority/binding/attestation fields.
     */
    if (adapter->descriptor_ready == 0u) {
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
     * This legacy accessor is intentionally standalone.  Its scope has no
     * Fabric cookie, so open/start_send remain fail-closed even if the same
     * adapter is later registered through wifi_fabric_register_v1().
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
    if (adapter->descriptor_ready == 0u
        || adapter->session.phase != NINLIL_WIFI_PHASE_ATTACHED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_UNAVAILABLE;
    }
    if ((adapter->descriptor.capability_flags
            & NINLIL_FABRIC_CAP_CUSTODY)
        != 0u) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    if (!ninlil_wifi_fabric_packet_link_authority_prepare(
            &adapter->link_user, fabric_cookie)) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_DENIED;
    }
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
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
        || !ninlil_wifi_fabric_packet_link_authority_activate(
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
    if (adapter->link_user.open != 0u) {
        adapter->link_ops.close(
            adapter->link_ops.user,
            (ninlil_fabric_packet_link_handle_t)(uintptr_t)
                adapter->link_user.open_generation);
    }
    if (!ninlil_wifi_fabric_packet_link_authority_unbind(
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
        || !ninlil_wifi_fabric_packet_link_authority_drain(
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
        || adapter->link_user.open != 0u || retained_work(adapter)
        || !ninlil_wifi_fabric_packet_link_authority_unbind(
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
    uint32_t work = 0u;
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
    status = adapter_refresh_trusted_clock(adapter);
    if (status != WIFI_PRIVATE_OK) {
        adapter_leave(adapter);
        return status;
    }
    if (adapter->lifecycle == WIFI_ADAPTER_LIFECYCLE_DRAINING) {
        if (adapter->link_user.open != 0u && work < max_work_1_to_64) {
            adapter->link_ops.close(
                adapter->link_ops.user,
                (ninlil_fabric_packet_link_handle_t)(uintptr_t)
                    adapter->link_user.open_generation);
            work += 1u;
        }
        if (!retained_work(adapter) && work < max_work_1_to_64) {
            ninlil_wifi_session_close(&adapter->session);
            adapter->lifecycle = WIFI_ADAPTER_LIFECYCLE_CLOSED;
            work += 1u;
        }
    } else if (
        adapter->session.phase != NINLIL_WIFI_PHASE_CLOSED
        && adapter->session.phase != NINLIL_WIFI_PHASE_FENCED
        && adapter->session.phase != NINLIL_WIFI_PHASE_PEER_SESSION
        && adapter->session.phase
            != NINLIL_WIFI_PHASE_ATTACHMENT_NEGOTIATING) {
        status = map_session_status(
            ninlil_wifi_session_poll(&adapter->session));
        if (status != WIFI_PRIVATE_OK) {
            adapter_leave(adapter);
            return status;
        }
        work = 1u;
    }
    *out_work_done = work;
    adapter_leave(adapter);
    return WIFI_PRIVATE_OK;
}

wifi_private_adapter_status_v1_t wifi_state_v1(
    wifi_adapter_private_v1_t *adapter,
    wifi_operational_state_v1_t *out_operational_state,
    uint32_t *out_reason,
    uint64_t *out_epoch)
{
    wifi_private_adapter_status_v1_t status;
    if (out_operational_state != NULL) {
        *out_operational_state = 0u;
    }
    if (out_reason != NULL) {
        *out_reason = 0u;
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
    *out_reason = adapter->session.availability_epoch_exhausted
        ? WIFI_REASON_EPOCH_EXHAUSTED
        : adapter->reason;
    *out_epoch = adapter->session.availability_epoch;
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
    if (adapter->lifecycle == WIFI_ADAPTER_LIFECYCLE_CLOSED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_CLOSED;
    }
    if (adapter->fabric_registration_state != WIFI_FABRIC_REG_NONE) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_WOULD_BLOCK;
    }
    adapter->lifecycle = WIFI_ADAPTER_LIFECYCLE_DRAINING;
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
        adapter->lifecycle == WIFI_ADAPTER_LIFECYCLE_CLOSED ? 1u : 0u;
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
    if (adapter->lifecycle != WIFI_ADAPTER_LIFECYCLE_CLOSED) {
        adapter_leave(adapter);
        return WIFI_PRIVATE_WOULD_BLOCK;
    }
    /*
     * CLOSED has already released OS/storage/TLS state. Consume and zeroize the
     * exact caller-owned workspace; no callback may be invoked afterwards.
     */
    (void)memset(adapter, 0, sizeof(*adapter));
    return WIFI_PRIVATE_OK;
}

#endif /* NINLIL_ENABLE_PRIVATE_FABRIC_V1 */
