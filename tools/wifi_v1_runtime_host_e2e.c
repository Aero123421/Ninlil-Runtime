/*
 * Joined public Runtime -> private Fabric -> real Wi-Fi TLS/TCP acceptance.
 *
 * This test/tool translation unit deliberately starts at ninlil_submit().
 * It does not call the Fabric bearer send API directly and does not synthesize
 * a Receipt.  The server Runtime callback emits VERIFIED evidence; that
 * Receipt must traverse the same real TLS path back to the client Runtime.
 *
 * Private/test-only.  No installed ABI or physical-HIL claim.
 */
#include "wifi_v1_fabric_host_send.h"

#include "fabric_private_api.h"
#include "ninlil_posix_lab_platform.h"
#include "wifi_fabric_adapter.h"

#include <ninlil/runtime.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RUNTIME_WIFI_MAX_STEPS 30000u
#define RUNTIME_WIFI_PEER_CLOSE_MAX_STEPS 5000u

typedef struct runtime_wifi_context {
    ninlil_posix_lab_platform_t *platform;
    ninlil_platform_ops_t platform_ops;
    ninlil_fabric_private_t *fabric;
    const ninlil_bearer_ops_t *fabric_bearer;
    ninlil_fabric_registration_private_t *registration;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_wifi_fabric_link_user_t link_user;
    ninlil_wifi_fabric_call_scope_v1_t link_scope;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    struct {
        uint64_t next_sequence;
        uint8_t issuer_tag;
    } tx_gate;
    ninlil_tx_gate_ops_t tx_gate_ops;
    uint32_t authority_bound;
    _Alignas(max_align_t)
        uint8_t fabric_workspace[NINLIL_FABRIC_WORKSPACE_BYTES];
} runtime_wifi_context_t;

static const uint8_t g_runtime_wifi_payload[32] = {
    0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
    0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu,
    0xF0u, 0xE1u, 0xD2u, 0xC3u, 0xB4u, 0xA5u, 0x96u, 0x87u,
    0x78u, 0x69u, 0x5Au, 0x4Bu, 0x3Cu, 0x2Du, 0x1Eu, 0x0Fu
};
static const uint8_t g_runtime_wifi_evidence[] = "wifi-runtime-verified";
static uint32_t g_runtime_wifi_delivery_calls;

static void runtime_wifi_header(
    uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void runtime_wifi_id(ninlil_id128_t *id, uint8_t seed)
{
    uint32_t index;
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int runtime_wifi_id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void runtime_wifi_store_u64_be(uint8_t out[8], uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        out[7u - index] = (uint8_t)(value >> (index * 8u));
    }
}

static ninlil_tx_gate_status_t runtime_wifi_tx_gate_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    runtime_wifi_context_t *context = (runtime_wifi_context_t *)user;
    uint32_t index;

    if (out_permit != NULL) {
        (void)memset(out_permit, 0, sizeof(*out_permit));
    }
    if (context == NULL || request == NULL || now == NULL
        || out_permit == NULL
        || request->abi_version != NINLIL_ABI_VERSION
        || request->struct_size != (uint16_t)sizeof(*request)
        || request->message_kind < NINLIL_BEARER_MESSAGE_APPLICATION
        || request->message_kind > NINLIL_BEARER_MESSAGE_CANCEL_RESULT
        || runtime_wifi_id_is_zero(&request->transaction_id)
        || runtime_wifi_id_is_zero(&request->attempt_id)
        || now->abi_version != NINLIL_ABI_VERSION
        || now->struct_size != (uint16_t)sizeof(*now)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || runtime_wifi_id_is_zero(&now->clock_epoch_id)
        || context->tx_gate.next_sequence == UINT64_MAX
        || UINT64_MAX - now->now_ms < 60000u) {
        return NINLIL_TX_GATE_DENIED;
    }
    context->tx_gate.next_sequence += 1u;
    runtime_wifi_header(
        &out_permit->abi_version,
        &out_permit->struct_size,
        sizeof(*out_permit));
    for (index = 0u; index < 8u; ++index) {
        out_permit->permit_id.bytes[index] =
            (uint8_t)(context->tx_gate.issuer_tag + (uint8_t)index);
    }
    runtime_wifi_store_u64_be(
        &out_permit->permit_id.bytes[8], context->tx_gate.next_sequence);
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms = now->now_ms + 60000u;
    return NINLIL_TX_GATE_OK;
}

static void runtime_wifi_tx_gate_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static void runtime_wifi_tx_gate_init(
    runtime_wifi_context_t *context, int is_server)
{
    context->tx_gate.next_sequence = 0u;
    context->tx_gate.issuer_tag = is_server != 0 ? 0x51u : 0x31u;
    (void)memset(&context->tx_gate_ops, 0, sizeof(context->tx_gate_ops));
    runtime_wifi_header(
        &context->tx_gate_ops.abi_version,
        &context->tx_gate_ops.struct_size,
        sizeof(context->tx_gate_ops));
    context->tx_gate_ops.user = context;
    context->tx_gate_ops.acquire = runtime_wifi_tx_gate_acquire;
    context->tx_gate_ops.release_unused =
        runtime_wifi_tx_gate_release_unused;
}

static void runtime_wifi_digest(
    ninlil_digest256_t *digest, const uint8_t *bytes, uint32_t length)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    ninlil_fabric_private_sha256(bytes, length, digest->bytes);
}

static ninlil_runtime_config_t runtime_wifi_runtime_config(
    int is_server,
    const ninlil_id128_t *runtime_id)
{
    static const uint8_t client_namespace[] = "wifi-e2e-runtime-client";
    static const uint8_t server_namespace[] = "wifi-e2e-runtime-server";
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    runtime_wifi_header(
        &config.abi_version, &config.struct_size, sizeof(config));
    config.role =
        is_server != 0 ? NINLIL_ROLE_ENDPOINT : NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    config.runtime_id = *runtime_id;
    runtime_wifi_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    runtime_wifi_id(
        &config.local_identity.device_id,
        is_server != 0 ? 0x52u : 0x51u);
    runtime_wifi_id(
        &config.local_identity.installation_id,
        is_server != 0 ? 0x62u : 0x61u);
    runtime_wifi_id(
        &config.local_identity.site_domain_id,
        is_server != 0 ? 0x72u : 0x71u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data =
        is_server != 0 ? server_namespace : client_namespace;
    config.storage_namespace.length =
        is_server != 0
        ? (uint32_t)(sizeof(server_namespace) - 1u)
        : (uint32_t)(sizeof(client_namespace) - 1u);
    runtime_wifi_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 2u;
    config.limits.max_nonterminal_transactions = 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes =
        is_server != 0 ? 0u : 32768u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 16u;
    config.limits.max_nonterminal_deliveries = 8u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 16u;
    config.limits.max_retained_dispositions = 16u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static ninlil_service_descriptor_t runtime_wifi_service_descriptor(
    const ninlil_id128_t *application_id)
{
    static const uint8_t namespace_id[] = "org.ninlil.wifi.actual";
    static const uint8_t service_id[] = "verified-state";
    static const uint8_t schema_id[] = "verified-state-v1";
    static const uint8_t descriptor_material[] =
        "ninlil-wifi-runtime-actual-service-v1";
    ninlil_service_descriptor_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    runtime_wifi_header(
        &descriptor.abi_version,
        &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data = namespace_id;
    descriptor.namespace_id.length = sizeof(namespace_id) - 1u;
    descriptor.service_id.data = service_id;
    descriptor.service_id.length = sizeof(service_id) - 1u;
    descriptor.schema_id.data = schema_id;
    descriptor.schema_id.length = sizeof(schema_id) - 1u;
    descriptor.descriptor_revision = 1u;
    runtime_wifi_digest(
        &descriptor.descriptor_digest,
        descriptor_material,
        (uint32_t)(sizeof(descriptor_material) - 1u));
    descriptor.local_application_instance_id = *application_id;
    descriptor.schema_major = 1u;
    descriptor.schema_minor_min = 0u;
    descriptor.schema_minor_max = 0u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
    descriptor.logical_payload_limit = 1024u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 4u;
    descriptor.max_attempts_per_target_per_cycle = 8u;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 60000u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 5000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 60000u;
    return descriptor;
}

static ninlil_callback_action_t runtime_wifi_endpoint_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    (void)token;
    if (delivery == NULL || out_result == NULL
        || delivery->payload.data == NULL
        || delivery->payload.length != sizeof(g_runtime_wifi_payload)
        || memcmp(
               delivery->payload.data,
               g_runtime_wifi_payload,
               sizeof(g_runtime_wifi_payload))
            != 0) {
        return NINLIL_CALLBACK_DEFER;
    }
    g_runtime_wifi_delivery_calls += 1u;
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    out_result->evidence.data = g_runtime_wifi_evidence;
    out_result->evidence.length = sizeof(g_runtime_wifi_evidence) - 1u;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t runtime_wifi_endpoint_reconcile(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static void runtime_wifi_fill_descriptor(
    ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_id128_t *peer_runtime_id,
    const ninlil_time_sample_t *now)
{
    static const uint8_t descriptor_material[] =
        "wifi-runtime-actual-descriptor-v1";
    static const uint8_t security_material[] =
        "wifi-runtime-actual-security-v1";
    static const uint8_t attestation_material[] =
        "wifi-runtime-actual-attestation-v1";
    static const uint8_t attachment_material[] =
        "wifi-runtime-actual-attachment-v1";
    static const uint8_t configuration_material[] =
        "wifi-runtime-actual-configuration-v1";

    (void)memset(descriptor, 0, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    runtime_wifi_id(&descriptor->instance_id, 0x61u);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_EVIDENCE;
    descriptor->descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        descriptor_material,
        (uint32_t)(sizeof(descriptor_material) - 1u),
        descriptor->descriptor_digest);
    runtime_wifi_id(&descriptor->security_profile_id, 0x21u);
    descriptor->security_capability_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    ninlil_fabric_private_sha256(
        security_material,
        (uint32_t)(sizeof(security_material) - 1u),
        descriptor->security_binding_digest);
    descriptor->attestation_epoch = 1u;
    descriptor->attestation_clock_epoch_id = now->clock_epoch_id;
    descriptor->attestation_expires_at_ms = now->now_ms + 600000u;
    ninlil_fabric_private_sha256(
        attestation_material,
        (uint32_t)(sizeof(attestation_material) - 1u),
        descriptor->attestation_digest);
    descriptor->authenticated_peer_runtime_id = *peer_runtime_id;
    runtime_wifi_id(&descriptor->attachment_authority_id, 0x41u);
    ninlil_fabric_private_sha256(
        attachment_material,
        (uint32_t)(sizeof(attachment_material) - 1u),
        descriptor->attachment_binding_digest);
    descriptor->maximum_packet_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    descriptor->maximum_transfer_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    descriptor->latency_class = 10u;
    descriptor->cost_class = 20u;
    descriptor->reservation_capacity = NINLIL_WIFI_TX_QUEUE_DEPTH;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        configuration_material,
        (uint32_t)(sizeof(configuration_material) - 1u),
        descriptor->configuration_digest);
}

static void runtime_wifi_service_identity_digest(
    const ninlil_service_descriptor_t *descriptor, uint8_t out_digest[32])
{
    ninlil_fabric_private_nfl1_service_identity_digest(
        descriptor->namespace_id.data,
        (uint16_t)descriptor->namespace_id.length,
        descriptor->service_id.data,
        (uint16_t)descriptor->service_id.length,
        descriptor->schema_id.data,
        (uint16_t)descriptor->schema_id.length,
        descriptor->descriptor_revision,
        descriptor->descriptor_digest.bytes,
        descriptor->schema_major,
        descriptor->schema_minor_min,
        descriptor->family,
        out_digest);
}

static int runtime_wifi_install_policy(
    runtime_wifi_context_t *context,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *endpoint_runtime_id,
    const ninlil_id128_t *endpoint_application_id,
    const ninlil_time_sample_t *now)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t snapshot;
    ninlil_fabric_authority_binding_v1_t binding;
    uint8_t service_digest[32];
    uint32_t index;

    runtime_wifi_service_identity_digest(descriptor, service_digest);
    (void)memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    runtime_wifi_id(&policy.policy_id, 0x71u);
    policy.revision = 1u;
    (void)memcpy(
        policy.service_identity_digest, service_digest, sizeof(service_digest));
    policy.family = descriptor->family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_EVIDENCE;
    policy.required_security_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.maximum_latency_class = 50u;
    policy.maximum_cost_class = 50u;
    policy.minimum_packet_bytes = NINLIL_FABRIC_NFL1_STRUCTURAL_MIN;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.candidate_count = 1u;
    policy.candidates[0].instance_id = context->descriptor.instance_id;
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    if (ninlil_fabric_private_policy_put_v1(context->fabric, &policy)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    (void)memset(&snapshot, 0, sizeof(snapshot));
    if (ninlil_fabric_private_policy_snapshot_v1(
            context->fabric, &policy.policy_id, policy.revision, &snapshot)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }

    (void)memset(&binding, 0, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    runtime_wifi_id(&binding.binding_id, 0x81u);
    (void)memcpy(
        binding.service_identity_digest,
        service_digest,
        sizeof(service_digest));
    binding.family = descriptor->family;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    binding.endpoint_runtime_id = *endpoint_runtime_id;
    binding.target_runtime_id = *endpoint_runtime_id;
    binding.target_application_id = *endpoint_application_id;
    binding.policy_id = policy.policy_id;
    binding.policy_revision = policy.revision;
    (void)memcpy(
        binding.policy_digest,
        snapshot.canonical_digest_zero_on_input,
        sizeof(binding.policy_digest));
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    runtime_wifi_id(&binding.authority_id, 0x91u);
    binding.authority_term = 1u;
    binding.assignment_epoch = 1u;
    runtime_wifi_id(&binding.owner_scope_id, 0xA1u);
    for (index = 0u; index < sizeof(binding.owner_tuple_canonical); ++index) {
        binding.owner_tuple_canonical[index] =
            (uint8_t)(0xB1u + (uint8_t)index);
    }
    (void)memcpy(
        binding.owner_tuple_canonical,
        endpoint_runtime_id->bytes,
        sizeof(endpoint_runtime_id->bytes));
    (void)memcpy(
        binding.owner_tuple_canonical + sizeof(endpoint_runtime_id->bytes),
        endpoint_application_id->bytes,
        sizeof(endpoint_application_id->bytes));
    ninlil_fabric_private_owner_tuple_digest(
        binding.owner_tuple_canonical, binding.owner_tuple_digest);
    binding.authority_clock_epoch_id = now->clock_epoch_id;
    binding.lease_expires_at_ms = now->now_ms + 600000u;
    binding.assignment_revision = 1u;
    return ninlil_fabric_private_authority_put_v1(context->fabric, &binding)
        == NINLIL_FABRIC_PRIVATE_OK;
}

static int runtime_wifi_provider_released(
    const ninlil_wifi_fabric_link_user_t *user)
{
    uint32_t index;
    if (user->permit_live_count != 0u) {
        return 0;
    }
    for (index = 0u; index < NINLIL_WIFI_TX_QUEUE_DEPTH; ++index) {
        if (user->send_slots[index].in_use != 0u) {
            return 0;
        }
    }
    for (index = 0u; index < NINLIL_WIFI_FABRIC_PERMIT_LEDGER; ++index) {
        if (user->permit_ledger[index].state
            != NINLIL_WIFI_FABRIC_PERMIT_ST_EMPTY) {
            return 0;
        }
    }
    return 1;
}

static int runtime_wifi_context_close(runtime_wifi_context_t *context)
{
    const void *fabric_cookie;
    uint32_t done = 0u;
    uint32_t spin;
    int ok = 1;

    if (context == NULL) {
        return 0;
    }
    if (context->runtime != NULL) {
        if (ninlil_runtime_destroy(context->runtime) != NINLIL_OK) {
            ok = 0;
        }
        context->runtime = NULL;
    }
    fabric_cookie = context->fabric;
    if (context->fabric != NULL) {
        if (context->authority_bound != 0u
            && !ninlil_wifi_fabric_packet_link_authority_drain(
                &context->link_user, fabric_cookie)) {
            ok = 0;
        }
        if (ninlil_fabric_private_close_begin_v1(context->fabric)
            != NINLIL_FABRIC_PRIVATE_OK) {
            ok = 0;
        }
        for (spin = 0u; spin < 1024u && done == 0u; ++spin) {
            uint32_t work = 0u;
            if (ninlil_fabric_private_step_v1(
                    context->fabric, 64u, &work)
                    != NINLIL_FABRIC_PRIVATE_OK
                || ninlil_fabric_private_close_poll_v1(
                    context->fabric, &done)
                    != NINLIL_FABRIC_PRIVATE_OK) {
                ok = 0;
                break;
            }
        }
        if (done == 0u
            || ninlil_fabric_private_destroy_v1(context->fabric)
                != NINLIL_FABRIC_PRIVATE_OK) {
            ok = 0;
        }
        if (context->authority_bound != 0u
            && !ninlil_wifi_fabric_packet_link_authority_unbind(
                &context->link_user, fabric_cookie)) {
            ok = 0;
        }
        context->fabric = NULL;
    }
    if (context->platform != NULL) {
        ninlil_posix_lab_platform_destroy(context->platform);
        context->platform = NULL;
    }
    return ok;
}

static int runtime_wifi_context_init(
    runtime_wifi_context_t *context,
    ninlil_wifi_session_t *session,
    int is_server,
    const ninlil_id128_t *local_runtime_id,
    const ninlil_id128_t *peer_runtime_id,
    const ninlil_id128_t *local_application_id,
    const ninlil_id128_t *endpoint_runtime_id,
    const ninlil_id128_t *endpoint_application_id)
{
    ninlil_posix_lab_platform_config_t platform_config;
    ninlil_fabric_config_v1_t fabric_config;
    ninlil_runtime_config_t runtime_config;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_time_sample_t now;
    const ninlil_platform_ops_t *base_ops;

    (void)memset(context, 0, sizeof(*context));
    ninlil_posix_lab_platform_config_defaults(&platform_config);
    platform_config.role =
        is_server != 0 ? NINLIL_ROLE_ENDPOINT : NINLIL_ROLE_CONTROLLER;
    platform_config.environment = NINLIL_ENV_TEST;
    platform_config.execution_context_id = 1u;
    platform_config.entropy_seed =
        is_server != 0
        ? UINT64_C(0x5749464953455256)
        : UINT64_C(0x57494649434c4945);
    platform_config.entropy_stream_id = is_server != 0 ? 0x22u : 0x11u;
    platform_config.max_entries_per_namespace = 2048u;
    platform_config.max_bytes_per_namespace = 8u * 1024u * 1024u;
    context->platform = ninlil_posix_lab_platform_create(&platform_config);
    if (context->platform == NULL) {
        return 0;
    }
    base_ops = ninlil_posix_lab_platform_ops(context->platform);
    if (base_ops == NULL || base_ops->clock == NULL
        || base_ops->clock->now == NULL || base_ops->storage == NULL
        || base_ops->execution == NULL || base_ops->tx_gate == NULL) {
        return 0;
    }
    context->platform_ops = *base_ops;
    runtime_wifi_tx_gate_init(context, is_server);
    context->platform_ops.tx_gate = &context->tx_gate_ops;
    (void)memset(&now, 0, sizeof(now));
    runtime_wifi_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (base_ops->clock->now(base_ops->clock->user, &now) != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED
        || runtime_wifi_id_is_zero(&now.clock_epoch_id)) {
        return 0;
    }

    (void)memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = base_ops->storage;
    fabric_config.clock = base_ops->clock;
    fabric_config.execution = base_ops->execution;
    if (ninlil_fabric_private_create_v1(
            &fabric_config,
            context->fabric_workspace,
            (uint32_t)sizeof(context->fabric_workspace),
            &context->fabric)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    if (ninlil_fabric_private_bearer_ops_v1(
            context->fabric, &context->fabric_bearer)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    runtime_wifi_fill_descriptor(
        &context->descriptor, peer_runtime_id, &now);
    context->link_user.session = session;
    if (ninlil_wifi_fabric_bind_trusted_clock(&context->link_user, &now)
        != NINLIL_WIFI_OK) {
        return 0;
    }
    ninlil_wifi_fabric_packet_link_ops_init(
        &context->link_ops, &context->link_user);
    if (!ninlil_wifi_fabric_packet_link_authority_prepare(
            &context->link_user, context->fabric)) {
        return 0;
    }
    context->authority_bound = 1u;
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &context->link_ops,
        &context->link_user,
        &context->link_scope,
        context->fabric);
    if (ninlil_fabric_private_register_link_v1(
            context->fabric,
            &context->descriptor,
            &context->link_ops,
            &context->registration)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    if (!ninlil_wifi_fabric_packet_link_authority_activate(
            &context->link_user, context->fabric)) {
        return 0;
    }

    descriptor = runtime_wifi_service_descriptor(local_application_id);
    if (!runtime_wifi_install_policy(
            context,
            &descriptor,
            endpoint_runtime_id,
            endpoint_application_id,
            &now)) {
        return 0;
    }
    context->platform_ops.bearer = context->fabric_bearer;
    runtime_config = runtime_wifi_runtime_config(is_server, local_runtime_id);
    if (ninlil_runtime_create(
            &runtime_config, &context->platform_ops, &context->runtime)
        != NINLIL_OK) {
        return 0;
    }
    (void)memset(&callbacks, 0, sizeof(callbacks));
    runtime_wifi_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    if (is_server != 0) {
        callbacks.on_delivery = runtime_wifi_endpoint_delivery;
        callbacks.on_reconcile = runtime_wifi_endpoint_reconcile;
    }
    if (ninlil_service_register(
            context->runtime,
            &descriptor,
            &callbacks,
            &context->service)
        != NINLIL_OK) {
        return 0;
    }
    return 1;
}

static int runtime_wifi_step(runtime_wifi_context_t *context)
{
    ninlil_step_budget_t budget;
    ninlil_step_result_t result;
    ninlil_time_sample_t now;
    ninlil_wifi_status_t wifi_status;
    uint32_t work = 0u;

    (void)memset(&now, 0, sizeof(now));
    runtime_wifi_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (context->platform_ops.clock->now(
            context->platform_ops.clock->user, &now)
            != NINLIL_PORT_OK
        || ninlil_wifi_fabric_bind_trusted_clock(&context->link_user, &now)
            != NINLIL_WIFI_OK) {
        return 0;
    }
    wifi_status = ninlil_wifi_session_poll(context->link_user.session);
    if (wifi_status != NINLIL_WIFI_OK
        && wifi_status != NINLIL_WIFI_WOULD_BLOCK
        && wifi_status != NINLIL_WIFI_BACKPRESSURE) {
        return 0;
    }
    (void)memset(&budget, 0, sizeof(budget));
    runtime_wifi_header(
        &budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 8u;
    budget.max_callbacks = 8u;
    budget.max_state_transitions = 16u;
    budget.max_bearer_sends = 8u;
    (void)memset(&result, 0, sizeof(result));
    runtime_wifi_header(
        &result.abi_version, &result.struct_size, sizeof(result));
    if (ninlil_runtime_step(context->runtime, &budget, &result) != NINLIL_OK
        || ninlil_fabric_private_step_v1(context->fabric, 64u, &work)
            != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    wifi_status = ninlil_wifi_session_poll(context->link_user.session);
    if (wifi_status != NINLIL_WIFI_OK
        && wifi_status != NINLIL_WIFI_WOULD_BLOCK
        && wifi_status != NINLIL_WIFI_BACKPRESSURE) {
        return 0;
    }
    work = 0u;
    return ninlil_fabric_private_step_v1(context->fabric, 64u, &work)
        == NINLIL_FABRIC_PRIVATE_OK;
}

static int runtime_wifi_wait_for_peer_close(ninlil_wifi_session_t *session)
{
    uint32_t step;

    for (step = 0u; step < RUNTIME_WIFI_PEER_CLOSE_MAX_STEPS; ++step) {
        ninlil_wifi_status_t status = ninlil_wifi_session_poll(session);
        if (session->phase == NINLIL_WIFI_PHASE_CLOSED
            || session->phase == NINLIL_WIFI_PHASE_FENCED) {
            return 1;
        }
        if (status != NINLIL_WIFI_OK
            && status != NINLIL_WIFI_WOULD_BLOCK
            && status != NINLIL_WIFI_BACKPRESSURE) {
            return 0;
        }
        usleep(1000u);
    }
    (void)fprintf(stderr, "runtime Wi-Fi peer close timeout\n");
    return 0;
}

static int runtime_wifi_query_satisfied(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id)
{
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target;

    (void)memset(&target, 0, sizeof(target));
    runtime_wifi_header(
        &target.abi_version, &target.struct_size, sizeof(target));
    (void)memset(&snapshot, 0, sizeof(snapshot));
    runtime_wifi_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = &target;
    snapshot.target_capacity = 1u;
    if (ninlil_transaction_query(runtime, transaction_id, &snapshot)
        != NINLIL_OK) {
        return -1;
    }
    if (snapshot.state == NINLIL_TXN_TERMINAL
        && snapshot.outcome == NINLIL_OUTCOME_SATISFIED
        && target.latest_evidence >= NINLIL_EVIDENCE_VERIFIED) {
        return 1;
    }
    if (snapshot.state == NINLIL_TXN_TERMINAL) {
        (void)fprintf(
            stderr,
            "runtime Wi-Fi transaction terminal without satisfaction "
            "outcome=%u reason=%u target_outcome=%u target_reason=%u "
            "evidence=%u\n",
            (unsigned)snapshot.outcome,
            (unsigned)snapshot.reason,
            (unsigned)target.outcome,
            (unsigned)target.reason,
            (unsigned)target.latest_evidence);
        return -1;
    }
    return 0;
}

int ninlil_wifi_host_public_runtime_e2e(
    ninlil_wifi_session_t *session,
    int is_server)
{
    static const uint8_t idempotency_key[] =
        "wifi-public-runtime-e2e-idempotency-v1";
    runtime_wifi_context_t context;
    ninlil_id128_t client_runtime_id;
    ninlil_id128_t server_runtime_id;
    ninlil_id128_t client_application_id;
    ninlil_id128_t server_application_id;
    ninlil_submission_result_t submission_result;
    ninlil_id128_t transaction_id;
    uint32_t step;
    int success = 0;

    if (session == NULL || session->phase != NINLIL_WIFI_PHASE_ATTACHED
        || (is_server != 0 && is_server != 1)) {
        return -1;
    }
    runtime_wifi_id(&client_runtime_id, 0x31u);
    runtime_wifi_id(&server_runtime_id, 0x32u);
    runtime_wifi_id(&client_application_id, 0x71u);
    runtime_wifi_id(&server_application_id, 0x81u);
    (void)memset(&context, 0, sizeof(context));
    g_runtime_wifi_delivery_calls = 0u;
    (void)memset(&transaction_id, 0, sizeof(transaction_id));
    if (!runtime_wifi_context_init(
            &context,
            session,
            is_server,
            is_server != 0 ? &server_runtime_id : &client_runtime_id,
            is_server != 0 ? &client_runtime_id : &server_runtime_id,
            is_server != 0
                ? &server_application_id
                : &client_application_id,
            &server_runtime_id,
            &server_application_id)) {
        (void)fprintf(stderr, "runtime Wi-Fi context initialization failed\n");
        goto cleanup;
    }

    if (is_server == 0) {
        ninlil_submission_t submission;
        ninlil_concrete_target_t target;

        (void)memset(&target, 0, sizeof(target));
        runtime_wifi_header(
            &target.abi_version, &target.struct_size, sizeof(target));
        target.target_runtime_id = server_runtime_id;
        target.target_application_instance_id = server_application_id;
        (void)memset(&submission, 0, sizeof(submission));
        runtime_wifi_header(
            &submission.abi_version,
            &submission.struct_size,
            sizeof(submission));
        submission.schema_major = 1u;
        submission.schema_minor = 0u;
        submission.targets = &target;
        submission.target_count = 1u;
        submission.required_evidence = NINLIL_EVIDENCE_VERIFIED;
        submission.effect_deadline_ms = 60000u;
        submission.evidence_grace_ms = 5000u;
        submission.idempotency_key.data = idempotency_key;
        submission.idempotency_key.length = sizeof(idempotency_key) - 1u;
        submission.generation = 1u;
        submission.payload.data = g_runtime_wifi_payload;
        submission.payload.length = sizeof(g_runtime_wifi_payload);
        runtime_wifi_digest(
            &submission.content_digest,
            g_runtime_wifi_payload,
            sizeof(g_runtime_wifi_payload));
        (void)memset(&submission_result, 0, sizeof(submission_result));
        runtime_wifi_header(
            &submission_result.abi_version,
            &submission_result.struct_size,
            sizeof(submission_result));
        if (ninlil_submit(
                context.service, &submission, &submission_result)
                != NINLIL_OK
            || submission_result.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
            (void)fprintf(
                stderr,
                "runtime Wi-Fi public submit failed kind=%u reason=%u\n",
                (unsigned)submission_result.kind,
                (unsigned)submission_result.reason);
            goto cleanup;
        }
        transaction_id = submission_result.transaction_id;
    }

    for (step = 0u; step < RUNTIME_WIFI_MAX_STEPS; ++step) {
        if (!runtime_wifi_step(&context)) {
            (void)fprintf(
                stderr,
                "runtime Wi-Fi drive failed step=%u phase=%u tx=%llu rx=%llu\n",
                step,
                (unsigned)session->phase,
                (unsigned long long)context.link_user.accepted_send_count,
                (unsigned long long)context.link_user.accepted_receive_count);
            goto cleanup;
        }
        if (is_server == 0) {
            int query = runtime_wifi_query_satisfied(
                context.runtime, &transaction_id);
            if (query < 0) {
                goto cleanup;
            }
            if (query > 0
                && context.link_user.accepted_send_count >= 1u
                && context.link_user.accepted_receive_count >= 1u
                && runtime_wifi_provider_released(&context.link_user)) {
                success = 1;
                break;
            }
        } else if (
            g_runtime_wifi_delivery_calls == 1u
            && context.link_user.accepted_send_count >= 1u
            && context.link_user.accepted_receive_count >= 1u
            && runtime_wifi_provider_released(&context.link_user)) {
            success = 1;
            break;
        } else if (g_runtime_wifi_delivery_calls > 1u) {
            (void)fprintf(
                stderr,
                "runtime Wi-Fi duplicate application callback count=%u\n",
                g_runtime_wifi_delivery_calls);
            goto cleanup;
        }
        usleep(1000u);
    }

    if (success == 0) {
        (void)fprintf(
            stderr,
            "runtime Wi-Fi E2E timeout role=%s callbacks=%u tx=%llu rx=%llu "
            "released=%d phase=%u\n",
            is_server != 0 ? "server" : "client",
            g_runtime_wifi_delivery_calls,
            (unsigned long long)context.link_user.accepted_send_count,
            (unsigned long long)context.link_user.accepted_receive_count,
            runtime_wifi_provider_released(&context.link_user),
            (unsigned)session->phase);
        goto cleanup;
    }
    /*
     * The server's final Receipt has no application-level acknowledgement.
     * Keep the TLS session alive until the successful client closes it, so a
     * fast server cannot fence the client before its Runtime consumes the
     * already-received Receipt.  The shell harness checks both process exits.
     */
    if (is_server != 0 && !runtime_wifi_wait_for_peer_close(session)) {
        success = 0;
        goto cleanup;
    }
    if (is_server != 0) {
        (void)printf(
            "wifi_v1_host_e2e_driver: public Runtime/Fabric/TLS peer "
            "delivery verified exactly-once\n");
    } else {
        (void)printf(
            "wifi_v1_host_e2e_driver: public submit/Fabric/TLS/peer "
            "Runtime/Receipt satisfied\n");
    }

cleanup:
    if (!runtime_wifi_context_close(&context)) {
        success = 0;
    }
    return success != 0 ? 0 : -1;
}
