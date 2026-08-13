/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0029 instance-local composition acceptance:
 * two live Fabric/RRMP pairs select distinct paths without consulting or
 * contaminating the legacy process-global RRMP binding.
 */
#include "fabric_v1_test_common.h"
#include "fabric_v1_test_storage.h"
#include "rrmp_fabric_dispatch.h"
#include "rrmp_util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct isolation_pair {
    fabric_test_store_t store;
    fabric_test_provider_t provider;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric;
    const ninlil_bearer_ops_t *bearer;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_fabric_registration_private_t *registration;
    ninlil_bearer_handle_t bearer_handle;
    ninlil_bearer_message_t message;
    ninlil_tx_permit_t permit;
    ninlil_rrmp_owner_t *rrmp;
} isolation_pair_t;

static isolation_pair_t g_pair_a;
static isolation_pair_t g_pair_b;
_Alignas(16) static uint8_t g_fabric_ws_a[NINLIL_FABRIC_WORKSPACE_BYTES];
_Alignas(16) static uint8_t g_fabric_ws_b[NINLIL_FABRIC_WORKSPACE_BYTES];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_rrmp_ws_a[NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_rrmp_ws_b[NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES];

static void rrmp_fill_id(uint8_t id[16], uint8_t seed)
{
    fabric_test_pattern(id, seed, 16u);
}

static void fill_descriptor(
    ninlil_fabric_link_descriptor_v1_t *descriptor, uint8_t instance_seed)
{
    ninlil_fabric_private_memzero(descriptor, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    fabric_test_id(&descriptor->instance_id, instance_seed);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = 0x4fu;
    descriptor->descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-descriptor-v1",
        29u,
        descriptor->descriptor_digest);
    fabric_test_id(&descriptor->security_profile_id, 0x21u);
    descriptor->security_capability_flags = 0x0fu;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-binding-v1",
        26u,
        descriptor->security_binding_digest);
    descriptor->attestation_epoch = 5u;
    fabric_test_id(&descriptor->attestation_clock_epoch_id, 0xa1u);
    descriptor->attestation_expires_at_ms = 300000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-attestation-v1",
        30u,
        descriptor->attestation_digest);
    fabric_test_id(&descriptor->authenticated_peer_runtime_id, 0x31u);
    fabric_test_id(&descriptor->attachment_authority_id, 0x41u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-attachment-binding-v1",
        28u,
        descriptor->attachment_binding_digest);
    descriptor->maximum_packet_bytes = 1925u;
    descriptor->maximum_transfer_bytes = 1925u;
    descriptor->latency_class = 10u;
    descriptor->cost_class = 20u;
    descriptor->reservation_capacity = 8u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-config-v1",
        25u,
        descriptor->configuration_digest);
}

static void fill_message(ninlil_bearer_message_t *message, uint8_t id_offset)
{
    uint8_t digest[32];
    ninlil_fabric_private_memzero(message, sizeof(*message));
    message->abi_version = NINLIL_ABI_VERSION;
    message->struct_size = (uint16_t)sizeof(*message);
    message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    fabric_test_id(&message->transaction_id, (uint8_t)(0x10u + id_offset));
    fabric_test_id(&message->attempt_id, (uint8_t)(0x20u + id_offset));
    message->source.abi_version = NINLIL_ABI_VERSION;
    message->source.struct_size = (uint16_t)sizeof(message->source);
    fabric_test_id(&message->source.runtime_id, 0x30u);
    fabric_test_id(&message->source.application_instance_id, 0x40u);
    message->source.local_identity.abi_version = NINLIL_ABI_VERSION;
    message->source.local_identity.struct_size =
        (uint16_t)sizeof(message->source.local_identity);
    fabric_test_id(&message->source.local_identity.device_id, 0x50u);
    fabric_test_id(&message->source.local_identity.installation_id, 0x60u);
    fabric_test_id(&message->source.local_identity.site_domain_id, 0x70u);
    message->source.local_identity.binding_epoch = 7u;
    message->source.local_identity.membership_epoch = 9u;
    message->source.local_identity.flags = 7u;
    message->target.abi_version = NINLIL_ABI_VERSION;
    message->target.struct_size = (uint16_t)sizeof(message->target);
    fabric_test_id(&message->target.target_runtime_id, 0x80u);
    fabric_test_id(&message->target.target_application_instance_id, 0x90u);
    fabric_test_id(&message->target.device_id, 0xa0u);
    fabric_test_id(&message->target.installation_id, 0xb0u);
    fabric_test_id(&message->target.site_domain_id, 0xc0u);
    message->target.binding_epoch = 11u;
    message->target.membership_epoch = 13u;
    message->target.flags = 7u;
    message->service.abi_version = NINLIL_ABI_VERSION;
    message->service.struct_size = (uint16_t)sizeof(message->service);
    message->service.namespace_id.length = 1u;
    message->service.namespace_id.bytes[0] = (uint8_t)'n';
    message->service.service_id.length = 1u;
    message->service.service_id.bytes[0] = (uint8_t)'s';
    message->service.schema_id.length = 1u;
    message->service.schema_id.bytes[0] = (uint8_t)'x';
    message->service.descriptor_revision = 23u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-descriptor", 24u, digest);
    message->service.descriptor_digest.algorithm = 1u;
    (void)memcpy(message->service.descriptor_digest.bytes, digest, 32u);
    message->service.schema_major = 1u;
    message->service.schema_minor = 0u;
    message->service.family = NINLIL_FAMILY_DESIRED_STATE;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-content", 21u, digest);
    message->content_digest.algorithm = 1u;
    (void)memcpy(message->content_digest.bytes, digest, 32u);
    message->generation = 29u;
    fabric_test_id(&message->deadline_clock_epoch_id, 0xa1u);
    message->absolute_effect_deadline_ms = 200000u;
    message->evidence_grace_ms = 5000u;
    message->required_evidence = 3u;
}

static int put_policy_and_authority(
    isolation_pair_t *pair, uint8_t path_seed, uint8_t record_seed)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t policy_snapshot;
    ninlil_fabric_authority_binding_v1_t binding;
    uint8_t service_digest[32];

    ninlil_fabric_private_nfl1_service_identity_digest(
        pair->message.service.namespace_id.bytes,
        pair->message.service.namespace_id.length,
        pair->message.service.service_id.bytes,
        pair->message.service.service_id.length,
        pair->message.service.schema_id.bytes,
        pair->message.service.schema_id.length,
        pair->message.service.descriptor_revision,
        pair->message.service.descriptor_digest.bytes,
        pair->message.service.schema_major,
        pair->message.service.schema_minor,
        pair->message.service.family,
        service_digest);

    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, record_seed);
    policy.revision = 3u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = pair->message.service.family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = 0x02u;
    policy.required_security_flags = 0x0fu;
    policy.maximum_latency_class = 50u;
    policy.maximum_cost_class = 50u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 100u;
    policy.candidate_count = 1u;
    fabric_test_id(&policy.candidates[0].instance_id, path_seed);
    policy.candidates[0].rank = 10u;
    policy.candidates[0].reservation_units = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(pair->fabric, &policy),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            pair->fabric, &policy.policy_id, policy.revision, &policy_snapshot),
        NINLIL_FABRIC_PRIVATE_OK);

    ninlil_fabric_private_memzero(&binding, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    fabric_test_id(&binding.binding_id, (uint8_t)(record_seed + 1u));
    (void)memcpy(binding.service_identity_digest, service_digest, 32u);
    binding.family = pair->message.service.family;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
    fabric_test_id(&binding.target_runtime_id, 0x80u);
    fabric_test_id(&binding.target_application_id, 0x90u);
    binding.policy_id = policy.policy_id;
    binding.policy_revision = policy.revision;
    (void)memcpy(
        binding.policy_digest,
        policy_snapshot.canonical_digest_zero_on_input,
        32u);
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    fabric_test_id(&binding.authority_id, (uint8_t)(record_seed + 2u));
    binding.authority_term = 17u;
    binding.assignment_epoch = 19u;
    fabric_test_id(&binding.owner_scope_id, (uint8_t)(record_seed + 3u));
    fabric_test_pattern(binding.owner_tuple_canonical, record_seed, 200u);
    ninlil_fabric_private_owner_tuple_digest(
        binding.owner_tuple_canonical, binding.owner_tuple_digest);
    fabric_test_id(&binding.authority_clock_epoch_id, 0xa1u);
    binding.lease_expires_at_ms = 300000u;
    binding.assignment_revision = 11u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_put_v1(pair->fabric, &binding),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

static int initialize_pair(
    isolation_pair_t *pair,
    uint8_t *fabric_workspace,
    uint8_t *rrmp_workspace,
    uint8_t path_seed,
    uint8_t record_seed,
    uint8_t message_offset)
{
    ninlil_id128_t runtime_id;
    ninlil_rrmp_owner_config_v1_t rrmp_config;
    size_t rrmp_workspace_bytes = ninlil_rrmp_owner_workspace_bytes();

    FABRIC_REQUIRE(pair != NULL);
    FABRIC_REQUIRE(
        rrmp_workspace_bytes > 0u
        && rrmp_workspace_bytes <= NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES);
    ninlil_fabric_private_memzero(pair, sizeof(*pair));
    ninlil_fabric_private_memzero(
        fabric_workspace, NINLIL_FABRIC_WORKSPACE_BYTES);
    ninlil_rrmp_memzero(
        rrmp_workspace, NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES);

    fabric_test_storage_ops(&pair->storage);
    pair->storage.user = &pair->store;
    pair->clock.abi_version = NINLIL_ABI_VERSION;
    pair->clock.struct_size = (uint16_t)sizeof(pair->clock);
    pair->clock.now = test_clock_now;
    pair->execution.abi_version = NINLIL_ABI_VERSION;
    pair->execution.struct_size = (uint16_t)sizeof(pair->execution);
    pair->execution.current_context_id = test_exec_context;
    pair->config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    pair->config.struct_size = (uint16_t)sizeof(pair->config);
    pair->config.profile_id = NINLIL_FABRIC_PROFILE_1;
    pair->config.storage = &pair->storage;
    pair->config.clock = &pair->clock;
    pair->config.execution = &pair->execution;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &pair->config,
            fabric_workspace,
            NINLIL_FABRIC_WORKSPACE_BYTES,
            &pair->fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(pair->fabric, &pair->bearer),
        NINLIL_FABRIC_PRIVATE_OK);

    ninlil_rrmp_memzero(&rrmp_config, sizeof(rrmp_config));
    rrmp_config.preamble.api_version = 1u;
    rrmp_config.preamble.struct_size = (uint32_t)sizeof(rrmp_config);
    rrmp_fill_id(rrmp_config.local_runtime_id, record_seed);
    rrmp_fill_id(rrmp_config.authority_id, (uint8_t)(record_seed + 0x20u));
    rrmp_config.controller_term = 5u;
    rrmp_fill_id(rrmp_config.authority_clock_epoch_id, 0x50u);
    rrmp_config.feature_route_relay = 1u;
    rrmp_config.max_hops_profile = 3u;
    rrmp_config.now_ms = 1000000u;
    pair->rrmp = ninlil_rrmp_owner_init(
        rrmp_workspace, rrmp_workspace_bytes, &rrmp_config);
    FABRIC_REQUIRE(pair->rrmp != NULL);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bind_path_selected_hook_v1(
            pair->fabric,
            pair->rrmp,
            ninlil_rrmp_fabric_path_selected_hook_v1),
        NINLIL_FABRIC_PRIVATE_OK);

    fill_message(&pair->message, message_offset);
    fill_descriptor(&pair->descriptor, path_seed);
    pair->provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    pair->provider.completion_kind =
        NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    pair->provider.state.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    pair->provider.state.struct_size = (uint16_t)sizeof(pair->provider.state);
    pair->provider.state.availability_epoch = 7u;
    fabric_test_pattern(
        pair->provider.state.availability_clock_epoch_id.bytes, 0xa1u, 16u);
    pair->provider.state.available_until_ms = 250000u;
    pair->provider.state.available = 1u;
    fabric_test_provider_ops(&pair->link_ops, &pair->provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            pair->fabric,
            &pair->descriptor,
            &pair->link_ops,
            &pair->registration),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(put_policy_and_authority(pair, path_seed, record_seed) == 0);

    fabric_test_id(&runtime_id, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        pair->bearer->open(
            pair->bearer->user,
            &runtime_id,
            NINLIL_ROLE_ENDPOINT,
            &pair->bearer_handle),
        NINLIL_BEARER_OK);
    pair->permit.abi_version = NINLIL_ABI_VERSION;
    pair->permit.struct_size = (uint16_t)sizeof(pair->permit);
    fabric_test_id(&pair->permit.permit_id, (uint8_t)(record_seed + 4u));
    pair->permit.attempt_id = pair->message.attempt_id;
    fabric_test_id(&pair->permit.clock_epoch_id, 0xa1u);
    pair->permit.expires_at_ms = 200000u;
    return 0;
}

static int shutdown_pair(isolation_pair_t *pair)
{
    uint32_t done = 0u;
    uint32_t work_done = 0u;
    uint32_t spins;
    if (pair == NULL || pair->fabric == NULL) {
        return 0;
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bind_path_selected_hook_v1(
            pair->fabric, NULL, NULL),
        NINLIL_FABRIC_PRIVATE_OK);
    if (pair->bearer != NULL && pair->bearer_handle != NULL) {
        pair->bearer->close(pair->bearer->user, pair->bearer_handle);
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(pair->fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    for (spins = 0u; spins < 64u && done == 0u; ++spins) {
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_step_v1(pair->fabric, 16u, &work_done),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_close_poll_v1(pair->fabric, &done),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    FABRIC_REQUIRE(done == 1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(pair->fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    ninlil_rrmp_owner_fini(pair->rrmp);
    pair->fabric = NULL;
    pair->rrmp = NULL;
    return 0;
}

int main(void)
{
    ninlil_bearer_send_result_t send_result;
    uint8_t path_a[16];
    uint8_t path_b[16];
    uint8_t saved_a[16];
    uint64_t epoch_a = 0u;
    uint64_t epoch_b = 0u;
    uint64_t saved_epoch_a = 0u;

    fabric_test_reset_globals();
    FABRIC_REQUIRE(
        initialize_pair(
            &g_pair_a, g_fabric_ws_a, g_rrmp_ws_a, 0x61u, 0x71u, 0u)
        == 0);
    FABRIC_REQUIRE(
        initialize_pair(
            &g_pair_b, g_fabric_ws_b, g_rrmp_ws_b, 0x91u, 0xb1u, 1u)
        == 0);

    /* Replacing a live instance binding is deliberately fail-closed. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bind_path_selected_hook_v1(
            g_pair_a.fabric,
            g_pair_b.rrmp,
            ninlil_rrmp_fabric_path_selected_hook_v1),
        NINLIL_FABRIC_PRIVATE_CONFLICT);

    /* Both explicit owner domains are live; Fabric A updates only RRMP A. */
    FABRIC_REQUIRE(ninlil_rrmp_owner_bind(g_pair_a.rrmp) != 0);
    FABRIC_REQUIRE(ninlil_rrmp_owner_bind(g_pair_b.rrmp) != 0);
    ninlil_fabric_private_memzero(&send_result, sizeof(send_result));
    FABRIC_REQUIRE_EQ_U32(
        g_pair_a.bearer->send(
            g_pair_a.bearer->user,
            g_pair_a.bearer_handle,
            &g_pair_a.permit,
            &g_pair_a.message,
            &send_result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(
        ninlil_rrmp_fabric_last_path(g_pair_a.rrmp, path_a, &epoch_a) != 0);
    FABRIC_REQUIRE(epoch_a == 1u);
    FABRIC_REQUIRE(memcmp(path_a, g_pair_a.descriptor.instance_id.bytes, 16u) == 0);
    FABRIC_REQUIRE(
        ninlil_rrmp_fabric_last_path(g_pair_b.rrmp, path_b, &epoch_b) == 0);
    (void)memcpy(saved_a, path_a, sizeof(saved_a));
    saved_epoch_a = epoch_a;

    /* Fabric B updates only RRMP B without any implicit current-owner state. */
    ninlil_fabric_private_memzero(&send_result, sizeof(send_result));
    FABRIC_REQUIRE_EQ_U32(
        g_pair_b.bearer->send(
            g_pair_b.bearer->user,
            g_pair_b.bearer_handle,
            &g_pair_b.permit,
            &g_pair_b.message,
            &send_result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(
        ninlil_rrmp_fabric_last_path(g_pair_b.rrmp, path_b, &epoch_b) != 0);
    FABRIC_REQUIRE(epoch_b == 1u);
    FABRIC_REQUIRE(memcmp(path_b, g_pair_b.descriptor.instance_id.bytes, 16u) == 0);
    FABRIC_REQUIRE(
        ninlil_rrmp_fabric_last_path(g_pair_a.rrmp, path_a, &epoch_a) != 0);
    FABRIC_REQUIRE(epoch_a == saved_epoch_a);
    FABRIC_REQUIRE(memcmp(path_a, saved_a, 16u) == 0);
    FABRIC_REQUIRE(memcmp(path_a, path_b, 16u) != 0);
    FABRIC_REQUIRE(g_pair_a.provider.start_calls == 1u);
    FABRIC_REQUIRE(g_pair_b.provider.start_calls == 1u);

    FABRIC_REQUIRE(shutdown_pair(&g_pair_b) == 0);
    FABRIC_REQUIRE(shutdown_pair(&g_pair_a) == 0);
    (void)printf("rrmp_fabric_two_instance_isolation_test OK\n");
    return 0;
}
