/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Actual private composition proof:
 * ESP adapter host fake -> production registration wrapper -> real Fabric
 * outer bearer -> Wi-Fi provider.
 *
 * Reuse only the ESP adapter fixture helpers. The registry double and its
 * test main are excluded; this translation unit links the real Fabric core.
 */
#define NINLIL_WIFI_ACTUAL_FABRIC_HELPERS_ONLY 1
#include "wifi_v1_esp_adapter_e2e_test.c"

#include "fabric_private_util.h"

#include <stdalign.h>

static _Alignas(max_align_t)
    uint8_t actual_fabric_workspace[NINLIL_FABRIC_WORKSPACE_BYTES];

static void actual_id(ninlil_id128_t *id, uint8_t byte)
{
    (void)memset(id->bytes, byte, sizeof(id->bytes));
}

static void actual_fill_message(
    ninlil_bearer_message_t *message,
    const side_t *client,
    const side_t *server,
    const clock_fixture_t *clock_fixture,
    uint8_t payload[4],
    uint8_t attempt_byte)
{
    static const uint8_t namespace_id[] = {'a', 'c', 't'};
    static const uint8_t service_id[] = {'e', '2', 'e'};
    static const uint8_t schema_id[] = {'v', '1'};
    uint8_t digest[32];

    payload[0] = 0x10u;
    payload[1] = 0x20u;
    payload[2] = 0x30u;
    payload[3] = attempt_byte;
    (void)memset(message, 0, sizeof(*message));
    message->abi_version = NINLIL_ABI_VERSION;
    message->struct_size = (uint16_t)sizeof(*message);
    message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    actual_id(&message->transaction_id, 0x71u);
    actual_id(&message->attempt_id, attempt_byte);
    message->source.abi_version = NINLIL_ABI_VERSION;
    message->source.struct_size = (uint16_t)sizeof(message->source);
    message->source.runtime_id = client->config.local_runtime_id;
    actual_id(&message->source.application_instance_id, 0x41u);
    message->source.local_identity.abi_version = NINLIL_ABI_VERSION;
    message->source.local_identity.struct_size =
        (uint16_t)sizeof(message->source.local_identity);
    actual_id(&message->source.local_identity.device_id, 0x51u);
    actual_id(&message->source.local_identity.installation_id, 0x61u);
    actual_id(&message->source.local_identity.site_domain_id, 0x71u);
    message->source.local_identity.binding_epoch = 1u;
    message->source.local_identity.membership_epoch = 1u;
    message->source.local_identity.flags = 7u;
    message->target.abi_version = NINLIL_ABI_VERSION;
    message->target.struct_size = (uint16_t)sizeof(message->target);
    message->target.target_runtime_id = server->config.local_runtime_id;
    actual_id(&message->target.target_application_instance_id, 0x91u);
    actual_id(&message->target.device_id, 0xA1u);
    actual_id(&message->target.installation_id, 0xB1u);
    actual_id(&message->target.site_domain_id, 0xC1u);
    message->target.binding_epoch = 1u;
    message->target.membership_epoch = 1u;
    message->target.flags = 7u;
    message->service.abi_version = NINLIL_ABI_VERSION;
    message->service.struct_size = (uint16_t)sizeof(message->service);
    message->service.namespace_id.length = (uint8_t)sizeof(namespace_id);
    (void)memcpy(
        message->service.namespace_id.bytes,
        namespace_id,
        sizeof(namespace_id));
    message->service.service_id.length = (uint8_t)sizeof(service_id);
    (void)memcpy(
        message->service.service_id.bytes,
        service_id,
        sizeof(service_id));
    message->service.schema_id.length = (uint8_t)sizeof(schema_id);
    (void)memcpy(
        message->service.schema_id.bytes,
        schema_id,
        sizeof(schema_id));
    message->service.descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"actual-adapter-fabric-service-v1",
        32u,
        digest);
    message->service.descriptor_digest.algorithm = 1u;
    (void)memcpy(message->service.descriptor_digest.bytes, digest, 32u);
    message->service.schema_major = 1u;
    message->service.family = 2u;
    ninlil_fabric_private_sha256(payload, 4u, digest);
    message->content_digest.algorithm = 1u;
    (void)memcpy(message->content_digest.bytes, digest, 32u);
    message->generation = 1u;
    (void)memcpy(
        message->deadline_clock_epoch_id.bytes,
        clock_fixture->epoch,
        16u);
    message->absolute_effect_deadline_ms = clock_fixture->now_ms + 60000u;
    message->evidence_grace_ms = 1000u;
    message->required_evidence = NINLIL_EVIDENCE_NONE;
    message->payload.data = payload;
    message->payload.length = 4u;
}

static int actual_install_contract(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_bearer_message_t *message,
    const clock_fixture_t *clock_fixture)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t snapshot;
    ninlil_fabric_authority_binding_v1_t binding_record;
    uint8_t service_digest[32];

    ninlil_fabric_private_nfl1_service_identity_digest(
        message->service.namespace_id.bytes,
        message->service.namespace_id.length,
        message->service.service_id.bytes,
        message->service.service_id.length,
        message->service.schema_id.bytes,
        message->service.schema_id.length,
        message->service.descriptor_revision,
        message->service.descriptor_digest.bytes,
        message->service.schema_major,
        message->service.schema_minor,
        message->service.family,
        service_digest);
    (void)memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    actual_id(&policy.policy_id, 0x72u);
    policy.revision = 1u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = message->service.family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags =
        NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE | NINLIL_FABRIC_CAP_UNICAST;
    policy.required_security_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.maximum_latency_class = 50u;
    policy.maximum_cost_class = 50u;
    policy.minimum_packet_bytes = NINLIL_FABRIC_NFL1_STRUCTURAL_MIN;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 100u;
    policy.candidate_count = 1u;
    policy.candidates[0].instance_id = descriptor->instance_id;
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    if (ninlil_fabric_private_policy_put_v1(fabric, &policy)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    if (ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, policy.revision, &snapshot)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }

    (void)memset(&binding_record, 0, sizeof(binding_record));
    binding_record.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding_record.struct_size = (uint16_t)sizeof(binding_record);
    actual_id(&binding_record.binding_id, 0xB8u);
    (void)memcpy(
        binding_record.service_identity_digest, service_digest, 32u);
    binding_record.family = message->service.family;
    binding_record.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding_record.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding_record.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    binding_record.endpoint_runtime_id =
        message->target.target_runtime_id;
    binding_record.target_runtime_id =
        message->target.target_runtime_id;
    binding_record.target_application_id =
        message->target.target_application_instance_id;
    binding_record.policy_id = policy.policy_id;
    binding_record.policy_revision = policy.revision;
    (void)memcpy(
        binding_record.policy_digest,
        snapshot.canonical_digest_zero_on_input,
        32u);
    binding_record.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    actual_id(&binding_record.authority_id, 0xD0u);
    binding_record.authority_term = 7u;
    binding_record.assignment_epoch = 11u;
    actual_id(&binding_record.owner_scope_id, 0x81u);
    (void)memset(binding_record.owner_tuple_canonical, 0x82, 200u);
    ninlil_fabric_private_owner_tuple_digest(
        binding_record.owner_tuple_canonical,
        binding_record.owner_tuple_digest);
    (void)memcpy(
        binding_record.authority_clock_epoch_id.bytes,
        clock_fixture->epoch,
        16u);
    binding_record.lease_expires_at_ms = clock_fixture->now_ms + 100000u;
    binding_record.assignment_revision = 1u;
    return ninlil_fabric_private_authority_put_v1(
               fabric, &binding_record)
            == NINLIL_FABRIC_PRIVATE_OK
        ? 1
        : 0;
}

int main(void)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_storage_t *storage_fixture = NULL;
    const ninlil_storage_ops_t *storage = NULL;
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
    uint32_t reason = 0u;
    uint64_t epoch = 0u;
    const ninlil_fabric_packet_link_ops_v1_t *standalone_ops = NULL;
    ninlil_fabric_packet_link_handle_t standalone_handle = NULL;
    ninlil_fabric_packet_token_t standalone_token = NULL;
    ninlil_fabric_packet_view_v1_t standalone_packet;
    uint8_t standalone_byte = 0u;
    ninlil_fabric_config_v1_t fabric_config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    const ninlil_fabric_link_descriptor_v1_t *descriptor = NULL;
    ninlil_fabric_link_descriptor_v1_t *mutable_descriptor = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_handle_t bearer_handle = NULL;
    ninlil_bearer_message_t message;
    ninlil_bearer_message_t replay_message;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t send_result;
    ninlil_fabric_link_metrics_v1_t metrics;
    uint8_t payload[4];
    uint8_t replay_payload[4];
    uint32_t done = 0u;

    failures = 0;
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 8u;
    storage_config.max_entries_per_namespace = 300u;
    storage_config.max_bytes_per_namespace = 400000u;
    storage_fixture = ninlil_test_storage_create(&storage_config);
    CHECK(storage_fixture != NULL);
    storage = ninlil_test_storage_ops(storage_fixture);
    CHECK(storage != NULL);

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
    (void)memset(clock_fixture.epoch, 0xE2, 16u);
    (void)memset(&clock, 0, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.user = &clock_fixture;
    clock.now = clock_now;
    (void)memset(&execution, 0, sizeof(execution));
    execution.abi_version = NINLIL_ABI_VERSION;
    execution.struct_size = (uint16_t)sizeof(execution);
    execution.current_context_id = current_context;

    (void)memset(authority, 0xD0, sizeof(authority));
    (void)memset(binding, 0xA1, sizeof(binding));
    (void)memset(credential, 0xC1, sizeof(credential));
    (void)memset(registry_epoch, 0xE1, sizeof(registry_epoch));
    client_leaf = make_leaf(
        NINLIL_WIFI_LEAF_ROLE_CLIENT, 0x31, authority, binding);
    server_leaf = make_leaf(
        NINLIL_WIFI_LEAF_ROLE_SERVER, 0x32, authority, binding);
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
        "actual-m4-server",
        0x41,
        0xF1,
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
        "actual-m4-client",
        0x42,
        0xF2,
        credential,
        registry_epoch);
    CHECK(server.adapter != NULL && client.adapter != NULL);
    ninlil_wifi_esp_tls_host_pair(
        (ninlil_wifi_esp_tls_t *)(void *)server.tls_storage,
        (ninlil_wifi_esp_tls_t *)(void *)client.tls_storage);
    for (i = 0u; i < 10000u; ++i) {
        uint32_t work = 0u;
        CHECK(wifi_step_v1(server.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(client.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_state_v1(
                  server.adapter, &server_state, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        CHECK(wifi_state_v1(
                  client.adapter, &client_state, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        if (server_state == WIFI_OPERATIONAL_ATTACHED
            && client_state == WIFI_OPERATIONAL_ATTACHED) {
            break;
        }
    }
    CHECK(server_state == WIFI_OPERATIONAL_ATTACHED);
    CHECK(client_state == WIFI_OPERATIONAL_ATTACHED);

    /* Standalone raw access remains DENIED/TX0 before registration. */
    CHECK(wifi_packet_link_ops_v1(client.adapter, &standalone_ops)
        == WIFI_PRIVATE_OK);
    CHECK(standalone_ops != NULL);
    CHECK(standalone_ops->open(
              standalone_ops->user, &standalone_handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(standalone_handle == NULL);
    (void)memset(&standalone_packet, 0, sizeof(standalone_packet));
    standalone_packet.api_version = 1u;
    standalone_packet.struct_size =
        (uint16_t)sizeof(standalone_packet);
    standalone_packet.bytes = &standalone_byte;
    standalone_packet.length = 1u;
    standalone_token = (ninlil_fabric_packet_token_t)(uintptr_t)1u;
    CHECK(standalone_ops->start_send(
              standalone_ops->user,
              (ninlil_fabric_packet_link_handle_t)(uintptr_t)1u,
              &standalone_packet,
              &standalone_token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(standalone_token == NULL);

    (void)memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = storage;
    fabric_config.clock = &clock;
    fabric_config.execution = &execution;
    (void)memset(
        actual_fabric_workspace, 0, sizeof(actual_fabric_workspace));
    CHECK(ninlil_fabric_private_create_v1(
              &fabric_config,
              actual_fabric_workspace,
              sizeof(actual_fabric_workspace),
              &fabric)
        == NINLIL_FABRIC_PRIVATE_OK);
    CHECK(fabric != NULL);
    CHECK(wifi_packet_link_descriptor_v1(client.adapter, &descriptor)
        == WIFI_PRIVATE_OK);
    CHECK(descriptor != NULL);
    /*
     * Simulate corrupted retained M4 state: neither descriptor publication
     * nor registration preparation may expose Wi-Fi as custody-capable.
     */
    (void)memcpy(
        &mutable_descriptor, &descriptor, sizeof(mutable_descriptor));
    mutable_descriptor->capability_flags |= NINLIL_FABRIC_CAP_CUSTODY;
    descriptor = NULL;
    CHECK(wifi_packet_link_descriptor_v1(client.adapter, &descriptor)
        == WIFI_PRIVATE_DENIED);
    CHECK(descriptor == NULL);
    CHECK(wifi_fabric_register_v1(
              client.adapter, fabric, &registration)
        == WIFI_PRIVATE_DENIED);
    CHECK(registration == NULL);
    mutable_descriptor->capability_flags &= ~NINLIL_FABRIC_CAP_CUSTODY;
    CHECK(wifi_packet_link_descriptor_v1(client.adapter, &descriptor)
        == WIFI_PRIVATE_OK);
    CHECK(descriptor != NULL);
    CHECK(wifi_fabric_register_v1(
              client.adapter, fabric, &registration)
        == WIFI_PRIVATE_OK);
    CHECK(registration != NULL);
    CHECK(ninlil_fabric_private_bearer_ops_v1(fabric, &bearer)
        == NINLIL_FABRIC_PRIVATE_OK);
    CHECK(bearer != NULL);

    actual_fill_message(
        &message,
        &client,
        &server,
        &clock_fixture,
        payload,
        0x81u);
    CHECK(actual_install_contract(
        fabric, descriptor, &message, &clock_fixture));
    CHECK(bearer->open(
              bearer->user,
              &client.config.local_runtime_id,
              NINLIL_ROLE_ENDPOINT,
              &bearer_handle)
        == NINLIL_BEARER_OK);
    (void)memset(&permit, 0, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    actual_id(&permit.permit_id, 0x91u);
    permit.attempt_id = message.attempt_id;
    (void)memcpy(
        permit.clock_epoch_id.bytes, clock_fixture.epoch, 16u);
    permit.expires_at_ms = clock_fixture.now_ms + 50000u;
    (void)memset(&send_result, 0, sizeof(send_result));
    CHECK(bearer->send(
              bearer->user,
              bearer_handle,
              &permit,
              &message,
              &send_result)
        == NINLIL_BEARER_OK);
    CHECK(send_result.kind == NINLIL_BEARER_SEND_ACCEPTED);

    for (i = 0u; i < 10000u; ++i) {
        uint32_t work = 0u;
        CHECK(wifi_step_v1(server.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(client.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(ninlil_fabric_private_step_v1(fabric, 16u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        (void)memset(&metrics, 0, sizeof(metrics));
        CHECK(ninlil_fabric_private_metrics_snapshot_v1(
                  fabric, &descriptor->instance_id, &metrics)
            == NINLIL_FABRIC_PRIVATE_OK);
        if (metrics.retained_tokens == 0u && metrics.queued_items == 0u) {
            break;
        }
    }
    CHECK(metrics.retained_tokens == 0u);
    CHECK(metrics.queued_items == 0u);

    /* The same live durable pair cannot be reissued for another attempt. */
    actual_fill_message(
        &replay_message,
        &client,
        &server,
        &clock_fixture,
        replay_payload,
        0x82u);
    permit.attempt_id = replay_message.attempt_id;
    CHECK(bearer->send(
              bearer->user,
              bearer_handle,
              &permit,
              &replay_message,
              &send_result)
        == NINLIL_BEARER_DENIED);

    /* Wrong Fabric cookie is denied before any unregister mutation. */
    CHECK(wifi_fabric_unregister_begin_v1(
              client.adapter,
              (ninlil_fabric_private_t *)(uintptr_t)1u,
              registration)
        == WIFI_PRIVATE_DENIED);
    bearer->close(bearer->user, bearer_handle);
    bearer_handle = NULL;
    CHECK(wifi_fabric_unregister_begin_v1(
              client.adapter, fabric, registration)
        == WIFI_PRIVATE_OK);
    for (i = 0u; i < 32u && done == 0u; ++i) {
        CHECK(wifi_fabric_unregister_poll_v1(
                  client.adapter, fabric, registration, &done)
            == WIFI_PRIVATE_OK);
    }
    CHECK(done == 1u);
    done = 99u;
    CHECK(wifi_fabric_unregister_poll_v1(
              client.adapter, fabric, registration, &done)
        == WIFI_PRIVATE_DENIED);
    CHECK(done == 0u);

    CHECK(ninlil_fabric_private_close_begin_v1(fabric)
        == NINLIL_FABRIC_PRIVATE_OK);
    done = 0u;
    for (i = 0u; i < 64u && done == 0u; ++i) {
        uint32_t work = 0u;
        CHECK(ninlil_fabric_private_step_v1(fabric, 16u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        CHECK(ninlil_fabric_private_close_poll_v1(fabric, &done)
            == NINLIL_FABRIC_PRIVATE_OK);
    }
    CHECK(done == 1u);
    CHECK(ninlil_fabric_private_destroy_v1(fabric)
        == NINLIL_FABRIC_PRIVATE_OK);

    CHECK(wifi_drain_begin_v1(client.adapter) == WIFI_PRIVATE_OK);
    CHECK(wifi_drain_begin_v1(server.adapter) == WIFI_PRIVATE_OK);
    for (i = 0u; i < 32u; ++i) {
        uint32_t work = 0u;
        uint32_t client_done = 0u;
        uint32_t server_done = 0u;
        CHECK(wifi_step_v1(client.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(server.adapter, 16u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_drain_poll_v1(client.adapter, &client_done)
            == WIFI_PRIVATE_OK);
        CHECK(wifi_drain_poll_v1(server.adapter, &server_done)
            == WIFI_PRIVATE_OK);
        if (client_done != 0u && server_done != 0u) {
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
            stderr,
            "wifi_v1_actual_adapter_fabric_e2e_test FAIL %d\n",
            failures);
        return 1;
    }
    (void)printf(
        "wifi_v1_actual_adapter_fabric_e2e_test PASS "
        "adapter->register->outer send->provider->unregister\n");
    return 0;
}
